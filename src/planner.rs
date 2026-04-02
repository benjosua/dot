use anyhow::Result;
use serde::Serialize;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::config::{CollisionPolicy, Manifest, TargetKind};
use crate::discover::{DesiredTarget, DiscoveryResult};
use crate::fs::{ObservedTarget, inspect_target, parent_requires_privilege};
use crate::state::{StateEntry, StateFile};

#[derive(Debug, Clone, Serialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
}

impl Diagnostic {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum OperationKind {
    EnsureDir,
    CreateSymlink,
    ReplaceSymlink,
    RemoveSymlink,
    CreateCopy,
    ReplaceCopy,
    RemoveCopy,
    CreateRender,
    ReplaceRender,
    RemoveRender,
    SetMode,
    PrivilegedStat,
}

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub kind: OperationKind,
    pub package: Option<String>,
    pub target: PathBuf,
    pub source: Option<PathBuf>,
    pub source_rel: Option<PathBuf>,
    pub content_hash: Option<String>,
    pub requires_privilege: bool,
    pub blocked: bool,
    pub reason: Option<String>,
    pub diff: Option<String>,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PlanSummary {
    pub create: usize,
    pub replace: usize,
    pub remove: usize,
    pub ensure_dir: usize,
    pub set_mode: usize,
    pub blocked: usize,
    pub clean: usize,
    pub privileged_stat: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub operations: Vec<Operation>,
    pub diagnostics: Vec<Diagnostic>,
    pub summary: PlanSummary,
}

pub fn build_plan(
    manifest: &Manifest,
    discovery: DiscoveryResult,
    state: &StateFile,
    no_render_diff: bool,
) -> Result<Plan> {
    let mut diagnostics = discovery.diagnostics;
    let mut operations = Vec::new();
    let mut summary = PlanSummary::default();

    let desired_by_target = detect_collisions(&discovery.desired, manifest, &mut diagnostics)?;
    let state_by_target = state.by_target();
    let desired_targets = desired_by_target.keys().cloned().collect::<BTreeSet<_>>();
    let state_targets = state_by_target.keys().cloned().collect::<BTreeSet<_>>();

    for target in state_targets.difference(&desired_targets) {
        let entry = state_by_target.get(target).expect("state target exists");
        let observed = inspect_target(target)?;
        if let ObservedTarget::Unreadable = observed {
            operations.push(Operation {
                kind: OperationKind::PrivilegedStat,
                package: Some(entry.package.clone()),
                target: target.clone(),
                source: None,
                source_rel: Some(PathBuf::from(&entry.source_rel)),
                content_hash: Some(entry.content_hash.clone()),
                requires_privilege: true,
                blocked: false,
                reason: Some("target is unreadable without privilege".into()),
                diff: None,
                mode: None,
            });
            summary.privileged_stat += 1;
        }

        let (kind, blocked, reason) = removal_from_state(entry, &observed);
        operations.push(Operation {
            kind,
            package: Some(entry.package.clone()),
            target: target.clone(),
            source: None,
            source_rel: Some(PathBuf::from(&entry.source_rel)),
            content_hash: Some(entry.content_hash.clone()),
            requires_privilege: parent_requires_privilege(target),
            blocked,
            reason,
            diff: None,
            mode: None,
        });
        summary.remove += 1;
        if blocked {
            summary.blocked += 1;
        }
    }

    for (target, desired) in desired_by_target {
        let observed = inspect_target(&target)?;
        let state_entry = state_by_target.get(&target);

        if let ObservedTarget::Unreadable = observed {
            operations.push(Operation {
                kind: OperationKind::PrivilegedStat,
                package: Some(desired.package.clone()),
                target: target.clone(),
                source: operation_source(&desired),
                source_rel: Some(desired.source_rel.clone()),
                content_hash: Some(desired.desired_hash.clone()),
                requires_privilege: true,
                blocked: false,
                reason: Some("target is unreadable without privilege".into()),
                diff: None,
                mode: None,
            });
            summary.privileged_stat += 1;
        }

        let planned = plan_for_target(&desired, state_entry, &observed, no_render_diff);
        match planned {
            PlannedTarget::Clean => {
                summary.clean += 1;
            }
            PlannedTarget::Ops(mut ops) => {
                for op in &mut ops {
                    op.requires_privilege |= parent_requires_privilege(&op.target);
                    if op.blocked {
                        summary.blocked += 1;
                    }
                    match op.kind {
                        OperationKind::CreateSymlink
                        | OperationKind::CreateCopy
                        | OperationKind::CreateRender => summary.create += 1,
                        OperationKind::ReplaceSymlink
                        | OperationKind::ReplaceCopy
                        | OperationKind::ReplaceRender => summary.replace += 1,
                        OperationKind::EnsureDir => summary.ensure_dir += 1,
                        OperationKind::SetMode => summary.set_mode += 1,
                        _ => {}
                    }
                }
                operations.extend(ops);
            }
        }
    }

    Ok(Plan {
        operations,
        diagnostics,
        summary,
    })
}

fn detect_collisions(
    desired: &[DesiredTarget],
    manifest: &Manifest,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<BTreeMap<PathBuf, DesiredTarget>> {
    let mut map = BTreeMap::new();
    for item in desired {
        if let Some(existing) = map.insert(item.target.clone(), item.clone()) {
            let message = format!(
                "target collision: {} is claimed by {} and {}",
                existing.target.display(),
                existing.source_rel.display(),
                item.source_rel.display()
            );
            diagnostics.push(Diagnostic::error(message.clone()));
            if manifest.settings.collision_policy == CollisionPolicy::Error {
                map.insert(existing.target.clone(), existing);
            }
        }
    }
    Ok(map)
}

enum PlannedTarget {
    Clean,
    Ops(Vec<Operation>),
}

fn plan_for_target(
    desired: &DesiredTarget,
    state_entry: Option<&StateEntry>,
    observed: &ObservedTarget,
    no_render_diff: bool,
) -> PlannedTarget {
    let managed_current = state_entry.is_some_and(|entry| current_matches_state(entry, observed));
    let unmanaged_exists = matches!(
        observed,
        ObservedTarget::Directory | ObservedTarget::File { .. } | ObservedTarget::Symlink { .. }
    ) && !managed_current;

    if current_matches_desired(desired, observed) {
        return PlannedTarget::Clean;
    }

    if unmanaged_exists {
        return PlannedTarget::Ops(vec![Operation {
            kind: create_kind_for(desired.kind),
            package: Some(desired.package.clone()),
            target: desired.target.clone(),
            source: operation_source(desired),
            source_rel: Some(desired.source_rel.clone()),
            content_hash: Some(desired.desired_hash.clone()),
            requires_privilege: false,
            blocked: true,
            reason: Some("target exists with unmanaged changes".into()),
            diff: render_diff(desired, observed, no_render_diff),
            mode: desired.mode,
        }]);
    }

    let mut ops = Vec::new();
    ops.push(Operation {
        kind: OperationKind::EnsureDir,
        package: Some(desired.package.clone()),
        target: desired
            .target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| desired.target.clone()),
        source: None,
        source_rel: None,
        content_hash: None,
        requires_privilege: false,
        blocked: false,
        reason: None,
        diff: None,
        mode: None,
    });

    let kind = if matches!(observed, ObservedTarget::Missing) {
        create_kind_for(desired.kind)
    } else {
        replace_kind_for(desired.kind)
    };

    ops.push(Operation {
        kind,
        package: Some(desired.package.clone()),
        target: desired.target.clone(),
        source: operation_source(desired),
        source_rel: Some(desired.source_rel.clone()),
        content_hash: Some(desired.desired_hash.clone()),
        requires_privilege: false,
        blocked: false,
        reason: None,
        diff: render_diff(desired, observed, no_render_diff),
        mode: None,
    });

    if let Some(mode) = desired.mode
        && !matches!(desired.kind, TargetKind::Symlink)
    {
        ops.push(Operation {
            kind: OperationKind::SetMode,
            package: Some(desired.package.clone()),
            target: desired.target.clone(),
            source: None,
            source_rel: Some(desired.source_rel.clone()),
            content_hash: Some(desired.desired_hash.clone()),
            requires_privilege: false,
            blocked: false,
            reason: None,
            diff: None,
            mode: Some(mode),
        });
    }

    PlannedTarget::Ops(ops)
}

fn operation_source(desired: &DesiredTarget) -> Option<PathBuf> {
    match desired.kind {
        TargetKind::Render => desired.render_cache_path.clone(),
        TargetKind::Symlink | TargetKind::Copy => Some(desired.source_abs.clone()),
    }
}

fn create_kind_for(kind: TargetKind) -> OperationKind {
    match kind {
        TargetKind::Symlink => OperationKind::CreateSymlink,
        TargetKind::Copy => OperationKind::CreateCopy,
        TargetKind::Render => OperationKind::CreateRender,
    }
}

fn replace_kind_for(kind: TargetKind) -> OperationKind {
    match kind {
        TargetKind::Symlink => OperationKind::ReplaceSymlink,
        TargetKind::Copy => OperationKind::ReplaceCopy,
        TargetKind::Render => OperationKind::ReplaceRender,
    }
}

fn removal_from_state(
    entry: &StateEntry,
    observed: &ObservedTarget,
) -> (OperationKind, bool, Option<String>) {
    let kind = match entry.kind {
        TargetKind::Symlink => OperationKind::RemoveSymlink,
        TargetKind::Copy => OperationKind::RemoveCopy,
        TargetKind::Render => OperationKind::RemoveRender,
    };

    if current_matches_state(entry, observed)
        || matches!(
            observed,
            ObservedTarget::Missing | ObservedTarget::Unreadable
        )
    {
        (kind, false, None)
    } else {
        (
            kind,
            true,
            Some("managed target drifted since last apply".into()),
        )
    }
}

fn current_matches_desired(desired: &DesiredTarget, observed: &ObservedTarget) -> bool {
    match (desired.kind, observed) {
        (TargetKind::Symlink, ObservedTarget::Symlink { target }) => target == &desired.source_abs,
        (TargetKind::Copy, ObservedTarget::File { hash, .. })
        | (TargetKind::Render, ObservedTarget::File { hash, .. }) => hash == &desired.desired_hash,
        _ => false,
    }
}

fn current_matches_state(entry: &StateEntry, observed: &ObservedTarget) -> bool {
    match (entry.kind, observed) {
        (TargetKind::Symlink, ObservedTarget::Symlink { target }) => {
            hex::encode(sha2::Sha256::digest(
                target.display().to_string().as_bytes(),
            )) == entry.content_hash
        }
        (TargetKind::Copy, ObservedTarget::File { hash, .. })
        | (TargetKind::Render, ObservedTarget::File { hash, .. }) => hash == &entry.content_hash,
        (_, ObservedTarget::Missing) => false,
        _ => false,
    }
}

fn render_diff(
    desired: &DesiredTarget,
    observed: &ObservedTarget,
    no_render_diff: bool,
) -> Option<String> {
    if no_render_diff || desired.kind != TargetKind::Render {
        return None;
    }

    match (desired.rendered_text.as_deref(), observed) {
        (
            Some(after),
            ObservedTarget::File {
                text: Some(before), ..
            },
        ) => Some(crate::render::text_diff(before, after)),
        (Some(after), ObservedTarget::Missing) => Some(crate::render::text_diff("", after)),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::TargetKind;
    use crate::discover::DesiredTarget;

    #[test]
    fn replacement_ops_are_first_class() {
        let desired = DesiredTarget {
            package: "zsh".into(),
            source_rel: PathBuf::from("zsh/.zshrc"),
            source_abs: PathBuf::from("/repo/zsh/.zshrc"),
            target: PathBuf::from("/tmp/.zshrc"),
            kind: TargetKind::Symlink,
            mode: None,
            desired_hash: "abc".into(),
            rendered_text: None,
            render_cache_path: None,
        };
        let state = StateEntry {
            package: "zsh".into(),
            source_rel: "zsh/.zshrc".into(),
            target: "/tmp/.zshrc".into(),
            kind: TargetKind::Symlink,
            content_hash: hex::encode(sha2::Sha256::digest(b"/tmp/old")),
            mode: None,
        };

        let ops = match plan_for_target(
            &desired,
            Some(&state),
            &ObservedTarget::Symlink {
                target: PathBuf::from("/tmp/old"),
            },
            true,
        ) {
            PlannedTarget::Ops(ops) => ops,
            PlannedTarget::Clean => panic!("expected planned operations"),
        };
        assert!(
            ops.iter()
                .any(|op| matches!(op.kind, OperationKind::ReplaceSymlink))
        );
    }

    #[test]
    fn unmanaged_existing_target_is_blocked_instead_of_replaced() {
        let desired = DesiredTarget {
            package: "zsh".into(),
            source_rel: PathBuf::from("zsh/.zshrc"),
            source_abs: PathBuf::from("/repo/zsh/.zshrc"),
            target: PathBuf::from("/tmp/.zshrc"),
            kind: TargetKind::Symlink,
            mode: None,
            desired_hash: "abc".into(),
            rendered_text: None,
            render_cache_path: None,
        };

        let ops = match plan_for_target(
            &desired,
            None,
            &ObservedTarget::Symlink {
                target: PathBuf::from("/tmp/manual"),
            },
            true,
        ) {
            PlannedTarget::Ops(ops) => ops,
            PlannedTarget::Clean => panic!("expected blocked create"),
        };

        assert!(ops[0].blocked);
        assert!(matches!(ops[0].kind, OperationKind::CreateSymlink));
    }

    #[test]
    fn collisions_report_diagnostics_without_panicking_planning() {
        let desired = vec![
            DesiredTarget {
                package: "zsh".into(),
                source_rel: PathBuf::from("zsh/.zshrc"),
                source_abs: PathBuf::from("/repo/zsh/.zshrc"),
                target: PathBuf::from("/tmp/.shared"),
                kind: TargetKind::Symlink,
                mode: None,
                desired_hash: "a".into(),
                rendered_text: None,
                render_cache_path: None,
            },
            DesiredTarget {
                package: "git".into(),
                source_rel: PathBuf::from("git/.gitconfig"),
                source_abs: PathBuf::from("/repo/git/.gitconfig"),
                target: PathBuf::from("/tmp/.shared"),
                kind: TargetKind::Symlink,
                mode: None,
                desired_hash: "b".into(),
                rendered_text: None,
                render_cache_path: None,
            },
        ];

        let mut diagnostics = Vec::new();
        let map = detect_collisions(&desired, &Manifest::default(), &mut diagnostics).unwrap();

        assert_eq!(map.len(), 1);
        assert!(
            diagnostics
                .iter()
                .any(|diag| matches!(diag.severity, Severity::Error))
        );
    }

    #[test]
    fn copy_targets_schedule_mode_changes() {
        let desired = DesiredTarget {
            package: "assets".into(),
            source_rel: PathBuf::from("assets/wallpaper.png"),
            source_abs: PathBuf::from("/repo/assets/wallpaper.png"),
            target: PathBuf::from("/tmp/wallpaper.png"),
            kind: TargetKind::Copy,
            mode: Some(0o644),
            desired_hash: "abc".into(),
            rendered_text: None,
            render_cache_path: None,
        };

        let ops = match plan_for_target(&desired, None, &ObservedTarget::Missing, true) {
            PlannedTarget::Ops(ops) => ops,
            PlannedTarget::Clean => panic!("expected planned operations"),
        };

        assert!(
            ops.iter()
                .any(|op| matches!(op.kind, OperationKind::CreateCopy))
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op.kind, OperationKind::SetMode) && op.mode == Some(0o644))
        );
    }

    #[test]
    fn symlink_targets_do_not_schedule_mode_changes() {
        let desired = DesiredTarget {
            package: "zsh".into(),
            source_rel: PathBuf::from("zsh/.zshrc"),
            source_abs: PathBuf::from("/repo/zsh/.zshrc"),
            target: PathBuf::from("/tmp/.zshrc"),
            kind: TargetKind::Symlink,
            mode: Some(0o644),
            desired_hash: "abc".into(),
            rendered_text: None,
            render_cache_path: None,
        };

        let ops = match plan_for_target(&desired, None, &ObservedTarget::Missing, true) {
            PlannedTarget::Ops(ops) => ops,
            PlannedTarget::Clean => panic!("expected planned operations"),
        };

        assert!(
            ops.iter()
                .any(|op| matches!(op.kind, OperationKind::CreateSymlink))
        );
        assert!(
            ops.iter()
                .all(|op| !matches!(op.kind, OperationKind::SetMode))
        );
    }
}
