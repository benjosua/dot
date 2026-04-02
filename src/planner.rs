use anyhow::Result;
use serde::Serialize;
use sha2::Digest;
use std::fs;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::config::{
    CollisionPolicy, ConflictAction, ConflictOverrides, ConflictRules, Manifest, PrivilegeAction,
    TargetKind, resolve_conflict_rules,
};
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    UnmanagedExisting,
    ManagedDrift,
    PrivilegedPackage,
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
    pub skipped: bool,
    pub reason: Option<String>,
    pub diff: Option<String>,
    pub conflict_kind: Option<ConflictKind>,
    pub merge_command: Option<String>,
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
    pub skipped_privileged: usize,
    pub merge_required: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub operations: Vec<Operation>,
    pub diagnostics: Vec<Diagnostic>,
    pub summary: PlanSummary,
}

#[derive(Debug, Clone, Default)]
pub struct PlanOptions {
    pub no_render_diff: bool,
    pub conflict_overrides: ConflictOverrides,
}

pub fn build_plan(
    manifest: &Manifest,
    discovery: DiscoveryResult,
    state: &StateFile,
    options: &PlanOptions,
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
        let rules = resolve_conflict_rules(
            manifest,
            &entry.package,
            Some(Path::new(&entry.source_rel)),
            &options.conflict_overrides,
        );
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
                skipped: false,
                reason: Some("target is unreadable without privilege".into()),
                diff: None,
                conflict_kind: None,
                merge_command: None,
                mode: None,
            });
            summary.privileged_stat += 1;
        }

        let removal = removal_from_state(entry, &observed, &rules);
        operations.push(Operation {
            kind: removal.kind,
            package: Some(entry.package.clone()),
            target: target.clone(),
            source: None,
            source_rel: Some(PathBuf::from(&entry.source_rel)),
            content_hash: Some(entry.content_hash.clone()),
            requires_privilege: parent_requires_privilege(target),
            blocked: removal.blocked,
            skipped: false,
            reason: removal.reason,
            diff: removal.diff,
            conflict_kind: removal.conflict_kind,
            merge_command: removal.merge_command,
            mode: None,
        });
        summary.remove += 1;
        if removal.blocked {
            summary.blocked += 1;
        }
        if removal.merge_required {
            summary.merge_required += 1;
        }
    }

    for (target, desired) in desired_by_target {
        let rules = resolve_conflict_rules(
            manifest,
            &desired.package,
            Some(&desired.source_rel),
            &options.conflict_overrides,
        );
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
                skipped: false,
                reason: Some("target is unreadable without privilege".into()),
                diff: None,
                conflict_kind: None,
                merge_command: None,
                mode: None,
            });
            summary.privileged_stat += 1;
        }

        let planned = plan_for_target(&desired, state_entry, &observed, &rules, options);
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
                    if is_merge_required(op) {
                        summary.merge_required += 1;
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

    apply_privilege_policy(
        manifest,
        &options.conflict_overrides,
        &mut operations,
        &mut diagnostics,
        &mut summary,
    );

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

struct RemovalPlan {
    kind: OperationKind,
    blocked: bool,
    reason: Option<String>,
    diff: Option<String>,
    conflict_kind: Option<ConflictKind>,
    merge_command: Option<String>,
    merge_required: bool,
}

fn plan_for_target(
    desired: &DesiredTarget,
    state_entry: Option<&StateEntry>,
    observed: &ObservedTarget,
    rules: &ConflictRules,
    options: &PlanOptions,
) -> PlannedTarget {
    if current_matches_desired(desired, observed) {
        return PlannedTarget::Clean;
    }

    let observed_exists = matches!(
        observed,
        ObservedTarget::Directory | ObservedTarget::File { .. } | ObservedTarget::Symlink { .. }
    );
    let managed_current = state_entry.is_some_and(|entry| current_matches_state(entry, observed));
    let managed_drift = state_entry.is_some() && observed_exists && !managed_current;
    if managed_drift {
        if matches!(rules.managed, ConflictAction::Overwrite) {
            return planned_write_ops(desired, observed, None, options);
        }
        return PlannedTarget::Ops(vec![blocked_desired_operation(
            desired,
            observed,
            ConflictKind::ManagedDrift,
            rules.managed,
            options,
            true,
            rules.merge_tool.as_deref(),
        )]);
    }

    let unmanaged_exists = state_entry.is_none() && observed_exists;
    if unmanaged_exists {
        if matches!(rules.unmanaged, ConflictAction::Overwrite) {
            return planned_write_ops(desired, observed, None, options);
        }
        return PlannedTarget::Ops(vec![blocked_desired_operation(
            desired,
            observed,
            ConflictKind::UnmanagedExisting,
            rules.unmanaged,
            options,
            false,
            rules.merge_tool.as_deref(),
        )]);
    }

    planned_write_ops(desired, observed, state_entry, options)
}

fn planned_write_ops(
    desired: &DesiredTarget,
    observed: &ObservedTarget,
    _state_entry: Option<&StateEntry>,
    options: &PlanOptions,
) -> PlannedTarget {
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
        skipped: false,
        reason: None,
        diff: None,
        conflict_kind: None,
        merge_command: None,
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
        skipped: false,
        reason: None,
        diff: desired_diff(desired, observed, options.no_render_diff),
        conflict_kind: None,
        merge_command: None,
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
            skipped: false,
            reason: None,
            diff: None,
            conflict_kind: None,
            merge_command: None,
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
    rules: &ConflictRules,
) -> RemovalPlan {
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
        return RemovalPlan {
            kind,
            blocked: false,
            reason: None,
            diff: None,
            conflict_kind: None,
            merge_command: None,
            merge_required: false,
        };
    }

    if matches!(rules.managed, ConflictAction::Overwrite) {
        return RemovalPlan {
            kind,
            blocked: false,
            reason: None,
            diff: None,
            conflict_kind: None,
            merge_command: None,
            merge_required: false,
        };
    }

    RemovalPlan {
        kind,
        blocked: true,
        reason: Some(blocked_reason(
            ConflictKind::ManagedDrift,
            rules.managed,
            false,
        )),
        diff: None,
        conflict_kind: Some(ConflictKind::ManagedDrift),
        merge_command: None,
        merge_required: matches!(rules.managed, ConflictAction::Merge),
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

fn desired_diff(
    desired: &DesiredTarget,
    observed: &ObservedTarget,
    no_render_diff: bool,
) -> Option<String> {
    let after = desired_text(desired, no_render_diff)?;
    match observed {
        ObservedTarget::File {
            text: Some(before), ..
        } => Some(crate::render::text_diff(before, &after)),
        ObservedTarget::Missing => Some(crate::render::text_diff("", &after)),
        _ => None,
    }
}

fn desired_text(desired: &DesiredTarget, no_render_diff: bool) -> Option<String> {
    match desired.kind {
        TargetKind::Copy => fs::read_to_string(&desired.source_abs).ok(),
        TargetKind::Render => {
            if no_render_diff {
                None
            } else {
                desired.rendered_text.clone()
            }
        }
        TargetKind::Symlink => None,
    }
}

fn blocked_desired_operation(
    desired: &DesiredTarget,
    observed: &ObservedTarget,
    conflict_kind: ConflictKind,
    action: ConflictAction,
    options: &PlanOptions,
    use_replace_kind: bool,
    merge_tool: Option<&str>,
) -> Operation {
    let mergeable = is_mergeable(desired, observed, options.no_render_diff);
    Operation {
        kind: if use_replace_kind {
            replace_kind_for(desired.kind)
        } else {
            create_kind_for(desired.kind)
        },
        package: Some(desired.package.clone()),
        target: desired.target.clone(),
        source: operation_source(desired),
        source_rel: Some(desired.source_rel.clone()),
        content_hash: Some(desired.desired_hash.clone()),
        requires_privilege: false,
        blocked: true,
        skipped: false,
        reason: Some(blocked_reason(conflict_kind.clone(), action, mergeable)),
        diff: desired_diff(desired, observed, options.no_render_diff),
        conflict_kind: Some(conflict_kind),
        merge_command: merge_command(desired, observed, merge_tool, options.no_render_diff),
        mode: desired.mode,
    }
}

fn blocked_reason(conflict_kind: ConflictKind, action: ConflictAction, mergeable: bool) -> String {
    let (subject, policy, flag) = match conflict_kind {
        ConflictKind::UnmanagedExisting => (
            "target exists with unmanaged changes",
            "conflicts.unmanaged",
            "--overwrite-unmanaged",
        ),
        ConflictKind::ManagedDrift => (
            "managed target drifted since last apply",
            "conflicts.managed",
            "--overwrite-drift",
        ),
        ConflictKind::PrivilegedPackage => (
            "package requires privilege",
            "conflicts.privileged",
            "--allow-privileged",
        ),
    };

    match action {
        ConflictAction::Block => {
            format!("{subject}; {policy}=block (use {flag} or set {policy}=\"overwrite\")")
        }
        ConflictAction::Merge if mergeable => {
            format!("{subject}; {policy}=merge requires manual merge")
        }
        ConflictAction::Merge => {
            format!("{subject}; {policy}=merge requested but this target is not mergeable")
        }
        ConflictAction::Overwrite => subject.to_string(),
    }
}

fn is_mergeable(desired: &DesiredTarget, observed: &ObservedTarget, no_render_diff: bool) -> bool {
    desired_text(desired, no_render_diff).is_some()
        && matches!(
            observed,
            ObservedTarget::File {
                text: Some(_), ..
            }
        )
}

fn merge_command(
    desired: &DesiredTarget,
    observed: &ObservedTarget,
    merge_tool: Option<&str>,
    no_render_diff: bool,
) -> Option<String> {
    if !is_mergeable(desired, observed, no_render_diff) {
        return None;
    }
    let desired_path = operation_source(desired)?;
    merge_tool.map(|tool| {
        format!(
            "{tool} {} {}",
            desired.target.display(),
            desired_path.display()
        )
    })
}

fn is_merge_required(op: &Operation) -> bool {
    op.blocked
        && matches!(
            op.reason.as_deref(),
            Some(reason) if reason.contains("requires manual merge")
                || reason.contains("merge requested")
        )
}

fn apply_privilege_policy(
    manifest: &Manifest,
    overrides: &ConflictOverrides,
    operations: &mut [Operation],
    diagnostics: &mut Vec<Diagnostic>,
    summary: &mut PlanSummary,
) {
    let mut packages_to_skip = BTreeSet::new();

    for op in operations.iter().filter(|op| op.requires_privilege) {
        let Some(package) = &op.package else {
            continue;
        };
        let rules = resolve_conflict_rules(
            manifest,
            package,
            op.source_rel.as_deref(),
            overrides,
        );
        if matches!(rules.privileged, PrivilegeAction::SkipPackage) {
            packages_to_skip.insert(package.clone());
        }
    }

    for package in packages_to_skip {
        let mut skipped_any = false;
        for op in operations.iter_mut().filter(|op| op.package.as_deref() == Some(&package)) {
            if op.skipped {
                continue;
            }
            if op.blocked {
                summary.blocked = summary.blocked.saturating_sub(1);
                if is_merge_required(op) {
                    summary.merge_required = summary.merge_required.saturating_sub(1);
                }
            }
            op.skipped = true;
            op.blocked = false;
            op.reason = Some(
                "package skipped because privilege is disabled (use --allow-privileged or set conflicts.privileged=\"apply\")"
                    .into(),
            );
            op.conflict_kind = Some(ConflictKind::PrivilegedPackage);
            op.merge_command = None;
            summary.skipped_privileged += 1;
            skipped_any = true;
        }
        if skipped_any {
            diagnostics.push(Diagnostic::warning(format!(
                "package {package:?} was skipped because at least one target requires privilege"
            )));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::{ConflictAction, TargetKind};
    use crate::discover::DesiredTarget;
    use tempfile::tempdir;

    fn default_rules() -> ConflictRules {
        ConflictRules::default()
    }

    fn default_options() -> PlanOptions {
        PlanOptions::default()
    }

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
            &default_rules(),
            &default_options(),
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
            &default_rules(),
            &default_options(),
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

        let ops = match plan_for_target(
            &desired,
            None,
            &ObservedTarget::Missing,
            &default_rules(),
            &default_options(),
        ) {
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

        let ops = match plan_for_target(
            &desired,
            None,
            &ObservedTarget::Missing,
            &default_rules(),
            &default_options(),
        ) {
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

    #[test]
    fn unmanaged_overwrite_policy_allows_replace() {
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
        let rules = ConflictRules {
            unmanaged: ConflictAction::Overwrite,
            ..ConflictRules::default()
        };

        let ops = match plan_for_target(
            &desired,
            None,
            &ObservedTarget::Symlink {
                target: PathBuf::from("/tmp/manual"),
            },
            &rules,
            &default_options(),
        ) {
            PlannedTarget::Ops(ops) => ops,
            PlannedTarget::Clean => panic!("expected planned operations"),
        };

        assert!(
            ops.iter()
                .any(|op| matches!(op.kind, OperationKind::ReplaceSymlink))
        );
        assert!(ops.iter().all(|op| !op.blocked));
    }

    #[test]
    fn managed_merge_policy_blocks_with_merge_guidance_for_text_files() {
        let dir = tempdir().unwrap();
        let desired = DesiredTarget {
            package: "git".into(),
            source_rel: PathBuf::from("git/.gitconfig"),
            source_abs: dir.path().join(".gitconfig"),
            target: PathBuf::from("/tmp/.gitconfig"),
            kind: TargetKind::Copy,
            mode: None,
            desired_hash: "abc".into(),
            rendered_text: None,
            render_cache_path: None,
        };
        fs::write(&desired.source_abs, "[user]\nemail = new@example.test\n").unwrap();
        let state = StateEntry {
            package: "git".into(),
            source_rel: "git/.gitconfig".into(),
            target: "/tmp/.gitconfig".into(),
            kind: TargetKind::Copy,
            content_hash: "old".into(),
            mode: None,
        };
        let rules = ConflictRules {
            managed: ConflictAction::Merge,
            merge_tool: Some("opendiff".into()),
            ..ConflictRules::default()
        };

        let ops = match plan_for_target(
            &desired,
            Some(&state),
            &ObservedTarget::File {
                hash: "other".into(),
                text: Some("[user]\nemail = old@example.test\n".into()),
                mode: 0o644,
            },
            &rules,
            &default_options(),
        ) {
            PlannedTarget::Ops(ops) => ops,
            PlannedTarget::Clean => panic!("expected blocked operations"),
        };

        assert!(ops[0].blocked);
        assert_eq!(ops[0].conflict_kind, Some(ConflictKind::ManagedDrift));
        assert!(ops[0].diff.as_deref().is_some_and(|diff| diff.contains("-email = old")));
        let expected = format!("opendiff /tmp/.gitconfig {}", desired.source_abs.display());
        assert_eq!(ops[0].merge_command.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn skip_privilege_policy_marks_whole_package_skipped() {
        let mut operations = vec![
            Operation {
                kind: OperationKind::EnsureDir,
                package: Some("sys".into()),
                target: PathBuf::from("/root/.config"),
                source: None,
                source_rel: None,
                content_hash: None,
                requires_privilege: true,
                blocked: false,
                skipped: false,
                reason: None,
                diff: None,
                conflict_kind: None,
                merge_command: None,
                mode: None,
            },
            Operation {
                kind: OperationKind::CreateCopy,
                package: Some("sys".into()),
                target: PathBuf::from("/root/.config/app"),
                source: Some(PathBuf::from("/repo/sys/app")),
                source_rel: Some(PathBuf::from("sys/app")),
                content_hash: Some("abc".into()),
                requires_privilege: true,
                blocked: false,
                skipped: false,
                reason: None,
                diff: None,
                conflict_kind: None,
                merge_command: None,
                mode: None,
            },
        ];
        let manifest = Manifest::default();
        let mut diagnostics = Vec::new();
        let mut summary = PlanSummary::default();

        apply_privilege_policy(
            &manifest,
            &ConflictOverrides::default(),
            &mut operations,
            &mut diagnostics,
            &mut summary,
        );

        assert!(operations.iter().all(|op| op.skipped));
        assert!(operations.iter().all(|op| !op.blocked));
        assert_eq!(summary.skipped_privileged, 2);
        assert_eq!(operations[0].conflict_kind, Some(ConflictKind::PrivilegedPackage));
        assert!(!diagnostics.is_empty());
    }
}
