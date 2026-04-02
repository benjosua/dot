use anyhow::{Context, Result, bail};
use sha2::Digest;
use std::fs as stdfs;
use std::path::PathBuf;

use crate::config::TargetKind;
use crate::fs as dotfs;
use crate::planner::{Operation, OperationKind, Plan};
use crate::privilege;
use crate::state::{StateEntry, StateFile};

pub fn apply_plan(plan: &Plan, yes: bool) -> Result<()> {
    if plan.operations.iter().any(|op| op.blocked) && !yes {
        bail!("plan contains blocked operations; rerun with --yes to overwrite unmanaged drift");
    }

    if plan.operations.iter().any(|op| op.requires_privilege) {
        privilege::ensure_sudo_session()?;
    }

    for op in &plan.operations {
        execute_operation(op)?;
    }

    Ok(())
}

pub fn build_state_entries(plan: &Plan) -> Vec<StateEntry> {
    let mut entries = Vec::new();
    for op in &plan.operations {
        let Some(package) = &op.package else {
            continue;
        };
        let Some(source) = &op.source else {
            continue;
        };

        let kind = match op.kind {
            OperationKind::CreateSymlink | OperationKind::ReplaceSymlink => TargetKind::Symlink,
            OperationKind::CreateCopy | OperationKind::ReplaceCopy => TargetKind::Copy,
            OperationKind::CreateRender | OperationKind::ReplaceRender => TargetKind::Render,
            _ => continue,
        };

        let hash = match kind {
            TargetKind::Symlink => op.content_hash.clone().unwrap_or_else(|| {
                hex::encode(sha2::Sha256::digest(
                    source.display().to_string().as_bytes(),
                ))
            }),
            _ => dotfs::inspect_target(&op.target)
                .ok()
                .and_then(|observed| match observed {
                    dotfs::ObservedTarget::File { hash, .. } => Some(hash),
                    _ => None,
                })
                .or_else(|| op.content_hash.clone())
                .unwrap_or_default(),
        };

        entries.push(StateEntry {
            package: package.clone(),
            source_rel: op
                .source_rel
                .as_ref()
                .unwrap_or(source)
                .display()
                .to_string(),
            target: op.target.display().to_string(),
            kind,
            content_hash: hash,
            mode: op.mode,
        });
    }
    entries
}

pub fn state_after_apply(repo_id: String, previous: &StateFile, plan: &Plan) -> StateFile {
    let mut by_target = previous.by_target();

    for op in &plan.operations {
        match op.kind {
            OperationKind::RemoveSymlink
            | OperationKind::RemoveCopy
            | OperationKind::RemoveRender => {
                by_target.remove(&op.target);
            }
            _ => {}
        }
    }

    for entry in build_state_entries(plan) {
        by_target.insert(PathBuf::from(&entry.target), entry);
    }

    StateFile {
        repo_id,
        entries: by_target.into_values().collect(),
    }
}

fn execute_operation(op: &Operation) -> Result<()> {
    if matches!(op.kind, OperationKind::PrivilegedStat) {
        return Ok(());
    }

    match op.kind {
        OperationKind::EnsureDir => {
            if op.requires_privilege {
                privilege::run_privileged_command(
                    "mkdir",
                    &[String::from("-p"), privilege::path_arg(&op.target)],
                )?;
            } else {
                dotfs::ensure_dir(&op.target)?;
            }
        }
        OperationKind::CreateSymlink | OperationKind::ReplaceSymlink => {
            if op.blocked || matches!(op.kind, OperationKind::ReplaceSymlink) {
                remove_existing(&op.target, op.requires_privilege)?;
            }
            let source = op.source.as_ref().context("symlink op missing source")?;
            if op.requires_privilege {
                privilege::run_privileged_command(
                    "ln",
                    &[
                        String::from("-sfn"),
                        privilege::path_arg(source),
                        privilege::path_arg(&op.target),
                    ],
                )?;
            } else {
                dotfs::create_symlink(&op.target, source)?;
            }
        }
        OperationKind::CreateCopy | OperationKind::ReplaceCopy => {
            if op.blocked || matches!(op.kind, OperationKind::ReplaceCopy) {
                remove_existing(&op.target, op.requires_privilege)?;
            }
            let source = op.source.as_ref().context("copy op missing source")?;
            if op.requires_privilege {
                privilege::run_privileged_command(
                    "cp",
                    &[privilege::path_arg(source), privilege::path_arg(&op.target)],
                )?;
            } else {
                dotfs::copy_file(source, &op.target)?;
            }
        }
        OperationKind::CreateRender | OperationKind::ReplaceRender => {
            if op.blocked || matches!(op.kind, OperationKind::ReplaceRender) {
                remove_existing(&op.target, op.requires_privilege)?;
            }
            let source = op.source.as_ref().context("render op missing source")?;
            if op.requires_privilege {
                privilege::run_privileged_command(
                    "cp",
                    &[privilege::path_arg(source), privilege::path_arg(&op.target)],
                )?;
            } else {
                dotfs::copy_file(source, &op.target)?;
            }
        }
        OperationKind::RemoveSymlink | OperationKind::RemoveCopy | OperationKind::RemoveRender => {
            remove_existing(&op.target, op.requires_privilege)?;
        }
        OperationKind::SetMode => {
            let mode = op.mode.context("mode op missing mode")?;
            if op.requires_privilege {
                privilege::run_privileged_command(
                    "chmod",
                    &[format!("{mode:o}"), privilege::path_arg(&op.target)],
                )?;
            } else {
                dotfs::set_mode(&op.target, mode)?;
            }
        }
        OperationKind::PrivilegedStat => {}
    }

    Ok(())
}

fn remove_existing(target: &std::path::Path, requires_privilege: bool) -> Result<()> {
    if requires_privilege {
        privilege::run_privileged_command("rm", &[String::from("-rf"), privilege::path_arg(target)])
    } else {
        match stdfs::symlink_metadata(target) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                stdfs::remove_dir_all(target)
                    .with_context(|| format!("remove {}", target.display()))
            }
            Ok(_) => {
                stdfs::remove_file(target).with_context(|| format!("remove {}", target.display()))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("remove {}", target.display())),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::planner::{Operation, OperationKind, Plan, PlanSummary};

    #[test]
    fn state_after_apply_tracks_repo_relative_source_for_render_targets() {
        let plan = Plan {
            operations: vec![Operation {
                kind: OperationKind::CreateRender,
                package: Some("git".into()),
                target: PathBuf::from("/tmp/.config/git/config"),
                source: Some(PathBuf::from("/cache/rendered/abc.txt")),
                source_rel: Some(PathBuf::from("git/.config/git/config.tmpl")),
                content_hash: Some("rendered-hash".into()),
                requires_privilege: false,
                blocked: false,
                reason: None,
                diff: None,
                mode: Some(0o644),
            }],
            diagnostics: Vec::new(),
            summary: PlanSummary::default(),
        };

        let state = state_after_apply(
            "repo".into(),
            &StateFile {
                repo_id: "repo".into(),
                entries: Vec::new(),
            },
            &plan,
        );

        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].source_rel, "git/.config/git/config.tmpl");
        assert_eq!(state.entries[0].content_hash, "rendered-hash");
    }

    #[test]
    fn state_after_apply_removes_deleted_targets() {
        let previous = StateFile {
            repo_id: "repo".into(),
            entries: vec![StateEntry {
                package: "zsh".into(),
                source_rel: "zsh/.zshrc".into(),
                target: "/tmp/.zshrc".into(),
                kind: TargetKind::Symlink,
                content_hash: "old".into(),
                mode: None,
            }],
        };
        let plan = Plan {
            operations: vec![Operation {
                kind: OperationKind::RemoveSymlink,
                package: Some("zsh".into()),
                target: PathBuf::from("/tmp/.zshrc"),
                source: None,
                source_rel: Some(PathBuf::from("zsh/.zshrc")),
                content_hash: Some("old".into()),
                requires_privilege: false,
                blocked: false,
                reason: None,
                diff: None,
                mode: None,
            }],
            diagnostics: Vec::new(),
            summary: PlanSummary::default(),
        };

        let state = state_after_apply("repo".into(), &previous, &plan);
        assert!(state.entries.is_empty());
    }

    #[test]
    fn apply_plan_overwrites_blocked_symlinks_when_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.txt");
        let target = dir.path().join("target.txt");
        stdfs::write(&source, "managed").unwrap();
        stdfs::write(&target, "manual").unwrap();

        let plan = Plan {
            operations: vec![Operation {
                kind: OperationKind::CreateSymlink,
                package: Some("zsh".into()),
                target: target.clone(),
                source: Some(source.clone()),
                source_rel: Some(PathBuf::from("zsh/.zshrc")),
                content_hash: Some("abc".into()),
                requires_privilege: false,
                blocked: true,
                reason: Some("target exists with unmanaged changes".into()),
                diff: None,
                mode: None,
            }],
            diagnostics: Vec::new(),
            summary: PlanSummary {
                blocked: 1,
                ..PlanSummary::default()
            },
        };

        apply_plan(&plan, true).unwrap();

        let metadata = stdfs::symlink_metadata(&target).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert_eq!(stdfs::read_link(&target).unwrap(), source);
    }
}
