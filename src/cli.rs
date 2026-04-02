use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::config;
use crate::discover;
use crate::doctor;
use crate::executor;
use crate::planner::{self, Operation, OperationKind, Plan};
use crate::selectors::{RuntimeContext, RuntimeOs};
use crate::state;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliOs {
    Linux,
    Macos,
    Unix,
}

impl From<CliOs> for RuntimeOs {
    fn from(value: CliOs) -> Self {
        match value {
            CliOs::Linux => RuntimeOs::Linux,
            CliOs::Macos => RuntimeOs::Macos,
            CliOs::Unix => RuntimeOs::Unix,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "dot", about = "Unix-first ergonomic dotfile manager")]
pub struct Cli {
    #[arg(long, global = true)]
    repo: Option<PathBuf>,
    #[arg(long, global = true)]
    host: Option<String>,
    #[arg(long, global = true, hide = true)]
    os: Option<CliOs>,
    #[arg(long, short = 'v', action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    yes: bool,
    #[arg(long, global = true)]
    no_render_diff: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Plan { packages: Vec<String> },
    Apply { packages: Vec<String> },
    Status { packages: Vec<String> },
    Undeploy { packages: Vec<String> },
    Doctor { packages: Vec<String> },
}

#[derive(Debug, Serialize)]
struct StatusReport {
    clean: usize,
    pending_create: usize,
    pending_replace: usize,
    pending_remove: usize,
    blocked: usize,
    unmanaged_target_changes: usize,
    missing_source: usize,
    missing_target: usize,
    state_mismatch: usize,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose)?;

    let repo_root = cli
        .repo
        .clone()
        .unwrap_or(env::current_dir().context("get current working directory")?);
    let runtime = RuntimeContext::detect(cli.host.clone(), cli.os.map(Into::into));

    match &cli.command {
        Command::Init => init_repo(&repo_root),
        Command::Plan { packages } => {
            let plan = compute_plan(&repo_root, packages, &runtime, cli.no_render_diff)?;
            if cli.json {
                print_json(&plan)
            } else {
                print_plan(&plan);
                Ok(())
            }
        }
        Command::Apply { packages } => {
            apply(&repo_root, packages, &runtime, cli.no_render_diff, cli.yes)
        }
        Command::Status { packages } => {
            let plan = compute_plan(&repo_root, packages, &runtime, cli.no_render_diff)?;
            let report = status_report(&plan);
            if cli.json {
                print_json(&report)
            } else {
                print_status(&report);
                Ok(())
            }
        }
        Command::Doctor { packages } => {
            let plan = compute_plan(&repo_root, packages, &runtime, cli.no_render_diff)?;
            let report = doctor::diagnose(&plan)?;
            if cli.json {
                print_json(&report)
            } else {
                for diagnostic in report.diagnostics {
                    println!("{:?}: {}", diagnostic.severity, diagnostic.message);
                }
                Ok(())
            }
        }
        Command::Undeploy { packages } => undeploy(&repo_root, packages, cli.yes),
    }
}

fn init_logging(verbosity: u8) -> Result<()> {
    let level = match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    TermLogger::init(
        level,
        ConfigBuilder::new()
            .set_time_level(LevelFilter::Off)
            .set_thread_level(LevelFilter::Off)
            .set_target_level(LevelFilter::Off)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .ok();
    Ok(())
}

fn init_repo(repo_root: &Path) -> Result<()> {
    config::write_default_manifest(repo_root)?;
    config::append_gitignore_recommendations(repo_root)?;
    let (manifest, _) = config::load_manifest(repo_root)?;
    let cache_root = state::cache_root(repo_root)?;
    let runtime = RuntimeContext::detect(None, None);
    let discovery = discover::discover(repo_root, &manifest, &[], &runtime, &cache_root)?;
    println!("Initialized {}", repo_root.join("dot.toml").display());
    if discovery.packages.is_empty() {
        println!("No top-level package directories detected yet.");
    } else {
        println!("Detected packages:");
        for package in discovery.packages {
            println!("  - {package}");
        }
    }
    Ok(())
}

fn compute_plan(
    repo_root: &Path,
    packages: &[String],
    runtime: &RuntimeContext,
    no_render_diff: bool,
) -> Result<Plan> {
    let (manifest, _) = config::load_manifest(repo_root)?;
    let cache_root = state::cache_root(repo_root)?;
    let discovery = discover::discover(repo_root, &manifest, packages, runtime, &cache_root)?;
    let current_state = state::load(repo_root)?;
    planner::build_plan(&manifest, discovery, &current_state, no_render_diff)
}

fn apply(
    repo_root: &Path,
    packages: &[String],
    runtime: &RuntimeContext,
    no_render_diff: bool,
    yes: bool,
) -> Result<()> {
    let plan = compute_plan(repo_root, packages, runtime, no_render_diff)?;
    if plan_has_errors(&plan) {
        print_plan(&plan);
        bail!("refusing to apply a plan with validation errors");
    }
    if !yes && plan.operations.iter().any(|op| op.blocked) {
        print_plan(&plan);
        bail!("blocked operations require --yes");
    }
    executor::apply_plan(&plan, yes)?;
    let previous = state::load(repo_root)?;
    let new_state = executor::state_after_apply(state::repo_id(repo_root)?, &previous, &plan);
    state::save(repo_root, &new_state)?;
    print_plan(&plan);
    Ok(())
}

fn undeploy(repo_root: &Path, packages: &[String], yes: bool) -> Result<()> {
    let current_state = state::load(repo_root)?;
    let wanted = package_filter(packages);
    let mut operations = Vec::new();
    for entry in &current_state.entries {
        if !wanted.is_empty() && !wanted.contains_key(&entry.package) {
            continue;
        }
        operations.push(Operation {
            kind: match entry.kind {
                crate::config::TargetKind::Symlink => OperationKind::RemoveSymlink,
                crate::config::TargetKind::Copy => OperationKind::RemoveCopy,
                crate::config::TargetKind::Render => OperationKind::RemoveRender,
            },
            package: Some(entry.package.clone()),
            target: PathBuf::from(&entry.target),
            source: None,
            source_rel: Some(PathBuf::from(&entry.source_rel)),
            content_hash: Some(entry.content_hash.clone()),
            requires_privilege: crate::fs::parent_requires_privilege(Path::new(&entry.target)),
            blocked: false,
            reason: None,
            diff: None,
            mode: None,
        });
    }
    let plan = Plan {
        summary: planner::PlanSummary {
            remove: operations.len(),
            ..planner::PlanSummary::default()
        },
        diagnostics: Vec::new(),
        operations,
    };
    executor::apply_plan(&plan, yes)?;
    let mut next = current_state.clone();
    next.entries
        .retain(|entry| wanted.is_empty() || !wanted.contains_key(&entry.package));
    state::save(repo_root, &next)?;
    print_plan(&plan);
    Ok(())
}

fn status_report(plan: &Plan) -> StatusReport {
    let mut report = StatusReport {
        clean: plan.summary.clean,
        pending_create: 0,
        pending_replace: 0,
        pending_remove: 0,
        blocked: plan.summary.blocked,
        unmanaged_target_changes: 0,
        missing_source: 0,
        missing_target: 0,
        state_mismatch: 0,
    };

    for diagnostic in &plan.diagnostics {
        if diagnostic.message.contains("missing source") {
            report.missing_source += 1;
        }
    }

    for op in &plan.operations {
        match op.kind {
            OperationKind::CreateSymlink
            | OperationKind::CreateCopy
            | OperationKind::CreateRender => {
                report.pending_create += 1;
                if matches!(
                    op.reason.as_deref(),
                    Some("target exists with unmanaged changes")
                ) {
                    report.unmanaged_target_changes += 1;
                } else {
                    report.missing_target += 1;
                }
            }
            OperationKind::ReplaceSymlink
            | OperationKind::ReplaceCopy
            | OperationKind::ReplaceRender => {
                report.pending_replace += 1;
                if matches!(
                    op.reason.as_deref(),
                    Some("target exists with unmanaged changes")
                ) {
                    report.unmanaged_target_changes += 1;
                }
            }
            OperationKind::RemoveSymlink
            | OperationKind::RemoveCopy
            | OperationKind::RemoveRender => {
                report.pending_remove += 1;
                if matches!(
                    op.reason.as_deref(),
                    Some("managed target drifted since last apply")
                ) {
                    report.state_mismatch += 1;
                }
            }
            _ => {}
        }
    }

    report
}

fn print_plan(plan: &Plan) {
    for diagnostic in &plan.diagnostics {
        println!("{:?}: {}", diagnostic.severity, diagnostic.message);
    }
    for op in &plan.operations {
        let blocked = if op.blocked { " [blocked]" } else { "" };
        let detail = op
            .reason
            .as_ref()
            .map(|reason| format!(" ({reason})"))
            .unwrap_or_default();
        println!("{:?} {}{}{}", op.kind, op.target.display(), blocked, detail);
        if let Some(diff) = &op.diff {
            println!("{diff}");
        }
    }
    println!(
        "summary: create={} replace={} remove={} blocked={} clean={}",
        plan.summary.create,
        plan.summary.replace,
        plan.summary.remove,
        plan.summary.blocked,
        plan.summary.clean
    );
}

fn print_status(report: &StatusReport) {
    println!("clean: {}", report.clean);
    println!("pending create: {}", report.pending_create);
    println!("pending replace: {}", report.pending_replace);
    println!("pending remove: {}", report.pending_remove);
    println!("blocked: {}", report.blocked);
    println!(
        "unmanaged target changes: {}",
        report.unmanaged_target_changes
    );
    println!("missing source: {}", report.missing_source);
    println!("missing target: {}", report.missing_target);
    println!("state mismatch: {}", report.state_mismatch);
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).context("serialize json output")?
    );
    Ok(())
}

fn package_filter(packages: &[String]) -> BTreeMap<String, ()> {
    packages
        .iter()
        .cloned()
        .map(|package| (package, ()))
        .collect()
}

fn plan_has_errors(plan: &Plan) -> bool {
    plan.diagnostics
        .iter()
        .any(|diagnostic| matches!(diagnostic.severity, planner::Severity::Error))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn status_report_distinguishes_drift_and_missing_sources() {
        let plan = Plan {
            operations: vec![
                Operation {
                    kind: OperationKind::CreateRender,
                    package: Some("git".into()),
                    target: PathBuf::from("/tmp/.config/git/config"),
                    source: Some(PathBuf::from("/repo/git/.config/git/config.tmpl")),
                    source_rel: Some(PathBuf::from("git/.config/git/config.tmpl")),
                    content_hash: Some("abc".into()),
                    requires_privilege: false,
                    blocked: true,
                    reason: Some("target exists with unmanaged changes".into()),
                    diff: None,
                    mode: Some(0o644),
                },
                Operation {
                    kind: OperationKind::RemoveCopy,
                    package: Some("assets".into()),
                    target: PathBuf::from("/tmp/wallpaper.png"),
                    source: None,
                    source_rel: Some(PathBuf::from("assets/wallpaper.png")),
                    content_hash: Some("def".into()),
                    requires_privilege: false,
                    blocked: true,
                    reason: Some("managed target drifted since last apply".into()),
                    diff: None,
                    mode: None,
                },
            ],
            diagnostics: vec![planner::Diagnostic::error(
                "package \"git\" references missing source git/.config/git/config.tmpl",
            )],
            summary: planner::PlanSummary {
                blocked: 2,
                ..planner::PlanSummary::default()
            },
        };

        let report = status_report(&plan);
        assert_eq!(report.blocked, 2);
        assert_eq!(report.unmanaged_target_changes, 1);
        assert_eq!(report.missing_source, 1);
        assert_eq!(report.state_mismatch, 1);
    }
}
