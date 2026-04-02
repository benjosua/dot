use anyhow::Result;
use serde::Serialize;

use crate::planner::{Diagnostic, Plan, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub diagnostics: Vec<Diagnostic>,
    pub has_errors: bool,
}

pub fn diagnose(plan: &Plan) -> Result<DoctorReport> {
    let mut diagnostics = plan.diagnostics.clone();
    if plan.summary.blocked > 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "{} blocked operations need confirmation or cleanup",
                plan.summary.blocked
            ),
        });
    }
    if plan.summary.privileged_stat > 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Info,
            message: format!(
                "{} target(s) need privileged inspection before dot can confirm state",
                plan.summary.privileged_stat
            ),
        });
    }
    if plan.summary.skipped_privileged > 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "{} operation(s) were skipped because privilege is disabled",
                plan.summary.skipped_privileged
            ),
        });
    }
    if plan.summary.merge_required > 0 {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            message: format!(
                "{} operation(s) require a manual merge before dot can continue",
                plan.summary.merge_required
            ),
        });
    }
    if plan.operations.is_empty() && plan.summary.clean == 0 && diagnostics.is_empty() {
        diagnostics.push(Diagnostic::warning(
            "no managed packages were discovered; check your repo layout or selected packages",
        ));
    } else if plan.operations.is_empty() && diagnostics.is_empty() {
        diagnostics.push(Diagnostic::info("no problems detected"));
    }
    let has_errors = diagnostics
        .iter()
        .any(|diag| matches!(diag.severity, Severity::Error));
    Ok(DoctorReport {
        diagnostics,
        has_errors,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::planner::{Plan, PlanSummary};

    #[test]
    fn doctor_warns_when_no_packages_are_discovered() {
        let report = diagnose(&Plan {
            operations: Vec::new(),
            diagnostics: Vec::new(),
            summary: PlanSummary::default(),
        })
        .unwrap();

        assert!(
            report
                .diagnostics
                .iter()
                .any(|diag| diag.message.contains("no managed packages"))
        );
    }

    #[test]
    fn doctor_reports_clean_workspace_when_everything_is_healthy() {
        let report = diagnose(&Plan {
            operations: Vec::new(),
            diagnostics: Vec::new(),
            summary: PlanSummary {
                clean: 2,
                ..PlanSummary::default()
            },
        })
        .unwrap();

        assert!(
            report
                .diagnostics
                .iter()
                .any(|diag| diag.message == "no problems detected")
        );
    }
}
