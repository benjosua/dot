use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

pub fn ensure_sudo_session() -> Result<()> {
    let status = Command::new("sudo")
        .arg("-v")
        .status()
        .context("start sudo session")?;
    if status.success() {
        Ok(())
    } else {
        bail!("sudo session failed")
    }
}

pub fn run_privileged_command(program: &str, args: &[String]) -> Result<()> {
    let status = Command::new("sudo")
        .arg(program)
        .args(args)
        .status()
        .with_context(|| format!("run privileged command {program}"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("privileged command {program} failed")
    }
}

pub fn path_arg(path: &Path) -> String {
    path.display().to_string()
}
