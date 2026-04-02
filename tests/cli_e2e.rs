use serde_json::Value;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct TestEnv {
    _temp: TempDir,
    repo: PathBuf,
    home: PathBuf,
    state: PathBuf,
    cache: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("repo");
        let home = temp.path().join("home");
        let state = temp.path().join("state");
        let cache = temp.path().join("cache");
        fs::create_dir_all(&repo).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&cache).unwrap();
        Self {
            _temp: temp,
            repo,
            home,
            state,
            cache,
        }
    }

    fn run_success(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "command failed: {}\nstdout:\n{}\nstderr:\n{}",
            self.render_command(args),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn run_failure(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            !output.status.success(),
            "command unexpectedly succeeded: {}\nstdout:\n{}\nstderr:\n{}",
            self.render_command(args),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn run_json(&self, args: &[&str]) -> Value {
        let output = self.run_success(args);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_dot"))
            .args(["--repo", self.repo.to_str().unwrap()])
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_CACHE_HOME", &self.cache)
            .output()
            .unwrap()
    }

    fn run_with_path(&self, args: &[&str], path_prefix: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_dot"))
            .args(["--repo", self.repo.to_str().unwrap()])
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_STATE_HOME", &self.state)
            .env("XDG_CACHE_HOME", &self.cache)
            .env(
                "PATH",
                format!("{}:{}", path_prefix.display(), env::var("PATH").unwrap()),
            )
            .output()
            .unwrap()
    }

    fn render_command(&self, args: &[&str]) -> String {
        let mut parts = vec![
            env!("CARGO_BIN_EXE_dot").to_string(),
            "--repo".to_string(),
            self.repo.display().to_string(),
        ];
        parts.extend(args.iter().map(|arg| arg.to_string()));
        parts.join(" ")
    }
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn state_file_path(state_root: &Path) -> PathBuf {
    let repo_state_root = fs::read_dir(state_root.join("dot/repos"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    repo_state_root.join("state.json")
}

fn install_fake_sudo(bin_dir: &Path) {
    let sudo = bin_dir.join("sudo");
    write(
        &sudo,
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${1:-}\" == \"-v\" ]]; then\n  exit 0\nfi\ncmd=\"$1\"\nshift\nif [[ \"$#\" -gt 0 ]]; then\n  target=\"${!#}\"\n  if [[ -n \"$target\" ]]; then\n    chmod u+w \"$(dirname \"$target\")\" 2>/dev/null || true\n  fi\nfi\nexec \"$cmd\" \"$@\"\n",
    );
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn init_succeeds_when_repo_contains_templates() {
    let env = TestEnv::new();
    write(
        &env.repo.join("git/.config/git/config.tmpl"),
        "[user]\nemail = \"{{email}}\"\n",
    );

    let output = env.run_success(&["init"]);
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(env.repo.join("dot.toml").exists());
    assert!(stdout.contains("Initialized"));
    assert!(stdout.contains("Detected packages:"));
    assert!(stdout.contains("git"));
}

#[test]
fn full_cli_flow_applies_reports_and_undeploys() {
    let env = TestEnv::new();
    write(&env.repo.join("zsh/.zshrc"), "export EDITOR=vim\n");
    write(
        &env.repo.join("git/.config/git/config.tmpl"),
        "[user]\nemail = \"{{email}}\"\n",
    );
    write(&env.repo.join("assets/wallpaper.png"), "wallpaper-bytes");

    env.run_success(&["init"]);
    write(
        &env.repo.join("dot.toml"),
        "[settings]\ndefault_kind = \"symlink\"\nrender_suffix = \".tmpl\"\ncollision_policy = \"error\"\n\n[variables]\nemail = \"user@example.test\"\n\n[packages.assets.files.\"assets/wallpaper.png\"]\ntarget = \"~/.local/share/wallpaper.png\"\nkind = \"copy\"\nmode = \"0644\"\n",
    );

    let status_before = env.run_json(&["--json", "status"]);
    assert_eq!(status_before["pending_create"], 3);
    assert_eq!(status_before["blocked"], 0);

    env.run_success(&["--yes", "apply"]);

    let zsh_target = env.home.join(".zshrc");
    let git_target = env.home.join(".config/git/config");
    let asset_target = env.home.join(".local/share/wallpaper.png");

    assert_eq!(
        fs::read_link(&zsh_target).unwrap(),
        env.repo.join("zsh/.zshrc")
    );
    assert_eq!(
        fs::read_to_string(&git_target).unwrap(),
        "[user]\nemail = \"user@example.test\"\n"
    );
    assert_eq!(
        fs::read_to_string(&asset_target).unwrap(),
        "wallpaper-bytes"
    );
    assert_eq!(
        fs::metadata(&asset_target).unwrap().permissions().mode() & 0o7777,
        0o644
    );

    let status_after = env.run_json(&["--json", "status"]);
    assert_eq!(status_after["clean"], 3);
    assert_eq!(status_after["pending_create"], 0);
    assert_eq!(status_after["pending_replace"], 0);
    assert_eq!(status_after["pending_remove"], 0);

    let plan_after = env.run_json(&["--json", "plan"]);
    assert_eq!(plan_after["summary"]["clean"], 3);
    assert_eq!(plan_after["operations"].as_array().unwrap().len(), 0);

    let doctor_after = env.run_json(&["--json", "doctor"]);
    assert_eq!(doctor_after["has_errors"], false);
    assert!(
        doctor_after["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["message"] == "no problems detected")
    );

    env.run_success(&["--yes", "undeploy"]);

    assert!(!zsh_target.exists());
    assert!(!git_target.exists());
    assert!(!asset_target.exists());

    let state_json = state_file_path(&env.state);
    let state: Value = serde_json::from_str(&fs::read_to_string(state_json).unwrap()).unwrap();
    assert_eq!(state["entries"].as_array().unwrap().len(), 0);
}

#[test]
fn apply_requires_explicit_overwrite_policy_for_unmanaged_targets() {
    let env = TestEnv::new();
    write(&env.repo.join("zsh/.zshrc"), "export EDITOR=vim\n");

    env.run_success(&["init"]);
    write(&env.home.join(".zshrc"), "manually managed\n");

    let status = env.run_json(&["--json", "status"]);
    assert_eq!(status["blocked"], 1);
    assert_eq!(status["unmanaged_target_changes"], 1);

    let failed_apply = env.run_failure(&["apply"]);
    let stderr = String::from_utf8(failed_apply.stderr).unwrap();
    assert!(stderr.contains("--overwrite-unmanaged"));

    env.run_success(&["--overwrite-unmanaged", "apply"]);
    assert_eq!(
        fs::read_link(env.home.join(".zshrc")).unwrap(),
        env.repo.join("zsh/.zshrc")
    );
}

#[test]
fn per_file_unmanaged_overwrite_policy_replaces_manual_target_without_flag() {
    let env = TestEnv::new();
    write(&env.repo.join("zsh/.zshrc"), "export EDITOR=vim\n");

    env.run_success(&["init"]);
    write(
        &env.repo.join("dot.toml"),
        "[packages.zsh.files.\"zsh/.zshrc\".conflicts]\nunmanaged = \"overwrite\"\n",
    );
    write(&env.home.join(".zshrc"), "manually managed\n");

    env.run_success(&["apply"]);

    assert_eq!(
        fs::read_link(env.home.join(".zshrc")).unwrap(),
        env.repo.join("zsh/.zshrc")
    );
}

#[test]
fn managed_merge_policy_blocks_apply_and_prints_guidance() {
    let env = TestEnv::new();
    write(&env.repo.join("git/.gitconfig"), "[user]\nemail = \"new@example.test\"\n");

    env.run_success(&["init"]);
    write(
        &env.repo.join("dot.toml"),
        "[settings.conflicts]\nmerge_tool = \"opendiff\"\n\n[packages.git.files.\"git/.gitconfig\"]\ntarget = \"~/.gitconfig\"\nkind = \"copy\"\n\n[packages.git.files.\"git/.gitconfig\".conflicts]\nmanaged = \"merge\"\n",
    );

    env.run_success(&["apply"]);
    write(
        &env.home.join(".gitconfig"),
        "[user]\nemail = \"manual@example.test\"\n",
    );

    let failed_apply = env.run_failure(&["apply"]);
    let stdout = String::from_utf8(failed_apply.stdout).unwrap();
    let stderr = String::from_utf8(failed_apply.stderr).unwrap();

    assert!(stdout.contains("[blocked]"));
    assert!(stdout.contains("diff command: git diff --no-index"));
    assert!(stdout.contains("merge command: opendiff"));
    assert!(stderr.contains("blocked operations remain after applying conflict policies"));
    assert_eq!(
        fs::read_to_string(env.home.join(".gitconfig")).unwrap(),
        "[user]\nemail = \"manual@example.test\"\n"
    );

    let state_json = state_file_path(&env.state);
    let state: Value = serde_json::from_str(&fs::read_to_string(state_json).unwrap()).unwrap();
    assert_eq!(state["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn privileged_packages_are_skipped_by_default_and_can_be_allowed() {
    let env = TestEnv::new();
    let protected_root = env.home.join("protected");
    fs::create_dir_all(&protected_root).unwrap();
    fs::set_permissions(&protected_root, fs::Permissions::from_mode(0o555)).unwrap();

    write(&env.repo.join("zsh/.zshrc"), "export EDITOR=vim\n");
    write(&env.repo.join("sys/app.conf"), "port=8080\n");

    env.run_success(&["init"]);
    write(
        &env.repo.join("dot.toml"),
        &format!(
            "[packages.sys.files.\"sys/app.conf\"]\ntarget = \"{}\"\nkind = \"copy\"\n",
            protected_root.join("app.conf").display()
        ),
    );

    let first_apply = env.run_success(&["apply"]);
    let first_stdout = String::from_utf8(first_apply.stdout).unwrap();
    assert!(first_stdout.contains("[skipped]"));
    assert!(env.home.join(".zshrc").exists());
    assert!(!protected_root.join("app.conf").exists());

    let status_after_skip = env.run_json(&["--json", "status"]);
    assert_eq!(status_after_skip["skipped_privileged"], 2);

    let state_json = state_file_path(&env.state);
    let state: Value = serde_json::from_str(&fs::read_to_string(&state_json).unwrap()).unwrap();
    assert_eq!(state["entries"].as_array().unwrap().len(), 1);

    let bin_dir = env.home.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    install_fake_sudo(&bin_dir);

    let second_apply = env.run_with_path(&["--allow-privileged", "apply"], &bin_dir);
    assert!(
        second_apply.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&second_apply.stdout),
        String::from_utf8_lossy(&second_apply.stderr)
    );
    assert_eq!(
        fs::read_to_string(protected_root.join("app.conf")).unwrap(),
        "port=8080\n"
    );

    let status_after_allow = env.run_with_path(&["--json", "--allow-privileged", "status"], &bin_dir);
    assert!(status_after_allow.status.success());
    let json: Value = serde_json::from_slice(&status_after_allow.stdout).unwrap();
    assert_eq!(json["skipped_privileged"], 0);
    fs::set_permissions(&protected_root, fs::Permissions::from_mode(0o755)).unwrap();
}
