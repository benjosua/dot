use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    #[default]
    Symlink,
    Copy,
    Render,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum CollisionPolicy {
    #[default]
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OsSelector {
    Linux,
    Macos,
    Unix,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct When {
    #[serde(default)]
    pub os: Vec<OsSelector>,
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileConfig {
    pub target: Option<String>,
    pub kind: Option<TargetKind>,
    pub mode: Option<String>,
    pub when: Option<When>,
}

impl FileConfig {
    pub fn parsed_mode(&self) -> Result<Option<u32>> {
        match &self.mode {
            Some(mode) => {
                let trimmed = mode.trim();
                if trimmed.len() != 4 || !trimmed.starts_with('0') {
                    bail!("mode {trimmed:?} must be a 4-digit octal string like \"0644\"");
                }
                let parsed = u32::from_str_radix(trimmed, 8)
                    .with_context(|| format!("parse mode {trimmed:?} as octal"))?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageConfig {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub files: BTreeMap<String, FileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub default_kind: TargetKind,
    #[serde(default = "default_render_suffix")]
    pub render_suffix: String,
    #[serde(default)]
    pub collision_policy: CollisionPolicy,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_kind: TargetKind::Symlink,
            render_suffix: default_render_suffix(),
            collision_policy: CollisionPolicy::Error,
        }
    }
}

fn default_render_suffix() -> String {
    ".tmpl".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub variables: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pub packages: BTreeMap<String, PackageConfig>,
}

pub fn load_manifest(repo_root: &Path) -> Result<(Manifest, bool)> {
    let path = repo_root.join("dot.toml");
    if !path.exists() {
        return Ok((Manifest::default(), false));
    }

    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let manifest =
        toml::from_str::<Manifest>(&raw).with_context(|| format!("parse {}", path.display()))?;
    validate_manifest(&manifest)?;
    Ok((manifest, true))
}

pub fn validate_manifest(manifest: &Manifest) -> Result<()> {
    for (package_name, package) in &manifest.packages {
        for (source, file) in &package.files {
            let _ = file
                .parsed_mode()
                .with_context(|| format!("package {package_name:?} file {source:?}"))?;
            if file.kind == Some(TargetKind::Symlink) && file.mode.is_some() {
                bail!(
                    "package {package_name:?} file {source:?}: symlink targets do not support `mode` in v1"
                );
            }
        }
    }

    Ok(())
}

pub fn write_default_manifest(repo_root: &Path) -> Result<()> {
    let path = repo_root.join("dot.toml");
    if path.exists() {
        bail!("{} already exists", path.display());
    }

    let content = r#"[settings]
default_kind = "symlink"
render_suffix = ".tmpl"
collision_policy = "error"

[variables]
"#;
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn append_gitignore_recommendations(repo_root: &Path) -> Result<()> {
    let path = repo_root.join(".gitignore");
    let mut lines = if path.exists() {
        fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };

    let recommended = [".DS_Store"];
    for item in recommended {
        if !lines.lines().any(|line| line.trim() == item) {
            if !lines.is_empty() && !lines.ends_with('\n') {
                lines.push('\n');
            }
            lines.push_str(item);
            lines.push('\n');
        }
    }

    fs::write(&path, lines).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

pub fn expand_home(input: &str) -> Result<PathBuf> {
    if input == "~" {
        return home_dir();
    }

    if let Some(stripped) = input.strip_prefix("~/") {
        return Ok(home_dir()?.join(stripped));
    }

    Ok(PathBuf::from(input))
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_mode_accepts_octal_string() {
        let file = FileConfig {
            mode: Some("0644".into()),
            ..FileConfig::default()
        };
        assert_eq!(file.parsed_mode().unwrap(), Some(0o644));
    }

    #[test]
    fn parse_mode_rejects_malformed_strings() {
        let file = FileConfig {
            mode: Some("644".into()),
            ..FileConfig::default()
        };
        assert!(file.parsed_mode().is_err());
    }

    #[test]
    fn symlink_mode_is_rejected() {
        let manifest = Manifest {
            packages: BTreeMap::from([(
                "zsh".into(),
                PackageConfig {
                    enabled: Some(true),
                    files: BTreeMap::from([(
                        "zsh/.zshrc".into(),
                        FileConfig {
                            kind: Some(TargetKind::Symlink),
                            mode: Some("0644".into()),
                            ..FileConfig::default()
                        },
                    )]),
                },
            )]),
            ..Manifest::default()
        };

        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn write_default_manifest_creates_minimal_v1_config() {
        let dir = tempdir().unwrap();
        write_default_manifest(dir.path()).unwrap();
        let raw = fs::read_to_string(dir.path().join("dot.toml")).unwrap();
        assert!(raw.contains("default_kind = \"symlink\""));
        assert!(raw.contains("render_suffix = \".tmpl\""));
        let (manifest, exists) = load_manifest(dir.path()).unwrap();
        assert!(exists);
        assert_eq!(manifest.settings.default_kind, TargetKind::Symlink);
        assert_eq!(manifest.settings.render_suffix, ".tmpl");
    }

    #[test]
    fn append_gitignore_recommendations_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        fs::write(&path, "target\n.DS_Store\n").unwrap();

        append_gitignore_recommendations(dir.path()).unwrap();
        append_gitignore_recommendations(dir.path()).unwrap();

        let raw = fs::read_to_string(path).unwrap();
        assert_eq!(raw.lines().filter(|line| *line == ".DS_Store").count(), 1);
        assert!(raw.lines().any(|line| line == "target"));
    }
}
