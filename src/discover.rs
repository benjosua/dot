use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::config::{FileConfig, Manifest, TargetKind, expand_home};
use crate::planner::Diagnostic;
use crate::render::{cache_rendered_output, ensure_renderable, render_template, variables_context};
use crate::selectors::{RuntimeContext, matches};

#[derive(Debug, Clone)]
pub struct DesiredTarget {
    pub package: String,
    pub source_rel: PathBuf,
    pub source_abs: PathBuf,
    pub target: PathBuf,
    pub kind: TargetKind,
    pub mode: Option<u32>,
    pub desired_hash: String,
    pub rendered_text: Option<String>,
    pub render_cache_path: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub desired: Vec<DesiredTarget>,
    pub diagnostics: Vec<Diagnostic>,
    pub packages: Vec<String>,
}

pub fn discover(
    repo_root: &Path,
    manifest: &Manifest,
    selected_packages: &[String],
    runtime: &RuntimeContext,
    cache_root: &Path,
) -> Result<DiscoveryResult> {
    let context = variables_context(&manifest.variables, runtime)?;
    let mut diagnostics = Vec::new();
    let mut desired = Vec::new();

    let package_dirs = read_package_dirs(repo_root)?;
    let discovered_names = package_dirs.keys().cloned().collect::<BTreeSet<_>>();
    let selected = selected_package_set(selected_packages);
    let mut package_names = discovered_names.clone();
    package_names.extend(manifest.packages.keys().cloned());

    let mut active_packages = Vec::new();

    for package_name in package_names {
        if !selected.is_empty() && !selected.contains(&package_name) {
            continue;
        }

        let package_config = manifest.packages.get(&package_name);
        if package_config.and_then(|pkg| pkg.enabled) == Some(false) {
            continue;
        }

        let Some(package_dir) = package_dirs.get(&package_name) else {
            diagnostics.push(Diagnostic::warning(format!(
                "package {package_name:?} is configured but no matching top-level directory exists"
            )));
            continue;
        };

        active_packages.push(package_name.clone());
        let mut seen_sources = BTreeSet::new();
        for entry in WalkDir::new(package_dir)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
        {
            let source_abs = entry.path().to_path_buf();
            let source_rel = source_abs
                .strip_prefix(repo_root)
                .with_context(|| format!("strip repo prefix from {}", source_abs.display()))?
                .to_path_buf();
            let source_key = source_rel.display().to_string();
            seen_sources.insert(source_rel.clone());

            if let Some(target) = resolve_desired(
                manifest,
                runtime,
                cache_root,
                &context,
                &package_name,
                source_rel,
                source_abs,
                package_config.and_then(|pkg| pkg.files.get(&source_key)),
            )? {
                desired.push(target);
            }
        }

        if let Some(package_config) = package_config {
            for source_key in package_config.files.keys() {
                let source_rel = PathBuf::from(source_key);
                if seen_sources.contains(&source_rel) {
                    continue;
                }
                let source_abs = repo_root.join(&source_rel);
                if !source_abs.exists() {
                    diagnostics.push(Diagnostic::error(format!(
                        "package {package_name:?} references missing source {}",
                        source_rel.display()
                    )));
                    continue;
                }
                if let Some(target) = resolve_desired(
                    manifest,
                    runtime,
                    cache_root,
                    &context,
                    &package_name,
                    source_rel,
                    source_abs,
                    Some(package_config.files.get(source_key).expect("present")),
                )? {
                    desired.push(target);
                }
            }
        }
    }

    Ok(DiscoveryResult {
        desired,
        diagnostics,
        packages: active_packages,
    })
}

fn resolve_desired(
    manifest: &Manifest,
    runtime: &RuntimeContext,
    cache_root: &Path,
    context: &serde_json::Value,
    package_name: &str,
    source_rel: PathBuf,
    source_abs: PathBuf,
    file_config: Option<&FileConfig>,
) -> Result<Option<DesiredTarget>> {
    if !matches(file_config.and_then(|cfg| cfg.when.as_ref()), runtime) {
        return Ok(None);
    }

    let mut kind = file_config
        .and_then(|cfg| cfg.kind)
        .unwrap_or(manifest.settings.default_kind);
    let source_rel_string = source_rel.display().to_string();

    let default_target_rel = drop_package_root(&source_rel)
        .with_context(|| format!("compute default target for {}", source_rel.display()))?;
    let mut target_string = file_config
        .and_then(|cfg| cfg.target.clone())
        .unwrap_or_else(|| format!("~/{}", default_target_rel.display()));

    if file_config.and_then(|cfg| cfg.kind).is_none()
        && source_rel_string.ends_with(&manifest.settings.render_suffix)
    {
        kind = TargetKind::Render;
        if file_config.and_then(|cfg| cfg.target.as_ref()).is_none() {
            let stripped =
                strip_render_suffix(&default_target_rel, &manifest.settings.render_suffix)?;
            target_string = format!("~/{}", stripped.display());
        }
    }

    let mode = file_config
        .map(FileConfig::parsed_mode)
        .transpose()?
        .flatten();
    let target = expand_home(&target_string)?;

    let (desired_hash, rendered_text, render_cache_path) = match kind {
        TargetKind::Symlink => {
            let hash = hex::encode(Sha256::digest(source_abs.display().to_string().as_bytes()));
            (hash, None, None)
        }
        TargetKind::Copy => {
            let bytes = fs::read(&source_abs)
                .with_context(|| format!("read source {}", source_abs.display()))?;
            (hex::encode(Sha256::digest(&bytes)), None, None)
        }
        TargetKind::Render => {
            ensure_renderable(&source_abs)?;
            let rendered = render_template(&source_abs, context)?;
            let (hash, cache_path) = cache_rendered_output(cache_root, &rendered)?;
            (hash, Some(rendered), Some(cache_path))
        }
    };
    Ok(Some(DesiredTarget {
        package: package_name.to_string(),
        source_rel,
        source_abs,
        target,
        kind,
        mode,
        desired_hash,
        rendered_text,
        render_cache_path,
    }))
}

fn read_package_dirs(repo_root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut packages = BTreeMap::new();
    for entry in fs::read_dir(repo_root).with_context(|| format!("read {}", repo_root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if matches!(name.as_str(), ".git" | ".github") {
            continue;
        }
        packages.insert(name, path);
    }
    Ok(packages)
}

fn selected_package_set(selected: &[String]) -> BTreeSet<String> {
    selected.iter().cloned().collect()
}

fn drop_package_root(source_rel: &Path) -> Result<PathBuf> {
    let mut components = source_rel.components();
    components
        .next()
        .context("source must include a package root component")?;
    let mut out = PathBuf::new();
    for component in components {
        out.push(component.as_os_str());
    }
    Ok(out)
}

fn strip_render_suffix(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("render source must have a valid filename")?;
    let stripped = file_name
        .strip_suffix(suffix)
        .with_context(|| format!("filename {file_name:?} does not end with {suffix:?}"))?;
    let mut out = path.to_path_buf();
    out.set_file_name(stripped);
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::Manifest;
    use crate::selectors::{RuntimeContext, RuntimeOs};
    use tempfile::tempdir;

    #[test]
    fn strip_render_suffix_removes_suffix_from_filename() {
        assert_eq!(
            strip_render_suffix(Path::new(".config/git/config.tmpl"), ".tmpl").unwrap(),
            PathBuf::from(".config/git/config")
        );
    }

    #[test]
    fn discovery_maps_top_level_package_dirs_to_home() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("zsh")).unwrap();
        fs::write(dir.path().join("zsh/.zshrc"), "export FOO=1\n").unwrap();
        let runtime = RuntimeContext {
            host: "test".into(),
            os: RuntimeOs::Linux,
            env: BTreeMap::new(),
        };
        let cache = dir.path().join("cache");
        let result = discover(dir.path(), &Manifest::default(), &[], &runtime, &cache).unwrap();
        assert_eq!(result.desired.len(), 1);
        assert_eq!(
            result.desired[0].target,
            crate::config::home_dir().unwrap().join(".zshrc")
        );
    }

    #[test]
    fn discovery_auto_renders_tmpl_files_and_strips_suffix() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("git/.config/git")).unwrap();
        fs::write(
            dir.path().join("git/.config/git/config.tmpl"),
            "[user]\nemail = \"{{email}}\"\n",
        )
        .unwrap();

        let runtime = RuntimeContext {
            host: "test".into(),
            os: RuntimeOs::Linux,
            env: BTreeMap::new(),
        };
        let cache = dir.path().join("cache");
        let manifest = Manifest {
            variables: BTreeMap::from([(
                "email".into(),
                toml::Value::String("user@example.test".into()),
            )]),
            ..Manifest::default()
        };

        let result = discover(dir.path(), &manifest, &[], &runtime, &cache).unwrap();
        let desired = &result.desired[0];
        assert_eq!(desired.kind, crate::config::TargetKind::Render);
        assert_eq!(
            desired.target,
            crate::config::home_dir()
                .unwrap()
                .join(".config/git/config")
        );
        assert_eq!(
            desired.rendered_text.as_deref(),
            Some("[user]\nemail = \"user@example.test\"\n")
        );
        assert!(
            desired
                .render_cache_path
                .as_ref()
                .is_some_and(|path| path.exists())
        );
    }
}
