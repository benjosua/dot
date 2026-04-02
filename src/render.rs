use anyhow::{Context, Result, bail};
use handlebars::Handlebars;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn variables_context(
    variables: &std::collections::BTreeMap<String, toml::Value>,
    runtime: &crate::selectors::RuntimeContext,
) -> Result<Value> {
    let mut map = Map::new();
    for (key, value) in variables {
        map.insert(
            key.clone(),
            serde_json::to_value(value).with_context(|| format!("serialize variable {key:?}"))?,
        );
    }
    map.insert("host".into(), Value::String(runtime.host.clone()));
    map.insert(
        "os".into(),
        Value::String(
            match runtime.os {
                crate::selectors::RuntimeOs::Linux => "linux",
                crate::selectors::RuntimeOs::Macos => "macos",
                crate::selectors::RuntimeOs::Unix => "unix",
            }
            .to_string(),
        ),
    );
    map.insert(
        "home".into(),
        Value::String(crate::config::home_dir()?.display().to_string()),
    );
    Ok(Value::Object(map))
}

pub fn render_template(source: &Path, context: &Value) -> Result<String> {
    let raw = fs::read_to_string(source)
        .with_context(|| format!("read template source {}", source.display()))?;
    let mut handlebars = Handlebars::new();
    handlebars.set_strict_mode(true);
    handlebars
        .render_template(&raw, context)
        .with_context(|| format!("render template {}", source.display()))
}

pub fn cache_rendered_output(cache_root: &Path, rendered: &str) -> Result<(String, PathBuf)> {
    let hash = hex::encode(Sha256::digest(rendered.as_bytes()));
    let path = cache_root.join("rendered").join(format!("{hash}.txt"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create render cache directory {}", parent.display()))?;
    }
    fs::write(&path, rendered).with_context(|| format!("write render cache {}", path.display()))?;
    Ok((hash, path))
}

pub fn text_diff(before: &str, after: &str) -> String {
    let mut out = String::new();
    for change in diff::lines(before, after) {
        match change {
            diff::Result::Left(line) => {
                out.push('-');
                out.push_str(line);
                out.push('\n');
            }
            diff::Result::Right(line) => {
                out.push('+');
                out.push_str(line);
                out.push('\n');
            }
            diff::Result::Both(line, _) => {
                out.push(' ');
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

pub fn ensure_renderable(source: &Path) -> Result<()> {
    let bytes =
        fs::read(source).with_context(|| format!("read template source {}", source.display()))?;
    if std::str::from_utf8(&bytes).is_err() {
        bail!("template source {} is not valid UTF-8", source.display());
    }
    Ok(())
}
