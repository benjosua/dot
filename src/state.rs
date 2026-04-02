use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::TargetKind;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFile {
    pub repo_id: String,
    #[serde(default)]
    pub entries: Vec<StateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateEntry {
    pub package: String,
    pub source_rel: String,
    pub target: String,
    pub kind: TargetKind,
    pub content_hash: String,
    pub mode: Option<u32>,
}

impl StateFile {
    pub fn by_target(&self) -> BTreeMap<PathBuf, StateEntry> {
        self.entries
            .iter()
            .cloned()
            .map(|entry| (PathBuf::from(&entry.target), entry))
            .collect()
    }
}

pub fn repo_id(repo_root: &Path) -> Result<String> {
    let canonical = repo_root
        .canonicalize()
        .with_context(|| format!("canonicalize repo root {}", repo_root.display()))?;
    Ok(hex::encode(Sha256::digest(
        canonical.display().to_string().as_bytes(),
    )))
}

pub fn state_root(repo_root: &Path) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::config::home_dir().unwrap().join(".local/state"));
    Ok(base.join("dot/repos").join(repo_id(repo_root)?))
}

pub fn cache_root(repo_root: &Path) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::config::home_dir().unwrap().join(".cache"));
    Ok(base.join("dot/repos").join(repo_id(repo_root)?))
}

pub fn load(repo_root: &Path) -> Result<StateFile> {
    let path = state_root(repo_root)?.join("state.json");
    if !path.exists() {
        return Ok(StateFile {
            repo_id: repo_id(repo_root)?,
            entries: Vec::new(),
        });
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

pub fn save(repo_root: &Path, state: &StateFile) -> Result<()> {
    let root = state_root(repo_root)?;
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let path = root.join("state.json");
    let raw = serde_json::to_string_pretty(state).context("serialize state")?;
    fs::write(&path, raw).with_context(|| format!("write {}", path.display()))
}
