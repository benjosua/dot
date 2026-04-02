use crate::config::{OsSelector, When};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeOs {
    Linux,
    Macos,
    Unix,
}

#[derive(Debug, Clone)]
pub struct RuntimeContext {
    pub host: String,
    pub os: RuntimeOs,
    pub env: BTreeMap<String, String>,
}

impl RuntimeContext {
    pub fn detect(host_override: Option<String>, os_override: Option<RuntimeOs>) -> Self {
        let host = host_override.unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|value| value.into_string().ok())
                .unwrap_or_else(|| "unknown-host".to_string())
        });

        let os = os_override.unwrap_or_else(current_os);
        let env = std::env::vars().collect();
        Self { host, os, env }
    }
}

pub fn current_os() -> RuntimeOs {
    #[cfg(target_os = "macos")]
    {
        RuntimeOs::Macos
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        RuntimeOs::Linux
    }
}

pub fn matches(when: Option<&When>, runtime: &RuntimeContext) -> bool {
    let Some(when) = when else {
        return true;
    };

    if !when.os.is_empty() {
        let os_match = when.os.iter().any(|candidate| match candidate {
            OsSelector::Linux => runtime.os == RuntimeOs::Linux,
            OsSelector::Macos => runtime.os == RuntimeOs::Macos,
            OsSelector::Unix => matches!(
                runtime.os,
                RuntimeOs::Linux | RuntimeOs::Macos | RuntimeOs::Unix
            ),
        });
        if !os_match {
            return false;
        }
    }

    if !when.host.is_empty() && !when.host.iter().any(|candidate| candidate == &runtime.host) {
        return false;
    }

    for (key, value) in &when.env {
        match runtime.env.get(key) {
            Some(actual) if actual == value => {}
            _ => return false,
        }
    }

    true
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::When;

    #[test]
    fn selector_matching_checks_host_os_and_env() {
        let runtime = RuntimeContext {
            host: "laptop".into(),
            os: RuntimeOs::Linux,
            env: BTreeMap::from([("SHELL".into(), "/bin/bash".into())]),
        };

        let when = When {
            os: vec![OsSelector::Linux],
            host: vec!["laptop".into()],
            env: BTreeMap::from([("SHELL".into(), "/bin/bash".into())]),
        };

        assert!(matches(Some(&when), &runtime));
    }
}
