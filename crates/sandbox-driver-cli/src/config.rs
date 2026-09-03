use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use tokio::fs::{read_to_string, try_exists};

const CONFIG_ENV: &str = "SANDBOX_DRIVER_CONFIG";

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Config {
    pub default_provider: Option<String>,
    pub providers:        BTreeMap<String, ProviderProfile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ProviderProfile {
    Host(EmptyProfile),
    Docker(EmptyProfile),
    Daytona(DaytonaProfile),
    Plugin(PluginProfile),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::empty_structs_with_brackets,
    reason = "a map-shaped type lets serde reject unknown built-in profile fields"
)]
pub(crate) struct EmptyProfile {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct DaytonaProfile {
    pub(crate) api_key_env:         Option<String>,
    pub(crate) jwt_token_env:       Option<String>,
    pub(crate) organization_id_env: Option<String>,
    pub(crate) api_url:             Option<String>,
    pub(crate) target:              Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct PluginProfile {
    pub(crate) kind:        String,
    pub(crate) path:        Option<PathBuf>,
    pub(crate) sha256:      Option<String>,
    #[serde(default)]
    pub(crate) dev:         bool,
    #[serde(default)]
    pub(crate) args:        Vec<String>,
    #[serde(default)]
    pub(crate) env:         BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) inherit_env: Vec<String>,
}

impl Config {
    pub(crate) async fn load(explicit_path: Option<&Path>) -> Result<Self> {
        let Some(path) = find_config_path(explicit_path).await? else {
            return Ok(Self::default());
        };
        let contents = read_to_string(&path)
            .await
            .with_context(|| format!("reading configuration from {}", path.display()))?;
        toml::from_str(&contents)
            .with_context(|| format!("parsing configuration from {}", path.display()))
    }

    pub(crate) fn selected_provider<'a>(&'a self, requested: Option<&'a str>) -> &'a str {
        requested
            .or(self.default_provider.as_deref())
            .unwrap_or("host")
    }
}

impl ProviderProfile {
    pub(crate) fn provider_type(&self) -> &str {
        match self {
            Self::Host(_) => "host",
            Self::Docker(_) => "docker",
            Self::Daytona(_) => "daytona",
            Self::Plugin(_) => "plugin",
        }
    }

    pub(crate) fn provider_kind(&self) -> &str {
        match self {
            Self::Host(_) => "host",
            Self::Docker(_) => "docker",
            Self::Daytona(_) => "daytona",
            Self::Plugin(profile) => &profile.kind,
        }
    }
}

async fn find_config_path(explicit_path: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit_path {
        return Ok(Some(path.to_path_buf()));
    }
    if let Some(path) = env::var_os(CONFIG_ENV).filter(|value| !value.is_empty()) {
        return Ok(Some(PathBuf::from(path)));
    }

    let candidate = env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })
        .map(|root| root.join("sandbox-driver/config.toml"));

    match candidate {
        Some(path)
            if try_exists(&path)
                .await
                .with_context(|| format!("checking for configuration at {}", path.display()))? =>
        {
            Ok(Some(path))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_builtin_and_plugin_profiles() {
        let config: Config = toml::from_str(
            r#"
default-provider = "local"

[providers.local]
type = "docker"

[providers.remote]
type = "plugin"
kind = "e2b"
path = "/opt/lithos-sandbox-e2b"
sha256 = "abcd"
inherit-env = ["PATH", "E2B_API_KEY"]
"#,
        )
        .expect("configuration parses");

        assert_eq!(config.selected_provider(None), "local");
        assert_eq!(config.providers["local"].provider_type(), "docker");
        assert_eq!(config.providers["remote"].provider_kind(), "e2b");
    }

    #[test]
    fn rejects_unknown_profile_fields() {
        let error = toml::from_str::<Config>(
            r#"
[providers.local]
type = "docker"
surprise = true
"#,
        )
        .expect_err("unknown fields fail");

        assert!(error.to_string().contains("unknown field"));
    }
}
