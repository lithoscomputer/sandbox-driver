//! The catalog the CLI drives: provider entries and environments from one
//! TOML file, or a built-in default when there is no file.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use sandbox_driver::{
    CatalogOptions, Environment, EnvironmentName, Error, ProviderEntry, ProviderFactory,
    ProviderName, Registry, SandboxSpec, Sandboxes, SecretResolver, Source, StaticEnvironments,
};
use sandbox_driver_daytona::DaytonaFactory;
use sandbox_driver_docker::DockerFactory;
use sandbox_driver_host::{HostFactory, schemas as host_schemas};
use sandbox_driver_protocol::PluginLoader;
use serde::Deserialize;
use serde_json::Value;
use tokio::fs::{read_to_string, try_exists};

const CONFIG_ENV: &str = "SANDBOX_DRIVER_CONFIG";
/// The image the default Docker and Daytona environments start from.
const DEFAULT_IMAGE: &str = "ubuntu:24.04";

/// Both catalog levels, as written in the configuration file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    #[serde(default)]
    pub providers:    BTreeMap<ProviderName, ProviderEntry>,
    #[serde(default)]
    pub environments: BTreeMap<EnvironmentName, Environment>,
}

impl Catalog {
    /// The explicit file, the configured default file, or the built-in
    /// catalog when neither exists.
    pub(crate) async fn load(explicit_path: Option<&Path>) -> Result<Self> {
        let Some(path) = find_config_path(explicit_path).await? else {
            return Ok(Self::builtin());
        };
        let contents = read_to_string(&path)
            .await
            .with_context(|| format!("reading catalog {}", path.display()))?;
        let mut catalog: Self = toml::from_str(&contents)
            .with_context(|| format!("parsing catalog {}", path.display()))?;
        for entry in catalog.providers.values_mut() {
            if let Some(path) = &mut entry.path {
                *path = expand_home(path);
            }
        }
        Ok(catalog)
    }

    /// One entry and one same-named environment per built-in provider, so
    /// `lithos-sandbox run docker -- uname -a` works with no configuration.
    /// Unlike a configured entry, the default Daytona entry takes its
    /// settings from the standard `DAYTONA_*` variables.
    fn builtin() -> Self {
        let mut daytona = entry("daytona");
        let secret = if has_env("DAYTONA_API_KEY") || !has_env("DAYTONA_JWT_TOKEN") {
            "DAYTONA_API_KEY"
        } else {
            "DAYTONA_JWT_TOKEN"
        };
        daytona.secrets.push(secret.to_owned());
        for (key, variable) in [
            ("api_url", "DAYTONA_API_URL"),
            ("organization", "DAYTONA_ORGANIZATION_ID"),
            ("target", "DAYTONA_TARGET"),
        ] {
            if let Some(value) = nonempty_env(variable).and_then(|value| value.into_string().ok()) {
                daytona.config.insert(key.to_owned(), Value::String(value));
            }
        }

        let image = || SandboxSpec::new(Source::Image(DEFAULT_IMAGE.to_owned()));
        Self {
            providers:    [
                (name("host"), entry("host")),
                (name("docker"), entry("docker")),
                (name("daytona"), daytona),
            ]
            .into(),
            environments: [
                ("host", SandboxSpec::new(Source::HostDirectory)),
                ("docker", image()),
                ("daytona", image()),
            ]
            .into_iter()
            .map(|(environment, spec)| {
                (
                    EnvironmentName::try_new(environment).expect("static name"),
                    Environment {
                        provider: name(environment),
                        spec,
                    },
                )
            })
            .collect(),
        }
    }

    /// Builds the catalog with Host, Docker and Daytona linked in and the
    /// protocol 3 loader for every other kind. Nothing starts until a
    /// provider entry is first used.
    pub(crate) fn open(self) -> Result<Sandboxes> {
        let builtins: [(_, Arc<dyn ProviderFactory>); 3] = [
            (host_schemas().kind, Arc::new(HostFactory)),
            (DockerFactory::schemas().kind, Arc::new(DockerFactory)),
            (DaytonaFactory::kind(), Arc::new(DaytonaFactory)),
        ];
        let mut registry = Registry::new().plugins(Arc::new(PluginLoader::default()));
        for (kind, factory) in builtins {
            registry = registry
                .builtin(kind, factory)
                .context("registering built-in providers")?;
        }
        Sandboxes::try_new(
            self.providers,
            Arc::new(StaticEnvironments(self.environments)),
            &registry,
            Arc::new(EnvironmentSecrets),
            CatalogOptions::default(),
        )
        .context("opening the catalog")
    }
}

/// Resolves an entry's `secrets` from this process's environment.
struct EnvironmentSecrets;

#[async_trait]
impl SecretResolver for EnvironmentSecrets {
    async fn resolve(&self, name: &str) -> Result<Option<String>, Error> {
        Ok(nonempty_env(name).and_then(|value| value.into_string().ok()))
    }
}

fn entry(kind: &str) -> ProviderEntry {
    serde_json::from_value(serde_json::json!({ "plugin": kind })).expect("static entry")
}

fn name(text: &str) -> ProviderName {
    ProviderName::try_new(text).expect("static name")
}

/// A variable that is set to something; an empty value counts as unset.
fn nonempty_env(name: &str) -> Option<OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

fn has_env(name: &str) -> bool {
    nonempty_env(name).is_some()
}

/// Plugin paths must be absolute; a leading `~/` is the one shorthand the
/// CLI expands for them.
fn expand_home(path: &str) -> String {
    match (path.strip_prefix("~/"), env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest).to_string_lossy().into(),
        _ => path.to_owned(),
    }
}

async fn find_config_path(explicit_path: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(path) = explicit_path {
        return Ok(Some(path.to_path_buf()));
    }
    if let Some(path) = nonempty_env(CONFIG_ENV) {
        return Ok(Some(PathBuf::from(path)));
    }

    let candidate = nonempty_env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| nonempty_env("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|root| root.join("sandbox-driver/config.toml"));

    match candidate {
        Some(path)
            if try_exists(&path)
                .await
                .with_context(|| format!("checking for a catalog at {}", path.display()))? =>
        {
            Ok(Some(path))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;

    #[test]
    fn parses_entries_and_environments_as_next_api_writes_them() {
        let catalog: Catalog = toml::from_str(
            r#"
[providers.local]
plugin = "docker"
config = { host = "unix:///var/run/docker.sock" }

[providers.lima]
plugin = "lima"
path = "~/plugins/lima"
dev = true

[environments.ci]
provider = "local"

[environments.ci.spec]
source = { image = "alpine:3" }
resources = { memory = "1GB" }
"#,
        )
        .expect("catalog parses");

        assert_eq!(catalog.providers[&name("local")].plugin.as_str(), "docker");
        assert_eq!(catalog.providers[&name("lima")].plugin.as_str(), "lima");
        let ci = &catalog.environments[&EnvironmentName::try_new("ci").unwrap()];
        assert_eq!(ci.provider, name("local"));
        assert_eq!(ci.spec.resources.memory_mb.map(NonZeroU64::get), Some(1024));
    }

    #[test]
    fn rejects_the_old_profile_shape() {
        let error = toml::from_str::<Catalog>("[providers.local]\ntype = \"docker\"\n")
            .expect_err("profiles are gone");
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn default_catalog_pairs_every_builtin_with_an_environment() {
        let catalog = Catalog::builtin();
        for kind in ["host", "docker", "daytona"] {
            assert_eq!(catalog.providers[&name(kind)].plugin.as_str(), kind);
            let environment = &catalog.environments[&EnvironmentName::try_new(kind).unwrap()];
            assert_eq!(environment.provider, name(kind));
        }
    }
}
