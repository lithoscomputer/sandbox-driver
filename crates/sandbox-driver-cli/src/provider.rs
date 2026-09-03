use std::env;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{ProviderKind, SandboxProvider};
use sandbox_driver_daytona::{DaytonaConfig, DaytonaProvider};
use sandbox_driver_docker::DockerProvider;
use sandbox_driver_host::HostProvider;
use sandbox_driver_protocol::{PluginConfig, PluginProvider, launch_plugin};

use crate::config::{Config, DaytonaProfile, PluginProfile, ProviderProfile};

const PLUGIN_PREFIX: &str = "lithos-sandbox";

pub(crate) struct ProviderSession {
    pub provider: Arc<dyn SandboxProvider>,
    plugin:       Option<Arc<PluginProvider>>,
}

impl ProviderSession {
    #[tracing::instrument(skip_all, fields(provider_profile = name), err)]
    pub(crate) async fn connect(name: &str, config: &Config) -> Result<Self> {
        match config.providers.get(name) {
            Some(profile) => Self::connect_profile(profile).await,
            None => Self::connect_builtin(name).await,
        }
        .with_context(|| format!("connecting provider profile {name:?}"))
    }

    pub(crate) async fn shutdown(&self) -> Result<()> {
        if let Some(plugin) = &self.plugin {
            plugin.shutdown().await.context("shutting down plugin")?;
        }
        Ok(())
    }

    async fn connect_builtin(name: &str) -> Result<Self> {
        let provider: Arc<dyn SandboxProvider> = match name {
            "host" => Arc::new(HostProvider::new()),
            "docker" => Arc::new(DockerProvider::connect().await?),
            "daytona" => Arc::new(DaytonaProvider::connect().await?),
            _ => {
                bail!(
                    "unknown provider {name:?}; use host, docker, daytona, or a configured profile"
                )
            }
        };
        Ok(Self {
            provider,
            plugin: None,
        })
    }

    async fn connect_profile(profile: &ProviderProfile) -> Result<Self> {
        match profile {
            ProviderProfile::Host(_) => Self::connect_builtin("host").await,
            ProviderProfile::Docker(_) => Self::connect_builtin("docker").await,
            ProviderProfile::Daytona(DaytonaProfile {
                api_key_env,
                jwt_token_env,
                organization_id_env,
                api_url,
                target,
            }) => {
                let daytona_config = DaytonaConfig {
                    api_key:         env_value(api_key_env.as_deref())?,
                    jwt_token:       env_value(jwt_token_env.as_deref())?,
                    organization_id: env_value(organization_id_env.as_deref())?,
                    api_url:         api_url.clone(),
                    target:          target.clone(),
                    http_client:     None,
                };
                Ok(Self {
                    provider: Arc::new(DaytonaProvider::connect_with_config(daytona_config).await?),
                    plugin:   None,
                })
            }
            ProviderProfile::Plugin(PluginProfile {
                kind,
                path,
                sha256,
                dev,
                args,
                env,
                inherit_env,
            }) => {
                let mut plugin_config = PluginConfig::new(
                    ProviderKind::try_new(kind.clone()).context("validating plugin kind")?,
                );
                plugin_config.path = path.clone();
                plugin_config.sha256 = sha256.clone();
                plugin_config.dev = *dev;
                plugin_config.args.clone_from(args);
                plugin_config.env.clone_from(env);
                plugin_config.inherit_env.clone_from(inherit_env);

                let launch = launch_plugin(PLUGIN_PREFIX, &plugin_config).await?;
                let plugin = Arc::new(launch.provider);
                let provider: Arc<dyn SandboxProvider> = plugin.clone();
                Ok(Self {
                    provider,
                    plugin: Some(plugin),
                })
            }
        }
    }
}

fn env_value(name: Option<&str>) -> Result<Option<String>> {
    name.map(|name| {
        env::var(name).with_context(|| format!("reading required environment variable {name}"))
    })
    .transpose()
}
