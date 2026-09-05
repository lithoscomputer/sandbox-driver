use std::env;
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::ProviderKind;
use sandbox_driver_protocol::{PluginConfig, PluginProvider, launch_plugin};

use crate::config::{Config, DaytonaProfile, PluginProfile, ProviderProfile};

const PLUGIN_PREFIX: &str = "sandbox-driver";
const EXTERNAL_PLUGIN_PREFIX: &str = "lithos-sandbox";
const DAYTONA_ENV: &[&str] = &[
    "DAYTONA_API_KEY",
    "DAYTONA_JWT_TOKEN",
    "DAYTONA_ORGANIZATION_ID",
    "DAYTONA_API_URL",
    "DAYTONA_SERVER_URL",
    "DAYTONA_TARGET",
];

pub(crate) struct ProviderSession {
    pub provider: PluginProvider,
}

impl ProviderSession {
    #[tracing::instrument(skip_all, fields(provider_profile = name), err)]
    pub(crate) async fn connect(name: &str, config: &Config) -> Result<Self> {
        Self::launch(name, config)
            .await
            .with_context(|| format!("connecting provider profile {name:?}"))
    }

    async fn launch(name: &str, config: &Config) -> Result<Self> {
        let (prefix, plugin_config) = match config.providers.get(name) {
            Some(ProviderProfile::Plugin(profile)) => {
                (EXTERNAL_PLUGIN_PREFIX, external_config(profile)?)
            }
            Some(ProviderProfile::Daytona(profile)) => {
                let mut config = builtin_config("daytona")?;
                configure_daytona(&mut config, profile)?;
                (PLUGIN_PREFIX, config)
            }
            Some(profile) => (PLUGIN_PREFIX, builtin_config(profile.provider_kind())?),
            None => (PLUGIN_PREFIX, builtin_config(name)?),
        };
        let launch = launch_plugin(prefix, &plugin_config).await?;
        Ok(Self {
            provider: launch.provider,
        })
    }

    pub(crate) async fn shutdown(&self) -> Result<()> {
        self.provider
            .shutdown()
            .await
            .context("shutting down plugin")
    }
}

fn builtin_config(kind: &str) -> Result<PluginConfig> {
    if !matches!(kind, "host" | "docker" | "daytona") {
        bail!("unknown provider {kind:?}; use host, docker, daytona, or a configured profile");
    }
    let mut config =
        PluginConfig::new(ProviderKind::try_new(kind).context("validating provider kind")?);
    let env_prefix = format!("SANDBOX_DRIVER_{}", kind.to_ascii_uppercase());
    config.path = env::var_os(format!("{env_prefix}_PLUGIN"))
        .map(PathBuf::from)
        .or_else(|| adjacent_plugin(kind));
    config.sha256 = env::var(format!("{env_prefix}_SHA256")).ok();
    config.dev = env::var("SANDBOX_DRIVER_PLUGIN_DEV").is_ok_and(|value| value == "1");
    config.inherit_env = ["PATH", "HOME", "TMPDIR", "RUST_LOG", "LLVM_PROFILE_FILE"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    // Match the CLI's quiet default; explicit RUST_LOG still controls diagnostics.
    if env::var_os("RUST_LOG").is_none() {
        config.env.insert("RUST_LOG".to_owned(), "warn".to_owned());
    }
    let provider_env: &[&str] = match kind {
        "docker" => &[
            "DOCKER_HOST",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "DOCKER_CONFIG",
        ],
        "daytona" => DAYTONA_ENV,
        _ => &[],
    };
    config
        .inherit_env
        .extend(provider_env.iter().map(|key| (*key).to_owned()));
    Ok(config)
}

fn adjacent_plugin(kind: &str) -> Option<PathBuf> {
    let executable = env::current_exe().ok()?;
    let candidate = executable.parent()?.join(format!("{PLUGIN_PREFIX}-{kind}"));
    candidate.is_file().then_some(candidate)
}

fn external_config(profile: &PluginProfile) -> Result<PluginConfig> {
    let mut config = PluginConfig::new(
        ProviderKind::try_new(profile.kind.clone()).context("validating plugin kind")?,
    );
    config.path.clone_from(&profile.path);
    config.sha256.clone_from(&profile.sha256);
    config.dev = profile.dev;
    config.args.clone_from(&profile.args);
    config.env.clone_from(&profile.env);
    config.inherit_env.clone_from(&profile.inherit_env);
    Ok(config)
}

fn configure_daytona(config: &mut PluginConfig, profile: &DaytonaProfile) -> Result<()> {
    for (key, source) in [
        ("DAYTONA_API_KEY", &profile.api_key_env),
        ("DAYTONA_JWT_TOKEN", &profile.jwt_token_env),
        ("DAYTONA_ORGANIZATION_ID", &profile.organization_id_env),
    ] {
        if let Some(source) = source {
            let value = env::var(source)
                .with_context(|| format!("reading required environment variable {source}"))?;
            config.env.insert(key.to_owned(), value);
        }
    }
    for (key, value) in [
        ("DAYTONA_API_URL", &profile.api_url),
        ("DAYTONA_TARGET", &profile.target),
    ] {
        if let Some(value) = value {
            config.env.insert(key.to_owned(), value.clone());
        }
    }
    Ok(())
}
