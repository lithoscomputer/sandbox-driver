//! The Docker provider's `provider_config`, as a type.
//!
//! `SandboxSpec::provider_config` stays an opaque JSON value on the
//! portable spec — it crosses the plugin wire that way, and every provider
//! defines its own shape. This crate is the Docker shape, so a caller
//! constructs it type-checked and converts with
//! [`DockerProviderConfig::into_value`] instead of spelling string keys; a
//! typo is a compile error, not a runtime `InvalidSpec`. The provider
//! parses the value back through the same types, so the two can never
//! drift.
//!
//! The crate holds plain Serde data and nothing of the Docker client, so a
//! host that talks to the Docker provider over the plugin protocol can
//! depend on it without linking the provider.
//!
//! Every field is optional and unknown fields are rejected. The typed
//! fields are the Docker-only escape hatch for what the portable spec does
//! not carry: bind mounts, an init process, privilege, a pull-and-create
//! platform, extra host entries, DNS servers, added capabilities, registry
//! credentials, and sidecar service containers. A container-level `user`
//! rides on the portable `SandboxSpec::user`; an `entrypoint` override is a
//! sidecar-only field, because the scope container runs a fixed init and
//! commands go through `docker exec`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Options the Docker provider reads from `SandboxSpec::provider_config`.
/// Plain data: build it with a struct literal over [`Default`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerProviderConfig {
    /// Pull the image when the daemon does not have it. Default `true`.
    pub auto_pull:     bool,
    /// Run an init process as PID 1 so zombies are reaped.
    pub init:          bool,
    pub privileged:    bool,
    /// Share the daemon host's network namespace. Requires the default or
    /// allow-all network policy and cannot be combined with sidecars.
    pub host_network:  bool,
    /// The platform to pull and create for, such as `linux/amd64`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform:      Option<String>,
    /// Host directories mounted into the container. A bind at the
    /// sandbox's working directory replaces the provider's own workspace
    /// volume there.
    pub binds:         Vec<BindMount>,
    /// `host:ip` entries for the container's hosts file.
    pub extra_hosts:   Vec<String>,
    pub dns:           Vec<String>,
    pub cap_add:       Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_auth: Option<RegistryAuth>,
    pub sidecars:      Vec<Sidecar>,
}

impl Default for DockerProviderConfig {
    fn default() -> Self {
        Self {
            auto_pull:     true,
            init:          false,
            privileged:    false,
            host_network:  false,
            platform:      None,
            binds:         Vec::new(),
            extra_hosts:   Vec::new(),
            dns:           Vec::new(),
            cap_add:       Vec::new(),
            registry_auth: None,
            sidecars:      Vec::new(),
        }
    }
}

impl DockerProviderConfig {
    /// The value to place in `SandboxSpec::provider_config`.
    #[must_use]
    pub fn into_value(self) -> serde_json::Value {
        serde_json::to_value(self).expect("the Docker provider config is plain serializable data")
    }
}

/// A single host-to-container bind mount.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindMount {
    pub host:      String,
    pub container: String,
    /// `rw` (default) or `ro`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode:      Option<String>,
}

/// Registry credentials for pulling a private image.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server:   Option<String>,
}

/// One sidecar service container, started on the sandbox's network and
/// reachable from the sandbox by `name`. See the provider's sidecar
/// documentation for the readiness rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sidecar {
    pub name:          String,
    pub image:         String,
    #[serde(default)]
    pub env:           HashMap<String, String>,
    #[serde(default)]
    pub dns:           Vec<String>,
    #[serde(default)]
    pub cap_add:       Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user:          Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint:    Option<Vec<String>>,
    /// Run the sidecar privileged: what a Docker-in-Docker service needs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub privileged:    bool,
    /// When set, `create` waits for the sidecar to report healthy and
    /// fails if it exits or turns unhealthy first. When unset, the sidecar
    /// is started and not watched, so it may exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health:        Option<Health>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_auth: Option<RegistryAuth>,
}

impl Sidecar {
    /// A sidecar with no options set beyond its name and image.
    pub fn new(name: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            name:          name.into(),
            image:         image.into(),
            env:           HashMap::new(),
            dns:           Vec::new(),
            cap_add:       Vec::new(),
            user:          None,
            entrypoint:    None,
            privileged:    false,
            health:        None,
            registry_auth: None,
        }
    }
}

/// A sidecar health check, mapped onto Docker's own.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// The `CMD-SHELL` command, run by the container's default shell.
    pub cmd:             String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ms:     Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms:      Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries:         Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_period_ms: Option<u64>,
}

impl Health {
    /// A check that runs `cmd` on Docker's default schedule.
    pub fn new(cmd: impl Into<String>) -> Self {
        Self {
            cmd:             cmd.into(),
            interval_ms:     None,
            timeout_ms:      None,
            retries:         None,
            start_period_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_round_trips_through_its_value() {
        let mut sidecar = Sidecar::new("db", "postgres:16");
        sidecar
            .env
            .insert("POSTGRES_PASSWORD".to_owned(), "x".to_owned());
        sidecar.health = Some(Health::new("pg_isready"));
        sidecar.privileged = true;
        let config = DockerProviderConfig {
            init: true,
            platform: Some("linux/amd64".to_owned()),
            binds: vec![BindMount {
                host:      "/tmp/ws".to_owned(),
                container: "/workspace".to_owned(),
                mode:      None,
            }],
            sidecars: vec![sidecar],
            ..Default::default()
        };
        let value = config.clone().into_value();
        // Unset optionals are absent, not `null`, so the value reads like a
        // hand-written one and an older parser would accept it.
        assert!(value.get("registry_auth").is_none(), "{value}");
        assert!(value["sidecars"][0].get("user").is_none(), "{value}");
        let parsed: DockerProviderConfig =
            serde_json::from_value(value).expect("the provider parses what it emits");
        assert!(parsed.init);
        assert_eq!(parsed.platform.as_deref(), Some("linux/amd64"));
        assert_eq!(parsed.binds[0].container, "/workspace");
        assert_eq!(
            parsed.sidecars[0].health.as_ref().map(|h| h.cmd.as_str()),
            Some("pg_isready")
        );
        assert!(parsed.sidecars[0].privileged);
    }

    #[test]
    fn the_default_is_the_provider_default() {
        let parsed: DockerProviderConfig =
            serde_json::from_value(serde_json::json!({})).expect("an empty object is the default");
        assert!(parsed.auto_pull);
        assert!(!parsed.init);
        assert!(parsed.sidecars.is_empty());
    }
}
