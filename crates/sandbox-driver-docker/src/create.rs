//! Creating a sandbox container: a plan decided from the spec alone, then
//! a guarded launch that removes what it created when a later step fails.

use std::collections::HashMap;

use bollard::container::{Config, CreateContainerOptions};
use bollard::models::{HostConfig, Mount, MountTypeEnum};
use sandbox_driver::{
    BASH_ENV_VAR, Error, LifecycleTimers, NetworkPolicy, Result, SandboxKind, SandboxSource,
    SandboxSpec,
};
use serde::Deserialize;

use crate::config::{DockerProviderConfig, RegistryAuth, Sidecar};
use crate::daemon::{POSIX_SH, shell_quote};
use crate::{
    DEFAULT_WORKING_DIRECTORY, MANAGED_LABEL, RUNTIME_DIRECTORY, RUNTIME_DIRECTORY_PARENT,
    SIDECAR_NETWORK_LABEL, non_empty,
};

/// Everything `create` decides before it touches the daemon, derived from
/// the spec alone: the image to have ready, the container to create, and
/// the sidecars to bring up beside it.
#[derive(Debug)]
pub(crate) struct ContainerPlan {
    pub(crate) image:           String,
    pub(crate) auto_pull:       bool,
    pub(crate) registry_auth:   Option<RegistryAuth>,
    pub(crate) platform:        Option<String>,
    pub(crate) sidecars:        Vec<Sidecar>,
    /// The user-defined network the sandbox and its sidecars share, when
    /// it has sidecars.
    pub(crate) sidecar_network: Option<String>,
    pub(crate) config:          Config<String>,
    pub(crate) options:         Option<CreateContainerOptions<String>>,
    /// Whether the spec named the container: a create conflict is then
    /// the caller's name, not the daemon.
    pub(crate) named:           bool,
}

impl ContainerPlan {
    /// Validates the spec and maps it onto a container. Deterministic:
    /// no daemon is consulted.
    pub(crate) fn plan(spec: &SandboxSpec) -> Result<Self> {
        spec.validate()?;
        validate_supported_creation_fields(spec)?;
        if matches!(spec.sandbox_kind, Some(kind) if kind != SandboxKind::Container) {
            return Err(Error::invalid_spec(
                "sandbox_kind",
                "the docker provider creates container sandboxes only",
            ));
        }
        let SandboxSource::Image { reference } = &spec.source else {
            return Err(Error::invalid_spec(
                "source",
                "the docker provider supports SandboxSource::Image only",
            ));
        };
        if !spec.volumes.is_empty() {
            return Err(Error::invalid_spec(
                "volumes",
                "the docker provider does not support volumes yet",
            ));
        }
        let config_options = provider_config(&spec.provider_config)?;
        let base_network = if config_options.host_network {
            if !matches!(
                spec.network,
                NetworkPolicy::ProviderDefault | NetworkPolicy::AllowAll
            ) || !config_options.sidecars.is_empty()
            {
                return Err(Error::invalid_spec(
                    "provider_config.host_network",
                    "host networking requires unrestricted networking and no sidecars",
                ));
            }
            Some("host".to_owned())
        } else {
            network_mode(&spec.network)?
        };
        // Sidecars live on one user-defined network the main container
        // joins, named after the sandbox. They need a named sandbox.
        let sidecar_network = if config_options.sidecars.is_empty() {
            None
        } else {
            let name = spec.name.clone().ok_or_else(|| {
                Error::invalid_spec("name", "a sandbox with sidecars must be named")
            })?;
            Some(format!("{name}-net"))
        };

        let working_dir = spec
            .working_directory
            .clone()
            .unwrap_or_else(|| DEFAULT_WORKING_DIRECTORY.to_owned());
        let mut labels: HashMap<String, String> = spec
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
        if let Some(network) = &sidecar_network {
            labels.insert(SIDECAR_NETWORK_LABEL.to_owned(), network.clone());
        }

        let DockerProviderConfig {
            auto_pull,
            init,
            privileged,
            platform,
            binds,
            extra_hosts,
            dns,
            cap_add,
            registry_auth,
            sidecars,
            ..
        } = config_options;
        // The labeled primary must exist before any dependent
        // resource. Keep it stopped and isolated while preparing
        // its network; the label records cleanup identity even
        // before the container joins that network.
        let network_mode = if sidecar_network.is_some() {
            Some("none".to_owned())
        } else {
            base_network
        };
        // The workspace is the sandbox's own volume, unless the
        // caller bound a host directory there.
        let workspace_bound = binds
            .iter()
            .any(|bind| bind.container.trim_end_matches('/') == working_dir.trim_end_matches('/'));
        let mounts = (!workspace_bound).then(|| {
            vec![Mount {
                target: Some(working_dir.clone()),
                typ: Some(MountTypeEnum::VOLUME),
                ..Default::default()
            }]
        });
        let binds: Vec<String> = binds
            .iter()
            .map(|bind| {
                let mode = bind.mode.as_deref().unwrap_or("rw");
                format!("{}:{}:{mode}", bind.host, bind.container)
            })
            .collect();
        let host_config = HostConfig {
            network_mode,
            binds: non_empty(binds),
            mounts,
            init: init.then_some(true),
            privileged: privileged.then_some(true),
            extra_hosts: non_empty(extra_hosts),
            dns: non_empty(dns),
            cap_add: non_empty(cap_add),
            memory: spec
                .resources
                .memory_mb
                .and_then(|mb| i64::try_from(mb).ok())
                .map(|mb| mb * 1024 * 1024),
            cpu_quota: spec
                .resources
                .cpu_cores
                .map(|cores| i64::from(cores) * 100_000),
            ..Default::default()
        };
        // Blank BASH_ENV at the container level too: an image (or spec)
        // startup file would otherwise run inside the init command below
        // and can kill the container the moment it starts.
        let mut env_entries: Vec<String> = spec
            .env
            .iter()
            .filter(|(key, _)| key.as_str() != BASH_ENV_VAR)
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        env_entries.push(format!("{BASH_ENV_VAR}="));
        // The init script is POSIX and runs under /bin/sh, which
        // every Linux image has.
        let config = Config {
            image: Some(reference.clone()),
            user: spec.user.clone(),
            cmd: Some(vec![
                POSIX_SH.to_owned(),
                "-c".to_owned(),
                format!(
                    "mkdir -p {working_dir} {runtime_dir} && chmod 0700 \
                     {runtime_parent} {runtime_dir} && exec sleep infinity",
                    working_dir = shell_quote(&working_dir),
                    runtime_parent = shell_quote(RUNTIME_DIRECTORY_PARENT),
                    runtime_dir = shell_quote(RUNTIME_DIRECTORY),
                ),
            ]),
            working_dir: Some(working_dir),
            env: Some(env_entries),
            labels: Some(labels),
            host_config: Some(host_config),
            ..Default::default()
        };
        let options = (spec.name.is_some() || platform.is_some()).then(|| CreateContainerOptions {
            name:     spec.name.clone().unwrap_or_default(),
            platform: platform.clone(),
        });
        Ok(Self {
            image: reference.clone(),
            auto_pull,
            registry_auth,
            platform,
            sidecars,
            sidecar_network,
            config,
            options,
            named: spec.name.is_some(),
        })
    }
}

/// Parses `SandboxSpec::provider_config` as [`DockerProviderConfig`]:
/// `null` is the default, an object is validated, anything else is
/// rejected.
fn provider_config(value: &serde_json::Value) -> Result<DockerProviderConfig> {
    match value {
        serde_json::Value::Null => Ok(DockerProviderConfig::default()),
        serde_json::Value::Object(_) => DockerProviderConfig::deserialize(value)
            .map_err(|error| Error::invalid_spec("provider_config", error.to_string())),
        _ => Err(Error::invalid_spec("provider_config", "expected an object")),
    }
}

fn network_mode(policy: &NetworkPolicy) -> Result<Option<String>> {
    match policy {
        NetworkPolicy::ProviderDefault => Ok(None),
        NetworkPolicy::AllowAll => Ok(Some("bridge".to_owned())),
        NetworkPolicy::Block => Ok(Some("none".to_owned())),
        NetworkPolicy::CidrAllowList { .. } => Err(Error::invalid_spec(
            "network",
            "the docker provider does not support CIDR allow lists",
        )),
        NetworkPolicy::DomainAllowList { .. } => Err(Error::invalid_spec(
            "network",
            "the docker provider does not support domain allow lists",
        )),
        _ => Err(Error::invalid_spec("network", "unsupported network policy")),
    }
}

fn validate_supported_creation_fields(spec: &SandboxSpec) -> Result<()> {
    if spec.resources.disk_mb.is_some() {
        return Err(Error::invalid_spec(
            "resources.disk_mb",
            "the docker provider does not enforce a writable-layer disk limit",
        ));
    }
    if spec.resources.gpus.is_some() {
        return Err(Error::invalid_spec(
            "resources.gpus",
            "the docker provider does not configure GPU devices",
        ));
    }
    if spec.timers != LifecycleTimers::default() {
        return Err(Error::invalid_spec(
            "timers",
            "the docker provider does not support lifecycle timers",
        ));
    }
    if spec.ephemeral {
        return Err(Error::invalid_spec(
            "ephemeral",
            "the docker provider does not delete a container when it stops",
        ));
    }
    if spec.public.is_some() {
        return Err(Error::invalid_spec(
            "public",
            "the docker provider does not manage public access",
        ));
    }
    if spec.region.is_some() {
        return Err(Error::invalid_spec(
            "region",
            "the docker provider does not select a region",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn image_spec() -> SandboxSpec {
        SandboxSpec::new(SandboxSource::Image {
            reference: "debian:stable-slim".to_owned(),
        })
    }

    fn host_config(plan: &ContainerPlan) -> &HostConfig {
        plan.config.host_config.as_ref().expect("host config")
    }

    fn assert_invalid_field(spec: &SandboxSpec, expected_field: &str) {
        let error = validate_supported_creation_fields(spec)
            .expect_err("unsupported field should fail validation");
        assert!(
            matches!(&error, Error::InvalidSpec { field, .. } if field == expected_field),
            "expected InvalidSpec for {expected_field}, got {error}"
        );
    }

    #[test]
    fn a_plain_spec_plans_a_workspace_volume_and_a_blank_bash_env() {
        let spec = image_spec()
            .env_var("KEY", "value")
            .env_var(BASH_ENV_VAR, "/untrusted");
        let plan = ContainerPlan::plan(&spec).expect("plan");
        assert_eq!(plan.image, "debian:stable-slim");
        assert!(plan.sidecar_network.is_none());
        assert!(plan.options.is_none());
        assert_eq!(
            plan.config.working_dir.as_deref(),
            Some(DEFAULT_WORKING_DIRECTORY)
        );
        let host = host_config(&plan);
        assert_eq!(host.network_mode, None);
        assert_eq!(host.binds, None);
        let mounts = host.mounts.as_ref().expect("workspace volume");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].typ, Some(MountTypeEnum::VOLUME));
        assert_eq!(mounts[0].target.as_deref(), Some(DEFAULT_WORKING_DIRECTORY));
        assert_eq!(
            plan.config.env,
            Some(vec!["KEY=value".to_owned(), format!("{BASH_ENV_VAR}=")])
        );
        let labels = plan.config.labels.as_ref().expect("labels");
        assert_eq!(labels.get(MANAGED_LABEL).map(String::as_str), Some("true"));
        assert!(!labels.contains_key(SIDECAR_NETWORK_LABEL));
    }

    #[test]
    fn a_bind_at_the_working_directory_replaces_the_workspace_volume() {
        let mut spec = image_spec().working_directory("/srv/app/");
        spec.provider_config = json!({
            "binds": [
                {"host": "/tmp/app", "container": "/srv/app"},
                {"host": "/tmp/data", "container": "/data", "mode": "ro"}
            ]
        });
        let plan = ContainerPlan::plan(&spec).expect("plan");
        let host = host_config(&plan);
        assert_eq!(host.mounts, None, "the bound workspace needs no volume");
        assert_eq!(
            host.binds,
            Some(vec![
                "/tmp/app:/srv/app:rw".to_owned(),
                "/tmp/data:/data:ro".to_owned(),
            ])
        );
    }

    #[test]
    fn sidecars_keep_the_container_isolated_while_preparing_their_network() {
        let mut spec = image_spec().name("demo");
        spec.provider_config = json!({"sidecars": [{"name": "db", "image": "postgres:16"}]});
        let plan = ContainerPlan::plan(&spec).expect("plan");
        assert_eq!(plan.sidecar_network.as_deref(), Some("demo-net"));
        assert_eq!(plan.sidecars.len(), 1);
        assert_eq!(host_config(&plan).network_mode.as_deref(), Some("none"));
        let labels = plan.config.labels.as_ref().expect("labels");
        assert_eq!(
            labels.get(SIDECAR_NETWORK_LABEL).map(String::as_str),
            Some("demo-net")
        );
        let options = plan.options.expect("a named container");
        assert_eq!(options.name, "demo");
        assert_eq!(options.platform, None);
    }

    #[test]
    fn sidecars_need_a_named_sandbox() {
        let mut spec = image_spec();
        spec.provider_config = json!({"sidecars": [{"name": "db", "image": "postgres:16"}]});
        let error = ContainerPlan::plan(&spec).expect_err("unnamed");
        assert!(matches!(error, Error::InvalidSpec { field, .. } if field == "name"));
    }

    #[test]
    fn network_policies_map_onto_network_modes() {
        let plan = ContainerPlan::plan(&image_spec().network(NetworkPolicy::Block)).expect("plan");
        assert_eq!(host_config(&plan).network_mode.as_deref(), Some("none"));
        let plan =
            ContainerPlan::plan(&image_spec().network(NetworkPolicy::AllowAll)).expect("plan");
        assert_eq!(host_config(&plan).network_mode.as_deref(), Some("bridge"));

        let mut spec = image_spec();
        spec.provider_config = json!({"host_network": true});
        let plan = ContainerPlan::plan(&spec).expect("plan");
        assert_eq!(host_config(&plan).network_mode.as_deref(), Some("host"));

        let mut spec = image_spec().network(NetworkPolicy::Block);
        spec.provider_config = json!({"host_network": true});
        let error = ContainerPlan::plan(&spec).expect_err("host networking is unrestricted");
        assert!(matches!(
            error,
            Error::InvalidSpec { field, .. } if field == "provider_config.host_network"
        ));
    }

    #[test]
    fn resources_and_platform_reach_the_container() {
        let mut spec = image_spec();
        spec.resources.cpu_cores = Some(2);
        spec.resources.memory_mb = Some(512);
        spec.provider_config = json!({"platform": "linux/amd64", "init": true});
        let plan = ContainerPlan::plan(&spec).expect("plan");
        let host = host_config(&plan);
        assert_eq!(host.memory, Some(512 * 1024 * 1024));
        assert_eq!(host.cpu_quota, Some(200_000));
        assert_eq!(host.init, Some(true));
        assert_eq!(plan.platform.as_deref(), Some("linux/amd64"));
        let options = plan.options.expect("a platform names options");
        assert_eq!(options.name, "");
        assert_eq!(options.platform.as_deref(), Some("linux/amd64"));
    }

    #[test]
    fn unsupported_creation_fields_return_invalid_spec() {
        let mut spec = image_spec();
        spec.resources.disk_mb = Some(1024);
        assert_invalid_field(&spec, "resources.disk_mb");

        let mut spec = image_spec();
        spec.resources.gpus = Some(1);
        assert_invalid_field(&spec, "resources.gpus");

        let mut spec = image_spec();
        spec.timers.auto_stop_after_idle = Some(Duration::from_secs(60));
        assert_invalid_field(&spec, "timers");

        let mut spec = image_spec();
        spec.ephemeral = true;
        assert_invalid_field(&spec, "ephemeral");

        let mut spec = image_spec();
        spec.public = Some(false);
        assert_invalid_field(&spec, "public");

        let mut spec = image_spec();
        spec.region = Some("local".to_owned());
        assert_invalid_field(&spec, "region");
    }

    #[test]
    fn supported_cpu_and_memory_requests_pass_creation_field_validation() {
        let mut spec = image_spec();
        spec.resources.cpu_cores = Some(2);
        spec.resources.memory_mb = Some(4096);
        validate_supported_creation_fields(&spec).expect("CPU and memory are supported");
    }
}
