//! Turning a portable workload spec into a Daytona sandbox recipe.
//!
//! The caller describes the workload; the recipe is the provider's choice.
//! A workload without services or container options runs as the Daytona
//! sandbox itself, built from its source into a cached snapshot. A workload
//! with either runs as a container inside a Docker-capable runner sandbox,
//! beside its services. Callers never select or see the runner.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use sandbox_driver::contract::{
    ContainerSpec, Error, NetworkPolicy, Resources, SandboxSpec, ServiceSpec, Source,
};
use sandbox_driver::{
    BASH_ENV_VAR, LifecycleTimers, NetworkPolicy as LegacyNetwork, Resources as LegacyResources,
    SandboxKind, SandboxSource, SandboxSpec as LegacySpec,
};
use sandbox_driver_daytona_config::{
    DaytonaProviderConfig, DockerExecutionTarget, NestedDockerConfig, allocation_mib,
};
use serde::Deserialize;

use crate::labels::{IMAGE_LABEL, INTERNAL_PREFIX, RECIPE_LABEL};

/// The Docker-capable runner a nested workload lives in, unless the provider
/// entry names another. It provides Docker, `start-docker` and Python 3.
pub(crate) const DEFAULT_RUNNER_IMAGE: &str =
    "ghcr.io/lithoscomputer/ubuntu-24.04:dind-f8bbbfd81934";
/// The workspace a nested workload gets when the spec names none.
const NESTED_WORKSPACE: &str = "/workspace";
/// The smallest runner that holds Docker, the workload and its services.
const RUNNER_MIN_CPU: u32 = 2;
const RUNNER_MIN_MEMORY_MB: u64 = 4096;
/// Ports the runner's own daemons hold: the toolbox, the web terminal and
/// SSH. A service on the runner's network cannot take them.
const RESERVED_PORTS: [u16; 3] = [2280, 22220, 22222];

pub(crate) const DIRECT: &str = "direct";
pub(crate) const NESTED: &str = "nested";

/// Per-sandbox options with no provider-neutral meaning. The descriptor's
/// `spec_schema` describes the same fields.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SpecOptions {
    outbound_proxy_url: Option<String>,
}

pub(super) fn spec_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "outbound_proxy_url": {
                "type": "string",
                "minLength": 1,
                "description": "Route the sandbox's outbound HTTP(S) through this proxy"
            }
        }
    })
}

/// What a nested workload needs once its runner exists.
#[derive(Clone)]
pub(super) struct Nested {
    pub(super) image:     WorkloadImage,
    pub(super) services:  BTreeMap<String, ServiceSpec>,
    pub(super) container: ContainerSpec,
    pub(super) user:      Option<String>,
    pub(super) env:       BTreeMap<String, String>,
    /// Applied once provisioning has pulled what it needs, so a restrictive
    /// policy does not block the images the workload is made from.
    pub(super) network:   LegacyNetwork,
}

#[derive(Clone)]
pub(super) enum WorkloadImage {
    Pull(String),
    /// Dockerfile text, built inside the runner under a tag named by its
    /// digest.
    Build {
        content: String,
        tag:     String,
    },
}

impl WorkloadImage {
    /// The reference the workload container runs.
    pub(super) fn reference(&self) -> &str {
        match self {
            Self::Pull(reference) => reference,
            Self::Build { tag, .. } => tag,
        }
    }
}

pub(super) struct Plan {
    pub(super) legacy: LegacySpec,
    pub(super) labels: BTreeMap<String, String>,
    /// `None` runs the workload as the Daytona sandbox itself.
    pub(super) nested: Option<Nested>,
}

/// Validates what Daytona cannot honour, beyond the descriptor check the
/// catalog already ran, and chooses the recipe.
pub(super) fn plan(spec: &SandboxSpec, runner_image: &str) -> Result<Plan, Error> {
    reject_reserved(spec)?;
    let options = spec_options(spec)?;
    let nested = !spec.services.is_empty() || spec.container.is_some();
    let timers = timers(spec)?;
    let network = network(&spec.network);
    let mut labels = BTreeMap::from([(
        RECIPE_LABEL.to_owned(),
        if nested { NESTED } else { DIRECT }.to_owned(),
    )]);
    if let Source::Image(reference) = &spec.source {
        labels.insert(IMAGE_LABEL.to_owned(), reference.clone());
    }
    let mut legacy;
    let nested = if nested {
        let image = match &spec.source {
            Source::Image(reference) => WorkloadImage::Pull(reference.clone()),
            Source::Dockerfile(content) => WorkloadImage::Build {
                content: content.clone(),
                tag:     build_tag(content),
            },
            Source::Snapshot(_) | Source::HostDirectory => {
                return Err(unsupported(if spec.services.is_empty() {
                    "container"
                } else {
                    "services"
                }));
            }
        };
        validate_service_ports(&spec.services)?;
        legacy = LegacySpec::new(SandboxSource::Image {
            reference: runner_image.to_owned(),
        });
        legacy.resources = runner_resources(spec)?;
        legacy.sandbox_kind = Some(SandboxKind::Container);
        legacy.working_directory = Some(
            spec.working_directory
                .clone()
                .unwrap_or_else(|| NESTED_WORKSPACE.to_owned()),
        );
        legacy.provider_config = DaytonaProviderConfig {
            outbound_proxy_url: options.outbound_proxy_url,
            docker:             Some(nested_target(
                DockerExecutionTarget::Container,
                image.reference(),
            )),
        }
        .into_value();
        Some(Nested {
            image,
            services: spec.services.clone(),
            container: spec.container.clone().unwrap_or_default(),
            user: spec.user.clone(),
            env: spec.env.clone(),
            network: network.clone(),
        })
    } else {
        legacy = LegacySpec::new(match &spec.source {
            Source::Image(reference) => SandboxSource::Image {
                reference: reference.clone(),
            },
            Source::Dockerfile(content) => SandboxSource::Dockerfile {
                content: content.clone(),
            },
            Source::Snapshot(id) => {
                if spec.resources != Resources::default() {
                    return Err(Error::InvalidSpec {
                        path:    "resources".to_owned(),
                        message: "a Daytona snapshot fixes the resources of its sandboxes"
                            .to_owned(),
                    });
                }
                SandboxSource::Snapshot { id: id.clone() }
            }
            Source::HostDirectory => return Err(unsupported("source")),
        });
        legacy.resources = resources(spec);
        // The descriptor promises container isolation, so a snapshot must be
        // container-class too; the legacy create refuses any other class.
        legacy.sandbox_kind = Some(SandboxKind::Container);
        legacy.working_directory.clone_from(&spec.working_directory);
        legacy.user.clone_from(&spec.user);
        legacy.network = network;
        // One-shot containers run on Docker inside the workload, when the
        // workload provides it; the target marks that on the sandbox.
        legacy.provider_config = DaytonaProviderConfig {
            outbound_proxy_url: options.outbound_proxy_url,
            docker:             Some(nested_target(DockerExecutionTarget::VirtualMachine, "")),
        }
        .into_value();
        None
    };
    legacy.name.clone_from(&spec.name);
    legacy.env.clone_from(&spec.env);
    legacy.labels.clone_from(&spec.labels);
    legacy.timers = timers;
    Ok(Plan {
        legacy,
        labels,
        nested,
    })
}

/// Records where exec runs. Provisioning is this module's, so only the
/// target and the workload image are set.
fn nested_target(target: DockerExecutionTarget, image: &str) -> NestedDockerConfig {
    serde_json::from_value(serde_json::json!({ "target": target, "image": image }))
        .expect("a target-only nested Docker configuration is valid")
}

fn build_tag(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(content.as_bytes());
    let mut hex = String::new();
    for byte in &digest[..8] {
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sandbox-driver-workload:{hex}")
}

fn reject_reserved(spec: &SandboxSpec) -> Result<(), Error> {
    if spec
        .labels
        .keys()
        .any(|key| key.starts_with(INTERNAL_PREFIX))
    {
        return Err(Error::InvalidSpec {
            path:    "labels".to_owned(),
            message: format!("keys under {INTERNAL_PREFIX} are reserved for provider metadata"),
        });
    }
    // The sandbox's own environment carries this blank so that no startup
    // file runs ahead of a command; a caller value could not round-trip.
    if spec.env.contains_key(BASH_ENV_VAR) {
        return Err(Error::InvalidSpec {
            path:    "env".to_owned(),
            message: format!("{BASH_ENV_VAR} is reserved by the Daytona provider"),
        });
    }
    Ok(())
}

fn spec_options(spec: &SandboxSpec) -> Result<SpecOptions, Error> {
    let value = serde_json::Value::Object(spec.provider_config.clone().into_iter().collect());
    SpecOptions::deserialize(value).map_err(|error| Error::InvalidSpec {
        path:    "provider_config".to_owned(),
        message: error.to_string(),
    })
}

fn resources(spec: &SandboxSpec) -> LegacyResources {
    let mut resources = LegacyResources::default();
    resources.cpu_cores = spec.resources.cpu_cores.map(NonZeroU32::get);
    resources.memory_mb = spec.resources.memory_mb.map(NonZeroU64::get);
    resources.disk_mb = spec.resources.disk_mb.map(NonZeroU64::get);
    resources
}

/// The runner holds the workload and its services, so it has a floor. An
/// explicit request below it is refused rather than silently raised.
fn runner_resources(spec: &SandboxSpec) -> Result<LegacyResources, Error> {
    let mut resources = resources(spec);
    match resources.cpu_cores {
        Some(cpu) if cpu < RUNNER_MIN_CPU => {
            return Err(Error::InvalidSpec {
                path:    "resources.cpu_cores".to_owned(),
                message: format!(
                    "a workload with services or container options needs at least {RUNNER_MIN_CPU} cores on Daytona"
                ),
            });
        }
        Some(_) => {}
        None => resources.cpu_cores = Some(RUNNER_MIN_CPU),
    }
    match resources.memory_mb.map(allocation_mib) {
        Some(memory) if memory < RUNNER_MIN_MEMORY_MB => {
            return Err(Error::InvalidSpec {
                path:    "resources.memory_mb".to_owned(),
                message: format!(
                    "a workload with services or container options needs at least {RUNNER_MIN_MEMORY_MB} MiB on Daytona"
                ),
            });
        }
        Some(_) => {}
        None => resources.memory_mb = Some(RUNNER_MIN_MEMORY_MB),
    }
    Ok(resources)
}

/// Contract timers are milliseconds where zero disables; Daytona counts
/// whole minutes and reads zero differently per timer.
fn timers(spec: &SandboxSpec) -> Result<LifecycleTimers, Error> {
    let duration = |ms: u64| Duration::from_millis(ms);
    let mut timers = LifecycleTimers::default();
    // Wire zero disables auto-stop; the legacy encoding sends `-1` for a
    // disabled auto-delete, since Daytona's zero deletes on stop.
    timers.auto_stop_after_idle = spec.timers.auto_stop_ms.map(duration);
    timers.auto_delete_after_stop = spec.timers.auto_delete_ms.map(duration);
    timers.auto_archive_after_stop = match spec.timers.auto_archive_ms {
        // Daytona reads zero as its maximum interval; it cannot disable it.
        Some(0) => {
            return Err(Error::InvalidSpec {
                path:    "timers.auto_archive_ms".to_owned(),
                message: "Daytona cannot disable auto-archive; give an interval".to_owned(),
            });
        }
        other => other.map(duration),
    };
    // Daytona applies no TTL unless one is set, so a disabled TTL is unset.
    timers.ttl = spec.timers.ttl_ms.filter(|ms| *ms != 0).map(duration);
    Ok(timers)
}

/// The contract's network policy as the legacy provider takes it, and
/// [`contract_network`] the other way; keep the two together.
fn network(policy: &NetworkPolicy) -> LegacyNetwork {
    match policy {
        NetworkPolicy::ProviderDefault => LegacyNetwork::ProviderDefault,
        NetworkPolicy::AllowAll => LegacyNetwork::AllowAll,
        NetworkPolicy::Block => LegacyNetwork::Block,
        NetworkPolicy::CidrAllowList { cidrs } => LegacyNetwork::CidrAllowList {
            cidrs: cidrs.clone(),
        },
        NetworkPolicy::DomainAllowList { domains } => LegacyNetwork::DomainAllowList {
            domains: domains.clone(),
        },
    }
}

/// A legacy network policy read back as the contract's. `None` is a policy
/// the contract cannot express, reported as not observed.
pub(super) fn contract_network(policy: LegacyNetwork) -> Option<NetworkPolicy> {
    Some(match policy {
        LegacyNetwork::ProviderDefault => NetworkPolicy::ProviderDefault,
        LegacyNetwork::AllowAll => NetworkPolicy::AllowAll,
        LegacyNetwork::Block => NetworkPolicy::Block,
        LegacyNetwork::CidrAllowList { cidrs } => NetworkPolicy::CidrAllowList { cidrs },
        LegacyNetwork::DomainAllowList { domains } => NetworkPolicy::DomainAllowList { domains },
        _ => return None,
    })
}

/// Services share the runner's network with the workload, so their ports
/// must not collide with each other or with the runner's daemons.
fn validate_service_ports(services: &BTreeMap<String, ServiceSpec>) -> Result<(), Error> {
    let mut taken = BTreeSet::new();
    for (name, service) in services {
        for port in &service.ports {
            if RESERVED_PORTS.contains(&port.get()) || !taken.insert(port.get()) {
                return Err(Error::InvalidSpec {
                    path:    format!("services.{name}.ports"),
                    message: format!("port {port} is already taken on the workload's network"),
                });
            }
        }
    }
    Ok(())
}

fn unsupported(capability: &str) -> Error {
    Error::Unsupported {
        capability: capability.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use sandbox_driver::SnapshotId;
    use sandbox_driver::contract::{ServiceSpec, Timers};

    use super::*;

    fn image() -> SandboxSpec {
        SandboxSpec::new(Source::Image("buildpack-deps:noble".to_owned()))
    }

    #[test]
    fn a_plain_workload_is_the_sandbox_itself() {
        let mut spec = image();
        spec.working_directory = Some("/srv/app".to_owned());
        spec.labels.insert("job".to_owned(), "1842".to_owned());
        let plan = plan(&spec, DEFAULT_RUNNER_IMAGE).expect("valid");
        assert!(plan.nested.is_none());
        assert!(matches!(
            &plan.legacy.source,
            SandboxSource::Image { reference } if reference == "buildpack-deps:noble"
        ));
        assert_eq!(plan.legacy.working_directory.as_deref(), Some("/srv/app"));
        assert_eq!(plan.labels[RECIPE_LABEL], DIRECT);
        assert_eq!(plan.labels[IMAGE_LABEL], "buildpack-deps:noble");
        assert_eq!(plan.legacy.labels["job"], "1842");
    }

    #[test]
    fn services_move_the_workload_into_the_providers_runner() {
        let mut spec = image();
        let mut postgres = ServiceSpec::new("postgres:16");
        postgres.ports = vec![NonZeroU16::new(5432).unwrap()];
        spec.services.insert("db".to_owned(), postgres);
        spec.env.insert("CI".to_owned(), "1".to_owned());
        let plan = plan(&spec, "registry.test/runner:pinned").expect("valid");
        let nested = plan.nested.expect("nested recipe");
        // The caller's image is the workload; the runner is the provider's.
        assert!(
            matches!(&nested.image, WorkloadImage::Pull(image) if image == "buildpack-deps:noble")
        );
        assert!(matches!(
            &plan.legacy.source,
            SandboxSource::Image { reference } if reference == "registry.test/runner:pinned"
        ));
        assert_eq!(nested.env["CI"], "1");
        assert_eq!(plan.legacy.resources.cpu_cores, Some(RUNNER_MIN_CPU));
        assert_eq!(plan.legacy.resources.memory_mb, Some(RUNNER_MIN_MEMORY_MB));
        assert_eq!(
            plan.legacy.working_directory.as_deref(),
            Some(NESTED_WORKSPACE)
        );
        assert_eq!(plan.labels[RECIPE_LABEL], NESTED);
    }

    #[test]
    fn an_explicit_runner_size_below_the_floor_is_refused_not_raised() {
        let mut spec = image();
        spec.container = Some(ContainerSpec::default());
        spec.resources.memory_mb = NonZeroU64::new(2048);
        assert!(matches!(
            plan(&spec, DEFAULT_RUNNER_IMAGE),
            Err(Error::InvalidSpec { path, .. }) if path == "resources.memory_mb"
        ));
        spec.resources.memory_mb = NonZeroU64::new(3073);
        spec.resources.cpu_cores = NonZeroU32::new(4);
        let plan = plan(&spec, DEFAULT_RUNNER_IMAGE).expect("rounds to 4 GiB");
        assert_eq!(plan.legacy.resources.cpu_cores, Some(4));
    }

    #[test]
    fn services_cannot_run_beside_a_snapshot_workload() {
        let mut spec = SandboxSpec::new(Source::Snapshot(SnapshotId::try_new("snap").unwrap()));
        spec.services
            .insert("db".to_owned(), ServiceSpec::new("postgres:16"));
        assert!(matches!(
            plan(&spec, DEFAULT_RUNNER_IMAGE),
            Err(Error::Unsupported { capability }) if capability == "services"
        ));
    }

    #[test]
    fn a_snapshot_workload_must_be_container_class() {
        let spec = SandboxSpec::new(Source::Snapshot(SnapshotId::try_new("snap").unwrap()));
        let plan = plan(&spec, DEFAULT_RUNNER_IMAGE).expect("valid");
        // The legacy create refuses a snapshot of any other class.
        assert_eq!(plan.legacy.sandbox_kind, Some(SandboxKind::Container));
    }

    #[test]
    fn colliding_and_reserved_service_ports_are_refused() {
        let port = |value| NonZeroU16::new(value).unwrap();
        let mut spec = image();
        let mut first = ServiceSpec::new("redis:7");
        first.ports = vec![port(6379)];
        let mut second = ServiceSpec::new("redis:7");
        second.ports = vec![port(6379)];
        spec.services.insert("a".to_owned(), first);
        spec.services.insert("b".to_owned(), second);
        assert!(matches!(
            plan(&spec, DEFAULT_RUNNER_IMAGE),
            Err(Error::InvalidSpec { path, .. }) if path == "services.b.ports"
        ));
        let mut toolbox = ServiceSpec::new("redis:7");
        toolbox.ports = vec![port(2280)];
        spec.services = BTreeMap::from([("a".to_owned(), toolbox)]);
        assert!(plan(&spec, DEFAULT_RUNNER_IMAGE).is_err());
    }

    #[test]
    fn timers_translate_zero_per_daytona_timer() {
        let mut spec = image();
        spec.timers = Timers {
            auto_stop_ms:    Some(0),
            auto_archive_ms: None,
            auto_delete_ms:  Some(0),
            ttl_ms:          Some(0),
        };
        let timers = plan(&spec, DEFAULT_RUNNER_IMAGE)
            .expect("valid")
            .legacy
            .timers;
        // The legacy encoder sends 0 for a disabled auto-stop and -1 for a
        // disabled auto-delete; an unset TTL is Daytona's "none".
        assert_eq!(timers.auto_stop_after_idle, Some(Duration::ZERO));
        assert_eq!(timers.auto_delete_after_stop, Some(Duration::ZERO));
        assert_eq!(timers.ttl, None);
        spec.timers.auto_archive_ms = Some(0);
        assert!(matches!(
            plan(&spec, DEFAULT_RUNNER_IMAGE),
            Err(Error::InvalidSpec { path, .. }) if path == "timers.auto_archive_ms"
        ));
    }

    #[test]
    fn reserved_labels_env_and_unknown_options_are_refused_not_dropped() {
        let mut spec = image();
        spec.labels
            .insert("sh.sandbox-driver.recipe".to_owned(), "direct".to_owned());
        assert!(
            matches!(plan(&spec, DEFAULT_RUNNER_IMAGE), Err(Error::InvalidSpec { path, .. }) if path == "labels")
        );
        let mut spec = image();
        spec.env
            .insert("BASH_ENV".to_owned(), "/etc/profile".to_owned());
        assert!(
            matches!(plan(&spec, DEFAULT_RUNNER_IMAGE), Err(Error::InvalidSpec { path, .. }) if path == "env")
        );
        let mut spec = image();
        spec.provider_config
            .insert("docker".to_owned(), serde_json::json!({"image": "x"}));
        assert!(matches!(
            plan(&spec, DEFAULT_RUNNER_IMAGE),
            Err(Error::InvalidSpec { path, .. }) if path == "provider_config"
        ));
    }
}
