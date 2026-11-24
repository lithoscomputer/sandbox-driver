//! An admitted `SandboxSpec` as boxd create parameters.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZero;

use sandbox_driver::{Error, NetworkPolicy, SandboxSpec, Source};
use serde::Deserialize;

const GIB: u64 = 1024 * 1024 * 1024;
/// boxd's size classes, smallest first: vCPUs and GiB of memory.
const SIZES: [(u32, u64); 4] = [(1, 4), (2, 8), (4, 16), (8, 32)];
/// Every machine gets a fixed disk of this size.
pub(super) const DISK_MIB: u64 = 100 * 1024;
/// The single egress entry that blocks everything.
pub(super) const EGRESS_NONE: &str = "none";
const MAX_NAME: usize = 40;

/// The image name for boxd's own base image. A bare name is an official
/// Docker Hub image, and Docker publishes none called `boxd`, so the name
/// cannot shadow a real image.
pub(super) const BASE_IMAGE: &str = "boxd";

/// What a machine boots from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Base {
    /// boxd's base image, through its fast path.
    Default,
    Image(String),
    Snapshot(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Plan {
    pub(super) name:              String,
    pub(super) base:              Base,
    /// Zero for both means the org's default size.
    pub(super) vcpu:              u32,
    pub(super) memory_bytes:      u64,
    pub(super) delete_after_secs: Option<u64>,
    /// `None` leaves egress unrestricted.
    pub(super) egress:            Option<Vec<String>>,
    pub(super) isolated:          bool,
    pub(super) working_directory: Option<String>,
    pub(super) env:               BTreeMap<String, String>,
    pub(super) labels:            BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProviderConfig {
    isolated: bool,
}

pub(super) fn spec_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "isolated": {
                "type": "boolean",
                "description": "Create an isolated machine: no metadata endpoint, in-machine boxd CLI or integration tokens"
            }
        }
    })
}

/// Maps a spec the core has already validated against this provider's
/// descriptor. Anything boxd cannot honour is refused here, before any
/// machine exists.
pub(super) fn plan(spec: &SandboxSpec) -> Result<Plan, Error> {
    let base = match &spec.source {
        Source::Image(reference) if reference == BASE_IMAGE => Base::Default,
        Source::Image(reference) => Base::Image(reference.clone()),
        Source::Snapshot(id) => Base::Snapshot(id.as_str().to_owned()),
        Source::Dockerfile(_) | Source::HostDirectory => {
            return Err(Error::Unsupported {
                capability: "source".to_owned(),
            });
        }
    };
    if spec.user.is_some() {
        return Err(Error::Unsupported {
            capability: "user".to_owned(),
        });
    }
    let config = ProviderConfig::deserialize(serde_json::Value::Object(
        spec.provider_config.clone().into_iter().collect(),
    ))
    .map_err(|error| Error::InvalidSpec {
        path:    "provider_config".to_owned(),
        message: error.to_string(),
    })?;
    let (vcpu, memory_bytes) = size(spec)?;
    if let Some(working_directory) = &spec.working_directory {
        if !working_directory.starts_with('/') {
            return Err(Error::InvalidSpec {
                path:    "working_directory".to_owned(),
                message: "must be an absolute path".to_owned(),
            });
        }
    }
    Ok(Plan {
        name: machine_name(spec.name.as_deref()),
        base,
        vcpu,
        memory_bytes,
        delete_after_secs: spec
            .timers
            .ttl_ms
            .filter(|ms| *ms > 0)
            .map(|ms| ms.div_ceil(1000)),
        egress: egress(&spec.network),
        isolated: config.isolated,
        working_directory: spec.working_directory.clone(),
        env: spec.env.clone(),
        labels: spec.labels.clone(),
    })
}

/// The smallest size class covering the request, or the org default when
/// nothing is requested.
fn size(spec: &SandboxSpec) -> Result<(u32, u64), Error> {
    let resources = &spec.resources;
    if let Some(disk) = resources.disk_mb {
        if disk.get() > DISK_MIB {
            return Err(Error::InvalidSpec {
                path:    "resources.disk".to_owned(),
                message: format!("boxd machines have a fixed {DISK_MIB} MiB disk"),
            });
        }
    }
    let cpu = resources.cpu_cores.map(NonZero::get);
    let memory = resources.memory_mb.map(NonZero::get);
    if cpu.is_none() && memory.is_none() {
        return Ok((0, 0));
    }
    SIZES
        .iter()
        .find(|(vcpu, gib)| {
            cpu.is_none_or(|cpu| cpu <= *vcpu) && memory.is_none_or(|mib| mib <= gib * 1024)
        })
        .map(|(vcpu, gib)| (*vcpu, gib * GIB))
        .ok_or_else(|| Error::InvalidSpec {
            path:    "resources".to_owned(),
            message: "the largest boxd machine has 8 vCPUs and 32 GiB of memory".to_owned(),
        })
}

fn egress(network: &NetworkPolicy) -> Option<Vec<String>> {
    match network {
        NetworkPolicy::ProviderDefault | NetworkPolicy::AllowAll => None,
        NetworkPolicy::Block => Some(vec![EGRESS_NONE.to_owned()]),
        NetworkPolicy::CidrAllowList { cidrs: allow }
        | NetworkPolicy::DomainAllowList { domains: allow } => Some(allow.clone()),
    }
}

/// The caller's name hint in boxd's machine-name grammar, or empty for a
/// generated name. Callers find machines by id and labels, never by name.
pub(super) fn machine_name(hint: Option<&str>) -> String {
    let Some(hint) = hint else {
        return String::new();
    };
    let mut name = String::new();
    for c in hint.chars().map(|c| c.to_ascii_lowercase()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            name.push(c);
        } else if !name.is_empty() && !name.ends_with('-') {
            name.push('-');
        }
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert_str(0, "sb-");
    }
    // Every character is ASCII, so the cut falls on a character boundary.
    name.truncate(MAX_NAME);
    name.trim_end_matches('-').to_owned()
}

/// The network policy a machine has from its egress allowlist.
pub(super) fn network(egress: &[String]) -> NetworkPolicy {
    match egress {
        [] => NetworkPolicy::AllowAll,
        [only] if only == EGRESS_NONE => NetworkPolicy::Block,
        entries
            if entries
                .iter()
                .all(|entry| entry.parse::<IpAddr>().is_ok() || entry.contains('/')) =>
        {
            NetworkPolicy::CidrAllowList {
                cidrs: entries.to_vec(),
            }
        }
        entries => NetworkPolicy::DomainAllowList {
            domains: entries.to_vec(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use sandbox_driver::SnapshotId;

    use super::*;

    fn image() -> SandboxSpec {
        SandboxSpec::new(Source::Image("ubuntu:24.04".to_owned()))
    }

    #[test]
    fn resources_round_up_to_the_smallest_size_that_covers_them() {
        let mut spec = image();
        assert_eq!(plan(&spec).unwrap().vcpu, 0);
        spec.resources.cpu_cores = NonZeroU32::new(3);
        let planned = plan(&spec).unwrap();
        assert_eq!((planned.vcpu, planned.memory_bytes), (4, 16 * GIB));
        spec.resources.cpu_cores = NonZeroU32::new(1);
        spec.resources.memory_mb = NonZeroU64::new(6000);
        let planned = plan(&spec).unwrap();
        assert_eq!((planned.vcpu, planned.memory_bytes), (2, 8 * GIB));
        spec.resources.memory_mb = NonZeroU64::new(64 * 1024);
        assert!(matches!(plan(&spec), Err(Error::InvalidSpec { .. })));
    }

    #[test]
    fn only_a_lifetime_becomes_a_delete_after_timer() {
        let mut spec = image();
        spec.timers.ttl_ms = Some(90_500);
        assert_eq!(plan(&spec).unwrap().delete_after_secs, Some(91));
        spec.timers.ttl_ms = Some(0);
        assert_eq!(plan(&spec).unwrap().delete_after_secs, None);
    }

    #[test]
    fn network_policies_become_egress_allowlists_and_back() {
        for policy in [
            NetworkPolicy::AllowAll,
            NetworkPolicy::Block,
            NetworkPolicy::DomainAllowList {
                domains: vec!["example.com".to_owned()],
            },
            NetworkPolicy::CidrAllowList {
                cidrs: vec!["1.1.1.0/24".to_owned()],
            },
        ] {
            let entries = egress(&policy).unwrap_or_default();
            assert_eq!(network(&entries), policy);
        }
    }

    #[test]
    fn snapshots_images_and_the_base_image_are_bases_and_a_user_is_refused() {
        let spec = SandboxSpec::new(Source::Image(BASE_IMAGE.to_owned()));
        assert_eq!(plan(&spec).unwrap().base, Base::Default);
        let spec = SandboxSpec::new(Source::Snapshot(SnapshotId::try_new("golden").unwrap()));
        assert_eq!(
            plan(&spec).unwrap().base,
            Base::Snapshot("golden".to_owned())
        );
        let mut spec = image();
        spec.user = Some("root".to_owned());
        assert!(
            matches!(plan(&spec), Err(Error::Unsupported { capability }) if capability == "user")
        );
    }

    #[test]
    fn name_hints_fit_boxd_names() {
        assert_eq!(machine_name(Some("petri-01JABC-l3")), "petri-01jabc-l3");
        assert_eq!(machine_name(Some("Fabro Run #7")), "fabro-run-7");
        assert_eq!(machine_name(Some("42")), "sb-42");
        assert_eq!(machine_name(Some("--")), "");
        assert_eq!(machine_name(None), "");
    }

    #[test]
    fn a_prefixed_name_hint_is_cut_back_to_a_letter_or_digit() {
        let hint = format!("{}-tail", "1".repeat(36));
        let name = machine_name(Some(&hint));
        assert!(name.len() <= MAX_NAME, "{name}");
        assert!(!name.ends_with('-'), "{name}");
    }
}
