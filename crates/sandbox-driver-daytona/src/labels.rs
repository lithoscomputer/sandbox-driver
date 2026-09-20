//! The labels Daytona stores for a managed sandbox.

use std::collections::{BTreeMap, HashMap};

use sandbox_driver::{Error, Result};
use sandbox_driver_daytona_config::DockerExecutionTarget;

pub(crate) const MANAGED_LABEL: &str = "sh.sandbox-driver.managed";
pub(crate) const WORKING_DIRECTORY_LABEL: &str = "sh.sandbox-driver.working-directory";
pub(crate) const TARGET_LABEL: &str = "sh.sandbox-driver.docker-target";

pub(crate) fn is_internal_label(key: &str) -> bool {
    matches!(key, MANAGED_LABEL | WORKING_DIRECTORY_LABEL | TARGET_LABEL)
}

/// The labels Daytona stores for a sandbox: the caller's, minus anything
/// that would spoof internal metadata, plus the internal set itself. Both
/// `create` and `set_labels` build them here, so replacing a sandbox's
/// labels cannot drop the nested-Docker target and demote it to a plain
/// VM on the next attach.
pub(crate) fn stored_labels(
    caller: &BTreeMap<String, String>,
    working_directory: Option<&str>,
    docker_target: Option<DockerExecutionTarget>,
) -> HashMap<String, String> {
    let mut labels: HashMap<String, String> = caller
        .iter()
        .filter(|(key, _)| !is_internal_label(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
    if let Some(working_directory) = working_directory {
        labels.insert(
            WORKING_DIRECTORY_LABEL.to_owned(),
            working_directory.to_owned(),
        );
    }
    if let Some(target) = docker_target {
        labels.insert(TARGET_LABEL.to_owned(), target_label(target).to_owned());
    }
    labels
}

/// The stored Daytona label. It must stay the configuration enum's own
/// serde encoding, so a label and a `provider_config` value can never
/// disagree; the tests below pin the two together.
pub(crate) fn target_label(target: DockerExecutionTarget) -> &'static str {
    match target {
        DockerExecutionTarget::Container => "container",
        DockerExecutionTarget::VirtualMachine => "virtual_machine",
    }
}

pub(crate) fn parse_target(label: &str) -> Result<DockerExecutionTarget> {
    match label {
        "container" => Ok(DockerExecutionTarget::Container),
        "virtual_machine" => Ok(DockerExecutionTarget::VirtualMachine),
        _ => Err(Error::invalid_spec(
            "docker-target",
            "unrecognized stored Docker execution target",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_labels_are_the_configuration_encoding_and_round_trip() {
        for target in [
            DockerExecutionTarget::Container,
            DockerExecutionTarget::VirtualMachine,
        ] {
            let label = target_label(target);
            assert_eq!(
                serde_json::to_value(target).expect("plain enum"),
                serde_json::Value::String(label.to_owned()),
                "the Daytona label and provider_config encodings disagree"
            );
            assert_eq!(parse_target(label).expect("own label"), target);
        }
    }
}
