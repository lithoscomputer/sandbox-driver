//! Public contract tests. Fixtures assert behavior at persisted/serialized
//! boundaries, not complete serialized shape snapshots.

use std::collections::BTreeMap;

use sandbox_driver::contract::{
    AccessScope, CapabilitySet, Descriptor, Durability, Environment, Error, MutationOutcome,
    NamespaceId, ProviderEntry, ProviderSchemas, SandboxRef, SandboxSpec, SandboxState, Source,
    Status,
};
use serde_json::{Value, json};

fn reference() -> SandboxRef {
    serde_json::from_value(json!({
        "provider": "production", "namespace": "daytona:org-original", "id": "sb-123"
    }))
    .expect("valid saved reference")
}

fn workload() -> Value {
    json!({
        "source": {"image": "ubuntu:24.04"},
        "env": {"TOKEN": "workload-secret"},
        "resources": {"cpu_cores": 2, "memory_mb": 4096},
        "network": {"mode": "block"},
        "services": {
            "postgres": {
                "image": "postgres:16", "credential": "registry-production",
                "env": {"PASSWORD": "service-secret"}, "ports": [5432],
                "ready": {
                    "command": ["pg_isready"], "interval_ms": 2000,
                    "timeout_ms": 1000, "deadline_ms": 60000, "retries": 30
                }
            }
        },
        "container": {"init": true, "privileged": false, "shm_size_mb": 64},
        "provider_config": {"vendor-option": "opaque-secret"}
    })
}

#[test]
fn saved_reference_does_not_depend_on_the_environment_catalog() {
    let environment: Environment = serde_json::from_value(json!({
        "provider": "production", "spec": {"source": {"image": "ubuntu:24.04"}}
    }))
    .expect("environment decodes");
    let mut environments = BTreeMap::from([("build", environment)]);
    let saved = serde_json::to_string(&reference()).expect("reference serializes");
    environments.clear();
    let restored: SandboxRef = serde_json::from_str(&saved).expect("no environment lookup");
    assert_eq!(restored, reference());
    assert_eq!(restored.provider.as_str(), "production");
    assert!(!saved.contains("environment"));
}

#[test]
fn reference_checks_observed_namespace_before_a_caller_dispatches() {
    let saved = reference();
    saved
        .check_namespace(&saved.namespace)
        .expect("same domain");
    let different = NamespaceId::try_new("daytona:org-replacement").expect("valid namespace");
    assert!(matches!(
        saved.check_namespace(&different),
        Err(Error::NamespaceMismatch { expected, actual })
            if expected == saved.namespace && actual == different
    ));
}

#[test]
fn saved_ids_are_validated_and_legacy_environment_refs_are_not_inferred() {
    for field in ["provider", "namespace", "id"] {
        for invalid in ["", "contains space", "contains\nnewline"] {
            let mut value = serde_json::to_value(reference()).expect("reference serializes");
            value[field] = json!(invalid);
            assert!(serde_json::from_value::<SandboxRef>(value).is_err());
        }
    }
    assert!(
        serde_json::from_value::<SandboxRef>(json!({
            "environment": "build", "namespace": "old", "id": "sb-123"
        }))
        .is_err()
    );
}

#[test]
fn portable_workload_survives_serialization_without_provider_recipes() {
    let spec: SandboxSpec = serde_json::from_value(workload()).expect("portable spec");
    spec.validate().expect("portable invariants");
    let back: SandboxSpec = serde_json::from_value(serde_json::to_value(&spec).expect("serialize"))
        .expect("deserialize");
    assert_eq!(back.source, Source::Image("ubuntu:24.04".into()));
    assert_eq!(
        back.services["postgres"].credential.as_deref(),
        Some("registry-production")
    );
    assert_eq!(back.services["postgres"].ports[0].get(), 5432);
    assert_eq!(
        back.container.expect("container options").privileged,
        Some(false)
    );
    assert_eq!(back.resources.memory_mb.expect("memory").get(), 4096);
    assert_eq!(back.env["TOKEN"], "workload-secret");
}

#[test]
fn absent_container_options_differ_from_an_explicit_false_request() {
    let spec = SandboxSpec::new(Source::Image("ubuntu:24.04".into()));
    assert!(spec.container.is_none());
    let specified: SandboxSpec = serde_json::from_value(json!({
        "source": {"image": "ubuntu:24.04"}, "container": {"init": false}
    }))
    .expect("explicit false decodes");
    assert_eq!(specified.container.expect("present").init, Some(false));
}

#[test]
fn request_typos_and_unsupported_target_selectors_are_not_dropped() {
    for path in [
        "/container/priviledged",
        "/resources/memory",
        "/execution_target",
    ] {
        let mut value = workload();
        let (parent, key) = path.rsplit_once('/').expect("path has parent");
        value.pointer_mut(parent).expect("parent exists")[key] = json!("outer-runner");
        assert!(
            serde_json::from_value::<SandboxSpec>(value).is_err(),
            "{path}"
        );
    }
    let mut value = workload();
    value["services"]["postgres"]["ready"]["timeout"] = json!(1000);
    assert!(serde_json::from_value::<SandboxSpec>(value).is_err());
}

#[test]
fn readiness_requires_finite_nonzero_budgets_and_a_valid_executable() {
    for field in ["interval_ms", "timeout_ms", "deadline_ms", "retries"] {
        let mut value = workload();
        value["services"]["postgres"]["ready"][field] = json!(0);
        assert!(
            serde_json::from_value::<SandboxSpec>(value).is_err(),
            "{field}"
        );
        let mut value = workload();
        value["services"]["postgres"]["ready"]
            .as_object_mut()
            .expect("object")
            .remove(field);
        assert!(
            serde_json::from_value::<SandboxSpec>(value).is_err(),
            "missing {field}"
        );
    }
    for command in [json!([]), json!([""]), json!(["check", "arg\u{0}ument"])] {
        let mut value = workload();
        value["services"]["postgres"]["ready"]["command"] = command;
        let spec: SandboxSpec = serde_json::from_value(value).expect("raw DTO decodes");
        assert!(
            matches!(spec.validate(), Err(Error::InvalidSpec { path, .. })
            if path == "services.postgres.ready.command")
        );
    }
}

#[test]
fn portable_validation_rejects_unsafe_or_empty_requests() {
    for value in [
        json!({"source": {"image": ""}}),
        json!({"source": {"image": "ubuntu:24.04"}, "network": {"mode": "cidr_allow_list", "cidrs": []}}),
        json!({"source": "host_directory", "workspace_ownership": "designated"}),
        json!({"source": {"image": "ubuntu:24.04"}, "workspace_ownership": "managed"}),
        json!({"source": {"image": "ubuntu:24.04"}, "services": {"bad name": {"image": "redis"}}}),
        json!({"source": {"image": "ubuntu:24.04"}, "services": {"DB": {"image": "redis"}, "db": {"image": "redis"}}}),
    ] {
        let spec: SandboxSpec = serde_json::from_value(value).expect("raw DTO");
        assert!(matches!(spec.validate(), Err(Error::InvalidSpec { .. })));
    }
    let mut invalid_port = workload();
    invalid_port["services"]["postgres"]["ports"] = json!([0]);
    assert!(serde_json::from_value::<SandboxSpec>(invalid_port).is_err());
}

#[test]
fn uncertain_errors_default_to_unknown_not_not_started_or_absence() {
    for code in ["unavailable", "transport", "stale"] {
        let error: Error = serde_json::from_value(json!({"code": code, "message": "lost reply"}))
            .expect("known error");
        assert!(matches!(
            error,
            Error::Unavailable {
                outcome: MutationOutcome::Unknown,
                ..
            } | Error::Transport {
                outcome: MutationOutcome::Unknown,
                ..
            } | Error::Stale {
                outcome: MutationOutcome::Unknown,
            }
        ));
    }
    let rejected: Error = serde_json::from_value(json!({
        "code": "transport", "message": "not admitted", "outcome": "not_started"
    }))
    .expect("explicit evidence");
    assert!(matches!(rejected, Error::Transport {
        outcome: MutationOutcome::NotStarted,
        ..
    }));
    assert!(serde_json::from_value::<Error>(json!({"code": "new_failure"})).is_err());
}

#[test]
fn incomplete_cleanup_preserves_known_ids_and_unknown_remainders() {
    for remaining in [
        json!([]),
        json!([{"kind": "helper_network", "id": "net-123"}]),
    ] {
        let error: Error = serde_json::from_value(json!({
            "code": "incomplete_cleanup", "message": "cleanup unconfirmed", "remaining": remaining
        }))
        .expect("cleanup failure");
        assert!(matches!(&error, Error::IncompleteCleanup { .. }));
        let encoded = serde_json::to_value(&error).expect("error serializes");
        assert_eq!(encoded["code"], "incomplete_cleanup");
        assert_eq!(encoded["remaining"], remaining);
        assert_eq!(
            serde_json::from_value::<Error>(encoded).expect("restores"),
            error
        );
    }
}

#[test]
fn connection_and_spec_schemas_are_separate_and_metadata_needs_no_namespace() {
    let schemas: ProviderSchemas = serde_json::from_value(json!({
        "kind": "example", "version": "1.0",
        "config_schema": {"type": "object", "required": ["endpoint"]},
        "spec_schema": {"type": "object", "required": ["zone"]},
        "secrets": ["API_KEY"]
    }))
    .expect("credential-free metadata");
    assert_eq!(schemas.config_schema["required"], json!(["endpoint"]));
    assert_eq!(
        schemas.spec_schema.expect("spec schema")["required"],
        json!(["zone"])
    );
    let caps: CapabilitySet = serde_json::from_value(json!({})).expect("omitted capabilities");
    assert!(!caps.services);
    assert!(!caps.containers);
    assert!(caps.container_fields.is_empty());
}

#[test]
fn descriptor_requires_runtime_identity_and_does_not_infer_shared_access_from_durability() {
    let value = json!({
        "schemas": {"kind": "example", "version": "1.0", "config_schema": {}},
        "namespace": {"id": "machine:original", "scope": "machine"},
        "isolation": "none", "durability": "machine", "access": "owner_process",
        "sources": ["host_directory"], "locality": {"host_address": null},
        "resources": [], "network": ["provider_default"],
        "ports": {"exposable": "none"}, "capabilities": {}
    });
    let descriptor: Descriptor = serde_json::from_value(value.clone()).expect("descriptor");
    assert_eq!(descriptor.durability, Durability::Machine);
    assert_eq!(descriptor.access, AccessScope::OwnerProcess);
    let mut missing = value.clone();
    missing.as_object_mut().expect("object").remove("namespace");
    assert!(serde_json::from_value::<Descriptor>(missing).is_err());
    let mut empty = value.clone();
    empty["namespace"]["id"] = json!("");
    assert!(serde_json::from_value::<Descriptor>(empty).is_err());
    let mut unknown = value;
    unknown["capabilities"]["container_fields"] = json!(["future_option"]);
    assert!(serde_json::from_value::<Descriptor>(unknown).is_err());
}

#[test]
fn environment_inheritance_distinguishes_default_from_explicitly_empty() {
    let entry: ProviderEntry = serde_json::from_value(json!({"plugin": "host"})).expect("entry");
    assert!(entry.inherit_env.is_none());
    let entry: ProviderEntry = serde_json::from_value(json!({
        "plugin": "host", "inherit_env": []
    }))
    .expect("empty inheritance");
    assert_eq!(entry.inherit_env, Some(vec![]));
    assert!(
        serde_json::from_value::<ProviderEntry>(json!({
            "plugin": "host", "spec": {"source": "host_directory"}
        }))
        .is_err()
    );
}

#[test]
fn status_unknown_state_is_not_deleted_and_service_addresses_are_workload_relative() {
    let status: Status = serde_json::from_value(json!({
        "reference": reference(), "state": "future_transition",
        "services": {"postgres": {"host": "postgres", "ports": {"5432": 15432}}}
    }))
    .expect("future status decodes conservatively");
    assert_eq!(status.state, SandboxState::Unknown);
    assert_eq!(status.services["postgres"].ports[&5432], 15432);
    assert_eq!(status.services["postgres"].host, "postgres");
}

#[test]
fn debug_output_redacts_launch_and_workload_secrets() {
    let entry: ProviderEntry = serde_json::from_value(json!({
        "plugin": "example", "config": {"credential": "config-secret"},
        "env": {"TOKEN": "launch-secret"}, "args": ["arg-secret"]
    }))
    .expect("entry");
    let debug = format!("{entry:?}");
    for secret in ["config-secret", "launch-secret", "arg-secret"] {
        assert!(!debug.contains(secret));
    }
    let mut value = workload();
    value["services"]["postgres"]["ready"]["command"] = json!(["check", "command-secret"]);
    let spec: SandboxSpec = serde_json::from_value(value).expect("spec");
    let debug = format!("{spec:?}");
    for secret in [
        "workload-secret",
        "service-secret",
        "opaque-secret",
        "command-secret",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn legacy_spec_and_error_construction_remain_available() {
    let old: sandbox_driver::SandboxSpec = serde_json::from_value(json!({
        "source": {"image": {"reference": "ubuntu:24.04"}},
        "provider_config": {"sidecars": []}
    }))
    .expect("v2 fixture still decodes");
    old.validate().expect("legacy spec still validates");
    let error = sandbox_driver::Error::invalid_spec("source", "legacy error");
    assert!(matches!(error, sandbox_driver::Error::InvalidSpec { field, .. } if field == "source"));
    // The two source encodings cannot accidentally interchange as Rust DTOs.
    assert!(
        serde_json::from_value::<SandboxSpec>(serde_json::to_value(old).expect("serialize"))
            .is_err()
    );
}
