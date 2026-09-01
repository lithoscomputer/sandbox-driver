//! Wire-compatibility behavior tests.
//!
//! These verify the compatibility contract itself — fixed encodings for
//! specific fields, tolerance of unknown fields and enum values, and
//! that JSON written by older or independently implemented peers still
//! decodes. They deliberately do not pin whole serialized shapes: an
//! additive field is the compatible evolution path and must not fail a
//! test (see "change-detector tests").

use std::time::Duration;

use sandbox_driver::{
    Action, Capabilities, Capability, Error, ErrorReport, Event, EventBody, EventSubject,
    ForkOptions, ResourceKind, SandboxKind, SandboxSnapshotOptions, SandboxSource, SandboxSpec,
    SandboxState, SandboxStatus, SnapshotId, SnapshotMode, SnapshotSource, SnapshotSpec,
    Termination,
};
use sandbox_driver_protocol::methods::{
    ForkOptionsDto, SandboxSnapshotOptionsDto, SandboxSpecDto, SnapshotSourceDto, SnapshotSpecDto,
};

/// The version-1 launch shape of the capability set, exactly as a plugin
/// built against the first protocol release sends it — before
/// `lifecycle.undelete`, `services`, `snapshots.activation`, and later
/// additions existed. A host must keep decoding it: missing newer fields
/// mean "absent", never a decode error.
#[test]
fn launch_era_capabilities_still_decode() {
    let json = r#"{
      "isolation": "vm",
      "lifecycle": {"pause":false,"archive":true,"fork":false,"checkpoint":false,
                     "resize":false,"recover":true,"refresh_activity":true,
                     "timers":true,"labels":true,"update_network":false,
                     "snapshot_sandbox":false},
      "exec": {"live_streaming":false,"streams_separated":false,"stdin":false,
                "cancel":false,"stdio_process":false},
      "fs": {"native":true,"upload":true,"download":true,"permissions":true},
      "search": {"native":false},
      "git": {"native":false},
      "pty": null,
      "logs": null,
      "access": {"preview_urls":true,"signed_preview_urls":true,"ssh":true,
                  "shell_command":false,"web_terminal":false,"vnc":false,"vpn":false},
      "network": {"allow_all":true,"block_all":true,"cidr_allow_list":true,
                   "domain_allow_list":false,"outbound_proxy":false},
      "snapshots": {"from_image":true,"from_dockerfile":true,"from_sandbox":false,
                     "include_memory":false,"build_logs":false},
      "volumes": {"create_time_attach":true}
    }"#;
    let caps: Capabilities = serde_json::from_str(json).expect("launch-era capabilities decode");
    assert!(caps.lifecycle.archive);
    assert!(!caps.lifecycle.undelete, "absent field defaults to false");
    assert!(!caps.services.native, "absent group defaults");
    let snapshots = caps.snapshots.expect("snapshots present");
    assert!(snapshots.from_image);
    assert!(!snapshots.from_image_kinds.container);
    assert!(!snapshots.from_image_kinds.virtual_machine);
}

/// A launch-era creation spec — written by hand the way a non-Rust host
/// would, exercising the stable field names and value encodings without
/// pinning the full shape. Fields added later may be absent.
#[test]
fn launch_era_spec_still_decodes() {
    let json = r#"{
      "name": "demo",
      "source": {"image": {"reference": "ubuntu:24.04"}},
      "resources": {"cpu_cores": 2, "memory_mb": 4096, "disk_mb": null, "gpus": null},
      "env": {"KEY": "value"},
      "labels": {},
      "user": null,
      "working_directory": null,
      "network": {"cidr_allow_list": {"cidrs": ["10.0.0.0/8"]}},
      "volumes": [],
      "timers": {"auto_stop_after_idle": {"secs": 90, "nanos": 0}},
      "ephemeral": true,
      "public": null,
      "region": null,
      "provider_config": null
    }"#;
    let spec: SandboxSpec = serde_json::from_str(json).expect("launch-era spec decodes");
    assert_eq!(spec.name.as_deref(), Some("demo"));
    assert_eq!(spec.resources.cpu_cores, Some(2));
    assert!(spec.ephemeral);
    assert_eq!(
        spec.timers.auto_stop_after_idle,
        Some(Duration::from_secs(90))
    );
}

/// A launch-era status as a plugin sends it — before `web_url` and any
/// later fields existed.
#[test]
fn launch_era_status_still_decodes() {
    let json = r#"{
      "id": "sb-1",
      "state": "running",
      "provider_state": "started",
      "error_reason": null,
      "labels": {"team": "a"}
    }"#;
    let status: SandboxStatus = serde_json::from_str(json).expect("launch-era status decodes");
    assert_eq!(status.state, SandboxState::Running);
    assert!(status.web_url.is_none(), "absent newer field defaults");
    assert!(status.name.is_none(), "absent display name defaults");
    assert!(status.sandbox_kind.is_none());
    assert!(status.region.is_none());
    assert_eq!(status.labels.get("team").map(String::as_str), Some("a"));
}

#[test]
fn snapshot_sandbox_source_keeps_the_v1_name_field() {
    let legacy: SandboxSpecDto = serde_json::from_value(serde_json::json!({
        "source": {"snapshot": {"name": "base-snapshot"}}
    }))
    .expect("v1 snapshot source decodes");
    let core = SandboxSpec::try_from(legacy).expect("maps to public API");
    assert!(matches!(
        &core.source,
        SandboxSource::Snapshot { id } if id.as_str() == "base-snapshot"
    ));

    let dto = SandboxSpecDto::try_from(&core).expect("maps back to v1");
    let json = serde_json::to_value(dto).expect("serializes");
    assert_eq!(json["source"]["snapshot"]["name"], "base-snapshot");
    assert!(json["source"]["snapshot"].get("id").is_none());
}

#[test]
fn sandbox_kind_and_region_cross_as_additive_fields() {
    let spec = SandboxSpec::new(SandboxSource::Snapshot {
        id: SnapshotId::try_new("base-snapshot").expect("valid snapshot id"),
    })
    .sandbox_kind(SandboxKind::VirtualMachine)
    .region("eu");
    let dto = SandboxSpecDto::try_from(&spec).expect("maps to v1 DTO");
    let json = serde_json::to_value(&dto).expect("serializes");
    assert_eq!(json["sandbox_kind"], "virtual_machine");
    assert_eq!(json["region"], "eu");
    let back = SandboxSpec::try_from(dto).expect("maps to public API");
    assert_eq!(back.sandbox_kind, Some(SandboxKind::VirtualMachine));
    assert_eq!(back.region.as_deref(), Some("eu"));
}

#[test]
fn state_enums_tolerate_unknown_wire_values() {
    let state: SandboxState = serde_json::from_str("\"a_state_from_the_future\"").expect("state");
    assert_eq!(state, SandboxState::Unknown);
    let termination: Termination =
        serde_json::from_str("\"a_termination_from_the_future\"").expect("termination");
    assert_eq!(termination, Termination::Unknown);
    let capability: Capability =
        serde_json::from_str("\"lifecycle.checkpoint\"").expect("legacy capability");
    assert_eq!(capability, Capability::Unknown);
    let action: Action = serde_json::from_str("\"checkpoint\"").expect("legacy action");
    assert_eq!(action, Action::Unknown);
    let resource: ResourceKind =
        serde_json::from_str("\"checkpoint\"").expect("legacy resource kind");
    assert_eq!(resource, ResourceKind::Unknown);
}

#[test]
fn unknown_object_fields_are_ignored() {
    let json = r#"{
        "kind": "provider",
        "message": "boom",
        "retryable": true,
        "causes": [],
        "field_from_the_future": {"nested": true}
    }"#;
    let report: ErrorReport = serde_json::from_str(json).expect("tolerates unknown fields");
    assert_eq!(report.kind, "provider");
    assert!(report.retryable);
}

#[test]
fn unknown_event_and_subject_kinds_are_tolerated() {
    let event: Event = serde_json::from_value(serde_json::json!({
        "id": {"source_id": "future-source", "sequence": 9},
        "occurred_at": {"secs_since_epoch": 1, "nanos_since_epoch": 0},
        "provider": "host",
        "subject": {"type": "future_resource", "detail": true},
        "type": "future_event",
        "detail": true
    }))
    .expect("unknown event kinds decode");
    assert!(matches!(event.subject, EventSubject::Unknown));
    assert!(matches!(event.body, EventBody::Unknown));
}

#[test]
fn duration_fields_use_serde_default_encoding_pinned() {
    // LifecycleTimers durations cross as {secs, nanos} in v1; pinned so a
    // change is a deliberate protocol decision, not an accident.
    let mut timers = sandbox_driver::LifecycleTimers::default();
    timers.auto_stop_after_idle = Some(Duration::from_secs(90));
    let json = serde_json::to_string(&timers).expect("serializes");
    assert!(
        json.contains("\"auto_stop_after_idle\":{\"secs\":90,\"nanos\":0}"),
        "json: {json}"
    );
}

#[test]
fn normalized_fork_maps_to_the_v1_memory_shape() {
    let dto = ForkOptionsDto::from(&ForkOptions::default());
    let json = serde_json::to_value(dto).expect("serializes");
    assert_eq!(json["include_memory"], true);

    let legacy: ForkOptionsDto = serde_json::from_value(serde_json::json!({
        "name": "old-client",
        "include_memory": false
    }))
    .expect("legacy fork shape decodes");
    assert!(matches!(
        ForkOptions::try_from(legacy),
        Err(Error::InvalidSpec { .. })
    ));
}

#[test]
fn normalized_snapshot_modes_map_to_the_v1_memory_shape() {
    for (mode, include_memory) in [
        (SnapshotMode::Filesystem, false),
        (SnapshotMode::LiveProcessState, true),
    ] {
        let mut options = SandboxSnapshotOptions::default();
        options.mode = mode;
        let dto = SandboxSnapshotOptionsDto::from(&options);
        assert_eq!(dto.include_memory, include_memory);
        assert_eq!(SandboxSnapshotOptions::from(dto).mode, mode);

        let id = sandbox_driver::SandboxId::try_new("sb-1").expect("valid id");
        let spec = SnapshotSpec::new(SnapshotSource::Sandbox { id, mode });
        let dto = SnapshotSpecDto::try_from(&spec).expect("maps to v1");
        let SnapshotSourceDto::Sandbox {
            include_memory: actual,
            ..
        } = dto.source
        else {
            panic!("expected sandbox source");
        };
        assert_eq!(actual, include_memory);
    }
}

#[test]
fn snapshot_build_kind_and_region_cross_as_additive_fields() {
    let spec = SnapshotSpec::new(SnapshotSource::Image {
        reference: "ubuntu:24.04".to_owned(),
    })
    .sandbox_kind(SandboxKind::VirtualMachine)
    .region("us");
    let dto = SnapshotSpecDto::try_from(&spec).expect("maps to v1 DTO");
    let json = serde_json::to_value(&dto).expect("serializes");
    assert_eq!(json["sandbox_kind"], "virtual_machine");
    assert_eq!(json["region"], "us");
    let back = SnapshotSpec::from(dto);
    assert_eq!(back.sandbox_kind, Some(SandboxKind::VirtualMachine));
    assert_eq!(back.region.as_deref(), Some("us"));
}
