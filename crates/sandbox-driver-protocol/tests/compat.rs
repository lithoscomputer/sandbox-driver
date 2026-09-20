//! Wire-compatibility behavior tests.
//!
//! These verify the compatibility contract itself — fixed encodings for
//! specific fields, tolerance of unknown fields and enum values, and
//! that JSON written by older or independently implemented peers still
//! decodes. They deliberately do not pin whole serialized shapes: an
//! additive field is the compatible evolution path and must not fail a
//! test (see "change-detector tests").

use std::time::{Duration, UNIX_EPOCH};

use sandbox_driver::{
    Action, Capabilities, Capability, Error, ErrorReport, Event, EventBody, EventSubject,
    ForkOptions, GitFailureKind, ResourceKind, SandboxKind, SandboxSnapshotOptions, SandboxSource,
    SandboxSpec, SandboxState, SandboxStatus, SearchCaps, ServiceCaps, SnapshotId, SnapshotMode,
    SnapshotSource, SnapshotSpec, Termination,
};
use sandbox_driver_protocol::WireError;
use sandbox_driver_protocol::methods::{
    ExecStreamResult, ForkOptionsDto, FsWriteParams, GitCloneParams, HealthResult,
    SandboxSnapshotOptionsDto, SandboxSpecDto, SnapshotSourceDto, SnapshotSpecDto,
};

#[test]
fn health_identity_is_optional_and_survives_the_wire() {
    let legacy: HealthResult =
        serde_json::from_str(r#"{"health":{"status":"ok"}}"#).expect("old health response");
    assert!(legacy.health.identity.is_none());
    let identified: HealthResult = serde_json::from_str(
        r#"{"health":{"status":"ok","identity":"organization:example","future_field":true}}"#,
    )
    .expect("new health response");
    assert_eq!(
        identified.health.identity.as_deref(),
        Some("organization:example")
    );
    let encoded = serde_json::to_value(identified).expect("encode health response");
    assert_eq!(encoded["health"]["identity"], "organization:example");
}

#[test]
fn version_two_file_writes_without_a_length_still_decode() {
    let request: FsWriteParams = serde_json::from_str(
        r#"{
        "sandbox_id": "host:test",
        "path": "file.bin",
        "channel": {"channel_id": 7, "token": "test-token"}
    }"#,
    )
    .expect("earlier version two write request");
    assert_eq!(request.content_length, None);
    assert!(!request.append);
}

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
    assert!(
        caps.search.supported,
        "the old native=false shape implied exec-derived search"
    );
    assert!(
        caps.git.supported,
        "the old native=false shape implied exec-derived git"
    );
    assert!(!caps.services.native, "absent group defaults");
    assert!(!caps.services.supported, "absent group is unsupported");
    let snapshots = caps.snapshots.expect("snapshots present");
    assert!(snapshots.from_image);
    assert!(!snapshots.from_image_kinds.container);
    assert!(!snapshots.from_image_kinds.virtual_machine);
}

#[test]
fn pre_normalization_search_capabilities_still_decode() {
    let legacy: SearchCaps =
        serde_json::from_str(r#"{"native":false}"#).expect("legacy search capabilities decode");
    assert!(legacy.supported, "native=false meant use derived search");
    assert!(!legacy.native);

    let unavailable: SearchCaps = serde_json::from_str(r#"{"supported":false,"native":false}"#)
        .expect("normalized search capabilities decode");
    assert!(!unavailable.supported);
}

#[test]
fn pre_normalization_service_capabilities_still_decode() {
    let legacy: ServiceCaps =
        serde_json::from_str(r#"{"native":false}"#).expect("legacy service capabilities decode");
    assert!(legacy.supported, "native=false meant use derived services");
    assert!(!legacy.native);

    let unavailable: ServiceCaps = serde_json::from_str(r#"{"supported":false,"native":false}"#)
        .expect("normalized service capabilities decode");
    assert!(!unavailable.supported);
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
    let git_kind: GitFailureKind =
        serde_json::from_str("\"a_git_class_from_the_future\"").expect("git failure kind");
    assert_eq!(git_kind, GitFailureKind::Unclassified);
}

/// `source` merged the image and the snapshot; it is gone, and a status
/// from a plugin that still sends it decodes with both new fields absent.
#[test]
fn a_status_with_the_retired_source_field_still_decodes() {
    let status: SandboxStatus =
        serde_json::from_str(r#"{"id":"sb-1","state":"running","source":"ubuntu:24.04"}"#)
            .expect("decodes");
    assert_eq!(status.image, None);
    assert_eq!(status.snapshot, None);
    assert!(status.network.is_none());
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
fn timestamps_cross_as_rfc_3339_and_the_structural_form_still_decodes() {
    let mut status = SandboxStatus::new(
        sandbox_driver::SandboxId::try_new("sb-1").expect("id"),
        SandboxState::Running,
    );
    status.created_at = Some(UNIX_EPOCH + Duration::from_secs(1_788_206_400));
    let encoded = serde_json::to_value(&status).expect("encode status");
    assert_eq!(encoded["created_at"], "2026-08-31T20:00:00Z");
    assert_eq!(encoded["updated_at"], serde_json::Value::Null);

    let legacy: SandboxStatus = serde_json::from_value(serde_json::json!({
        "id": "sb-1",
        "state": "running",
        "created_at": {"secs_since_epoch": 1_788_206_400, "nanos_since_epoch": 0},
        "updated_at": "2026-08-31T20:00:01.5Z"
    }))
    .expect("both timestamp forms decode");
    assert_eq!(legacy.created_at, status.created_at);
    assert_eq!(
        legacy.updated_at,
        Some(UNIX_EPOCH + Duration::from_millis(1_788_206_401_500))
    );
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

/// The exec/stream result before `output_loss` existed. A host must read
/// it as a lossless run; a plugin that lost output says so in the
/// additive object, whose fields default to zero on either side.
#[test]
fn pre_loss_exec_stream_results_still_decode() {
    let legacy: ExecStreamResult = serde_json::from_str(
        r#"{
        "result": {"exit_code": 0, "termination": "exited", "duration_ms": 5},
        "streams_separated": true,
        "live_streaming": true,
        "stdout_capture": {"observed_bytes": 3, "retained_bytes": 3, "omitted_bytes": 0},
        "stderr_capture": {"observed_bytes": 0, "retained_bytes": 0, "omitted_bytes": 0}
    }"#,
    )
    .expect("pre-loss exec/stream result");
    assert!(!legacy.output_loss.is_lossy());
    assert_eq!(legacy.output_loss.dropped_frames, 0);
    assert_eq!(legacy.output_loss.dropped_bytes, 0);

    let lossy: ExecStreamResult = serde_json::from_str(
        r#"{
        "result": {"exit_code": 0, "termination": "exited", "duration_ms": 5},
        "streams_separated": true,
        "live_streaming": true,
        "stdout_capture": {"observed_bytes": 3, "retained_bytes": 3, "omitted_bytes": 0,
                           "truncated": true},
        "stderr_capture": {"observed_bytes": 0, "retained_bytes": 0, "omitted_bytes": 0,
                           "truncated": true},
        "output_loss": {"dropped_frames": 2, "dropped_bytes": 391, "future_field": 1}
    }"#,
    )
    .expect("lossy exec/stream result");
    assert_eq!(lossy.output_loss.dropped_frames, 2);
    assert_eq!(lossy.output_loss.dropped_bytes, 391);
    let encoded = serde_json::to_value(&lossy).expect("encode exec/stream result");
    assert_eq!(encoded["output_loss"]["dropped_frames"], 2);
    assert_eq!(encoded["output_loss"]["dropped_bytes"], 391);
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

#[test]
fn git_clone_requests_default_their_options_and_redact_their_url() {
    let request: GitCloneParams = serde_json::from_str(
        r#"{"sandbox_id":"host:test","url":"https://u:secret@example.com/r.git","target_path":"r"}"#,
    )
    .expect("clone request without options");
    assert!(request.options.branch.is_none());
    assert!(request.options.commit.is_none());
    assert!(request.options.depth.is_none());
    assert!(request.options.credentials.is_none());
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret"), "debug: {debug}");
    assert!(debug.contains("host:test"), "debug: {debug}");

    let request: GitCloneParams = serde_json::from_str(
        r#"{"sandbox_id":"host:test","url":"https://example.com/r.git","target_path":"r",
            "options":{"branch":"main","commit":"0123456789abcdef0123456789abcdef01234567",
                       "depth":1,"credentials":{"username":"u","password":"hunter2"},
                       "future_option":true}}"#,
    )
    .expect("clone request with unknown option field");
    assert_eq!(request.options.depth, Some(1));
    let debug = format!("{request:?}");
    assert!(!debug.contains("hunter2"), "debug: {debug}");
}

/// An application error as an independently written peer sends it: the
/// section 7 `report` plus the kind's `detail` fields, with a field from
/// the future in each detail. Every kind in the table must decode to its
/// typed error from this era JSON.
fn wire_error(kind: &str, retryable: bool, causes: &[&str], detail: &serde_json::Value) -> Error {
    let json = serde_json::json!({
        "code": -32000,
        "message": format!("a {kind} failure"),
        "data": {
            "report": {"kind": kind, "message": format!("a {kind} failure"),
                        "retryable": retryable, "causes": causes},
            "detail": detail
        }
    });
    serde_json::from_value::<WireError>(json)
        .expect("era error decodes")
        .into_error()
}

#[test]
fn every_error_kind_decodes_from_its_era_detail() {
    use std::error::Error as _;

    let unsupported = wire_error(
        "unsupported",
        false,
        &[],
        &serde_json::json!({
            "capability": "lifecycle.pause", "future_field": 1
        }),
    );
    assert!(matches!(unsupported, Error::Unsupported {
        capability: Capability::LifecyclePause,
    }));

    let not_found = wire_error(
        "not_found",
        false,
        &[],
        &serde_json::json!({
            "resource": "sandbox", "id": "sb-1", "future_field": 1
        }),
    );
    assert!(
        matches!(not_found, Error::NotFound { resource: ResourceKind::Sandbox, id }
        if id == "sb-1")
    );

    let not_owned = wire_error(
        "not_owned",
        false,
        &[],
        &serde_json::json!({
            "resource": "snapshot", "id": "snap-1"
        }),
    );
    assert!(
        matches!(not_owned, Error::NotOwned { resource: ResourceKind::Snapshot, id }
        if id == "snap-1")
    );

    let invalid_spec = wire_error(
        "invalid_spec",
        false,
        &[],
        &serde_json::json!({
            "field": "source", "reason": "must be an image"
        }),
    );
    assert!(matches!(invalid_spec, Error::InvalidSpec { field, reason }
        if field == "source" && reason == "must be an image"));

    let invalid_state = wire_error(
        "invalid_state",
        false,
        &[],
        &serde_json::json!({
            "current": "paused", "action": "stop"
        }),
    );
    assert!(matches!(invalid_state, Error::InvalidState {
        current: SandboxState::Paused,
        action:  Action::Stop,
    }));

    let timeout = wire_error(
        "timeout",
        false,
        &[],
        &serde_json::json!({
            "operation": "creating sandbox", "elapsed": {"secs": 7, "nanos": 0}
        }),
    );
    assert!(matches!(timeout, Error::Timeout { operation, elapsed }
        if operation == "creating sandbox" && elapsed == Duration::from_secs(7)));

    let auth = wire_error(
        "auth",
        false,
        &["remote rejected token"],
        &serde_json::json!({
            "auth": {"provider": "test", "reason": "token expired", "future_field": 1}
        }),
    );
    let Error::Auth(auth) = auth else {
        panic!("expected auth: {auth:?}");
    };
    assert_eq!(auth.provider.as_str(), "test");
    assert_eq!(auth.reason, "token expired");
    assert_eq!(
        auth.source().expect("remote cause").to_string(),
        "remote rejected token"
    );

    let rate_limited = wire_error(
        "rate_limited",
        true,
        &[],
        &serde_json::json!({
            "retry_after": {"secs": 0, "nanos": 250_000_000}
        }),
    );
    assert!(matches!(rate_limited, Error::RateLimited { retry_after }
        if retry_after == Some(Duration::from_millis(250))));
    let rate_limited = wire_error("rate_limited", true, &[], &serde_json::json!({}));
    assert!(matches!(rate_limited, Error::RateLimited {
        retry_after: None,
    }));

    let overloaded = wire_error(
        "overloaded",
        true,
        &[],
        &serde_json::json!({
            "limit": "active_io", "not_started": true
        }),
    );
    assert!(matches!(overloaded, Error::Overloaded { limit } if limit == "active_io"));

    let limit = wire_error(
        "limit_exceeded",
        false,
        &[],
        &serde_json::json!({
            "limit": "buffered_value_bytes", "max_bytes": 4
        }),
    );
    assert!(matches!(limit, Error::LimitExceeded { limit, max_bytes: 4 }
        if limit == "buffered_value_bytes"));

    let incomplete = wire_error(
        "incomplete",
        false,
        &[],
        &serde_json::json!({
            "incomplete": {"operation": "hard cancellation drain", "output_abandoned": true,
                           "stop_acknowledged": true, "termination_confirmed": false,
                           "cleanup_confirmed": false, "future_field": 1}
        }),
    );
    let Error::Incomplete(incomplete) = incomplete else {
        panic!("expected incomplete: {incomplete:?}");
    };
    assert_eq!(incomplete.operation, "hard cancellation drain");
    assert!(incomplete.stop_acknowledged && !incomplete.termination_confirmed);

    let provider = wire_error(
        "provider",
        true,
        &["daemon disconnected"],
        &serde_json::json!({
            "provider": {"provider": "test", "message": "listing sandboxes",
                         "code": "backend_unavailable", "retryable": true, "detail": null}
        }),
    );
    let Error::Provider(provider) = provider else {
        panic!("expected provider: {provider:?}");
    };
    assert_eq!(provider.code.as_deref(), Some("backend_unavailable"));
    assert!(provider.retryable);
    assert_eq!(
        provider.source().expect("remote cause").to_string(),
        "daemon disconnected"
    );

    let exec = wire_error(
        "exec",
        false,
        &[],
        &serde_json::json!({
            "exec": {"label": "probe", "termination": "exited", "exit_code": 3,
                     "stdout_b64": "b3V0", "stderr_b64": "ZXJy"}
        }),
    );
    let Error::Exec(failure) = exec else {
        panic!("expected exec: {exec:?}");
    };
    assert_eq!(failure.label(), "probe");
    assert_eq!(failure.exit_code(), Some(3));
    assert_eq!(failure.stdout(), b"out");
    assert_eq!(failure.duration(), None, "duration_ms is additive");

    let git = wire_error(
        "git",
        false,
        &[],
        &serde_json::json!({
            "git": {"operation": "git clone", "kind": "ref_not_found",
                    "exec": {"label": "git fetch", "termination": "exited", "exit_code": 128,
                             "stdout_b64": "", "stderr_b64": "ZmF0YWw="}}
        }),
    );
    let Error::Git(failure) = git else {
        panic!("expected git: {git:?}");
    };
    assert_eq!(failure.operation(), "git clone");
    assert_eq!(failure.kind(), GitFailureKind::RefNotFound);
    assert_eq!(
        failure.output().expect("command output").exit_code(),
        Some(128)
    );

    let io = wire_error(
        "io",
        false,
        &["binary disappeared"],
        &serde_json::json!({
            "io_context": "reading plugin executable"
        }),
    );
    assert!(matches!(io, Error::Io { context, source }
        if context == "reading plugin executable" && source.to_string() == "binary disappeared"));

    let transport = wire_error(
        "transport",
        false,
        &["pipe closed"],
        &serde_json::json!({
            "transport_context": "reading plugin response"
        }),
    );
    let Error::Transport(transport) = transport else {
        panic!("expected transport: {transport:?}");
    };
    assert_eq!(transport.context, "reading plugin response");
    assert_eq!(
        transport.source().expect("remote cause").to_string(),
        "pipe closed"
    );
}

/// A kind from the future, or a detail missing the fields its kind
/// needs, still reaches the caller as a provider error that keeps the
/// report's kind and retryable flag.
#[test]
fn unknown_or_underspecified_error_kinds_fall_back_to_the_report() {
    let future = wire_error(
        "a_kind_from_the_future",
        true,
        &[],
        &serde_json::json!({
            "anything": true
        }),
    );
    let Error::Provider(provider) = future else {
        panic!("expected provider fallback: {future:?}");
    };
    assert_eq!(provider.code.as_deref(), Some("a_kind_from_the_future"));
    assert!(provider.retryable);

    let underspecified = wire_error(
        "not_found",
        false,
        &[],
        &serde_json::json!({
            "resource": "sandbox"
        }),
    );
    let Error::Provider(provider) = underspecified else {
        panic!("expected provider fallback: {underspecified:?}");
    };
    assert_eq!(provider.code.as_deref(), Some("not_found"));
}
