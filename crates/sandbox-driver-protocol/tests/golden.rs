//! Golden-file pins for wire shapes.
//!
//! Protocol v1 embeds several core serde shapes directly; these tests pin
//! them. A failure here is a **wire compatibility break**: fix the change
//! to be additive, or absorb it in the protocol crate with a dedicated
//! DTO — never ship the new shape silently.

use std::time::Duration;

use sandbox_driver::{
    Capabilities, ErrorReport, Isolation, LifecycleAction, SandboxEvent, SandboxSource,
    SandboxSpec, SandboxState, Termination,
};

fn pretty(value: &impl serde::Serialize) -> String {
    serde_json::to_string_pretty(value).expect("serializes")
}

#[test]
fn sandbox_spec_wire_shape_is_pinned() {
    let spec = SandboxSpec::new(SandboxSource::Image {
        reference: "ubuntu:24.04".into(),
    })
    .name("demo")
    .env_var("KEY", "value")
    .ephemeral(true);
    let expected = r#"{
  "name": "demo",
  "source": {
    "image": {
      "reference": "ubuntu:24.04"
    }
  },
  "resources": {
    "cpu_cores": null,
    "memory_mb": null,
    "disk_mb": null,
    "gpus": null
  },
  "env": {
    "KEY": "value"
  },
  "labels": {},
  "user": null,
  "working_directory": null,
  "network": "provider_default",
  "volumes": [],
  "timers": {
    "auto_stop_after_idle": null,
    "auto_pause_after_idle": null,
    "auto_archive_after_stop": null,
    "auto_delete_after_stop": null,
    "ttl": null
  },
  "ephemeral": true,
  "public": null,
  "region": null,
  "provider_config": null
}"#;
    assert_eq!(pretty(&spec), expected);
}

#[test]
fn event_wire_shape_is_pinned() {
    let event = SandboxEvent::ActionFailed {
        action: LifecycleAction::Start,
        error:  ErrorReport::new("timeout", "starting timed out"),
    };
    let expected = r#"{
  "type": "action_failed",
  "action": "start",
  "error": {
    "kind": "timeout",
    "message": "starting timed out",
    "retryable": false,
    "causes": []
  }
}"#;
    assert_eq!(pretty(&event), expected);
}

#[test]
fn state_enums_tolerate_unknown_wire_values() {
    let state: SandboxState = serde_json::from_str("\"a_state_from_the_future\"").expect("state");
    assert_eq!(state, SandboxState::Unknown);
    let termination: Termination =
        serde_json::from_str("\"a_termination_from_the_future\"").expect("termination");
    assert_eq!(termination, Termination::Unknown);
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
fn capabilities_wire_shape_is_pinned() {
    let caps = Capabilities::minimal(Isolation::Vm);
    let expected = r#"{
  "isolation": "vm",
  "lifecycle": {
    "pause": false,
    "archive": false,
    "fork": false,
    "checkpoint": false,
    "resize": false,
    "recover": false,
    "undelete": false,
    "refresh_activity": false,
    "timers": false,
    "labels": false,
    "update_network": false,
    "snapshot_sandbox": false
  },
  "exec": {
    "live_streaming": false,
    "streams_separated": false,
    "stdin": false,
    "cancel": false,
    "stdio_process": false
  },
  "fs": {
    "native": false,
    "upload": false,
    "download": false,
    "permissions": false
  },
  "search": {
    "native": false
  },
  "git": {
    "native": false
  },
  "services": {
    "native": false
  },
  "pty": null,
  "logs": null,
  "access": {
    "preview_urls": false,
    "signed_preview_urls": false,
    "ssh": false,
    "shell_command": false,
    "web_terminal": false,
    "vnc": false,
    "vpn": false
  },
  "network": {
    "allow_all": false,
    "block_all": false,
    "cidr_allow_list": false,
    "domain_allow_list": false,
    "outbound_proxy": false
  },
  "snapshots": null,
  "volumes": null
}"#;
    assert_eq!(pretty(&caps), expected);
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
