//! Exercises discovery through real executable boundaries, without a backend.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use sandbox_driver::contract::{
    Descriptor, Error, MutationOutcome, ProviderEntry, ProviderName, ProviderSchemas,
};
use sandbox_driver_protocol::file_sha256;
use sandbox_driver_protocol::metadata::{DiscoveryLimits, SchemaDiscovery, write_schema};
use serde_json::json;
use tokio::time;

struct Fixture {
    root:   PathBuf,
    binary: PathBuf,
}

impl Fixture {
    fn new(body: &str) -> Self {
        let root = std::env::temp_dir().join(format!("schema-probe-{}", rand::random::<u64>()));
        fs::create_dir(&root).expect("fixture directory");
        let binary = root.join("plugin");
        let fixture = Self { root, binary };
        fixture.write(body);
        fixture
    }
    fn write(&self, body: &str) {
        fs::write(
            &self.binary,
            format!("#!/bin/sh\ncd '{}'\n{body}\n", self.root.display()),
        )
        .expect("fixture executable");
        fs::set_permissions(&self.binary, fs::Permissions::from_mode(0o700))
            .expect("executable permission");
    }
    fn entry(&self) -> ProviderEntry {
        serde_json::from_value(json!({
            "plugin": "fixture", "path": self.binary, "dev": true,
            "args": ["--runtime-secret", "credential-value"],
            "env": {"PRIVATE_TOKEN": "secret-value"},
            "inherit_env": ["HOME", "USER", "PATH"],
            "config": {"token": "config-secret"}, "secrets": ["PRIVATE_TOKEN"]
        }))
        .expect("entry")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn name() -> ProviderName {
    ProviderName::try_new("test-entry").expect("name")
}
fn schemas() -> ProviderSchemas {
    serde_json::from_value(json!({"kind":"fixture", "version":"1.0", "config_schema":{"$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object"}, "secrets": ["PRIVATE_TOKEN"]})).expect("schemas")
}
fn emit() -> String {
    format!(
        "printf '%s\\n' '{}'",
        serde_json::to_string(&schemas()).expect("json")
    )
}

#[tokio::test]
async fn probe_is_credential_free_and_cache_is_shared_by_digest() {
    let fixture = Fixture::new(&format!(
        "[ \"$#\" = 1 ] && [ \"$1\" = '--describe-schema' ] || exit 8\n\
        [ -z \"${{HOME+x}}${{USER+x}}${{PRIVATE_TOKEN+x}}\" ] || exit 9\n\
        [ \"$PATH\" = /usr/bin:/bin ] || exit 10\n\
        if read line; then exit 11; fi\n\
        echo probe >> calls\n{}",
        emit()
    ));
    let cache = SchemaDiscovery::default();
    assert!(!fixture.root.join("calls").exists(), "construction is cold");
    let first = cache
        .discover("unused", &name(), &fixture.entry())
        .await
        .expect("credential-free probe");
    assert_eq!(first.schemas(), &schemas());
    assert!(!first.verified());
    let mut renamed = fixture.entry();
    let copy = fixture.root.join("renamed");
    fs::copy(&fixture.binary, &copy).expect("same bytes at another path");
    renamed.path = Some(copy.to_string_lossy().into());
    let second = cache
        .discover("unused", &name(), &renamed)
        .await
        .expect("cached schema");
    assert_eq!(second.digest(), first.digest());
    assert_eq!(
        fs::read_to_string(fixture.root.join("calls")).expect("calls"),
        "probe\n"
    );
}

#[tokio::test]
async fn every_cache_hit_enforces_trust_and_changed_bytes_invalidate_metadata() {
    let fixture = Fixture::new(&format!("echo probe >> calls\n{}", emit()));
    let cache = SchemaDiscovery::default();
    let original = cache
        .discover("unused", &name(), &fixture.entry())
        .await
        .expect("first");
    let mut entry = fixture.entry();
    entry.trust = None;
    assert!(matches!(
        cache.discover("unused", &name(), &entry).await,
        Err(Error::InvalidConfig { .. })
    ));
    let pin = file_sha256(&fixture.binary).await.expect("checksum");
    entry.trust = Some(sandbox_driver::contract::PluginTrust::Sha256 {
        digest: pin.try_into().expect("digest"),
    });
    assert!(
        cache
            .discover("unused", &name(), &entry)
            .await
            .expect("pinned cache hit")
            .verified()
    );
    fixture.write(&format!(
        "echo changed >> calls\n{}",
        emit().replace("1.0", "2.0")
    ));
    assert!(matches!(
        cache.discover("unused", &name(), &entry).await,
        Err(Error::InvalidConfig { .. })
    ));
    original
        .verify_unchanged()
        .await
        .expect_err("cannot launch changed binary");
    assert_eq!(
        fs::read_to_string(fixture.root.join("calls")).expect("calls"),
        "probe\n",
        "bad pin never executes"
    );
    let changed = cache
        .discover("unused", &name(), &fixture.entry())
        .await
        .expect("dev re-probes new bytes");
    assert_eq!(changed.schemas().version, "2.0");
    assert_ne!(changed.digest(), original.digest());
}

#[tokio::test]
async fn missing_or_wrong_kind_entry_does_not_poison_other_entries() {
    let fixture = Fixture::new(&emit());
    let cache = SchemaDiscovery::default();
    let mut bad = fixture.entry();
    bad.path = Some(fixture.root.join("absent").to_string_lossy().into());
    assert!(matches!(
        cache.discover("unused", &name(), &bad).await,
        Err(Error::Unavailable {
            outcome: MutationOutcome::NotStarted,
            ..
        })
    ));
    bad = fixture.entry();
    bad.plugin = "other".to_string().try_into().expect("kind");
    assert!(matches!(
        cache.discover("unused", &name(), &bad).await,
        Err(Error::InvalidConfig { .. })
    ));
    cache
        .discover("unused", &name(), &fixture.entry())
        .await
        .expect("unrelated entry still usable");
}

#[tokio::test]
async fn invalid_failed_and_oversize_probes_are_never_cached_or_echoed() {
    for body in [
        "echo secret-value; echo secret-value >&2; exit 1".into(),
        "echo secret-value".into(),
        format!("{}\n{}", emit(), emit()),
        format!("{}\nexit 2", emit()),
        "while :; do printf secret-value; done".into(),
        "while :; do printf secret-value >&2; done".into(),
    ] {
        let fixture = Fixture::new(&body);
        let cache = SchemaDiscovery::try_new(DiscoveryLimits {
            stdout_bytes: 512,
            stderr_bytes: 64,
            ..DiscoveryLimits::default()
        })
        .expect("limits");
        let error = cache
            .discover("unused", &name(), &fixture.entry())
            .await
            .expect_err("bad probe");
        assert!(!format!("{error:?}").contains("secret-value"));
        fixture.write(&emit());
        cache
            .discover("unused", &name(), &fixture.entry())
            .await
            .expect("successful retry");
    }
}

async fn wait_for_file(path: &std::path::Path) {
    time::timeout(Duration::from_secs(3), async {
        while !path.exists() {
            time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("probe started");
}
async fn assert_dead(pid: u32) {
    time::timeout(Duration::from_secs(3), async {
        while tokio::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .expect("check process")
            .success()
        {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("probe is killed and reaped");
}

#[tokio::test]
async fn timeout_and_caller_cancellation_kill_the_metadata_child() {
    let fixture = Fixture::new(&format!("{}\necho $$ > pid; exec /bin/sleep 30", emit()));
    let cache = SchemaDiscovery::try_new(DiscoveryLimits {
        timeout: Duration::from_secs(1),
        ..DiscoveryLimits::default()
    })
    .expect("limits");
    cache
        .discover("unused", &name(), &fixture.entry())
        .await
        .expect_err("timeout");
    let pid = fs::read_to_string(fixture.root.join("pid"))
        .expect("pid")
        .trim()
        .parse()
        .expect("pid number");
    assert_dead(pid).await;
    fs::remove_file(fixture.root.join("pid")).expect("remove pid");
    let entry = fixture.entry();
    let task = tokio::spawn(async move {
        SchemaDiscovery::default()
            .discover("unused", &name(), &entry)
            .await
    });
    wait_for_file(&fixture.root.join("pid")).await;
    let pid = fs::read_to_string(fixture.root.join("pid"))
        .expect("pid")
        .trim()
        .parse()
        .expect("pid number");
    task.abort();
    assert!(task.await.expect_err("cancelled").is_cancelled());
    assert_dead(pid).await;
}

#[tokio::test]
async fn admission_and_cache_storage_are_bounded() {
    let fixture = Fixture::new("echo $$ > pid; exec /bin/sleep 30");
    let cache = SchemaDiscovery::try_new(DiscoveryLimits {
        concurrent_probes: 1,
        cached_binaries: 1,
        ..DiscoveryLimits::default()
    })
    .expect("limits");
    let entry = fixture.entry();
    let name = name();
    let mut pending = Box::pin(cache.discover("unused", &name, &entry));
    let pid_path = fixture.root.join("pid");
    tokio::select! {
        result = &mut pending => panic!("probe returned early: {result:?}"),
        () = wait_for_file(&pid_path) => {}
    }
    assert!(matches!(
        cache.discover("unused", &name, &entry).await,
        Err(Error::ResourceExhausted { .. })
    ));
    drop(pending);
    let first = Fixture::new(&format!("echo probe >> calls\n{}", emit()));
    let second = Fixture::new(&emit());
    cache
        .discover("unused", &name, &first.entry())
        .await
        .expect("first");
    cache
        .discover("unused", &name, &second.entry())
        .await
        .expect("evicts first");
    cache
        .discover("unused", &name, &first.entry())
        .await
        .expect("probes again");
    assert_eq!(
        fs::read_to_string(first.root.join("calls")).expect("calls"),
        "probe\nprobe\n"
    );
}

#[tokio::test]
async fn sdk_output_and_runtime_metadata_agreement() {
    let fixture = Fixture::new(&emit());
    let discovered = SchemaDiscovery::default()
        .discover("unused", &name(), &fixture.entry())
        .await
        .expect("discovery");
    let mut bytes = Vec::new();
    write_schema(&mut bytes, &schemas()).expect("SDK output");
    assert_eq!(
        serde_json::from_slice::<ProviderSchemas>(&bytes).expect("one object"),
        schemas()
    );
    let mut descriptor: Descriptor = serde_json::from_value(json!({
        "schemas": schemas(), "namespace":{"id":"fixture:machine", "scope":"machine"},
        "isolation":"none", "durability":"process", "access":"owner_process",
        "sources":["host_directory"], "locality": {"host_address":null},
        "resources":[], "network":["provider_default"], "ports":{"exposable":"none"}, "capabilities":{}
    })).expect("descriptor");
    discovered.check_descriptor(&descriptor).expect("matching");
    descriptor.schemas.version = "new-version".into();
    assert!(matches!(
        discovered.check_descriptor(&descriptor),
        Err(Error::Transport {
            outcome: MutationOutcome::NotStarted,
            ..
        })
    ));
}
