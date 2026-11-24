//! boxd on the shared sandbox contract.

mod api;
mod connection;
mod error;
mod exec;
#[cfg(test)]
mod fake;
mod handle;
mod labels;
#[cfg(test)]
mod live;
mod provider;
mod spec;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    Activation, Error, JsonSchema, MutationOutcome, PluginLocation, Provider, ProviderFactory,
    ProviderKind, ProviderSchemas,
};
use tokio_util::sync::CancellationToken;

use self::provider::BoxdRuntime;

/// The credential an entry names under `secrets`.
const API_KEY: &str = "BOXD_API_KEY";
/// Bounds waiting for a machine to start, stop or come up from an image
/// pull.
const LIFECYCLE_BUDGET: Duration = Duration::from_secs(600);
/// Bounds confirming that a destroyed machine is gone.
const CLEANUP_BUDGET: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_secs(1);

/// The boxd built-in for the shared contract's registry.
///
/// An embedding program adds it with
/// `Registry::builtin(BoxdFactory::kind(), Arc::new(BoxdFactory))`, and a
/// provider entry with `plugin = "boxd"` then reaches boxd through the
/// catalog.
///
/// # Configuration
///
/// The entry names its credential under `secrets`: `BOXD_API_KEY`, a
/// `bxd_…` key from `boxd auth keys create`, fenced to one organization.
/// The entry's `config` takes, all optional:
///
/// - `org`: the organization, by name, slug or id; the key's own when omitted.
/// - `region`: a boxd region id such as `fra` or `nyc`; the organization's home
///   region when omitted.
/// - `api_url` and `auth_url`: the gRPC endpoint and the token exchange, for a
///   boxd deployment other than the hosted one.
///
/// Nothing is read from the process environment. The namespace is
/// `boxd:<organization id>/<region>`, because machines live in one region.
///
/// # Workloads
///
/// Every sandbox is a boxd machine, a KVM microVM (`isolation: vm`). Its
/// `source` is a boxd snapshot or an OCI image, booted as the machine's
/// root filesystem. The image `boxd` names boxd's own base image, which
/// boots in well under a second with Docker, Node, Python and Go installed
/// and runs commands as the `boxd` user. Other images take as long as their
/// pull; most run commands as root, each as PID 1 of its own PID namespace,
/// so a command cannot be signalled from outside it.
///
/// Resources round up to boxd's size classes (1 vCPU / 4 GiB, 2 / 8,
/// 4 / 16, 8 / 32); every machine has a fixed 100 GiB disk. A `ttl` timer
/// becomes boxd's delete-after timer, which deletes the machine at that
/// deadline whatever state it is in. Network policies become the machine's
/// egress allowlist; a CIDR list takes only public IPv4 addresses.
/// `provider_config = { isolated = true }` creates an isolated machine,
/// without boxd's metadata endpoint, in-machine CLI or integration tokens.
/// Services, one-shot containers, `user` and Dockerfile sources are refused
/// as unsupported.
///
/// Labels round-trip exactly: those that fit boxd's label grammar are
/// stored as given and the rest under an encoded key. The working directory
/// and the ambient `env` are kept in labels too, because boxd keeps nothing
/// else per machine that an attach can read while the machine is stopped.
/// Anyone who can see the machine in boxd can read them, so put credentials
/// in the provider's secrets, not in `env`. A machine holds at most 64
/// labels in all.
///
/// # Fencing
///
/// boxd's control plane holds each machine's lifecycle state, and every
/// provider instance reaching the namespace reads it, so the fence is
/// shared (`access: shared`). Commands and file writes are admitted only
/// while the machine is running, and each command records the machine's
/// kernel boot id when it is admitted. `stop` returns once boxd reports the
/// machine stopped, which ends every process in it.
///
/// A command whose stream breaks reports `killed` when boxd shows the
/// machine stopped, or running under a different boot id; otherwise its
/// fate is unknown and it reports `lost`. Term, kill and a timeout cancel
/// the call, which makes boxd signal the command's process tree, and then
/// report `terminated`, `killed` or `timed_out` only once a lock the
/// command held is confirmed released. That lock needs `flock` in the
/// workload image; without it, a stopped command reports `lost`. A machine
/// boxd put to sleep (standby or hibernated) reads as `paused`, and `start`
/// resumes or wakes it.
///
/// # Ports and endpoints
///
/// `ports().expose` publishes a port as a public HTTPS subdomain,
/// `https://p<port>.<machine>.boxd.sh`; boxd has no signed URLs, so
/// `signed: true` is refused. `endpoints().shell_command` returns a
/// `boxd machine connect` command for the operator's own boxd CLI.
#[derive(Clone, Copy, Debug, Default)]
pub struct BoxdFactory;

impl BoxdFactory {
    /// The provider kind this factory registers as.
    pub fn kind() -> ProviderKind {
        ProviderKind::try_new("boxd").expect("static kind is valid")
    }

    /// Credential-free metadata. Nothing here reaches a backend.
    pub fn schemas() -> ProviderSchemas {
        ProviderSchemas {
            kind:          Self::kind(),
            version:       env!("CARGO_PKG_VERSION").to_owned(),
            config_schema: object(config_schema()),
            spec_schema:   Some(object(spec::spec_schema())),
            secrets:       vec![API_KEY.to_owned()],
        }
    }
}

/// Refuses work once the runtime that owns `closed` has shut down. Nothing
/// has been sent when this refuses.
fn ensure_open(closed: &CancellationToken) -> Result<(), Error> {
    if closed.is_cancelled() {
        Err(Error::Stale {
            outcome: MutationOutcome::NotStarted,
        })
    } else {
        Ok(())
    }
}

fn object(value: serde_json::Value) -> JsonSchema {
    serde_json::from_value(value).expect("a constant schema is an object")
}

fn config_schema() -> serde_json::Value {
    let text = |description: &str| serde_json::json!({"type": "string", "minLength": 1, "description": description});
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "org": text("Organization name, slug or id; the API key's own when omitted"),
            "region": text("boxd region id, such as fra or nyc; the organization's home region when omitted"),
            "api_url": text("boxd gRPC endpoint; the hosted service when omitted"),
            "auth_url": text("API key exchange endpoint; the hosted service when omitted"),
        }
    })
}

#[async_trait]
impl ProviderFactory for BoxdFactory {
    async fn discover(&self, _location: &PluginLocation) -> Result<ProviderSchemas, Error> {
        Ok(Self::schemas())
    }

    async fn activate(&self, activation: Activation) -> Result<Arc<dyn Provider>, Error> {
        Ok(Arc::new(BoxdRuntime::activate(activation).await?))
    }
}
