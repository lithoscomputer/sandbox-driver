//! Host on the shared contract, registered as the built-in `host` provider.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, SeekFrom};
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::gethostname;
use sandbox_driver::contract::{
    AccessScope, Activation, ByteStream, CapabilitySet, Descriptor, Durability, Error,
    ExecControls, ExecOutcome, ExecSpec, Expose, Exposure, FileEntry, FileRange, Files, Health,
    LabelFilter, Locality, MutationOutcome, Namespace, NamespaceId, NamespaceScope, NetworkMode,
    OutputStream as ContractStream, PluginLocation, PortSupport, Ports, ProviderFactory,
    ProviderName, ProviderRuntime, ProviderSchemas, RemainingResource, Resources, Sandbox,
    SandboxRef, SandboxState, SandboxSummary, SourceKind, Status, Termination, WorkloadAdmission,
};
use sandbox_driver::{
    FileKind, Isolation, OutputStream, SandboxId, SandboxProvider, SandboxSource, StdinSource,
    WorkspaceOwnership,
};
use serde_json::json;
use tokio::fs as tokio_fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, copy as io_copy};

use crate::fs::kind_of;
use crate::{HostProvider, host_kind, registry, temporary_root};

/// The credential-free metadata `--describe-schema` prints. Host takes no
/// connection configuration and no secrets.
pub fn schemas() -> ProviderSchemas {
    let config_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
    });
    ProviderSchemas {
        kind:          host_kind(),
        version:       env!("CARGO_PKG_VERSION").to_owned(),
        config_schema: serde_json::from_value(config_schema).expect("static schema"),
        spec_schema:   None,
        secrets:       Vec::new(),
    }
}

/// Activates one Host instance per configured entry. Applications register
/// it with `Registry::builtin` under the `host` kind.
///
/// Each activation is one instance, and it owns its sandboxes: their process
/// groups, lifecycle and managed workspaces. Ids carry the instance's
/// generation, so a ref never leads another instance (or a restarted one) to
/// adopt them. Another instance's id is refused with `Busy` while its owner is
/// alive and `Unavailable` otherwise, never `NotFound`. The sandboxes last as
/// long as the instance: shutdown fences and destroys them, removing managed
/// workspaces and leaving designated ones in place.
///
/// Host runs commands as local processes in a directory. It implements no
/// optional capability and refuses every workload field it cannot honour.
pub struct HostFactory;

#[async_trait]
impl ProviderFactory for HostFactory {
    async fn discover(&self, _: &PluginLocation) -> Result<ProviderSchemas, Error> {
        Ok(schemas())
    }

    async fn activate(&self, activation: Activation) -> Result<Arc<dyn ProviderRuntime>, Error> {
        Ok(Arc::new(HostRuntime::start(activation.name).await?))
    }
}

/// What every Host instance on this machine offers.
fn descriptor() -> Descriptor {
    Descriptor {
        schemas:      schemas(),
        namespace:    Namespace {
            id:    machine_namespace(),
            scope: NamespaceScope::Machine,
        },
        isolation:    Isolation::None,
        durability:   Durability::Process,
        access:       AccessScope::OwnerProcess,
        sources:      [SourceKind::HostDirectory].into(),
        locality:     Locality {
            host_address:      Some(LOOPBACK.into()),
            mounts_host_paths: true,
        },
        resources:    BTreeSet::default(),
        network:      [NetworkMode::ProviderDefault].into(),
        ports:        PortSupport::Any,
        capabilities: CapabilitySet::default(),
    }
}

/// A sandbox this instance created and still owns.
struct Owned {
    legacy:     Arc<dyn sandbox_driver::Sandbox>,
    workspace:  PathBuf,
    designated: bool,
    name:       Option<String>,
    labels:     BTreeMap<String, String>,
    env:        BTreeMap<String, String>,
    /// Counts fences begun, so an execution ended by one reports `Killed`
    /// rather than an exit without a code.
    fences:     AtomicU64,
}

impl Owned {
    fn fence_begun(&self) {
        self.fences.fetch_add(1, Ordering::SeqCst);
    }
}

struct HostRuntime {
    entry:      ProviderName,
    provider:   HostProvider,
    generation: String,
    descriptor: Descriptor,
    sequence:   AtomicU64,
    owned:      Mutex<BTreeMap<SandboxId, Arc<Owned>>>,
    /// Held for the instance's life; another instance tests it to tell a
    /// live owner (`Busy`) from one that is gone (`Unavailable`).
    _owner:     Flock<File>,
}

const ID_PREFIX: &str = "host-";
const SEQUENCE_SEPARATOR: &str = "-s";
const OWNER_LOCK: &str = "owner.lock";
/// A Host sandbox is reached on this machine.
const LOOPBACK: &str = "127.0.0.1";

impl HostRuntime {
    async fn start(entry: ProviderName) -> Result<Self, Error> {
        let generation = registry::fresh_id();
        let provider = HostProvider::temporary(&generation);
        registry::private_directory(&provider.root)
            .await
            .map_err(|error| unavailable(&error.to_string()))?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(provider.root.join(OWNER_LOCK))
            .map_err(|error| unavailable(&error.to_string()))?;
        let owner = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| unavailable("the Host instance could not lock its registry"))?;
        Ok(Self {
            entry,
            provider,
            generation,
            descriptor: descriptor(),
            sequence: AtomicU64::new(1),
            owned: Mutex::new(BTreeMap::new()),
            _owner: owner,
        })
    }

    fn sandboxes(&self) -> MutexGuard<'_, BTreeMap<SandboxId, Arc<Owned>>> {
        self.owned.lock().expect("owned lock")
    }

    /// Every sandbox this instance owns, read without holding the lock.
    fn snapshot(&self) -> Vec<(SandboxId, Arc<Owned>)> {
        self.sandboxes()
            .iter()
            .map(|(id, owned)| (id.clone(), Arc::clone(owned)))
            .collect()
    }

    fn reference(&self, id: &SandboxId) -> SandboxRef {
        SandboxRef {
            provider:  self.entry.clone(),
            namespace: self.descriptor.namespace.id.clone(),
            id:        id.clone(),
        }
    }

    /// This instance's sandbox, or why it cannot be operated from here.
    /// Absence is authoritative only for an id this instance issued.
    fn owned(&self, id: &SandboxId) -> Result<Arc<Owned>, Error> {
        if let Some(owned) = self.sandboxes().get(id) {
            return Ok(Arc::clone(owned));
        }
        match generation_of(id) {
            Some(generation) if generation == self.generation => Err(not_found(id)),
            Some(generation) => Err(foreign_owner(generation)),
            None => Err(unavailable("this id was not issued by a Host instance")),
        }
    }

    fn handle(&self, id: &SandboxId, owned: Arc<Owned>) -> Box<dyn Sandbox> {
        Box::new(HostSandbox {
            reference: self.reference(id),
            owned,
        })
    }

    async fn destroy_owned(&self, id: &SandboxId, owned: &Owned) -> Result<(), Error> {
        owned.fence_begun();
        owned.legacy.delete().await.map_err(contract_error)?;
        self.sandboxes().remove(id);
        Ok(())
    }
}

#[async_trait]
impl ProviderRuntime for HostRuntime {
    async fn describe(&self) -> Result<Descriptor, Error> {
        Ok(self.descriptor.clone())
    }

    async fn health(&self) -> Result<Health, Error> {
        Ok(Health {
            healthy: true,
            message: None,
        })
    }

    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error> {
        let spec = admission.spec;
        spec.validate_for(&self.descriptor)?;
        if spec.user.is_some() {
            return Err(unsupported("user"));
        }
        if !spec.provider_config.is_empty() {
            return Err(unsupported("provider_config"));
        }
        if spec.container.is_some() {
            return Err(unsupported("container"));
        }
        let mut legacy = sandbox_driver::SandboxSpec::new(SandboxSource::HostDirectory);
        legacy.name = spec.name.clone();
        legacy.labels = spec.labels.clone();
        legacy.env = spec.env.clone();
        legacy.workspace_ownership = spec.workspace_ownership;
        legacy.working_directory = spec.working_directory.clone();
        let designated = spec
            .working_directory
            .as_ref()
            .filter(|_| spec.workspace_ownership != Some(WorkspaceOwnership::Managed));
        if let Some(path) = designated {
            // One owner per directory in this instance: a second live
            // sandbox would share, and break, the first one's fence.
            let canonical = tokio_fs::canonicalize(path)
                .await
                .map_err(|_| Error::InvalidSpec {
                    path:    "working_directory".into(),
                    message: "the designated directory does not exist".into(),
                })?;
            let taken = self
                .sandboxes()
                .values()
                .any(|owned| owned.designated && owned.workspace == canonical);
            if taken {
                return Err(Error::Busy {
                    message: "another sandbox of this instance owns the directory".into(),
                });
            }
        }
        let designated = designated.is_some();
        let sandbox = self
            .provider
            .create(&legacy, None)
            .await
            .map_err(contract_error)?;
        let env = sandbox.environment().await.map_err(contract_error)?;
        let id = SandboxId::try_new(format!(
            "{ID_PREFIX}{}{SEQUENCE_SEPARATOR}{}",
            self.generation,
            self.sequence.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("generated ids are valid");
        let owned = Arc::new(Owned {
            workspace: PathBuf::from(sandbox.working_directory()),
            legacy: sandbox,
            designated,
            name: spec.name,
            labels: spec.labels,
            env,
            fences: AtomicU64::new(0),
        });
        self.sandboxes().insert(id.clone(), Arc::clone(&owned));
        Ok(self.handle(&id, owned))
    }

    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error> {
        let owned = self.owned(id)?;
        Ok(self.handle(id, owned))
    }

    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error> {
        let mut summaries = Vec::new();
        for (id, owned) in self.snapshot() {
            if !filter.matches(&owned.labels) {
                continue;
            }
            summaries.push(SandboxSummary {
                reference: self.reference(&id),
                name:      owned.name.clone(),
                state:     state_of(&*owned.legacy).await?,
                labels:    owned.labels.clone(),
            });
        }
        Ok(summaries)
    }

    async fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        match self.owned(id) {
            Ok(owned) => self.destroy_owned(id, &owned).await,
            // Already destroyed by this instance.
            Err(Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// The instance is ending and its sandboxes with it: every one is fenced
    /// and destroyed. A failure leaves the rest attempted and is reported.
    async fn shutdown(&self) -> Result<(), Error> {
        let mut remaining = Vec::new();
        for (id, owned) in self.snapshot() {
            if let Err(error) = self.destroy_owned(&id, &owned).await {
                tracing::warn!(sandbox_id = %id, error = %error, "host sandbox cleanup failed");
                remaining.push(RemainingResource {
                    kind: "sandbox".into(),
                    id:   id.to_string(),
                });
            }
        }
        if remaining.is_empty() {
            let _ = tokio_fs::remove_dir_all(&self.provider.root).await;
            Ok(())
        } else {
            Err(Error::IncompleteCleanup {
                message: "some Host sandboxes could not be fenced and removed".into(),
                remaining,
            })
        }
    }
}

struct HostSandbox {
    reference: SandboxRef,
    owned:     Arc<Owned>,
}

impl HostSandbox {
    /// Relative paths address the workspace; Host has no isolation, so an
    /// absolute path is the host path it names.
    fn resolve(&self, path: &str) -> Result<PathBuf, Error> {
        if path.is_empty() || path.contains('\0') {
            return Err(Error::InvalidSpec {
                path:    "path".into(),
                message: "path must be non-empty and contain no NUL".into(),
            });
        }
        Ok(self.owned.workspace.join(path))
    }
}

#[async_trait]
impl Sandbox for HostSandbox {
    fn reference(&self) -> SandboxRef {
        self.reference.clone()
    }
    fn working_directory(&self) -> &Path {
        &self.owned.workspace
    }
    fn env(&self) -> &BTreeMap<String, String> {
        &self.owned.env
    }
    async fn status(&self) -> Result<Status, Error> {
        Ok(Status {
            reference: self.reference.clone(),
            state:     state_of(&*self.owned.legacy).await?,
            name:      self.owned.name.clone(),
            labels:    self.owned.labels.clone(),
            image:     None,
            snapshot:  None,
            resources: Resources::default(),
            network:   None,
            services:  BTreeMap::new(),
            web_url:   None,
        })
    }
    async fn start(&self) -> Result<(), Error> {
        self.owned.legacy.start().await.map_err(contract_error)
    }
    /// Fences every process group of the sandbox before returning.
    async fn stop(&self) -> Result<(), Error> {
        self.owned.fence_begun();
        self.owned.legacy.stop().await.map_err(contract_error)
    }
    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error> {
        spec.validate()?;
        if spec.tty {
            return Err(unsupported("exec.tty"));
        }
        let mut argv = spec.argv.into_iter();
        let program = argv.next().expect("validated argv");
        let mut legacy = sandbox_driver::ExecSpec::new(program).args(argv);
        legacy.timeout = spec.timeout_ms.map(Duration::from_millis);
        legacy.working_dir = spec.working_directory;
        legacy.env = spec.env;
        let sink = controls.sink.map(|sink| {
            let sink: sandbox_driver::OutputSink = Arc::new(move |stream, chunk| {
                let stream = match stream {
                    OutputStream::Stdout => ContractStream::Stdout,
                    OutputStream::Stderr => ContractStream::Stderr,
                };
                let delivery = sink(stream, chunk);
                Box::pin(async move {
                    delivery.await.map_err(|error| {
                        sandbox_driver::Error::Transport(sandbox_driver::TransportError::new(
                            error.to_string(),
                        ))
                    })
                })
            });
            sink
        });
        let fences = self.owned.fences.load(Ordering::SeqCst);
        let result = self
            .owned
            .legacy
            .exec()
            .run_streaming(&legacy, sandbox_driver::ExecControls {
                term: controls.term,
                kill: controls.kill,
                stdin: controls.stdin.map(StdinSource::new),
                sink,
                retained_output_limit: None,
            })
            .await
            .map_err(contract_error)?;
        Ok(ExecOutcome {
            termination: match result.result.termination {
                // A process with no exit code died by a signal; one sent by
                // a fence that began during the run is the stop's kill.
                sandbox_driver::Termination::Exited
                    if result.result.exit_code.is_none()
                        && self.owned.fences.load(Ordering::SeqCst) != fences =>
                {
                    Termination::Killed
                }
                sandbox_driver::Termination::Exited => Termination::Exited,
                sandbox_driver::Termination::TimedOut => Termination::TimedOut,
                sandbox_driver::Termination::Cancelled => Termination::Terminated,
                sandbox_driver::Termination::Killed => Termination::Killed,
                _ => Termination::Lost,
            },
            exit_code:   result.result.exit_code,
            signal:      result.result.signal,
            output_loss: result.output_loss,
        })
    }
    fn files(&self) -> &dyn Files {
        self
    }
    fn ports(&self) -> &dyn Ports {
        &HostPorts
    }
}

#[async_trait]
impl Files for HostSandbox {
    async fn get(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error> {
        let resolved = self.resolve(path)?;
        let mut file = tokio_fs::File::open(&resolved)
            .await
            .map_err(|error| file_error(path, &error))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|error| file_error(path, &error))?;
        if !metadata.is_file() {
            return Err(Error::InvalidSpec {
                path:    "path".into(),
                message: "not a regular file".into(),
            });
        }
        let Some(range) = range else {
            return Ok(Box::pin(file));
        };
        file.seek(SeekFrom::Start(range.offset))
            .await
            .map_err(|error| file_error(path, &error))?;
        Ok(Box::pin(file.take(range.length.unwrap_or(u64::MAX))))
    }

    /// Writes beside the destination and renames, so a failed or partial
    /// upload never replaces the file.
    async fn put(&self, path: &str, mut bytes: ByteStream) -> Result<(), Error> {
        let destination = self.resolve(path)?;
        let (Some(parent), Some(name)) = (destination.parent(), destination.file_name()) else {
            return Err(Error::InvalidSpec {
                path:    "path".into(),
                message: "path must name a file".into(),
            });
        };
        tokio_fs::create_dir_all(parent)
            .await
            .map_err(|error| file_error(path, &error))?;
        let temporary = parent.join(format!(
            ".{}.upload-{}",
            name.to_string_lossy(),
            registry::fresh_id()
        ));
        let written = async {
            let mut file = tokio_fs::File::create(&temporary).await?;
            io_copy(&mut bytes, &mut file).await?;
            file.flush().await?;
            file.sync_all().await?;
            tokio_fs::rename(&temporary, &destination).await
        }
        .await;
        if let Err(error) = written {
            let _ = tokio_fs::remove_file(&temporary).await;
            return Err(Error::Transport {
                message: format!("writing {path} failed: {error}"),
                outcome: MutationOutcome::NotStarted,
            });
        }
        Ok(())
    }

    async fn list(&self, path: &str, depth: u32) -> Result<Vec<FileEntry>, Error> {
        let root = self.resolve(path)?;
        let mut entries = Vec::new();
        let mut pending = vec![(root, path.trim_end_matches('/').to_owned(), 0)];
        while let Some((directory, prefix, level)) = pending.pop() {
            let mut children = tokio_fs::read_dir(&directory)
                .await
                .map_err(|error| file_error(path, &error))?;
            while let Some(child) = children
                .next_entry()
                .await
                .map_err(|error| file_error(path, &error))?
            {
                let child_path = child.path();
                let metadata = tokio_fs::symlink_metadata(&child_path)
                    .await
                    .map_err(|error| file_error(path, &error))?;
                let kind = kind_of(metadata.file_type());
                let entry_path = format!("{prefix}/{}", child.file_name().to_string_lossy());
                if kind == FileKind::Directory && level < depth {
                    pending.push((child_path, entry_path.clone(), level + 1));
                }
                entries.push(FileEntry {
                    path: entry_path,
                    kind,
                    size: metadata.len(),
                });
            }
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }
}

/// A port in a Host sandbox is a port on this machine.
struct HostPorts;

#[async_trait]
impl Ports for HostPorts {
    async fn expose(&self, port: NonZeroU16, options: Expose) -> Result<Exposure, Error> {
        if options.signed {
            return Err(unsupported("ports.signed"));
        }
        Ok(Exposure {
            url:           format!("http://{LOOPBACK}:{port}"),
            headers:       BTreeMap::new(),
            expires_at_ms: None,
        })
    }
    async fn release(&self, _: NonZeroU16) -> Result<(), Error> {
        Ok(())
    }
}

async fn state_of(sandbox: &dyn sandbox_driver::Sandbox) -> Result<SandboxState, Error> {
    let status = sandbox.describe().await.map_err(contract_error)?;
    Ok(match status.state {
        sandbox_driver::SandboxState::Running => SandboxState::Running,
        sandbox_driver::SandboxState::Stopped => SandboxState::Stopped,
        sandbox_driver::SandboxState::Stopping => SandboxState::Stopping,
        sandbox_driver::SandboxState::Starting => SandboxState::Starting,
        sandbox_driver::SandboxState::Creating => SandboxState::Creating,
        sandbox_driver::SandboxState::Deleting => SandboxState::Deleting,
        sandbox_driver::SandboxState::Deleted => SandboxState::Deleted,
        sandbox_driver::SandboxState::Error => SandboxState::Unhealthy,
        _ => SandboxState::Unknown,
    })
}

/// `host:` plus a stable machine identity: the systemd/D-Bus machine id
/// where there is one, otherwise the host name.
fn machine_namespace() -> NamespaceId {
    let machine = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .or_else(|| gethostname().ok().and_then(|name| name.into_string().ok()))
        .unwrap_or_else(|| "unknown".into());
    let machine: String = machine
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .take(200)
        .collect();
    NamespaceId::try_new(format!("host:{machine}")).expect("sanitized namespace is valid")
}

/// The generation an id names, when it has this provider's id shape.
fn generation_of(id: &SandboxId) -> Option<&str> {
    let (generation, sequence) = id
        .as_str()
        .strip_prefix(ID_PREFIX)?
        .rsplit_once(SEQUENCE_SEPARATOR)?;
    let plain = |text: &str| {
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    (plain(generation) && sequence.bytes().all(|b| b.is_ascii_digit())).then_some(generation)
}

/// Another instance's sandbox. Its liveness is visible through the lock it
/// holds; this instance never takes the sandbox over either way.
fn foreign_owner(generation: &str) -> Error {
    let lock = temporary_root(generation).join(OWNER_LOCK);
    let live = File::open(lock).is_ok_and(|file| {
        matches!(
            Flock::lock(file, FlockArg::LockSharedNonblock),
            Err((_, Errno::EWOULDBLOCK))
        )
    });
    if live {
        Error::Busy {
            message: "the sandbox is owned by another live Host instance".into(),
        }
    } else {
        unavailable(
            "the Host instance that owned this sandbox cannot be reached; it is not \
             reattachable",
        )
    }
}

fn not_found(id: &SandboxId) -> Error {
    Error::NotFound {
        resource: "sandbox".into(),
        id:       id.to_string(),
    }
}

/// A refusal made before anything was attempted.
fn unavailable(message: &str) -> Error {
    Error::Unavailable {
        message: message.into(),
        outcome: MutationOutcome::NotStarted,
    }
}

fn unsupported(capability: &str) -> Error {
    Error::Unsupported {
        capability: capability.into(),
    }
}

fn file_error(path: &str, error: &io::Error) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        Error::NotFound {
            resource: "file".into(),
            id:       path.into(),
        }
    } else {
        Error::InvalidSpec {
            path:    "path".into(),
            message: format!("{path}: {}", error.kind()),
        }
    }
}

/// The legacy implementation's errors in the shared vocabulary. Only a
/// classification the legacy error establishes is kept; anything else is an
/// unknown outcome, never absence or success.
fn contract_error(error: sandbox_driver::Error) -> Error {
    use sandbox_driver::Error as Legacy;
    match error {
        Legacy::NotFound { resource, id } => Error::NotFound {
            resource: format!("{resource:?}").to_ascii_lowercase(),
            id,
        },
        Legacy::InvalidSpec { field, reason } => Error::InvalidSpec {
            path:    field,
            message: reason,
        },
        Legacy::Unsupported { capability } => Error::Unsupported {
            capability: capability.to_string(),
        },
        Legacy::InvalidState { current, action } => Error::Busy {
            message: format!("cannot {action:?} while the sandbox is {current:?}"),
        },
        other => Error::Unavailable {
            message: other.to_string(),
            outcome: MutationOutcome::Unknown,
        },
    }
}
