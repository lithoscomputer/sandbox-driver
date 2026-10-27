//! Deterministic in-memory provider for caller tests. No commands run on the
//! host. Exec responses are explicitly scripted; an unscripted command fails.
use std::collections::{BTreeMap, BTreeSet};
use std::future;
use std::io::Cursor;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::contract::{
    AccessScope, Activation, ByteStream, CapabilitySet, CatalogOptions, Descriptor, Durability,
    Environment, EnvironmentName, Error, ExecControls, ExecOutcome, ExecSpec, Expose, Exposure,
    FileEntry, FileRange, Files, Health, LabelFilter, Locality, MutationOutcome, Namespace,
    NamespaceId, NamespaceScope, NetworkMode, OutputStream, PluginLocation, PortSupport, Ports,
    ProviderEntry, ProviderFactory, ProviderName, ProviderRuntime, ProviderSchemas, Registry,
    Sandbox, SandboxRef, SandboxSpec, SandboxState, SandboxSummary, Sandboxes, SecretResolver,
    Source, SourceKind, StaticEnvironments, Status, Termination, WorkloadAdmission,
};
use sandbox_driver::{FileKind, Isolation, OutputLoss, ProviderKind, SandboxId};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tokio_util::sync::CancellationToken;

static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(1);

/// A scripted command. Output is delivered through the real sink. Pending
/// commands finish only on cancellation, timeout or sandbox stop/destroy.
#[derive(Clone, Debug, Default)]
pub struct FakeExec {
    pub stdout:        Vec<u8>,
    pub stderr:        Vec<u8>,
    pub exit_code:     i32,
    pub wait_for_stop: bool,
}
/// Observable calls contain IDs/operation names, never runtime secret values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeCall {
    pub operation: String,
    pub id:        Option<SandboxId>,
}

/// One fake backend. Clones share state; each factory activation remains bound
/// to its entry. It declares process durability and no optional capabilities.
#[derive(Clone)]
pub struct FakeProvider {
    inner: Arc<FakeState>,
}
struct FakeState {
    namespace: NamespaceId,
    next_id:   AtomicU64,
    records:   Mutex<BTreeMap<SandboxId, Arc<Record>>>,
    calls:     Mutex<Vec<FakeCall>>,
    scripts:   Mutex<BTreeMap<Vec<String>, FakeExec>>,
}
struct Runtime {
    fake:   FakeProvider,
    entry:  ProviderName,
    closed: CancellationToken,
}
struct Record {
    reference: SandboxRef,
    spec:      SandboxSpec,
    directory: PathBuf,
    state:     Mutex<RunningState>,
    fence:     RwLock<()>,
    files:     Mutex<BTreeMap<String, Vec<u8>>>,
}
struct RunningState {
    state: SandboxState,
    stop:  CancellationToken,
}
struct Handle {
    record: Arc<Record>,
    fake:   FakeProvider,
    closed: CancellationToken,
}

impl Default for FakeProvider {
    fn default() -> Self {
        Self::new()
    }
}
impl FakeProvider {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FakeState {
                namespace: NamespaceId::try_new(format!(
                    "fake:{}",
                    NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed)
                ))
                .expect("generated namespace"),
                next_id:   AtomicU64::new(1),
                records:   Mutex::new(BTreeMap::new()),
                calls:     Mutex::new(Vec::new()),
                scripts:   Mutex::new(BTreeMap::new()),
            }),
        }
    }
    pub async fn script(
        &self,
        argv: impl IntoIterator<Item = impl Into<String>>,
        response: FakeExec,
    ) {
        self.inner
            .scripts
            .lock()
            .await
            .insert(argv.into_iter().map(Into::into).collect(), response);
    }
    pub async fn calls(&self) -> Vec<FakeCall> {
        self.inner.calls.lock().await.clone()
    }
    pub fn schemas() -> ProviderSchemas {
        ProviderSchemas { kind:ProviderKind::try_new("fake").expect("constant kind"), version:"1".into(),
            config_schema:serde_json::from_value(serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object", "additionalProperties":false})).expect("constant schema"),
            spec_schema:Some(serde_json::from_value(serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "type":"object", "additionalProperties":false})).expect("constant schema")), secrets:Vec::new() }
    }
    pub fn descriptor(&self) -> Descriptor {
        Descriptor {
            schemas:      Self::schemas(),
            namespace:    Namespace {
                id:    self.inner.namespace.clone(),
                scope: NamespaceScope::Process,
            },
            isolation:    Isolation::None,
            durability:   Durability::Process,
            access:       AccessScope::Shared,
            sources:      [SourceKind::Image].into(),
            locality:     Locality::default(),
            resources:    BTreeSet::default(),
            network:      [NetworkMode::ProviderDefault].into(),
            ports:        PortSupport::None,
            capabilities: CapabilitySet::default(),
        }
    }
    async fn record(&self, operation: &str, id: Option<&SandboxId>) {
        self.inner.calls.lock().await.push(FakeCall {
            operation: operation.into(),
            id:        id.cloned(),
        });
    }
    /// Creates a catalog with `fake` provider and `default` environment. These
    /// names are test fixtures only; production catalogs have no seeded
    /// entries.
    pub fn sandboxes(&self) -> Sandboxes {
        struct NoSecrets;
        #[async_trait]
        impl SecretResolver for NoSecrets {
            async fn resolve(&self, _: &str) -> Result<Option<String>, Error> {
                Ok(None)
            }
        }
        let name = ProviderName::try_new("fake").expect("constant name");
        let entry: ProviderEntry =
            serde_json::from_value(serde_json::json!({"plugin":"fake"})).expect("constant entry");
        let environment = Environment {
            provider: name.clone(),
            spec:     SandboxSpec::new(Source::Image("fake:workload".into())),
        };
        let registry = Registry::new()
            .builtin(entry.plugin.clone(), Arc::new(self.clone()))
            .expect("unique fake registration");
        Sandboxes::try_new(
            [(name, entry)],
            Arc::new(StaticEnvironments(BTreeMap::from([(
                EnvironmentName::try_new("default").expect("constant name"),
                environment,
            )]))),
            &registry,
            Arc::new(NoSecrets),
            CatalogOptions {
                environment: BTreeMap::new(),
                ..CatalogOptions::default()
            },
        )
        .expect("valid fake catalog")
    }
}
/// Creates a catalog with a fresh in-memory fake and the `default` environment.
pub fn fake() -> Sandboxes {
    FakeProvider::new().sandboxes()
}

#[async_trait]
impl ProviderFactory for FakeProvider {
    async fn discover(&self, _: &PluginLocation) -> Result<ProviderSchemas, Error> {
        self.record("discover", None).await;
        Ok(Self::schemas())
    }
    async fn activate(&self, activation: Activation) -> Result<Arc<dyn ProviderRuntime>, Error> {
        self.record("activate", None).await;
        Ok(Arc::new(Runtime {
            fake:   self.clone(),
            entry:  activation.name,
            closed: CancellationToken::new(),
        }))
    }
}
impl Runtime {
    fn open(&self) -> Result<(), Error> {
        if self.closed.is_cancelled() {
            Err(stale())
        } else {
            Ok(())
        }
    }
    async fn handle(&self, id: &SandboxId) -> Result<Handle, Error> {
        self.open()?;
        let record = self
            .fake
            .inner
            .records
            .lock()
            .await
            .get(id)
            .filter(|record| record.reference.provider == self.entry)
            .cloned()
            .ok_or_else(|| absent(id))?;
        Ok(Handle {
            record,
            fake: self.fake.clone(),
            closed: self.closed.clone(),
        })
    }
}
#[async_trait]
impl ProviderRuntime for Runtime {
    async fn describe(&self) -> Result<Descriptor, Error> {
        self.open()?;
        self.fake.record("describe", None).await;
        Ok(self.fake.descriptor())
    }
    async fn health(&self) -> Result<Health, Error> {
        self.open()?;
        self.fake.record("health", None).await;
        Ok(Health {
            healthy: true,
            message: None,
        })
    }
    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error> {
        self.open()?;
        admission.spec.validate_for(&self.fake.descriptor())?;
        if !admission.spec.provider_config.is_empty() {
            return Err(Error::InvalidSpec {
                path:    "provider_config".into(),
                message: "fake accepts no options".into(),
            });
        }
        let mut records = self.fake.inner.records.lock().await;
        if let Some(name) = &admission.spec.name {
            if let Some(record) = records.values().find(|record| {
                record.reference.provider == self.entry && record.spec.name.as_ref() == Some(name)
            }) {
                return Err(Error::AlreadyExists {
                    name: name.clone(),
                    id:   record.reference.id.to_string(),
                });
            }
        }
        let id = SandboxId::try_new(format!(
            "sandbox-{}",
            self.fake.inner.next_id.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("generated id");
        let directory = PathBuf::from(
            admission
                .spec
                .working_directory
                .as_deref()
                .unwrap_or("/workspace"),
        );
        let record = Arc::new(Record {
            reference: SandboxRef {
                provider:  self.entry.clone(),
                namespace: self.fake.inner.namespace.clone(),
                id:        id.clone(),
            },
            spec: admission.spec,
            directory,
            state: Mutex::new(RunningState {
                state: SandboxState::Running,
                stop:  CancellationToken::new(),
            }),
            fence: RwLock::new(()),
            files: Mutex::new(BTreeMap::new()),
        });
        records.insert(id.clone(), Arc::clone(&record));
        drop(records);
        self.fake.record("create", Some(&id)).await;
        Ok(Box::new(Handle {
            record,
            fake: self.fake.clone(),
            closed: self.closed.clone(),
        }))
    }
    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error> {
        let handle = self.handle(id).await?;
        self.fake.record("attach", Some(id)).await;
        Ok(Box::new(handle))
    }
    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error> {
        self.open()?;
        self.fake.record("list", None).await;
        let records: Vec<_> = self
            .fake
            .inner
            .records
            .lock()
            .await
            .values()
            .filter(|record| {
                record.reference.provider == self.entry && filter.matches(&record.spec.labels)
            })
            .cloned()
            .collect();
        let mut summaries = Vec::new();
        for record in records {
            summaries.push(SandboxSummary {
                reference: record.reference.clone(),
                name:      record.spec.name.clone(),
                state:     record.state.lock().await.state,
                labels:    record.spec.labels.clone(),
            });
        }
        Ok(summaries)
    }
    async fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        self.open()?;
        let handle = match self.handle(id).await {
            Ok(handle) => handle,
            Err(Error::NotFound { .. }) => return Ok(()),
            Err(error) => return Err(error),
        };
        handle.end(true).await?;
        self.fake.inner.records.lock().await.remove(id);
        self.fake.record("destroy", Some(id)).await;
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), Error> {
        // Each activation owns its handles; closed cancels all its live execs.
        self.closed.cancel();
        self.fake.record("shutdown", None).await;
        Ok(())
    }
}

impl Handle {
    fn path(&self, path: &str) -> Result<String, Error> {
        if path.is_empty() || path.contains('\0') {
            return Err(Error::InvalidSpec {
                path:    "path".into(),
                message: "requires a non-empty NUL-free workload path".into(),
            });
        }
        let joined = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{}", self.record.directory.display(), path)
        };
        let mut parts = Vec::new();
        for part in joined.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                part => parts.push(part),
            }
        }
        Ok(format!("/{}", parts.join("/")))
    }
    fn open(&self) -> Result<(), Error> {
        if self.closed.is_cancelled() {
            Err(stale())
        } else {
            Ok(())
        }
    }
    async fn end(&self, destroy: bool) -> Result<(), Error> {
        self.open()?;
        {
            let mut state = self.record.state.lock().await;
            if state.state == SandboxState::Deleted {
                return if destroy {
                    Ok(())
                } else {
                    Err(absent(&self.record.reference.id))
                };
            }
            if state.state == SandboxState::Deleting && !destroy {
                return Err(busy());
            }
            state.state = if destroy {
                SandboxState::Deleting
            } else {
                SandboxState::Stopping
            };
            state.stop.cancel();
        }
        let _fence = self.record.fence.write().await;
        let mut state = self.record.state.lock().await;
        if destroy {
            self.record.files.lock().await.clear();
            state.state = SandboxState::Deleted;
        } else if state.state == SandboxState::Stopping {
            state.state = SandboxState::Stopped;
        }
        Ok(())
    }
}
#[async_trait]
impl Sandbox for Handle {
    fn reference(&self) -> SandboxRef {
        self.record.reference.clone()
    }
    fn working_directory(&self) -> &Path {
        &self.record.directory
    }
    fn env(&self) -> &BTreeMap<String, String> {
        &self.record.spec.env
    }
    async fn status(&self) -> Result<Status, Error> {
        self.open()?;
        self.fake
            .record("status", Some(&self.record.reference.id))
            .await;
        let state = self.record.state.lock().await.state;
        Ok(Status {
            reference: self.reference(),
            state,
            name: self.record.spec.name.clone(),
            labels: self.record.spec.labels.clone(),
            image: match &self.record.spec.source {
                Source::Image(image) => Some(image.clone()),
                _ => None,
            },
            snapshot: None,
            resources: self.record.spec.resources.clone(),
            network: Some(self.record.spec.network.clone()),
            services: BTreeMap::new(),
            web_url: None,
        })
    }
    async fn start(&self) -> Result<(), Error> {
        self.open()?;
        let _fence = self.record.fence.try_write().map_err(|_| busy())?;
        let mut state = self.record.state.lock().await;
        match state.state {
            SandboxState::Stopping | SandboxState::Deleting => return Err(busy()),
            SandboxState::Deleted => return Err(absent(&self.record.reference.id)),
            SandboxState::Running => return Ok(()),
            _ => {}
        }
        state.stop = CancellationToken::new();
        state.state = SandboxState::Running;
        self.fake
            .record("start", Some(&self.record.reference.id))
            .await;
        Ok(())
    }
    async fn stop(&self) -> Result<(), Error> {
        self.end(false).await?;
        self.fake
            .record("stop", Some(&self.record.reference.id))
            .await;
        Ok(())
    }
    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error> {
        self.open()?;
        spec.validate()?;
        let _fence = self.record.fence.read().await;
        let stop = {
            let state = self.record.state.lock().await;
            if state.state != SandboxState::Running {
                return Err(busy());
            }
            state.stop.clone()
        };
        let response = self
            .fake
            .inner
            .scripts
            .lock()
            .await
            .get(&spec.argv)
            .cloned()
            .ok_or_else(|| Error::Unsupported {
                capability: "unscripted fake command".into(),
            })?;
        self.fake
            .record("exec", Some(&self.record.reference.id))
            .await;
        let work = async {
            if let Some(mut stdin) = controls.stdin {
                let mut bytes = [0; 4096];
                while stdin.read(&mut bytes).await.map_err(|_| Error::Transport {
                    message: "fake stdin failed".into(),
                    outcome: MutationOutcome::Unknown,
                })? != 0
                {}
            }
            if let Some(sink) = controls.sink {
                let stdout = if spec.tty {
                    OutputStream::Terminal
                } else {
                    OutputStream::Stdout
                };
                let stderr = if spec.tty {
                    OutputStream::Terminal
                } else {
                    OutputStream::Stderr
                };
                if !response.stdout.is_empty() {
                    sink(stdout, response.stdout).await?;
                }
                if !response.stderr.is_empty() {
                    sink(stderr, response.stderr).await?;
                }
            }
            if response.wait_for_stop {
                future::pending::<()>().await;
            }
            Ok::<_, Error>(Termination::Exited)
        };
        let deadline = async {
            if let Some(ms) = spec.timeout_ms {
                time::sleep(Duration::from_millis(ms)).await;
            } else {
                future::pending::<()>().await;
            }
        };
        let termination = tokio::select! {
            biased;
            () = self.closed.cancelled() => return Err(Error::Stale {outcome:MutationOutcome::Unknown}),
            () = stop.cancelled() => Termination::Killed,
            () = sandbox_driver::stop_signal(controls.kill.as_ref()) => Termination::Killed,
            () = sandbox_driver::stop_signal(controls.term.as_ref()) => Termination::Terminated,
            () = deadline => Termination::TimedOut,
            result = work => result?,
        };
        Ok(ExecOutcome {
            termination,
            exit_code: (termination == Termination::Exited).then_some(response.exit_code),
            signal: None,
            output_loss: OutputLoss::default(),
        })
    }
    fn files(&self) -> &dyn Files {
        self
    }
    fn ports(&self) -> &dyn Ports {
        self
    }
}

#[async_trait]
impl Files for Handle {
    async fn get(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error> {
        self.open()?;
        self.fake
            .record("files.get", Some(&self.record.reference.id))
            .await;
        let files = self.record.files.lock().await;
        let path = self.path(path)?;
        let bytes = files.get(&path).ok_or_else(|| Error::NotFound {
            resource: "file".into(),
            id:       path,
        })?;
        let start = range
            .map_or(0, |range| {
                usize::try_from(range.offset).unwrap_or(usize::MAX)
            })
            .min(bytes.len());
        let end = range
            .and_then(|range| range.length)
            .map_or(bytes.len(), |length| {
                start
                    .saturating_add(usize::try_from(length).unwrap_or(usize::MAX))
                    .min(bytes.len())
            });
        Ok(Box::pin(Cursor::new(bytes[start..end].to_vec())))
    }
    async fn put(&self, path: &str, mut bytes: ByteStream) -> Result<(), Error> {
        self.open()?;
        let _fence = self.record.fence.read().await;
        let stop = {
            let state = self.record.state.lock().await;
            if state.state != SandboxState::Running {
                return Err(busy());
            }
            state.stop.clone()
        };
        let mut buffer = Vec::new();
        tokio::select! {
            () = self.closed.cancelled() => return Err(stale()),
            () = stop.cancelled() => return Err(busy()),
            result = bytes.read_to_end(&mut buffer) => {result.map_err(|_| Error::Transport {message:"fake file input failed".into(), outcome:MutationOutcome::Unknown})?;}
        }
        self.record
            .files
            .lock()
            .await
            .insert(self.path(path)?, buffer);
        self.fake
            .record("files.put", Some(&self.record.reference.id))
            .await;
        Ok(())
    }
    async fn list(&self, path: &str, depth: u32) -> Result<Vec<FileEntry>, Error> {
        self.open()?;
        self.fake
            .record("files.list", Some(&self.record.reference.id))
            .await;
        let path = self.path(path)?;
        let prefix = format!("{}/", path.trim_end_matches('/'));
        let files = self.record.files.lock().await;
        let mut entries = BTreeMap::new();
        for (path, bytes) in files.iter() {
            let Some(tail) = path.strip_prefix(&prefix) else {
                continue;
            };
            let parts: Vec<_> = tail.split('/').collect();
            for index in 0..parts.len().min((depth as usize).saturating_add(1)) {
                let entry_path = format!("{}{}", prefix, parts[..=index].join("/"));
                let is_file = index + 1 == parts.len();
                entries.insert(entry_path.clone(), FileEntry {
                    path: entry_path,
                    kind: if is_file {
                        FileKind::File
                    } else {
                        FileKind::Directory
                    },
                    size: if is_file { bytes.len() as u64 } else { 0 },
                });
            }
        }
        Ok(entries.into_values().collect())
    }
}
#[async_trait]
impl Ports for Handle {
    async fn expose(&self, _: NonZeroU16, _: Expose) -> Result<Exposure, Error> {
        self.open()?;
        self.fake
            .record("ports", Some(&self.record.reference.id))
            .await;
        Err(Error::Unsupported {
            capability: "ports".into(),
        })
    }
    async fn release(&self, _: NonZeroU16) -> Result<(), Error> {
        self.open()?;
        self.fake
            .record("ports", Some(&self.record.reference.id))
            .await;
        Err(Error::Unsupported {
            capability: "ports".into(),
        })
    }
}
fn absent(id: &SandboxId) -> Error {
    Error::NotFound {
        resource: "sandbox".into(),
        id:       id.to_string(),
    }
}
fn busy() -> Error {
    Error::Busy {
        message: "fake sandbox is not accepting execution".into(),
    }
}
fn stale() -> Error {
    Error::Stale {
        outcome: MutationOutcome::NotStarted,
    }
}
