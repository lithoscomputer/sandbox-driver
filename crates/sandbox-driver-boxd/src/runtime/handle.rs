//! One boxd machine behind the shared contract's `Sandbox`.
//!
//! The fence is the machine's own lifecycle state on boxd's control plane,
//! which every provider instance reads. Commands and writes are admitted
//! only while the machine is running, and a command records the machine's
//! kernel boot id when it is admitted, so a restart under it can be told
//! from a broken connection. `StopVm` returns once the machine is stopped,
//! which ends every process in it, and this provider reads the state back
//! before reporting the fence.

use std::collections::BTreeMap;
use std::io::{self, Cursor};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::{TryStreamExt as _, stream};
use sandbox_driver::{
    ByteStream, Endpoints, Error, ExecControls, ExecOutcome, ExecSpec, Expose, Exposure, FileEntry,
    FileKind, FileRange, Files, MutationOutcome, OutputLoss, Ports, Resources, Sandbox, SandboxRef,
    SandboxState, SshAccessInfo, Status, Termination, VncConnection,
};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;
use tonic::Code;

use super::api::{
    CreateProxyRequest, DeleteProxyRequest, FsEntryType, FsListRequest, FsReadRequest,
    FsWriteChunk, GetVmRequest, GetVmResponse, ListProxiesRequest, ResumeVmRequest, StartVmRequest,
    StopVmRequest, WakeVmRequest,
};
use super::connection::{Connection, requests};
use super::error::{classify, not_found, refused};
use super::exec::{self, Command, Controls, Ended};
use super::labels::{self, Meta};
use super::spec::{self, DISK_MIB};
use super::{LIFECYCLE_BUDGET, POLL, ensure_open};

/// Bytes of file content sent per message.
const WRITE_CHUNK: usize = 256 * 1024;
const MIB: u64 = 1024 * 1024;
/// Changes on every boot of the machine's kernel, and on no other event.
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// boxd's lifecycle states, as `GetVm` reports them. Only states boxd
/// documents, or was seen to report, are named; any other is `Other`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    /// Created, pulling its image.
    Pending,
    Starting,
    Running,
    Hibernating,
    Stopped,
    /// Suspended (standby) or hibernated: memory is kept, nothing runs.
    Asleep {
        hibernated: bool,
    },
    Destroying,
    Destroyed,
    Failed,
    Other,
}

impl Phase {
    pub(super) fn of(status: &str) -> Self {
        match status {
            "pending" => Self::Pending,
            "starting" | "rebooting" => Self::Starting,
            "running" => Self::Running,
            "hibernating" => Self::Hibernating,
            "stopped" => Self::Stopped,
            // `standby` is the CLI's name for the API's `suspended`.
            "suspended" | "standby" => Self::Asleep { hibernated: false },
            "hibernated" => Self::Asleep { hibernated: true },
            "destroying" => Self::Destroying,
            "destroyed" => Self::Destroyed,
            "failed" => Self::Failed,
            _ => Self::Other,
        }
    }

    pub(super) fn state(self) -> SandboxState {
        match self {
            Self::Pending => SandboxState::Creating,
            Self::Starting => SandboxState::Starting,
            Self::Running => SandboxState::Running,
            Self::Hibernating => SandboxState::Stopping,
            Self::Stopped => SandboxState::Stopped,
            Self::Asleep { .. } => SandboxState::Paused,
            Self::Destroying => SandboxState::Deleting,
            Self::Destroyed => SandboxState::Deleted,
            Self::Failed => SandboxState::Unhealthy,
            Self::Other => SandboxState::Unknown,
        }
    }
}

pub(super) struct Machine {
    connection: Arc<Connection>,
    reference:  SandboxRef,
    name:       String,
    directory:  PathBuf,
    env:        BTreeMap<String, String>,
    closed:     CancellationToken,
}

impl Machine {
    pub(super) fn new(
        connection: Arc<Connection>,
        reference: SandboxRef,
        name: String,
        meta: Meta,
        closed: CancellationToken,
    ) -> Self {
        Self {
            connection,
            reference,
            name,
            directory: PathBuf::from(meta.working_directory),
            env: meta.env,
            closed,
        }
    }

    fn id(&self) -> &str {
        self.reference.id.as_str()
    }

    fn absent(&self) -> Error {
        Error::NotFound {
            resource: "sandbox".to_owned(),
            id:       self.id().to_owned(),
        }
    }

    /// The machine as boxd has it now, or `None` once boxd no longer knows
    /// it.
    async fn fetch(&self) -> Result<Option<GetVmResponse>, Error> {
        ensure_open(&self.closed)?;
        fetch(&self.connection, self.id()).await
    }

    async fn phase(&self) -> Result<Phase, Error> {
        Ok(self
            .fetch()
            .await?
            .map_or(Phase::Destroyed, |vm| Phase::of(&vm.status)))
    }

    /// The running kernel's boot id, or `None` when it cannot be read.
    async fn boot_id(&self) -> Option<String> {
        let mut text = Vec::new();
        let mut read = self.read(BOOT_ID, None).await.ok()?;
        read.read_to_end(&mut text).await.ok()?;
        let id = String::from_utf8(text).ok()?.trim().to_owned();
        (!id.is_empty()).then_some(id)
    }

    /// Admits work only into a running machine, and returns the boot it
    /// was admitted into when that can be read. Nothing has been sent when
    /// this refuses.
    async fn admit(&self) -> Result<Option<String>, Error> {
        let (phase, boot) = tokio::join!(self.phase(), self.boot_id());
        match phase.map_err(not_started)? {
            Phase::Running => Ok(boot),
            Phase::Destroyed => Err(self.absent()),
            phase => Err(Error::Busy {
                message: format!("the machine is {:?}, not running", phase.state()),
            }),
        }
    }

    /// Waits for the machine to run, within the lifecycle budget.
    async fn until_running(&self) -> Result<(), Error> {
        let started = Instant::now();
        loop {
            match self.phase().await? {
                Phase::Running => return Ok(()),
                Phase::Destroyed | Phase::Destroying => return Err(self.absent()),
                Phase::Failed => {
                    return Err(Error::Unhealthy {
                        message: "boxd reports the machine failed".to_owned(),
                    });
                }
                _ if started.elapsed() > LIFECYCLE_BUDGET => {
                    return Err(Error::Unavailable {
                        message: "the machine did not reach running within the budget".to_owned(),
                        outcome: MutationOutcome::Unknown,
                    });
                }
                _ => time::sleep(POLL).await,
            }
        }
    }

    fn path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            self.directory.join(path).to_string_lossy().into_owned()
        }
    }

    /// Whether the boot a command was admitted into has ended: boxd reports
    /// the machine stopped or on its way back, or running a different
    /// kernel boot. Nothing else is taken as a stop.
    async fn boot_ended(&self, admitted: Option<&str>) -> bool {
        match self.phase().await {
            Ok(Phase::Stopped | Phase::Starting | Phase::Destroying | Phase::Destroyed) => true,
            Ok(Phase::Running) => match (admitted, self.boot_id().await) {
                (Some(admitted), Some(now)) => admitted != now,
                _ => false,
            },
            _ => false,
        }
    }

    async fn read(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error> {
        let path = self.path(path);
        let request = || FsReadRequest {
            vm_id:  self.id().to_owned(),
            path:   path.clone().into_bytes(),
            offset: range.map_or(0, |range| range.offset),
            length: range.and_then(|range| range.length),
        };
        let mut stream = self
            .connection
            .read(|| async {
                let request = self.connection.request(request()).await?;
                Ok(self.connection.api().fs_read(request).await)
            })
            .await?
            .map_err(|status| file_error("reading file", &path, &status))?
            .into_inner();
        // The first chunk carries the entry, or the failure: surface it here
        // rather than as a read error.
        let first = stream
            .message()
            .await
            .map_err(|status| file_error("reading file", &path, &status))?;
        let Some(first) = first else {
            return Err(Error::Transport {
                message: format!("reading file {path}: boxd sent nothing"),
                outcome: MutationOutcome::Unknown,
            });
        };
        let state = (Some(first), Some(stream));
        let chunks = stream::unfold(state, |(head, stream)| async move {
            if let Some(chunk) = head {
                let next = (!chunk.eof).then_some(stream).flatten();
                return Some((Ok(Cursor::new(chunk.data)), (None, next)));
            }
            let mut stream = stream?;
            match stream.message().await {
                Ok(Some(chunk)) => {
                    let next = (!chunk.eof).then_some(stream);
                    Some((Ok(Cursor::new(chunk.data)), (None, next)))
                }
                // A stream that ends before `eof` is a failed read, never a
                // shorter file.
                Ok(None) => Some((
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the read ended early",
                    )),
                    (None, None),
                )),
                Err(status) => Some((
                    Err(io::Error::other(status.message().to_owned())),
                    (None, None),
                )),
            }
        });
        Ok(Box::pin(StreamReader::new(chunks)))
    }
}

/// The machine `id`, or `None` once boxd no longer knows it.
pub(super) async fn fetch(
    connection: &Connection,
    id: &str,
) -> Result<Option<GetVmResponse>, Error> {
    let response = connection
        .read(|| async {
            let request = connection
                .unary(GetVmRequest {
                    vm_id: id.to_owned(),
                })
                .await?;
            Ok(connection.api().get_vm(request).await)
        })
        .await?;
    match response {
        Ok(response) => Ok(Some(response.into_inner())),
        Err(status) if not_found(&status) => Ok(None),
        Err(status) => Err(classify("fetching machine", &status)),
    }
}

fn not_started(error: Error) -> Error {
    match error {
        Error::Unavailable { message, .. } => Error::Unavailable {
            message,
            outcome: MutationOutcome::NotStarted,
        },
        Error::Transport { message, .. } => Error::Transport {
            message,
            outcome: MutationOutcome::NotStarted,
        },
        error => error,
    }
}

fn file_error(operation: &str, path: &str, status: &tonic::Status) -> Error {
    if not_found(status) {
        Error::NotFound {
            resource: "file".to_owned(),
            id:       path.to_owned(),
        }
    } else {
        classify(operation, status)
    }
}

fn outcome(termination: Termination, exit_code: Option<i32>) -> ExecOutcome {
    ExecOutcome {
        termination,
        exit_code,
        signal: None,
        output_loss: OutputLoss::default(),
    }
}

/// A failure boxd reported for the command itself before it ran: the
/// command was refused, not lost.
fn rejected(status: &tonic::Status) -> Option<Error> {
    match status.code() {
        Code::InvalidArgument
        | Code::PermissionDenied
        | Code::Unauthenticated
        | Code::ResourceExhausted
        | Code::FailedPrecondition => Some(classify("running command", status)),
        _ => None,
    }
}

/// What boxd says the machine has, in the contract's units.
pub(super) fn resources(vm: &GetVmResponse) -> Resources {
    Resources {
        cpu_cores: NonZeroU32::new(vm.vcpu),
        memory_mb: NonZeroU64::new(vm.memory_bytes / MIB),
        disk_mb:   NonZeroU64::new(vm.disk_bytes / MIB).or(NonZeroU64::new(DISK_MIB)),
        gpus:      None,
    }
}

#[async_trait]
impl Sandbox for Machine {
    fn reference(&self) -> SandboxRef {
        self.reference.clone()
    }

    fn working_directory(&self) -> &Path {
        &self.directory
    }

    fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    async fn status(&self) -> Result<Status, Error> {
        let Some(vm) = self.fetch().await? else {
            return Ok(Status {
                reference: self.reference(),
                state:     SandboxState::Deleted,
                name:      None,
                labels:    BTreeMap::new(),
                image:     None,
                snapshot:  None,
                resources: Resources::default(),
                network:   None,
                services:  BTreeMap::new(),
                web_url:   None,
            });
        };
        let stored: BTreeMap<String, String> = vm.labels.clone().into_iter().collect();
        Ok(Status {
            reference: self.reference(),
            state:     Phase::of(&vm.status).state(),
            name:      Some(vm.name.clone()),
            labels:    labels::caller_labels(&stored),
            image:     (!vm.image_ref.is_empty()).then(|| vm.image_ref.clone()),
            snapshot:  None,
            resources: resources(&vm),
            network:   Some(spec::network(&vm.egress_allow)),
            services:  BTreeMap::new(),
            web_url:   (!vm.access_domain.is_empty())
                .then(|| format!("https://{}.{}", vm.name, vm.access_domain)),
        })
    }

    #[tracing::instrument(skip_all, fields(sandbox_id = %self.reference.id), err)]
    async fn start(&self) -> Result<(), Error> {
        let vm_id = self.id().to_owned();
        let mut api = self.connection.api();
        let result = match self.phase().await.map_err(not_started)? {
            Phase::Running => return Ok(()),
            Phase::Pending | Phase::Starting => return self.until_running().await,
            Phase::Hibernating => {
                return Err(Error::Busy {
                    message: "the machine is still hibernating".to_owned(),
                });
            }
            Phase::Destroying | Phase::Destroyed => return Err(self.absent()),
            Phase::Asleep { hibernated: false } => api
                .resume_vm(self.connection.unary(ResumeVmRequest { vm_id }).await?)
                .await
                .map(drop),
            Phase::Asleep { hibernated: true } => api
                .wake_vm(self.connection.unary(WakeVmRequest { vm_id }).await?)
                .await
                .map(drop),
            Phase::Stopped | Phase::Failed | Phase::Other => api
                .start_vm(self.connection.unary(StartVmRequest { vm_id }).await?)
                .await
                .map(drop),
        };
        match result {
            Ok(()) => self.until_running().await,
            Err(status) if not_found(&status) => Err(self.absent()),
            Err(status) => Err(classify("starting machine", &status)),
        }
    }

    #[tracing::instrument(skip_all, fields(sandbox_id = %self.reference.id), err)]
    async fn stop(&self) -> Result<(), Error> {
        match self.phase().await.map_err(not_started)? {
            Phase::Stopped => return Ok(()),
            Phase::Destroyed => return Err(self.absent()),
            _ => {}
        }
        let request = self
            .connection
            .unary(StopVmRequest {
                vm_id: self.id().to_owned(),
            })
            .await?;
        let stopped = self.connection.api().stop_vm(request).await;
        if let Err(status) = &stopped {
            if not_found(status) {
                return Err(self.absent());
            }
            let error = classify("stopping machine", status);
            if refused(&error) {
                return Err(error);
            }
        }
        // Success is boxd's report that the machine is stopped, read after
        // the request: an accepted stop alone is not a fence.
        let started = Instant::now();
        let phase = loop {
            match self.phase().await? {
                Phase::Stopped => return Ok(()),
                Phase::Destroyed => return Err(self.absent()),
                phase if started.elapsed() > LIFECYCLE_BUDGET => break phase,
                _ => time::sleep(POLL).await,
            }
        };
        Err(Error::FenceLeaked {
            message: match stopped {
                Ok(_) => format!("the machine is {:?} after stop", phase.state()),
                Err(status) => classify("stopping machine", &status).to_string(),
            },
        })
    }

    async fn exec(&self, spec: ExecSpec, controls: ExecControls) -> Result<ExecOutcome, Error> {
        spec.validate()?;
        if spec.tty {
            return Err(Error::Unsupported {
                capability: "tty".to_owned(),
            });
        }
        let ExecControls {
            stdin,
            sink,
            term,
            kill,
            resize: _,
        } = controls;
        // Admission first, so a refused command consumes none of its input.
        let admitted = self.admit().await?;
        let directory = spec.working_directory.as_deref().map_or_else(
            || self.directory.to_string_lossy().into_owned(),
            |dir| self.path(dir),
        );
        let mut env = self.env.clone();
        env.extend(spec.env);
        let command = Command::new(
            self.id(),
            &directory,
            &env,
            &spec.argv,
            spec.timeout_ms.map(Duration::from_millis),
        );
        let controls = Controls {
            stdin,
            sink,
            term,
            kill,
            closed: self.closed.clone(),
        };
        let status = match exec::run(&self.connection, command, controls).await? {
            Ended::Exited(code) => return Ok(outcome(Termination::Exited, Some(code))),
            Ended::Stopped(termination) => return Ok(outcome(termination, None)),
            Ended::Unconfirmed => None,
            Ended::Broken(status) => status,
        };
        if self.boot_ended(admitted.as_deref()).await {
            return Ok(outcome(Termination::Killed, None));
        }
        if let Some(error) = status.as_ref().and_then(rejected) {
            return Err(error);
        }
        tracing::warn!(
            code = ?status.as_ref().map(tonic::Status::code),
            "boxd command outcome unknown"
        );
        Ok(outcome(Termination::Lost, None))
    }

    fn files(&self) -> &dyn Files {
        self
    }

    fn ports(&self) -> &dyn Ports {
        self
    }

    fn endpoints(&self) -> Option<&dyn Endpoints> {
        Some(self)
    }
}

#[async_trait]
impl Files for Machine {
    async fn get(&self, path: &str, range: Option<FileRange>) -> Result<ByteStream, Error> {
        ensure_open(&self.closed)?;
        self.read(path, range).await
    }

    async fn put(&self, path: &str, bytes: ByteStream) -> Result<(), Error> {
        // Admission first, so a refused write does not drain the caller's
        // stream. The write still fails if a stop wins the race.
        self.admit().await?;
        let path = self.path(path);
        let (sender, receiver) = mpsc::channel::<FsWriteChunk>(2);
        let request = self.connection.request(requests(receiver)).await?;
        let mut api = self.connection.api();
        let call = api.fs_write(request);
        tokio::pin!(call);
        let machine = self.id().to_owned();
        let pump = async move {
            let mut bytes = bytes;
            let mut first = Some((machine, path.into_bytes()));
            loop {
                let mut buffer = Vec::with_capacity(WRITE_CHUNK);
                let read = (&mut bytes)
                    .take(WRITE_CHUNK as u64)
                    .read_to_end(&mut buffer)
                    .await
                    .map_err(|_| Error::Transport {
                        message: "reading file input failed".to_owned(),
                        outcome: MutationOutcome::Unknown,
                    })?;
                // The first message names the file even for empty content.
                if read == 0 && first.is_none() {
                    return Ok::<(), Error>(());
                }
                let (vm_id, path) = first.take().unwrap_or_default();
                let chunk = FsWriteChunk {
                    vm_id,
                    path,
                    data: buffer,
                    ..FsWriteChunk::default()
                };
                if sender.send(chunk).await.is_err() || read == 0 {
                    return Ok(());
                }
            }
        };
        tokio::pin!(pump);
        let mut pumped = false;
        let response = loop {
            tokio::select! {
                biased;
                // A failed read cancels the call by dropping it; boxd then
                // keeps the file as it was rather than a truncated one.
                result = &mut pump, if !pumped => {
                    result?;
                    pumped = true;
                }
                response = &mut call => break response,
            }
        };
        response
            .map(drop)
            .map_err(|status| classify("writing file", &status))
    }

    async fn list(&self, path: &str, depth: u32) -> Result<Vec<FileEntry>, Error> {
        ensure_open(&self.closed)?;
        let mut entries = Vec::new();
        let mut pending = vec![(self.path(path), 0)];
        while let Some((directory, level)) = pending.pop() {
            let request = || FsListRequest {
                vm_id: self.id().to_owned(),
                path:  directory.clone().into_bytes(),
            };
            let chunks: Vec<_> = self
                .connection
                .read(|| async {
                    let request = self.connection.request(request()).await?;
                    Ok(self.connection.api().fs_list(request).await)
                })
                .await?
                .map_err(|status| file_error("listing directory", &directory, &status))?
                .into_inner()
                .try_collect()
                .await
                .map_err(|status| file_error("listing directory", &directory, &status))?;
            for entry in chunks.into_iter().flat_map(|chunk| chunk.entries) {
                let name = String::from_utf8_lossy(&entry.name).into_owned();
                let path = if entry.path.is_empty() {
                    format!("{}/{name}", directory.trim_end_matches('/'))
                } else {
                    String::from_utf8_lossy(&entry.path).into_owned()
                };
                let kind = match FsEntryType::try_from(entry.r#type) {
                    Ok(FsEntryType::File) => FileKind::File,
                    Ok(FsEntryType::Directory) => FileKind::Directory,
                    Ok(FsEntryType::Symlink) => FileKind::Symlink,
                    _ => FileKind::Other,
                };
                if kind == FileKind::Directory && level < depth {
                    pending.push((path.clone(), level + 1));
                }
                entries.push(FileEntry {
                    path,
                    kind,
                    size: entry.size,
                });
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }
}

/// The subdomain proxy name for a port.
fn proxy_name(port: NonZeroU16) -> String {
    format!("p{port}")
}

#[async_trait]
impl Ports for Machine {
    async fn expose(&self, port: NonZeroU16, options: Expose) -> Result<Exposure, Error> {
        ensure_open(&self.closed)?;
        // boxd proxies are public URLs; there is no signed form to offer.
        if options.signed {
            return Err(Error::Unsupported {
                capability: "ports.signed".to_owned(),
            });
        }
        let name = proxy_name(port);
        let request = CreateProxyRequest {
            name: name.clone(),
            port: u32::from(port.get()),
            vm: self.id().to_owned(),
            ..CreateProxyRequest::default()
        };
        let domain = match self
            .connection
            .api()
            .create_proxy(self.connection.unary(request).await?)
            .await
        {
            Ok(response) => response.into_inner().domain,
            // Exposing a port twice returns the proxy that already exists.
            Err(status) if status.code() == Code::AlreadyExists => {
                let request = ListProxiesRequest {
                    vm: self.id().to_owned(),
                    ..ListProxiesRequest::default()
                };
                self.connection
                    .api()
                    .list_proxies(self.connection.unary(request).await?)
                    .await
                    .map_err(|status| classify("listing proxies", &status))?
                    .into_inner()
                    .proxies
                    .into_iter()
                    .find(|proxy| proxy.name == name && proxy.port == u32::from(port.get()))
                    .map(|proxy| proxy.domain)
                    .ok_or_else(|| classify("exposing port", &status))?
            }
            Err(status) if not_found(&status) => return Err(self.absent()),
            Err(status) => return Err(classify("exposing port", &status)),
        };
        Ok(Exposure {
            url:           format!("https://{domain}"),
            headers:       BTreeMap::new(),
            expires_at_ms: None,
        })
    }

    async fn release(&self, port: NonZeroU16) -> Result<(), Error> {
        ensure_open(&self.closed)?;
        let request = DeleteProxyRequest {
            name: proxy_name(port),
            vm: self.id().to_owned(),
            ..DeleteProxyRequest::default()
        };
        match self
            .connection
            .api()
            .delete_proxy(self.connection.unary(request).await?)
            .await
        {
            Ok(_) => Ok(()),
            Err(status) if not_found(&status) => Ok(()),
            Err(status) => Err(classify("releasing port", &status)),
        }
    }
}

#[async_trait]
impl Endpoints for Machine {
    async fn ssh(&self, _ttl_ms: u64) -> Result<SshAccessInfo, Error> {
        Err(Error::Unsupported {
            capability: "endpoints.ssh".to_owned(),
        })
    }

    async fn ssh_revoke(&self, _token: &str) -> Result<(), Error> {
        Err(Error::Unsupported {
            capability: "endpoints.ssh".to_owned(),
        })
    }

    /// An interactive shell through the operator's own boxd CLI login.
    async fn shell_command(&self) -> Result<String, Error> {
        ensure_open(&self.closed)?;
        Ok(format!("boxd machine connect {}", exec::quote(&self.name)))
    }

    async fn vnc(&self) -> Result<VncConnection, Error> {
        Err(Error::Unsupported {
            capability: "endpoints.vnc".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boxd_states_map_to_the_contract_and_sleep_reads_as_paused() {
        assert_eq!(Phase::of("running").state(), SandboxState::Running);
        assert_eq!(Phase::of("suspended").state(), SandboxState::Paused);
        assert_eq!(Phase::of("hibernated").state(), SandboxState::Paused);
        assert_eq!(Phase::of("pending").state(), SandboxState::Creating);
        assert_eq!(Phase::of("failed").state(), SandboxState::Unhealthy);
        assert_eq!(Phase::of("something-new").state(), SandboxState::Unknown);
    }
}
