//! An in-process boxd for unit tests. It answers the token exchange over
//! HTTP and the calls the provider makes over gRPC, and runs every machine
//! on this host: a command is `sh -c` in its own process group, in a
//! temporary home directory, and files are the host's files. Stopping a
//! machine kills its process groups and changes its boot id, as a real
//! stop does, so the shared conformance suite runs against it unchanged.
//! Every call is recorded by method name.

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use std::{env, fs, mem, process};

use futures_util::{Stream, stream};
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time;
use tonic::{Request, Response, Status, Streaming};

use super::api::server::boxd_api_server::{BoxdApi, BoxdApiServer};
use super::api::*;
use super::connection::requests;

type Replies<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// How the fake misbehaves, when a test asks it to.
#[derive(Clone, Copy, Default)]
pub(super) struct Faults {
    /// `SetVmEgressAllow` refuses its entries.
    pub(super) refuse_egress: bool,
    /// `DestroyVm` fails, leaving the machine in place.
    pub(super) fail_destroy:  bool,
}

struct Vm {
    info:   GetVmResponse,
    home:   PathBuf,
    boot:   u32,
    groups: Vec<i32>,
}

#[derive(Default)]
struct State {
    machines: HashMap<String, Vm>,
    calls:    Vec<&'static str>,
    created:  u32,
    root:     PathBuf,
}

impl State {
    fn find(&mut self, id: &str) -> Result<&mut Vm, Status> {
        self.machines
            .values_mut()
            .find(|vm| vm.info.vm_id == id || vm.info.name == id)
            .ok_or_else(|| Status::not_found("VM not found (region fra)"))
    }

    fn running(&mut self, id: &str) -> Result<&mut Vm, Status> {
        let vm = self.find(id)?;
        if vm.info.status == "running" {
            Ok(vm)
        } else {
            Err(Status::failed_precondition(format!(
                "VM {} is {}",
                vm.info.name, vm.info.status
            )))
        }
    }
}

#[derive(Clone)]
struct Service {
    state:  Arc<Mutex<State>>,
    faults: Faults,
}

pub(super) struct FakeBoxd {
    state: Arc<Mutex<State>>,
    grpc:  SocketAddr,
    auth:  SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for FakeBoxd {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let state = self.state.lock().expect("state");
        for vm in state.machines.values() {
            kill(&vm.groups);
        }
        let _ = fs::remove_dir_all(&state.root);
    }
}

fn kill(groups: &[i32]) {
    for group in groups {
        let _ = killpg(Pid::from_raw(*group), Signal::SIGKILL);
    }
}

impl FakeBoxd {
    pub(super) async fn start(faults: Faults) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = env::temp_dir().join(format!(
            "sandbox-driver-boxd-fake-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).expect("fake root");
        let state = Arc::new(Mutex::new(State {
            root,
            ..State::default()
        }));
        let service = BoxdApiServer::new(Service {
            state: Arc::clone(&state),
            faults,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gRPC");
        let grpc = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let service = TowerToHyperService::new(service.clone());
                connections.spawn(async move {
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind auth");
        let auth = listener.local_addr().expect("address");
        let exchange = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = vec![0; 4096];
                let read = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let (status, body) = if request.contains("bxd_good") {
                    (
                        "200 OK",
                        r#"{"token":"jwt","expires_at":4102444800,"user_id":"u"}"#,
                    )
                } else {
                    ("401 Unauthorized", r#"{"error":"bad key"}"#)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        Self {
            state,
            grpc,
            auth,
            tasks: vec![server, exchange],
        }
    }

    pub(super) fn api_url(&self) -> String {
        format!("http://{}", self.grpc)
    }

    pub(super) fn auth_url(&self) -> String {
        format!("http://{}/api/v1/auth/token", self.auth)
    }

    pub(super) fn calls(&self) -> Vec<&'static str> {
        self.state.lock().expect("state").calls.clone()
    }

    /// Adds a machine as another tool would have made it.
    pub(super) fn insert(&self, info: GetVmResponse) {
        let mut state = self.state.lock().expect("state");
        let home = state.root.join(&info.vm_id);
        state.machines.insert(info.vm_id.clone(), Vm {
            info,
            home,
            boot: 0,
            groups: Vec::new(),
        });
    }

    pub(super) fn machine(&self, id: &str) -> Option<GetVmResponse> {
        let state = self.state.lock().expect("state");
        state.machines.get(id).map(|vm| vm.info.clone())
    }
}

fn io_status(error: &io::Error, path: &Path) -> Status {
    let message = format!("{}: {error}", path.display());
    match error.kind() {
        ErrorKind::NotFound => Status::not_found(message),
        ErrorKind::PermissionDenied => Status::permission_denied(message),
        _ => Status::internal(message),
    }
}

fn path_of(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

impl Service {
    fn record(&self, call: &'static str) -> MutexGuard<'_, State> {
        let mut state = self.state.lock().expect("state");
        state.calls.push(call);
        state
    }

    fn create(
        &self,
        call: &'static str,
        name: String,
        labels: HashMap<String, String>,
    ) -> Result<CreateVmResponse, Status> {
        let mut state = self.record(call);
        state.created += 1;
        let vm_id = format!("vm-{}", state.created);
        let name = if name.is_empty() { vm_id.clone() } else { name };
        let home = state.root.join(&vm_id);
        fs::create_dir_all(&home).map_err(|error| io_status(&error, &home))?;
        let info = GetVmResponse {
            vm_id: vm_id.clone(),
            name: name.clone(),
            status: "running".to_owned(),
            labels,
            vcpu: 1,
            memory_bytes: 4 << 30,
            access_domain: "boxd.sh".to_owned(),
            ..GetVmResponse::default()
        };
        state.machines.insert(vm_id.clone(), Vm {
            info: info.clone(),
            home,
            boot: 0,
            groups: Vec::new(),
        });
        Ok(CreateVmResponse {
            vm_id,
            name,
            status: "running".to_owned(),
            machine: Some(info),
            ..CreateVmResponse::default()
        })
    }

    fn set_status(&self, call: &'static str, id: &str, status: &str) -> Result<(), Status> {
        let mut state = self.record(call);
        let vm = state.find(id)?;
        status.clone_into(&mut vm.info.status);
        Ok(())
    }

    /// Kills every process the machine runs and waits for them to go, as a
    /// real stop ends the machine's kernel.
    async fn halt(&self, call: &'static str, id: &str) -> Result<(), Status> {
        let groups = {
            let mut state = self.record(call);
            let vm = state.find(id)?;
            vm.info.status = "stopped".to_owned();
            vm.boot += 1;
            mem::take(&mut vm.groups)
        };
        kill(&groups);
        for _ in 0..100 {
            let alive = groups
                .iter()
                .any(|group| killpg(Pid::from_raw(*group), None).is_ok());
            if !alive {
                break;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }

    /// Relays one command: stdin in, output out, then its exit code, or a
    /// broken stream when its machine stopped under it. A cancelled call
    /// kills the command's process group, as boxd's agent does.
    async fn relay(
        state: Arc<Mutex<State>>,
        machine: String,
        boot: u32,
        mut child: Child,
        mut inbound: Streaming<ExecChunk>,
        replies: mpsc::Sender<Result<ExecChunk, Status>>,
    ) {
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .unwrap_or(0);
        // Input is written apart from the output loop, as a real agent
        // does: a command that answers as it reads would otherwise block
        // on full pipes in both directions.
        let stdin = child.stdin.take();
        let feeder = tokio::spawn(async move {
            let mut stdin = stdin;
            while let Ok(Some(chunk)) = inbound.message().await {
                if let Some(input) = stdin.as_mut() {
                    if input.write_all(&chunk.data).await.is_err() {
                        stdin = None;
                    }
                }
            }
        });
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let (mut out, mut err) = (vec![0; 8192], vec![0; 8192]);
        let (mut out_open, mut err_open) = (true, true);
        let send = |data: Vec<u8>, is_stderr| ExecChunk {
            data,
            is_stderr,
            ..ExecChunk::default()
        };
        let exit = loop {
            tokio::select! {
                () = replies.closed() => {
                    feeder.abort();
                    kill(&[group]);
                    return;
                }
                read = stdout.read(&mut out), if out_open => match read {
                    Ok(0) | Err(_) => out_open = false,
                    Ok(n) => { let _ = replies.send(Ok(send(out[..n].to_vec(), false))).await; }
                },
                read = stderr.read(&mut err), if err_open => match read {
                    Ok(0) | Err(_) => err_open = false,
                    Ok(n) => { let _ = replies.send(Ok(send(err[..n].to_vec(), true))).await; }
                },
                exit = child.wait(), if !out_open && !err_open => break exit,
            }
        };
        feeder.abort();
        let stopped = {
            let mut state = state.lock().expect("state");
            match state.find(&machine) {
                Ok(vm) => {
                    vm.groups.retain(|g| *g != group);
                    vm.boot != boot
                }
                Err(_) => true,
            }
        };
        let reply = if stopped {
            Err(Status::unavailable(
                "lost the connection to the machine during exec: the machine was stopped or rebooted",
            ))
        } else {
            let code = exit.ok().and_then(|exit| {
                exit.code()
                    .or_else(|| exit.signal().map(|signal| 128 + signal))
            });
            Ok(ExecChunk {
                exit_code: code.unwrap_or(-1),
                ..ExecChunk::default()
            })
        };
        let _ = replies.send(reply).await;
    }
}

fn replies<T: Send + 'static>(items: Vec<Result<T, Status>>) -> Replies<T> {
    Box::pin(stream::iter(items))
}

#[tonic::async_trait]
impl BoxdApi for Service {
    type ExecStream = Replies<ExecChunk>;
    type FsListStream = Replies<FsListChunk>;
    type FsReadStream = Replies<FsReadChunk>;

    async fn create_vm(
        &self,
        request: Request<CreateVmRequest>,
    ) -> Result<Response<CreateVmResponse>, Status> {
        let request = request.into_inner();
        self.create("CreateVm", request.name, request.labels)
            .map(Response::new)
    }

    async fn create_vm_from_snapshot(
        &self,
        request: Request<CreateVmFromSnapshotRequest>,
    ) -> Result<Response<CreateVmResponse>, Status> {
        let request = request.into_inner();
        self.create("CreateVmFromSnapshot", request.name, request.labels)
            .map(Response::new)
    }

    async fn destroy_vm(
        &self,
        request: Request<DestroyVmRequest>,
    ) -> Result<Response<DestroyVmResponse>, Status> {
        let id = request.into_inner().vm_id;
        if self.faults.fail_destroy {
            drop(self.record("DestroyVm"));
            return Err(Status::internal("the worker is unreachable"));
        }
        self.halt("DestroyVm", &id).await?;
        let mut state = self.state.lock().expect("state");
        let key = state.find(&id)?.info.vm_id.clone();
        if let Some(vm) = state.machines.remove(&key) {
            let _ = fs::remove_dir_all(vm.home);
        }
        Ok(Response::new(DestroyVmResponse {}))
    }

    async fn get_vm(
        &self,
        request: Request<GetVmRequest>,
    ) -> Result<Response<GetVmResponse>, Status> {
        let id = request.into_inner().vm_id;
        let mut state = self.record("GetVm");
        Ok(Response::new(state.find(&id)?.info.clone()))
    }

    async fn list_vms(
        &self,
        request: Request<ListVmsRequest>,
    ) -> Result<Response<ListVmsResponse>, Status> {
        let selectors = request.into_inner().label_selector;
        let state = self.record("ListVms");
        let vms = state
            .machines
            .values()
            .map(|vm| &vm.info)
            .filter(|vm| {
                selectors.iter().all(|selector| {
                    let (key, value) = selector.split_once('=').unwrap_or((selector, ""));
                    vm.labels.get(key).is_some_and(|v| v == value)
                })
            })
            .cloned()
            .collect();
        Ok(Response::new(ListVmsResponse {
            vms,
            ..ListVmsResponse::default()
        }))
    }

    async fn start_vm(
        &self,
        request: Request<StartVmRequest>,
    ) -> Result<Response<StartVmResponse>, Status> {
        self.set_status("StartVm", &request.into_inner().vm_id, "running")?;
        Ok(Response::new(StartVmResponse {}))
    }

    async fn stop_vm(
        &self,
        request: Request<StopVmRequest>,
    ) -> Result<Response<StopVmResponse>, Status> {
        self.halt("StopVm", &request.into_inner().vm_id).await?;
        Ok(Response::new(StopVmResponse {}))
    }

    async fn resume_vm(
        &self,
        request: Request<ResumeVmRequest>,
    ) -> Result<Response<ResumeVmResponse>, Status> {
        self.set_status("ResumeVm", &request.into_inner().vm_id, "running")?;
        Ok(Response::new(ResumeVmResponse::default()))
    }

    async fn wake_vm(
        &self,
        request: Request<WakeVmRequest>,
    ) -> Result<Response<WakeVmResponse>, Status> {
        self.set_status("WakeVm", &request.into_inner().vm_id, "running")?;
        Ok(Response::new(WakeVmResponse {}))
    }

    async fn set_vm_egress_allow(
        &self,
        request: Request<SetVmEgressAllowRequest>,
    ) -> Result<Response<SetVmEgressAllowResponse>, Status> {
        let request = request.into_inner();
        let mut state = self.record("SetVmEgressAllow");
        if self.faults.refuse_egress {
            return Err(Status::invalid_argument(
                "10.0.0.0/8 is not a public address",
            ));
        }
        state.find(&request.vm)?.info.egress_allow = request.entries.clone();
        Ok(Response::new(SetVmEgressAllowResponse {
            entries: request.entries,
        }))
    }

    async fn update_vm_labels(
        &self,
        request: Request<UpdateVmLabelsRequest>,
    ) -> Result<Response<UpdateVmLabelsResponse>, Status> {
        let request = request.into_inner();
        let mut state = self.record("UpdateVmLabels");
        let vm = state.find(&request.vm)?;
        if request.replace_all {
            vm.info.labels = request.set;
        } else {
            vm.info.labels.extend(request.set);
        }
        Ok(Response::new(UpdateVmLabelsResponse {
            labels: vm.info.labels.clone(),
        }))
    }

    async fn exec(
        &self,
        request: Request<Streaming<ExecChunk>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("no command"))?;
        let (home, boot) = {
            let mut state = self.record("Exec");
            let vm = state.running(&first.vm_id)?;
            (vm.home.clone(), vm.boot)
        };
        let child = Command::new("sh")
            .args(["-c", &first.command])
            .current_dir(&home)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| io_status(&error, &home))?;
        if let Some(group) = child.id().and_then(|id| i32::try_from(id).ok()) {
            let mut state = self.state.lock().expect("state");
            state.find(&first.vm_id)?.groups.push(group);
        }
        let (sender, receiver) = mpsc::channel(16);
        tokio::spawn(Self::relay(
            Arc::clone(&self.state),
            first.vm_id,
            boot,
            child,
            inbound,
            sender,
        ));
        Ok(Response::new(Box::pin(requests(receiver))))
    }

    async fn fs_read(
        &self,
        request: Request<FsReadRequest>,
    ) -> Result<Response<Self::FsReadStream>, Status> {
        let request = request.into_inner();
        let boot = {
            let mut state = self.record("FsRead");
            state.running(&request.vm_id)?.boot
        };
        let path = path_of(&request.path);
        let bytes = if path == Path::new(BOOT_ID) {
            format!("fake-boot-{boot}\n").into_bytes()
        } else {
            fs::read(&path).map_err(|error| io_status(&error, &path))?
        };
        let start = usize::try_from(request.offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let end = request.length.map_or(bytes.len(), |length| {
            start
                .saturating_add(usize::try_from(length).unwrap_or(usize::MAX))
                .min(bytes.len())
        });
        let data = bytes[start..end].to_vec();
        Ok(Response::new(replies(vec![Ok(FsReadChunk {
            bytes_read: data.len() as u64,
            data,
            eof: true,
            ..FsReadChunk::default()
        })])))
    }

    async fn fs_write(
        &self,
        request: Request<Streaming<FsWriteChunk>>,
    ) -> Result<Response<FsWriteResponse>, Status> {
        let mut inbound = request.into_inner();
        let mut first: Option<FsWriteChunk> = None;
        let mut data = Vec::new();
        // A stream that fails part way writes nothing, as boxd keeps the
        // file as it was.
        while let Some(chunk) = inbound.message().await? {
            data.extend_from_slice(&chunk.data);
            first.get_or_insert(chunk);
        }
        let first = first.ok_or_else(|| Status::invalid_argument("no file named"))?;
        self.record("FsWrite").running(&first.vm_id)?;
        let path = path_of(&first.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| io_status(&error, parent))?;
        }
        fs::write(&path, &data).map_err(|error| io_status(&error, &path))?;
        Ok(Response::new(FsWriteResponse {
            bytes_written: data.len() as u64,
            ..FsWriteResponse::default()
        }))
    }

    async fn fs_list(
        &self,
        request: Request<FsListRequest>,
    ) -> Result<Response<Self::FsListStream>, Status> {
        let request = request.into_inner();
        self.record("FsList").running(&request.vm_id)?;
        let path = path_of(&request.path);
        let mut entries = Vec::new();
        for entry in fs::read_dir(&path).map_err(|error| io_status(&error, &path))? {
            let entry = entry.map_err(|error| io_status(&error, &path))?;
            let metadata = entry.metadata().map_err(|error| io_status(&error, &path))?;
            let kind = if metadata.is_dir() {
                FsEntryType::Directory
            } else if metadata.is_file() {
                FsEntryType::File
            } else if metadata.is_symlink() {
                FsEntryType::Symlink
            } else {
                FsEntryType::Other
            };
            entries.push(FsEntry {
                name: entry.file_name().to_string_lossy().as_bytes().to_vec(),
                path: entry.path().to_string_lossy().as_bytes().to_vec(),
                r#type: kind.into(),
                size: metadata.len(),
                ..FsEntry::default()
            });
        }
        Ok(Response::new(replies(vec![Ok(FsListChunk { entries })])))
    }

    async fn fs_mkdir(
        &self,
        request: Request<FsMkdirRequest>,
    ) -> Result<Response<FsMkdirResponse>, Status> {
        let request = request.into_inner();
        self.record("FsMkdir").running(&request.vm_id)?;
        let path = path_of(&request.path);
        fs::create_dir_all(&path).map_err(|error| io_status(&error, &path))?;
        Ok(Response::new(FsMkdirResponse::default()))
    }

    async fn fs_realpath(
        &self,
        request: Request<FsRealpathRequest>,
    ) -> Result<Response<FsRealpathResponse>, Status> {
        let request = request.into_inner();
        let mut state = self.record("FsRealpath");
        let home = state.running(&request.vm_id)?.home.clone();
        Ok(Response::new(FsRealpathResponse {
            path: home.to_string_lossy().as_bytes().to_vec(),
        }))
    }

    async fn create_proxy(
        &self,
        request: Request<CreateProxyRequest>,
    ) -> Result<Response<CreateProxyResponse>, Status> {
        let request = request.into_inner();
        let mut state = self.record("CreateProxy");
        let name = state.find(&request.vm)?.info.name.clone();
        Ok(Response::new(CreateProxyResponse {
            domain: format!("{}.{name}.boxd.sh", request.name),
            name: request.name,
            port: request.port,
            ..CreateProxyResponse::default()
        }))
    }

    async fn delete_proxy(
        &self,
        _request: Request<DeleteProxyRequest>,
    ) -> Result<Response<DeleteProxyResponse>, Status> {
        drop(self.record("DeleteProxy"));
        Err(Status::not_found("no such proxy"))
    }

    async fn list_proxies(
        &self,
        _request: Request<ListProxiesRequest>,
    ) -> Result<Response<ListProxiesResponse>, Status> {
        drop(self.record("ListProxies"));
        Ok(Response::new(ListProxiesResponse::default()))
    }

    async fn list_orgs(
        &self,
        _request: Request<ListOrgsRequest>,
    ) -> Result<Response<ListOrgsResponse>, Status> {
        drop(self.record("ListOrgs"));
        Ok(Response::new(ListOrgsResponse {
            orgs:           vec![OrgSummary {
                id: "org-1".to_owned(),
                name: "Acme".to_owned(),
                slug: "acme".to_owned(),
                ..OrgSummary::default()
            }],
            default_org_id: "org-1".to_owned(),
        }))
    }

    async fn list_regions(
        &self,
        _request: Request<ListRegionsRequest>,
    ) -> Result<Response<ListRegionsResponse>, Status> {
        drop(self.record("ListRegions"));
        Ok(Response::new(ListRegionsResponse {
            regions:     Vec::new(),
            org_id:      "org-1".to_owned(),
            this_region: "fra".to_owned(),
        }))
    }

    async fn whoami(
        &self,
        _request: Request<WhoamiRequest>,
    ) -> Result<Response<WhoamiResponse>, Status> {
        drop(self.record("Whoami"));
        Ok(Response::new(WhoamiResponse::default()))
    }

    async fn create_snapshot(
        &self,
        _request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        Err(Status::unimplemented("snapshots"))
    }

    async fn delete_snapshot(
        &self,
        _request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        Err(Status::unimplemented("snapshots"))
    }

    async fn suspend_vm(
        &self,
        request: Request<SuspendVmRequest>,
    ) -> Result<Response<SuspendVmResponse>, Status> {
        self.set_status("SuspendVm", &request.into_inner().vm_id, "suspended")?;
        Ok(Response::new(SuspendVmResponse::default()))
    }

    async fn hibernate_vm(
        &self,
        request: Request<HibernateVmRequest>,
    ) -> Result<Response<HibernateVmResponse>, Status> {
        self.set_status("HibernateVm", &request.into_inner().vm_id, "hibernated")?;
        Ok(Response::new(HibernateVmResponse {}))
    }
}
