use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Error, Exec, Filesystem, Isolation, PlatformInfo, Result, Sandbox, SandboxId,
    SandboxState, SandboxStatus, Search, TransportError,
};

use crate::exec::ScriptedExec;
use crate::fs::MemoryFs;
use crate::search::ScriptedSearch;

/// A [`Sandbox`] double: scripted exec, in-memory files, canned search,
/// counted lifecycle calls.
///
/// Built with [`ScriptedSandbox::new`] and the builder methods, then
/// driven through the trait. The doubles behind the facets are reachable
/// through [`ScriptedSandbox::scripted_exec`], [`ScriptedSandbox::memory_fs`],
/// and [`ScriptedSandbox::scripted_search`] for scripting and assertions.
///
/// Capabilities default to a stop-capable exec with stdin, streamed
/// stdin, and stdio processes, native search (walks and globs over the
/// memory filesystem, canned grep), and derived git (over the scripted
/// exec). Every optional lifecycle
/// operation stays unsupported unless the test sets capabilities that
/// declare it — the doubles only count `start`, `stop`, and `delete`.
pub struct ScriptedSandbox {
    id:           SandboxId,
    capabilities: Capabilities,
    working_dir:  String,
    runtime_dir:  Option<String>,
    platform:     PlatformInfo,
    labels:       BTreeMap<String, String>,
    state:        Mutex<SandboxState>,
    start_error:  Option<String>,
    exec:         ScriptedExec,
    fs:           Arc<MemoryFs>,
    search:       ScriptedSearch,
    starts:       AtomicU32,
    stops:        AtomicU32,
    deletes:      AtomicU32,
}

impl Default for ScriptedSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedSandbox {
    /// A running Linux sandbox with id `scripted-1` and working directory
    /// `/work`.
    pub fn new() -> Self {
        Self::with_id_and_working_dir("scripted-1", "/work")
    }

    pub fn with_id_and_working_dir(id: &str, working_dir: &str) -> Self {
        let fs = Arc::new(MemoryFs::new(working_dir));
        Self {
            id:           SandboxId::try_new(id).expect("scripted sandbox id is valid"),
            capabilities: Self::default_capabilities(),
            working_dir:  working_dir.to_owned(),
            runtime_dir:  None,
            platform:     PlatformInfo::new("linux", "x86_64", "6.0.0-scripted"),
            labels:       BTreeMap::new(),
            state:        Mutex::new(SandboxState::Running),
            start_error:  None,
            exec:         ScriptedExec::new(),
            fs:           Arc::clone(&fs),
            search:       ScriptedSearch::new(fs),
            starts:       AtomicU32::new(0),
            stops:        AtomicU32::new(0),
            deletes:      AtomicU32::new(0),
        }
    }

    /// The capability set a fresh double declares.
    pub fn default_capabilities() -> Capabilities {
        let mut capabilities = Capabilities::minimal(Isolation::None);
        capabilities.exec.live_streaming = true;
        capabilities.exec.streams_separated = true;
        capabilities.exec.stdin = true;
        capabilities.exec.stdin_stream = true;
        capabilities.exec.stop = true;
        capabilities.exec.stdio_process = true;
        capabilities.fs.upload = true;
        capabilities.fs.download = true;
        capabilities.search.supported = true;
        capabilities.search.native = true;
        capabilities.git.supported = true;
        capabilities
    }

    #[must_use]
    pub fn capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    #[must_use]
    pub fn platform(mut self, platform: PlatformInfo) -> Self {
        self.platform = platform;
        self
    }

    #[must_use]
    pub fn runtime_directory(mut self, directory: impl Into<String>) -> Self {
        self.runtime_dir = Some(directory.into());
        self
    }

    /// The state `describe` reports until a lifecycle call changes it.
    #[must_use]
    pub fn state(self, state: SandboxState) -> Self {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
        self
    }

    #[must_use]
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Seeds a file, resolved against the working directory when relative.
    #[must_use]
    pub fn file(self, path: &str, content: impl AsRef<[u8]>) -> Self {
        self.fs.insert(path, content);
        self
    }

    /// Makes `start` fail with a transport error.
    #[must_use]
    pub fn start_error(mut self, message: impl Into<String>) -> Self {
        self.start_error = Some(message.into());
        self
    }

    pub fn scripted_exec(&self) -> &ScriptedExec {
        &self.exec
    }

    pub fn memory_fs(&self) -> &MemoryFs {
        &self.fs
    }

    pub fn scripted_search(&self) -> &ScriptedSearch {
        &self.search
    }

    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    pub fn start_count(&self) -> u32 {
        self.starts.load(Ordering::SeqCst)
    }

    pub fn stop_count(&self) -> u32 {
        self.stops.load(Ordering::SeqCst)
    }

    pub fn delete_count(&self) -> u32 {
        self.deletes.load(Ordering::SeqCst)
    }

    pub fn current_state(&self) -> SandboxState {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_state(&self, state: SandboxState) {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = state;
    }
}

#[async_trait]
impl Sandbox for ScriptedSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        let mut status = SandboxStatus::new(self.id.clone(), self.current_state());
        status.labels.clone_from(&self.labels);
        status.provider_state = format!("{:?}", self.current_state()).to_ascii_lowercase();
        Ok(status)
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

    fn runtime_directory(&self) -> Option<&str> {
        self.runtime_dir.as_deref()
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        Ok(self.platform.clone())
    }

    async fn start(&self) -> Result<()> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = &self.start_error {
            return Err(Error::Transport(TransportError::new(message.clone())));
        }
        self.set_state(SandboxState::Running);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        self.set_state(SandboxState::Stopped);
        Ok(())
    }

    async fn delete(&self) -> Result<()> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.set_state(SandboxState::Deleted);
        Ok(())
    }

    fn exec(&self) -> &dyn Exec {
        &self.exec
    }

    fn fs(&self) -> &dyn Filesystem {
        self.fs.as_ref()
    }

    fn provider_search(&self) -> Option<&dyn Search> {
        Some(&self.search)
    }
}
