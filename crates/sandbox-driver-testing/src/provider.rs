use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use sandbox_driver::{
    Capabilities, Error, EventContext, HealthStatus, ProviderHealth, ProviderKind, Result, Sandbox,
    SandboxFilter, SandboxId, SandboxProvider, SandboxSpec, SandboxState, SandboxStatus,
    TransportError,
};

use crate::sandbox::ScriptedSandbox;

/// A [`SandboxProvider`] that hands out [`ScriptedSandbox`]es.
///
/// `create` builds a running sandbox carrying the spec's labels and
/// working directory (or `/work/<id>`), registers it, and returns it;
/// `attach` and `list` read the registry; `delete` goes through the
/// trait's default. Sandboxes a test builds itself can be registered up
/// front with [`ScriptedProvider::register`].
pub struct ScriptedProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    sandboxes:    Mutex<BTreeMap<SandboxId, Arc<ScriptedSandbox>>>,
    create_error: Mutex<Option<String>>,
    health:       Mutex<ProviderHealth>,
    next:         AtomicU32,
}

impl Default for ScriptedProvider {
    fn default() -> Self {
        Self::new("scripted")
    }
}

impl ScriptedProvider {
    pub fn new(kind: &str) -> Self {
        Self {
            kind:         ProviderKind::try_new(kind).expect("scripted provider kind is valid"),
            capabilities: ScriptedSandbox::default_capabilities(),
            sandboxes:    Mutex::new(BTreeMap::new()),
            create_error: Mutex::new(None),
            health:       Mutex::new(ProviderHealth::new(HealthStatus::Ok)),
            next:         AtomicU32::new(1),
        }
    }

    /// Adds a sandbox the test built, so `attach` and `list` find it.
    pub fn register(&self, sandbox: Arc<ScriptedSandbox>) -> &Self {
        self.sandboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sandbox.id().clone(), sandbox);
        self
    }

    /// The registered sandboxes, created or added, by id.
    pub fn sandboxes(&self) -> Vec<Arc<ScriptedSandbox>> {
        self.sandboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Makes every `create` fail with a transport error.
    pub fn set_create_error(&self, message: impl Into<String>) -> &Self {
        *self
            .create_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(message.into());
        self
    }

    /// What `health` reports.
    pub fn set_health(&self, health: ProviderHealth) -> &Self {
        *self.health.lock().unwrap_or_else(PoisonError::into_inner) = health;
        self
    }
}

#[async_trait]
impl SandboxProvider for ScriptedProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn create(
        &self,
        spec: &SandboxSpec,
        _events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        if let Some(message) = self
            .create_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(Error::Transport(TransportError::new(message)));
        }
        let id = format!("{}-{}", self.kind, self.next.fetch_add(1, Ordering::SeqCst));
        let working_dir = spec
            .working_directory
            .clone()
            .unwrap_or_else(|| format!("/work/{id}"));
        let mut sandbox = ScriptedSandbox::with_id_and_working_dir(&id, &working_dir)
            .capabilities(self.capabilities.clone())
            .state(SandboxState::Running);
        for (key, value) in &spec.labels {
            sandbox = sandbox.label(key.clone(), value.clone());
        }
        let sandbox = Arc::new(sandbox);
        self.register(Arc::clone(&sandbox));
        Ok(sandbox)
    }

    async fn attach(
        &self,
        id: &SandboxId,
        _events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let found = self
            .sandboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned();
        match found {
            Some(sandbox) if sandbox.current_state() != SandboxState::Deleted => Ok(sandbox),
            _ => Err(Error::NotFound {
                resource: sandbox_driver::ResourceKind::Sandbox,
                id:       id.as_str().to_owned(),
            }),
        }
    }

    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let sandboxes = self.sandboxes();
        let mut statuses = Vec::new();
        for sandbox in sandboxes {
            if sandbox.current_state() == SandboxState::Deleted {
                continue;
            }
            if filter
                .labels
                .iter()
                .all(|(key, value)| sandbox.labels().get(key) == Some(value))
            {
                statuses.push(sandbox.describe().await?);
            }
        }
        Ok(statuses)
    }

    async fn health(&self) -> Result<ProviderHealth> {
        Ok(self
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }
}
