//! Replacement for new work only. A failed call is never replayed.
use std::collections::btree_map::Entry;
use std::sync::Arc;
use std::{env, mem};

use sandbox_driver::Result;
use tokio::sync::Mutex;

use crate::{PluginConfig, PluginProvider, launch_plugin};

/// Owns at most one live plugin for one fixed configuration and credential
/// context. Share this owner for the application's lifetime. Each call to
/// `current` obtains the current generation; old sandbox handles remain tied
/// to the failed generation and must be reconstructed explicitly.
///
/// The application bounds the number of supervisors and authorizes resource
/// IDs. This type never retries commands or mutations after an uncertain
/// result.
pub struct PluginSupervisor {
    prefix:  String,
    config:  PluginConfig,
    current: Mutex<Option<Arc<PluginProvider>>>,
}

impl PluginSupervisor {
    /// Freezes forwarded environment values now so replacements cannot inherit
    /// a different credential context from later environment changes.
    pub fn new(prefix: impl Into<String>, mut config: PluginConfig) -> Self {
        for key in mem::take(&mut config.inherit_env) {
            if let Entry::Vacant(entry) = config.env.entry(key) {
                if let Ok(value) = env::var(entry.key()) {
                    entry.insert(value);
                }
            }
        }
        Self {
            prefix: prefix.into(),
            config,
            current: Mutex::new(None),
        }
    }

    /// Serializes startup so concurrent callers share a single replacement.
    /// Failed generations and their calls are never rebound to the replacement.
    pub async fn current(&self) -> Result<Arc<PluginProvider>> {
        let mut slot = self.current.lock().await;
        if let Some(provider) = slot.as_ref().filter(|provider| !provider.is_closed()) {
            return Ok(Arc::clone(provider));
        }
        if let Some(old) = slot.take() {
            let _ = old.shutdown().await;
        }
        let launched = launch_plugin(&self.prefix, &self.config).await?;
        let provider = Arc::new(launched.provider);
        *slot = Some(Arc::clone(&provider));
        Ok(provider)
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut slot = self.current.lock().await;
        if let Some(provider) = slot.take() {
            provider.shutdown().await?;
        }
        Ok(())
    }
}
