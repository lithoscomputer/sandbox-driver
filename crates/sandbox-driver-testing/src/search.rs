use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use sandbox_driver::{
    Error, GrepMatch, GrepOptions, Result, Search, TransportError, WalkOptions, WalkedFile,
};

/// A [`Search`] that returns canned results and counts calls.
#[derive(Default)]
pub struct ScriptedSearch {
    grep:       Mutex<Vec<GrepMatch>>,
    glob:       Mutex<Vec<String>>,
    walk:       Mutex<Vec<WalkedFile>>,
    walk_error: Mutex<Option<String>>,
    walk_calls: AtomicUsize,
}

impl ScriptedSearch {
    pub fn new() -> Self {
        Self::default()
    }

    /// The matches every grep returns.
    pub fn set_grep(&self, matches: Vec<GrepMatch>) -> &Self {
        *self.grep.lock().unwrap_or_else(PoisonError::into_inner) = matches;
        self
    }

    /// The paths every glob returns.
    pub fn set_glob(&self, paths: Vec<String>) -> &Self {
        *self.glob.lock().unwrap_or_else(PoisonError::into_inner) = paths;
        self
    }

    /// The files every walk returns, before any filtering the caller
    /// applies.
    pub fn set_walk(&self, files: Vec<WalkedFile>) -> &Self {
        *self.walk.lock().unwrap_or_else(PoisonError::into_inner) = files;
        self
    }

    /// Makes every walk fail with a transport error.
    pub fn set_walk_error(&self, message: impl Into<String>) -> &Self {
        *self
            .walk_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(message.into());
        self
    }

    /// How many walks ran so far.
    pub fn walk_calls(&self) -> usize {
        self.walk_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Search for ScriptedSearch {
    async fn grep(
        &self,
        _pattern: &str,
        _path: &str,
        _options: &GrepOptions,
    ) -> Result<Vec<GrepMatch>> {
        Ok(self
            .grep
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }

    async fn glob(&self, _pattern: &str, _base: &str) -> Result<Vec<String>> {
        Ok(self
            .glob
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }

    async fn walk(&self, _base: &str, _options: &WalkOptions) -> Result<Vec<WalkedFile>> {
        self.walk_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = self
            .walk_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(Error::Transport(TransportError::new(message)));
        }
        Ok(self
            .walk
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }
}
