use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use sandbox_driver::{
    Error, GrepMatch, GrepOptions, Result, Search, TransportError, WalkOptions, WalkedFile,
};

use crate::fs::MemoryFs;

/// A [`Search`] over the in-memory filesystem, with canned results on top.
///
/// A walk enumerates the files below the requested base in the memory
/// filesystem unless the test canned a listing; a glob matches the memory
/// filesystem's paths unless the test canned one; grep is canned only,
/// since nothing here evaluates patterns. Walks are counted.
pub struct ScriptedSearch {
    fs:         Arc<MemoryFs>,
    grep:       Mutex<Vec<GrepMatch>>,
    glob:       Mutex<Option<Vec<String>>>,
    walk:       Mutex<Option<Vec<WalkedFile>>>,
    walk_error: Mutex<Option<String>>,
    walk_calls: AtomicUsize,
}

impl ScriptedSearch {
    pub fn new(fs: Arc<MemoryFs>) -> Self {
        Self {
            fs,
            grep: Mutex::new(Vec::new()),
            glob: Mutex::new(None),
            walk: Mutex::new(None),
            walk_error: Mutex::new(None),
            walk_calls: AtomicUsize::new(0),
        }
    }

    /// The matches every grep returns.
    pub fn set_grep(&self, matches: Vec<GrepMatch>) -> &Self {
        *self.grep.lock().unwrap_or_else(PoisonError::into_inner) = matches;
        self
    }

    /// The paths every glob returns, instead of matching the memory
    /// filesystem.
    pub fn set_glob(&self, paths: Vec<String>) -> &Self {
        *self.glob.lock().unwrap_or_else(PoisonError::into_inner) = Some(paths);
        self
    }

    /// The files every walk returns, instead of the memory filesystem's,
    /// before any filtering the caller applies.
    pub fn set_walk(&self, files: Vec<WalkedFile>) -> &Self {
        *self.walk.lock().unwrap_or_else(PoisonError::into_inner) = Some(files);
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

    async fn glob(&self, pattern: &str, base: &str) -> Result<Vec<String>> {
        if let Some(paths) = self
            .glob
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(paths);
        }
        Ok(self.fs.glob(pattern, base))
    }

    async fn walk(&self, base: &str, options: &WalkOptions) -> Result<Vec<WalkedFile>> {
        self.walk_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = self
            .walk_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(Error::Transport(TransportError::new(message)));
        }
        if let Some(files) = self
            .walk
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(files);
        }
        Ok(self.fs.walk(base, options))
    }
}
