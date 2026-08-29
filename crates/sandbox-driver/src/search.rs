use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Content and file-tree search inside a sandbox.
///
/// The library will ship an exec-derived implementation (ripgrep with
/// grep/find fallbacks); providers with native search may implement this
/// directly and declare `Capabilities::search.native = true`.
#[async_trait]
pub trait Search: Send + Sync {
    /// Searches file contents for a regex pattern.
    async fn grep(
        &self,
        pattern: &str,
        path: &str,
        options: &GrepOptions,
    ) -> Result<Vec<GrepMatch>>;

    /// Matches file paths against a glob pattern, relative to `base`.
    async fn glob(&self, pattern: &str, base: &str) -> Result<Vec<String>>;

    /// Walks the file tree under `base`.
    async fn walk(&self, base: &str, options: &WalkOptions) -> Result<Vec<WalkedFile>>;
}

/// Options for [`Search::grep`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GrepOptions {
    pub case_insensitive: bool,
    pub max_matches:      Option<usize>,
    /// Glob the searched files must match.
    pub include:          Option<String>,
}

/// One content match.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GrepMatch {
    pub path:        String,
    pub line_number: u64,
    pub line:        String,
}

/// Options for [`Search::walk`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WalkOptions {
    pub max_depth:    Option<usize>,
    /// Directory names pruned from the walk (e.g. `.git`, `node_modules`).
    pub exclude_dirs: Vec<String>,
}

/// One file from [`Search::walk`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WalkedFile {
    /// Path relative to the walk base.
    pub path: String,
    /// `None` when the transport cannot report sizes (BSD find fallback).
    pub size: Option<u64>,
}
