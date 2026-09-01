use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::derived::DerivedSearch;
use crate::error::Result;
use crate::exec::Exec;

/// Content and file-tree search inside a sandbox.
///
/// The library provides an exec-derived implementation with optional ripgrep
/// acceleration and `grep`/`find` fallbacks. Providers with native search may
/// implement this directly. [`crate::Sandbox::search`] hides that choice from
/// callers.
///
/// A sandbox that derives this facet must provide `grep`, `find`, and `head`.
/// `rg` is optional and used when present. Providers do not probe required
/// commands before they advertise support.
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

/// A sandbox's normalized search facet.
///
/// This facade hides whether the provider supplies a native implementation or
/// uses the shared exec-derived implementation.
pub struct SearchFacet<'a> {
    implementation: SearchImplementation<'a>,
}

enum SearchImplementation<'a> {
    Provider(&'a dyn Search),
    Derived(DerivedSearch<'a>),
}

impl<'a> SearchFacet<'a> {
    pub(crate) fn provider(search: &'a dyn Search) -> Self {
        Self {
            implementation: SearchImplementation::Provider(search),
        }
    }

    pub(crate) fn derived(exec: &'a dyn Exec) -> Self {
        Self {
            implementation: SearchImplementation::Derived(DerivedSearch::new(exec)),
        }
    }

    fn implementation(&self) -> &dyn Search {
        match &self.implementation {
            SearchImplementation::Provider(search) => *search,
            SearchImplementation::Derived(search) => search,
        }
    }
}

#[async_trait]
impl Search for SearchFacet<'_> {
    async fn grep(
        &self,
        pattern: &str,
        path: &str,
        options: &GrepOptions,
    ) -> Result<Vec<GrepMatch>> {
        self.implementation().grep(pattern, path, options).await
    }

    async fn glob(&self, pattern: &str, base: &str) -> Result<Vec<String>> {
        self.implementation().glob(pattern, base).await
    }

    async fn walk(&self, base: &str, options: &WalkOptions) -> Result<Vec<WalkedFile>> {
        self.implementation().walk(base, options).await
    }
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
