use async_trait::async_trait;

use crate::legacy::derived::DerivedSearch;
use crate::legacy::error::Result;
use crate::legacy::exec::Exec;
use crate::search::{GrepMatch, GrepOptions, WalkOptions, WalkedFile};

/// Content and file-tree search inside a sandbox.
///
/// The library provides an exec-derived implementation with optional ripgrep
/// acceleration and `grep`/`find` fallbacks. Providers with native search may
/// implement this directly. [`crate::legacy::Sandbox::search`] hides that
/// choice from callers.
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
