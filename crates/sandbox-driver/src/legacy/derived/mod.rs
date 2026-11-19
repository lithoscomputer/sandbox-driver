//! Exec-derived facet implementations.
//!
//! [`DerivedSearch`], [`DerivedGit`], and [`DerivedServices`] implement their
//! facets over any [`crate::legacy::Exec`] for providers without matching
//! native APIs. They borrow the exec facet and power the normalized accessors
//! on [`crate::legacy::Sandbox`]. Consumers use those accessors instead of
//! selecting a fallback themselves.

mod fs;
mod git;
mod search;
mod service;

pub use fs::DerivedFs;
pub use git::DerivedGit;
pub use search::DerivedSearch;
pub use service::DerivedServices;

pub(crate) use crate::file_ops::shell_quote;
