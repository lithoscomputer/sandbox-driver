//! Exec-derived facet implementations.
//!
//! [`DerivedSearch`] and [`DerivedGit`] implement the [`crate::Search`]
//! and [`crate::Git`] facets over any [`crate::Exec`], for providers with
//! no native API. Both borrow the exec facet, so they work ad hoc over a
//! sandbox handle:
//!
//! ```ignore
//! let search = DerivedSearch::new(sandbox.exec());
//! let matches = search.grep("TODO", ".", &GrepOptions::default()).await?;
//! ```

mod fs;
mod git;
mod search;
mod service;

pub use fs::DerivedFs;
pub use git::DerivedGit;
pub use search::DerivedSearch;
pub use service::DerivedServices;

/// Quotes a string for safe interpolation into Bash source.
pub(crate) fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_single_quotes_safely() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("a b;c$d"), "'a b;c$d'");
    }
}
