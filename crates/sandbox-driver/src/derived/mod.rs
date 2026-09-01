//! Exec-derived facet implementations.
//!
//! [`DerivedSearch`], [`DerivedGit`], and [`DerivedServices`] implement their
//! facets over any [`crate::Exec`] for providers without matching native APIs.
//! They borrow the exec facet and power the normalized accessors on
//! [`crate::Sandbox`]. Consumers use those accessors instead of selecting a
//! fallback themselves.

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
