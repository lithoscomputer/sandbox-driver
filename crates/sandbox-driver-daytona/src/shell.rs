//! Shell quoting for the toolbox's shell-string command surface.

use std::collections::BTreeMap;

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

/// `exec env KEY=VALUE… program args…` as one shell word list, each word
/// single-quoted. The toolbox API takes a shell string, so this is the one
/// place the exec contract's argv is turned back into shell — and the
/// quoting is what keeps it literal. The environment rides on `env`
/// rather than `export` so that names which are not shell identifiers
/// (`INPUT_INCLUDE-HIDDEN-FILES`) reach the program too.
pub(crate) fn exec_line(env: &BTreeMap<String, String>, program: &str, args: &[String]) -> String {
    let mut line = String::from("exec env");
    for (key, value) in env {
        line.push(' ');
        line.push_str(&shell_quote(&format!("{key}={value}")));
    }
    line.push(' ');
    line.push_str(&shell_quote(program));
    for arg in args {
        line.push(' ');
        line.push_str(&shell_quote(arg));
    }
    line
}
