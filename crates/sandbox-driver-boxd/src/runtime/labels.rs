//! boxd labels carry both the caller's labels, exactly, and what this
//! provider must recover on attach: that the contract created the machine,
//! its working directory and its ambient environment.
//!
//! boxd accepts keys of 1 to 63 characters from `a-z`, `0-9`, `.`, `_`, `/`
//! and `-`, starting and ending with a letter or digit, and values of up to
//! 256 characters without control or invisible formatting characters. A
//! caller label that fits, and whose key is not one of this provider's, is
//! stored as given, so it reads naturally in `boxd machine list`. Any other
//! label is stored under an encoded key with an encoded value. Provider
//! metadata is JSON, base64url-encoded and split across numbered labels.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::str;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sandbox_driver::Error;
use serde::{Deserialize, Serialize};

/// Marks a machine this contract created and manages.
pub(super) const MANAGED: &str = "sandbox-driver/managed";
const MANAGED_VALUE: &str = "1";
/// Numbered chunks of the provider's metadata.
const META_PREFIX: &str = "sandbox-driver/meta.";
/// Caller labels that do not fit boxd's grammar: hex key, base64url value.
/// The `k` keeps the stored key ending in a letter or digit, as boxd
/// requires, even when the caller's key is empty.
const ENCODED_PREFIX: &str = "sdl/k";
/// Every key under these belongs to this provider or the platform.
const RESERVED_PREFIXES: [&str; 3] = ["sandbox-driver/", "sdl/", "boxd/"];
const MAX_KEY: usize = 63;
const MAX_VALUE: usize = 256;
const MAX_LABELS: usize = 64;

/// What the provider recovers from a machine on attach.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Meta {
    #[serde(rename = "wd")]
    pub(super) working_directory: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) env:               BTreeMap<String, String>,
}

/// The selector that finds every machine this contract manages.
pub(super) fn managed_selector() -> String {
    format!("{MANAGED}={MANAGED_VALUE}")
}

pub(super) fn is_managed(labels: &BTreeMap<String, String>) -> bool {
    labels
        .get(MANAGED)
        .is_some_and(|value| value == MANAGED_VALUE)
}

/// The full label set for a new machine.
pub(super) fn encode(
    caller: &BTreeMap<String, String>,
    meta: &Meta,
) -> Result<BTreeMap<String, String>, Error> {
    let mut labels = BTreeMap::from([(MANAGED.to_owned(), MANAGED_VALUE.to_owned())]);
    let json = serde_json::to_vec(meta).expect("metadata serializes");
    let encoded = URL_SAFE_NO_PAD.encode(json);
    for (index, chunk) in encoded.as_bytes().chunks(MAX_VALUE).enumerate() {
        let chunk = str::from_utf8(chunk).expect("base64 is ASCII");
        labels.insert(format!("{META_PREFIX}{index}"), chunk.to_owned());
    }
    for (key, value) in caller {
        let (stored_key, stored_value) = encode_label(key, value)?;
        labels.insert(stored_key, stored_value);
    }
    if labels.len() > MAX_LABELS {
        return Err(Error::InvalidSpec {
            path:    "labels".to_owned(),
            message: format!(
                "boxd stores at most {MAX_LABELS} labels per machine, and these labels, the \
                 environment and the working directory need {}",
                labels.len()
            ),
        });
    }
    Ok(labels)
}

fn encode_label(key: &str, value: &str) -> Result<(String, String), Error> {
    if native_key(key) && native_value(value) {
        return Ok((key.to_owned(), value.to_owned()));
    }
    let stored_key = format!("{ENCODED_PREFIX}{}", hex(key.as_bytes()));
    let stored_value = URL_SAFE_NO_PAD.encode(value);
    if stored_key.len() > MAX_KEY || stored_value.len() > MAX_VALUE {
        return Err(Error::InvalidSpec {
            path:    format!("labels.{key}"),
            message: "boxd cannot store this label: keys outside a-z, 0-9, '.', '_', '/' and '-' \
                      are limited to 29 bytes and values with other characters to 192 bytes"
                .to_owned(),
        });
    }
    Ok((stored_key, stored_value))
}

/// The caller's labels, exactly as set, from a machine's stored labels.
pub(super) fn caller_labels(stored: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    stored
        .iter()
        .filter_map(|(key, value)| {
            if let Some(encoded) = key.strip_prefix(ENCODED_PREFIX) {
                let key = String::from_utf8(unhex(encoded)?).ok()?;
                let value = String::from_utf8(URL_SAFE_NO_PAD.decode(value).ok()?).ok()?;
                Some((key, value))
            } else if reserved(key) {
                None
            } else {
                Some((key.clone(), value.clone()))
            }
        })
        .collect()
}

/// The provider's metadata, or `None` when it is missing or unreadable.
pub(super) fn meta(stored: &BTreeMap<String, String>) -> Option<Meta> {
    let mut encoded = String::new();
    for index in 0.. {
        match stored.get(&format!("{META_PREFIX}{index}")) {
            Some(chunk) => encoded.push_str(chunk),
            None => break,
        }
    }
    let json = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&json).ok()
}

fn reserved(key: &str) -> bool {
    RESERVED_PREFIXES
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

fn native_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (1..=MAX_KEY).contains(&bytes.len())
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes
            .iter()
            .all(|b| edge(b) || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && !reserved(key)
}

/// Printable ASCII only: boxd also refuses invisible formatting characters,
/// and encoding every non-ASCII value keeps that rule out of this check.
fn native_value(value: &str) -> bool {
    value.len() <= MAX_VALUE && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").expect("writing to a String succeeds");
        text
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Meta {
        Meta {
            working_directory: "/home/boxd/work".to_owned(),
            env:               BTreeMap::from([("CI".to_owned(), "1".to_owned())]),
        }
    }

    #[test]
    fn labels_round_trip_exactly_and_plain_ones_stay_readable() {
        let caller = BTreeMap::from([
            ("fabro.run".to_owned(), "01JABC".to_owned()),
            (
                "conformance".to_owned(),
                "quotes='\" unicode=λ newline=\n".to_owned(),
            ),
            ("Job".to_owned(), "1842".to_owned()),
            ("sandbox-driver/managed".to_owned(), "spoof".to_owned()),
            ("empty".to_owned(), String::new()),
        ]);
        let stored = encode(&caller, &meta()).unwrap();
        assert_eq!(stored.get("fabro.run").map(String::as_str), Some("01JABC"));
        assert_eq!(stored.get(MANAGED).map(String::as_str), Some("1"));
        assert!(stored.keys().all(|key| native_key(key) || reserved(key)));
        assert!(stored.values().all(|value| native_value(value)));
        assert_eq!(caller_labels(&stored), caller);
        assert_eq!(super::meta(&stored), Some(meta()));
    }

    /// boxd's own key grammar, without this provider's reservations.
    fn boxd_accepts(key: &str) -> bool {
        let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let bytes = key.as_bytes();
        (1..=MAX_KEY).contains(&bytes.len())
            && bytes.first().copied().is_some_and(edge)
            && bytes.last().copied().is_some_and(edge)
            && bytes
                .iter()
                .all(|&b| edge(b) || matches!(b, b'.' | b'_' | b'/' | b'-'))
            && !key.starts_with("boxd/")
    }

    #[test]
    fn every_stored_key_is_one_boxd_accepts() {
        let caller = BTreeMap::from([
            (String::new(), "empty key".to_owned()),
            ("UPPER".to_owned(), String::new()),
            ("boxd/owner".to_owned(), "spoof".to_owned()),
            ("k".repeat(29), "v".to_owned()),
        ]);
        let stored = encode(&caller, &meta()).unwrap();
        assert!(stored.keys().all(|key| boxd_accepts(key)), "{stored:?}");
        assert_eq!(caller_labels(&stored), caller);
    }

    #[test]
    fn large_metadata_spans_several_labels() {
        let mut big = meta();
        big.env.insert("BLOB".to_owned(), "x".repeat(2000));
        let stored = encode(&BTreeMap::new(), &big).unwrap();
        assert!(stored.len() > 3);
        assert_eq!(super::meta(&stored), Some(big));
    }

    #[test]
    fn a_label_boxd_cannot_hold_is_refused_by_name() {
        let caller = BTreeMap::from([("K".repeat(40), "v".to_owned())]);
        assert!(matches!(
            encode(&caller, &meta()),
            Err(Error::InvalidSpec { path, .. }) if path.starts_with("labels.")
        ));
    }
}
