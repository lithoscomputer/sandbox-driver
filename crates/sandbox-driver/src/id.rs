use std::fmt;

use serde::{Deserialize, Serialize};

/// Rejected identifier input.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid {kind} {value:?}: {reason}")]
pub struct InvalidIdError {
    kind:   &'static str,
    value:  String,
    reason: &'static str,
}

impl InvalidIdError {
    fn new(kind: &'static str, value: &str, reason: &'static str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
            reason,
        }
    }
}

const MAX_ID_LEN: usize = 256;

fn validate_id(kind: &'static str, value: &str) -> Result<(), InvalidIdError> {
    if value.is_empty() {
        return Err(InvalidIdError::new(kind, value, "must not be empty"));
    }
    if value.len() > MAX_ID_LEN {
        return Err(InvalidIdError::new(kind, value, "exceeds 256 bytes"));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(InvalidIdError::new(
            kind,
            value,
            "must not contain whitespace or control characters",
        ));
    }
    Ok(())
}

macro_rules! id_newtype {
    ($(#[$doc:meta])* $name:ident, $kind:literal) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps a provider-issued identifier.
            pub fn try_new(value: impl Into<String>) -> Result<Self, InvalidIdError> {
                let value = value.into();
                validate_id($kind, &value)?;
                Ok(Self(value))
            }

            /// The identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidIdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::try_new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

id_newtype!(
    /// Provider-scoped sandbox identifier. Persist it to re-attach later.
    SandboxId,
    "sandbox id"
);
id_newtype!(
    /// Provider-scoped snapshot identifier or name.
    SnapshotId,
    "snapshot id"
);
id_newtype!(
    /// Provider-scoped volume identifier or name.
    VolumeId,
    "volume id"
);
id_newtype!(
    /// Sandbox-scoped background-service identifier.
    ServiceId,
    "service id"
);

/// Open provider kind: `"host"`, `"docker"`, `"daytona"`, or any plugin name.
///
/// Deliberately not an enum — new providers must not require changes here.
/// Kinds are lowercase ASCII letters, digits, and hyphens.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProviderKind(String);

impl ProviderKind {
    /// Validates and wraps a provider kind name.
    pub fn try_new(value: impl Into<String>) -> Result<Self, InvalidIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(InvalidIdError::new(
                "provider kind",
                &value,
                "must not be empty",
            ));
        }
        if value.len() > 64 {
            return Err(InvalidIdError::new(
                "provider kind",
                &value,
                "exceeds 64 bytes",
            ));
        }
        let valid = value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid || value.starts_with('-') || value.ends_with('-') {
            return Err(InvalidIdError::new(
                "provider kind",
                &value,
                "must be lowercase ASCII letters, digits, and interior hyphens",
            ));
        }
        Ok(Self(value))
    }

    /// The kind as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ProviderKind {
    type Error = InvalidIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<ProviderKind> for String {
    fn from(value: ProviderKind) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_ids() {
        let id = SandboxId::try_new("sb_a1-B2.c3").expect("valid id");
        assert_eq!(id.as_str(), "sb_a1-B2.c3");
    }

    #[test]
    fn rejects_empty_and_whitespace_ids() {
        SandboxId::try_new("").expect_err("empty is rejected");
        SandboxId::try_new("a b").expect_err("whitespace is rejected");
        SandboxId::try_new("a\nb").expect_err("control characters are rejected");
    }

    #[test]
    fn provider_kind_enforces_naming_convention() {
        ProviderKind::try_new("daytona").expect("valid kind");
        ProviderKind::try_new("my-provider2").expect("valid kind");
        ProviderKind::try_new("Daytona").expect_err("uppercase is rejected");
        ProviderKind::try_new("-daytona").expect_err("leading hyphen is rejected");
        ProviderKind::try_new("day tona").expect_err("whitespace is rejected");
    }

    #[test]
    fn ids_round_trip_through_serde() {
        let id = SandboxId::try_new("sb-1").expect("valid id");
        let json = serde_json::to_string(&id).expect("serializes");
        assert_eq!(json, "\"sb-1\"");
        let back: SandboxId = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, id);
        serde_json::from_str::<SandboxId>("\"\"")
            .expect_err("invalid ids are rejected on deserialize");
    }
}
