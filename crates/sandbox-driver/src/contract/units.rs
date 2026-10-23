//! The one size and duration grammar. Templates and overrides may carry
//! `"4GB"` or `"60m"`; providers receive whole MiB and milliseconds.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

/// Rejected size or duration text.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid {kind} {text:?}: {reason}")]
pub struct ParseUnitError {
    kind:   &'static str,
    text:   String,
    reason: String,
}

impl ParseUnitError {
    fn new(kind: &'static str, text: &str, reason: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.to_owned(),
            reason: reason.into(),
        }
    }
}

/// Parses a size into whole MiB, read the way Docker and systemd read it:
/// `4GB`, `4G`, `4GiB` and `4Gi` all mean 4096 MiB. The count is a whole
/// number; the unit is `B`, or `K`, `M`, `G`, `T` with an optional `B`,
/// `i` or `iB`, in any case. A unit is required, and the result must be a
/// whole number of MiB.
pub fn parse_size_mib(text: &str) -> Result<u64, ParseUnitError> {
    const KIND: &str = "size";
    let trimmed = text.trim();
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (count, unit) = trimmed.split_at(digits_end);
    let count: u64 = count
        .parse()
        .map_err(|_| ParseUnitError::new(KIND, text, "must start with a whole number"))?;
    let unit = unit.trim_start().to_ascii_lowercase();
    let prefix = ["ib", "b", "i"]
        .iter()
        .find_map(|suffix| unit.strip_suffix(suffix))
        .unwrap_or(&unit);
    let bytes_per_unit: u64 = match prefix {
        "" if unit == "b" => 1,
        "" => {
            return Err(ParseUnitError::new(
                KIND,
                text,
                "requires a unit such as MiB or GB",
            ));
        }
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        "t" => 1 << 40,
        _ => {
            return Err(ParseUnitError::new(
                KIND,
                text,
                format!("unknown unit {unit:?}"),
            ));
        }
    };
    let bytes = count
        .checked_mul(bytes_per_unit)
        .ok_or_else(|| ParseUnitError::new(KIND, text, "is too large"))?;
    if bytes % (1 << 20) != 0 {
        return Err(ParseUnitError::new(
            KIND,
            text,
            "must be a whole number of MiB",
        ));
    }
    Ok(bytes >> 20)
}

/// Parses a duration such as `60m`, `1h 30m` or `500ms` into milliseconds.
/// A unit is required; `0s` is zero.
pub fn parse_duration_ms(text: &str) -> Result<u64, ParseUnitError> {
    const KIND: &str = "duration";
    let duration = humantime::parse_duration(text.trim())
        .map_err(|error| ParseUnitError::new(KIND, text, error.to_string()))?;
    u64::try_from(duration.as_millis()).map_err(|_| ParseUnitError::new(KIND, text, "is too large"))
}

/// Whole MiB from either a number or size text.
pub(super) struct Mib(pub(super) u64);

impl<'de> Deserialize<'de> for Mib {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(UnitVisitor {
                expecting: "whole MiB or a size with a unit such as \"4GB\"",
                parse:     parse_size_mib,
            })
            .map(Self)
    }
}

/// Milliseconds from either a number or duration text.
pub(super) struct Millis(pub(super) u64);

impl<'de> Deserialize<'de> for Millis {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(UnitVisitor {
                expecting: "milliseconds or a duration with a unit such as \"60m\"",
                parse:     parse_duration_ms,
            })
            .map(Self)
    }
}

struct UnitVisitor {
    expecting: &'static str,
    parse:     fn(&str) -> Result<u64, ParseUnitError>,
}

impl Visitor<'_> for UnitVisitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.expecting)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<u64, E> {
        Ok(value)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<u64, E> {
        u64::try_from(value).map_err(|_| E::custom("must not be negative"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<u64, E> {
        (self.parse)(value).map_err(E::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_binary_units_in_any_spelling() {
        for text in [
            "4GB",
            "4G",
            "4GiB",
            "4Gi",
            "4gb",
            " 4 GB ",
            "4096MB",
            "4096M",
            "4194304KiB",
        ] {
            assert_eq!(parse_size_mib(text).expect(text), 4096, "{text}");
        }
        assert_eq!(parse_size_mib("1048576B").expect("bytes"), 1);
        assert_eq!(parse_size_mib("1T").expect("tebibytes"), 1 << 20);
    }

    #[test]
    fn sizes_require_a_unit_and_whole_mebibytes() {
        for text in ["4", "", "GB", "1.5GB", "512KB", "4PB", "4 gigs", "-4GB"] {
            parse_size_mib(text).expect_err(text);
        }
    }

    #[test]
    fn durations_use_the_humantime_grammar_in_milliseconds() {
        assert_eq!(parse_duration_ms("60m").expect("minutes"), 3_600_000);
        assert_eq!(parse_duration_ms("1h 30m").expect("mixed"), 5_400_000);
        assert_eq!(parse_duration_ms("500ms").expect("millis"), 500);
        assert_eq!(parse_duration_ms("0s").expect("zero"), 0);
        for text in ["60", "", "soon"] {
            parse_duration_ms(text).expect_err(text);
        }
    }
}
