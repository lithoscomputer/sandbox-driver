//! Timestamps on the wire.
//!
//! Every timestamp the driver serializes is an RFC 3339 string in UTC
//! (`2026-09-11T12:00:00.250Z`), the form a consumer can hand on to its
//! own API or a browser unchanged. Peers written before this encoding sent
//! `SystemTime`'s structural form,
//! `{"secs_since_epoch":…,"nanos_since_epoch":…}`; readers accept both.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::ser::Serializer;

/// Serializes a timestamp as an RFC 3339 string.
pub(crate) fn serialize<S: Serializer>(
    time: &SystemTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&humantime::format_rfc3339(*time))
}

/// Deserializes a timestamp from an RFC 3339 string or the structural form.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<SystemTime, D::Error> {
    deserializer.deserialize_any(TimeVisitor)
}

struct TimeVisitor;

impl<'de> Visitor<'de> for TimeVisitor {
    type Value = SystemTime;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "an RFC 3339 timestamp or an object with secs_since_epoch and nanos_since_epoch",
        )
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<SystemTime, E> {
        humantime::parse_rfc3339_weak(text).map_err(E::custom)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SystemTime, A::Error> {
        let mut secs = None;
        let mut nanos = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "secs_since_epoch" => secs = Some(map.next_value::<u64>()?),
                "nanos_since_epoch" => nanos = Some(map.next_value::<u32>()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let secs = secs.ok_or_else(|| de::Error::missing_field("secs_since_epoch"))?;
        Ok(UNIX_EPOCH + Duration::new(secs, nanos.unwrap_or(0)))
    }
}

/// The same encoding for an optional timestamp; `None` is `null` or absent.
pub(crate) mod option {
    use std::time::SystemTime;

    use serde::de::Deserializer;
    use serde::ser::Serializer;
    use serde::{Deserialize, Serialize};

    #[expect(
        clippy::ref_option,
        reason = "serde's serialize_with hands the field by reference"
    )]
    pub(crate) fn serialize<S: Serializer>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a>(#[serde(serialize_with = "super::serialize")] &'a SystemTime);
        match time {
            Some(time) => serializer.serialize_some(&Wire(time)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        #[derive(Deserialize)]
        struct Wire(#[serde(deserialize_with = "super::deserialize")] SystemTime);
        Option::<Wire>::deserialize(deserializer).map(|wire| wire.map(|Wire(time)| time))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Stamped {
        #[serde(with = "super")]
        at:    SystemTime,
        #[serde(default, with = "super::option")]
        maybe: Option<SystemTime>,
    }

    fn epoch_plus(secs: u64, nanos: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, nanos)
    }

    #[test]
    fn timestamps_are_written_as_rfc_3339_and_read_back() {
        let stamped = Stamped {
            at:    epoch_plus(1_788_206_400, 250_000_000),
            maybe: Some(epoch_plus(1_788_206_401, 0)),
        };
        let json = serde_json::to_value(&stamped).expect("encode");
        assert_eq!(json["at"], "2026-08-31T20:00:00.250000000Z");
        assert_eq!(json["maybe"], "2026-08-31T20:00:01Z");
        let decoded: Stamped = serde_json::from_value(json).expect("decode");
        assert_eq!(decoded, stamped);
    }

    #[test]
    fn the_structural_form_still_decodes() {
        let decoded: Stamped = serde_json::from_str(
            r#"{"at":{"secs_since_epoch":1,"nanos_since_epoch":500},
                "maybe":{"secs_since_epoch":2,"nanos_since_epoch":0,"future":true}}"#,
        )
        .expect("legacy decode");
        assert_eq!(decoded.at, epoch_plus(1, 500));
        assert_eq!(decoded.maybe, Some(epoch_plus(2, 0)));
    }

    #[test]
    fn a_missing_or_null_option_is_none() {
        let absent: Stamped =
            serde_json::from_str(r#"{"at":"1970-01-01T00:00:01Z"}"#).expect("absent option");
        assert_eq!(absent.maybe, None);
        let null: Stamped = serde_json::from_str(r#"{"at":"1970-01-01T00:00:01Z","maybe":null}"#)
            .expect("null option");
        assert_eq!(null.maybe, None);
        assert_eq!(
            serde_json::to_value(&null).expect("encode")["maybe"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn a_malformed_timestamp_is_an_error() {
        let error =
            serde_json::from_str::<Stamped>(r#"{"at":"yesterday"}"#).expect_err("not a timestamp");
        assert!(error.to_string().contains("at"), "{error}");
    }
}
