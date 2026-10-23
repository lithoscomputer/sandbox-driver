use std::error::Error as StdError;
use std::io;

use jsonschema::{Draft, Retrieve, Uri, Validator};
use serde_json::Value;

use super::{Error, JsonSchema, ProviderName, ProviderSchemas};

pub(super) struct Schemas {
    config: Validator,
    spec:   Option<Validator>,
}

// Explicitly block resolution even if another workspace consumer enables
// jsonschema's network/file features through Cargo feature unification.
struct NoExternalReferences;
impl Retrieve for NoExternalReferences {
    fn retrieve(&self, _: &Uri<String>) -> Result<Value, Box<dyn StdError + Send + Sync>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "external schema references are disabled",
        )
        .into())
    }
}

impl Schemas {
    pub(super) fn compile(entry: &ProviderName, schemas: &ProviderSchemas) -> Result<Self, Error> {
        Ok(Self {
            config: compile(entry, "config_schema", &schemas.config_schema)?,
            spec:   schemas
                .spec_schema
                .as_ref()
                .map(|schema| compile(entry, "spec_schema", schema))
                .transpose()?,
        })
    }

    pub(super) fn config(&self, entry: &ProviderName, value: &Value) -> Result<(), Error> {
        self.config
            .validate(value)
            .map_err(|error| Error::InvalidConfig {
                entry:   entry.clone(),
                path:    format!("config{}", error.instance_path()),
                // Engine diagnostics contain instance values, including secrets.
                message: "does not satisfy provider config_schema".into(),
            })
    }

    pub(super) fn spec(&self, value: &Value) -> Result<(), Error> {
        if let Some(schema) = &self.spec {
            schema.validate(value).map_err(|error| Error::InvalidSpec {
                path:    format!("provider_config{}", error.instance_path()),
                message: "does not satisfy provider spec_schema".into(),
            })?;
        }
        Ok(())
    }
}

fn compile(entry: &ProviderName, path: &str, schema: &JsonSchema) -> Result<Validator, Error> {
    let invalid = |message: &str| Error::InvalidConfig {
        entry:   entry.clone(),
        path:    path.into(),
        message: message.into(),
    };
    let draft = match schema.get("$schema").and_then(Value::as_str) {
        Some("http://json-schema.org/draft-07/schema#") => Draft::Draft7,
        Some("https://json-schema.org/draft/2019-09/schema") => Draft::Draft201909,
        Some("https://json-schema.org/draft/2020-12/schema") => Draft::Draft202012,
        _ => {
            return Err(invalid(
                "requires a supported declared JSON Schema dialect (draft-07, 2019-09 or 2020-12)",
            ));
        }
    };
    jsonschema::options()
        .with_draft(draft)
        .with_retriever(NoExternalReferences)
        .build(&Value::Object(schema.clone().into_iter().collect()))
        .map_err(|_| invalid("invalid schema or unresolved external reference"))
}
