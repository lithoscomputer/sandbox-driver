use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{SandboxBuilder, SandboxSpec, SnapshotId, Source, parse_duration_ms};
use serde_json::Value;
use tokio::fs::{read, read_to_string};
use tokio::io::{AsyncReadExt as _, stdin};

use crate::cli::CreateArgs;

/// Applies the command-line changes to the environment's template through
/// the builder's setters. Options that were not given leave the template's
/// value in place; `--spec` replaces the whole template first.
pub(super) async fn apply(builder: SandboxBuilder, args: &CreateArgs) -> Result<SandboxBuilder> {
    let mut builder = match &args.spec {
        Some(path) => builder.spec(read_spec(path).await?),
        None => builder,
    };
    // The builder has no setter for these two, so they edit the spec.
    if args.snapshot.is_some() || args.name.is_some() {
        let mut spec = builder.resolved_spec().clone();
        if let Some(snapshot) = &args.snapshot {
            spec.source = Source::Snapshot(
                SnapshotId::try_new(snapshot.clone()).context("validating --snapshot")?,
            );
        }
        if let Some(name) = &args.name {
            spec.name = Some(name.clone());
        }
        builder = builder.spec(spec);
    }
    if let Some(image) = &args.image {
        builder = builder.image(image);
    }
    if let Some(path) = &args.dockerfile {
        let content = read_to_string(path)
            .await
            .with_context(|| format!("reading Dockerfile {}", path.display()))?;
        builder = builder.dockerfile(&content);
    }
    if let Some(cpu) = args.cpu {
        builder = builder.cpu(cpu);
    }
    // Sizes are checked by the builder; a bad one fails `create` before
    // anything is admitted.
    if let Some(memory) = &args.memory {
        builder = builder.memory(memory);
    }
    if let Some(disk) = &args.disk {
        builder = builder.disk(disk);
    }
    for (key, value) in parse_assignments(&args.env, "env")? {
        builder = builder.env(&key, &value);
    }
    for (key, value) in parse_assignments(&args.labels, "label")? {
        builder = builder.label(&key, &value);
    }
    if let Some(workspace) = &args.workspace {
        builder = builder.working_directory(workspace);
    }
    if let Some(user) = &args.user {
        builder = builder.user(user);
    }
    if let Some(network) = args.network {
        builder = builder.network(network.into());
    }
    if let Some(config) = &args.provider_config {
        let values: BTreeMap<String, Value> =
            serde_json::from_str(config).context("parsing --provider-config as a JSON object")?;
        builder = builder.provider_config(values);
    }
    Ok(builder)
}

async fn read_spec(path: &Path) -> Result<SandboxSpec> {
    let (contents, source) = if path == Path::new("-") {
        let mut contents = Vec::new();
        stdin()
            .read_to_end(&mut contents)
            .await
            .context("reading stdin")?;
        (contents, "stdin".to_owned())
    } else {
        let contents = read(path)
            .await
            .with_context(|| format!("reading {}", path.display()))?;
        (contents, path.display().to_string())
    };
    serde_json::from_slice(&contents).with_context(|| format!("parsing SandboxSpec from {source}"))
}

/// A duration option's value in milliseconds. `example` shows the form.
pub(super) fn duration(option: &str, value: &str, example: &str) -> Result<u64> {
    parse_duration_ms(value)
        .ok()
        .with_context(|| format!("{option} needs a duration with a unit, such as {example}"))
}

pub(super) fn parse_assignments(
    values: &[String],
    option: &str,
) -> Result<BTreeMap<String, String>> {
    let mut assignments = BTreeMap::new();
    for value in values {
        let (key, value) = value
            .split_once('=')
            .with_context(|| format!("--{option} must use KEY=VALUE syntax"))?;
        if key.is_empty() {
            bail!("--{option} key must not be empty");
        }
        assignments.insert(key.to_owned(), value.to_owned());
    }
    Ok(assignments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_split_only_on_the_first_equals_sign() {
        let values = vec!["TOKEN=abc=123".to_owned()];
        let assignments = parse_assignments(&values, "env").expect("assignment parses");
        assert_eq!(assignments["TOKEN"], "abc=123");
    }

    #[test]
    fn assignments_require_a_nonempty_key() {
        let missing_equals =
            parse_assignments(&["TOKEN".to_owned()], "env").expect_err("missing equals fails");
        assert!(missing_equals.to_string().contains("KEY=VALUE"));

        let empty_key =
            parse_assignments(&["=value".to_owned()], "env").expect_err("empty key fails");
        assert!(empty_key.to_string().contains("key must not be empty"));
    }
}
