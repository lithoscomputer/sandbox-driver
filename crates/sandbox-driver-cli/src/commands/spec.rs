use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{SandboxSource, SandboxSpec};
use tokio::fs::{read, read_to_string};
use tokio::io::{AsyncReadExt as _, stdin as async_stdin};

use crate::cli::CreateSpecArgs;

pub(super) async fn build_spec(
    args: &CreateSpecArgs,
    provider_kind: &str,
    running_one_shot: bool,
) -> Result<SandboxSpec> {
    let explicit_source = source_from_args(args).await?;
    let mut spec = if let Some(path) = &args.spec {
        let contents = read_local_input(path).await?;
        serde_json::from_slice(&contents)
            .with_context(|| format!("parsing SandboxSpec from {}", display_input(path)))?
    } else {
        let source = explicit_source
            .clone()
            .or_else(|| (provider_kind == "host").then_some(SandboxSource::HostDirectory));
        SandboxSpec::new(source.context(
            "a creation source is required; use --image, --dockerfile, --snapshot, --host-directory, or --spec",
        )?)
    };

    if let Some(source) = explicit_source {
        spec.source = source;
    }
    if let Some(name) = &args.name {
        spec.name = Some(name.clone());
    }
    if let Some(kind) = args.kind {
        spec.sandbox_kind = Some(kind.into());
    }
    if args.cpu.is_some()
        || args.memory_mb.is_some()
        || args.disk_mb.is_some()
        || args.gpus.is_some()
    {
        let mut resources = spec.resources;
        resources.cpu_cores = args.cpu.or(resources.cpu_cores);
        resources.memory_mb = args.memory_mb.or(resources.memory_mb);
        resources.disk_mb = args.disk_mb.or(resources.disk_mb);
        resources.gpus = args.gpus.or(resources.gpus);
        spec.resources = resources;
    }
    spec.env.extend(parse_assignments(&args.env, "env")?);
    spec.labels
        .extend(parse_assignments(&args.labels, "label")?);
    if let Some(directory) = &args.working_directory {
        spec.working_directory = Some(directory.clone());
    }
    if let Some(network) = args.network {
        spec.network = network.into();
    }
    if let Some(region) = &args.region {
        spec.region = Some(region.clone());
    }
    if args.ephemeral {
        spec.ephemeral = true;
    }
    if let Some(provider_config) = &args.provider_config {
        spec.provider_config =
            serde_json::from_str(provider_config).context("parsing --provider-config as JSON")?;
    }

    if running_one_shot && provider_kind == "host" && spec.working_directory.is_none() {
        tracing::debug!("Host run will use a managed temporary workspace");
    }
    spec.validate()
        .context("validating sandbox specification")?;
    Ok(spec)
}

async fn source_from_args(args: &CreateSpecArgs) -> Result<Option<SandboxSource>> {
    if let Some(reference) = &args.image {
        return Ok(Some(SandboxSource::Image {
            reference: reference.clone(),
        }));
    }
    if let Some(path) = &args.dockerfile {
        let content = read_to_string(path)
            .await
            .with_context(|| format!("reading Dockerfile from {}", path.display()))?;
        return Ok(Some(SandboxSource::Dockerfile { content }));
    }
    if let Some(id) = &args.snapshot {
        return Ok(Some(SandboxSource::Snapshot {
            id: sandbox_driver::SnapshotId::try_new(id.clone())
                .context("validating snapshot ID")?,
        }));
    }
    Ok(args.host_directory.then_some(SandboxSource::HostDirectory))
}

async fn read_local_input(path: &Path) -> Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut contents = Vec::new();
        async_stdin()
            .read_to_end(&mut contents)
            .await
            .context("reading stdin")?;
        return Ok(contents);
    }
    read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))
}

fn display_input(path: &Path) -> String {
    if path == Path::new("-") {
        "stdin".to_owned()
    } else {
        path.display().to_string()
    }
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
