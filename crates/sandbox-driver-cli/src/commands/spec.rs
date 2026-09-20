use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sandbox_driver::{ProviderKind, SandboxSource, SandboxSpec};
use tokio::fs::{read, read_to_string};
use tokio::io::{AsyncReadExt as _, stdin as async_stdin};

use super::is_host;
use crate::cli::CreateSpecArgs;

pub(super) async fn build_spec(args: &CreateSpecArgs, kind: &ProviderKind) -> Result<SandboxSpec> {
    let explicit_source = source_from_args(args).await?;
    let mut spec = base_spec(args, kind, explicit_source).await?;
    apply_overrides(&mut spec, args)?;
    spec.validate()
        .context("validating sandbox specification")?;
    Ok(spec)
}

/// Chooses the starting specification: the `--spec` document when given,
/// otherwise a fresh one from the explicit source, or the Host directory
/// default. An explicit source always wins over the document's.
async fn base_spec(
    args: &CreateSpecArgs,
    kind: &ProviderKind,
    explicit_source: Option<SandboxSource>,
) -> Result<SandboxSpec> {
    let Some(path) = &args.spec else {
        let source =
            explicit_source.or_else(|| is_host(kind).then_some(SandboxSource::HostDirectory));
        return Ok(SandboxSpec::new(source.context(
            "a creation source is required; use --image, --dockerfile, --snapshot, --host-directory, or --spec",
        )?));
    };
    let contents = read_local_input(path).await?;
    let mut spec: SandboxSpec = serde_json::from_slice(&contents)
        .with_context(|| format!("parsing SandboxSpec from {}", display_input(path)))?;
    if let Some(source) = explicit_source {
        spec.source = source;
    }
    Ok(spec)
}

/// Applies every field option to `spec`; an option that was not given
/// leaves the field as it is.
fn apply_overrides(spec: &mut SandboxSpec, args: &CreateSpecArgs) -> Result<()> {
    if let Some(name) = &args.name {
        spec.name = Some(name.clone());
    }
    if let Some(kind) = args.kind {
        spec.sandbox_kind = Some(kind.into());
    }
    spec.resources.cpu_cores = args.cpu.or(spec.resources.cpu_cores);
    spec.resources.memory_mb = args.memory_mb.or(spec.resources.memory_mb);
    spec.resources.disk_mb = args.disk_mb.or(spec.resources.disk_mb);
    spec.resources.gpus = args.gpus.or(spec.resources.gpus);
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
    Ok(())
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
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command, SandboxCommand};

    fn create_args(options: &[&str]) -> CreateSpecArgs {
        let cli = Cli::try_parse_from(
            ["lithos-sandbox", "sandbox", "create"]
                .into_iter()
                .chain(options.iter().copied()),
        )
        .expect("create options parse");
        let Command::Sandbox { command } = cli.command else {
            panic!("expected sandbox command");
        };
        let SandboxCommand::Create(args) = *command else {
            panic!("expected sandbox create");
        };
        args.spec
    }

    #[test]
    fn overrides_replace_only_the_given_fields() {
        let mut spec = SandboxSpec::new(SandboxSource::HostDirectory);
        spec.name = Some("from-spec".to_owned());
        spec.resources.cpu_cores = Some(1);
        spec.resources.memory_mb = Some(512);
        spec.env.insert("KEEP".to_owned(), "yes".to_owned());

        let args = create_args(&["--cpu", "2", "--env", "ADDED=1"]);
        apply_overrides(&mut spec, &args).expect("overrides apply");

        assert_eq!(spec.name.as_deref(), Some("from-spec"));
        assert_eq!(spec.resources.cpu_cores, Some(2));
        assert_eq!(spec.resources.memory_mb, Some(512));
        assert_eq!(spec.env["KEEP"], "yes");
        assert_eq!(spec.env["ADDED"], "1");
    }

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
