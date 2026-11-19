use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::{Context as _, Result};
use sandbox_driver::{
    Descriptor, Environment, EnvironmentName, Exposure, FileEntry, Found, Health, ProviderEntry,
    ProviderName, SandboxRef, Source, Status,
};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncWriteExt as _, stderr, stdout};

use crate::cli::OutputFormat;

/// How a sandbox is named on the command line: `<entry>/<id>`.
pub(crate) fn display_ref(reference: &SandboxRef) -> String {
    format!("{}/{}", reference.provider, reference.id)
}

#[derive(Serialize)]
struct ProviderRow<'a> {
    name:   &'a ProviderName,
    plugin: &'a str,
    path:   Option<&'a str>,
}

pub(crate) async fn write_providers(
    entries: &BTreeMap<ProviderName, ProviderEntry>,
    format: OutputFormat,
) -> Result<()> {
    let rows: Vec<_> = entries
        .iter()
        .map(|(name, entry)| ProviderRow {
            name,
            plugin: entry.plugin.as_str(),
            path: entry.path.as_deref(),
        })
        .collect();
    match format {
        OutputFormat::Json => write_json(&rows).await,
        OutputFormat::Id => write_lines(rows.iter().map(|row| row.name.to_string())).await,
        OutputFormat::Table => {
            let mut rendered = String::from("NAME\tPLUGIN\tPATH\n");
            for row in &rows {
                let path = row.path.unwrap_or("built in");
                let _ = writeln!(rendered, "{}\t{}\t{path}", row.name, row.plugin);
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_environments(
    environments: &[(EnvironmentName, Environment)],
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let map: serde_json::Map<_, _> = environments
                .iter()
                .map(|(name, environment)| {
                    serde_json::to_value(environment).map(|value| (name.to_string(), value))
                })
                .collect::<Result<_, _>>()
                .context("serializing environments")?;
            write_json(&map).await
        }
        OutputFormat::Id => {
            write_lines(environments.iter().map(|(name, _)| name.to_string())).await
        }
        OutputFormat::Table => {
            let mut rendered = String::from("NAME\tPROVIDER\tSOURCE\n");
            for (name, environment) in environments {
                let _ = writeln!(
                    rendered,
                    "{name}\t{}\t{}",
                    environment.provider,
                    summarize_source(&environment.spec.source)
                );
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

/// `image ubuntu:24.04`, `dockerfile`, `snapshot base` or `host_directory`.
/// A Dockerfile's content is never printed.
fn summarize_source(source: &Source) -> String {
    match source {
        Source::Image(image) => format!("image {image}"),
        Source::Dockerfile(_) => "dockerfile".to_owned(),
        Source::Snapshot(snapshot) => format!("snapshot {snapshot}"),
        Source::HostDirectory => "host_directory".to_owned(),
    }
}

pub(crate) async fn write_descriptor(
    entry: &str,
    descriptor: &Descriptor,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(descriptor).await,
        OutputFormat::Id => write_line(descriptor.namespace.id.as_str()).await,
        OutputFormat::Table => {
            let mut rendered = format!(
                "provider: {entry}\nplugin: {} {}\n",
                descriptor.schemas.kind, descriptor.schemas.version
            );
            let Value::Object(fields) =
                serde_json::to_value(descriptor).context("serializing descriptor")?
            else {
                unreachable!("a descriptor serializes as an object");
            };
            for (key, value) in fields.iter().filter(|(key, _)| *key != "schemas") {
                let _ = writeln!(rendered, "{key}: {}", render_value(value));
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_health(entry: &str, health: &Health, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(health).await,
        OutputFormat::Table | OutputFormat::Id => {
            let status = if health.healthy { "ok" } else { "unhealthy" };
            let mut rendered = format!("provider: {entry}\nstatus: {status}\n");
            if let Some(message) = &health.message {
                let _ = writeln!(rendered, "message: {message}");
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_status(status: &Status, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(status).await,
        OutputFormat::Id => write_line(&display_ref(&status.reference)).await,
        OutputFormat::Table => {
            let Value::Object(fields) =
                serde_json::to_value(status).context("serializing status")?
            else {
                unreachable!("a status serializes as an object");
            };
            let mut rendered = format!("sandbox: {}\n", display_ref(&status.reference));
            for (key, value) in &fields {
                // An object with no fields set, or none at all, says nothing.
                let empty = value.is_null()
                    || value
                        .as_object()
                        .is_some_and(|map| map.values().all(Value::is_null));
                if key != "reference" && !empty {
                    let _ = writeln!(rendered, "{key}: {}", render_value(value));
                }
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_found(found: &Found, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(&found.sandboxes).await?,
        OutputFormat::Id => {
            write_lines(
                found
                    .sandboxes
                    .iter()
                    .map(|summary| display_ref(&summary.reference)),
            )
            .await?;
        }
        OutputFormat::Table => {
            let mut rendered = String::from("SANDBOX\tNAME\tSTATE\tLABELS\n");
            for summary in &found.sandboxes {
                let labels: Vec<_> = summary
                    .labels
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect();
                let _ = writeln!(
                    rendered,
                    "{}\t{}\t{}\t{}",
                    display_ref(&summary.reference),
                    summary.name.as_deref().unwrap_or(""),
                    render_value(&serde_json::to_value(summary.state)?),
                    labels.join(",")
                );
            }
            write_stdout(rendered.as_bytes()).await?;
        }
    }
    // Skipped entries are reported, never read as having no sandboxes.
    let mut warnings = String::new();
    for failure in &found.failures {
        let _ = writeln!(
            warnings,
            "warning: provider {} was not searched: {}",
            failure.entry, failure.error
        );
    }
    write_stderr(warnings.as_bytes()).await
}

pub(crate) async fn write_files(entries: &[FileEntry], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(entries).await,
        OutputFormat::Id => write_lines(entries.iter().map(|entry| entry.path.clone())).await,
        OutputFormat::Table => {
            let mut rendered = String::from("KIND\tSIZE\tPATH\n");
            for entry in entries {
                let kind = render_value(&serde_json::to_value(entry.kind)?);
                let _ = writeln!(rendered, "{kind}\t{}\t{}", entry.size, entry.path);
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

pub(crate) async fn write_exposure(exposure: &Exposure, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(exposure).await,
        OutputFormat::Id => write_line(&exposure.url).await,
        OutputFormat::Table => {
            let mut rendered = format!("url: {}\n", exposure.url);
            for (name, value) in &exposure.headers {
                let _ = writeln!(rendered, "header: {name}: {value}");
            }
            if let Some(expires) = exposure.expires_at_ms {
                let _ = writeln!(rendered, "expires_at_ms: {expires}");
            }
            write_stdout(rendered.as_bytes()).await
        }
    }
}

/// Reports a completed action on one sandbox, such as `stopped docker/1a2b`.
pub(crate) async fn write_action(
    reference: &SandboxRef,
    action: &str,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            write_json(&serde_json::json!({ "sandbox": reference, "action": action })).await
        }
        OutputFormat::Id => write_line(&display_ref(reference)).await,
        OutputFormat::Table => write_line(&format!("{action} {}", display_ref(reference))).await,
    }
}

/// One line per value: strings bare, lists joined, anything else as
/// compact JSON.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) if items.is_empty() => "none".to_owned(),
        Value::Array(items) => items
            .iter()
            .map(render_value)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

async fn write_lines(lines: impl Iterator<Item = String>) -> Result<()> {
    let mut rendered = String::new();
    for line in lines {
        rendered.push_str(&line);
        rendered.push('\n');
    }
    write_stdout(rendered.as_bytes()).await
}

pub(crate) async fn write_line(value: &str) -> Result<()> {
    write_stdout(format!("{value}\n").as_bytes()).await
}

pub(crate) async fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut output = stdout();
    output.write_all(bytes).await.context("writing stdout")?;
    output.flush().await.context("flushing stdout")
}

pub(crate) async fn write_stderr(bytes: &[u8]) -> Result<()> {
    let mut output = stderr();
    output.write_all(bytes).await.context("writing stderr")?;
    output.flush().await.context("flushing stderr")
}

pub(crate) async fn write_json<T>(value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let mut rendered = serde_json::to_vec_pretty(value).context("serializing JSON output")?;
    rendered.push(b'\n');
    write_stdout(&rendered).await
}
