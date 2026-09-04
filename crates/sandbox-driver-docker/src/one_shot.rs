//! One-shot containers beside a Docker sandbox.
//!
//! A one-shot container is created from its own image, mounts the
//! sandbox's workspace volume at the sandbox's working directory, joins
//! the sandbox container's network namespace (so it reaches sidecars by
//! alias and the daemon host by the same names), runs one command, and is
//! removed. It carries [`ONE_SHOT_LABEL`] naming its sandbox, which is how
//! the sandbox's `stop` and `delete` find and end any left running by a
//! caller that went away.
//!
//! Output streams through an attach, stops are signals to the container
//! (`term` sends SIGTERM once, `kill` and the timeout send SIGKILL), and
//! the exit code is the container's own.

use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::io::Cursor;
use std::pin::pin;
use std::time::{Duration, Instant};
use std::{future, io};

use async_trait::async_trait;
use bollard::Docker;
use bollard::container::{
    AttachContainerOptions, Config, CreateContainerOptions, DownloadFromContainerOptions,
    KillContainerOptions, ListContainersOptions, RemoveContainerOptions, StartContainerOptions,
    WaitContainerOptions,
};
use bollard::errors::Error as DockerApiError;
use bollard::image::BuildImageOptions;
use bollard::models::{HostConfig, Mount};
use futures_util::StreamExt;
use sandbox_driver::{
    Error, ExecControls, ExecStreamingResult, OneShot, OneShotImage, OneShotSpec, ProviderError,
    Result, Termination, stop_signal,
};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::exec::{StreamOutput, docker_error, docker_kind, is_conflict, is_not_found};
use crate::{MANAGED_LABEL, image_present, non_empty, pull_image};

/// The label every one-shot container carries, naming the sandbox it
/// belongs to (the sandbox container's id).
pub(crate) const ONE_SHOT_LABEL: &str = "sh.sandbox-driver.one-shot";
/// The one fallback platform: CI images target linux/amd64, so an image
/// with no manifest for the daemon's architecture is pulled as amd64.
const FALLBACK_PLATFORM: &str = "linux/amd64";
/// Grace period for draining output after a kill.
const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);

/// The one-shot facet of one Docker sandbox.
pub(crate) struct DockerOneShot {
    docker:       Docker,
    container_id: String,
    working_dir:  String,
    /// The shared workspace mount, including the sandbox's access mode.
    workspace:    Mount,
}

impl DockerOneShot {
    pub(crate) fn new(
        docker: Docker,
        container_id: String,
        working_dir: String,
        workspace: Mount,
    ) -> Self {
        Self {
            docker,
            container_id,
            working_dir,
            workspace,
        }
    }

    /// Pulls a registry image, retrying once for the fallback platform
    /// when the daemon's own has no manifest.
    async fn ensure_registry_image(&self, reference: &str) -> Result<()> {
        if image_present(&self.docker, reference).await? {
            return Ok(());
        }
        let Err(error) = pull_image(&self.docker, reference, None, None).await else {
            return Ok(());
        };
        if !is_missing_platform(&error) {
            return Err(error);
        }
        pull_image(&self.docker, reference, None, Some(FALLBACK_PLATFORM))
            .await
            .map_err(|_| error)?;
        tracing::warn!(
            provider_kind = "docker",
            platform = FALLBACK_PLATFORM,
            "one-shot image pulled for a fallback platform"
        );
        Ok(())
    }

    /// Builds an image from a Dockerfile inside the sandbox's workspace,
    /// reading the context out through the archive API.
    async fn build_image(
        &self,
        context: &str,
        dockerfile: Option<&str>,
        tag: &str,
        reuse: bool,
    ) -> Result<()> {
        if reuse && image_present(&self.docker, tag).await? {
            return Ok(());
        }
        let context_path = if context.starts_with('/') {
            context.to_owned()
        } else {
            format!("{}/{}", self.working_dir.trim_end_matches('/'), context)
        };
        let options = DownloadFromContainerOptions {
            path: context_path.clone(),
        };
        let mut stream = self
            .docker
            .download_from_container(&self.container_id, Some(options));
        let mut archive = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| docker_error("reading build context", error))?;
            archive.extend_from_slice(&chunk);
        }
        let context_tar = strip_leading_component(&archive)?;
        let options = BuildImageOptions {
            dockerfile: dockerfile.unwrap_or("Dockerfile").to_owned(),
            t: tag.to_owned(),
            rm: true,
            ..Default::default()
        };
        let mut build = self
            .docker
            .build_image(options, None, Some(context_tar.into()));
        while let Some(info) = build.next().await {
            let info = info.map_err(|error| docker_error("building image", error))?;
            if let Some(message) = info.error {
                let mut provider =
                    ProviderError::new(docker_kind(), format!("image build failed: {message}"));
                provider.code = Some("build".to_owned());
                return Err(Error::Provider(provider));
            }
        }
        Ok(())
    }

    async fn prepare_image(&self, image: &OneShotImage) -> Result<String> {
        match image {
            OneShotImage::Registry { reference } => {
                self.ensure_registry_image(reference).await?;
                Ok(reference.clone())
            }
            OneShotImage::Build {
                context,
                dockerfile,
                tag,
                reuse,
            } => {
                self.build_image(context, dockerfile.as_deref(), tag, *reuse)
                    .await?;
                Ok(tag.clone())
            }
            _ => Err(Error::invalid_spec("image", "unsupported one-shot image")),
        }
    }

    async fn signal(&self, container: &str, signal: &str) {
        let outcome = self
            .docker
            .kill_container(container, Some(KillContainerOptions { signal }))
            .await;
        match outcome {
            Ok(()) => {}
            // Already gone or already stopped: the stop has nothing to do.
            Err(error) if is_not_found(&error) || is_conflict(&error) => {}
            Err(error) => {
                tracing::warn!(
                    provider_kind = "docker",
                    error = %docker_error("signalling one-shot container", error),
                    "one-shot stop request failed"
                );
            }
        }
    }
}

fn is_missing_platform(error: &Error) -> bool {
    let mut source: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(current) = source {
        if current.to_string().contains("no matching manifest") {
            return true;
        }
        source = current.source();
    }
    false
}

/// Re-roots an archive of one directory so its contents sit at the top
/// level, as a build context expects: `dir/Dockerfile` becomes
/// `Dockerfile`.
fn strip_leading_component(archive: &[u8]) -> Result<Vec<u8>> {
    let tar_io = |error| Error::io("re-rooting build context", error);
    let mut source = tar::Archive::new(Cursor::new(archive));
    let mut builder = tar::Builder::new(Vec::new());
    for entry in source.entries().map_err(tar_io)? {
        let mut entry = entry.map_err(tar_io)?;
        let path = entry.path().map_err(tar_io)?.into_owned();
        let mut components = path.components();
        components.next();
        let rest = components.as_path().to_path_buf();
        if rest.as_os_str().is_empty() {
            continue;
        }
        let mut header = entry.header().clone();
        if header.entry_type().is_dir() {
            builder
                .append_data(&mut header, rest, io::empty())
                .map_err(tar_io)?;
        } else if header.entry_type().is_symlink() || header.entry_type().is_hard_link() {
            let mut link = entry
                .link_name()
                .map_err(tar_io)?
                .map(Cow::into_owned)
                .unwrap_or_default();
            // Hard-link targets are archive-root paths; symlink targets
            // remain relative to the symlink itself.
            if header.entry_type().is_hard_link() {
                let mut components = link.components();
                components.next();
                link = components.as_path().to_path_buf();
            }
            builder
                .append_link(&mut header, rest, link)
                .map_err(tar_io)?;
        } else {
            builder
                .append_data(&mut header, rest, &mut entry)
                .map_err(tar_io)?;
        }
    }
    builder.into_inner().map_err(tar_io)
}

fn one_shot_filter(sandbox_id: &str) -> ListContainersOptions<String> {
    let mut filters = HashMap::new();
    filters.insert("label".to_owned(), vec![format!(
        "{ONE_SHOT_LABEL}={sandbox_id}"
    )]);
    ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    }
}

/// Removes every one-shot container of `sandbox_id`, running or not.
/// Best-effort, as the sidecar sweep is: a missing container is fine.
pub(crate) async fn sweep(docker: &Docker, sandbox_id: &str) {
    let Ok(containers) = docker
        .list_containers(Some(one_shot_filter(sandbox_id)))
        .await
    else {
        return;
    };
    for container in containers {
        if let Some(id) = container.id {
            let _ = docker
                .remove_container(
                    &id,
                    Some(RemoveContainerOptions {
                        force: true,
                        v: true,
                        ..Default::default()
                    }),
                )
                .await;
        }
    }
}

#[async_trait]
impl OneShot for DockerOneShot {
    #[tracing::instrument(
        skip_all,
        fields(provider_kind = "docker", sandbox_id = %self.container_id),
        err
    )]
    async fn run(&self, spec: &OneShotSpec, controls: ExecControls) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        // An already cancelled run does not pull an image or create a
        // container. Image preparation shares the operation's deadline.
        let deadline = async {
            match spec.timeout {
                Some(timeout) if started.elapsed() < timeout => {
                    time::sleep(timeout.saturating_sub(started.elapsed())).await;
                }
                Some(_) => {}
                None => future::pending().await,
            }
        };
        let prepared = tokio::select! {
            biased;
            () = stop_signal(controls.kill.as_ref()) => Err(Termination::Killed),
            () = stop_signal(controls.term.as_ref()) => Err(Termination::Cancelled),
            () = deadline => Err(Termination::TimedOut),
            image = self.prepare_image(&spec.image) => Ok(image?),
        };
        let image = match prepared {
            Ok(image) => image,
            Err(termination) => {
                return Ok(StreamOutput::new(
                    spec.output_sanitization,
                    controls.retained_output_limit,
                )
                .into_result(termination, None, started.elapsed(), false));
            }
        };

        let mut labels = HashMap::new();
        labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
        labels.insert(ONE_SHOT_LABEL.to_owned(), self.container_id.clone());
        let host_config = HostConfig {
            network_mode: Some(format!("container:{}", self.container_id)),
            mounts: Some(vec![self.workspace.clone()]),
            init: Some(true),
            ..Default::default()
        };
        let env: Vec<String> = spec
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        let config = Config {
            image: Some(image),
            entrypoint: spec.entrypoint.clone().map(|entrypoint| vec![entrypoint]),
            cmd: non_empty(spec.args.clone()),
            env: non_empty(env),
            working_dir: Some(
                spec.working_dir
                    .clone()
                    .unwrap_or_else(|| self.working_dir.clone()),
            ),
            labels: Some(labels),
            host_config: Some(host_config),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };
        let created = self
            .docker
            .create_container(None::<CreateContainerOptions<String>>, config)
            .await
            .map_err(|error| docker_error("creating one-shot container", error))?;
        let container = created.id;
        let remove = |docker: Docker, container: String| async move {
            let _ = docker
                .remove_container(
                    &container,
                    Some(RemoveContainerOptions {
                        force: true,
                        v: true,
                        ..Default::default()
                    }),
                )
                .await;
        };

        let attached = match self
            .docker
            .attach_container(
                &container,
                Some(AttachContainerOptions::<String> {
                    stdout: Some(true),
                    stderr: Some(true),
                    stream: Some(true),
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(attached) => attached,
            Err(error) => {
                remove(self.docker.clone(), container).await;
                return Err(docker_error("attaching one-shot container", error));
            }
        };
        let output = attached.output;
        if let Err(error) = self
            .docker
            .start_container(&container, None::<StartContainerOptions<String>>)
            .await
        {
            remove(self.docker.clone(), container).await;
            return Err(docker_error("starting one-shot container", error));
        }

        let mut captured =
            StreamOutput::new(spec.output_sanitization, controls.retained_output_limit);
        let sink_failed = CancellationToken::new();
        let mut termination = Termination::Exited;
        let mut term_fired = false;
        let mut kill_fired = false;
        let mut drain_deadline: Option<Instant> = None;
        let mut termed = pin!(stop_signal(controls.term.as_ref()));
        let mut killed = pin!(stop_signal(controls.kill.as_ref()));
        let (stream_result, truncated) = {
            let mut drain = pin!(captured.drain(output, controls.sink.as_ref(), &sink_failed));
            loop {
                let timeout = async {
                    match spec.timeout {
                        Some(timeout) if !kill_fired => {
                            time::sleep(timeout.saturating_sub(started.elapsed())).await;
                        }
                        _ => future::pending().await,
                    }
                };
                let drain_timeout = async {
                    match drain_deadline {
                        Some(deadline) => time::sleep_until(deadline.into()).await,
                        None => future::pending().await,
                    }
                };
                tokio::select! {
                    outcome = &mut drain => break (outcome, false),
                    () = sink_failed.cancelled(), if !kill_fired => {
                        termination = Termination::Cancelled;
                        kill_fired = true;
                        drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                        self.signal(&container, "SIGKILL").await;
                    }
                    () = &mut termed, if !term_fired && !kill_fired => {
                        termination = Termination::Cancelled;
                        term_fired = true;
                        self.signal(&container, "SIGTERM").await;
                    }
                    () = &mut killed, if !kill_fired => {
                        termination = Termination::Killed;
                        kill_fired = true;
                        drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                        self.signal(&container, "SIGKILL").await;
                    }
                    () = timeout => {
                        termination = Termination::TimedOut;
                        kill_fired = true;
                        drain_deadline = Some(Instant::now() + KILL_DRAIN_GRACE);
                        self.signal(&container, "SIGKILL").await;
                    }
                    () = drain_timeout => break (Ok(()), true),
                }
            }
        };
        if sink_failed.is_cancelled() && !kill_fired {
            termination = Termination::Cancelled;
            self.signal(&container, "SIGKILL").await;
        }

        // The exit code, from the daemon's own wait; a container the drain
        // deadline abandoned may still be running, and the removal below
        // ends it.
        let exit_code = if stream_result.is_ok() {
            let mut wait = self.docker.wait_container(
                &container,
                Some(WaitContainerOptions {
                    condition: "not-running",
                }),
            );
            // Bollard reports a non-zero status as an error variant that
            // still carries the code; both shapes are the container's exit.
            match time::timeout(KILL_DRAIN_GRACE, wait.next()).await {
                Ok(Some(Ok(response))) => i32::try_from(response.status_code).ok(),
                Ok(Some(Err(DockerApiError::DockerContainerWaitError { code, .. }))) => {
                    i32::try_from(code).ok()
                }
                _ => None,
            }
        } else {
            None
        };
        remove(self.docker.clone(), container).await;
        stream_result.map_err(|error| docker_error("reading one-shot output", error))?;

        // A container that vanished under the run — the sandbox's stop or
        // delete swept it — ended, but not by exiting: nobody observed how.
        let termination = if termination == Termination::Exited && exit_code.is_none() {
            Termination::Unknown
        } else {
            termination
        };
        Ok(captured.into_result(termination, exit_code, started.elapsed(), truncated))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn the_build_context_is_re_rooted() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        builder
            .append_data(&mut dir, "action/", io::empty())
            .expect("dir");
        let mut file = tar::Header::new_gnu();
        file.set_size(4);
        file.set_mode(0o644);
        builder
            .append_data(&mut file, "action/Dockerfile", Cursor::new(b"FROM"))
            .expect("file");
        let archive = builder.into_inner().expect("tar");
        let rerooted = strip_leading_component(&archive).expect("re-root");
        let mut archive = tar::Archive::new(Cursor::new(rerooted));
        let paths: Vec<String> = archive
            .entries()
            .expect("entries")
            .map(|entry| {
                entry
                    .expect("entry")
                    .path()
                    .expect("path")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(paths, ["Dockerfile"]);
    }

    #[test]
    fn build_context_links_keep_their_targets_after_re_rooting() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut file = tar::Header::new_gnu();
        file.set_size(4);
        file.set_mode(0o644);
        builder
            .append_data(&mut file, "action/source", Cursor::new(b"data"))
            .expect("file");
        for (kind, path, target) in [
            (tar::EntryType::Link, "action/hard", "action/source"),
            (tar::EntryType::Symlink, "action/sub/soft", "../source"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            builder
                .append_link(&mut header, path, target)
                .expect("link");
        }
        let original = builder.into_inner().expect("archive");
        let rewritten = strip_leading_component(&original).expect("re-root");
        let mut archive = tar::Archive::new(rewritten.as_slice());
        let links: Vec<_> = archive
            .entries()
            .expect("entries")
            .map(|entry| entry.expect("entry"))
            .filter_map(|entry| entry.link_name().expect("link name").map(Cow::into_owned))
            .collect();
        assert_eq!(links, [PathBuf::from("source"), PathBuf::from("../source")]);
    }

    #[tokio::test]
    async fn cancelled_one_shots_do_not_prepare_an_image() {
        let docker =
            Docker::connect_with_http("http://127.0.0.1:1", 1, bollard::API_DEFAULT_VERSION)
                .expect("client");
        let runner = DockerOneShot::new(
            docker,
            "missing".to_owned(),
            "/workspace".to_owned(),
            Mount::default(),
        );
        let token = CancellationToken::new();
        token.cancel();
        for (controls, expected) in [
            (
                ExecControls {
                    term: Some(token.clone()),
                    ..ExecControls::default()
                },
                Termination::Cancelled,
            ),
            (
                ExecControls {
                    kill: Some(token.clone()),
                    ..ExecControls::default()
                },
                Termination::Killed,
            ),
        ] {
            let result = runner
                .run(&OneShotSpec::registry("unreachable"), controls)
                .await
                .expect("stopped");
            assert_eq!(result.result.termination, expected);
            assert_eq!(result.result.exit_code, None);
        }
    }

    #[tokio::test]
    async fn image_preparation_obeys_the_operation_deadline() {
        // This socket accepts connections but never answers Docker requests.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let docker = Docker::connect_with_http(
            &format!("http://{}", listener.local_addr().expect("address")),
            60,
            bollard::API_DEFAULT_VERSION,
        )
        .expect("client");
        let runner = DockerOneShot::new(
            docker,
            "missing".to_owned(),
            "/workspace".to_owned(),
            Mount::default(),
        );
        let spec = OneShotSpec::registry("unreachable").timeout(Duration::from_millis(20));
        let result = time::timeout(
            Duration::from_secs(2),
            runner.run(&spec, ExecControls::default()),
        )
        .await
        .expect("preparation deadline")
        .expect("timed out run");
        assert_eq!(result.result.termination, Termination::TimedOut);
        assert_eq!(result.result.exit_code, None);
    }
}
