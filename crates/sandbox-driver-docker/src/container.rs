//! One container on the daemon, as every facet of a sandbox sees it: the
//! client, the container id, and the working directory relative paths
//! resolve against, with the daemon calls the facets share.

use std::io;
use std::pin::Pin;
use std::result::Result as StdResult;

use bollard::Docker;
use bollard::container::{InspectContainerOptions, LogOutput, RemoveContainerOptions};
use bollard::errors::Error as DockerApiError;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::{ContainerInspectResponse, ExecInspectResponse};
use futures_util::Stream;
use sandbox_driver::{Error, ResourceKind, Result};
use tokio::io::AsyncWrite;

use crate::daemon::{docker_error, is_not_found};
use crate::{one_shot, sidecars};

/// A started exec instance with its attached streams.
pub(crate) struct AttachedExec {
    pub(crate) id:     String,
    pub(crate) output: Pin<Box<dyn Stream<Item = StdResult<LogOutput, DockerApiError>> + Send>>,
    pub(crate) input:  Pin<Box<dyn AsyncWrite + Send>>,
}

/// One container and the client that reaches it.
#[derive(Clone)]
pub(crate) struct ContainerRef {
    pub(crate) docker:      Docker,
    pub(crate) id:          String,
    /// The sandbox working directory, which relative paths resolve
    /// against.
    pub(crate) working_dir: String,
}

impl ContainerRef {
    pub(crate) fn new(docker: Docker, id: String, working_dir: String) -> Self {
        Self {
            docker,
            id,
            working_dir,
        }
    }

    /// Resolves a path against the sandbox working directory; an absolute
    /// path stands as given. Every facet resolves the same way, and Docker
    /// rejects a relative exec `Cwd` outright.
    pub(crate) fn resolve(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{}", self.working_dir.trim_end_matches('/'), path)
        }
    }

    /// The directory a command runs in: `dir` resolved, or the sandbox
    /// working directory when none was given.
    pub(crate) fn resolve_dir(&self, dir: Option<&str>) -> String {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) => self.resolve(dir),
        }
    }

    /// Inspects the container; a missing one is [`Error::NotFound`].
    pub(crate) async fn inspect(&self) -> Result<ContainerInspectResponse> {
        inspect_container(&self.docker, &self.id).await
    }

    /// Creates an exec from `options` and starts it attached to its
    /// streams. `what` names the exec in errors: "stdio exec", say.
    pub(crate) async fn start_attached(
        &self,
        options: CreateExecOptions<String>,
        what: &str,
    ) -> Result<AttachedExec> {
        let exec = self
            .docker
            .create_exec(&self.id, options)
            .await
            .map_err(|error| docker_error(&format!("creating {what}"), error))?;
        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .map_err(|error| docker_error(&format!("starting {what}"), error))?;
        let StartExecResults::Attached { output, input } = start else {
            return Err(docker_error(
                &format!("starting {what}"),
                DockerApiError::IOError {
                    err: io::Error::other("exec started detached"),
                },
            ));
        };
        Ok(AttachedExec {
            id: exec.id,
            output,
            input,
        })
    }

    /// The exit code of an exec, once it has one.
    pub(crate) async fn exec_exit_code(&self, exec_id: &str) -> Result<Option<i32>> {
        let inspect = self
            .docker
            .inspect_exec(exec_id)
            .await
            .map_err(|error| docker_error("inspecting exec", error))?;
        Ok(exit_code_of(&inspect))
    }
}

/// The exit code an exec inspect reports, when it fits the type the
/// caller sees.
pub(crate) fn exit_code_of(inspect: &ExecInspectResponse) -> Option<i32> {
    inspect.exit_code.and_then(|code| i32::try_from(code).ok())
}

/// Inspects `container_id`; a missing container is [`Error::NotFound`].
pub(crate) async fn inspect_container(
    docker: &Docker,
    container_id: &str,
) -> Result<ContainerInspectResponse> {
    docker
        .inspect_container(container_id, None::<InspectContainerOptions>)
        .await
        .map_err(|error| {
            if is_not_found(&error) {
                Error::NotFound {
                    resource: ResourceKind::Sandbox,
                    id:       container_id.to_owned(),
                }
            } else {
                docker_error("inspecting container", error)
            }
        })
}

/// Removes a container, running or not, with its anonymous volumes. A
/// container already gone is fine; `context` names the removal in any
/// other failure.
pub(crate) async fn remove_container_forced(
    docker: &Docker,
    container_id: &str,
    context: &str,
) -> Result<()> {
    let options = RemoveContainerOptions {
        force: true,
        v: true,
        ..Default::default()
    };
    match docker.remove_container(container_id, Some(options)).await {
        Ok(()) => Ok(()),
        Err(error) if is_not_found(&error) => Ok(()),
        Err(error) => Err(docker_error(context, error)),
    }
}

/// Removes a sandbox's container and everything that depends on it.
/// One-shot containers hold the workspace volume too, so they go first
/// and the volume goes with its last user; the sidecar network follows,
/// then the container itself. A failure part-way keeps the container, so
/// the caller can retry the cleanup by label.
pub(crate) async fn remove_sandbox(
    docker: &Docker,
    container_id: &str,
    sidecar_network: Option<&str>,
) -> Result<()> {
    one_shot::sweep(docker, container_id).await?;
    if let Some(network) = sidecar_network {
        sidecars::sweep(docker, network, Some(container_id)).await?;
    }
    remove_container_forced(docker, container_id, "removing container").await
}
