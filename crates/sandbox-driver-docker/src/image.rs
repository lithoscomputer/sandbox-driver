//! Image presence and pulls against the daemon, shared by the main image,
//! sidecars, and one-shot containers.

use bollard::Docker;
use bollard::image::CreateImageOptions;
use futures_util::StreamExt;
use sandbox_driver::Result;

use crate::config::{RegistryAuth, to_credentials};
use crate::daemon::{docker_error, is_not_found};

/// Whether the daemon has `reference` locally. Only a definitive "not
/// present" is `false`; a daemon or transport failure surfaces as what
/// it is.
pub(crate) async fn image_present(docker: &Docker, reference: &str) -> Result<bool> {
    match docker.inspect_image(reference).await {
        Ok(_) => Ok(true),
        Err(error) if is_not_found(&error) => Ok(false),
        Err(error) => Err(docker_error("inspecting image", error)),
    }
}

/// Pulls an image, using registry credentials when given, and waits for
/// the pull to finish. Shared by the main-image path and sidecars.
pub(crate) async fn pull_image(
    docker: &Docker,
    reference: &str,
    auth: Option<&RegistryAuth>,
    platform: Option<&str>,
) -> Result<()> {
    let credentials = auth.map(to_credentials);
    let mut stream =
        docker.create_image(Some(pull_options(reference, platform)), None, credentials);
    while let Some(progress) = stream.next().await {
        progress.map_err(|error| docker_error("pulling image", error))?;
    }
    Ok(())
}

/// Splits an image reference for the pull API. An empty tag pulls every
/// tag of the repository, so bare references default to `latest`; digest
/// references pass through whole.
fn pull_options(reference: &str, platform: Option<&str>) -> CreateImageOptions<'static, String> {
    let platform = platform.unwrap_or_default().to_owned();
    if reference.contains('@') {
        return CreateImageOptions {
            from_image: reference.to_owned(),
            platform,
            ..Default::default()
        };
    }
    // A colon only marks a tag when the remainder has no `/` — otherwise
    // it is a registry port (`registry:5000/img`).
    let (repo, tag) = match reference.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => (repo.to_owned(), tag.to_owned()),
        _ => (reference.to_owned(), "latest".to_owned()),
    };
    CreateImageOptions {
        from_image: repo,
        tag,
        platform,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_options_default_a_bare_reference_to_latest() {
        let options = pull_options("ubuntu", None);
        assert_eq!(options.from_image, "ubuntu");
        assert_eq!(options.tag, "latest");
    }

    #[test]
    fn pull_options_split_an_explicit_tag() {
        let options = pull_options("debian:stable-slim", None);
        assert_eq!(options.from_image, "debian");
        assert_eq!(options.tag, "stable-slim");
    }

    #[test]
    fn pull_options_treat_a_registry_port_as_untagged() {
        let options = pull_options("registry:5000/img", None);
        assert_eq!(options.from_image, "registry:5000/img");
        assert_eq!(options.tag, "latest");
    }

    #[test]
    fn pull_options_pass_digest_references_through() {
        let options = pull_options("img@sha256:abc123", None);
        assert_eq!(options.from_image, "img@sha256:abc123");
        assert_eq!(options.tag, "");
    }
}
