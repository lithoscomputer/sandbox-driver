//! Reaching a port inside a host sandbox: the sandbox is this machine, so
//! the port is the caller's own loopback port.

use async_trait::async_trait;
use sandbox_driver::{Error, PreviewUrl, PreviewUrls, Result};

/// Preview URLs for a directory-backed sandbox on the local machine.
pub(crate) struct HostPreview;

#[async_trait]
impl PreviewUrls for HostPreview {
    async fn preview_url(&self, port: u16) -> Result<PreviewUrl> {
        if port == 0 {
            return Err(Error::invalid_spec("port", "a preview URL needs a port"));
        }
        Ok(PreviewUrl::new(format!("http://127.0.0.1:{port}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preview_url_is_the_local_loopback_port() {
        let preview = HostPreview.preview_url(8080).await.expect("url");
        assert_eq!(preview.url, "http://127.0.0.1:8080");
        assert!(preview.headers.is_empty());
        HostPreview
            .release_preview_url(8080)
            .await
            .expect("nothing to release");
        assert!(matches!(
            HostPreview.preview_url(0).await,
            Err(Error::InvalidSpec { .. })
        ));
    }
}
