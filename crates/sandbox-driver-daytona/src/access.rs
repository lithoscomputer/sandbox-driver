use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{PreviewUrl, PreviewUrls, Result, SshAccess, SshAccessInfo};

use crate::{DaytonaClient, daytona_error};

/// Preview-URL and SSH access through the Daytona control plane.
pub struct DaytonaAccess {
    client:     DaytonaClient,
    sandbox_id: String,
}

impl DaytonaAccess {
    pub(crate) fn new(client: DaytonaClient, sandbox_id: String) -> Self {
        Self { client, sandbox_id }
    }

    async fn sdk(&self) -> Result<daytona_sdk::Sandbox> {
        self.client
            .get(&self.sandbox_id)
            .await
            .map_err(|error| daytona_error("fetching sandbox", &error))
    }
}

#[async_trait]
impl PreviewUrls for DaytonaAccess {
    async fn preview_url(&self, port: u16) -> Result<PreviewUrl> {
        let link = self
            .sdk()
            .await?
            .get_preview_link(port)
            .await
            .map_err(|error| daytona_error("fetching preview link", &error))?;
        let mut url = PreviewUrl::new(link.url);
        url.headers = BTreeMap::from([
            ("x-daytona-preview-token".to_owned(), link.token),
            (
                "X-Daytona-Skip-Preview-Warning".to_owned(),
                "true".to_owned(),
            ),
        ]);
        Ok(url)
    }

    async fn signed_preview_url(&self, port: u16, expires_in: Duration) -> Result<PreviewUrl> {
        let expires_secs = i32::try_from(expires_in.as_secs())
            .unwrap_or(i32::MAX)
            .max(1);
        let signed = self
            .sdk()
            .await?
            .get_signed_preview_url(i32::from(port), Some(expires_secs))
            .await
            .map_err(|error| daytona_error("fetching signed preview url", &error))?;
        Ok(PreviewUrl::new(signed.url))
    }
}

#[async_trait]
impl SshAccess for DaytonaAccess {
    async fn create_ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo> {
        let minutes = ttl.map(|ttl| (ttl.as_secs_f64() / 60.0).max(1.0));
        let access = self
            .sdk()
            .await?
            .create_ssh_access(minutes)
            .await
            .map_err(|error| daytona_error("creating ssh access", &error))?;
        let mut info = SshAccessInfo::new(access.ssh_command);
        info.token = Some(access.token);
        Ok(info)
    }

    async fn revoke_ssh_access(&self, token: &str) -> Result<()> {
        self.sdk()
            .await?
            .revoke_ssh_access(token)
            .await
            .map_err(|error| daytona_error("revoking ssh access", &error))
    }
}
