use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use sandbox_driver::{
    PreviewUrl, PreviewUrls, Result, SshAccess, SshAccessInfo, Vnc, VncConnection, WebTerminal,
};

use crate::{DaytonaClient, daytona_error};

const WEB_TERMINAL_PORT: u16 = 22_222;
const VNC_PORT: u16 = 6_080;
const BROWSER_ACCESS_TTL: Duration = Duration::from_secs(60 * 60);

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
            .map_err(|error| daytona_error("fetching sandbox", error))
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
            .map_err(|error| daytona_error("fetching preview link", error))?;
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
            .map_err(|error| daytona_error("fetching signed preview url", error))?;
        Ok(PreviewUrl::new(signed.url))
    }
}

#[async_trait]
impl SshAccess for DaytonaAccess {
    async fn ssh_access(&self, ttl: Option<Duration>) -> Result<SshAccessInfo> {
        let minutes = ttl.map(|ttl| ttl.as_secs_f64() / 60.0);
        let access = self
            .sdk()
            .await?
            .create_ssh_access(minutes)
            .await
            .map_err(|error| daytona_error("creating ssh access", error))?;
        let mut info = SshAccessInfo::new(access.ssh_command);
        info.token = Some(access.token);
        info.expires_at = ttl.and_then(|ttl| SystemTime::now().checked_add(ttl));
        Ok(info)
    }

    async fn revoke_ssh_access(&self, token: &str) -> Result<()> {
        self.sdk()
            .await?
            .revoke_ssh_access(token)
            .await
            .map_err(|error| daytona_error("revoking ssh access", error))
    }
}

#[async_trait]
impl WebTerminal for DaytonaAccess {
    async fn web_terminal_url(&self) -> Result<String> {
        Ok(self
            .signed_preview_url(WEB_TERMINAL_PORT, BROWSER_ACCESS_TTL)
            .await?
            .url)
    }
}

#[async_trait]
impl Vnc for DaytonaAccess {
    async fn vnc_connection(&self) -> Result<VncConnection> {
        let sandbox = self.sdk().await?;
        sandbox
            .computer_use()
            .await
            .map_err(|error| daytona_error("connecting to computer use", error))?
            .start()
            .await
            .map_err(|error| daytona_error("starting computer use", error))?;
        let signed = sandbox
            .get_signed_preview_url(
                i32::from(VNC_PORT),
                Some(
                    i32::try_from(BROWSER_ACCESS_TTL.as_secs())
                        .expect("browser access TTL fits in an i32"),
                ),
            )
            .await
            .map_err(|error| daytona_error("fetching signed VNC URL", error))?;
        Ok(VncConnection::new(vnc_viewer_url(&signed.url)))
    }
}

fn vnc_viewer_url(signed_url: &str) -> String {
    match signed_url.split_once('?') {
        Some((base, query)) => format!(
            "{}/vnc.html?{query}&autoconnect=true&resize=scale",
            base.trim_end_matches('/')
        ),
        None => format!(
            "{}/vnc.html?autoconnect=true&resize=scale",
            signed_url.trim_end_matches('/')
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::vnc_viewer_url;

    #[test]
    fn vnc_url_selects_the_browser_viewer_and_preserves_auth() {
        assert_eq!(
            vnc_viewer_url("https://preview.test/?token=secret"),
            "https://preview.test/vnc.html?token=secret&autoconnect=true&resize=scale"
        );
    }
}
