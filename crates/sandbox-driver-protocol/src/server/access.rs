//! `access/*` and `git/clone`: the sandbox facets a host reaches by
//! request rather than by stream.

use std::sync::Arc;
use std::time::Duration;

use sandbox_driver::{Capability, Error, Git};
use serde_json::Value;

use super::{DispatchError, ServerState, parse, to_value};
use crate::methods as m;

pub(super) async fn dispatch(
    state: &Arc<ServerState>,
    method: &str,
    params: Value,
) -> Result<Value, DispatchError> {
    match method {
        m::GIT_CLONE => {
            let request: m::GitCloneParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            // The sandbox selects native, hybrid, or derived git exactly as
            // it does in-process, so a host sees one clone implementation
            // regardless of transport.
            let git = handle
                .git()
                .ok_or_else(|| Error::unsupported(Capability::Git))?;
            git.clone_repo(&request.url, &request.target_path, &request.options)
                .await?;
            to_value(&m::Empty)
        }
        m::ACCESS_PREVIEW_URL => {
            let request: m::PreviewUrlParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .preview_urls()
                .ok_or_else(|| Error::unsupported(Capability::PreviewUrls))?;
            let preview = facet.preview_url(request.port).await?;
            to_value(&m::PreviewUrlResult { preview })
        }
        m::ACCESS_SIGNED_PREVIEW_URL => {
            let request: m::SignedPreviewUrlParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .preview_urls()
                .ok_or_else(|| Error::unsupported(Capability::PreviewUrls))?;
            let preview = facet
                .signed_preview_url(request.port, Duration::from_millis(request.expires_in_ms))
                .await?;
            to_value(&m::PreviewUrlResult { preview })
        }
        m::ACCESS_PREVIEW_RELEASE => {
            let request: m::PreviewUrlParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .preview_urls()
                .ok_or_else(|| Error::unsupported(Capability::PreviewUrls))?;
            facet.release_preview_url(request.port).await?;
            to_value(&m::Empty)
        }
        m::ACCESS_SSH_CREATE => {
            let request: m::SshCreateParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            if request.ttl_ms.is_some() && !handle.capabilities().access.ssh_ttl {
                return Err(Error::unsupported(Capability::SshTtl).into());
            }
            let facet = handle
                .ssh()
                .ok_or_else(|| Error::unsupported(Capability::Ssh))?;
            let access = facet
                .ssh_access(request.ttl_ms.map(Duration::from_millis))
                .await?;
            to_value(&m::SshCreateResult { access })
        }
        m::ACCESS_SSH_REVOKE => {
            let request: m::SshRevokeParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            if !handle.capabilities().access.ssh_revoke {
                return Err(Error::unsupported(Capability::SshRevoke).into());
            }
            let facet = handle
                .ssh()
                .ok_or_else(|| Error::unsupported(Capability::Ssh))?;
            facet.revoke_ssh_access(&request.token).await?;
            to_value(&m::Empty)
        }
        m::ACCESS_WEB_TERMINAL => {
            let request: m::SandboxIdParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .web_terminal()
                .ok_or_else(|| Error::unsupported(Capability::WebTerminalAccess))?;
            to_value(&m::WebTerminalResult {
                url: facet.web_terminal_url().await?,
            })
        }
        m::ACCESS_VNC => {
            let request: m::SandboxIdParams = parse(params)?;
            let handle = state.sandbox(&request.sandbox_id).await?;
            let facet = handle
                .vnc()
                .ok_or_else(|| Error::unsupported(Capability::VncAccess))?;
            to_value(&m::VncResult {
                connection: facet.vnc_connection().await?,
            })
        }
        _ => Err(DispatchError::UnknownMethod),
    }
}
