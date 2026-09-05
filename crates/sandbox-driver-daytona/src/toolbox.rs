//! Bounded reads for toolbox endpoints whose SDK convenience methods buffer
//! an entire response before returning it.
use std::io;

use daytona_api_client::apis::sandbox_api;
use reqwest::Method;
use sandbox_driver::{DEFAULT_BUFFER_BYTES, Error, Result};
use serde_json::Value;

use crate::DaytonaClient;

pub(crate) async fn endpoint(client: &DaytonaClient, sandbox_id: &str) -> Result<String> {
    let proxy = sandbox_api::get_toolbox_proxy_url(
        client.api_configuration(),
        sandbox_id,
        client.organization_id(),
    )
    .await
    .map_err(|_| {
        Error::io(
            "resolving toolbox endpoint",
            io::Error::other("request failed"),
        )
    })?;
    Ok(format!(
        "{}/{}",
        proxy.url.trim_end_matches('/'),
        sandbox_id
    ))
}

pub(crate) async fn request(
    client: &DaytonaClient,
    endpoint: &str,
    path: &[&str],
    body: Option<Value>,
) -> Result<(u16, Vec<u8>)> {
    let mut url = reqwest::Url::parse(endpoint)
        .map_err(|_| Error::invalid_spec("toolbox", "invalid endpoint URL"))?;
    url.path_segments_mut()
        .map_err(|()| Error::invalid_spec("toolbox", "invalid endpoint path"))?
        .extend(path);
    let config = client.api_configuration();
    let mut request = config
        .client
        .request(
            if body.is_some() {
                Method::POST
            } else {
                Method::GET
            },
            url,
        )
        .header("Accept", "application/json, text/plain, */*")
        .header("X-Daytona-Split-Output", "true");
    if let Some(token) = &config.bearer_access_token {
        request = request.bearer_auth(token);
    }
    if let Some(org) = client.organization_id() {
        request = request.header("X-Daytona-Organization-ID", org);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let mut response = request.send().await.map_err(|_| {
        Error::io(
            "requesting toolbox operation",
            io::Error::other("request failed"),
        )
    })?;
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        Error::io(
            "reading toolbox response",
            io::Error::other(error.without_url()),
        )
    })? {
        if chunk.len() > DEFAULT_BUFFER_BYTES.saturating_sub(bytes.len()) {
            return Err(Error::LimitExceeded {
                limit:     "buffered_value_bytes".into(),
                max_bytes: DEFAULT_BUFFER_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}
