//! Direct `daytona-api-client` calls for control-plane endpoints the
//! wrapped SDK does not expose (snapshot activation, current-API-key
//! introspection), resolved from the same environment variables the SDK
//! reads. The SDK keeps its `Configuration` private, so this module
//! builds an equivalent one.

use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use daytona_api_client::apis::Error as ApiError;
use daytona_api_client::apis::configuration::Configuration;
use sandbox_driver::{Error, ProviderError, ProviderKind, Result};

const DEFAULT_API_URL: &str = "https://app.daytona.io/api";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared configuration for raw API calls.
pub(crate) struct RawApi {
    pub(crate) configuration:   Configuration,
    pub(crate) organization_id: Option<String>,
}

fn non_empty(variable: &str) -> Option<String> {
    env::var(variable).ok().filter(|value| !value.is_empty())
}

fn api_url() -> String {
    non_empty("DAYTONA_API_URL")
        .or_else(|| non_empty("DAYTONA_SERVER_URL"))
        .unwrap_or_else(|| DEFAULT_API_URL.to_owned())
}

/// The dashboard page listing sandboxes, derived from the API URL. The
/// hosted control plane serves the API under `/api` next to the
/// dashboard; a differently shaped deployment gets no link rather than a
/// guessed one.
pub(crate) fn dashboard_url() -> Option<&'static str> {
    static URL: OnceLock<Option<String>> = OnceLock::new();
    URL.get_or_init(|| {
        let api = api_url();
        let base = api.strip_suffix("/api")?;
        Some(format!("{base}/dashboard/sandboxes"))
    })
    .as_deref()
}

pub(crate) fn raw_api() -> Result<&'static RawApi> {
    static RAW: OnceLock<Option<RawApi>> = OnceLock::new();
    RAW.get_or_init(build).as_ref().ok_or_else(|| {
        Error::Provider(ProviderError::new(
            kind(),
            "no DAYTONA_API_KEY or DAYTONA_JWT_TOKEN in the environment",
        ))
    })
}

fn build() -> Option<RawApi> {
    let bearer = non_empty("DAYTONA_API_KEY").or_else(|| non_empty("DAYTONA_JWT_TOKEN"))?;
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_default();
    Some(RawApi {
        configuration:   Configuration {
            base_path:           api_url(),
            user_agent:          Some(
                concat!("sandbox-driver-daytona/", env!("CARGO_PKG_VERSION")).to_owned(),
            ),
            client:              reqwest_middleware::ClientBuilder::new(client).build(),
            basic_auth:          None,
            oauth_access_token:  None,
            bearer_access_token: Some(bearer),
            api_key:             None,
        },
        organization_id: non_empty("DAYTONA_ORGANIZATION_ID"),
    })
}

fn kind() -> ProviderKind {
    ProviderKind::try_new("daytona").expect("static kind is valid")
}

pub(crate) fn is_raw_not_found<T>(error: &ApiError<T>) -> bool {
    matches!(error, ApiError::ResponseError(content) if content.status.as_u16() == 404)
}

pub(crate) fn raw_error<T>(context: &str, error: &ApiError<T>) -> Error {
    let mut provider = ProviderError::new(kind(), format!("{context}: {error}"));
    if let ApiError::ResponseError(content) = error {
        provider.code = Some(content.status.as_u16().to_string());
        provider.retryable = content.status.is_server_error();
    }
    Error::Provider(provider)
}
