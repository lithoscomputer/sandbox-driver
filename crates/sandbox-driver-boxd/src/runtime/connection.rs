//! The boxd public gRPC API: one TLS channel, and the short-lived JWT every
//! call carries, exchanged from the entry's API key and refreshed before it
//! expires.

use std::error::Error as _;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::stream::{self, Stream};
use rustls::crypto::ring;
use rustls::{ClientConfig, RootCertStore};
use sandbox_driver::{Error, MutationOutcome};
use serde::Deserialize;
use tokio::sync::{Mutex, mpsc};
use tokio::time;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Status};

use super::api::boxd_api_client::BoxdApiClient;

/// Bounds connecting, the token exchange, and each unary call. Streams
/// (exec, file transfer) are bounded by their callers instead.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// Pings an idle connection so one boxd closed is noticed and replaced
/// before a call is sent on it.
const KEEPALIVE: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// A token is replaced this long before boxd says it expires, so a call
/// never starts with one about to lapse.
const REFRESH_MARGIN: Duration = Duration::from_secs(300);
/// gRPC's default 4 MiB receive limit is below what one `FsRead` or exec
/// chunk may carry.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;
/// Attempts of an idempotent read whose connection failed, and the first
/// pause between them.
const READ_ATTEMPTS: u32 = 3;
const READ_RETRY: Duration = Duration::from_millis(250);

pub(super) type Api = BoxdApiClient<Channel>;

/// The API key, which is a secret; `Debug` never prints it.
#[derive(Clone)]
pub(super) struct ApiKey(pub(super) String);

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

struct Token {
    bearer:  MetadataValue<Ascii>,
    refresh: SystemTime,
}

pub(super) struct Connection {
    channel:  Channel,
    http:     reqwest::Client,
    auth_url: String,
    api_key:  ApiKey,
    token:    Mutex<Option<Token>>,
}

#[derive(Deserialize)]
struct Exchanged {
    token:      String,
    expires_at: u64,
}

impl Connection {
    /// Opens the channel lazily: nothing is contacted until the first call.
    pub(super) fn new(api_url: &str, auth_url: String, api_key: ApiKey) -> Result<Self, String> {
        let mut endpoint = Endpoint::from_shared(api_url.to_owned())
            .map_err(|error| format!("api_url: {error}"))?
            .connect_timeout(CALL_TIMEOUT)
            .http2_keep_alive_interval(KEEPALIVE)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .user_agent(concat!("sandbox-driver/", env!("CARGO_PKG_VERSION")))
            .map_err(|error| format!("user agent: {error}"))?;
        if api_url.starts_with("https://") {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(|error| format!("api_url TLS: {error}"))?;
        }
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT)
            .tls_backend_preconfigured(tls()?)
            .build()
            .map_err(|error| format!("HTTP client: {error}"))?;
        Ok(Self {
            channel: endpoint.connect_lazy(),
            http,
            auth_url,
            api_key,
            token: Mutex::new(None),
        })
    }

    pub(super) fn api(&self) -> Api {
        BoxdApiClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_MESSAGE)
            .max_encoding_message_size(MAX_MESSAGE)
    }

    /// `message` as an authenticated request.
    pub(super) async fn request<T>(&self, message: T) -> Result<tonic::Request<T>, Error> {
        let mut request = tonic::Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", self.bearer().await?);
        Ok(request)
    }

    /// `message` as an authenticated unary request with the call timeout.
    pub(super) async fn unary<T>(&self, message: T) -> Result<tonic::Request<T>, Error> {
        let mut request = self.request(message).await?;
        request.set_timeout(CALL_TIMEOUT);
        Ok(request)
    }

    /// Runs an idempotent read, retrying when its connection failed before
    /// boxd answered. Only reads come through here: a mutation is never
    /// replayed.
    pub(super) async fn read<T, F, Fut>(&self, mut call: F) -> Result<Result<T, Status>, Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<Result<T, Status>, Error>>,
    {
        let mut pause = READ_RETRY;
        let mut attempt = 1;
        loop {
            match call().await? {
                Err(status) if attempt < READ_ATTEMPTS && transient(&status) => {
                    tracing::debug!(code = ?status.code(), attempt, "retrying a boxd read");
                    time::sleep(pause).await;
                    pause *= 4;
                    attempt += 1;
                }
                result => return Ok(result),
            }
        }
    }

    async fn bearer(&self) -> Result<MetadataValue<Ascii>, Error> {
        let mut token = self.token.lock().await;
        if let Some(current) = token.as_ref() {
            if SystemTime::now() < current.refresh {
                return Ok(current.bearer.clone());
            }
        }
        let fresh = self.exchange().await?;
        let bearer = fresh.bearer.clone();
        *token = Some(fresh);
        Ok(bearer)
    }

    /// Trades the API key for a JWT. A refusal is reported as such; nothing
    /// was admitted either way.
    async fn exchange(&self) -> Result<Token, Error> {
        let unavailable = |message: String| Error::Unavailable {
            message,
            outcome: MutationOutcome::NotStarted,
        };
        let response = self
            .http
            .post(&self.auth_url)
            .json(&serde_json::json!({ "api_key": self.api_key.0 }))
            .send()
            .await
            .map_err(|error| {
                unavailable(format!("exchanging the API key: {}", error.without_url()))
            })?;
        let status = response.status().as_u16();
        let message = format!("exchanging the API key: HTTP {status}");
        match status {
            200..=299 => {}
            400 | 401 => return Err(Error::Unauthenticated { message }),
            403 => return Err(Error::PermissionDenied { message }),
            429 => {
                return Err(Error::ResourceExhausted {
                    message,
                    retry_after_ms: None,
                });
            }
            _ => return Err(unavailable(message)),
        }
        let exchanged: Exchanged = response
            .json()
            .await
            .map_err(|error| unavailable(format!("reading the token: {}", error.without_url())))?;
        let bearer = format!("Bearer {}", exchanged.token)
            .parse()
            .map_err(|_| unavailable("boxd returned an unusable token".to_owned()))?;
        let expires = UNIX_EPOCH + Duration::from_secs(exchanged.expires_at);
        Ok(Token {
            bearer,
            refresh: expires.checked_sub(REFRESH_MARGIN).unwrap_or(UNIX_EPOCH),
        })
    }
}

/// A client-streaming request: every message sent, ending when the sender
/// is dropped, which boxd reads as the end of the stream.
pub(super) fn requests<T: Send + 'static>(receiver: mpsc::Receiver<T>) -> impl Stream<Item = T> {
    stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|message| (message, receiver))
    })
}

/// The token exchange's TLS: ring and the webpki roots, as the gRPC channel
/// uses, so no second crypto provider is linked.
fn tls() -> Result<ClientConfig, String> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Ok(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("TLS: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Whether a call failed in transport, before boxd could answer it.
fn transient(status: &Status) -> bool {
    match status.code() {
        Code::Unavailable => true,
        // tonic reports a broken connection as UNKNOWN with the transport
        // error as its source; boxd's own UNKNOWN answers carry none.
        Code::Unknown => status.source().is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_connection_failures_are_retried() {
        assert!(transient(&Status::unavailable("connection refused")));
        assert!(!transient(&Status::unknown("boxd failed")));
        assert!(!transient(&Status::not_found("vm")));
        assert!(!transient(&Status::deadline_exceeded("slow")));
    }

    #[test]
    fn the_api_key_never_prints() {
        assert_eq!(
            format!("{:?}", ApiKey("bxd_secret".to_owned())),
            "ApiKey(<redacted>)"
        );
    }
}
