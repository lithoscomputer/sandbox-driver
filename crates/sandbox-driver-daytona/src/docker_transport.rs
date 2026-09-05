//! Authenticated Docker HTTP transport through a private Daytona preview.

use std::error::Error as StdError;

use bollard::{API_DEFAULT_VERSION, Docker};
use http::{HeaderMap, HeaderName, HeaderValue, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::crypto::ring;
use sandbox_driver::{Error, PreviewUrl, ProviderError, ProviderKind, Result};

/// Build a connection for one running VM generation. Fetching the preview
/// again on start/attach refreshes Daytona's restart-scoped token. Requests
/// are never replayed after a transport failure.
pub(super) fn connect(preview: PreviewUrl) -> Result<Docker> {
    let connector = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(ring::default_provider())
        .map_err(|error| transport_error("configuring Docker TLS", error))?
        .https_only()
        .enable_http1()
        .build();
    connect_with_connector(preview, connector)
}

fn connect_with_connector(
    preview: PreviewUrl,
    connector: HttpsConnector<HttpConnector>,
) -> Result<Docker> {
    let uri: Uri = preview.url.parse().map_err(|_| invalid_preview())?;
    if uri.scheme_str() != Some("https")
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return Err(invalid_preview());
    }
    let mut headers = HeaderMap::new();
    for (name, value) in preview.headers {
        let name = HeaderName::try_from(name).map_err(|_| invalid_preview())?;
        let mut value = HeaderValue::try_from(value).map_err(|_| invalid_preview())?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    let client = Client::builder(TokioExecutor::new())
        .retry_canceled_requests(false)
        .build(connector);
    Docker::connect_with_custom_transport(
        move |mut request: bollard::BollardRequest| {
            let client = client.clone();
            request.headers_mut().extend(headers.clone());
            Box::pin(async move { client.request(request).await.map_err(Into::into) })
        },
        Some(preview.url.trim_end_matches('/')),
        120,
        API_DEFAULT_VERSION,
    )
    .map_err(|error| transport_error("configuring Docker connection", error))
}

fn invalid_preview() -> Error {
    Error::invalid_spec(
        "preview",
        "expected a private HTTPS preview origin and valid headers",
    )
}

pub(super) fn transport_error(
    operation: &str,
    source: impl StdError + Send + Sync + 'static,
) -> Error {
    Error::Provider(ProviderError::with_source(
        ProviderKind::try_new("daytona").expect("constant provider kind"),
        operation,
        source,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use bollard::container::{AttachContainerOptions, LogOutput};
    use futures_util::StreamExt;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[test]
    fn refuses_credentials_in_urls_and_insecure_or_non_origin_previews() {
        for url in [
            "http://preview.test",
            "https://user:secret@preview.test",
            "https://preview.test/docker",
            "https://preview.test?token=secret",
        ] {
            assert!(connect(PreviewUrl::new(url)).is_err());
        }
    }

    #[tokio::test]
    async fn authenticated_preview_preserves_docker_upgrade_and_binary_output() {
        let cert =
            CertificateDer::from(include_bytes!("../tests/fixtures/preview-cert.der").to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../tests/fixtures/preview-key.der").to_vec(),
        ));
        let crypto = Arc::new(ring::default_provider());
        let server = ServerConfig::builder_with_provider(Arc::clone(&crypto))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let client = ClientConfig::builder_with_provider(crypto)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(client)
            .https_only()
            .enable_http1()
            .build();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut preview = PreviewUrl::new(format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ));
        preview.headers.insert(
            "x-daytona-preview-token".to_owned(),
            "private-test-token".to_owned(),
        );
        let docker = connect_with_connector(preview, connector).unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = TlsAcceptor::from(Arc::new(server))
                .accept(socket)
                .await
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 8192, "bounded HTTP request");
                request.push(socket.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.contains("x-daytona-preview-token: private-test-token\r\n"),
                "private preview header missing"
            );
            assert!(request.contains("/containers/test/attach?"));
            socket
                .write_all(b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
                .await
                .unwrap();
            socket
                .write_all(&[1, 0, 0, 0, 0, 0, 0, 4, 0, 255, 128, 10])
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });
        let received = timeout(Duration::from_secs(10), async {
            let mut attached = docker
                .attach_container(
                    "test",
                    Some(AttachContainerOptions::<String> {
                        stdout: Some(true),
                        stream: Some(true),
                        ..Default::default()
                    }),
                )
                .await
                .unwrap();
            attached.output.next().await.unwrap().unwrap()
        })
        .await;
        if received.is_err() {
            server.abort();
        }
        server.await.unwrap();
        assert!(
            matches!(received.unwrap(), LogOutput::StdOut { message } if message.as_ref() == [0, 255, 128, 10])
        );
    }
}
