//! Lifecycle failures must preserve the sandbox so callers can retry cleanup.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bollard::Docker;
use sandbox_driver::{SandboxFilter, SandboxId, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_docker::DockerProvider;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

struct Daemon {
    provider: DockerProvider,
    requests: Arc<Mutex<Vec<String>>>,
    stop:     CancellationToken,
    task:     JoinHandle<()>,
}

impl Daemon {
    async fn new(reply: impl Fn(&str) -> (u16, Value) + Send + 'static) -> Self {
        Self::with_bytes(move |request| {
            let (status, body) = reply(request);
            (status, body.to_string().into_bytes())
        })
        .await
    }

    async fn with_bytes(reply: impl Fn(&str) -> (u16, Vec<u8>) + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test operation succeeds");
        let address = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let docker = Docker::connect_with_http(&address, 2, bollard::API_DEFAULT_VERSION)
            .expect("Docker client");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = tokio::select! {
                    () = stopped.cancelled() => break,
                    connection = listener.accept() => connection.expect("test connection"),
                };
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = stream
                        .read(&mut buffer)
                        .await
                        .expect("test operation succeeds");
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]);
                        let length = headers
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map_or(0, |(_, value)| {
                                value.trim().parse::<usize>().expect("content length")
                            });
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(bytes).expect("HTTP request is text");
                recorded.lock().unwrap().push(request.clone());
                let request = request.lines().next().expect("request line");
                let (status, body) = reply(request);
                let body = if status == 204 || status == 304 {
                    Vec::new()
                } else {
                    body
                };
                let response = format!(
                    "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("test operation succeeds");
                stream.write_all(&body).await.expect("response body");
            }
        });
        Self {
            provider: DockerProvider::from_client(docker),
            requests,
            stop,
            task,
        }
    }

    async fn finish(self) -> Vec<String> {
        self.stop.cancel();
        self.task.await.expect("test operation succeeds");
        self.requests.lock().unwrap().clone()
    }
}

fn inspect(running: bool) -> Value {
    json!({
        "Id": "main",
        "Config": {"Labels": {"sh.sandbox-driver.managed": "true"}, "WorkingDir": "/workspace"},
        "HostConfig": {"NetworkMode": "example-net"},
        "State": {"Running": running, "Paused": false}
    })
}

fn cleanup_reply(request: &str) -> (u16, Value) {
    if request.contains("/containers/main/json") {
        (200, inspect(true))
    } else if request.contains("/containers/json?") {
        let id = if request.contains("one-shot") {
            "action"
        } else {
            "service"
        };
        (200, json!([{"Id": id}]))
    } else if request.starts_with("GET ") && request.contains("/networks/example-net") {
        (200, json!({"Containers": {"main": {"Name": "main"}}}))
    } else {
        (204, Value::Null)
    }
}

#[tokio::test]
async fn delete_keeps_the_primary_resource_until_dependents_are_removed() {
    for failure in [
        "one-shot",
        "/containers/action?",
        "network%3D",
        "/containers/service?",
        "network-delete",
    ] {
        let daemon = Daemon::new(move |request| {
            // API versions are selected by Bollard; match the endpoint for
            // network deletion without depending on the selected version.
            let fail = if failure == "network-delete" {
                request.starts_with("DELETE ") && request.contains("/networks/example-net")
            } else {
                request.contains(failure)
            };
            if fail {
                (500, json!({"message": "injected cleanup failure"}))
            } else {
                cleanup_reply(request)
            }
        })
        .await;
        let result = daemon
            .provider
            .delete(&SandboxId::try_new("main").unwrap(), None)
            .await;
        let requests = daemon.finish().await;
        assert!(result.is_err(), "failure {failure}: {requests:?}");
        assert!(
            !requests
                .iter()
                .any(|request| request.starts_with("DELETE ")
                    && request.contains("/containers/main?")),
            "primary removed after {failure}: {requests:?}"
        );
    }
}

#[tokio::test]
async fn missing_dependents_are_successful_cleanup() {
    let daemon = Daemon::new(|request| {
        if request.starts_with("DELETE ") && !request.contains("/containers/main?") {
            (404, json!({"message": "already removed"}))
        } else {
            cleanup_reply(request)
        }
    })
    .await;
    daemon
        .provider
        .delete(&SandboxId::try_new("main").unwrap(), None)
        .await
        .unwrap();
    let requests = daemon.finish().await;
    assert!(requests.last().unwrap().contains("/containers/main?"));
}

#[tokio::test]
async fn delete_retries_a_network_failure_after_disconnecting_the_sandbox() {
    let state = Mutex::new((true, true));
    let daemon = Daemon::new(move |request| {
        let mut state = state.lock().unwrap();
        if request.starts_with("GET ") && request.contains("/networks/example-net") {
            let containers = if state.0 {
                json!({"main": {"Name": "main"}})
            } else {
                json!({})
            };
            (200, json!({"Containers": containers}))
        } else if request.contains("/networks/example-net/disconnect") {
            assert!(state.0, "retry must not disconnect an absent endpoint");
            state.0 = false;
            (204, Value::Null)
        } else if request.starts_with("DELETE ")
            && request.contains("/networks/example-net")
            && state.1
        {
            state.1 = false;
            (500, json!({"message": "network is temporarily busy"}))
        } else {
            cleanup_reply(request)
        }
    })
    .await;
    let id = SandboxId::try_new("main").unwrap();
    let sandbox = daemon
        .provider
        .attach(&id, None)
        .await
        .expect("test operation succeeds");
    assert!(sandbox.delete().await.is_err());
    // A fresh provider call must be able to recover from the main
    // container's preserved network mode, without the original handle.
    daemon
        .provider
        .delete(&id, None)
        .await
        .expect("test operation succeeds");
    let requests = daemon.finish().await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/disconnect"))
            .count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(
                |request| request.starts_with("DELETE ") && request.contains("/containers/main?")
            )
            .count(),
        1
    );
    assert!(requests.last().unwrap().contains("/containers/main?"));
}

#[tokio::test]
async fn stop_reports_failed_one_shot_cleanup() {
    let daemon = Daemon::new(|request| {
        if request.contains("one-shot") {
            (500, json!({"message": "list failed"}))
        } else {
            cleanup_reply(request)
        }
    })
    .await;
    let sandbox = daemon
        .provider
        .attach(&SandboxId::try_new("main").unwrap(), None)
        .await
        .unwrap();
    assert!(sandbox.stop().await.is_err());
    let requests = daemon.finish().await;
    assert!(
        !requests
            .iter()
            .any(|request| request.contains("/containers/main/stop"))
    );
}

#[tokio::test]
async fn start_is_idempotent_and_waits_for_service_health() {
    let health_reads = Mutex::new(0);
    let daemon = Daemon::new(move |request| {
        if request.contains("/containers/main/json") {
            (200, inspect(true))
        } else if request.contains("/containers/json?") {
            (200, json!([{"Id": "service"}]))
        } else if request.contains("/containers/service/json") {
            let mut reads = health_reads.lock().unwrap();
            *reads += 1;
            let health = if *reads < 3 { "starting" } else { "healthy" };
            (
                200,
                json!({"State": {"Status": "running", "Health": {"Status": health}}}),
            )
        } else if request.contains("/start") {
            (304, Value::Null)
        } else {
            panic!("unexpected request: {request}")
        }
    })
    .await;
    let sandbox = daemon
        .provider
        .attach(&SandboxId::try_new("main").unwrap(), None)
        .await
        .unwrap();
    timeout(Duration::from_secs(3), sandbox.start())
        .await
        .unwrap()
        .unwrap();
    let requests = daemon.finish().await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/containers/service/json"))
            .count(),
        3
    );
    assert!(requests.last().unwrap().contains("/containers/main/start"));
}

#[tokio::test]
async fn interrupted_service_creation_remains_discoverable_for_cleanup() {
    let retrying = Arc::new(AtomicBool::new(false));
    let retry = retrying.clone();
    let daemon = Daemon::new(move |request| {
        if request.contains("/images/") && request.contains("/json") {
            (200, json!({}))
        } else if request.contains("/containers/create?name=example-net-db") {
            (500, json!({"message": "original service create failure"}))
        } else if request.contains("/containers/create?") {
            (201, json!({"Id": "main", "Warnings": []}))
        } else if request.contains("/networks/create") {
            (201, json!({"Id": "network", "Warning": ""}))
        } else if request.contains("/containers/json?") && request.contains("network%3D") {
            if retry.load(Ordering::SeqCst) {
                (200, json!([]))
            } else {
                (500, json!({"message": "cleanup unavailable"}))
            }
        } else if request.contains("/containers/json?") {
            if request.contains("one-shot") {
                (200, json!([]))
            } else {
                (200, json!([{"Id": "main"}]))
            }
        } else if request.contains("/containers/main/json") {
            (
                200,
                json!({
                    "Id": "main", "Config": {"Labels": {
                        "sh.sandbox-driver.managed": "true",
                        "sh.sandbox-driver.sidecar-network": "example-net",
                        "petri.workspace": "test/work"
                    }}, "HostConfig": {"NetworkMode": "none"},
                    "State": {"Status": "created", "Running": false},
                    "NetworkSettings": {"Networks": {"none": {}}}
                }),
            )
        } else if request.starts_with("GET ") && request.contains("/networks/example-net") {
            (200, json!({"Containers": {}}))
        } else {
            (204, Value::Null)
        }
    })
    .await;
    let mut spec = SandboxSpec::new(SandboxSource::Image {
        reference: "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17".to_owned(),
    })
    .name("example")
    .label("petri.workspace", "test/work");
    spec.provider_config = json!({"sidecars": [{"name": "db", "image": "ghcr.io/fabro-sh/dhi-alpine-base:3.23-dev-2026-06-17"}]});
    let error = daemon
        .provider
        .create(&spec, None)
        .await
        .err()
        .expect("create fails");
    assert!(error.to_string().contains("creating sidecar"), "{error}");
    let mut filter = SandboxFilter::default();
    filter
        .labels
        .insert("petri.workspace".to_owned(), "test/work".to_owned());
    let found = daemon
        .provider
        .list(&filter)
        .await
        .expect("allocation remains discoverable");
    assert_eq!(found.len(), 1);
    let sandbox = daemon
        .provider
        .attach(&found[0].id, None)
        .await
        .expect("attach partial allocation");
    assert!(
        sandbox.start().await.is_err(),
        "incomplete services must not become a usable sandbox"
    );
    retrying.store(true, Ordering::SeqCst);
    daemon
        .provider
        .delete(&found[0].id, None)
        .await
        .expect("retry cleans the allocation");
    let requests = daemon.finish().await;
    let primary = requests
        .iter()
        .position(|request| request.contains("/containers/create?name=example "))
        .expect("primary create");
    let network = requests
        .iter()
        .position(|request| request.contains("/networks/create"))
        .expect("network create");
    assert!(
        primary < network,
        "primary must precede every dependent: {requests:?}"
    );
    assert!(requests[primary].contains("sh.sandbox-driver.sidecar-network"));
    assert!(requests[primary].contains("petri.workspace"));
    assert_eq!(
        requests
            .iter()
            .filter(
                |request| request.starts_with("DELETE ") && request.contains("/containers/main?")
            )
            .count(),
        1
    );
    assert!(
        requests
            .last()
            .expect("last cleanup")
            .contains("/containers/main?")
    );
}
