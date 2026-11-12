//! The nested recipe: a workload container and its services inside the
//! provider's Docker-capable runner sandbox.
//!
//! Everything shares the runner's network namespace. The workload reaches
//! a service at `127.0.0.1:<port>`, one-shot containers join the workload's
//! namespace, and a workload port is a runner port, so Daytona preview URLs
//! reach it. Each service container records its ports and readiness check
//! in Docker labels, so a later start restores and rechecks it from the
//! sandbox itself rather than from a caller's spec.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future;
use sandbox_driver::contract::{
    ContainerSpec, Error, ReadinessCheck, SecretValues, ServiceAddress, ServiceSpec,
};
use sandbox_driver::{Result as LegacyResult, Sandbox as _};
use sandbox_driver_docker_config::RegistryAuth;
use tokio::time;

use super::error::classify;
use super::spec::{Nested, WorkloadImage};
use crate::nested::{
    CONTAINER_NAME, DockerCli, IDLE, MANAGED_LABEL, NestedDocker, flags, words, workspace_mount,
};
use crate::{DaytonaSandbox, RUNTIME_DIRECTORY};

const SERVICE_PREFIX: &str = "sandbox-driver-service-";
const SERVICE_LABEL: &str = "sh.sandbox-driver.service";
const PORTS_LABEL: &str = "sh.sandbox-driver.service-ports";
const READY_LABEL: &str = "sh.sandbox-driver.service-ready";
const PULL_TIMEOUT: Duration = Duration::from_secs(900);
/// The host the workload and its one-shots reach services at.
const SERVICE_HOST: &str = "127.0.0.1";
/// The provider error code a failed readiness check crosses the legacy
/// create with; the classifier reads it back as `Unhealthy`.
pub(super) const UNHEALTHY_CODE: &str = "unhealthy";

/// Registry credentials for a service image, parsed before anything is
/// created so a malformed value fails admission rather than provisioning.
pub(super) type ServiceAuth = BTreeMap<String, RegistryAuth>;

/// Reads each service's named credential from the admission. A value is
/// `{"username", "password", "server"?}` JSON or `username:password`.
pub(super) fn service_auth(
    services: &BTreeMap<String, ServiceSpec>,
    credentials: &SecretValues,
) -> Result<ServiceAuth, Error> {
    let mut auth = ServiceAuth::new();
    for (name, service) in services {
        let Some(credential) = &service.credential else {
            continue;
        };
        let path = format!("services.{name}.credential");
        let value = credentials
            .values()
            .get(credential)
            .ok_or_else(|| Error::InvalidSpec {
                path:    path.clone(),
                message: "the credential was not supplied with the admission".to_owned(),
            })?;
        let parsed = serde_json::from_str::<RegistryAuth>(value)
            .ok()
            .or_else(|| {
                let (username, password) = value.split_once(':')?;
                Some(RegistryAuth {
                    username: username.to_owned(),
                    password: password.to_owned(),
                    server:   None,
                })
            })
            .ok_or_else(|| Error::InvalidSpec {
                path,
                message: "expected registry credentials as JSON or username:password".to_owned(),
            })?;
        auth.insert(name.clone(), parsed);
    }
    Ok(auth)
}

/// The nested Docker of a runner sandbox handle.
fn docker(handle: &DaytonaSandbox) -> Result<&NestedDocker, Error> {
    handle.nested.as_ref().ok_or_else(|| Error::Unhealthy {
        message: "the runner sandbox has no nested Docker target".to_owned(),
    })
}

/// Provisions a fresh runner: Docker, the workload image, the services
/// (ready before success), then the workload container. Runs inside the
/// legacy create, so any failure deletes the runner and confirms it.
pub(super) async fn provision(
    handle: Arc<DaytonaSandbox>,
    nested: Nested,
    auth: ServiceAuth,
) -> LegacyResult<()> {
    let docker = handle
        .nested
        .as_ref()
        .ok_or_else(|| sandbox_driver::Error::invalid_spec("recipe", "runner has no Docker"))?;
    docker
        .provision_with(|cli| provision_containers(cli, &nested, &auth))
        .await?;
    // Provisioning pulls images; the requested egress policy applies to
    // everything that runs afterwards.
    if nested.network != sandbox_driver::NetworkPolicy::ProviderDefault {
        handle.update_network(&nested.network).await?;
    }
    Ok(())
}

/// The containers of a nested workload: its services, ready before the
/// workload container is created. The caller starts the workload.
async fn provision_containers(
    cli: Arc<DockerCli>,
    nested: &Nested,
    auth: &ServiceAuth,
) -> LegacyResult<()> {
    let cli = &cli;
    // Downloads dominate provisioning, so every image comes down at once;
    // each pull keeps its own credential directory.
    let pulls = nested
        .services
        .iter()
        .map(|(name, service)| cli.pull(&service.image, auth.get(name), None));
    future::try_join(
        prepare_workload_image(cli, &nested.image),
        future::try_join_all(pulls),
    )
    .await?;
    // Services are independent containers on the runner's network.
    let starts = nested.services.iter().map(|(name, service)| async move {
        cli.run(service_args(name, service)?).await?;
        cli.run(words(["start", &container_name(name)])).await
    });
    future::try_join_all(starts).await?;
    if let Err(error) = await_services(cli, &nested.services).await {
        return Err(unready(&error));
    }
    cli.run(workload_args(
        &cli.working_dir,
        nested.image.reference(),
        &nested.container,
        nested.user.as_deref(),
        &nested.env,
    ))
    .await?;
    Ok(())
}

/// A readiness failure crosses the legacy create (and its cleanup) as a
/// provider error the classifier reads back as `Unhealthy`.
fn unready(error: &Error) -> sandbox_driver::Error {
    let kind = super::DaytonaFactory::kind();
    // Carry the bare message; the classifier wraps it as `Unhealthy` once.
    let message = match error {
        Error::Unhealthy { message } => message.clone(),
        error => error.to_string(),
    };
    let mut provider = sandbox_driver::ProviderError::new(kind, message);
    provider.code = Some(UNHEALTHY_CODE.to_owned());
    sandbox_driver::Error::Provider(provider)
}

async fn prepare_workload_image(cli: &DockerCli, image: &WorkloadImage) -> LegacyResult<()> {
    match image {
        WorkloadImage::Pull(reference) => cli.pull(reference, None, None).await,
        WorkloadImage::Build { content, tag } => {
            let context = format!("{RUNTIME_DIRECTORY}/workload-build");
            cli.fs
                .write(&format!("{context}/Dockerfile"), content.as_bytes())
                .await?;
            cli.run_spec(
                &DockerCli::command(words(["build", "--tag", tag, &context])).timeout(PULL_TIMEOUT),
            )
            .await?;
            Ok(())
        }
    }
}

fn container_name(service: &str) -> String {
    format!("{SERVICE_PREFIX}{service}")
}

fn service_args(name: &str, service: &ServiceSpec) -> LegacyResult<Vec<String>> {
    let ports = service
        .ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let ready = match &service.ready {
        Some(check) => serde_json::to_string(check).map_err(|error| {
            sandbox_driver::Error::invalid_spec("services.ready", error.to_string())
        })?,
        None => String::new(),
    };
    let mut args = words([
        "create",
        "--name",
        &container_name(name),
        "--label",
        MANAGED_LABEL,
        "--label",
        &format!("{SERVICE_LABEL}={name}"),
        "--label",
        &format!("{PORTS_LABEL}={ports}"),
        "--label",
        &format!("{READY_LABEL}={ready}"),
        "--network",
        "host",
        "--restart",
        "no",
    ]);
    flags(
        &mut args,
        "--env",
        service
            .env
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    args.push(service.image.clone());
    Ok(args)
}

fn workload_args(
    working_dir: &str,
    image: &str,
    container: &ContainerSpec,
    user: Option<&str>,
    env: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut args = words([
        "create",
        "--name",
        CONTAINER_NAME,
        "--label",
        MANAGED_LABEL,
        "--network",
        "host",
        "--workdir",
        working_dir,
        "--mount",
        &workspace_mount(working_dir),
    ]);
    // Unspecified keeps the provider default, an init process; an explicit
    // false is honoured.
    if container.init != Some(false) {
        args.push("--init".to_owned());
    }
    if container.privileged == Some(true) {
        args.push("--privileged".to_owned());
    }
    if let Some(user) = user {
        args.extend(words(["--user", user]));
    }
    flags(&mut args, "--cap-add", container.capabilities_add.clone());
    flags(&mut args, "--cap-drop", container.capabilities_drop.clone());
    if let Some(shm) = container.shm_size_mb {
        args.extend(["--shm-size".to_owned(), format!("{shm}m")]);
    }
    flags(
        &mut args,
        "--env",
        env.iter().map(|(key, value)| format!("{key}={value}")),
    );
    args.extend(words(["--entrypoint", "/bin/sh", image, "-c", IDLE]));
    args
}

/// Every declared service passes its readiness check, or has started when
/// it declares none. Checks run concurrently, each within its own budget.
async fn await_services(
    cli: &DockerCli,
    services: &BTreeMap<String, ServiceSpec>,
) -> Result<(), Error> {
    let checks = services
        .iter()
        .map(|(name, service)| await_service(cli, name, service.ready.as_ref()));
    future::try_join_all(checks).await.map(|_| ())
}

async fn await_service(
    cli: &DockerCli,
    name: &str,
    check: Option<&ReadinessCheck>,
) -> Result<(), Error> {
    let container = container_name(name);
    let Some(check) = check else {
        let inspect = cli
            .inspect(&container)
            .await
            .map_err(|error| classify("inspecting service", error))?;
        return running(name, &inspect);
    };
    let started = Instant::now();
    let deadline = Duration::from_millis(check.deadline_ms.get());
    let per_attempt = Duration::from_millis(check.timeout_ms.get());
    let interval = Duration::from_millis(check.interval_ms.get());
    for attempt in 1..=check.retries.get() {
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let budget = per_attempt.min(remaining);
        let mut argv = words(["exec", &container]);
        argv.extend(check.command.iter().cloned());
        let probe = DockerCli::command(argv).timeout(budget);
        let passed = time::timeout(budget, cli.exec.run(&probe))
            .await
            .is_ok_and(|result| result.is_ok_and(|output| output.success()));
        tracing::debug!(service = name, attempt, passed, "service readiness attempt");
        if passed {
            return Ok(());
        }
        if attempt == check.retries.get() {
            break;
        }
        time::sleep(interval.min(deadline.saturating_sub(started.elapsed()))).await;
    }
    Err(Error::Unhealthy {
        message: format!("service {name} did not pass its readiness check"),
    })
}

/// A service without a readiness check is ready once it runs.
fn running(name: &str, inspect: &serde_json::Value) -> Result<(), Error> {
    if inspect["State"]["Running"] == true {
        Ok(())
    } else {
        Err(Error::Unhealthy {
            message: format!("service {name} is not running"),
        })
    }
}

/// After the runner restarts: starts every service it recorded and checks
/// each again with the check it was admitted with.
pub(super) async fn restart_services(handle: &DaytonaSandbox) -> Result<(), Error> {
    let cli = docker(handle)?.cli();
    let ids = cli
        .ids(SERVICE_LABEL)
        .await
        .map_err(|error| classify("listing services", error))?;
    let restarts = ids.iter().map(|id| restart_service(cli, id));
    future::try_join_all(restarts).await.map(|_| ())
}

async fn restart_service(cli: &DockerCli, id: &str) -> Result<(), Error> {
    cli.run(words(["start", id]))
        .await
        .map_err(|error| classify("starting service", error))?;
    let inspect = cli
        .inspect(id)
        .await
        .map_err(|error| classify("inspecting service", error))?;
    let labels = &inspect["Config"]["Labels"];
    let name = labels[SERVICE_LABEL].as_str().unwrap_or_default();
    let ready = labels[READY_LABEL]
        .as_str()
        .filter(|ready| !ready.is_empty())
        .map(serde_json::from_str::<ReadinessCheck>)
        .transpose()
        .map_err(|_| Error::Unhealthy {
            message: format!("service {name} has an unreadable readiness record"),
        })?;
    match ready {
        Some(check) => await_service(cli, name, Some(&check)).await,
        None => running(name, &inspect),
    }
}

/// The services running now, as the workload reaches them.
pub(super) async fn service_addresses(
    handle: &DaytonaSandbox,
) -> Result<BTreeMap<String, ServiceAddress>, Error> {
    let cli = docker(handle)?.cli();
    let output = cli
        .run(words([
            "ps",
            "--filter",
            &format!("label={SERVICE_LABEL}"),
            "--filter",
            "status=running",
            "--format",
            &format!("{{{{.Label \"{SERVICE_LABEL}\"}}}}\t{{{{.Label \"{PORTS_LABEL}\"}}}}"),
        ]))
        .await
        .map_err(|error| classify("listing services", error))?;
    Ok(parse_addresses(&output.stdout_lossy()))
}

fn parse_addresses(listing: &str) -> BTreeMap<String, ServiceAddress> {
    listing
        .lines()
        .filter_map(|line| {
            let (name, ports) = line.split_once('\t')?;
            let ports = ports
                .split(',')
                .filter_map(|port| port.trim().parse::<u16>().ok())
                .map(|port| (port, port))
                .collect();
            Some((name.to_owned(), ServiceAddress {
                host: SERVICE_HOST.to_owned(),
                ports,
            }))
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

    use super::*;

    #[test]
    fn service_addresses_are_loopback_ports_of_running_services() {
        let listing = "db\t5432\ncache\t6379,6380\n\t\n";
        let addresses = parse_addresses(listing);
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses["db"].host, "127.0.0.1");
        assert_eq!(addresses["db"].ports, BTreeMap::from([(5432, 5432)]));
        assert_eq!(
            addresses["cache"].ports,
            BTreeMap::from([(6379, 6379), (6380, 6380)])
        );
    }

    #[test]
    fn a_service_records_its_ports_and_check_for_restart() {
        let mut service = ServiceSpec::new("postgres:16");
        service.ports = vec![NonZeroU16::new(5432).unwrap()];
        service
            .env
            .insert("POSTGRES_PASSWORD".to_owned(), "x".to_owned());
        service.ready = Some(ReadinessCheck {
            command:     vec!["pg_isready".to_owned()],
            interval_ms: NonZeroU64::new(2000).unwrap(),
            timeout_ms:  NonZeroU64::new(1000).unwrap(),
            deadline_ms: NonZeroU64::new(60_000).unwrap(),
            retries:     NonZeroU32::new(30).unwrap(),
        });
        let args = service_args("db", &service).expect("serializable");
        let ready = args
            .iter()
            .find_map(|arg| arg.strip_prefix(&format!("{READY_LABEL}=")))
            .expect("readiness label");
        let restored: ReadinessCheck = serde_json::from_str(ready).expect("round trip");
        assert_eq!(restored.command, vec!["pg_isready".to_owned()]);
        assert_eq!(restored.retries.get(), 30);
        assert!(args.contains(&format!("{PORTS_LABEL}=5432")));
        assert!(args.contains(&"POSTGRES_PASSWORD=x".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("postgres:16"));
    }

    #[test]
    fn workload_container_options_are_translated_and_explicit_false_honoured() {
        let container = ContainerSpec {
            init: Some(false),
            privileged: Some(false),
            capabilities_add: vec!["SYS_PTRACE".to_owned()],
            capabilities_drop: vec!["NET_RAW".to_owned()],
            shm_size_mb: NonZeroU64::new(512),
            ..ContainerSpec::default()
        };
        let args = workload_args(
            "/workspace",
            "buildpack-deps:noble",
            &container,
            Some("1000"),
            &BTreeMap::from([("CI".to_owned(), "1".to_owned())]),
        );
        assert!(!args.contains(&"--init".to_owned()));
        assert!(!args.contains(&"--privileged".to_owned()));
        for expected in ["SYS_PTRACE", "NET_RAW", "512m", "1000", "CI=1", "host"] {
            assert!(args.contains(&expected.to_owned()), "{expected} missing");
        }
        let default = workload_args(
            "/workspace",
            "img",
            &ContainerSpec::default(),
            None,
            &BTreeMap::new(),
        );
        assert!(default.contains(&"--init".to_owned()));
    }

    #[test]
    fn service_credentials_accept_json_or_user_password_and_must_be_supplied() {
        let mut service = ServiceSpec::new("registry.test/db:1");
        service.credential = Some("REGISTRY".to_owned());
        let services = BTreeMap::from([("db".to_owned(), service)]);
        let supplied = |value: &str| {
            SecretValues::new(BTreeMap::from([("REGISTRY".to_owned(), value.to_owned())]))
        };
        let auth = service_auth(&services, &supplied("robot:s3:cret")).expect("user:password");
        assert_eq!(auth["db"].username, "robot");
        assert_eq!(auth["db"].password, "s3:cret");
        let auth = service_auth(
            &services,
            &supplied(r#"{"username":"u","password":"p","server":"registry.test"}"#),
        )
        .expect("json");
        assert_eq!(auth["db"].server.as_deref(), Some("registry.test"));
        assert!(matches!(
            service_auth(&services, &SecretValues::default()),
            Err(Error::InvalidSpec { path, .. }) if path == "services.db.credential"
        ));
        assert!(service_auth(&services, &supplied("no-separator")).is_err());
    }
}
