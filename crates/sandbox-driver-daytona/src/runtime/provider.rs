//! One activated Daytona provider entry.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use daytona_sdk::{DaytonaConfig, SandboxListItem};
use futures_util::{FutureExt, TryStreamExt};
use sandbox_driver::contract::{
    AccessScope, Activation, CapabilitySet, ContainerField, Descriptor, Durability, Error, Health,
    LabelFilter, Locality, MutationOutcome, Namespace, NamespaceId, NamespaceScope, NetworkMode,
    PortSupport, ProviderName, ProviderRuntime, ProviderSchemas, RemainingResource,
    ResourceCapability, Sandbox, SandboxRef, SandboxSummary, SourceKind, TimerCapability,
    WorkloadAdmission,
};
use sandbox_driver::{
    BASH_ENV_VAR, EventEmitter, HealthStatus, Isolation, SandboxId, SandboxProvider as _,
    SandboxState as LegacyState,
};
use serde::Deserialize;
use tokio::time;
use tokio_util::sync::CancellationToken;

use super::error::{classify, from_sdk, refused};
use super::handle::{Workload, contract_state, public_labels};
use super::spec::{self, DEFAULT_RUNNER_IMAGE};
use super::{DaytonaFactory, runner};
use crate::labels::{MANAGED_LABEL, RECIPE_LABEL};
use crate::provider::{CurrentApiKey, Provision};
use crate::sdk::{find_sandbox, map_state};
use crate::{
    DaytonaProvider, DaytonaSandbox, FAILED_CREATE_CLEANUP_BUDGET, LIST_PAGE_SIZE, cleanup,
};

const API_KEY: &str = "DAYTONA_API_KEY";
const JWT_TOKEN: &str = "DAYTONA_JWT_TOKEN";
const READING_ORGANIZATION: &str = "reading the API key's organization";

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EntryConfig {
    api_url:      Option<String>,
    organization: Option<String>,
    target:       Option<String>,
    runner_image: Option<String>,
}

pub(super) struct DaytonaRuntime {
    entry:        ProviderName,
    provider:     DaytonaProvider,
    descriptor:   Descriptor,
    runner_image: String,
    closed:       CancellationToken,
}

impl DaytonaRuntime {
    /// Connects with exactly the entry's config and resolved secrets and
    /// establishes the namespace. No sandbox is touched.
    pub(super) async fn activate(activation: Activation) -> Result<Self, Error> {
        let Activation {
            name,
            entry,
            schemas,
            environment: _,
            secrets,
        } = activation;
        let config = EntryConfig::deserialize(serde_json::Value::Object(
            entry.config.into_iter().collect(),
        ))
        .map_err(|error| Error::InvalidConfig {
            entry:   name.clone(),
            path:    "config".to_owned(),
            message: error.to_string(),
        })?;
        let api_key = secrets.values().get(API_KEY).cloned();
        let jwt_token = secrets.values().get(JWT_TOKEN).cloned();
        if api_key.is_none() && jwt_token.is_none() {
            return Err(Error::MissingSecret {
                entry: name,
                name:  API_KEY.to_owned(),
            });
        }
        if api_key.is_none() && config.organization.is_none() {
            return Err(Error::InvalidConfig {
                entry:   name,
                path:    "organization".to_owned(),
                message: "a JWT credential needs an explicit organization".to_owned(),
            });
        }
        let sdk_config = DaytonaConfig {
            api_key,
            jwt_token,
            organization_id: config.organization.clone(),
            api_url: config.api_url.clone(),
            target: config.target.clone(),
            user_agent: Some(format!("sandbox-driver/{}", env!("CARGO_PKG_VERSION"))),
            ..DaytonaConfig::default()
        };
        let provider = DaytonaProvider::connect_explicit(sdk_config)
            .await
            .map_err(|error| classify("connecting to Daytona", error))?;
        let organization = organization(&provider, config.organization.as_deref()).await?;
        let namespace = NamespaceId::try_new(format!("daytona:{organization}")).map_err(|_| {
            Error::Transport {
                message: "Daytona reported an unusable organization id".to_owned(),
                outcome: MutationOutcome::NotStarted,
            }
        })?;
        Ok(Self {
            entry: name,
            provider,
            descriptor: descriptor(schemas, namespace),
            runner_image: config
                .runner_image
                .unwrap_or_else(|| DEFAULT_RUNNER_IMAGE.to_owned()),
            closed: CancellationToken::new(),
        })
    }

    fn ensure_open(&self) -> Result<(), Error> {
        super::ensure_open(&self.closed)
    }

    fn reference(&self, id: SandboxId) -> SandboxRef {
        SandboxRef {
            provider: self.entry.clone(),
            namespace: self.descriptor.namespace.id.clone(),
            id,
        }
    }

    fn workload(&self, handle: Arc<DaytonaSandbox>, env: BTreeMap<String, String>) -> Workload {
        let reference = self.reference(handle_id(&handle));
        Workload::new(reference, handle, env, self.closed.clone())
    }

    /// The sandbox `id` when it exists and this contract created it.
    async fn contract_sandbox(
        &self,
        id: &SandboxId,
    ) -> Result<Option<daytona_sdk::Sandbox>, Error> {
        let Some(sdk) = find_sandbox(&self.provider.client, id.as_str())
            .await
            .map_err(|error| from_sdk("fetching sandbox", &error))?
        else {
            return Ok(None);
        };
        if map_state(sdk.state) == LegacyState::Deleted {
            return Ok(None);
        }
        // A sandbox without the contract's recipe label was made by someone
        // else, or by the legacy provider; it exists, so it is not absent.
        if !sdk.labels.contains_key(RECIPE_LABEL) {
            return Err(Error::NotOwned { id: id.to_string() });
        }
        Ok(Some(sdk))
    }

    /// Daytona refuses a duplicate name with a conflict; report the
    /// existing sandbox's id when it can be read.
    async fn name_conflict(&self, name: Option<&str>, error: Error) -> Error {
        let (Some(name), Error::Busy { .. }) = (name, &error) else {
            return error;
        };
        match self.provider.client.get(name).await {
            Ok(existing) if existing.name == name => Error::AlreadyExists {
                name: name.to_owned(),
                id:   existing.id,
            },
            _ => error,
        }
    }
}

fn handle_id(handle: &DaytonaSandbox) -> SandboxId {
    sandbox_driver::Sandbox::id(handle).clone()
}

/// The API key's own organization, which is where its sandboxes live, or
/// the explicit organization of a JWT.
async fn organization(
    provider: &DaytonaProvider,
    configured: Option<&str>,
) -> Result<String, Error> {
    if !provider.uses_api_key() {
        return configured
            .map(str::to_owned)
            .ok_or_else(|| Error::Transport {
                message: "no organization for the JWT credential".to_owned(),
                outcome: MutationOutcome::NotStarted,
            });
    }
    let unavailable = |detail: &dyn Display| Error::Unavailable {
        message: format!("{READING_ORGANIZATION}: {detail}"),
        outcome: MutationOutcome::NotStarted,
    };
    let response = provider
        .current_api_key()
        .await
        .map_err(|error| unavailable(&error))?;
    let status = response.status().as_u16();
    let message = format!("{READING_ORGANIZATION}: HTTP {status}");
    match status {
        200..=299 => {}
        401 => return Err(Error::Unauthenticated { message }),
        403 => return Err(Error::PermissionDenied { message }),
        _ => return Err(unavailable(&format_args!("HTTP {status}"))),
    }
    let key: CurrentApiKey = response.json().await.map_err(|error| unavailable(&error))?;
    key.organization_id
        .filter(|id| !id.is_empty())
        .or_else(|| configured.map(str::to_owned))
        .ok_or_else(|| Error::Transport {
            message: "Daytona did not report the API key's organization; set organization"
                .to_owned(),
            outcome: MutationOutcome::NotStarted,
        })
}

fn descriptor(schemas: ProviderSchemas, namespace: NamespaceId) -> Descriptor {
    debug_assert_eq!(schemas, DaytonaFactory::schemas());
    Descriptor {
        schemas,
        namespace: Namespace {
            id:    namespace,
            scope: NamespaceScope::Remote,
        },
        // The sandboxes this provider creates are Daytona's container class.
        isolation: Isolation::Container,
        durability: Durability::Remote,
        access: AccessScope::Shared,
        sources: BTreeSet::from([
            SourceKind::Image,
            SourceKind::Dockerfile,
            SourceKind::Snapshot,
        ]),
        locality: Locality::default(),
        resources: BTreeSet::from([
            ResourceCapability::Cpu,
            ResourceCapability::Memory,
            ResourceCapability::Disk,
        ]),
        network: BTreeSet::from([
            NetworkMode::AllowAll,
            NetworkMode::Block,
            NetworkMode::CidrAllowList,
            NetworkMode::DomainAllowList,
        ]),
        ports: PortSupport::Any,
        capabilities: CapabilitySet {
            lifecycle:        BTreeSet::new(),
            endpoints:        BTreeSet::new(),
            services:         true,
            containers:       true,
            container_fields: BTreeSet::from([
                ContainerField::Init,
                ContainerField::Privileged,
                ContainerField::CapabilitiesAdd,
                ContainerField::CapabilitiesDrop,
                ContainerField::ShmSizeMb,
            ]),
            timers:           BTreeSet::from([
                TimerCapability::AutoStop,
                TimerCapability::AutoArchive,
                TimerCapability::AutoDelete,
                TimerCapability::Ttl,
            ]),
        },
    }
}

#[async_trait]
impl ProviderRuntime for DaytonaRuntime {
    async fn describe(&self) -> Result<Descriptor, Error> {
        self.ensure_open()?;
        Ok(self.descriptor.clone())
    }

    async fn health(&self) -> Result<Health, Error> {
        self.ensure_open()?;
        let health = self
            .provider
            .health()
            .await
            .map_err(|error| classify("checking health", error))?;
        Ok(Health {
            healthy: health.status == HealthStatus::Ok,
            message: health.message,
        })
    }

    #[tracing::instrument(skip_all, fields(provider_entry = %self.entry), err)]
    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error> {
        self.ensure_open()?;
        let WorkloadAdmission { spec, credentials } = admission;
        spec.validate_for(&self.descriptor)?;
        let plan = spec::plan(&spec, &self.runner_image)?;
        let auth = runner::service_auth(&spec.services, &credentials)?;
        let provision = plan.nested.map(|nested| -> Provision {
            Box::new(move |handle| runner::provision(handle, nested, auth).boxed())
        });
        let created = self
            .provider
            .create_with(&plan.legacy, None, &plan.labels, provision)
            .await;
        let handle = match created {
            Ok(handle) => handle,
            Err(error) => {
                let error = classify("creating sandbox", error);
                return Err(self.name_conflict(spec.name.as_deref(), error).await);
            }
        };
        tracing::info!(
            sandbox_id = %handle_id(&handle),
            nested = handle.runs_in_container(),
            "daytona workload created"
        );
        Ok(Box::new(self.workload(handle, spec.env)))
    }

    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error> {
        self.ensure_open()?;
        let sdk = self
            .contract_sandbox(id)
            .await?
            .ok_or_else(|| Error::NotFound {
                resource: "sandbox".to_owned(),
                id:       id.to_string(),
            })?;
        let env = public_env(&sdk.env);
        let handle = DaytonaSandbox::build(
            &self.provider.client,
            self.provider.capabilities(),
            sdk,
            EventEmitter::disabled(DaytonaFactory::kind()),
        )
        .await
        .map_err(|error| classify("attaching sandbox", error))?;
        Ok(Box::new(self.workload(handle, env)))
    }

    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error> {
        self.ensure_open()?;
        let mut labels: HashMap<String, String> = filter.0.clone().into_iter().collect();
        labels.insert(MANAGED_LABEL.to_owned(), "true".to_owned());
        let items: Vec<SandboxListItem> = self
            .provider
            .client
            .list_all(Some(&labels), Some(LIST_PAGE_SIZE))
            .try_collect()
            .await
            .map_err(|error| from_sdk("listing sandboxes", &error))?;
        items
            .into_iter()
            .filter(|item| item.labels.contains_key(RECIPE_LABEL))
            .map(|item| {
                let id = SandboxId::try_new(&item.id).map_err(|_| Error::Transport {
                    message: "Daytona listed an unusable sandbox id".to_owned(),
                    outcome: MutationOutcome::Unknown,
                })?;
                Ok(SandboxSummary {
                    reference: self.reference(id),
                    name:      (!item.name.is_empty()).then(|| item.name.clone()),
                    state:     contract_state(map_state(item.state)),
                    labels:    public_labels(&item.labels),
                })
            })
            .collect()
    }

    #[tracing::instrument(skip_all, fields(provider_entry = %self.entry, sandbox_id = %id), err)]
    async fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        self.ensure_open()?;
        // Everything nested lives inside the sandbox, so its confirmed
        // removal is the confirmed removal of every managed resource.
        if self.contract_sandbox(id).await?.is_none() {
            return Ok(());
        }
        let confirmed = time::timeout(
            FAILED_CREATE_CLEANUP_BUDGET,
            cleanup::delete_and_confirm(&self.provider.client, id.as_str()),
        )
        .await;
        let remaining = || {
            vec![RemainingResource {
                kind: "sandbox".to_owned(),
                id:   id.to_string(),
            }]
        };
        match confirmed {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => match classify("destroying sandbox", error) {
                // A refused delete was not admitted; the sandbox is intact.
                error if refused(&error) => Err(error),
                error => Err(Error::IncompleteCleanup {
                    message:   error.to_string(),
                    remaining: remaining(),
                }),
            },
            Err(_) => Err(Error::IncompleteCleanup {
                message:   "removal was not confirmed within the cleanup budget".to_owned(),
                remaining: remaining(),
            }),
        }
    }

    async fn shutdown(&self) -> Result<(), Error> {
        // Nothing runs in the background; durable sandboxes stay as they are.
        self.closed.cancel();
        Ok(())
    }
}

/// The workload environment Daytona stores, minus the blank `BASH_ENV`
/// the provider adds to every sandbox.
fn public_env(env: &HashMap<String, String>) -> BTreeMap<String, String> {
    env.iter()
        .filter(|(key, value)| !(key.as_str() == BASH_ENV_VAR && value.is_empty()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use sandbox_driver::contract::{
        CatalogOptions, Environment, EnvironmentName, ExecControls, ExecSpec, OneShotImage,
        OneShotSpec, ProviderEntry, Registry, SandboxSpec, SandboxState, Sandboxes, SecretResolver,
        Source, StaticEnvironments, Termination,
    };
    use tokio::io::{AsyncReadExt as _, repeat};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::fake_daytona::{FakeDaytona, Reply};

    struct Secrets(Option<&'static str>);

    #[async_trait]
    impl SecretResolver for Secrets {
        async fn resolve(&self, name: &str) -> Result<Option<String>, Error> {
            Ok((name == API_KEY)
                .then_some(self.0)
                .flatten()
                .map(str::to_owned))
        }
    }

    fn sandbox(id: &str, labels: &serde_json::Value) -> String {
        serde_json::json!({
            "id": id, "organizationId": "org-42", "name": id, "user": "daytona",
            "env": {"CI": "1", "BASH_ENV": ""}, "labels": labels, "public": false,
            "networkBlockAll": false, "target": "us", "cpu": 2.0, "gpu": 0.0,
            "memory": 4.0, "disk": 10.0, "state": "stopped",
            "toolboxProxyUrl": "http://unused",
        })
        .to_string()
    }

    /// Direct workload `sb-1`, started, last changed at `updated_at`.
    fn started(updated_at: &str) -> String {
        let mut record: serde_json::Value = serde_json::from_str(&sandbox(
            "sb-1",
            &serde_json::json!({
                "sh.sandbox-driver.managed": "true",
                "sh.sandbox-driver.recipe": "direct",
                "sh.sandbox-driver.working-directory": "/workspace",
            }),
        ))
        .expect("sandbox json");
        record["state"] = "started".into();
        record["updatedAt"] = updated_at.into();
        record.to_string()
    }

    fn catalog(fake: &FakeDaytona, key: Option<&'static str>) -> Sandboxes {
        let entry: ProviderEntry = serde_json::from_value(serde_json::json!({
            "plugin": "daytona",
            "config": {"api_url": fake.url()},
            "secrets": [API_KEY],
        }))
        .expect("valid entry");
        let registry = Registry::new()
            .builtin(DaytonaFactory::kind(), Arc::new(DaytonaFactory))
            .expect("one registration");
        let environment = Environment {
            provider: ProviderName::try_new("cloud").unwrap(),
            spec:     SandboxSpec::new(Source::Image("buildpack-deps:noble".to_owned())),
        };
        Sandboxes::try_new(
            [(ProviderName::try_new("cloud").unwrap(), entry)],
            Arc::new(StaticEnvironments(BTreeMap::from([(
                EnvironmentName::try_new("cloud").unwrap(),
                environment,
            )]))),
            &registry,
            Arc::new(Secrets(key)),
            CatalogOptions {
                environment: BTreeMap::new(),
                ..CatalogOptions::default()
            },
        )
        .expect("valid catalog")
    }

    fn reference(id: &str) -> SandboxRef {
        SandboxRef {
            provider:  ProviderName::try_new("cloud").unwrap(),
            namespace: NamespaceId::try_new("daytona:org-42").unwrap(),
            id:        SandboxId::try_new(id).unwrap(),
        }
    }

    #[tokio::test]
    async fn the_catalog_reaches_daytona_through_the_entry_and_fences_admission_on_its_state() {
        let ours = sandbox(
            "sb-ours",
            &serde_json::json!({
                "sh.sandbox-driver.managed": "true",
                "sh.sandbox-driver.recipe": "direct",
                "sh.sandbox-driver.working-directory": "/workspace",
                "sh.sandbox-driver.docker-target": "virtual_machine",
                "job": "1842",
            }),
        );
        let legacy = sandbox(
            "sb-legacy",
            &serde_json::json!({"sh.sandbox-driver.managed": "true"}),
        );
        let fake = FakeDaytona::start(move |_| {
            Arc::new(move |method, target| match (method, target) {
                ("GET", target) if target.ends_with("/api-keys/current") => Reply::Json(
                    200,
                    r#"{"name":"k","permissions":[],"organizationId":"org-42"}"#.to_owned(),
                ),
                ("GET", target) if target.contains("/sandbox/sb-ours?") => {
                    Reply::Json(200, ours.clone())
                }
                ("GET", target) if target.contains("/sandbox/sb-legacy?") => {
                    Reply::Json(200, legacy.clone())
                }
                _ => Reply::Json(404, r#"{"message":"not found"}"#.to_owned()),
            })
        })
        .await;

        // Without the named secret nothing is contacted.
        let unconfigured = catalog(&fake, None);
        assert!(matches!(
            unconfigured.provider("cloud").unwrap().describe().await,
            Err(Error::MissingSecret { name, .. }) if name == API_KEY
        ));
        assert!(fake.requests().is_empty(), "{:?}", fake.requests());

        let sandboxes = catalog(&fake, Some("test-key"));
        let descriptor = sandboxes
            .provider("cloud")
            .unwrap()
            .describe()
            .await
            .unwrap();
        assert_eq!(descriptor.namespace.id.as_str(), "daytona:org-42");
        assert_eq!(descriptor.access, AccessScope::Shared);

        // A sandbox the contract did not create exists, so it is not absent.
        assert!(matches!(
            sandboxes.attach(&reference("sb-legacy")).await,
            Err(Error::NotOwned { .. })
        ));
        assert!(matches!(
            sandboxes.attach(&reference("sb-gone")).await,
            Err(Error::NotFound { .. })
        ));

        let attached = sandboxes.attach(&reference("sb-ours")).await.unwrap();
        assert_eq!(
            attached.env(),
            &BTreeMap::from([("CI".to_owned(), "1".to_owned())])
        );
        assert_eq!(attached.working_directory(), Path::new("/workspace"));
        let status = attached.status().await.unwrap();
        assert_eq!(status.state, SandboxState::Stopped);
        assert_eq!(
            status.labels,
            BTreeMap::from([("job".to_owned(), "1842".to_owned())])
        );

        // A stopped sandbox admits nothing, and nothing reaches its toolbox.
        let refused = attached
            .exec(ExecSpec::argv(["true"]), ExecControls::default())
            .await;
        assert!(matches!(refused, Err(Error::Busy { .. })), "{refused:?}");
        // A one-shot takes no input; it is refused, not dropped.
        let one_shot = attached
            .containers()
            .expect("containers")
            .run(
                OneShotSpec::new(OneShotImage::Image("alpine".to_owned())),
                ExecControls {
                    stdin: Some(Box::pin(Cursor::new(b"input".to_vec()))),
                    ..ExecControls::default()
                },
            )
            .await;
        assert!(
            matches!(&one_shot, Err(Error::Unsupported { capability }) if capability == "containers.stdin"),
            "{one_shot:?}"
        );
        assert!(
            fake.requests()
                .iter()
                .all(|request| !request.contains("toolbox")),
            "{:?}",
            fake.requests()
        );
    }

    /// Daytona can stop and restart a sandbox in about a second and then
    /// answer the dead command's output poll with 400. Only a changed
    /// record, not the 400 itself, may read as the stop that killed it.
    #[tokio::test]
    async fn a_command_whose_sandbox_restarted_under_it_was_killed() {
        for restarted in [true, false] {
            let polled = Arc::new(AtomicBool::new(false));
            let fake = FakeDaytona::start({
                let polled = Arc::clone(&polled);
                move |address| {
                    Arc::new(move |method, target| match (method, target) {
                        ("GET", target) if target.ends_with("/api-keys/current") => Reply::Json(
                            200,
                            r#"{"name":"k","permissions":[],"organizationId":"org-42"}"#.to_owned(),
                        ),
                        ("GET", target)
                            if target.starts_with("/sandbox/sb-1/toolbox-proxy-url") =>
                        {
                            Reply::Json(200, format!(r#"{{"url":"http://{address}/toolbox"}}"#))
                        }
                        ("GET", target) if target.starts_with("/sandbox/sb-1?") => {
                            let generation = if restarted && polled.load(Ordering::SeqCst) {
                                "2026-11-10T19:22:18.690Z"
                            } else {
                                "2026-11-10T19:22:08.169Z"
                            };
                            Reply::Json(200, started(generation))
                        }
                        ("POST", "/toolbox/sb-1/process/session") => {
                            Reply::Json(201, "{}".to_owned())
                        }
                        ("POST", target) if target.ends_with("/exec") => {
                            Reply::Json(200, r#"{"cmdId":"cmd-1"}"#.to_owned())
                        }
                        ("GET", target) if target.contains("/command/cmd-1") => {
                            polled.store(true, Ordering::SeqCst);
                            Reply::Json(400, r#"{"message":"bad request"}"#.to_owned())
                        }
                        ("DELETE", _) => Reply::Json(200, "{}".to_owned()),
                        _ => Reply::Json(404, "{}".to_owned()),
                    })
                }
            })
            .await;
            let sandbox = catalog(&fake, Some("test-key"))
                .attach(&reference("sb-1"))
                .await
                .expect("attach");
            let result = sandbox
                .exec(ExecSpec::argv(["sleep", "60"]), ExecControls {
                    kill: Some(CancellationToken::new()),
                    ..ExecControls::default()
                })
                .await;
            assert!(
                fake.requests().iter().any(|r| r.contains("/command/cmd-1")),
                "the command was polled: {:?}",
                fake.requests()
            );
            if restarted {
                assert!(
                    matches!(&result, Ok(outcome) if outcome.termination == Termination::Killed),
                    "{result:?}"
                );
            } else {
                assert!(
                    !matches!(&result, Ok(outcome) if outcome.termination == Termination::Killed),
                    "no restart, so no stop to blame: {result:?}"
                );
            }
        }
    }

    /// A write longer than the upload limit is refused before anything is
    /// uploaded, having read at most one byte past the limit.
    #[tokio::test]
    async fn an_oversized_write_is_refused_before_upload() {
        let fake = FakeDaytona::start(|address| {
            Arc::new(move |method, target| match (method, target) {
                ("GET", target) if target.ends_with("/api-keys/current") => Reply::Json(
                    200,
                    r#"{"name":"k","permissions":[],"organizationId":"org-42"}"#.to_owned(),
                ),
                ("GET", target) if target.starts_with("/sandbox/sb-1/toolbox-proxy-url") => {
                    Reply::Json(200, format!(r#"{{"url":"http://{address}/toolbox"}}"#))
                }
                ("GET", target) if target.starts_with("/sandbox/sb-1?") => {
                    Reply::Json(200, started("2026-11-10T19:22:08.169Z"))
                }
                _ => Reply::Json(200, "{}".to_owned()),
            })
        })
        .await;
        let sandbox = catalog(&fake, Some("test-key"))
            .attach(&reference("sb-1"))
            .await
            .expect("attach");
        let limit = sandbox_driver::DEFAULT_BUFFER_BYTES as u64;
        let refused = sandbox
            .files()
            .put("big.bin", Box::pin(repeat(7).take(limit + 1)))
            .await;
        assert!(
            matches!(&refused, Err(Error::Unsupported { capability }) if capability.starts_with("file input")),
            "{refused:?}"
        );
        assert!(
            fake.requests()
                .iter()
                .all(|request| !request.contains("toolbox/")),
            "{:?}",
            fake.requests()
        );
    }
}
