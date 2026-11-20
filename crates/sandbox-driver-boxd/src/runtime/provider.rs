//! One activated boxd provider entry.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use sandbox_driver::{
    AccessScope, Activation, CapabilitySet, Descriptor, Durability, EndpointCapability, Error,
    Health, Isolation, LabelFilter, Locality, MutationOutcome, Namespace, NamespaceId,
    NamespaceScope, NetworkMode, PortSupport, Provider, ProviderName, ProviderSchemas,
    RemainingResource, ResourceCapability, Sandbox, SandboxId, SandboxRef, SandboxSummary,
    SourceKind, TimerCapability, WorkloadAdmission,
};
use serde::Deserialize;
use tokio::time;
use tokio_util::sync::CancellationToken;

use super::api::{
    CreateVmFromSnapshotRequest, CreateVmRequest, DestroyVmRequest, FsMkdirRequest,
    FsRealpathRequest, GetVmResponse, ListOrgsRequest, ListRegionsRequest, ListVmsRequest,
    SetVmEgressAllowRequest, UpdateVmLabelsRequest, VmConfig, WhoamiRequest,
};
use super::connection::{ApiKey, Connection};
use super::error::{classify, classify_spec, not_found, refused};
use super::handle::{self, Machine, Phase};
use super::labels::{self, Meta};
use super::spec::{self, Base, Plan};
use super::{API_KEY, BoxdFactory, CLEANUP_BUDGET, LIFECYCLE_BUDGET, POLL, ensure_open, exec};

const DEFAULT_API_URL: &str = "https://boxd.sh:9443";
const DEFAULT_AUTH_URL: &str = "https://app.boxd.sh/api/v1/auth/token";

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EntryConfig {
    api_url:  Option<String>,
    auth_url: Option<String>,
    org:      Option<String>,
    region:   Option<String>,
}

pub(super) struct BoxdRuntime {
    entry:      ProviderName,
    connection: Arc<Connection>,
    org:        String,
    descriptor: Descriptor,
    closed:     CancellationToken,
}

impl BoxdRuntime {
    /// Connects with exactly the entry's config and resolved secret, and
    /// establishes the namespace: the org and region machines are made in.
    /// No machine is touched.
    pub(super) async fn activate(activation: Activation) -> Result<Self, Error> {
        let Activation {
            name,
            entry,
            schemas,
            environment: _,
            secrets,
        } = activation;
        let invalid = |path: &str, message: String| Error::InvalidConfig {
            entry: name.clone(),
            path: path.to_owned(),
            message,
        };
        let config = EntryConfig::deserialize(serde_json::Value::Object(
            entry.config.into_iter().collect(),
        ))
        .map_err(|error| invalid("config", error.to_string()))?;
        let api_key =
            secrets
                .values()
                .get(API_KEY)
                .cloned()
                .ok_or_else(|| Error::MissingSecret {
                    entry: name.clone(),
                    name:  API_KEY.to_owned(),
                })?;
        let api_key = ApiKey(api_key);
        let auth_url = config
            .auth_url
            .unwrap_or_else(|| DEFAULT_AUTH_URL.to_owned());
        let home_url = config.api_url.unwrap_or_else(|| DEFAULT_API_URL.to_owned());
        let home = Connection::new(&home_url, auth_url.clone(), api_key.clone())
            .map_err(|message| invalid("api_url", message))?;
        let org =
            organization(&home, config.org.as_deref())
                .await
                .map_err(|error| match error {
                    Error::NotFound { .. } => invalid(
                        "org",
                        "the API key cannot reach this organization".to_owned(),
                    ),
                    error => error,
                })?;
        let (region, endpoint) = region(&home, &org, config.region.as_deref())
            .await
            .map_err(|error| match error {
                Error::NotFound { .. } => invalid(
                    "region",
                    "boxd has no such region enabled for this organization".to_owned(),
                ),
                error => error,
            })?;
        let connection = match endpoint {
            Some(endpoint) => Connection::new(&endpoint, auth_url, api_key)
                .map_err(|message| invalid("region", message))?,
            None => home,
        };
        let namespace =
            NamespaceId::try_new(format!("boxd:{org}/{region}")).map_err(|_| Error::Transport {
                message: "boxd reported an unusable organization or region id".to_owned(),
                outcome: MutationOutcome::NotStarted,
            })?;
        Ok(Self {
            entry: name,
            connection: Arc::new(connection),
            org,
            descriptor: descriptor(schemas, namespace),
            closed: CancellationToken::new(),
        })
    }

    fn ensure_open(&self) -> Result<(), Error> {
        ensure_open(&self.closed)
    }

    fn reference(&self, id: SandboxId) -> SandboxRef {
        SandboxRef {
            provider: self.entry.clone(),
            namespace: self.descriptor.namespace.id.clone(),
            id,
        }
    }

    fn machine(&self, vm: &GetVmResponse, meta: Meta) -> Result<Machine, Error> {
        let id = SandboxId::try_new(&vm.vm_id).map_err(|_| Error::Transport {
            message: "boxd returned an unusable machine id".to_owned(),
            outcome: MutationOutcome::Unknown,
        })?;
        Ok(Machine::new(
            Arc::clone(&self.connection),
            self.reference(id),
            vm.name.clone(),
            meta,
            self.closed.clone(),
        ))
    }

    /// The machine `id` when it exists and this contract created it.
    async fn contract_machine(&self, id: &SandboxId) -> Result<Option<GetVmResponse>, Error> {
        let Some(vm) = handle::fetch(&self.connection, id.as_str()).await? else {
            return Ok(None);
        };
        if Phase::of(&vm.status) == Phase::Destroyed {
            return Ok(None);
        }
        // A machine without the managed label was made by someone else; it
        // exists, so it is not absent.
        if !labels::is_managed(&stored(&vm)) {
            return Err(Error::NotOwned { id: id.to_string() });
        }
        Ok(Some(vm))
    }

    /// Creates the machine and returns its id as soon as boxd reports one.
    async fn launch(
        &self,
        plan: &Plan,
        labels: BTreeMap<String, String>,
    ) -> Result<GetVmResponse, Error> {
        let config = VmConfig {
            vcpu: plan.vcpu,
            memory_bytes: plan.memory_bytes,
            ..VmConfig::default()
        };
        let mut api = self.connection.api();
        let response = match &plan.base {
            Base::Default | Base::Image(_) => {
                let image_ref = match &plan.base {
                    Base::Image(image) => image.clone(),
                    _ => String::new(),
                };
                let request = CreateVmRequest {
                    name: plan.name.clone(),
                    image_ref,
                    config: Some(config),
                    org: self.org.clone(),
                    isolated: plan.isolated,
                    labels: labels.into_iter().collect(),
                    delete_after_secs: plan.delete_after_secs,
                    ..CreateVmRequest::default()
                };
                api.create_vm(self.connection.unary(request).await?).await
            }
            Base::Snapshot(snapshot) => {
                let request = CreateVmFromSnapshotRequest {
                    snapshot: snapshot.clone(),
                    name: plan.name.clone(),
                    config: Some(config),
                    org: self.org.clone(),
                    isolated: plan.isolated,
                    labels: labels.into_iter().collect(),
                    delete_after_secs: plan.delete_after_secs,
                    ..CreateVmFromSnapshotRequest::default()
                };
                api.create_vm_from_snapshot(self.connection.unary(request).await?)
                    .await
            }
        };
        match response {
            Ok(response) => {
                let response = response.into_inner();
                Ok(response.machine.unwrap_or(GetVmResponse {
                    vm_id: response.vm_id,
                    name: response.name,
                    status: response.status,
                    ..GetVmResponse::default()
                }))
            }
            Err(status) if not_found(&status) => Err(Error::InvalidSpec {
                path:    "source".to_owned(),
                message: status.message().to_owned(),
            }),
            Err(status) if status.code() == tonic::Code::AlreadyExists && !plan.name.is_empty() => {
                Err(self.name_conflict(&plan.name, &status).await)
            }
            Err(status) => Err(classify_spec("spec", &status)),
        }
    }

    async fn name_conflict(&self, name: &str, status: &tonic::Status) -> Error {
        match handle::fetch(&self.connection, name).await {
            Ok(Some(existing)) if existing.name == name => Error::AlreadyExists {
                name: name.to_owned(),
                id:   existing.vm_id,
            },
            _ => classify_spec("spec", status),
        }
    }

    /// Everything after boxd accepted the machine: running, egress, working
    /// directory, and the labels that make it attachable.
    async fn provision(
        &self,
        vm_id: &str,
        plan: &Plan,
        caller: &BTreeMap<String, String>,
    ) -> Result<(GetVmResponse, Meta), Error> {
        let vm = self.until_running(vm_id).await?;
        let mut api = self.connection.api();
        if let Some(entries) = &plan.egress {
            let request = SetVmEgressAllowRequest {
                vm:      vm_id.to_owned(),
                entries: entries.clone(),
            };
            api.set_vm_egress_allow(self.connection.unary(request).await?)
                .await
                .map_err(|status| classify_spec("network", &status))?;
        }
        let working_directory = if let Some(directory) = &plan.working_directory {
            let request = FsMkdirRequest {
                vm_id: vm_id.to_owned(),
                path: directory.clone().into_bytes(),
                ..FsMkdirRequest::default()
            };
            match api.fs_mkdir(self.connection.unary(request).await?).await {
                Ok(_) => {}
                Err(status) if status.code() == tonic::Code::PermissionDenied => {
                    self.make_directory_as_root(vm_id, directory).await?;
                }
                Err(status) => return Err(classify_spec("working_directory", &status)),
            }
            directory.clone()
        } else {
            let request = FsRealpathRequest {
                vm_id: vm_id.to_owned(),
                path:  b".".to_vec(),
            };
            let home = api
                .fs_realpath(self.connection.unary(request).await?)
                .await
                .map_err(|status| classify("resolving the home directory", &status))?
                .into_inner();
            String::from_utf8(home.path).map_err(|_| Error::Unsupported {
                capability: "a home directory that is not UTF-8".to_owned(),
            })?
        };
        let meta = Meta {
            working_directory,
            env: plan.env.clone(),
        };
        // Exactly these labels: a snapshot brings its source's labels, which
        // must not become this machine's.
        let request = UpdateVmLabelsRequest {
            vm:          vm_id.to_owned(),
            set:         labels::encode(caller, &meta)?.into_iter().collect(),
            remove:      Vec::new(),
            replace_all: true,
        };
        api.update_vm_labels(self.connection.unary(request).await?)
            .await
            .map_err(|status| classify_spec("labels", &status))?;
        Ok((vm, meta))
    }

    /// Creates a working directory the workload user may not create itself,
    /// with passwordless `sudo` where the image has it, and gives it to that
    /// user.
    async fn make_directory_as_root(&self, vm_id: &str, directory: &str) -> Result<(), Error> {
        let quoted = exec::quote(directory);
        let line =
            format!("sudo -n mkdir -p {quoted} && sudo -n chown \"$(id -u):$(id -g)\" {quoted}");
        match exec::exit_code(&self.connection, vm_id, line, &self.closed).await {
            Some(0) => Ok(()),
            _ => Err(Error::InvalidSpec {
                path:    "working_directory".to_owned(),
                message: format!(
                    "the workload user cannot create {directory}, and the image has no \
                     passwordless sudo to create it"
                ),
            }),
        }
    }

    async fn until_running(&self, vm_id: &str) -> Result<GetVmResponse, Error> {
        let started = Instant::now();
        loop {
            ensure_open(&self.closed)?;
            let vm = handle::fetch(&self.connection, vm_id)
                .await?
                .ok_or_else(|| Error::Unhealthy {
                    message: "boxd removed the machine while it was starting".to_owned(),
                })?;
            match Phase::of(&vm.status) {
                Phase::Running => return Ok(vm),
                Phase::Failed | Phase::Destroying | Phase::Destroyed => {
                    return Err(Error::Unhealthy {
                        message: format!("the machine is {} instead of running", vm.status),
                    });
                }
                _ if started.elapsed() > LIFECYCLE_BUDGET => {
                    return Err(Error::Unavailable {
                        message: "the machine did not start within the create budget".to_owned(),
                        outcome: MutationOutcome::Unknown,
                    });
                }
                _ => time::sleep(POLL).await,
            }
        }
    }

    /// Destroys `vm_id` and waits for boxd to no longer know it. `Ok` only
    /// once removal is confirmed.
    async fn remove(&self, vm_id: &str) -> Result<(), Error> {
        let request = self
            .connection
            .unary(DestroyVmRequest {
                vm_id: vm_id.to_owned(),
            })
            .await?;
        match self.connection.api().destroy_vm(request).await {
            Ok(_) => {}
            Err(status) if not_found(&status) => return Ok(()),
            Err(status) => return Err(classify("destroying machine", &status)),
        }
        let started = Instant::now();
        loop {
            match handle::fetch(&self.connection, vm_id).await {
                Ok(None) => return Ok(()),
                Ok(Some(vm)) if Phase::of(&vm.status) == Phase::Destroyed => return Ok(()),
                _ if started.elapsed() > CLEANUP_BUDGET => {
                    return Err(Error::Unavailable {
                        message: "removal was not confirmed within the cleanup budget".to_owned(),
                        outcome: MutationOutcome::Unknown,
                    });
                }
                _ => time::sleep(POLL).await,
            }
        }
    }

    /// After a failed create: the original failure once the machine is
    /// confirmed gone, otherwise incomplete cleanup naming it.
    async fn abandon(&self, vm_id: &str, failure: Error) -> Error {
        match self.remove(vm_id).await {
            Ok(()) => failure,
            Err(cleanup) => {
                tracing::warn!(error = ?cleanup, "failed create left a machine");
                Error::IncompleteCleanup {
                    message:   format!("{failure}; cleanup: {cleanup}"),
                    remaining: vec![RemainingResource {
                        kind: "machine".to_owned(),
                        id:   vm_id.to_owned(),
                    }],
                }
            }
        }
    }
}

fn stored(vm: &GetVmResponse) -> BTreeMap<String, String> {
    vm.labels.clone().into_iter().collect()
}

/// The org machines are made in: the configured one, by name, slug or id,
/// or the one the API key is fenced to.
async fn organization(connection: &Connection, configured: Option<&str>) -> Result<String, Error> {
    let orgs = connection
        .read(|| async {
            let request = connection.unary(ListOrgsRequest {}).await?;
            Ok(connection.api().list_orgs(request).await)
        })
        .await?
        .map_err(|status| classify("listing organizations", &status))?
        .into_inner();
    let found = match configured {
        Some(wanted) => orgs
            .orgs
            .into_iter()
            .find(|org| org.id == wanted || org.name == wanted || org.slug == wanted)
            .map(|org| org.id),
        None => Some(orgs.default_org_id).filter(|id| !id.is_empty()),
    };
    found.ok_or_else(|| Error::NotFound {
        resource: "organization".to_owned(),
        id:       configured.unwrap_or_default().to_owned(),
    })
}

/// The region machines are made in, and its endpoint when it is not the
/// one `connection` already reaches.
async fn region(
    connection: &Connection,
    org: &str,
    configured: Option<&str>,
) -> Result<(String, Option<String>), Error> {
    let regions = connection
        .read(|| async {
            let request = connection
                .unary(ListRegionsRequest {
                    org_id: org.to_owned(),
                })
                .await?;
            Ok(connection.api().list_regions(request).await)
        })
        .await?
        .map_err(|status| classify("listing regions", &status))?
        .into_inner();
    let here = regions.this_region;
    let Some(wanted) = configured.filter(|wanted| *wanted != here) else {
        return Ok((here, None));
    };
    regions
        .regions
        .into_iter()
        .find(|region| region.id == wanted && region.org_state == "enabled")
        .map(|region| (region.id, Some(region.api_endpoint)))
        .ok_or_else(|| Error::NotFound {
            resource: "region".to_owned(),
            id:       wanted.to_owned(),
        })
}

fn descriptor(schemas: ProviderSchemas, namespace: NamespaceId) -> Descriptor {
    debug_assert_eq!(schemas, BoxdFactory::schemas());
    Descriptor {
        schemas,
        namespace: Namespace {
            id:    namespace,
            scope: NamespaceScope::Remote,
        },
        isolation: Isolation::Vm,
        durability: Durability::Remote,
        access: AccessScope::Shared,
        sources: BTreeSet::from([SourceKind::Image, SourceKind::Snapshot]),
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
            endpoints: BTreeSet::from([EndpointCapability::ShellCommand]),
            timers: BTreeSet::from([TimerCapability::Ttl]),
            ..CapabilitySet::default()
        },
    }
}

#[async_trait]
impl Provider for BoxdRuntime {
    async fn describe(&self) -> Result<Descriptor, Error> {
        self.ensure_open()?;
        Ok(self.descriptor.clone())
    }

    async fn health(&self) -> Result<Health, Error> {
        self.ensure_open()?;
        let connection = &self.connection;
        let checked = connection
            .read(|| async {
                let request = connection.unary(WhoamiRequest {}).await?;
                Ok(connection.api().whoami(request).await)
            })
            .await
            .and_then(|answer| {
                answer
                    .map(drop)
                    .map_err(|status| classify("checking health", &status))
            });
        Ok(match checked {
            Ok(()) => Health {
                healthy: true,
                message: None,
            },
            Err(error) => Health {
                healthy: false,
                message: Some(error.to_string()),
            },
        })
    }

    #[tracing::instrument(skip_all, fields(provider_entry = %self.entry), err)]
    async fn create(&self, admission: WorkloadAdmission) -> Result<Box<dyn Sandbox>, Error> {
        self.ensure_open()?;
        let WorkloadAdmission {
            spec,
            credentials: _,
        } = admission;
        spec.validate_for(&self.descriptor)?;
        let plan = spec::plan(&spec)?;
        // Refuse labels boxd cannot hold before anything exists. The
        // working directory is not known yet; it only adds metadata.
        let provisional = Meta {
            working_directory: plan.working_directory.clone().unwrap_or_default(),
            env:               plan.env.clone(),
        };
        let initial = labels::encode(&plan.labels, &provisional)?;
        let launched = self.launch(&plan, initial).await?;
        let vm_id = launched.vm_id.clone();
        tracing::info!(machine_id = %vm_id, "boxd machine accepted");
        match self.provision(&vm_id, &plan, &plan.labels).await {
            Ok((vm, meta)) => Ok(Box::new(self.machine(&vm, meta)?)),
            Err(failure) => Err(self.abandon(&vm_id, failure).await),
        }
    }

    async fn attach(&self, id: &SandboxId) -> Result<Box<dyn Sandbox>, Error> {
        self.ensure_open()?;
        let vm = self
            .contract_machine(id)
            .await?
            .ok_or_else(|| Error::NotFound {
                resource: "sandbox".to_owned(),
                id:       id.to_string(),
            })?;
        let meta = labels::meta(&stored(&vm))
            .filter(|meta| !meta.working_directory.is_empty())
            .ok_or_else(|| Error::Unhealthy {
                message: "the machine's sandbox metadata is incomplete".to_owned(),
            })?;
        Ok(Box::new(self.machine(&vm, meta)?))
    }

    async fn list(&self, filter: &LabelFilter) -> Result<Vec<SandboxSummary>, Error> {
        self.ensure_open()?;
        let connection = &self.connection;
        let vms = connection
            .read(|| async {
                let request = connection
                    .unary(ListVmsRequest {
                        org: self.org.clone(),
                        label_selector: vec![labels::managed_selector()],
                        ..ListVmsRequest::default()
                    })
                    .await?;
                Ok(connection.api().list_vms(request).await)
            })
            .await?
            .map_err(|status| classify("listing machines", &status))?
            .into_inner()
            .vms;
        let mut summaries = Vec::new();
        for vm in vms {
            let stored = stored(&vm);
            let caller = labels::caller_labels(&stored);
            if !labels::is_managed(&stored) || !filter.matches(&caller) {
                continue;
            }
            let id = SandboxId::try_new(&vm.vm_id).map_err(|_| Error::Transport {
                message: "boxd listed an unusable machine id".to_owned(),
                outcome: MutationOutcome::Unknown,
            })?;
            summaries.push(SandboxSummary {
                reference: self.reference(id),
                name:      (!vm.name.is_empty()).then(|| vm.name.clone()),
                state:     Phase::of(&vm.status).state(),
                labels:    caller,
            });
        }
        Ok(summaries)
    }

    #[tracing::instrument(skip_all, fields(provider_entry = %self.entry, sandbox_id = %id), err)]
    async fn destroy(&self, id: &SandboxId) -> Result<(), Error> {
        self.ensure_open()?;
        // Everything this provider makes lives inside the machine, so its
        // confirmed removal is the confirmed removal of every resource.
        if self.contract_machine(id).await?.is_none() {
            return Ok(());
        }
        match self.remove(id.as_str()).await {
            Ok(()) => Ok(()),
            // A refused destroy was not admitted; the machine is intact.
            Err(error) if refused(&error) => Err(error),
            Err(error) => Err(Error::IncompleteCleanup {
                message:   error.to_string(),
                remaining: vec![RemainingResource {
                    kind: "machine".to_owned(),
                    id:   id.to_string(),
                }],
            }),
        }
    }

    async fn shutdown(&self) -> Result<(), Error> {
        // Nothing runs in the background; durable machines stay as they are.
        self.closed.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::io::Cursor;
    use std::num::NonZeroU16;
    use std::process::Command as Shell;
    use std::sync::Mutex;
    use std::time::Duration;

    use sandbox_driver::{
        ByteStream, CatalogOptions, Environment, EnvironmentName, ExecControls, ExecSpec, Expose,
        NetworkPolicy, OutputSink, ProviderEntry, Registry, SandboxSpec, SandboxState, Sandboxes,
        SecretResolver, Source, StaticEnvironments, Termination,
    };
    use sandbox_driver_conformance::{Commands, Conformance};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::runtime::fake::{FakeBoxd, Faults};

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

    fn catalog(fake: &FakeBoxd, key: Option<&'static str>, spec: SandboxSpec) -> Sandboxes {
        let entry: ProviderEntry = serde_json::from_value(serde_json::json!({
            "plugin": "boxd",
            "config": {"api_url": fake.api_url(), "auth_url": fake.auth_url()},
            "secrets": [API_KEY],
        }))
        .expect("valid entry");
        let registry = Registry::new()
            .builtin(BoxdFactory::kind(), Arc::new(BoxdFactory))
            .expect("one registration");
        let provider = ProviderName::try_new("cloud").unwrap();
        Sandboxes::try_new(
            [(provider.clone(), entry)],
            Arc::new(StaticEnvironments(BTreeMap::from([(
                EnvironmentName::try_new("cloud").unwrap(),
                Environment { provider, spec },
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

    fn base() -> SandboxSpec {
        SandboxSpec::new(Source::Image(spec::BASE_IMAGE.to_owned()))
    }

    fn reference(id: &str) -> SandboxRef {
        SandboxRef {
            provider:  ProviderName::try_new("cloud").unwrap(),
            namespace: NamespaceId::try_new("boxd:org-1/fra").unwrap(),
            id:        SandboxId::try_new(id).unwrap(),
        }
    }

    async fn run(sandbox: &dyn Sandbox, argv: &[&str], input: Option<&[u8]>) -> (i32, String) {
        let output = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&output);
        let sink: OutputSink = Arc::new(move |_, bytes| {
            captured.lock().unwrap().extend(bytes);
            Box::pin(future::ready(Ok(())))
        });
        let outcome = sandbox
            .exec(ExecSpec::argv(argv.iter().copied()), ExecControls {
                sink: Some(sink),
                stdin: input.map(|bytes| -> ByteStream { Box::pin(Cursor::new(bytes.to_vec())) }),
                ..ExecControls::default()
            })
            .await
            .expect("exec admitted");
        assert_eq!(outcome.termination, Termination::Exited, "{argv:?}");
        let text = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
        (outcome.exit_code.expect("exited"), text)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_fake_passes_the_shared_contract() {
        let fake = FakeBoxd::start(Faults::default()).await;
        let commands = Commands {
            probe:        ExecSpec::argv(["printf", "conformance"]),
            probe_output: b"conformance".to_vec(),
            long_running: ExecSpec::argv(["sh", "-c", "echo ready; exec sleep 600"]),
        };
        let report = Conformance::new(catalog(&fake, Some("bxd_good"), base()), "cloud", commands)
            .with_peer(catalog(&fake, Some("bxd_good"), base()))
            .run()
            .await;
        report.assert_pass();
    }

    #[tokio::test]
    async fn credentials_gate_activation_and_the_namespace_is_the_org_and_region() {
        let fake = FakeBoxd::start(Faults::default()).await;
        let missing = catalog(&fake, None, base());
        assert!(matches!(
            missing.provider("cloud").unwrap().describe().await,
            Err(Error::MissingSecret { name, .. }) if name == API_KEY
        ));
        let rejected = catalog(&fake, Some("bxd_bad"), base());
        assert!(matches!(
            rejected.provider("cloud").unwrap().describe().await,
            Err(Error::Unauthenticated { .. })
        ));
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());

        let sandboxes = catalog(&fake, Some("bxd_good"), base());
        let descriptor = sandboxes
            .provider("cloud")
            .unwrap()
            .describe()
            .await
            .unwrap();
        assert_eq!(descriptor.namespace.id.as_str(), "boxd:org-1/fra");
        assert_eq!(descriptor.access, AccessScope::Shared);
    }

    #[tokio::test]
    async fn a_machine_made_elsewhere_exists_but_is_not_owned() {
        let fake = FakeBoxd::start(Faults::default()).await;
        fake.insert(GetVmResponse {
            vm_id: "vm-theirs".to_owned(),
            name: "theirs".to_owned(),
            status: "running".to_owned(),
            ..GetVmResponse::default()
        });
        let sandboxes = catalog(&fake, Some("bxd_good"), base());
        assert!(matches!(
            sandboxes.attach(&reference("vm-theirs")).await,
            Err(Error::NotOwned { .. })
        ));
        assert!(matches!(
            sandboxes.attach(&reference("vm-gone")).await,
            Err(Error::NotFound { .. })
        ));
        assert!(matches!(
            sandboxes.destroy(&reference("vm-theirs")).await,
            Err(Error::NotOwned { .. })
        ));
        assert!(fake.machine("vm-theirs").is_some());
        sandboxes
            .destroy(&reference("vm-gone"))
            .await
            .expect("absent is success");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn another_instance_recovers_labels_environment_and_directory() {
        let fake = FakeBoxd::start(Faults::default()).await;
        let mut spec = base();
        spec.env.insert("CI".to_owned(), "it's 1".to_owned());
        let awkward = "quotes='\" λ\n";
        let sandbox = catalog(&fake, Some("bxd_good"), spec.clone())
            .builder("cloud")
            .await
            .unwrap()
            .label("Job", awkward)
            .create()
            .await
            .expect("create");

        let other = catalog(&fake, Some("bxd_good"), spec);
        let attached = other.attach(&sandbox.reference()).await.expect("attach");
        assert_eq!(attached.working_directory(), sandbox.working_directory());
        let (code, ci) = run(attached.as_ref(), &["printenv", "CI"], None).await;
        assert_eq!((code, ci.as_str()), (0, "it's 1\n"));
        let (code, pwd) = run(attached.as_ref(), &["pwd"], None).await;
        assert_eq!(pwd.trim(), sandbox.working_directory().to_string_lossy());
        assert_eq!(code, 0);
        let (code, echoed) = run(attached.as_ref(), &["cat"], Some(b"input")).await;
        assert_eq!((code, echoed.as_str()), (0, "input"));
        let (code, _) = run(attached.as_ref(), &["sh", "-c", "exit 7"], None).await;
        assert_eq!(code, 7);

        let status = attached.status().await.unwrap();
        assert_eq!(
            status.labels,
            BTreeMap::from([("Job".to_owned(), awkward.to_owned())])
        );
        let found = other.find(LabelFilter::eq("Job", awkward)).await.unwrap();
        assert_eq!(found.sandboxes.len(), 1);

        let exposure = attached
            .ports()
            .expose(NonZeroU16::new(8080).unwrap(), Expose {
                signed: false,
                ttl_ms: None,
            })
            .await
            .unwrap();
        assert_eq!(exposure.url, "https://p8080.vm-1.boxd.sh");

        other.destroy(&sandbox.reference()).await.expect("destroy");
        assert!(fake.machine(sandbox.reference().id.as_str()).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_stopped_machine_admits_nothing_and_kills_what_it_ran() {
        let fake = FakeBoxd::start(Faults::default()).await;
        let sandboxes = catalog(&fake, Some("bxd_good"), base());
        let sandbox = sandboxes
            .builder("cloud")
            .await
            .unwrap()
            .create()
            .await
            .unwrap();
        let running = sandbox.exec(ExecSpec::argv(["sleep", "600"]), ExecControls::default());
        let stop = async {
            time::sleep(Duration::from_millis(500)).await;
            sandbox.stop().await
        };
        let (outcome, stopped) = tokio::join!(running, stop);
        stopped.expect("stop");
        assert_eq!(outcome.unwrap().termination, Termination::Killed);

        assert_eq!(sandbox.status().await.unwrap().state, SandboxState::Stopped);
        let execs = |fake: &FakeBoxd| fake.calls().iter().filter(|call| **call == "Exec").count();
        let before = execs(&fake);
        assert!(matches!(
            sandbox
                .exec(ExecSpec::argv(["true"]), ExecControls::default())
                .await,
            Err(Error::Busy { .. })
        ));
        assert_eq!(execs(&fake), before, "nothing reached the machine");
        sandbox.start().await.expect("start");
        sandboxes.destroy(&sandbox.reference()).await.unwrap();
    }

    /// A stop the caller asks for is reported only once confirmed: by the
    /// command's lock where the host has `flock`, otherwise as lost.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_kill_is_reported_only_once_its_end_is_confirmed() {
        let has_flock = Shell::new("sh")
            .args(["-c", "command -v flock"])
            .status()
            .is_ok_and(|status| status.success());
        let fake = FakeBoxd::start(Faults::default()).await;
        let sandboxes = catalog(&fake, Some("bxd_good"), base());
        let sandbox = sandboxes
            .builder("cloud")
            .await
            .unwrap()
            .create()
            .await
            .unwrap();
        let kill = CancellationToken::new();
        let running = sandbox.exec(ExecSpec::argv(["sleep", "600"]), ExecControls {
            kill: Some(kill.clone()),
            ..ExecControls::default()
        });
        let killer = async {
            time::sleep(Duration::from_millis(500)).await;
            kill.cancel();
        };
        let (outcome, ()) = tokio::join!(running, killer);
        let expected = if has_flock {
            Termination::Killed
        } else {
            Termination::Lost
        };
        assert_eq!(outcome.unwrap().termination, expected);
        sandboxes.destroy(&sandbox.reference()).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stdin_arrives_whole_while_the_command_answers_as_it_reads() {
        let fake = FakeBoxd::start(Faults::default()).await;
        let sandboxes = catalog(&fake, Some("bxd_good"), base());
        let sandbox = sandboxes
            .builder("cloud")
            .await
            .unwrap()
            .create()
            .await
            .unwrap();
        let input: Vec<u8> = (0..4_000_000_u32).map(|i| b'a' + (i % 26) as u8).collect();
        let text = String::from_utf8(input.clone()).unwrap();
        let (code, output) = time::timeout(
            Duration::from_secs(60),
            run(sandbox.as_ref(), &["cat"], Some(&input)),
        )
        .await
        .expect("cat finishes");
        assert_eq!(code, 0);
        assert_eq!(output.len(), text.len(), "bytes lost on the way in");
        assert!(output == text, "bytes reordered or changed");
        sandboxes.destroy(&sandbox.reference()).await.unwrap();
    }

    #[tokio::test]
    async fn a_failed_create_removes_its_machine_or_names_it() {
        let mut spec = base();
        spec.network = NetworkPolicy::CidrAllowList {
            cidrs: vec!["10.0.0.0/8".to_owned()],
        };
        let fake = FakeBoxd::start(Faults {
            refuse_egress: true,
            ..Faults::default()
        })
        .await;
        let error = catalog(&fake, Some("bxd_good"), spec.clone())
            .builder("cloud")
            .await
            .unwrap()
            .create()
            .await
            .err()
            .expect("egress refused");
        assert!(
            matches!(&error, Error::InvalidSpec { path, .. } if path == "network"),
            "{error:?}"
        );
        assert!(fake.machine("vm-1").is_none(), "the machine was removed");

        let fake = FakeBoxd::start(Faults {
            refuse_egress: true,
            fail_destroy:  true,
        })
        .await;
        let error = catalog(&fake, Some("bxd_good"), spec)
            .builder("cloud")
            .await
            .unwrap()
            .create()
            .await
            .err()
            .expect("egress refused");
        assert!(
            matches!(&error, Error::IncompleteCleanup { remaining, .. } if remaining[0].id == "vm-1"),
            "{error:?}"
        );
    }
}
