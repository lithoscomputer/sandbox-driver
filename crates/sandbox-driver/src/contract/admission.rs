use super::{
    ContainerField, Descriptor, Environment, Error, NetworkMode, NetworkPolicy, ResourceCapability,
    SandboxSpec, Source, SourceKind, TimerCapability,
};

impl Environment {
    /// Portable and descriptor checks for editing a template. Schema validation
    /// and credential resolution remain required at admission.
    pub fn validate(&self, descriptor: &Descriptor) -> Result<(), Error> {
        self.spec.validate_for(descriptor)
    }
}

impl SandboxSpec {
    /// Rejects unsupported explicit requests before mutation, including false
    /// container flags and disabled timers. Opaque provider options require
    /// schema/backend validation in addition to this check.
    pub fn validate_for(&self, descriptor: &Descriptor) -> Result<(), Error> {
        self.validate()?;
        let source = match self.source {
            Source::Image(_) => SourceKind::Image,
            Source::Dockerfile(_) => SourceKind::Dockerfile,
            Source::Snapshot(_) => SourceKind::Snapshot,
            Source::HostDirectory => SourceKind::HostDirectory,
        };
        require(descriptor.sources.contains(&source), "source")?;
        for (requested, capability, field) in [
            (
                self.resources.cpu_cores.is_some(),
                ResourceCapability::Cpu,
                "resources.cpu_cores",
            ),
            (
                self.resources.memory_mb.is_some(),
                ResourceCapability::Memory,
                "resources.memory_mb",
            ),
            (
                self.resources.disk_mb.is_some(),
                ResourceCapability::Disk,
                "resources.disk_mb",
            ),
            (
                self.resources.gpus.is_some_and(|value| value != 0),
                ResourceCapability::Gpus,
                "resources.gpus",
            ),
        ] {
            if requested {
                require(descriptor.resources.contains(&capability), field)?;
            }
        }
        let network = match self.network {
            NetworkPolicy::ProviderDefault => NetworkMode::ProviderDefault,
            NetworkPolicy::AllowAll => NetworkMode::AllowAll,
            NetworkPolicy::Block => NetworkMode::Block,
            NetworkPolicy::CidrAllowList { .. } => NetworkMode::CidrAllowList,
            NetworkPolicy::DomainAllowList { .. } => NetworkMode::DomainAllowList,
        };
        require(descriptor.network.contains(&network), "network")?;
        for (requested, capability, field) in [
            (
                self.timers.auto_stop_ms,
                TimerCapability::AutoStop,
                "timers.auto_stop_ms",
            ),
            (
                self.timers.auto_archive_ms,
                TimerCapability::AutoArchive,
                "timers.auto_archive_ms",
            ),
            (
                self.timers.auto_delete_ms,
                TimerCapability::AutoDelete,
                "timers.auto_delete_ms",
            ),
            (self.timers.ttl_ms, TimerCapability::Ttl, "timers.ttl_ms"),
        ] {
            if requested.is_some() {
                require(descriptor.capabilities.timers.contains(&capability), field)?;
            }
        }
        require(
            self.services.is_empty() || descriptor.capabilities.services,
            "services",
        )?;
        if let Some(container) = &self.container {
            for (requested, capability, field) in [
                (
                    container.init.is_some(),
                    ContainerField::Init,
                    "container.init",
                ),
                (
                    container.privileged.is_some(),
                    ContainerField::Privileged,
                    "container.privileged",
                ),
                (
                    !container.capabilities_add.is_empty(),
                    ContainerField::CapabilitiesAdd,
                    "container.capabilities_add",
                ),
                (
                    !container.capabilities_drop.is_empty(),
                    ContainerField::CapabilitiesDrop,
                    "container.capabilities_drop",
                ),
                (
                    !container.dns.is_empty(),
                    ContainerField::Dns,
                    "container.dns",
                ),
                (
                    !container.extra_hosts.is_empty(),
                    ContainerField::ExtraHosts,
                    "container.extra_hosts",
                ),
                (
                    container.shm_size_mb.is_some(),
                    ContainerField::ShmSizeMb,
                    "container.shm_size_mb",
                ),
            ] {
                if requested {
                    require(
                        descriptor
                            .capabilities
                            .container_fields
                            .contains(&capability),
                        field,
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn require(supported: bool, field: &str) -> Result<(), Error> {
    if supported {
        Ok(())
    } else {
        Err(Error::Unsupported {
            capability: field.to_owned(),
        })
    }
}
