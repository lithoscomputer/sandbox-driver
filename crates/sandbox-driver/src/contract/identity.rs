use serde::{Deserialize, Serialize};

use super::{Error, NamespaceId, ProviderName};
use crate::SandboxId;

/// Durable routing data, independent of the environment used to create it.
///
/// Durability of this *value* does not promise resource survival. `provider`
/// names an operator entry, not a provider kind. Check the observed namespace
/// before sending any sandbox operation through that entry.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SandboxRef {
    pub provider:  ProviderName,
    pub namespace: NamespaceId,
    pub id:        SandboxId,
}

impl SandboxRef {
    /// Refuses a changed backend before attach, stop, or any other operation.
    pub fn check_namespace(&self, observed: &NamespaceId) -> Result<(), Error> {
        if &self.namespace == observed {
            Ok(())
        } else {
            Err(Error::NamespaceMismatch {
                expected: self.namespace.clone(),
                actual:   observed.clone(),
            })
        }
    }
}
