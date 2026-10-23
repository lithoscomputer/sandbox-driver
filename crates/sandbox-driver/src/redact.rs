use std::collections::BTreeMap;
use std::fmt;

/// Formats an environment map as its key list, for `Debug` impls that must
/// not print values.
pub(crate) struct EnvKeys<'a>(pub(crate) &'a BTreeMap<String, String>);

impl fmt::Debug for EnvKeys<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}
