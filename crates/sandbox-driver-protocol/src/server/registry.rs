//! One registry per kind of live resource the plugin holds for the host
//! between requests: execs, stdio processes, PTYs, log streams, and
//! cached sandbox handles.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Mutex, MutexGuard};

/// A string-keyed map behind one lock. Every method takes the lock for a
/// single operation and releases it before returning, so no caller ever
/// holds a registry lock across an `.await`.
pub(super) struct Registry<T> {
    entries: Mutex<HashMap<String, T>>,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> Registry<T> {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, T>> {
        self.entries.lock().expect("registry lock")
    }

    /// Adds `value` under `id`, or hands it back when the id is taken so
    /// the caller can release whatever the value owns.
    pub(super) fn try_insert(&self, id: String, value: T) -> Result<(), T> {
        match self.lock().entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(())
            }
            Entry::Occupied(_) => Err(value),
        }
    }

    /// Adds or replaces the entry under `id`.
    pub(super) fn insert(&self, id: String, value: T) {
        self.lock().insert(id, value);
    }

    /// Adds or replaces the entry under `id`, first evicting one
    /// arbitrary entry when the registry is full and `id` is new.
    pub(super) fn insert_bounded(&self, id: String, value: T, max: usize) {
        let mut entries = self.lock();
        if !entries.contains_key(&id) && entries.len() >= max {
            if let Some(oldest) = entries.keys().next().cloned() {
                entries.remove(&oldest);
            }
        }
        entries.insert(id, value);
    }

    pub(super) fn remove(&self, id: &str) -> Option<T> {
        self.lock().remove(id)
    }

    /// Takes every entry out of the registry.
    pub(super) fn drain(&self) -> Vec<T> {
        self.lock().drain().map(|(_, value)| value).collect()
    }

    pub(super) fn len(&self) -> usize {
        self.lock().len()
    }
}

impl<T: Clone> Registry<T> {
    pub(super) fn get(&self, id: &str) -> Option<T> {
        self.lock().get(id).cloned()
    }

    /// The entry under `id`, inserting `make()` first when there is none.
    pub(super) fn get_or_insert_with(&self, id: String, make: impl FnOnce() -> T) -> T {
        self.lock().entry(id).or_insert_with(make).clone()
    }
}
