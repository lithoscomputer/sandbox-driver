//! [boxd.sh](https://boxd.sh) cloud microVMs on the shared sandbox
//! contract ([`sandbox_driver`]).
//!
//! [`BoxdFactory`] is the built-in registration; its documentation covers
//! configuration and behavior.

mod runtime;

pub use crate::runtime::BoxdFactory;
