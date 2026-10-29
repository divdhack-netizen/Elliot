//! Scope abstraction for the proxy.
//!
//! The [`ScopeDecider`] trait is the shared contract and lives in
//! `elliot-httpraw`, along with the [`AllowAll`] / [`DenyAll`] trivial
//! deciders. They are re-exported here (and from the crate root) so the proxy's
//! public API is unchanged. The proxy depends only on the trait, never on the
//! `elliot-scope` crate, so the real engine can be wired in without a reverse
//! dependency.

pub use elliot_httpraw::{AllowAll, DenyAll, ScopeDecider};
