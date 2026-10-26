//! Scope abstraction for the proxy.
//!
//! The [`ScopeDecider`] trait is the shared contract and lives in
//! `elliot-httpraw`; it is re-exported here (and from the crate root) so the
//! proxy's public API is unchanged. The proxy depends only on the trait, never
//! on the `elliot-scope` crate, so Phase A can run with [`AllowAll`] and
//! `elliot-scope` can provide the real engine without a reverse dependency.

pub use elliot_httpraw::ScopeDecider;
use elliot_httpraw::ScopeDecision;

/// Everything is in scope. Useful for Phase A and tests.
pub struct AllowAll;

impl ScopeDecider for AllowAll {
    fn decide(&self, _scheme: &str, _host: &str, _port: u16, _path: &str) -> ScopeDecision {
        ScopeDecision::InScope
    }
}
