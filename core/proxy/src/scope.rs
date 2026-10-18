//! Scope abstraction. The proxy depends on a trait, not on the `elliot-scope`
//! crate, so Phase A can run with [`AllowAll`] and `elliot-scope` can implement
//! [`ScopeDecider`] later without a reverse dependency.

use elliot_httpraw::ScopeDecision;

/// Decides whether traffic is in scope, out of scope, or should be tunnelled
/// transparently (passthrough).
pub trait ScopeDecider: Send + Sync {
    fn decide(&self, scheme: &str, host: &str, port: u16, path: &str) -> ScopeDecision;
}

/// Everything is in scope. Useful for Phase A and tests.
pub struct AllowAll;

impl ScopeDecider for AllowAll {
    fn decide(&self, _scheme: &str, _host: &str, _port: u16, _path: &str) -> ScopeDecision {
        ScopeDecision::InScope
    }
}
