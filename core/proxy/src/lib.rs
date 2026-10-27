//! elliot-proxy — intercepting MITM proxy engine.
//!
//! Listens on a loopback address, speaks HTTP/1.1 and HTTP/2, terminates TLS
//! with an on-the-fly per-host certificate signed by a local CA, and emits
//! [`elliot_httpraw::Flow`] values to the core over an mpsc channel.
//!
//! Trust/privacy posture (see the plan, non-negotiable):
//! - binds loopback only — never an open proxy;
//! - out-of-scope traffic is tunnelled transparently, never decrypted or
//!   stored;
//! - upstream certificate verification is on by default;
//! - the CA private key never leaves the machine; only the public certificate
//!   is exported, for the user-driven trust-store install.

mod convert;
mod engine;
mod handler;
mod intercept;
mod scope;
mod websocket;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;

pub use elliot_httpraw::{Flow, ScopeDecision, WsDirection, WsKind, WsMessage};
pub use intercept::InterceptDecision;
pub use scope::{AllowAll, DenyAll, ScopeDecider};

/// Configuration for a proxy instance.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Address to listen on. Must be loopback; [`start`] rejects anything else.
    pub listen_addr: SocketAddr,
    /// Directory where the root CA (`ca.crt` + `ca.key`) is persisted.
    pub ca_dir: PathBuf,
    /// Verify upstream server certificates. Default `true`.
    pub verify_upstream: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            ca_dir: PathBuf::from("."),
            verify_upstream: true,
        }
    }
}

/// Events streamed from the proxy to the core.
#[derive(Clone, Debug)]
pub enum ProxyEvent {
    /// A new in-scope request has started.
    FlowStarted(Flow),
    /// A flow changed state (e.g. paused for interception).
    FlowUpdated(Flow),
    /// A flow finished (response received, dropped, or errored).
    FlowCompleted(Flow),
    /// A WebSocket message observed on an in-scope connection (Phase D).
    WebSocket(WsMessage),
    /// A proxy-level error not attached to a specific flow.
    Error(String),
}

/// Handle to a running proxy. Dropping it does not stop the proxy; call
/// [`ProxyHandle::stop`].
pub struct ProxyHandle {
    inner: engine::EngineHandle,
}

impl ProxyHandle {
    /// Turn interception on or off. When on, in-scope flows pause until a
    /// decision is supplied via [`ProxyHandle::decide`].
    pub fn set_intercept(&self, on: bool) {
        self.inner.set_intercept(on);
    }

    /// Supply a decision for a paused flow. No-op if the flow is unknown or
    /// already resumed.
    pub fn decide(&self, flow_id: uuid::Uuid, decision: InterceptDecision) {
        self.inner.decide(flow_id, decision);
    }

    /// PEM of the root CA **certificate** (public), for the guided trust-store
    /// install. The private key is never exposed.
    pub fn ca_pem(&self) -> String {
        self.inner.ca_pem()
    }

    /// Stop the proxy and wait for it to wind down.
    pub async fn stop(self) {
        self.inner.stop().await;
    }
}

/// Start the proxy. Builds (or loads) the CA, binds the listener and spawns the
/// server task.
///
/// # Errors
/// Returns an error if `listen_addr` is not loopback, if the CA cannot be
/// prepared, or if the server fails to bind.
pub async fn start(
    config: ProxyConfig,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<ProxyEvent>,
) -> anyhow::Result<ProxyHandle> {
    if !config.listen_addr.ip().is_loopback() {
        anyhow::bail!(
            "refusing to bind non-loopback address {} (open-proxy guard)",
            config.listen_addr
        );
    }
    let inner = engine::start(config, scope, events).await?;
    Ok(ProxyHandle { inner })
}
