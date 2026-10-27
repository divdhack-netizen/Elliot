//! Engine: wires the CA, authority, connector and handler into a hudsucker
//! [`Proxy`], runs it on a tokio task, and exposes runtime controls.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use hudsucker::{
    certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs,
    tokio_tungstenite::Connector, Proxy,
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use elliot_tls::{Ca, EffectiveKeyStore};

use crate::handler::Handler;
use crate::intercept::{InterceptDecision, Registry, WsDecision, WsRegistry};
use crate::scope::ScopeDecider;
use crate::{ProxyConfig, ProxyEvent};

/// Max per-host leaf certificates cached in memory by the authority.
const CERT_CACHE_SIZE: u64 = 1_000;

pub struct EngineHandle {
    intercept_on: Arc<AtomicBool>,
    registry: Registry,
    ws_registry: WsRegistry,
    ca_pem: String,
    /// Which backend really held the CA key this run, read before the CA is
    /// consumed by the issuer.
    ca_key_store: EffectiveKeyStore,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

pub async fn start(
    config: ProxyConfig,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<ProxyEvent>,
) -> Result<EngineHandle> {
    let ca = Ca::load_or_create_with(&config.ca_dir, config.ca_key_store)
        .context("preparing root CA")?;
    let ca_pem = ca.cert_pem().to_string();
    let ca_key_store = ca.key_store();
    let authority = RcgenAuthority::new(
        ca.into_issuer(),
        CERT_CACHE_SIZE,
        aws_lc_rs::default_provider(),
    );

    let intercept_on = Arc::new(AtomicBool::new(false));
    let registry = Registry::default();
    let ws_registry = WsRegistry::default();
    // The WebSocket handler shares the event sink, scope decider and
    // intercept switch with the HTTP handler: one toggle governs both.
    let ws_handler = crate::websocket::WsHandler {
        events: events.clone(),
        scope: scope.clone(),
        intercept_on: intercept_on.clone(),
        registry: ws_registry.clone(),
        // The template; hudsucker's per-connection clone regenerates it.
        connection_id: Uuid::new_v4(),
    };
    let handler = Handler {
        events,
        scope,
        intercept_on: intercept_on.clone(),
        registry: registry.clone(),
        pending: VecDeque::new(),
    };

    // Bind synchronously so that `start` returning means the proxy is already
    // accepting connections, and so bind errors (e.g. port in use) surface here
    // rather than in the background task.
    let std_listener =
        std::net::TcpListener::bind(config.listen_addr).context("binding listen address")?;
    std_listener
        .set_nonblocking(true)
        .context("setting listener non-blocking")?;
    let listener =
        tokio::net::TcpListener::from_std(std_listener).context("adopting listener into tokio")?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown = async move {
        let _ = shutdown_rx.await;
    };

    // `with_rustls_connector` hands back an opaque connector type, so the two
    // arms cannot be unified into one expression. Only the upstream connector
    // (and with it the verification policy) differs.
    let join = if config.verify_upstream {
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(authority)
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(handler)
            .with_websocket_handler(ws_handler)
            .with_graceful_shutdown(shutdown)
            .build()
            .context("building proxy")?;
        tokio::spawn(async move {
            if let Err(e) = proxy.start().await {
                tracing::error!("proxy server stopped with error: {e}");
            }
        })
    } else {
        // Deliberate opt-out: upstream certificates are not verified. Logged
        // loudly because it silently weakens every MITM'd connection.
        tracing::warn!(
            "verify_upstream=false: upstream TLS certificates will NOT be verified"
        );
        // One permissive config feeds both the HTTP client connector and the
        // WebSocket connector, so `wss://` upstream is covered too.
        let tls_config = Arc::new(
            elliot_tls::insecure_client_config()
                .context("building the permissive TLS config")?,
        );
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*tls_config).clone())
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(authority)
            .with_http_connector(connector)
            .with_websocket_connector(Connector::Rustls(tls_config))
            .with_http_handler(handler)
            .with_websocket_handler(ws_handler)
            .with_graceful_shutdown(shutdown)
            .build()
            .context("building proxy")?;
        tokio::spawn(async move {
            if let Err(e) = proxy.start().await {
                tracing::error!("proxy server stopped with error: {e}");
            }
        })
    };

    Ok(EngineHandle {
        intercept_on,
        registry,
        ws_registry,
        ca_pem,
        ca_key_store,
        shutdown: Some(shutdown_tx),
        join,
    })
}

impl EngineHandle {
    pub fn set_intercept(&self, on: bool) {
        self.intercept_on.store(on, Ordering::Relaxed);
    }

    pub fn decide(&self, flow_id: Uuid, decision: InterceptDecision) {
        self.registry.resolve(flow_id, decision);
    }

    pub fn decide_ws(&self, message_id: Uuid, decision: WsDecision) {
        self.ws_registry.resolve(message_id, decision);
    }

    pub fn ca_pem(&self) -> String {
        self.ca_pem.clone()
    }

    pub fn ca_key_store(&self) -> EffectiveKeyStore {
        self.ca_key_store
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }
}
