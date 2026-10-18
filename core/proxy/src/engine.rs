//! Engine: wires the CA, authority, connector and handler into a hudsucker
//! [`Proxy`], runs it on a tokio task, and exposes runtime controls.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use hudsucker::{
    certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs, Proxy,
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::handler::Handler;
use crate::intercept::{InterceptDecision, Registry};
use crate::scope::ScopeDecider;
use crate::tls::ca::Ca;
use crate::{ProxyConfig, ProxyEvent};

/// Max per-host leaf certificates cached in memory by the authority.
const CERT_CACHE_SIZE: u64 = 1_000;

pub struct EngineHandle {
    intercept_on: Arc<AtomicBool>,
    registry: Registry,
    ca_pem: String,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

pub async fn start(
    config: ProxyConfig,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<ProxyEvent>,
) -> Result<EngineHandle> {
    if !config.verify_upstream {
        // Accept-invalid upstream verification is a deliberate, logged opt-out.
        // TODO(separate task): build a custom rustls ClientConfig with a
        // permissive verifier wired via `with_http_connector`. Until then we
        // fail safe and keep verifying.
        tracing::warn!(
            "verify_upstream=false requested but not yet implemented; keeping upstream \
             certificate verification ON"
        );
    }

    let ca = Ca::load_or_create(&config.ca_dir).context("preparing root CA")?;
    let ca_pem = ca.cert_pem().to_string();
    let authority = RcgenAuthority::new(
        ca.into_issuer(),
        CERT_CACHE_SIZE,
        aws_lc_rs::default_provider(),
    );

    let intercept_on = Arc::new(AtomicBool::new(false));
    let registry = Registry::default();
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
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()
        .context("building proxy")?;

    let join = tokio::spawn(async move {
        if let Err(e) = proxy.start().await {
            tracing::error!("proxy server stopped with error: {e}");
        }
    });

    Ok(EngineHandle {
        intercept_on,
        registry,
        ca_pem,
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

    pub fn ca_pem(&self) -> String {
        self.ca_pem.clone()
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }
}
