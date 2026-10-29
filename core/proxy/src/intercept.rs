//! Phase B — interception: a registry of paused flows awaiting a decision, and
//! a parser that turns user-edited raw request bytes back into a forwardable
//! message.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri};
use tokio::sync::oneshot;
use uuid::Uuid;

/// What to do with a paused request.
pub enum InterceptDecision {
    /// Forward unchanged.
    Forward,
    /// Forward after replacing the raw request bytes.
    ForwardEdited(Vec<u8>),
    /// Drop the request; the client gets a minimal response.
    Drop,
}

/// What to do with a paused WebSocket frame.
///
/// The replacement payload is bytes rather than `Message` variants so the UI
/// can edit a `Text` frame as text and a `Binary` frame as bytes without
/// knowing the transport type; the handler rebuilds the right kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsDecision {
    /// Forward the frame unchanged.
    Forward,
    /// Forward after replacing the payload (same frame kind).
    ForwardEdited(Vec<u8>),
    /// Drop the frame; nothing goes on the wire.
    Drop,
}

/// Registry of flows paused in the handler, keyed by flow id.
#[derive(Default, Clone)]
pub struct Registry {
    inner: Arc<Mutex<HashMap<Uuid, oneshot::Sender<InterceptDecision>>>>,
}

impl Registry {
    /// Register a paused flow and get the receiver the handler awaits on.
    pub fn register(&self, id: Uuid) -> oneshot::Receiver<InterceptDecision> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .lock()
            .expect("intercept registry poisoned")
            .insert(id, tx);
        rx
    }

    /// Resolve a paused flow. No-op if unknown or already resolved.
    pub fn resolve(&self, id: Uuid, decision: InterceptDecision) {
        if let Some(tx) = self
            .inner
            .lock()
            .expect("intercept registry poisoned")
            .remove(&id)
        {
            let _ = tx.send(decision);
        }
    }
}

/// Registry of WebSocket frames paused in the handler, keyed by message id.
///
/// Deliberately a sibling of [`Registry`] rather than a generic `Registry<T>`:
/// the two decisions have different payloads and the HTTP path is the one that
/// must not regress, so a few duplicated lines buy isolation.
#[derive(Default, Clone)]
pub struct WsRegistry {
    inner: Arc<Mutex<HashMap<Uuid, oneshot::Sender<WsDecision>>>>,
}

impl WsRegistry {
    /// Register a paused frame and get the receiver the handler awaits on.
    pub fn register(&self, id: Uuid) -> oneshot::Receiver<WsDecision> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .lock()
            .expect("ws intercept registry poisoned")
            .insert(id, tx);
        rx
    }

    /// Resolve a paused frame. No-op if unknown or already resolved.
    pub fn resolve(&self, id: Uuid, decision: WsDecision) {
        if let Some(tx) = self
            .inner
            .lock()
            .expect("ws intercept registry poisoned")
            .remove(&id)
        {
            let _ = tx.send(decision);
        }
    }
}

/// Parse user-edited raw request bytes into forwardable parts + body.
///
/// Scheme and authority are taken from `base` (the original request) unless the
/// edited request-target is in absolute form; only the path, method, version-
/// agnostic headers and body come from the edited bytes.
pub fn parse_edited_request(
    bytes: &[u8],
    base: &http::request::Parts,
) -> Result<(http::request::Parts, Bytes)> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Request::new(&mut headers);
    let body_offset = match parsed.parse(bytes).context("parsing edited request")? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => anyhow::bail!("edited request is incomplete"),
    };

    let method_str = parsed.method.context("edited request missing method")?;
    let target = parsed.path.context("edited request missing target")?;
    let method = Method::from_bytes(method_str.as_bytes()).context("invalid method")?;
    let uri = resolve_uri(target, base).context("resolving edited target")?;

    let mut hmap = HeaderMap::new();
    for h in parsed.headers.iter() {
        let name = HeaderName::from_bytes(h.name.as_bytes())
            .with_context(|| format!("invalid header name {}", h.name))?;
        let value = HeaderValue::from_bytes(h.value).context("invalid header value")?;
        hmap.append(name, value);
    }

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(base.version);
    if let Some(dst) = builder.headers_mut() {
        *dst = hmap;
    }
    let (parts, ()) = builder
        .body(())
        .context("assembling edited request")?
        .into_parts();

    let body = Bytes::copy_from_slice(&bytes[body_offset..]);
    Ok((parts, body))
}

fn resolve_uri(target: &str, base: &http::request::Parts) -> Result<Uri> {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.parse().context("parsing absolute target");
    }
    let mut parts = base.uri.clone().into_parts();
    parts.path_and_query = Some(target.parse().context("parsing request target")?);
    Uri::from_parts(parts).context("rebuilding uri from base")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_registered_flow_receives_its_decision() {
        let registry = Registry::default();
        let id = Uuid::new_v4();
        let rx = registry.register(id);
        registry.resolve(id, InterceptDecision::Drop);
        assert!(matches!(rx.await, Ok(InterceptDecision::Drop)));
    }

    #[tokio::test]
    async fn resolving_an_unknown_flow_is_a_no_op() {
        let registry = Registry::default();
        // Must not panic: the UI may decide a flow that already resumed.
        registry.resolve(Uuid::new_v4(), InterceptDecision::Forward);
    }

    #[tokio::test]
    async fn a_registered_ws_frame_receives_its_decision() {
        let registry = WsRegistry::default();
        let id = Uuid::new_v4();
        let rx = registry.register(id);
        registry.resolve(id, WsDecision::ForwardEdited(b"edited".to_vec()));
        assert_eq!(
            rx.await.unwrap(),
            WsDecision::ForwardEdited(b"edited".to_vec())
        );
    }

    #[tokio::test]
    async fn ws_resolution_is_idempotent() {
        let registry = WsRegistry::default();
        let id = Uuid::new_v4();
        let _rx = registry.register(id);
        registry.resolve(id, WsDecision::Forward);
        // The second decision finds nothing to resolve and must not panic.
        registry.resolve(id, WsDecision::Drop);
    }
}
