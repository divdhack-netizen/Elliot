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
