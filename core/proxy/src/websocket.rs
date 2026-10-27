//! Phase D — WebSocket capture and intercept.
//!
//! A [`WsHandler`] that observes messages on in-scope connections, emits them as
//! [`ProxyEvent::WebSocket`], and forwards them. With intercept off it is
//! observe-only (frames pass through untouched); with intercept on, every
//! **data** frame pauses, is announced to the UI (`paused: true`) and resumes
//! on a [`WsDecision`]: forward unchanged, forward with a replaced payload, or
//! drop.
//!
//! Control frames (`Ping`/`Pong`/`Close`) are never intercepted: holding them
//! would break keep-alive and the closing handshake, which is a protocol
//! concern the user did not ask to tamper with.
//!
//! Out-of-scope `wss://` never reaches this handler — those connections are
//! tunnelled transparently by [`HttpHandler::should_intercept_connect`], so
//! they are never decrypted. For `ws://` (and as defence in depth) the scope
//! decision is re-checked here and non-in-scope messages are dropped from the
//! capture, never from the wire, and never paused.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use hudsucker::{
    tokio_tungstenite::tungstenite::Message, WebSocketContext, WebSocketHandler,
};
use uuid::Uuid;

use elliot_httpraw::net::split_host_port;
use elliot_httpraw::{Scheme, ScopeDecision, WsDirection, WsKind, WsMessage};

use crate::intercept::{WsDecision, WsRegistry};
use crate::scope::ScopeDecider;
use crate::ProxyEvent;

pub struct WsHandler {
    pub events: tokio::sync::mpsc::Sender<ProxyEvent>,
    pub scope: Arc<dyn ScopeDecider>,
    /// The same switch as the HTTP intercept, so one toggle governs both.
    pub intercept_on: Arc<AtomicBool>,
    pub registry: WsRegistry,
    /// Identity of the socket this handler instance serves. hudsucker clones
    /// the handler once per connection, so a fresh id per clone is what makes
    /// it per-socket rather than per-process.
    pub connection_id: Uuid,
}

/// A hand-written clone: the shared plumbing is copied, the connection identity
/// is regenerated.
///
/// This relies on hudsucker cloning the handler **once per connection**. The
/// end-to-end test in `tests/websocket.rs` asserts that all frames of one socket
/// share an id and a second socket gets a different one, so if that changes the
/// test fails instead of the history silently merging sockets.
impl Clone for WsHandler {
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
            scope: self.scope.clone(),
            intercept_on: self.intercept_on.clone(),
            registry: self.registry.clone(),
            connection_id: Uuid::new_v4(),
        }
    }
}

impl WebSocketHandler for WsHandler {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        // `WebSocketContext`'s variants are `#[non_exhaustive]`, so destructure
        // with `..`. Both directions carry the server URI and the client addr.
        let (direction, client_addr, uri) = match ctx {
            WebSocketContext::ClientToServer { src, dst, .. } => {
                (WsDirection::ClientToServer, *src, dst.clone())
            }
            WebSocketContext::ServerToClient { src, dst, .. } => {
                (WsDirection::ServerToClient, *dst, src.clone())
            }
        };

        let Some(observed) = self.observe(direction, client_addr, &uri, &message) else {
            // Out of scope: not captured, not paused — and forwarded untouched.
            return Some(message);
        };

        if !self.should_intercept(observed.kind) {
            // Observe-only: forward the frame untouched.
            let _ = self.events.send(ProxyEvent::WebSocket(observed)).await;
            return Some(message);
        }

        let mut paused = observed;
        paused.paused = true;
        // Register *before* announcing: the UI can only act on a frame it has
        // been told about, and registering first means a decision that arrives
        // immediately finds its channel.
        let rx = self.registry.register(paused.id);
        let _ = self.events.send(ProxyEvent::WebSocket(paused.clone())).await;

        // Default to forwarding if the core drops the channel (shutdown).
        let decision = rx.await.unwrap_or(WsDecision::Forward);
        self.apply(decision, message, paused)
    }
}

impl WsHandler {
    /// Only data frames pause; control frames stay on the wire.
    fn should_intercept(&self, kind: WsKind) -> bool {
        matches!(kind, WsKind::Text | WsKind::Binary)
            && self.intercept_on.load(Ordering::Relaxed)
    }

    /// Turn a decision into the frame to forward (`None` = drop).
    fn apply(
        &self,
        decision: WsDecision,
        original: Message,
        observed: WsMessage,
    ) -> Option<Message> {
        match decision {
            WsDecision::Forward => Some(original),
            WsDecision::Drop => None,
            WsDecision::ForwardEdited(bytes) => {
                // Rebuild the *same* kind. A `Text` frame is only allowed to
                // stay text when the edit is valid UTF-8; otherwise the edit is
                // rejected and the original forwards, mirroring HTTP's
                // behaviour on an unparsable edit.
                match observed.kind {
                    WsKind::Text => match String::from_utf8(bytes) {
                        Ok(text) => Some(Message::text(text)),
                        Err(_) => {
                            let reason = "WebSocket edit rejected: a text frame must be UTF-8";
                            tracing::warn!("{reason}");
                            // The handler runs on the proxy task; the event
                            // channel may already be gone.
                            let _ = self
                                .events
                                .try_send(ProxyEvent::Error(reason.to_string()));
                            Some(original)
                        }
                    },
                    _ => Some(Message::binary(bytes)),
                }
            }
        }
    }

    /// Build the observed message, or `None` if the connection is not strictly
    /// in scope or the frame carries nothing worth logging.
    fn observe(
        &self,
        direction: WsDirection,
        client_addr: std::net::SocketAddr,
        uri: &http::Uri,
        message: &Message,
    ) -> Option<WsMessage> {
        let (scheme, host, port) = uri_target(uri);
        if host.is_empty() {
            return None;
        }
        // Mirror the HTTP scope decision made on the upgrade request.
        if self.scope.decide(scheme.as_str(), &host, port, uri.path()) != ScopeDecision::InScope {
            return None;
        }

        let (kind, payload) = classify(message)?;
        Some(WsMessage {
            id: Uuid::new_v4(),
            connection: format!("{client_addr} <-> {host}:{port}"),
            connection_id: self.connection_id,
            at: SystemTime::now(),
            client_addr,
            scheme,
            host,
            port,
            direction,
            kind,
            payload,
            paused: false,
        })
    }
}

/// Derive (scheme, host, port) from a WebSocket URI, accepting both the
/// `ws`/`wss` and the `http`/`https` scheme spellings hudsucker may present.
fn uri_target(uri: &http::Uri) -> (Scheme, String, u16) {
    let scheme = match uri.scheme_str() {
        Some("https") | Some("wss") => Scheme::Https,
        Some("http") | Some("ws") => Scheme::Http,
        _ if uri.port_u16() == Some(443) => Scheme::Https,
        _ => Scheme::Http,
    };
    // Host and port come from the shared authority parser, not a local copy.
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or_default();
    let (host, port) = split_host_port(authority);
    let port = port.or_else(|| uri.port_u16()).unwrap_or(match scheme {
        Scheme::Https => 443,
        Scheme::Http => 80,
    });
    (scheme, host, port)
}

/// Map a tungstenite [`Message`] to a kind + payload bytes. Returns `None` for
/// raw `Frame`s, which are not produced while reading a stream.
fn classify(message: &Message) -> Option<(WsKind, Bytes)> {
    let out = match message {
        Message::Text(t) => (WsKind::Text, Bytes::copy_from_slice(t.as_str().as_bytes())),
        Message::Binary(b) => (WsKind::Binary, b.clone()),
        Message::Ping(b) => (WsKind::Ping, b.clone()),
        Message::Pong(b) => (WsKind::Pong, b.clone()),
        Message::Close(frame) => {
            let reason = frame
                .as_ref()
                .map(|f| f.reason.as_str().as_bytes().to_vec())
                .unwrap_or_default();
            (WsKind::Close, Bytes::from(reason))
        }
        Message::Frame(_) => return None,
    };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{AllowAll, DenyAll};

    fn handler(scope: Arc<dyn ScopeDecider>) -> WsHandler {
        let (events, _rx) = tokio::sync::mpsc::channel(4);
        WsHandler {
            events,
            scope,
            intercept_on: Arc::new(AtomicBool::new(false)),
            registry: WsRegistry::default(),
            connection_id: Uuid::new_v4(),
        }
    }

    fn intercepting(scope: Arc<dyn ScopeDecider>) -> (WsHandler, tokio::sync::mpsc::Receiver<ProxyEvent>) {
        let (events, rx) = tokio::sync::mpsc::channel(8);
        let handler = WsHandler {
            events,
            scope,
            intercept_on: Arc::new(AtomicBool::new(true)),
            registry: WsRegistry::default(),
            connection_id: Uuid::new_v4(),
        };
        (handler, rx)
    }

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:5000".parse().unwrap()
    }

    fn observed(kind: WsKind, payload: &[u8]) -> WsMessage {
        WsMessage {
            id: Uuid::new_v4(),
            connection: "127.0.0.1:5000 <-> example.com:443".into(),
            connection_id: Uuid::new_v4(),
            at: SystemTime::now(),
            client_addr: addr(),
            scheme: Scheme::Https,
            host: "example.com".into(),
            port: 443,
            direction: WsDirection::ClientToServer,
            kind,
            payload: Bytes::copy_from_slice(payload),
            paused: false,
        }
    }

    #[test]
    fn classify_covers_each_kind() {
        assert_eq!(classify(&Message::Text("hi".into())).unwrap().0, WsKind::Text);
        assert_eq!(
            classify(&Message::Binary(Bytes::from_static(b"\x00\x01"))).unwrap().0,
            WsKind::Binary
        );
        assert_eq!(classify(&Message::Ping(Bytes::new())).unwrap().0, WsKind::Ping);
        assert_eq!(classify(&Message::Pong(Bytes::new())).unwrap().0, WsKind::Pong);
        assert_eq!(classify(&Message::Close(None)).unwrap().0, WsKind::Close);
    }

    #[test]
    fn in_scope_message_is_observed() {
        let uri: http::Uri = "wss://example.com/chat".parse().unwrap();
        let obs = handler(Arc::new(AllowAll))
            .observe(WsDirection::ClientToServer, addr(), &uri, &Message::Text("hi".into()))
            .expect("in-scope message should be observed");
        assert_eq!(obs.host, "example.com");
        assert_eq!(obs.port, 443);
        assert_eq!(obs.scheme, Scheme::Https);
        assert_eq!(obs.kind, WsKind::Text);
        assert_eq!(obs.direction, WsDirection::ClientToServer);
        assert_eq!(&obs.payload[..], b"hi");
        assert_eq!(obs.connection, "127.0.0.1:5000 <-> example.com:443");
        assert!(!obs.paused, "an observed frame is not paused");
    }

    #[test]
    fn out_of_scope_message_is_skipped() {
        let uri: http::Uri = "wss://example.com/chat".parse().unwrap();
        let obs = handler(Arc::new(DenyAll)).observe(
            WsDirection::ServerToClient,
            addr(),
            &uri,
            &Message::Text("hi".into()),
        );
        assert!(obs.is_none(), "out-of-scope WS must not be captured");
    }

    #[test]
    fn plain_ws_scheme_defaults_to_port_80() {
        let uri: http::Uri = "ws://example.com/chat".parse().unwrap();
        let obs = handler(Arc::new(AllowAll))
            .observe(WsDirection::ClientToServer, addr(), &uri, &Message::Ping(Bytes::new()))
            .unwrap();
        assert_eq!(obs.scheme, Scheme::Http);
        assert_eq!(obs.port, 80);
    }

    #[test]
    fn control_frames_are_never_intercepted() {
        let (h, _rx) = intercepting(Arc::new(AllowAll));
        assert!(h.should_intercept(WsKind::Text));
        assert!(h.should_intercept(WsKind::Binary));
        assert!(!h.should_intercept(WsKind::Ping));
        assert!(!h.should_intercept(WsKind::Pong));
        assert!(!h.should_intercept(WsKind::Close));
    }

    #[test]
    fn with_intercept_off_data_frames_stay_observe_only() {
        let h = handler(Arc::new(AllowAll));
        assert!(!h.should_intercept(WsKind::Text));
    }

    #[test]
    fn two_clones_get_different_connection_ids() {
        // hudsucker clones the handler once per connection: that is where the
        // socket identity is born.
        let first = handler(Arc::new(AllowAll));
        let second = first.clone();
        assert_ne!(first.connection_id, second.connection_id);
        // A third clone of the same original differs again: no id is reused.
        assert_ne!(second.connection_id, first.clone().connection_id);
    }

    #[test]
    fn an_observed_frame_carries_the_handler_connection_id() {
        let h = handler(Arc::new(AllowAll));
        let uri: http::Uri = "wss://example.com/chat".parse().unwrap();
        let first = h
            .observe(WsDirection::ClientToServer, addr(), &uri, &Message::Text("a".into()))
            .unwrap();
        let second = h
            .observe(WsDirection::ServerToClient, addr(), &uri, &Message::Text("b".into()))
            .unwrap();
        assert_eq!(first.connection_id, h.connection_id);
        assert_eq!(second.connection_id, h.connection_id);
        // Different frames of the same socket, different frame ids.
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn a_forward_edit_replaces_the_payload_in_the_same_kind() {
        let (h, _rx) = intercepting(Arc::new(AllowAll));
        let out = h
            .apply(
                WsDecision::ForwardEdited(b"edited".to_vec()),
                Message::Text("original".into()),
                observed(WsKind::Text, b"original"),
            )
            .expect("forwarded");
        assert_eq!(out.to_text().unwrap(), "edited");
    }

    #[test]
    fn a_binary_edit_may_carry_non_utf8_bytes() {
        let (h, _rx) = intercepting(Arc::new(AllowAll));
        let out = h
            .apply(
                WsDecision::ForwardEdited(vec![0xff, 0x00]),
                Message::Binary(Bytes::from_static(b"original")),
                observed(WsKind::Binary, b"original"),
            )
            .expect("forwarded");
        assert_eq!(out.into_data().as_ref(), &[0xff, 0x00]);
    }

    #[test]
    fn a_text_edit_that_is_not_utf8_forwards_the_original() {
        let (h, mut rx) = intercepting(Arc::new(AllowAll));
        let out = h
            .apply(
                WsDecision::ForwardEdited(vec![0xff, 0xfe]),
                Message::Text("original".into()),
                observed(WsKind::Text, b"original"),
            )
            .expect("the original is forwarded instead of dropping");
        assert_eq!(out.to_text().unwrap(), "original");
        // The rejection is surfaced, not swallowed.
        match rx.try_recv() {
            Ok(ProxyEvent::Error(e)) => assert!(e.contains("UTF-8"), "got {e}"),
            other => panic!("expected an error event, got {other:?}"),
        }
    }

    #[test]
    fn a_drop_decision_returns_none() {
        let (h, _rx) = intercepting(Arc::new(AllowAll));
        let out = h.apply(
            WsDecision::Drop,
            Message::Text("original".into()),
            observed(WsKind::Text, b"original"),
        );
        assert!(out.is_none(), "a dropped frame must not be forwarded");
    }

    #[test]
    fn a_forward_decision_returns_the_original_frame() {
        let (h, _rx) = intercepting(Arc::new(AllowAll));
        let out = h
            .apply(
                WsDecision::Forward,
                Message::Text("original".into()),
                observed(WsKind::Text, b"original"),
            )
            .unwrap();
        assert_eq!(out.to_text().unwrap(), "original");
    }
}
