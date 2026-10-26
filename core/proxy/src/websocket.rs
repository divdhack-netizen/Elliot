//! Phase D — WebSocket capture.
//!
//! A [`WebSocketHandler`] that observes messages on in-scope connections, emits
//! them as [`ProxyEvent::WebSocket`], and forwards every message **unchanged**.
//! Capture here is observe-only: tampering with WebSocket frames is out of scope
//! for this phase (the intercept path is HTTP-only for now).
//!
//! Out-of-scope `wss://` never reaches this handler — those connections are
//! tunnelled transparently by [`HttpHandler::should_intercept_connect`], so
//! they are never decrypted. For `ws://` (and as defence in depth) the scope
//! decision is re-checked here and non-in-scope messages are dropped from the
//! capture, never from the wire.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use hudsucker::{
    tokio_tungstenite::tungstenite::Message, WebSocketContext, WebSocketHandler,
};
use uuid::Uuid;

use elliot_httpraw::{Scheme, ScopeDecision, WsDirection, WsKind, WsMessage};

use crate::scope::ScopeDecider;
use crate::ProxyEvent;

#[derive(Clone)]
pub struct WsHandler {
    pub events: tokio::sync::mpsc::Sender<ProxyEvent>,
    pub scope: Arc<dyn ScopeDecider>,
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

        if let Some(observed) = self.observe(direction, client_addr, &uri, &message) {
            // The core owns the receiver; if it is gone the proxy is shutting down.
            let _ = self.events.send(ProxyEvent::WebSocket(observed)).await;
        }

        // Observe-only: forward the frame untouched.
        Some(message)
    }
}

impl WsHandler {
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
            at: SystemTime::now(),
            client_addr,
            scheme,
            host,
            port,
            direction,
            kind,
            payload,
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
    let host = uri.host().unwrap_or_default().to_string();
    let port = uri.port_u16().unwrap_or(match scheme {
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
    use crate::scope::AllowAll;

    struct DenyAll;
    impl ScopeDecider for DenyAll {
        fn decide(&self, _s: &str, _h: &str, _p: u16, _path: &str) -> ScopeDecision {
            ScopeDecision::OutOfScope
        }
    }

    fn handler(scope: Arc<dyn ScopeDecider>) -> WsHandler {
        let (events, _rx) = tokio::sync::mpsc::channel(4);
        WsHandler { events, scope }
    }

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:5000".parse().unwrap()
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
}
