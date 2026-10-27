//! elliot-httpraw — shared request/response model for Elliot.
//!
//! This crate owns the [`Flow`] type: the contract exchanged between the proxy,
//! the repeater, the intruder and the store. A flow carries both a *parsed*
//! view (method, headers, body…) and a *raw* byte view.
//!
//! On the proxy capture path the raw bytes are **reconstructed** by
//! re-serializing the parsed message (see [`serialize_request`] /
//! [`serialize_response`]). This is faithful for the well-formed traffic a
//! browser emits, but is not guaranteed byte-exact. Byte-exact editing lives on
//! the repeater/intruder path, which works on raw TCP and populates `raw`
//! directly.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;
use uuid::Uuid;

pub mod net;

/// A single request/response exchange observed (or produced) by Elliot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flow {
    pub id: Uuid,
    pub started_at: SystemTime,
    pub completed_at: Option<SystemTime>,
    pub client_addr: SocketAddr,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub request: Request,
    pub response: Option<Response>,
    pub state: FlowState,
    pub scope: ScopeDecision,
    pub error: Option<String>,
}

/// Parsed + raw view of a request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    /// Request target as seen on the wire (path + query, or absolute form).
    pub target: String,
    pub version: HttpVersion,
    /// Headers in order, duplicates preserved.
    pub headers: Vec<Header>,
    pub body: Bytes,
    /// Bytes reconstructed from the parsed message.
    pub raw: Bytes,
}

/// Parsed + raw view of a response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<Header>,
    pub body: Bytes,
    pub raw: Bytes,
}

/// A single header. The value is kept as raw bytes because header values are
/// not guaranteed to be valid UTF-8.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    /// Canonical token written to disk by `elliot-store`. Frozen: changing it
    /// breaks existing project files.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// Inverse of [`Scheme::as_str`]. Unknown tokens fall back to `Http`.
    pub fn from_token(token: &str) -> Self {
        match token {
            "https" => Scheme::Https,
            _ => Scheme::Http,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpVersion {
    Http10,
    Http11,
    H2,
}

impl HttpVersion {
    /// Map from the `http` crate version. Unknown versions fall back to 1.1.
    pub fn from_http(v: http::Version) -> Self {
        match v {
            http::Version::HTTP_10 => HttpVersion::Http10,
            http::Version::HTTP_2 => HttpVersion::H2,
            _ => HttpVersion::Http11,
        }
    }

    /// Wire token for the request/status line (HTTP/2 is written as 1.1 since
    /// h2 has no textual start line; the reconstruction is a best-effort view).
    pub fn wire_token(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 | HttpVersion::H2 => "HTTP/1.1",
        }
    }

    /// Canonical token written to disk by `elliot-store`. Frozen: changing it
    /// breaks existing project files.
    pub fn as_token(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "1.0",
            HttpVersion::Http11 => "1.1",
            HttpVersion::H2 => "2",
        }
    }

    /// Inverse of [`HttpVersion::as_token`]. Unknown tokens fall back to 1.1.
    pub fn from_token(token: &str) -> Self {
        match token {
            "1.0" => HttpVersion::Http10,
            "2" => HttpVersion::H2,
            _ => HttpVersion::Http11,
        }
    }
}

/// A single WebSocket message observed on an in-scope connection (Phase D).
///
/// WebSocket traffic does not fit the request/response [`Flow`] shape, so it is
/// carried as its own value. The `connection` key groups the two directions of
/// one socket; it is derived from the client address and the server authority,
/// so concurrent sockets from the same client to the same host currently share
/// a key (a known limitation — stitching messages to the originating HTTP
/// upgrade flow, and separating concurrent sockets, is a follow-up).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WsMessage {
    pub id: Uuid,
    pub connection: String,
    pub at: SystemTime,
    pub client_addr: SocketAddr,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub direction: WsDirection,
    pub kind: WsKind,
    pub payload: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WsKind {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// The transport a [`Stream`] was captured on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// Canonical token written to disk by `elliot-store`. Frozen: changing it
    /// breaks existing project files.
    pub fn as_token(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }

    /// Inverse of [`Transport::as_token`]. Unknown tokens fall back to `Tcp`.
    pub fn from_token(token: &str) -> Self {
        match token {
            "udp" => Transport::Udp,
            _ => Transport::Tcp,
        }
    }

    /// The token passed to [`ScopeDecider::decide`] for this transport.
    pub fn scheme(self) -> &'static str {
        self.as_token()
    }
}

/// Which end of a stream a [`Message`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    /// Canonical token written to disk by `elliot-store`. Frozen: changing it
    /// breaks existing project files.
    pub fn as_token(self) -> &'static str {
        match self {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        }
    }

    /// Inverse of [`Direction::as_token`]. Unknown tokens fall back to
    /// `ClientToServer`.
    pub fn from_token(token: &str) -> Self {
        match token {
            "s2c" => Direction::ServerToClient,
            _ => Direction::ClientToServer,
        }
    }
}

/// A captured connection (TCP) or association (UDP) that is *not* an HTTP
/// [`Flow`].
///
/// The generic, transport-agnostic counterpart of [`Flow`]: the contract
/// between the non-HTTP capture listener (`elliot-socks`), the store and the
/// UI. A TCP connection maps one-to-one onto a stream; a UDP association maps
/// onto a stream whose host/port are those of the **first** datagram seen (a
/// SOCKS UDP association may fan out to several targets — a `Message` carries
/// the payload, not the destination).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stream {
    pub id: Uuid,
    pub started_at: SystemTime,
    pub completed_at: Option<SystemTime>,
    pub client_addr: SocketAddr,
    pub transport: Transport,
    pub host: String,
    pub port: u16,
    /// True when the captured bytes are the application plaintext behind a
    /// terminated (MITM) TLS session, false when they are opaque bytes.
    pub tls: bool,
    pub scope: ScopeDecision,
    /// Reuses [`FlowState`]: `Pending` while open, then `Completed`/`Error`.
    pub state: FlowState,
    pub error: Option<String>,
}

/// One observed chunk (TCP) or datagram (UDP) on a [`Stream`]. The bytes are
/// raw: no protocol is assumed, no framing is implied. On TCP a message is one
/// read, so its boundaries are those of the relay's reads, not of a protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub stream_id: Uuid,
    /// Order of this message within its stream (per whole stream, both
    /// directions counted together).
    pub seq: u64,
    pub at: SystemTime,
    pub direction: Direction,
    pub data: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    Pending,
    Paused,
    Completed,
    Dropped,
    Error,
}

impl FlowState {
    /// Canonical token written to disk by `elliot-store`. Frozen: changing it
    /// breaks existing project files.
    pub fn as_token(self) -> &'static str {
        match self {
            FlowState::Pending => "pending",
            FlowState::Paused => "paused",
            FlowState::Completed => "completed",
            FlowState::Dropped => "dropped",
            FlowState::Error => "error",
        }
    }

    /// Inverse of [`FlowState::as_token`]. Unknown tokens fall back to `Pending`.
    pub fn from_token(token: &str) -> Self {
        match token {
            "paused" => FlowState::Paused,
            "completed" => FlowState::Completed,
            "dropped" => FlowState::Dropped,
            "error" => FlowState::Error,
            _ => FlowState::Pending,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeDecision {
    InScope,
    OutOfScope,
    Passthrough,
}

impl ScopeDecision {
    /// Canonical token written to disk by `elliot-store`. Frozen: changing it
    /// breaks existing project files.
    pub fn as_token(self) -> &'static str {
        match self {
            ScopeDecision::InScope => "in",
            ScopeDecision::OutOfScope => "out",
            ScopeDecision::Passthrough => "passthrough",
        }
    }

    /// Inverse of [`ScopeDecision::as_token`]. Unknown tokens fall back to
    /// `InScope`.
    pub fn from_token(token: &str) -> Self {
        match token {
            "out" => ScopeDecision::OutOfScope,
            "passthrough" => ScopeDecision::Passthrough,
            _ => ScopeDecision::InScope,
        }
    }
}

/// Decides whether traffic is in scope (capture + MITM), out of scope, or
/// should be tunnelled transparently (passthrough).
///
/// This is the shared contract between the scope engine (`elliot-scope`) and
/// its consumers (the proxy today; the repeater, intruder and tool runner
/// next). It lives here, in the common model crate, so that neither side has
/// to depend on the other's crate: consumers take `Arc<dyn ScopeDecider>`,
/// `elliot-scope` implements it, and the app wires the two together.
pub trait ScopeDecider: Send + Sync {
    fn decide(&self, scheme: &str, host: &str, port: u16, path: &str) -> ScopeDecision;
}

/// The trivial always-in-scope decider: everything [`ScopeDecision::InScope`].
///
/// Lives here, next to the trait, so every consumer (proxy, runner, intruder,
/// tests) shares one definition instead of re-declaring its own.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl ScopeDecider for AllowAll {
    fn decide(&self, _scheme: &str, _host: &str, _port: u16, _path: &str) -> ScopeDecision {
        ScopeDecision::InScope
    }
}

/// The trivial never-in-scope decider: everything
/// [`ScopeDecision::OutOfScope`]. The mirror of [`AllowAll`], mainly for tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAll;

impl ScopeDecider for DenyAll {
    fn decide(&self, _scheme: &str, _host: &str, _port: u16, _path: &str) -> ScopeDecision {
        ScopeDecision::OutOfScope
    }
}

/// Reconstruct the raw bytes of a request from its parsed parts.
pub fn serialize_request(
    method: &str,
    target: &str,
    version: HttpVersion,
    headers: &[Header],
    body: &[u8],
) -> Bytes {
    let mut out = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(version.wire_token().as_bytes());
    out.extend_from_slice(b"\r\n");
    write_headers(&mut out, headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Bytes::from(out)
}

/// Reconstruct the raw bytes of a response from its parsed parts.
pub fn serialize_response(
    status: u16,
    reason: &str,
    version: HttpVersion,
    headers: &[Header],
    body: &[u8],
) -> Bytes {
    let mut out = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(version.wire_token().as_bytes());
    out.push(b' ');
    out.extend_from_slice(status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\n");
    write_headers(&mut out, headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Bytes::from(out)
}

fn write_headers(out: &mut Vec<u8>, headers: &[Header]) {
    for h in headers {
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&h.value);
        out.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_to_wire() {
        let headers = vec![Header {
            name: "Host".into(),
            value: b"example.com".to_vec(),
        }];
        let raw = serialize_request("GET", "/", HttpVersion::Http11, &headers, b"");
        assert_eq!(&raw[..], b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn response_round_trips_to_wire() {
        let raw = serialize_response(200, "OK", HttpVersion::Http11, &[], b"hi");
        assert_eq!(&raw[..], b"HTTP/1.1 200 OK\r\n\r\nhi");
    }

    #[test]
    fn http2_version_maps_and_serializes_as_1_1() {
        // Phase C: an h2 message is tagged H2 in the parsed view, but has no
        // textual start line, so the reconstructed raw view falls back to 1.1.
        assert_eq!(HttpVersion::from_http(http::Version::HTTP_2), HttpVersion::H2);
        assert_eq!(HttpVersion::H2.wire_token(), "HTTP/1.1");
        let raw = serialize_request("GET", "/", HttpVersion::H2, &[], b"");
        assert_eq!(&raw[..], b"GET / HTTP/1.1\r\n\r\n");
    }

    /// These exact strings are written to (and read back from) the SQLCipher
    /// project file by `elliot-store`. Changing any of them silently would
    /// break every existing `.elliot` project, so they are pinned here.
    #[test]
    fn enum_tokens_are_frozen_for_the_store() {
        assert_eq!(Scheme::Http.as_str(), "http");
        assert_eq!(Scheme::Https.as_str(), "https");

        assert_eq!(Transport::Tcp.as_token(), "tcp");
        assert_eq!(Transport::Udp.as_token(), "udp");
        assert_eq!(Direction::ClientToServer.as_token(), "c2s");
        assert_eq!(Direction::ServerToClient.as_token(), "s2c");

        assert_eq!(HttpVersion::Http10.as_token(), "1.0");
        assert_eq!(HttpVersion::Http11.as_token(), "1.1");
        assert_eq!(HttpVersion::H2.as_token(), "2");

        assert_eq!(FlowState::Pending.as_token(), "pending");
        assert_eq!(FlowState::Paused.as_token(), "paused");
        assert_eq!(FlowState::Completed.as_token(), "completed");
        assert_eq!(FlowState::Dropped.as_token(), "dropped");
        assert_eq!(FlowState::Error.as_token(), "error");

        assert_eq!(ScopeDecision::InScope.as_token(), "in");
        assert_eq!(ScopeDecision::OutOfScope.as_token(), "out");
        assert_eq!(ScopeDecision::Passthrough.as_token(), "passthrough");
    }

    fn sample_stream() -> Stream {
        Stream {
            id: Uuid::new_v4(),
            started_at: std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_000),
            completed_at: Some(
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_050),
            ),
            client_addr: "127.0.0.1:51000".parse().unwrap(),
            transport: Transport::Tcp,
            host: "redis.internal".into(),
            port: 6379,
            tls: false,
            scope: ScopeDecision::InScope,
            state: FlowState::Completed,
            error: None,
        }
    }

    /// The UI receives these over IPC as JSON, so the (de)serialization is the
    /// contract, not an implementation detail.
    #[test]
    fn stream_and_message_round_trip_through_json() {
        let stream = sample_stream();
        let json = serde_json::to_string(&stream).unwrap();
        let back: Stream = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, stream.id);
        assert_eq!(back.transport, Transport::Tcp);
        assert_eq!(back.host, "redis.internal");
        assert_eq!(back.scope, ScopeDecision::InScope);
        assert_eq!(back.state, FlowState::Completed);

        let msg = Message {
            id: Uuid::new_v4(),
            stream_id: stream.id,
            seq: 7,
            at: std::time::UNIX_EPOCH,
            direction: Direction::ServerToClient,
            data: Bytes::from_static(b"+PONG\r\n"),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stream_id, stream.id);
        assert_eq!(back.seq, 7);
        assert_eq!(back.direction, Direction::ServerToClient);
        assert_eq!(&back.data[..], b"+PONG\r\n");
    }

    #[test]
    fn transport_and_direction_tokens_round_trip_and_degrade_safely() {
        for t in [Transport::Tcp, Transport::Udp] {
            assert_eq!(Transport::from_token(t.as_token()), t);
        }
        for d in [Direction::ClientToServer, Direction::ServerToClient] {
            assert_eq!(Direction::from_token(d.as_token()), d);
        }
        assert_eq!(Transport::from_token("sctp"), Transport::Tcp);
        assert_eq!(Direction::from_token("weird"), Direction::ClientToServer);
    }

    #[test]
    fn trivial_deciders_take_the_expected_decision() {
        assert_eq!(AllowAll.decide("https", "x", 443, "/"), ScopeDecision::InScope);
        assert_eq!(
            DenyAll.decide("https", "x", 443, "/"),
            ScopeDecision::OutOfScope
        );
        // Usable as a shared trait object, the way consumers hold it.
        let d: std::sync::Arc<dyn ScopeDecider> = std::sync::Arc::new(AllowAll);
        assert_eq!(d.decide("http", "y", 80, "/"), ScopeDecision::InScope);
    }

    #[test]
    fn enum_tokens_round_trip_and_degrade_safely() {
        for v in [Scheme::Http, Scheme::Https] {
            assert_eq!(Scheme::from_token(v.as_str()), v);
        }
        for v in [HttpVersion::Http10, HttpVersion::Http11, HttpVersion::H2] {
            assert_eq!(HttpVersion::from_token(v.as_token()), v);
        }
        for v in [
            FlowState::Pending,
            FlowState::Paused,
            FlowState::Completed,
            FlowState::Dropped,
            FlowState::Error,
        ] {
            assert_eq!(FlowState::from_token(v.as_token()), v);
        }
        for v in [
            ScopeDecision::InScope,
            ScopeDecision::OutOfScope,
            ScopeDecision::Passthrough,
        ] {
            assert_eq!(ScopeDecision::from_token(v.as_token()), v);
        }

        // An unknown token must degrade to the safe default, never panic.
        assert_eq!(Scheme::from_token("gopher"), Scheme::Http);
        assert_eq!(HttpVersion::from_token("9"), HttpVersion::Http11);
        assert_eq!(FlowState::from_token("weird"), FlowState::Pending);
        assert_eq!(ScopeDecision::from_token("weird"), ScopeDecision::InScope);
    }
}
