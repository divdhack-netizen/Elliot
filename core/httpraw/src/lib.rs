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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    Pending,
    Paused,
    Completed,
    Dropped,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeDecision {
    InScope,
    OutOfScope,
    Passthrough,
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
}
