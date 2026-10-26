//! elliot-repeater — resend one raw request, return the response.
//!
//! The repeater is the byte-exact counterpart to the proxy. Where the proxy
//! parses well-formed browser traffic, the repeater exists to send **exactly
//! the bytes the user crafted** — malformed start lines, odd header casing,
//! duplicate headers, deliberate smuggling — over a raw TCP (optionally TLS)
//! connection, with **no normalization** on the request path.
//!
//! The response *is* parsed, best-effort, into the shared
//! [`elliot_httpraw::Response`] for display, but the exact response bytes are
//! always preserved in [`RepeatResponse::raw`].

use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use elliot_httpraw::{Header, HttpVersion, Response};

mod tls;

/// Default cap on how long to wait for the response once the request is sent.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A single request to replay.
#[derive(Clone, Debug)]
pub struct RepeatRequest {
    pub host: String,
    pub port: u16,
    /// Wrap the connection in TLS (SNI = `host`).
    pub tls: bool,
    /// Raw request bytes, sent verbatim. Never rewritten.
    pub raw: Bytes,
    /// How long to wait for the response before giving up.
    pub read_timeout: Duration,
    /// Skip upstream certificate verification. Off by default; a deliberate,
    /// caller-set opt-out for testing broken or self-signed targets.
    pub accept_invalid_certs: bool,
}

impl RepeatRequest {
    /// A plaintext request with default timeout and certificate verification on.
    pub fn new(host: impl Into<String>, port: u16, raw: impl Into<Bytes>) -> Self {
        Self {
            host: host.into(),
            port,
            tls: false,
            raw: raw.into(),
            read_timeout: DEFAULT_READ_TIMEOUT,
            accept_invalid_certs: false,
        }
    }

    /// Enable TLS (SNI = `host`).
    pub fn with_tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn accepting_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }
}

/// The result of a replay.
#[derive(Clone, Debug)]
pub struct RepeatResponse {
    /// Exact response bytes as received off the wire.
    pub raw: Bytes,
    /// Best-effort parse of `raw`. `None` if the bytes are not a parseable HTTP
    /// response (the raw bytes are still available).
    pub response: Option<Response>,
    /// Wall-clock time from just before sending to the last byte read.
    pub elapsed: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum RepeatError {
    #[error("invalid server name {0:?}")]
    InvalidServerName(String),
    #[error("connect: {0}")]
    Connect(#[source] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[source] std::io::Error),
    #[error("write request: {0}")]
    Write(#[source] std::io::Error),
    #[error("read response: {0}")]
    Read(#[source] std::io::Error),
    #[error("timed out waiting for response")]
    Timeout,
}

/// Replay one request and return its response.
pub async fn send(req: RepeatRequest) -> Result<RepeatResponse, RepeatError> {
    let tcp = TcpStream::connect((req.host.as_str(), req.port))
        .await
        .map_err(RepeatError::Connect)?;
    // Craft requests often want Nagle off for predictable framing.
    let _ = tcp.set_nodelay(true);

    let started = Instant::now();
    let raw = if req.tls {
        let server_name = ServerName::try_from(req.host.clone())
            .map_err(|_| RepeatError::InvalidServerName(req.host.clone()))?;
        let connector = tls::connector(req.accept_invalid_certs);
        let mut stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(RepeatError::Tls)?;
        exchange(&mut stream, &req.raw, req.read_timeout).await?
    } else {
        let mut stream = tcp;
        exchange(&mut stream, &req.raw, req.read_timeout).await?
    };
    let elapsed = started.elapsed();

    let response = parse_response(&raw);
    Ok(RepeatResponse {
        raw,
        response,
        elapsed,
    })
}

/// Write the raw request verbatim, then read the response under a timeout.
async fn exchange<S>(stream: &mut S, raw: &[u8], timeout: Duration) -> Result<Bytes, RepeatError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    stream.write_all(raw).await.map_err(RepeatError::Write)?;
    stream.flush().await.map_err(RepeatError::Write)?;

    match tokio::time::timeout(timeout, read_response(stream)).await {
        Ok(res) => res,
        Err(_) => Err(RepeatError::Timeout),
    }
}

/// Read an HTTP response, framing it by `Content-Length`, chunked terminator,
/// or connection close, whichever comes first.
async fn read_response<S>(stream: &mut S) -> Result<Bytes, RepeatError>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    let mut header_end: Option<usize> = None;
    let mut framing: Option<Framing> = None;

    loop {
        // Decide completeness from what we already have.
        if header_end.is_none() {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                header_end = Some(pos + 4);
                framing = Some(detect_framing(&buf[..pos + 4]));
            }
        }
        if let (Some(hend), Some(f)) = (header_end, framing.as_ref()) {
            if is_complete(&buf, hend, f) {
                break;
            }
        }

        let n = stream.read(&mut chunk).await.map_err(RepeatError::Read)?;
        if n == 0 {
            break; // peer closed — whatever we have is the response
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok(Bytes::from(buf))
}

#[derive(Debug)]
enum Framing {
    /// Exact body length is known.
    ContentLength(usize),
    /// Body is chunked; complete at the terminal `0\r\n\r\n`.
    Chunked,
    /// No length signalled; complete only at connection close.
    UntilClose,
}

fn detect_framing(headers: &[u8]) -> Framing {
    // Case-insensitive header scan over the already-terminated header block.
    let text = headers;
    if let Some(len) = header_value(text, b"content-length")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        return Framing::ContentLength(len);
    }
    if let Some(te) = header_value(text, b"transfer-encoding") {
        if contains_ignore_ascii_case(te, b"chunked") {
            return Framing::Chunked;
        }
    }
    Framing::UntilClose
}

fn is_complete(buf: &[u8], header_end: usize, framing: &Framing) -> bool {
    match framing {
        Framing::ContentLength(len) => buf.len() >= header_end + len,
        // Terminal chunk; good enough for well-behaved servers.
        Framing::Chunked => {
            buf.len() >= header_end && find_subslice(&buf[header_end..], b"0\r\n\r\n").is_some()
        }
        Framing::UntilClose => false,
    }
}

/// Best-effort parse of raw response bytes into the shared model.
fn parse_response(raw: &[u8]) -> Option<Response> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut headers);
    let body_offset = match parsed.parse(raw).ok()? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return None,
    };

    let status = parsed.code?;
    let reason = parsed.reason.unwrap_or("").to_string();
    let version = match parsed.version {
        Some(0) => HttpVersion::Http10,
        _ => HttpVersion::Http11,
    };
    let hdrs: Vec<Header> = parsed
        .headers
        .iter()
        .map(|h| Header {
            name: h.name.to_string(),
            value: h.value.to_vec(),
        })
        .collect();
    let body = Bytes::copy_from_slice(&raw[body_offset..]);

    Some(Response {
        status,
        reason,
        version,
        headers: hdrs,
        body,
        raw: Bytes::copy_from_slice(raw),
    })
}

// --- small byte helpers -----------------------------------------------------

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Find the first value of `name` (lowercase) in a header block.
fn header_value<'a>(block: &'a [u8], name_lower: &[u8]) -> Option<&'a [u8]> {
    for line in block.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let (n, v) = line.split_at(colon);
            if n.eq_ignore_ascii_case(name_lower) {
                return Some(trim_ascii(&v[1..]));
            }
        }
    }
    None
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Spawn a one-shot TCP server that records the request bytes it received
    /// and replies with `response`. Returns (addr, join handle yielding request).
    async fn one_shot(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read whatever the client sends until a short idle, then reply.
            let mut got = vec![0u8; 4096];
            let n = sock.read(&mut got).await.unwrap();
            got.truncate(n);
            sock.write_all(response).await.unwrap();
            sock.flush().await.unwrap();
            drop(sock);
            got
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn sends_bytes_verbatim_and_parses_response() {
        let (addr, server) = one_shot(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").await;
        // A deliberately odd request line the repeater must not touch.
        let raw = b"GeT /x HTTP/1.1\r\nHost: t\r\nX-Odd:  weird \r\n\r\n".to_vec();

        let res = send(RepeatRequest::new(addr.ip().to_string(), addr.port(), raw.clone()))
            .await
            .unwrap();

        let got = server.await.unwrap();
        assert_eq!(got, raw, "request must be sent byte-for-byte");

        let parsed = res.response.expect("parseable response");
        assert_eq!(parsed.status, 200);
        assert_eq!(&parsed.body[..], b"hi");
        assert!(res.raw.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn reads_body_until_close_without_content_length() {
        let (addr, _server) = one_shot(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let res = send(RepeatRequest::new(
            addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        ))
        .await
        .unwrap();
        assert_eq!(res.response.unwrap().status, 204);
    }

    #[tokio::test]
    async fn times_out_when_server_is_silent() {
        // Listener that accepts but never replies.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _sock = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let req = RepeatRequest::new(
            addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        )
        .with_timeout(Duration::from_millis(150));
        let err = send(req).await.unwrap_err();
        assert!(matches!(err, RepeatError::Timeout), "got {err:?}");
    }

    #[test]
    fn header_value_is_case_insensitive() {
        let block = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(header_value(block, b"content-length"), Some(&b"42"[..]));
    }
}
