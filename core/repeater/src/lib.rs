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
//!
//! # Scope
//!
//! The repeater does **not** consult the scope engine itself: it sends exactly
//! the bytes it is handed, to whatever host it is pointed at. Scope is enforced
//! by the caller — `elliot-intruder` checks it before sending anything, and
//! the proxy only ever surfaces in-scope traffic. Keeping the gate out of this
//! crate leaves it a pure "send these bytes" primitive; any caller that accepts
//! a target from outside the app must run it through
//! [`elliot_httpraw::ScopeDecider`] first.

use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use elliot_httpraw::{Header, HttpVersion, Response};

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
    #[error("tls config: {0}")]
    TlsConfig(#[from] elliot_tls::TlsError),
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
        let connector = elliot_tls::connector(req.accept_invalid_certs)?;
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
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(raw).await.map_err(RepeatError::Write)?;
    stream.flush().await.map_err(RepeatError::Write)?;

    match tokio::time::timeout(timeout, read_response(stream)).await {
        Ok(res) => res,
        Err(_) => Err(RepeatError::Timeout),
    }
}

/// Read an HTTP response, framing it by `Transfer-Encoding: chunked`,
/// `Content-Length`, or connection close, whichever applies.
///
/// The header block is parsed **once** with `httparse` — the same parser
/// [`parse_response`] uses — to decide the framing, so the headers are never
/// scanned by hand. The bytes returned are always the raw bytes off the wire.
async fn read_response<S>(stream: &mut S) -> Result<Bytes, RepeatError>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    let mut header_end: Option<usize> = None;
    let mut framing: Option<Framing> = None;

    loop {
        // Decide completeness from what we already have.
        if header_end.is_none() {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                let end = pos + 4;
                header_end = Some(end);
                framing = Some(parse_framing(&buf[..end]));
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
    /// Body is chunked; complete at the terminal chunk plus its trailer section.
    Chunked,
    /// No length signalled; complete only at connection close.
    UntilClose,
}

/// Decide the body framing from the (already terminated) header block using
/// `httparse`, rather than a hand-rolled header scan.
fn parse_framing(head: &[u8]) -> Framing {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut headers);
    // A header block that does not parse cannot be framed from its headers.
    if !matches!(parsed.parse(head), Ok(httparse::Status::Complete(_))) {
        return Framing::UntilClose;
    }

    let mut content_length = None;
    for h in parsed.headers.iter() {
        // Transfer-Encoding wins over Content-Length when both appear
        // (RFC 7230 §3.3.3) — checking it first also keeps a smuggled
        // Content-Length from shortening the read.
        if h.name.eq_ignore_ascii_case("transfer-encoding")
            && h.value
                .split(|&b| b == b',')
                .any(|token| trim_ascii(token).eq_ignore_ascii_case(b"chunked"))
        {
            return Framing::Chunked;
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            content_length = std::str::from_utf8(h.value)
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok());
        }
    }
    match content_length {
        Some(len) => Framing::ContentLength(len),
        None => Framing::UntilClose,
    }
}

fn is_complete(buf: &[u8], header_end: usize, framing: &Framing) -> bool {
    match framing {
        // `saturating_sub` keeps a bogus huge Content-Length from overflowing.
        Framing::ContentLength(len) => buf.len().saturating_sub(header_end) >= *len,
        Framing::Chunked => chunked_complete(&buf[header_end.min(buf.len())..]),
        Framing::UntilClose => false,
    }
}

/// Is the chunked body that follows the headers complete?
///
/// Walks chunk by chunk — `size[;extension] CRLF`, then the data and its CRLF —
/// until the terminal zero-length chunk, whose (possibly empty) trailer section
/// ends at a blank line. Anything not yet fully received, or malformed, returns
/// `false` so the reader keeps going (the read timeout bounds the wait).
fn chunked_complete(mut body: &[u8]) -> bool {
    loop {
        let Some(line_end) = find_subslice(body, b"\r\n") else {
            return false;
        };
        let line = &body[..line_end];
        // A chunk extension (everything after `;`) is legal but ignored.
        let size_field = match line.iter().position(|&b| b == b';') {
            Some(i) => &line[..i],
            None => line,
        };
        let Ok(size) = parse_chunk_size(size_field) else {
            return false;
        };
        body = &body[line_end + 2..];

        if size == 0 {
            // Trailer section: zero or more header lines, ended by a blank one.
            let mut rest = body;
            loop {
                let Some(end) = find_subslice(rest, b"\r\n") else {
                    return false;
                };
                if end == 0 {
                    return true;
                }
                rest = &rest[end + 2..];
            }
        }

        // The chunk data and its trailing CRLF must both be present.
        // `get` (not `size + 2`) so a huge declared size cannot overflow.
        let Some(rest) = body.get(size..) else {
            return false;
        };
        if !rest.starts_with(b"\r\n") {
            return false;
        }
        body = &rest[2..];
    }
}

/// Parse a hexadecimal chunk size. Rejects empty or non-hex input and cannot
/// overflow (a bogus size simply reports "not complete yet").
fn parse_chunk_size(field: &[u8]) -> Result<usize, ()> {
    let field = trim_ascii(field);
    if field.is_empty() {
        return Err(());
    }
    let mut value: usize = 0;
    for &b in field {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(()),
        };
        value = value.checked_mul(16).ok_or(())?;
        value = value.checked_add(usize::from(digit)).ok_or(())?;
    }
    Ok(value)
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
        response: Vec<u8>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read whatever the client sends until a short idle, then reply.
            let mut got = vec![0u8; 4096];
            let n = sock.read(&mut got).await.unwrap();
            got.truncate(n);
            sock.write_all(&response).await.unwrap();
            sock.flush().await.unwrap();
            drop(sock);
            got
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn sends_bytes_verbatim_and_parses_response() {
        let (addr, server) = one_shot(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec()).await;
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
        let (addr, _server) = one_shot(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()).await;
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

    #[tokio::test]
    async fn reads_multi_chunk_chunked_response() {
        let response: Vec<u8> =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                .to_vec();
        let expected = response.clone();
        let (addr, _server) = one_shot(response).await;

        let res = send(RepeatRequest::new(
            addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        ))
        .await
        .unwrap();

        assert_eq!(&res.raw[..], &expected[..], "raw chunked bytes are preserved");
        assert_eq!(res.response.expect("parseable").status, 200);
    }

    #[tokio::test]
    async fn chunked_decoder_handles_extensions_and_trailers() {
        // `;name=value` on the data chunk and a trailer after the terminal one.
        let response: Vec<u8> = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb;name=value\r\nhello world\r\n0\r\nX-Trailer: done\r\n\r\n".to_vec();
        let expected = response.clone();
        let (addr, _server) = one_shot(response).await;

        let res = send(RepeatRequest::new(
            addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        ))
        .await
        .unwrap();

        assert_eq!(&res.raw[..], &expected[..]);
    }

    /// Regression for the old framing: the raw body *contains* the byte
    /// sequence `0\r\n\r\n`, so the previous substring-based check declared the
    /// response complete halfway through. The decoder must instead wait for the
    /// real terminal chunk. The server splits the write so the false positive
    /// window is real, and keeps the socket open so a close cannot mask it.
    #[tokio::test]
    async fn chunked_body_containing_terminator_is_not_truncated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut ignore = [0u8; 4096];
            let _ = sock.read(&mut ignore).await;
            // First chunk header plus a prefix of its data, ending right after
            // the embedded `0\r\n\r\n`.
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nX0\r\n\r\n")
                .await
                .unwrap();
            sock.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Rest of the chunk data, then the terminal chunk.
            sock.write_all(b"Y\r\n0\r\n\r\n").await.unwrap();
            sock.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let res = send(RepeatRequest::new(
            addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        ))
        .await
        .unwrap();

        let expected =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nX0\r\n\r\nY\r\n0\r\n\r\n";
        assert_eq!(&res.raw[..], &expected[..], "the whole chunked body is read");
    }

    #[test]
    fn chunk_size_parsing_is_bounded_and_strict() {
        assert_eq!(parse_chunk_size(b"0"), Ok(0));
        assert_eq!(parse_chunk_size(b"b"), Ok(11));
        assert_eq!(parse_chunk_size(b"1A"), Ok(26));
        assert_eq!(parse_chunk_size(b" 10 "), Ok(16));
        assert!(parse_chunk_size(b"").is_err());
        assert!(parse_chunk_size(b"zz").is_err());
        // A size that would overflow reports "not a size", never a panic.
        assert!(parse_chunk_size(b"FFFFFFFFFFFFFFFFFFFFFFFF").is_err());
    }

    #[test]
    fn chunked_completeness_needs_the_terminal_chunk() {
        assert!(!chunked_complete(b"5\r\nhello\r\n"));
        assert!(chunked_complete(b"5\r\nhello\r\n0\r\n\r\n"));
        assert!(chunked_complete(b"0\r\n\r\n"));
        // Terminal chunk with a trailer section.
        assert!(chunked_complete(b"0\r\nX: y\r\n\r\n"));
        // Trailer section started but not terminated yet.
        assert!(!chunked_complete(b"0\r\nX: y\r\n"));
        // Chunk data shorter than declared.
        assert!(!chunked_complete(b"7\r\nhello\r\n"));
    }
}
