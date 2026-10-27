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
//! # Beyond HTTP
//!
//! The same primitive sends a payload at any TCP port — a Redis command, a
//! line protocol, a binary RPC — and, with [`Transport::Udp`], a single
//! datagram. Since those protocols have no framing Elliot knows, the caller
//! says how the reply ends via [`ReadMode`]; HTTP framing stays the default, so
//! existing callers behave exactly as before.
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
use tokio::net::{TcpStream, UdpSocket};

use elliot_httpraw::{Header, HttpVersion, Response};

/// Re-exported: a replay is TCP or UDP, the same vocabulary the captured
/// [`elliot_httpraw::Stream`] uses.
pub use elliot_httpraw::Transport;

/// Default cap on how long to wait for the response once the request is sent.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on an [`ReadMode::Exact`] read, so a mistyped length cannot make the
/// repeater allocate without bound.
pub const MAX_EXACT_READ: usize = 16 * 1024 * 1024;

/// Largest datagram a UDP replay will accept (the protocol maximum).
const MAX_DATAGRAM: usize = 65_535;

/// How the end of a response is decided.
///
/// [`ReadMode::Http`] is the default and preserves the historical behaviour.
/// Everything else exists for protocols with no framing Elliot can rely on: the
/// caller says what a complete reply looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    /// Frame the reply as HTTP: `Content-Length`, chunked, or connection close.
    Http,
    /// Read until no bytes arrive for this long. The **first** byte still has
    /// to arrive within `read_timeout`, so a silent target fails instead of
    /// returning an empty success.
    UntilIdle(Duration),
    /// Read exactly this many bytes. A peer that closes early yields the bytes
    /// received so far (a partial reply is data, not an error).
    Exact(usize),
    /// Read until the peer closes, bounded by `read_timeout`.
    UntilClose,
    /// Send one datagram, receive one datagram. Valid only with
    /// [`Transport::Udp`].
    Datagram,
}

/// A single request to replay.
#[derive(Clone, Debug)]
pub struct RepeatRequest {
    pub host: String,
    pub port: u16,
    /// Wrap the connection in TLS (SNI = `host`).
    pub tls: bool,
    /// Raw request bytes, sent verbatim. Never rewritten.
    pub raw: Bytes,
    /// How long to wait for the response before giving up. For the non-HTTP
    /// read modes it is the overall bound (and the wait for the first byte).
    pub read_timeout: Duration,
    /// Skip upstream certificate verification. Off by default; a deliberate,
    /// caller-set opt-out for testing broken or self-signed targets.
    pub accept_invalid_certs: bool,
    /// TCP (stream) or UDP (datagram). Defaults to TCP.
    pub transport: Transport,
    /// How the reply is framed. Defaults to [`ReadMode::Http`].
    pub read_mode: ReadMode,
}

impl RepeatRequest {
    /// A plaintext TCP request with default timeout, HTTP framing and
    /// certificate verification on — the historical behaviour, unchanged.
    pub fn new(host: impl Into<String>, port: u16, raw: impl Into<Bytes>) -> Self {
        Self {
            host: host.into(),
            port,
            tls: false,
            raw: raw.into(),
            read_timeout: DEFAULT_READ_TIMEOUT,
            accept_invalid_certs: false,
            transport: Transport::Tcp,
            read_mode: ReadMode::Http,
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

    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_read_mode(mut self, read_mode: ReadMode) -> Self {
        self.read_mode = read_mode;
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
    #[error("resolve {0}: {1}")]
    Resolve(String, #[source] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[source] std::io::Error),
    #[error("write request: {0}")]
    Write(#[source] std::io::Error),
    #[error("read response: {0}")]
    Read(#[source] std::io::Error),
    #[error("timed out waiting for response")]
    Timeout,
    #[error("read mode {mode:?} is not valid for {transport:?}")]
    ModeNotSupported {
        mode: ReadMode,
        transport: Transport,
    },
    #[error("an exact read of {len} bytes exceeds the {max}-byte cap")]
    ExactTooLarge { len: usize, max: usize },
    #[error("TLS over UDP is not implemented (DTLS is a different protocol)")]
    TlsOverUdp,
}

/// Replay one request and return its response.
pub async fn send(req: RepeatRequest) -> Result<RepeatResponse, RepeatError> {
    // Cheap validation first: a request that cannot work must not open a
    // socket (or send a byte) before failing.
    if let ReadMode::Exact(len) = req.read_mode {
        if len > MAX_EXACT_READ {
            return Err(RepeatError::ExactTooLarge {
                len,
                max: MAX_EXACT_READ,
            });
        }
    }

    match (req.transport, req.read_mode) {
        (Transport::Tcp, ReadMode::Datagram) => Err(RepeatError::ModeNotSupported {
            mode: ReadMode::Datagram,
            transport: Transport::Tcp,
        }),
        (Transport::Udp, mode) if mode != ReadMode::Datagram => Err(RepeatError::ModeNotSupported {
            mode,
            transport: Transport::Udp,
        }),
        (Transport::Udp, _) => send_udp(req).await,
        (Transport::Tcp, mode) => send_tcp(req, mode).await,
    }
}

/// TCP (optionally over TLS): connect, send verbatim, read per `mode`.
async fn send_tcp(req: RepeatRequest, mode: ReadMode) -> Result<RepeatResponse, RepeatError> {
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
        exchange(&mut stream, &req, mode).await?
    } else {
        let mut stream = tcp;
        exchange(&mut stream, &req, mode).await?
    };
    let elapsed = started.elapsed();

    let response = parse_response(&raw);
    Ok(RepeatResponse {
        raw,
        response,
        elapsed,
    })
}

/// UDP: one datagram out, one datagram back.
///
/// There is no connection to frame against and no ordering to preserve, so the
/// reply is correlated with the request only by the socket the answer arrives
/// on: a target that answers from a different port is not matched (documented
/// as best-effort in the plan; DNS, echo and most RPCs answer from the same
/// address).
async fn send_udp(req: RepeatRequest) -> Result<RepeatResponse, RepeatError> {
    if req.tls {
        return Err(RepeatError::TlsOverUdp);
    }
    let dest = tokio::net::lookup_host((req.host.as_str(), req.port))
        .await
        .map_err(|e| RepeatError::Resolve(req.host.clone(), e))?
        .next()
        .ok_or_else(|| {
            RepeatError::Resolve(
                req.host.clone(),
                std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved"),
            )
        })?;
    // Bind in the target's family: a v4 socket cannot send to a v6 address.
    let local = if dest.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(local).await.map_err(RepeatError::Connect)?;

    let started = Instant::now();
    socket
        .send_to(&req.raw, dest)
        .await
        .map_err(RepeatError::Write)?;

    let mut buf = vec![0u8; MAX_DATAGRAM];
    let (n, _from) = match tokio::time::timeout(req.read_timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(RepeatError::Read(e)),
        Err(_) => return Err(RepeatError::Timeout),
    };
    let elapsed = started.elapsed();

    let raw = Bytes::copy_from_slice(&buf[..n]);
    let response = parse_response(&raw);
    Ok(RepeatResponse {
        raw,
        response,
        elapsed,
    })
}

/// Write the raw request verbatim, then read the response per `mode`.
async fn exchange<S>(
    stream: &mut S,
    req: &RepeatRequest,
    mode: ReadMode,
) -> Result<Bytes, RepeatError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&req.raw).await.map_err(RepeatError::Write)?;
    stream.flush().await.map_err(RepeatError::Write)?;

    match mode {
        ReadMode::Http => match tokio::time::timeout(req.read_timeout, read_response(stream)).await {
            Ok(res) => res,
            Err(_) => Err(RepeatError::Timeout),
        },
        ReadMode::UntilIdle(idle) => read_until_idle(stream, idle, req.read_timeout).await,
        ReadMode::Exact(len) => read_exactly(stream, len, req.read_timeout).await,
        ReadMode::UntilClose => read_until_close(stream, req.read_timeout).await,
        ReadMode::Datagram => Err(RepeatError::ModeNotSupported {
            mode,
            transport: Transport::Tcp,
        }),
    }
}

/// Read until silence: at least one byte within `read_timeout`, then keep going
/// while bytes keep arriving and stop after `idle` without any.
async fn read_until_idle<S>(
    stream: &mut S,
    idle: Duration,
    read_timeout: Duration,
) -> Result<Bytes, RepeatError>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    let deadline = tokio::time::Instant::now() + read_timeout;

    // The first read waits for the reply to *start*: silence here is a failure.
    match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
        Ok(Ok(0)) => return Ok(Bytes::new()),
        Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        Ok(Err(e)) => return Err(RepeatError::Read(e)),
        Err(_) => return Err(RepeatError::Timeout),
    }

    loop {
        // Whichever comes first: the idle window or the overall deadline.
        let window = idle.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        match tokio::time::timeout(window, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(RepeatError::Read(e)),
            // Idle (or the overall deadline): the reply is as complete as it
            // will get.
            Err(_) => break,
        }
    }
    Ok(Bytes::from(out))
}

/// Read exactly `len` bytes; a peer that closes early yields a shorter reply.
async fn read_exactly<S>(
    stream: &mut S,
    len: usize,
    read_timeout: Duration,
) -> Result<Bytes, RepeatError>
where
    S: AsyncRead + Unpin,
{
    if len > MAX_EXACT_READ {
        return Err(RepeatError::ExactTooLarge {
            len,
            max: MAX_EXACT_READ,
        });
    }
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    let deadline = tokio::time::Instant::now() + read_timeout;

    while filled < len {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => return Err(RepeatError::Read(e)),
            // Nothing at all is a failure; a partial reply is returned as-is.
            Err(_) if filled == 0 => return Err(RepeatError::Timeout),
            Err(_) => break,
        }
    }
    buf.truncate(filled);
    Ok(Bytes::from(buf))
}

/// Read until the peer closes, bounded by `read_timeout`.
async fn read_until_close<S>(stream: &mut S, read_timeout: Duration) -> Result<Bytes, RepeatError>
where
    S: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    let deadline = tokio::time::Instant::now() + read_timeout;

    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(RepeatError::Read(e)),
            Err(_) if out.is_empty() => return Err(RepeatError::Timeout),
            Err(_) => break,
        }
    }
    Ok(Bytes::from(out))
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

    // --- non-HTTP framing + UDP ---------------------------------------------

    /// A server that answers a fixed payload and then keeps the connection
    /// open: the reply is complete only because the mode says so.
    async fn unresponsive_after(
        request: &'static [u8],
        response: &'static [u8],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], request, "the request goes out verbatim");
            sock.write_all(response).await.unwrap();
            sock.flush().await.unwrap();
            // Stay open, so a close cannot be what ends the read.
            tokio::time::sleep(Duration::from_millis(600)).await;
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn until_idle_reads_a_reply_without_http_framing() {
        let (addr, _server) = unresponsive_after(b"PING\r\n", b"+PONG\r\n").await;
        let req = RepeatRequest::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"PING\r\n"))
            .with_read_mode(ReadMode::UntilIdle(Duration::from_millis(80)))
            .with_timeout(Duration::from_secs(2));
        let res = send(req).await.unwrap();
        assert_eq!(&res.raw[..], b"+PONG\r\n");
        assert!(res.response.is_none(), "not an HTTP response");
    }

    #[tokio::test]
    async fn exact_reads_exactly_the_requested_length() {
        let (addr, _server) = unresponsive_after(b"GET 4", b"0123456789").await;
        let req = RepeatRequest::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"GET 4"))
            .with_read_mode(ReadMode::Exact(4))
            .with_timeout(Duration::from_secs(2));
        let res = send(req).await.unwrap();
        assert_eq!(&res.raw[..], b"0123");
    }

    #[tokio::test]
    async fn exact_returns_a_short_reply_when_the_peer_closes_first() {
        let (addr, _server) = one_shot(b"abc".to_vec()).await;
        let req = RepeatRequest::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"x"))
            .with_read_mode(ReadMode::Exact(16))
            .with_timeout(Duration::from_secs(2));
        let res = send(req).await.unwrap();
        assert_eq!(&res.raw[..], b"abc", "a partial reply is data, not an error");
    }

    #[tokio::test]
    async fn until_close_reads_to_eof() {
        let (addr, _server) = one_shot(b"no framing at all".to_vec()).await;
        let req = RepeatRequest::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"x"))
            .with_read_mode(ReadMode::UntilClose)
            .with_timeout(Duration::from_secs(2));
        let res = send(req).await.unwrap();
        assert_eq!(&res.raw[..], b"no framing at all");
    }

    #[tokio::test]
    async fn a_silent_target_times_out_instead_of_succeeding_empty() {
        // Accepts, never answers, never closes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let req = RepeatRequest::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"x"))
            .with_read_mode(ReadMode::UntilIdle(Duration::from_millis(50)))
            .with_timeout(Duration::from_millis(150));
        assert!(matches!(send(req).await, Err(RepeatError::Timeout)));
    }

    #[tokio::test]
    async fn an_exact_read_beyond_the_cap_is_refused() {
        let req = RepeatRequest::new("127.0.0.1", 1, Bytes::from_static(b"x"))
            .with_read_mode(ReadMode::Exact(MAX_EXACT_READ + 1));
        assert!(matches!(
            send(req).await,
            Err(RepeatError::ExactTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn udp_replay_sends_and_receives_one_datagram() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello");
            server.send_to(b"world", from).await.unwrap();
        });

        let req = RepeatRequest::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"hello"))
            .with_transport(Transport::Udp)
            .with_read_mode(ReadMode::Datagram)
            .with_timeout(Duration::from_secs(2));
        let res = send(req).await.unwrap();
        assert_eq!(&res.raw[..], b"world");
        assert!(res.response.is_none());
    }

    #[tokio::test]
    async fn mismatched_mode_and_transport_are_rejected_before_any_io() {
        let datagram_over_tcp = RepeatRequest::new("127.0.0.1", 1, Bytes::from_static(b"x"))
            .with_read_mode(ReadMode::Datagram);
        assert!(matches!(
            send(datagram_over_tcp).await,
            Err(RepeatError::ModeNotSupported { .. })
        ));

        let http_over_udp = RepeatRequest::new("127.0.0.1", 1, Bytes::from_static(b"x"))
            .with_transport(Transport::Udp);
        assert!(matches!(
            send(http_over_udp).await,
            Err(RepeatError::ModeNotSupported { .. })
        ));

        let tls_over_udp = RepeatRequest::new("127.0.0.1", 1, Bytes::from_static(b"x"))
            .with_transport(Transport::Udp)
            .with_read_mode(ReadMode::Datagram)
            .with_tls(true);
        assert!(matches!(send(tls_over_udp).await, Err(RepeatError::TlsOverUdp)));
    }

    /// The HTTP default must stay exactly as it was: a struct literal built the
    /// old way (no read mode, no transport) still frames by Content-Length.
    #[tokio::test]
    async fn the_defaults_are_still_http_over_tcp() {
        let req = RepeatRequest::new("127.0.0.1", 1, Bytes::from_static(b"x"));
        assert_eq!(req.transport, Transport::Tcp);
        assert_eq!(req.read_mode, ReadMode::Http);
        let (addr, _server) = one_shot(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec()).await;
        let res = send(RepeatRequest::new(
            addr.ip().to_string(),
            addr.port(),
            b"GET / HTTP/1.1\r\nHost: t\r\n\r\n".to_vec(),
        ))
        .await
        .unwrap();
        assert_eq!(res.response.unwrap().status, 200);
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
