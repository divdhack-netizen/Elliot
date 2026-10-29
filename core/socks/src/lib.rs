//! elliot-socks — a loopback SOCKS5 listener that captures non-HTTP traffic.
//!
//! Where [`elliot-proxy`](https://docs.rs/elliot-proxy) speaks HTTP, this crate
//! carries *anything*: it implements CONNECT (TCP) and UDP ASSOCIATE (UDP) from
//! RFC 1928 so a client can be pointed at Elliot with `--socks5-hostname`,
//! `proxychains`, or the OS proxy settings, and the raw bytes become
//! [`Stream`]/[`Message`] values the repeater, the intruder and the store can
//! work with.
//!
//! Design points that matter:
//!
//! - **Loopback only.** [`start`] refuses a non-loopback bind, and the UDP relay
//!   socket is bound to `127.0.0.1` explicitly. Never an open proxy.
//! - **Scope decides capture, not reachability.** Out-of-scope (and explicitly
//!   excluded) targets are relayed transparently: no event, no decryption, no
//!   persistence. Only [`ScopeDecision::InScope`] traffic is captured.
//! - **TLS is terminated only in scope and only on request.** With `mitm_tls`,
//!   a connection whose first bytes are a TLS ClientHello is terminated with a
//!   per-host leaf minted from the shared local CA, and the *plaintext* is what
//!   gets captured; any other first byte is relayed opaquely.
//! - **UDP is connectionless.** An association maps to one stream whose
//!   host/port are those of the first in-scope datagram, and each datagram is
//!   scope-checked on its own.
//!
//! No `unsafe`, no auth bypass, and the CA private key never leaves
//! `elliot-tls`.

pub mod protocol;
mod relay;

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use elliot_httpraw::{Direction, FlowState, ScopeDecider, ScopeDecision, Stream, Transport};
pub use elliot_tls::KeyStore;
use elliot_tls::Ca;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use protocol::ParseError;

/// How long to wait for the client's first bytes before giving up on TLS
/// detection and relaying opaquely.
///
/// Only paid when `mitm_tls` is on, and only by protocols where the *server*
/// speaks first (SMTP, MySQL, …): a client that starts with a ClientHello is
/// detected immediately.
const TLS_SNIFF_WINDOW: Duration = Duration::from_millis(300);

/// Largest SOCKS request we accept (domain name + headers), a bound on the
/// incremental reader so a hostile peer cannot make us buffer forever.
const MAX_REQUEST: usize = 512;

/// How long [`SocksHandle::stop`] waits for in-flight relays to wind down and
/// report their streams before aborting them. Relays observe the stop signal
/// and finish promptly, so this only bounds a peer stalled mid-write.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Configuration for a capture listener.
#[derive(Clone, Debug)]
pub struct SocksConfig {
    /// Address to listen on. Must be loopback; [`start`] rejects anything else.
    pub listen_addr: SocketAddr,
    /// Terminate TLS for in-scope connections whose client starts with a TLS
    /// ClientHello, so the captured bytes are the application plaintext.
    pub mitm_tls: bool,
    /// Verify upstream certificates on the MITM path. Default `true`.
    pub verify_upstream: bool,
    /// Directory holding the root CA (`ca.crt` + the key store). Shared with the
    /// HTTP proxy: one certificate to install, both listeners.
    pub ca_dir: PathBuf,
    /// Where the CA private key lives. Must match the HTTP proxy's setting, so
    /// both listeners load the *same* key ([`KeyStore::Keychain`] for the
    /// desktop app, [`KeyStore::EncryptedFile`] otherwise).
    pub ca_key_store: KeyStore,
    /// Require RFC 1929 user/password auth. `None` (the default) accepts
    /// no-auth, which is safe only because the listener is loopback-bound.
    pub credentials: Option<(String, String)>,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 1080)),
            mitm_tls: false,
            verify_upstream: true,
            ca_dir: PathBuf::from("."),
            ca_key_store: KeyStore::default(),
            credentials: None,
        }
    }
}

/// Events streamed from the listener to the core.
#[derive(Clone, Debug)]
pub enum StreamEvent {
    /// A new in-scope stream has started (TLS already classified).
    StreamStarted(Stream),
    /// A chunk (TCP) or datagram (UDP) observed on a stream.
    Message(elliot_httpraw::Message),
    /// A stream finished (closed cleanly or errored).
    StreamCompleted(Stream),
    /// A listener-level error not attached to a stream (bad handshake, …).
    Error(String),
}

/// Handle to a running listener. Dropping it does not stop the listener; call
/// [`SocksHandle::stop`].
pub struct SocksHandle {
    local_addr: SocketAddr,
    stopping: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl SocksHandle {
    /// The address actually bound (useful when the config asked for port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the listener: stop accepting, let in-flight relays finish and close
    /// (they see the stop signal and complete their streams).
    pub async fn stop(self) {
        let _ = self.stopping.send(true);
        let _ = self.join.await;
    }
}

/// Start the listener. Binds (and loads the CA, when `mitm_tls` is set) before
/// returning, so a bind or CA failure surfaces here rather than in the
/// background.
///
/// # Errors
/// Returns an error if `listen_addr` is not loopback, if the CA cannot be
/// prepared, or if the listener fails to bind.
pub async fn start(
    config: SocksConfig,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<StreamEvent>,
) -> Result<SocksHandle> {
    if !config.listen_addr.ip().is_loopback() {
        bail!(
            "refusing to bind non-loopback address {} (open-proxy guard)",
            config.listen_addr
        );
    }

    let ca = if config.mitm_tls {
        Some(Arc::new(
            Ca::load_or_create_with(&config.ca_dir, config.ca_key_store)
                .context("preparing root CA")?,
        ))
    } else {
        None
    };

    // Bind synchronously: `start` returning means the listener is accepting,
    // and bind errors (port in use) surface here.
    let std_listener = std::net::TcpListener::bind(config.listen_addr)
        .with_context(|| format!("binding {}", config.listen_addr))?;
    std_listener
        .set_nonblocking(true)
        .context("setting listener non-blocking")?;
    let listener =
        TcpListener::from_std(std_listener).context("adopting listener into tokio")?;
    let local_addr = listener.local_addr().context("reading the bound address")?;

    let config = Arc::new(config);
    let (stopping, mut stop_rx) = watch::channel(false);

    let join = tokio::spawn(async move {
        let mut connections: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok((client, peer)) => {
                        let config = config.clone();
                        let ca = ca.clone();
                        let scope = scope.clone();
                        let events = events.clone();
                        // Cloned before any stop signal can be observed, so the
                        // connection sees the stop like the accept loop does.
                        let stop = stop_rx.clone();
                        connections.spawn(async move {
                            serve(client, peer, config, ca, scope, events, stop).await;
                        });
                    }
                    Err(e) => tracing::warn!("socks accept failed: {e}"),
                },
                Some(_) = connections.join_next() => {}
            }
        }

        // Let in-flight relays observe the stop signal and complete their
        // streams, so stopping the listener never leaves a stream pending. The
        // grace period keeps a stalled peer from blocking `stop` forever;
        // whatever is left after it is aborted.
        let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        while let Ok(Some(_)) = tokio::time::timeout_at(deadline, connections.join_next()).await {}
        connections.shutdown().await;
    });

    Ok(SocksHandle {
        local_addr,
        stopping,
        join,
    })
}

/// One client connection, end to end.
async fn serve(
    client: TcpStream,
    peer: SocketAddr,
    config: Arc<SocksConfig>,
    ca: Option<Arc<Ca>>,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<StreamEvent>,
    stop: watch::Receiver<bool>,
) {
    let _ = client.set_nodelay(true);
    let mut client = client;

    if let Err(e) = negotiate(&mut client, &config).await {
        relay::send(
            &events,
            StreamEvent::Error(format!("SOCKS handshake from {peer}: {e}")),
        )
        .await;
        return;
    }

    let (command, target) = match read_request(&mut client).await {
        Ok(v) => v,
        Err(e) => {
            relay::send(
                &events,
                StreamEvent::Error(format!("SOCKS request from {peer}: {e}")),
            )
            .await;
            return;
        }
    };

    match command {
        protocol::Command::Connect => {
            connect(client, peer, &target, config, ca, scope, events, stop).await
        }
        protocol::Command::UdpAssociate => {
            associate(client, peer, target, scope, events, stop).await
        }
        protocol::Command::Bind | protocol::Command::Unsupported(_) => {
            // BIND is not implemented (it would require listening for an
            // inbound connection back to the client) and neither is any
            // unknown command: answer, then close.
            let _ = client
                .write_all(&protocol::error_reply(protocol::REP_COMMAND_UNSUPPORTED))
                .await;
        }
    }
}

// --- handshake ---------------------------------------------------------------

/// Method negotiation (RFC 1928) plus user/password auth when configured.
async fn negotiate(sock: &mut TcpStream, config: &SocksConfig) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != protocol::VERSION {
        return Err(invalid("unsupported SOCKS version"));
    }
    if head[1] == 0 {
        return Err(invalid("no authentication methods offered"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await?;

    match protocol::select_method(&methods, config.credentials.is_some()) {
        Some(method) => sock.write_all(&protocol::method_reply(method)).await?,
        None => {
            sock.write_all(&protocol::method_reply(protocol::METHOD_NONE_ACCEPTABLE))
                .await?;
            return Err(invalid("no acceptable authentication method"));
        }
    }

    if config.credentials.is_some() {
        authenticate(sock, config).await?;
    }
    Ok(())
}

/// RFC 1929 sub-negotiation. A mismatch is answered with the failure status
/// before the error, so the client sees "auth failed" rather than a bare close.
async fn authenticate(sock: &mut TcpStream, config: &SocksConfig) -> std::io::Result<()> {
    let Some((expected_user, expected_pass)) = &config.credentials else {
        return Ok(());
    };

    let mut buf = Vec::with_capacity(16);
    let mut chunk = [0u8; 64];
    let (user, pass) = loop {
        match protocol::parse_auth(&buf) {
            Ok((user, pass, _)) => break (user, pass),
            Err(ParseError::Incomplete) => {
                if buf.len() > MAX_REQUEST {
                    return Err(invalid("oversized authentication message"));
                }
                let n = sock.read(&mut chunk).await?;
                if n == 0 {
                    return Err(invalid("client closed during authentication"));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(ParseError::Malformed(why)) => return Err(invalid(why)),
            Err(ParseError::Fragmented) => return Err(invalid("unexpected fragment")),
        }
    };

    if secret_eq(&user, expected_user) && secret_eq(&pass, expected_pass) {
        sock.write_all(&protocol::auth_reply(0x00)).await?;
        Ok(())
    } else {
        sock.write_all(&protocol::auth_reply(0x01)).await?;
        Err(invalid("invalid credentials"))
    }
}

/// Length-checked, non-short-circuiting comparison, so a wrong credential does
/// not leak its correct prefix through timing.
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Read a request incrementally, so a client that trickles bytes (or a domain
/// name longer than one segment) still parses.
async fn read_request(sock: &mut TcpStream) -> std::io::Result<(protocol::Command, protocol::Target)> {
    let mut buf = Vec::with_capacity(32);
    let mut chunk = [0u8; 64];
    loop {
        match protocol::parse_request(&buf) {
            Ok((command, target, _)) => return Ok((command, target)),
            Err(ParseError::Incomplete) => {
                if buf.len() > MAX_REQUEST {
                    return Err(invalid("oversized SOCKS request"));
                }
                let n = sock.read(&mut chunk).await?;
                if n == 0 {
                    return Err(invalid("client closed before sending a request"));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(ParseError::Malformed(why)) => return Err(invalid(why)),
            Err(ParseError::Fragmented) => return Err(invalid("unexpected fragment")),
        }
    }
}

fn invalid(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what)
}

// --- CONNECT -----------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn connect(
    mut client: TcpStream,
    peer: SocketAddr,
    target: &protocol::Target,
    config: Arc<SocksConfig>,
    ca: Option<Arc<Ca>>,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<StreamEvent>,
    mut stop: watch::Receiver<bool>,
) {
    let host = target.host();
    let port = target.port();
    let decision = scope.decide(Transport::Tcp.scheme(), &host, port, "");
    let capture = decision == ScopeDecision::InScope;

    // Connect before replying: a failure has to become a SOCKS error reply, not
    // a silent close.
    let upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("CONNECT {host}:{port} failed: {e}");
            let _ = client
                .write_all(&protocol::error_reply(protocol::reply_code_for(&e)))
                .await;
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    let bound = upstream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    if client.write_all(&protocol::success_reply(bound)).await.is_err() {
        return;
    }

    if !capture {
        // Out of scope or explicitly excluded: relay, accumulate nothing.
        relay::both_ways(&mut client, upstream, None, &mut stop).await;
        return;
    }

    // Only now decide whether to terminate TLS: the sniff needs the client's
    // first bytes, which a client sends only after the success reply.
    let mitm_tls = config.mitm_tls
        && ca.is_some()
        && looks_like_tls(&client, TLS_SNIFF_WINDOW).await;

    let mut stream = Stream {
        id: Uuid::new_v4(),
        started_at: SystemTime::now(),
        completed_at: None,
        client_addr: peer,
        transport: Transport::Tcp,
        host,
        port,
        tls: mitm_tls,
        scope: decision,
        state: FlowState::Pending,
        error: None,
    };
    let capture = relay::Capture::new(stream.id, events.clone());
    capture.started(&stream).await;

    let error = if mitm_tls {
        let ca = ca.as_ref().expect("mitm_tls checked above");
        mitm_tls_relay(
            &mut client,
            upstream,
            &stream.host,
            &config,
            ca,
            &capture,
            &mut stop,
        )
        .await
    } else {
        relay::both_ways(&mut client, upstream, Some(&capture), &mut stop).await
    };

    relay::finish(&mut stream, error);
    capture.completed(&stream).await;
}

/// Does the connection start with a TLS ClientHello?
///
/// `peek` is used so nothing is consumed: the same bytes are then handed to the
/// TLS acceptor (or relayed opaquely). Fewer than three bytes are not enough to
/// tell, so we wait — bounded by `window` — rather than misclassifying.
async fn looks_like_tls(sock: &TcpStream, window: Duration) -> bool {
    const RECORD_HANDSHAKE: u8 = 0x16;
    const RECORD_MAJOR: u8 = 0x03;

    let deadline = Instant::now() + window;
    let mut buf = [0u8; 5];
    loop {
        match sock.peek(&mut buf).await {
            Ok(0) => return false, // peer closed: nothing to terminate
            Ok(n) if n >= 3 => {
                return buf[0] == RECORD_HANDSHAKE
                    && buf[1] == RECORD_MAJOR
                    && matches!(buf[2], 0x00..=0x04);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("peek for TLS detection failed ({e}); relaying opaquely");
                return false;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Terminate TLS on both sides and capture the plaintext in between.
async fn mitm_tls_relay(
    client: &mut TcpStream,
    upstream: TcpStream,
    host: &str,
    config: &SocksConfig,
    ca: &Ca,
    capture: &relay::Capture,
    stop: &mut watch::Receiver<bool>,
) -> Option<String> {
    let leaf = match ca.leaf_for_host(host) {
        Ok(leaf) => leaf,
        Err(e) => return Some(format!("minting a certificate for {host}: {e}")),
    };
    let server_config = match elliot_tls::server_config_with_leaf(leaf.cert, leaf.key) {
        Ok(c) => c,
        Err(e) => return Some(format!("building the TLS server config: {e}")),
    };
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let client_tls = match acceptor.accept(&mut *client).await {
        Ok(s) => s,
        Err(e) => return Some(format!("client TLS handshake: {e}")),
    };

    let name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return Some(format!("{host:?} is not a valid TLS server name")),
    };
    let connector = match elliot_tls::connector(!config.verify_upstream) {
        Ok(c) => c,
        Err(e) => return Some(format!("building the TLS client config: {e}")),
    };
    let upstream_tls = match connector.connect(name, upstream).await {
        Ok(s) => s,
        Err(e) => return Some(format!("upstream TLS handshake: {e}")),
    };

    relay::both_ways(client_tls, upstream_tls, Some(capture), stop).await
}

// --- UDP ASSOCIATE -----------------------------------------------------------

/// Open a relay for the association and forward datagrams until the control
/// connection (or the listener) goes away.
async fn associate(
    mut client: TcpStream,
    peer: SocketAddr,
    target: protocol::Target,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<StreamEvent>,
    mut stop: watch::Receiver<bool>,
) {
    // The relay socket is bound to loopback explicitly: the association exists
    // for a local client only.
    let relay = match UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("udp relay bind failed: {e}");
            let _ = client
                .write_all(&protocol::error_reply(protocol::REP_GENERAL_FAILURE))
                .await;
            return;
        }
    };
    let bound = relay
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    if client.write_all(&protocol::success_reply(bound)).await.is_err() {
        return;
    }
    tracing::debug!("udp association for {peer}: relay on {bound}, requested {target:?}");

    udp_relay(relay, client, peer, scope, events, &mut stop).await;
}

/// The datagram loop. Both directions are gated: what the client sends is
/// scope-checked per datagram, and only addresses we have already sent to are
/// allowed to answer (an unsolicited datagram from elsewhere is never forwarded
/// to the client and never captured).
async fn udp_relay(
    relay: UdpSocket,
    mut control: TcpStream,
    peer: SocketAddr,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<StreamEvent>,
    stop: &mut watch::Receiver<bool>,
) {
    // One unconnected socket for every destination: `recv_from` then tells us
    // which target answered, which is all the correlation UDP allows.
    let upstream = match UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("udp upstream bind failed: {e}");
            return;
        }
    };

    // Max UDP payload, so nothing is silently truncated.
    let mut from_client = vec![0u8; 65_535];
    let mut from_target = vec![0u8; 65_535];
    let mut control_buf = [0u8; 64];

    let mut client_relay_addr: Option<SocketAddr> = None;
    let mut targets: HashSet<SocketAddr> = HashSet::new();
    let mut stream: Option<Stream> = None;
    let mut capture: Option<relay::Capture> = None;
    let mut error: Option<String> = None;

    loop {
        tokio::select! {
            _ = stop.changed() => break,
            read = control.read(&mut control_buf) => {
                // The association lasts exactly as long as its control
                // connection: EOF (or junk) ends it.
                let _ = read;
                break;
            }
            datagram = relay.recv_from(&mut from_client) => {
                let (n, from) = match datagram {
                    Ok(v) => v,
                    Err(e) => { error = Some(format!("udp relay: {e}")); break; }
                };
                // Latch the first source as the client; another local process
                // cannot join the association later.
                match client_relay_addr {
                    Some(known) if known != from => continue,
                    None => client_relay_addr = Some(from),
                    _ => {}
                }
                let (target, offset) = match protocol::parse_datagram(&from_client[..n]) {
                    Ok(v) => v,
                    // Fragmentation is not implemented [RFC 1928]: drop, never
                    // tear the association down.
                    Err(_) => continue,
                };
                let host = target.host();
                let decision = scope.decide(Transport::Udp.scheme(), &host, target.port(), "");
                if decision != ScopeDecision::InScope {
                    tracing::debug!("udp datagram to {host}:{} dropped: out of scope", target.port());
                    continue;
                }
                let Some(dest) = resolve(&target).await else { continue };

                // The first in-scope datagram names the stream: an association
                // has no target of its own (the requested address is usually
                // 0.0.0.0:0).
                if capture.is_none() {
                    let s = Stream {
                        id: Uuid::new_v4(),
                        started_at: SystemTime::now(),
                        completed_at: None,
                        client_addr: peer,
                        transport: Transport::Udp,
                        host: host.clone(),
                        port: target.port(),
                        tls: false,
                        scope: decision,
                        state: FlowState::Pending,
                        error: None,
                    };
                    let c = relay::Capture::new(s.id, events.clone());
                    c.started(&s).await;
                    stream = Some(s);
                    capture = Some(c);
                }

                targets.insert(dest);
                let payload = &from_client[offset..n];
                if let Err(e) = upstream.send_to(payload, dest).await {
                    tracing::debug!("udp send to {dest} failed: {e}");
                    continue;
                }
                if let Some(c) = capture.as_ref() {
                    c.message(Direction::ClientToServer, payload).await;
                }
            }
            datagram = upstream.recv_from(&mut from_target) => {
                let (n, from) = match datagram {
                    Ok(v) => v,
                    Err(e) => { error = Some(format!("udp upstream: {e}")); break; }
                };
                if !targets.contains(&from) {
                    continue; // unsolicited: never forwarded, never captured
                }
                let (Some(client_addr), Some(c)) = (client_relay_addr, capture.as_ref()) else {
                    continue;
                };
                let target = protocol::Target::Ip(from.ip(), from.port());
                let payload = &from_target[..n];
                let framed = protocol::encode_datagram(&target, payload);
                if relay.send_to(&framed, client_addr).await.is_err() {
                    continue;
                }
                c.message(Direction::ServerToClient, payload).await;
            }
        }
    }

    if let Some(mut s) = stream {
        relay::finish(&mut s, error);
        if let Some(c) = capture {
            c.completed(&s).await;
        }
    }
}

/// Resolve a target to a socket address (a literal is already one).
async fn resolve(target: &protocol::Target) -> Option<SocketAddr> {
    match target {
        protocol::Target::Ip(ip, port) => Some(SocketAddr::new(*ip, *port)),
        protocol::Target::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .ok()?
            .next(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_comparison_is_length_checked() {
        assert!(secret_eq("hunter2", "hunter2"));
        assert!(!secret_eq("hunter2", "hunter3"));
        assert!(!secret_eq("hunter2", "hunter22"));
        assert!(!secret_eq("", "hunter2"));
        assert!(secret_eq("", ""));
        // Not valid UTF-8 on the wire, but the comparison is byte-wise.
        assert!(secret_eq("ünïcode", "ünïcode"));
    }

    #[tokio::test]
    async fn refuses_a_non_loopback_bind() {
        let dir = tempfile::tempdir().unwrap();
        let config = SocksConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            ca_dir: dir.path().to_path_buf(),
            ..SocksConfig::default()
        };
        let (tx, _rx) = mpsc::channel(8);
        let err = start(config, Arc::new(elliot_httpraw::AllowAll), tx)
            .await
            .err()
            .expect("a non-loopback bind must be refused");
        assert!(err.to_string().contains("loopback"), "got {err}");
    }
}
