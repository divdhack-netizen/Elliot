//! Shared helpers for the `elliot-socks` integration tests: a minimal SOCKS5
//! client, small loopback servers, and event-collection utilities.
//!
//! The client here is hand-written on purpose: it exercises the listener the
//! way `curl --socks5-hostname` or `proxychains` would, without adding a client
//! dependency to the crate.

#![allow(dead_code)] // Every test binary compiles this shared module.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use elliot_scope::ScopePolicy;
use elliot_socks::protocol::{self, Target};
use elliot_socks::{SocksConfig, SocksHandle, StreamEvent};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Generous enough that a correct implementation never hits it, short enough
/// that a broken one fails the test instead of hanging the suite.
const WAIT: Duration = Duration::from_secs(5);

/// Start a listener on an ephemeral loopback port with the given policy.
pub async fn start_listener(
    ca_dir: &Path,
    mitm_tls: bool,
    policy: ScopePolicy,
) -> (SocksHandle, mpsc::Receiver<StreamEvent>) {
    start_listener_with(ca_dir, mitm_tls, policy, None).await
}

/// As [`start_listener`], with optional RFC 1929 credentials.
pub async fn start_listener_with(
    ca_dir: &Path,
    mitm_tls: bool,
    policy: ScopePolicy,
    credentials: Option<(String, String)>,
) -> (SocksHandle, mpsc::Receiver<StreamEvent>) {
    let config = SocksConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        mitm_tls,
        // The test origins are self-signed; the listener's *client* side is not
        // what these tests are about.
        verify_upstream: false,
        ca_dir: ca_dir.to_path_buf(),
        credentials,
    };
    let (tx, rx) = mpsc::channel(256);
    let handle = elliot_socks::start(config, Arc::new(policy), tx)
        .await
        .expect("listener should start");
    (handle, rx)
}

// --- a minimal SOCKS5 client -------------------------------------------------

pub async fn handshake(sock: &mut TcpStream) {
    sock.write_all(&[protocol::VERSION, 1, protocol::METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut reply = [0u8; 2];
    sock.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply,
        [protocol::VERSION, protocol::METHOD_NO_AUTH],
        "the listener must select no-auth when no credentials are configured"
    );
}

/// Send a request and read the reply code (0 = succeeded).
pub async fn request(sock: &mut TcpStream, command: u8, target: &Target) -> u8 {
    let mut msg = vec![protocol::VERSION, command, 0x00];
    msg.extend_from_slice(&protocol::encode_address(target));
    sock.write_all(&msg).await.unwrap();
    sock.flush().await.unwrap();
    read_reply(sock).await.0
}

/// Read a reply, consuming the bounded address it carries.
pub async fn read_reply(sock: &mut TcpStream) -> (u8, Target) {
    let mut buf = Vec::with_capacity(24);
    let mut chunk = [0u8; 64];
    loop {
        while buf.len() < 4 {
            let n = sock.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the listener closed before replying");
            buf.extend_from_slice(&chunk[..n]);
        }
        match protocol::parse_address(&buf[3..]) {
            Ok((target, _)) => return (buf[1], target),
            Err(protocol::ParseError::Incomplete) => {
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0, "the listener closed mid-reply");
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => panic!("malformed reply: {e:?}"),
        }
    }
}

/// Open a CONNECT tunnel. Returns the tunnel and the reply code.
pub async fn connect_through(socks: SocketAddr, target: &Target) -> (TcpStream, u8) {
    let mut sock = TcpStream::connect(socks).await.unwrap();
    handshake(&mut sock).await;
    let rep = request(&mut sock, protocol::CMD_CONNECT, target).await;
    (sock, rep)
}

/// Open a UDP association. Returns the control connection and the relay
/// address, and binds a local socket to talk to the relay from.
pub async fn udp_associate(socks: SocketAddr) -> (TcpStream, SocketAddr, UdpSocket) {
    let mut sock = TcpStream::connect(socks).await.unwrap();
    handshake(&mut sock).await;
    // 0.0.0.0:0 is what a client normally asks for: the real address is learned
    // from the traffic.
    let unspecified = Target::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let mut msg = vec![protocol::VERSION, protocol::CMD_UDP_ASSOCIATE, 0x00];
    msg.extend_from_slice(&protocol::encode_address(&unspecified));
    sock.write_all(&msg).await.unwrap();
    sock.flush().await.unwrap();
    let (rep, addr) = read_reply(&mut sock).await;
    assert_eq!(rep, protocol::REP_SUCCEEDED, "UDP ASSOCIATE should succeed");
    let relay = match addr {
        Target::Ip(ip, port) => SocketAddr::new(ip, port),
        Target::Domain(host, port) => format!("{host}:{port}").parse().unwrap(),
    };
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (sock, relay, local)
}

// --- loopback servers -------------------------------------------------------

/// A TCP echo server: echoes each block back, until the client half-closes.
pub async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = sock.flush().await;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// A UDP echo server.
pub async fn udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                break;
            };
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// A TLS echo server with a self-signed certificate for `localhost` — the
/// "non-HTTP protocol over TLS" case the MITM path exists for.
pub async fn tls_echo() -> SocketAddr {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
    );
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tls.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = tls.flush().await;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// A TLS client that trusts **only** the CA in `ca_dir`, proving the listener's
/// minted leaf actually chains to the shared local CA.
pub fn client_trusting_ca(ca_dir: &Path) -> TlsConnector {
    let ca = elliot_tls::Ca::load_or_create(ca_dir).expect("load the test CA");
    let der = CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// A TLS client that accepts any certificate (used where the listener is not
/// supposed to terminate TLS at all).
pub fn client_accepting_anything() -> TlsConnector {
    TlsConnector::from(Arc::new(
        elliot_tls::insecure_client_config().expect("build the permissive config"),
    ))
}

pub fn server_name(host: &str) -> ServerName<'static> {
    ServerName::try_from(host.to_string()).unwrap()
}

// --- events -----------------------------------------------------------------

pub async fn next_event(rx: &mut mpsc::Receiver<StreamEvent>) -> StreamEvent {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("timed out waiting for a capture event")
        .expect("the event channel closed unexpectedly")
}

/// Assert nothing arrives within a short window (used for out-of-scope traffic).
pub async fn expect_no_events(rx: &mut mpsc::Receiver<StreamEvent>) {
    match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        Err(_) => {}
        Ok(Some(ev)) => panic!("expected no events, got {ev:?}"),
        Ok(None) => panic!("the event channel closed unexpectedly"),
    }
}
