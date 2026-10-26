//! End-to-end check of the `verify_upstream` switch.
//!
//! A loopback HTTPS server with a self-signed certificate stands in for a
//! broken or self-signed target. The same request through the proxy must fail
//! while upstream verification is on, and succeed only when the caller
//! explicitly turned it off — that is the whole point of the switch, so it is
//! exercised against real TLS rather than asserted on a config value.
//!
//! Everything is loopback: no outbound network, no external binary.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use hudsucker::rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use elliot_proxy::{start, AllowAll, ProxyConfig, ProxyHandle, ScopeDecider};

/// How long any single step of the exchange may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// A loopback address that is free right now. The proxy does not report the
/// port it bound (it is given one), so pick one and hand it over.
fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a free port");
    listener.local_addr().expect("local addr")
}

async fn start_proxy(addr: SocketAddr, verify_upstream: bool, ca_dir: &Path) -> ProxyHandle {
    let (events, _rx) = tokio::sync::mpsc::channel(64);
    let config = ProxyConfig {
        listen_addr: addr,
        ca_dir: ca_dir.to_path_buf(),
        verify_upstream,
    };
    let scope: Arc<dyn ScopeDecider> = Arc::new(AllowAll);
    start(config, scope, events)
        .await
        .expect("the proxy should start on loopback")
}

/// A local HTTPS server whose certificate nobody trusts, answering one request
/// per connection and then closing.
async fn spawn_self_signed_https_server() -> SocketAddr {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("rcgen should issue a self-signed certificate");
    let cert_der = cert.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the aws-lc-rs provider supports the default versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("the generated certificate is usable");
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
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                    )
                    .await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// Read until the end of the header block (`\r\n\r\n`), or EOF.
async fn read_headers<S: AsyncReadExt + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(buf)
}

/// Issue one `https://host:port/` request through the proxy and return the
/// response status code.
///
/// The client deliberately does **not** verify the proxy's own MITM
/// certificate: the question here is how the proxy treats the *upstream*
/// certificate.
async fn status_through_proxy(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> Result<u16, String> {
    let mut tcp = TcpStream::connect(proxy).await.map_err(|e| e.to_string())?;

    // 1. Open the tunnel.
    let connect = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    tcp.write_all(connect.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let head = read_headers(&mut tcp).await.map_err(|e| e.to_string())?;
    if !head.starts_with(b"HTTP/1.1 200") {
        return Err(format!(
            "tunnel refused: {}",
            String::from_utf8_lossy(&head)
        ));
    }

    // 2. TLS to the proxy, which terminates it with a certificate for `host`.
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let connector = elliot_tls::connector(true).map_err(|e| e.to_string())?;
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;

    // 3. The request the proxy forwards upstream.
    let request = format!("GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;

    let head = read_headers(&mut tls).await.map_err(|e| e.to_string())?;
    let status_line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let status_line = String::from_utf8_lossy(status_line);
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("unexpected status line: {status_line:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_self_signed_upstream_is_refused_unless_verification_is_off() {
    let ca_dir = tempfile::tempdir().unwrap();
    let upstream = spawn_self_signed_https_server().await;
    let host = "localhost";
    let port = upstream.port();

    // Verification on (the default): the self-signed upstream must not succeed.
    let addr = free_loopback_addr();
    let proxy = start_proxy(addr, true, ca_dir.path()).await;
    let refused = tokio::time::timeout(STEP_TIMEOUT, status_through_proxy(addr, host, port))
        .await
        .expect("the exchange timed out");
    assert_ne!(
        refused.as_ref().ok(),
        Some(&200),
        "a self-signed upstream must be refused when verification is on, got {refused:?}"
    );
    proxy.stop().await;

    // The explicit opt-out: the same request reaches the origin.
    let addr = free_loopback_addr();
    let proxy = start_proxy(addr, false, ca_dir.path()).await;
    let code = tokio::time::timeout(STEP_TIMEOUT, status_through_proxy(addr, host, port))
        .await
        .expect("the exchange timed out")
        .expect("with verification off the request should complete");
    assert_eq!(
        code, 200,
        "accept-invalid upstream must reach the origin, got {code}"
    );
    proxy.stop().await;
}
