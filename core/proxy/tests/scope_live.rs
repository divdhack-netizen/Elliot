//! End-to-end check that the proxy really enforces the scope policy, and that an
//! edit made while it runs applies to the next request.
//!
//! "Enforced" here means: out-of-scope traffic is still forwarded (it is the
//! user's own traffic, just not Elliot's business) but produces **no flow
//! events** — nothing is captured, stored or shown. That is the property the
//! whole scope feature rests on, so it is asserted against a running proxy
//! rather than on a config value.
//!
//! Everything is loopback: no outbound network, no external binary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use elliot_proxy::{start, ProxyConfig, ProxyEvent};
use elliot_scope::{ScopePolicy, SharedPolicy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A plain-HTTP origin on loopback, answering every request with `200 hi`.
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
                    .await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn free_loopback_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a free port");
    listener.local_addr().expect("local addr")
}

/// One absolute-form request through the proxy; returns the status line.
async fn get_through_proxy(proxy: SocketAddr, target: SocketAddr) -> Result<String, String> {
    let mut sock = TcpStream::connect(proxy).await.map_err(|e| e.to_string())?;
    let request = format!(
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    sock.flush().await.map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    Ok(text.lines().next().unwrap_or_default().to_string())
}

/// Hosts of every flow event seen within `within`, then stop waiting.
async fn captured_hosts(
    rx: &mut tokio::sync::mpsc::Receiver<ProxyEvent>,
    within: Duration,
) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + within;
    let mut hosts = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Ok(Some(
                ProxyEvent::FlowStarted(f) | ProxyEvent::FlowUpdated(f) | ProxyEvent::FlowCompleted(f),
            )) => hosts.push(f.host),
            // WebSocket and proxy-level errors are not what this asserts on.
            Ok(Some(_)) => {}
            // Channel closed, or nothing more arrived in the window.
            Ok(None) | Err(_) => break,
        }
    }
    hosts
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scope_decides_capture_and_edits_apply_immediately() {
    let ca_dir = tempfile::tempdir().unwrap();
    let origin = spawn_origin().await;
    let proxy_addr = free_loopback_addr();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProxyEvent>(64);
    let policy = Arc::new(SharedPolicy::default());
    let handle = start(
        ProxyConfig {
            listen_addr: proxy_addr,
            ca_dir: ca_dir.path().to_path_buf(),
            verify_upstream: true,
        },
        policy.decider(),
        tx,
    )
    .await
    .expect("the proxy should start");

    // 1. Empty policy → Passthrough: forwarded, but nothing captured.
    let status = get_through_proxy(proxy_addr, origin)
        .await
        .expect("the first request should complete");
    assert!(status.contains("200"), "got {status:?}");
    assert!(
        captured_hosts(&mut rx, Duration::from_millis(400)).await.is_empty(),
        "an empty policy must capture nothing"
    );

    // 2. Define the scope. The decider the running proxy already holds must pick
    //    the change up on the next request.
    policy.set(ScopePolicy::host_suffix("127.0.0.1"));
    let status = get_through_proxy(proxy_addr, origin)
        .await
        .expect("the second request should complete");
    assert!(status.contains("200"), "got {status:?}");
    let hosts = captured_hosts(&mut rx, Duration::from_secs(2)).await;
    assert!(
        hosts.iter().any(|h| h == "127.0.0.1"),
        "after the edit the flow must be captured, got {hosts:?}"
    );

    // 3. Clearing the scope stops capturing again — same handle, no restart.
    policy.set(ScopePolicy::new());
    let _ = get_through_proxy(proxy_addr, origin).await;
    assert!(
        captured_hosts(&mut rx, Duration::from_millis(400)).await.is_empty(),
        "clearing the scope must stop capture"
    );

    handle.stop().await;
}
