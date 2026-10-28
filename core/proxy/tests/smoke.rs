//! Phase A smoke tests: the proxy binds on loopback and refuses non-loopback.

use std::net::SocketAddr;
use std::sync::Arc;

use elliot_proxy::{start, AllowAll, DenyAll, ProxyConfig};

fn config(dir: &tempfile::TempDir, port: u16) -> ProxyConfig {
    ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        ca_dir: dir.path().to_path_buf(),
        ca_key_store: elliot_proxy::KeyStore::EncryptedFile,
        verify_upstream: true,
    }
}

#[tokio::test]
async fn binds_on_loopback_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let handle = start(config(&dir, 0), Arc::new(DenyAll), tx)
        .await
        .expect("proxy should start on loopback");
    // CA PEM is available for the guided install.
    assert!(handle.ca_pem().contains("BEGIN CERTIFICATE"));
    handle.stop().await;
}

/// The intercept switch can be read back, so a reloaded UI can reconcile its
/// own view with the running proxy instead of guessing.
#[tokio::test]
async fn intercept_switch_is_readable() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let handle = start(config(&dir, 0), Arc::new(AllowAll), tx)
        .await
        .expect("proxy should start on loopback");
    assert!(!handle.intercept(), "intercept starts off");
    handle.set_intercept(true);
    assert!(handle.intercept(), "reads back on after being turned on");
    handle.set_intercept(false);
    assert!(!handle.intercept(), "reads back off again");
    handle.stop().await;
}

/// Live MITM check against a real HTTPS host. Needs outbound network and the
/// `curl` binary, so it is ignored by default:
/// `cargo test -p elliot-proxy -- --ignored live_https_capture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn live_https_capture() {
    use elliot_proxy::ProxyEvent;

    let dir = tempfile::tempdir().unwrap();
    let port = 18_080;
    let mut cfg = config(&dir, port);
    cfg.listen_addr = SocketAddr::from(([127, 0, 0, 1], port));

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let handle = start(cfg, Arc::new(AllowAll), tx).await.unwrap();

    let ca_path = dir.path().join("exported-ca.pem");
    std::fs::write(&ca_path, handle.ca_pem()).unwrap();

    let status = std::process::Command::new("curl")
        .args([
            "--max-time",
            "15",
            "-x",
            &format!("http://127.0.0.1:{port}"),
            "https://example.com",
            "--cacert",
        ])
        .arg(&ca_path)
        .args(["-s", "-o", "/dev/null"])
        .status()
        .expect("curl should run");
    assert!(status.success(), "curl through the proxy should succeed");

    // Expect a completed flow for example.com within a short window.
    let got = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(ev) = rx.recv().await {
            if let ProxyEvent::FlowCompleted(flow) = ev {
                if flow.host == "example.com" && flow.response.is_some() {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(got, "a completed flow for example.com should be captured");

    handle.stop().await;
}

#[tokio::test]
async fn refuses_non_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let mut cfg = config(&dir, 0);
    cfg.listen_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let err = start(cfg, Arc::new(DenyAll), tx).await.err();
    assert!(err.is_some(), "non-loopback bind must be refused");
}
