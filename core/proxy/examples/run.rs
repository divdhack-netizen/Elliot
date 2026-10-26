//! Manual runner: starts the proxy on 127.0.0.1:18081, writes the CA to the
//! given dir, and prints events. Ctrl-C to stop.
//!
//! `cargo run -p elliot-proxy --example run -- /tmp/elliot-ca`

use std::net::SocketAddr;
use std::sync::Arc;

use elliot_proxy::{start, AllowAll, ProxyConfig, ProxyEvent};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/elliot-ca".into());
    let cfg = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 18081)),
        ca_dir: dir.clone().into(),
        verify_upstream: true,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let handle = start(cfg, Arc::new(AllowAll), tx).await?;
    std::fs::write(format!("{dir}/exported-ca.pem"), handle.ca_pem())?;
    println!("proxy on 127.0.0.1:18081, CA at {dir}/exported-ca.pem");
    while let Some(ev) = rx.recv().await {
        match ev {
            ProxyEvent::FlowStarted(f) => println!("START {} {} {}", f.scheme.as_str(), f.host, f.request.target),
            ProxyEvent::FlowCompleted(f) => println!(
                "DONE  {} {} -> {}",
                f.host,
                f.request.target,
                f.response.map(|r| r.status).unwrap_or(0)
            ),
            ProxyEvent::FlowUpdated(f) => println!("PAUSE {} {}", f.host, f.request.target),
            ProxyEvent::WebSocket(m) => println!(
                "WS    {:?} {:?} {}:{} ({} bytes)",
                m.direction,
                m.kind,
                m.host,
                m.port,
                m.payload.len()
            ),
            ProxyEvent::Error(e) => println!("ERR   {e}"),
        }
    }
    Ok(())
}
