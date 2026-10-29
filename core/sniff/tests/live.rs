//! Live capture test on loopback.
//!
//! This is the only test that opens a real BPF device and generates real
//! traffic. It is `#[ignore]` because it needs capture privileges (ChmodBPF or
//! an elevated process) and a loopback interface; normal `cargo test` stays
//! hermetic. Run it explicitly:
//!
//! ```text
//! cargo test -p elliot-sniff --test live -- --ignored --nocapture
//! ```
//!
//! Without BPF permission (or when every BPF device is busy) the test skips
//! with a notice instead of failing: the environment cannot exercise the path,
//! and the parser unit tests remain the hermetic coverage. When it does run, it
//! validates the DLT_NULL framing of `lo0` on macOS and that a capture can be
//! stopped and immediately resumed on a fresh port.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use elliot_httpraw::{AllowAll, ScopeDecider, Transport};
use elliot_sniff::{
    list_interfaces, start, FlowMeta, PacketMeta, SniffConfig, SniffEvent, DEFAULT_SNAPLEN,
};
use tokio::sync::mpsc;

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_REQUEST: &[u8] = b"GET /live HTTP/1.1\r\nHost: live\r\n\r\n";

/// `lo0` on macOS, the loopback interface on other platforms. The live test
/// does not care about the name beyond preferring what the UI preselects.
fn loopback_interface() -> Option<String> {
    let interfaces = list_interfaces().expect("listing capture interfaces");
    interfaces
        .iter()
        .find(|iface| iface.name == "lo0")
        .or_else(|| interfaces.iter().find(|iface| iface.loopback))
        .map(|iface| iface.name.clone())
}

fn config(interface: &str, port: u16) -> SniffConfig {
    SniffConfig {
        interface: interface.to_string(),
        // Narrow the capture to the probe connection: this also keeps the
        // test independent of whatever else the machine is doing.
        bpf_filter: Some(format!("tcp port {port}")),
        snaplen: DEFAULT_SNAPLEN,
        // Promiscuous mode is meaningless on loopback and some BSD/macOS
        // devices refuse to activate with it; the port filter is enough.
        promisc: false,
    }
}

/// Why the live test cannot run here. Only environmental refusals are skipped;
/// a bad interface or a malformed filter still fails the test.
fn unavailable_reason(error: &anyhow::Error) -> Option<&'static str> {
    let message = format!("{error:#}").to_lowercase();
    if message.contains("permission")
        || message.contains("not permitted")
        || message.contains("root privileges")
        || message.contains("access denied")
    {
        Some("BPF permission denied")
    } else if message.contains("busy") {
        Some("every BPF device is busy")
    } else {
        None
    }
}

/// One TCP connection to `port`, with a little payload in both directions so
/// the capture sees more than a bare handshake. The listener must already be
/// bound; it is consumed here.
fn hit_port(listener: TcpListener, port: u16) {
    let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connecting to the probe");
    client.set_nodelay(true).ok();
    let (mut server, _) = listener.accept().expect("accepting the probe");
    client
        .write_all(PROBE_REQUEST)
        .expect("writing the probe request");
    let mut buf = [0u8; PROBE_REQUEST.len()];
    server
        .read_exact(&mut buf)
        .expect("reading the probe request");
    assert_eq!(buf.as_slice(), PROBE_REQUEST);
    server
        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .expect("writing the probe response");
}

/// Wait for the first packet of the probe flow, keeping the flow event that
/// preceded it. Any capture-level error fails the test with its message.
async fn expect_tcp_flow(
    mut events: mpsc::Receiver<SniffEvent>,
    port: u16,
) -> (FlowMeta, PacketMeta) {
    let deadline = Instant::now() + EVENT_TIMEOUT;
    let mut flow: Option<FlowMeta> = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("the capture channel closed before the probe packet"),
            Err(_) => panic!("no probe packet on tcp/{port} within {EVENT_TIMEOUT:?}"),
        };
        match event {
            SniffEvent::FlowStarted(meta) | SniffEvent::FlowUpdated(meta)
                if meta.client_addr.port() == port || meta.server_addr.port() == port =>
            {
                flow = Some(meta);
            }
            SniffEvent::Packet(packet)
                if packet.src_addr.port() == port || packet.dst_addr.port() == port =>
            {
                let flow = flow.expect("a packet must be preceded by its flow event");
                return (flow, packet);
            }
            SniffEvent::Error(error) => panic!("capture error during the live probe: {error}"),
            _ => {}
        }
    }
}

/// Print the picker's view of this machine's adapters. Listing needs no BPF
/// privilege; on a Mac with Wi-Fi the adapter must come out named and flagged.
#[test]
#[ignore = "depends on the host's adapters; run with --ignored --nocapture"]
fn interfaces_are_named_like_the_os_names_them() {
    let interfaces = list_interfaces().expect("listing capture interfaces");
    for iface in &interfaces {
        eprintln!(
            "{:<10} {:<28} up={:<5} wireless={:<5} connected={:<5} {:?}",
            iface.name,
            iface.friendly_name.as_deref().unwrap_or("-"),
            iface.up,
            iface.wireless,
            iface.connected,
            iface.addresses,
        );
    }
    // awdl0 (AirDrop) is wireless too, so check from the name side: whatever
    // the OS calls "Wi-Fi" must be flagged as an 802.11 adapter.
    if let Some(wifi) = interfaces
        .iter()
        .find(|i| i.friendly_name.as_deref() == Some("Wi-Fi"))
    {
        assert!(wifi.wireless, "the Wi-Fi port must be wireless: {wifi:?}");
    }
}

/// Start on loopback, capture a real TCP connection, stop, then start again
/// immediately on a new port and capture a second connection. The second start
/// exercises the same path as pressing Start right after Stop (or after a
/// capture error cleaned up its handle): the old BPF descriptor must be gone
/// and the new device must open without waiting.
#[tokio::test]
#[ignore = "requires BPF permissions and loopback traffic; run with --ignored"]
async fn loopback_capture_stops_and_resumes() {
    let Some(interface) = loopback_interface() else {
        eprintln!("skip live sniff test: no loopback interface");
        return;
    };

    let scope: Arc<dyn ScopeDecider> = Arc::new(AllowAll);

    // First capture.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binding the first probe");
    let port = listener
        .local_addr()
        .expect("first listener address")
        .port();
    let (tx, rx) = mpsc::channel(1024);
    let handle = match start(config(&interface, port), scope.clone(), tx).await {
        Ok(handle) => handle,
        Err(error) => match unavailable_reason(&error) {
            Some(reason) => {
                eprintln!("skip live sniff test on {interface}: {reason}: {error:#}");
                return;
            }
            None => panic!("starting the live capture on {interface}: {error:#}"),
        },
    };
    assert!(handle.is_running(), "the first capture must report running");

    hit_port(listener, port);
    let (first_flow, first_packet) = expect_tcp_flow(rx, port).await;
    assert_eq!(first_flow.id, first_packet.flow_id);
    assert_eq!(first_flow.transport, Transport::Tcp);
    assert!(
        first_packet.src_addr.ip().is_loopback() && first_packet.dst_addr.ip().is_loopback(),
        "the probe packet must stay on loopback: {first_packet:?}"
    );

    handle.stop().await;

    // Second capture, started with no pause. A new port makes the two sessions
    // distinguishable and proves the new filter was compiled, not inherited.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binding the second probe");
    let port = listener
        .local_addr()
        .expect("second listener address")
        .port();
    let (tx, rx) = mpsc::channel(1024);
    let handle = start(config(&interface, port), scope, tx)
        .await
        .unwrap_or_else(|error| panic!("resuming the live capture on {interface}: {error:#}"));
    assert!(
        handle.is_running(),
        "the resumed capture must report running"
    );

    hit_port(listener, port);
    let (second_flow, second_packet) = expect_tcp_flow(rx, port).await;
    assert_eq!(second_flow.id, second_packet.flow_id);
    assert_eq!(second_flow.transport, Transport::Tcp);
    assert_ne!(
        first_flow.id, second_flow.id,
        "a resumed capture must start a new flow table"
    );

    handle.stop().await;
}
