//! elliot-sniff — passive packet capture for Elliot.
//!
//! Where the HTTP proxy and the SOCKS listener are *active* (the client must be
//! routed to Elliot and trust its CA), this crate is the opposite: it observes
//! a network interface through libpcap, forwards nothing and decrypts nothing.
//! It is the Wireshark-style view for apps that ignore the proxy and for
//! protocols the proxy does not speak.
//!
//! What leaves this crate is metadata only:
//!
//! - [`PacketMeta`]: 5-tuple, TCP flags, wire/payload lengths, direction and an
//!   optional label (TLS SNI, DNS query);
//! - [`FlowMeta`]: packets grouped by 5-tuple, with counters, TLS detection and
//!   a best-effort scope tag once an SNI or DNS name identifies the host.
//!
//! There is no TCP reassembly, no payload retention and no persistence: v1 is
//! live-only and in memory. On TLS flows the content is ciphertext and stays
//! unreadable — that is the nature of passive sniffing, not a limitation to
//! fix here.
//!
//! Scope is a *label*, not a gate: the capture is narrowed by the BPF filter
//! (the honest analogue of Wireshark's capture filter), and when a host becomes
//! known the flow is re-checked with the shared [`ScopeDecider`] so the UI can
//! dim out-of-scope traffic. Nothing is ever persisted.

pub mod parse;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use elliot_httpraw::{Direction, ScopeDecider, ScopeDecision, Transport};
use pcap::Linktype;
use serde::Serialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use parse::ParsedPacket;

/// Default bytes captured per packet: enough for a full frame together with
/// its link-layer header, so labels (ClientHello, DNS query) are not truncated
/// by the snap length.
pub const DEFAULT_SNAPLEN: i32 = 65_535;

/// How long the non-blocking capture loop sleeps when no packet is available.
/// Short enough to feel live, long enough not to spin a core.
const IDLE_POLL: Duration = Duration::from_millis(5);

/// Configuration for a passive capture.
#[derive(Clone, Debug)]
pub struct SniffConfig {
    /// Interface name as reported by [`list_interfaces`] (e.g. `en0`, `lo0`).
    pub interface: String,
    /// Optional BPF capture filter (e.g. `tcp port 8080`). Invalid filters are
    /// rejected by [`start`] before any packet is read.
    pub bpf_filter: Option<String>,
    /// Bytes captured per packet.
    pub snaplen: i32,
    /// Put the interface in promiscuous mode (no effect on loopback).
    pub promisc: bool,
}

impl Default for SniffConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            bpf_filter: None,
            snaplen: DEFAULT_SNAPLEN,
            promisc: true,
        }
    }
}

/// One capture interface, as shown in the picker.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IfaceInfo {
    pub name: String,
    /// Human name of the adapter ("Wi-Fi", "Thunderbolt Bridge"), the way
    /// Wireshark shows it. libpcap has none on macOS, so it comes from the
    /// system's hardware-port list; `None` when unknown.
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
    /// An 802.11 adapter, as reported by libpcap.
    pub wireless: bool,
    /// The interface is up and running.
    pub up: bool,
    /// Associated with a network (Wi-Fi) or with a link (wired).
    pub connected: bool,
}

/// A flow is a 5-tuple, not a TCP connection: no state machine is tracked in
/// v1, only the packets that share the tuple. Counters are cumulative for the
/// lifetime of the capture.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowMeta {
    pub id: Uuid,
    pub started_at: SystemTime,
    pub last_seen_at: SystemTime,
    /// The endpoint that sent the first packet seen for this tuple. If the
    /// capture starts mid-connection this may be the server; the direction is
    /// relative to this choice, consistently for the whole flow.
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub transport: Transport,
    /// Server name from a TLS ClientHello or a DNS query, once observed.
    pub host: Option<String>,
    /// Best-effort scope label, set when `host` becomes known.
    pub scope: Option<ScopeDecision>,
    pub packets: u64,
    pub bytes: u64,
    /// A TLS handshake record was seen on this flow (content stays encrypted).
    pub tls: bool,
}

/// Metadata for one captured packet. The payload itself is never retained.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketMeta {
    pub flow_id: Uuid,
    pub at: SystemTime,
    pub direction: Direction,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    /// Frame length as reported by libpcap.
    pub wire_len: u32,
    /// Bytes after the TCP/UDP header.
    pub payload_len: u32,
    /// Human-readable TCP flags ("SYN, ACK"); `None` for UDP.
    pub tcp_flags: Option<String>,
    /// Short label for the packet list ("SNI example.com", "DNS example.com").
    pub info: Option<String>,
}

/// Events streamed from the capture loop to the UI.
#[derive(Clone, Debug)]
pub enum SniffEvent {
    /// A new 5-tuple was seen.
    FlowStarted(FlowMeta),
    /// Counters or labels changed on an already-known flow.
    FlowUpdated(FlowMeta),
    /// One packet was captured.
    Packet(PacketMeta),
    /// A capture-level error (the loop stops after reporting it).
    Error(String),
}

/// Handle to a running capture. Dropping it does not stop the capture; call
/// [`SniffHandle::stop`].
pub struct SniffHandle {
    stopping: Arc<AtomicBool>,
    /// Set by the capture loop before it reports a terminal error, so a status
    /// query racing with that event cannot claim the capture is still alive.
    ended: Arc<AtomicBool>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl SniffHandle {
    /// Is the capture loop still running?
    ///
    /// A loop that ended on its own (an interface that disappeared, a BPF read
    /// error) leaves a finished handle behind; callers use this to tell that
    /// apart from a live capture instead of waiting for the user to press stop.
    pub fn is_running(&self) -> bool {
        !self.ended.load(Ordering::Relaxed)
            && self.join.as_ref().is_some_and(|join| !join.is_finished())
    }

    /// Stop the capture loop and wait for it to wind down.
    pub async fn stop(mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        self.ended.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

/// List the interfaces libpcap can capture on.
///
/// # Errors
/// Returns an error if libpcap cannot enumerate devices.
pub fn list_interfaces() -> Result<Vec<IfaceInfo>> {
    let devices = pcap::Device::list().context("listing capture interfaces")?;
    let ports = hardware_port_names();
    let mut interfaces: Vec<IfaceInfo> = devices
        .into_iter()
        .map(|device| {
            let loopback = device.flags.is_loopback();
            let friendly_name = ports
                .get(&device.name)
                .cloned()
                .or_else(|| loopback.then(|| "Loopback".to_string()));
            IfaceInfo {
                friendly_name,
                description: device.desc,
                addresses: device
                    .addresses
                    .iter()
                    .map(|address| address.addr.to_string())
                    .collect(),
                loopback,
                wireless: device.flags.is_wireless(),
                up: device.flags.is_up() && device.flags.is_running(),
                connected: matches!(
                    device.flags.connection_status,
                    pcap::ConnectionStatus::Connected
                ),
                name: device.name,
            }
        })
        .collect();
    // Like Wireshark's welcome list: what can actually carry traffic first,
    // idle virtual adapters (awdl, utun, gif…) last. The sort is stable, so
    // libpcap's own order is kept within each group.
    interfaces.sort_by_key(interface_rank);
    Ok(interfaces)
}

/// 0 = up with an address, 1 = up, 2 = down.
fn interface_rank(iface: &IfaceInfo) -> u8 {
    match (iface.up, iface.addresses.is_empty()) {
        (true, false) => 0,
        (true, true) => 1,
        (false, _) => 2,
    }
}

/// Device → hardware-port name ("en0" → "Wi-Fi"), from macOS's
/// `networksetup`. Best effort: any failure just leaves the names out.
#[cfg(target_os = "macos")]
fn hardware_port_names() -> HashMap<String, String> {
    std::process::Command::new("/usr/sbin/networksetup")
        .arg("-listallhardwareports")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_hardware_ports(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

#[cfg(not(target_os = "macos"))]
fn hardware_port_names() -> HashMap<String, String> {
    HashMap::new()
}

/// Parse `networksetup -listallhardwareports`: blocks of
/// `Hardware Port: <name>` followed by `Device: <iface>`.
fn parse_hardware_ports(text: &str) -> HashMap<String, String> {
    let mut names = HashMap::new();
    let mut port: Option<&str> = None;
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("Hardware Port:") {
            port = Some(name.trim());
        } else if let Some(device) = line.strip_prefix("Device:") {
            if let Some(name) = port.take() {
                names.insert(device.trim().to_string(), name.to_string());
            }
        }
    }
    names
}

/// Validate a BPF filter expression without opening a device.
///
/// The filter is compiled against a *dead* Ethernet handle, so this needs no
/// capture privileges and touches no interface: it is meant to give the UI a
/// live "is this expression well-formed?" hint while the user types. It catches
/// the common case — a malformed expression — but is not authoritative: a few
/// constructs depend on the link layer, so [`start`] still compiles the filter
/// against the interface's real datalink and remains the final word.
///
/// An empty (or whitespace-only) filter is valid and means "capture everything".
///
/// # Errors
/// Returns an error if libpcap cannot create the validation handle or if the
/// expression does not compile.
pub fn validate_filter(filter: &str) -> Result<()> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Ok(());
    }
    let capture = pcap::Capture::dead(Linktype::ETHERNET).context("creating a validation handle")?;
    capture
        .compile(filter, true)
        .with_context(|| format!("invalid BPF filter `{filter}`"))?;
    Ok(())
}

/// Start a passive capture.
///
/// The device is opened, the BPF program compiled and the handle switched to
/// non-blocking mode before this returns, so a permission error, a bad filter
/// or a missing interface surfaces to the caller instead of in the background.
/// Packets are then read on a blocking task and forwarded through `events`.
///
/// # Errors
/// Returns an error if the interface cannot be opened (on macOS the BPF
/// devices require privileges: ChmodBPF or an elevated process), if the BPF
/// filter does not compile, or if the snapshot length is invalid.
pub async fn start(
    config: SniffConfig,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<SniffEvent>,
) -> Result<SniffHandle> {
    if config.interface.trim().is_empty() {
        bail!("no capture interface selected");
    }
    if config.snaplen <= 0 {
        bail!("snaplen must be positive");
    }

    let mut capture = pcap::Capture::from_device(config.interface.as_str())
        .map_err(|e| open_error(&config.interface, e))?
        .promisc(config.promisc)
        .snaplen(config.snaplen)
        .timeout(100)
        .open()
        .map_err(|e| open_error(&config.interface, e))?;

    if let Some(filter) = config
        .bpf_filter
        .as_deref()
        .map(str::trim)
        .filter(|filter| !filter.is_empty())
    {
        capture
            .filter(filter, true)
            .with_context(|| format!("compiling BPF filter `{filter}`"))?;
    }

    // Non-blocking mode is what lets `stop` interrupt the loop promptly; the
    // loop sleeps only when libpcap says there is nothing to read.
    capture = capture
        .setnonblock()
        .context("setting the capture non-blocking")?;

    // Loopback is DLT_NULL on macOS, Ethernet elsewhere: the parser must know
    // which header to skip, so resolve it once, before the loop starts.
    let link = link_type(capture.get_datalink()).with_context(|| {
        format!(
            "interface {} reports an unsupported link-layer type",
            config.interface
        )
    })?;

    let stopping = Arc::new(AtomicBool::new(false));
    let stop_for_loop = stopping.clone();
    let ended = Arc::new(AtomicBool::new(false));
    let ended_for_loop = ended.clone();
    let join = tokio::task::spawn_blocking(move || {
        let mut flows = FlowTable::new(scope);
        loop {
            if stop_for_loop.load(Ordering::Relaxed) {
                break;
            }
            match capture.next_packet() {
                Ok(packet) => {
                    let Some(parsed) = parse::parse_packet(packet.data, link) else {
                        continue;
                    };
                    let at = SystemTime::now();
                    let observation = flows.observe(&parsed, at, packet.header.len);
                    if observation.created
                        && events
                            .blocking_send(SniffEvent::FlowStarted(observation.flow.clone()))
                            .is_err()
                    {
                        break;
                    }
                    if events
                        .blocking_send(SniffEvent::FlowUpdated(observation.flow.clone()))
                        .is_err()
                    {
                        break;
                    }
                    let meta = PacketMeta {
                        flow_id: observation.flow.id,
                        at,
                        direction: observation.direction,
                        src_addr: parsed.src,
                        dst_addr: parsed.dst,
                        wire_len: packet.header.len,
                        payload_len: parsed.payload_len as u32,
                        tcp_flags: parsed.tcp_flags.clone(),
                        info: packet_info(&parsed),
                    };
                    if events.blocking_send(SniffEvent::Packet(meta)).is_err() {
                        break;
                    }
                }
                // Non-blocking mode reports "nothing yet" this way.
                Err(pcap::Error::TimeoutExpired) => std::thread::sleep(IDLE_POLL),
                Err(e) => {
                    // Mark the loop as ended *before* the UI hears about the
                    // error: a status check racing with that event must see
                    // the capture as stopped, not as running.
                    ended_for_loop.store(true, Ordering::Relaxed);
                    let _ = events.blocking_send(SniffEvent::Error(format!(
                        "capture stopped on {}: {e}",
                        config.interface
                    )));
                    break;
                }
            }
        }
        ended_for_loop.store(true, Ordering::Relaxed);
    });

    Ok(SniffHandle {
        stopping,
        ended,
        join: Some(join),
    })
}

/// Map libpcap's datalink type to the framing the parser knows how to skip.
fn link_type(datalink: Linktype) -> Result<parse::LinkType> {
    Ok(match datalink {
        Linktype::ETHERNET => parse::LinkType::Ethernet,
        Linktype::NULL => parse::LinkType::Null,
        Linktype::LOOP => parse::LinkType::Loop,
        Linktype::RAW => parse::LinkType::Raw,
        other => bail!(
            "unsupported link-layer type {other:?}: only Ethernet, raw IP and BSD loopback frames can be parsed"
        ),
    })
}

/// A capture error with an actionable hint when the cause is BPF permissions.
fn open_error(interface: &str, error: pcap::Error) -> anyhow::Error {
    let detail = error.to_string();
    let lower = detail.to_lowercase();
    let hint = if lower.contains("permission") || lower.contains("not permitted") {
        " (on macOS the BPF devices require privileges: install ChmodBPF, \
         e.g. with Wireshark, or run Elliot with sudo)"
    } else {
        ""
    };
    anyhow::anyhow!("cannot capture on {interface}: {detail}{hint}")
}

fn packet_info(parsed: &ParsedPacket) -> Option<String> {
    if let Some(host) = &parsed.sni {
        return Some(format!("SNI {host}"));
    }
    if let Some(name) = &parsed.dns_query {
        return Some(format!("DNS {name}"));
    }
    parsed.tls.then(|| "TLS".to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlowKey {
    client: SocketAddr,
    server: SocketAddr,
    transport: Transport,
}

// `Transport` in `elliot-httpraw` does not derive `Hash` (the shared model must
// not change for this crate), so hash its frozen token instead.
impl std::hash::Hash for FlowKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.client.hash(state);
        self.server.hash(state);
        self.transport.as_token().hash(state);
    }
}

struct Observation {
    flow: FlowMeta,
    direction: Direction,
    created: bool,
}

/// Flows keyed by 5-tuple. The first packet seen names the client side; later
/// packets in the opposite direction match the reversed key. This is enough to
/// group traffic without tracking TCP state.
struct FlowTable {
    scope: Arc<dyn ScopeDecider>,
    by_key: HashMap<FlowKey, Uuid>,
    flows: HashMap<Uuid, FlowMeta>,
}

impl FlowTable {
    fn new(scope: Arc<dyn ScopeDecider>) -> Self {
        Self {
            scope,
            by_key: HashMap::new(),
            flows: HashMap::new(),
        }
    }

    fn observe(&mut self, packet: &ParsedPacket, at: SystemTime, wire_len: u32) -> Observation {
        let forward = FlowKey {
            client: packet.src,
            server: packet.dst,
            transport: packet.transport,
        };
        let reverse = FlowKey {
            client: packet.dst,
            server: packet.src,
            transport: packet.transport,
        };

        let (id, direction, created) = if let Some(id) = self.by_key.get(&forward) {
            (*id, Direction::ClientToServer, false)
        } else if let Some(id) = self.by_key.get(&reverse) {
            (*id, Direction::ServerToClient, false)
        } else {
            let id = Uuid::new_v4();
            let flow = FlowMeta {
                id,
                started_at: at,
                last_seen_at: at,
                client_addr: packet.src,
                server_addr: packet.dst,
                transport: packet.transport,
                host: None,
                scope: None,
                packets: 0,
                bytes: 0,
                tls: false,
            };
            self.by_key.insert(forward, id);
            self.flows.insert(id, flow);
            (id, Direction::ClientToServer, true)
        };

        // Resolve the label (and with it the scope tag) before mutably
        // borrowing the flow, so both maps can be touched in one pass.
        let server = if direction == Direction::ClientToServer {
            packet.dst
        } else {
            packet.src
        };
        let discovery = packet
            .sni
            .as_ref()
            .or(packet.dns_query.as_ref())
            .map(|host| {
                let decision =
                    self.scope
                        .decide(packet.transport.scheme(), host, server.port(), "");
                (host.clone(), decision)
            });

        let flow = self
            .flows
            .get_mut(&id)
            .expect("a flow id is registered before it is observed");
        flow.last_seen_at = at;
        flow.packets += 1;
        flow.bytes += u64::from(wire_len);
        if packet.tls {
            flow.tls = true;
        }
        if let Some((host, decision)) = discovery {
            if flow.host.as_deref() != Some(host.as_str()) {
                flow.host = Some(host);
                flow.scope = Some(decision);
            }
        }

        Observation {
            flow: flow.clone(),
            direction,
            created,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliot_httpraw::AllowAll;
    use std::net::{IpAddr, Ipv4Addr};

    fn packet(src: ([u8; 4], u16), dst: ([u8; 4], u16), sni: Option<&str>) -> ParsedPacket {
        ParsedPacket {
            transport: Transport::Tcp,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src.0)), src.1),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst.0)), dst.1),
            payload_len: 0,
            tcp_flags: Some("SYN".into()),
            tls: false,
            sni: sni.map(str::to_string),
            dns_query: None,
        }
    }

    #[tokio::test]
    async fn a_handle_reports_its_loop_as_running() {
        let handle = SniffHandle {
            stopping: Arc::new(AtomicBool::new(false)),
            ended: Arc::new(AtomicBool::new(false)),
            join: Some(tokio::spawn(std::future::pending::<()>())),
        };
        assert!(handle.is_running());
    }

    #[tokio::test]
    async fn a_finished_loop_is_no_longer_running() {
        let join = tokio::spawn(async {});
        while !join.is_finished() {
            tokio::task::yield_now().await;
        }
        let handle = SniffHandle {
            stopping: Arc::new(AtomicBool::new(false)),
            ended: Arc::new(AtomicBool::new(false)),
            join: Some(join),
        };
        assert!(!handle.is_running());
    }

    #[tokio::test]
    async fn a_loop_that_reported_an_error_is_not_running_yet() {
        // The blocking thread may still be finishing when the error event is
        // already on its way to the UI; the ended flag closes that window.
        let handle = SniffHandle {
            stopping: Arc::new(AtomicBool::new(false)),
            ended: Arc::new(AtomicBool::new(true)),
            join: Some(tokio::spawn(std::future::pending::<()>())),
        };
        assert!(!handle.is_running());
    }

    #[test]
    fn hardware_ports_map_devices_to_their_names() {
        let text = "\nHardware Port: Ethernet Adapter (en3)\nDevice: en3\nEthernet Address: 56:a2:4f:31:28:4b\n\n\
                    Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 2c:ca:16:39:27:0e\n\n\
                    VLAN Configurations\n===================\n";
        let names = parse_hardware_ports(text);
        assert_eq!(names.get("en0").map(String::as_str), Some("Wi-Fi"));
        assert_eq!(
            names.get("en3").map(String::as_str),
            Some("Ethernet Adapter (en3)")
        );
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn active_interfaces_sort_before_idle_ones() {
        let iface = |name: &str, up: bool, addr: bool| IfaceInfo {
            name: name.into(),
            friendly_name: None,
            description: None,
            addresses: if addr { vec!["192.168.1.74".into()] } else { vec![] },
            loopback: false,
            wireless: false,
            up,
            connected: up,
        };
        let mut list = [
            iface("awdl0", false, false),
            iface("utun0", true, false),
            iface("en0", true, true),
        ];
        list.sort_by_key(interface_rank);
        let names: Vec<_> = list.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["en0", "utun0", "awdl0"]);
    }

    #[test]
    fn valid_filters_compile_and_empty_is_allowed() {
        assert!(validate_filter("").is_ok());
        assert!(validate_filter("   ").is_ok());
        assert!(validate_filter("tcp port 8080").is_ok());
        assert!(validate_filter("tcp port 443 or udp port 53").is_ok());
        assert!(validate_filter("host 127.0.0.1 and not port 22").is_ok());
    }

    #[test]
    fn a_malformed_filter_is_rejected() {
        let err = validate_filter("tcp port port").unwrap_err();
        assert!(format!("{err:#}").contains("invalid BPF filter"));
        assert!(validate_filter("port notanumber").is_err());
    }

    #[test]
    fn macos_loopback_datalink_is_supported() {
        assert_eq!(link_type(Linktype::NULL).unwrap(), parse::LinkType::Null);
        assert_eq!(link_type(Linktype::LOOP).unwrap(), parse::LinkType::Loop);
        assert_eq!(
            link_type(Linktype::ETHERNET).unwrap(),
            parse::LinkType::Ethernet
        );
        assert_eq!(link_type(Linktype::RAW).unwrap(), parse::LinkType::Raw);
        assert!(link_type(Linktype::LINUX_SLL).is_err());
    }

    #[test]
    fn packets_in_both_directions_share_one_flow() {
        let mut table = FlowTable::new(Arc::new(AllowAll));
        let at = SystemTime::now();
        let out = packet(
            ([10, 0, 0, 1], 51000),
            ([10, 0, 0, 2], 443),
            Some("example.com"),
        );
        let first = table.observe(&out, at, 60);
        assert!(first.created);
        assert_eq!(first.direction, Direction::ClientToServer);
        assert_eq!(first.flow.host.as_deref(), Some("example.com"));
        assert_eq!(first.flow.scope, Some(ScopeDecision::InScope));

        let back = packet(([10, 0, 0, 2], 443), ([10, 0, 0, 1], 51000), None);
        let second = table.observe(&back, at, 40);
        assert!(!second.created);
        assert_eq!(second.flow.id, first.flow.id);
        assert_eq!(second.direction, Direction::ServerToClient);
        assert_eq!(second.flow.packets, 2);
        assert_eq!(second.flow.bytes, 100);
    }

    #[test]
    fn a_scope_edit_labels_the_known_host() {
        let mut table = FlowTable::new(Arc::new(elliot_httpraw::DenyAll));
        let at = SystemTime::now();
        let observed = table.observe(
            &packet(
                ([10, 0, 0, 1], 51000),
                ([10, 0, 0, 2], 443),
                Some("example.com"),
            ),
            at,
            60,
        );
        assert_eq!(observed.flow.scope, Some(ScopeDecision::OutOfScope));
    }
}
