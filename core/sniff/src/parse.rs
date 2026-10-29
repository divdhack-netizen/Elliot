//! Best-effort packet parsing: Ethernet, BSD loopback or bare IP → IPv4/IPv6
//! → TCP/UDP.
//!
//! Only metadata leaves this module: the 5-tuple, TCP flags, payload length and
//! two optional labels (TLS SNI and DNS query name). Payload bytes are never
//! copied or retained.
//!
//! There is deliberately **no TLS decryption** and no TCP reassembly here: a
//! passive sniffer sees ciphertext, and a ClientHello / DNS query usually fits
//! in a single segment, which is exactly the metadata this v1 labels flows
//! with. Anything that spans segments is simply not recognised.

use std::net::{IpAddr, SocketAddr};

use elliot_httpraw::Transport;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// The link-layer framing libpcap reports for an interface.
///
/// macOS loopback (`lo0`) is not Ethernet: libpcap hands over a 4-byte
/// address-family word followed by the IP packet (DLT_NULL). Skipping the
/// wrong header would silently yield no packets on the default interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    /// DLT_EN10MB: Ethernet II, including VLAN-tagged frames.
    Ethernet,
    /// DLT_NULL: a 4-byte address-family word in host byte order, then IP.
    Null,
    /// DLT_LOOP: like [`LinkType::Null`], but network byte order.
    Loop,
    /// DLT_RAW: the IP packet starts at the first byte.
    Raw,
}

/// What a single captured packet contributes to a flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    pub transport: Transport,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Payload after the TCP/UDP header (0 for a bare IP packet).
    pub payload_len: usize,
    /// Human-readable TCP flags ("SYN, ACK"); `None` for UDP.
    pub tcp_flags: Option<String>,
    /// Does the payload begin with a TLS handshake record?
    pub tls: bool,
    /// Server name from a TLS ClientHello, when this packet carries one.
    pub sni: Option<String>,
    /// Name from a DNS query, when this datagram carries one.
    pub dns_query: Option<String>,
}

/// Parse one captured frame according to its link-layer framing. Returns
/// `None` for anything that is not IPv4/IPv6 TCP or UDP.
pub fn parse_packet(data: &[u8], link: LinkType) -> Option<ParsedPacket> {
    let sliced = match link {
        LinkType::Ethernet => SlicedPacket::from_ethernet(data).ok()?,
        // The family word itself is not needed: the IP version in the next
        // byte is authoritative, and libpcap already chose the framing.
        LinkType::Null | LinkType::Loop => SlicedPacket::from_ip(data.get(4..)?).ok()?,
        LinkType::Raw => SlicedPacket::from_ip(data).ok()?,
    };

    let (src_ip, dst_ip) = match sliced.net? {
        NetSlice::Ipv4(ip) => {
            let header = ip.header();
            (
                IpAddr::V4(header.source_addr()),
                IpAddr::V4(header.destination_addr()),
            )
        }
        NetSlice::Ipv6(ip) => {
            let header = ip.header();
            (
                IpAddr::V6(header.source_addr()),
                IpAddr::V6(header.destination_addr()),
            )
        }
    };

    match sliced.transport? {
        TransportSlice::Tcp(tcp) => {
            let payload = tcp.payload();
            Some(ParsedPacket {
                transport: Transport::Tcp,
                src: SocketAddr::new(src_ip, tcp.source_port()),
                dst: SocketAddr::new(dst_ip, tcp.destination_port()),
                payload_len: payload.len(),
                tcp_flags: Some(tcp_flags(&tcp)),
                tls: looks_like_tls(payload),
                sni: client_hello_sni(payload),
                dns_query: None,
            })
        }
        TransportSlice::Udp(udp) => {
            let payload = udp.payload();
            let src = SocketAddr::new(src_ip, udp.source_port());
            let dst = SocketAddr::new(dst_ip, udp.destination_port());
            // DNS queries travel to port 53; responses are not labelled (the
            // request already named the flow).
            let dns_query = (dst.port() == 53)
                .then(|| dns_query_name(payload))
                .flatten();
            Some(ParsedPacket {
                transport: Transport::Udp,
                src,
                dst,
                payload_len: payload.len(),
                tcp_flags: None,
                tls: false,
                sni: None,
                dns_query,
            })
        }
        // ICMP and friends are out of scope for a TCP/UDP flow view.
        TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => None,
    }
}

fn tcp_flags(tcp: &etherparse::TcpSlice<'_>) -> String {
    let mut flags = Vec::with_capacity(5);
    for (set, name) in [
        (tcp.syn(), "SYN"),
        (tcp.ack(), "ACK"),
        (tcp.fin(), "FIN"),
        (tcp.rst(), "RST"),
        (tcp.psh(), "PSH"),
    ] {
        if set {
            flags.push(name);
        }
    }
    flags.join(", ")
}

/// A TLS handshake record starts with 0x16 and a 3.x version. Both directions
/// match (ClientHello and ServerHello), which is enough to label the flow.
fn looks_like_tls(payload: &[u8]) -> bool {
    payload.len() >= 3 && payload[0] == 0x16 && payload[1] == 0x03
}

/// The first TLS record's ClientHello, if this payload starts with one.
fn client_hello_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2) — then the handshake message.
    if payload.len() < 9 || payload[0] != 0x16 || payload[5] != 0x01 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record = payload.get(5..5 + record_len)?;
    // Handshake header: type(1) length(3), then the ClientHello body.
    let body = record.get(4..)?;
    parse_client_hello(body)
}

fn parse_client_hello(body: &[u8]) -> Option<String> {
    let mut at = 0usize;

    // legacy_version(2) + random(32)
    at = at.checked_add(2 + 32)?;
    // session_id
    let session_id_len = *body.get(at)? as usize;
    at = at.checked_add(1 + session_id_len)?;
    // cipher_suites
    let cipher_len = read_u16(body, at)? as usize;
    at = at.checked_add(2 + cipher_len)?;
    // compression_methods
    let compression_len = *body.get(at)? as usize;
    at = at.checked_add(1 + compression_len)?;
    // extensions: total length, then a sequence of type(2) len(2) value
    let extensions_len = read_u16(body, at)? as usize;
    at = at.checked_add(2)?;
    let end = at.checked_add(extensions_len)?.min(body.len());

    while at + 4 <= end {
        let kind = read_u16(body, at)?;
        let len = read_u16(body, at + 2)? as usize;
        let value_start = at.checked_add(4)?;
        let value_end = value_start.checked_add(len)?;
        if value_end > end {
            return None;
        }
        if kind == 0x0000 {
            // server_name: list length(2), then name_type(1) len(2) name
            let value = body.get(value_start..value_end)?;
            let list_len = read_u16(value, 0)? as usize;
            let list = value.get(2..2 + list_len)?;
            let name_type = *list.first()?;
            let name_len = read_u16(list, 1)? as usize;
            if name_type == 0 {
                let name = list.get(3..3 + name_len)?;
                let host = std::str::from_utf8(name).ok()?;
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }
        at = value_end;
    }
    None
}

/// Parse the QNAME of a DNS query (the QR bit must be 0). Limited to what a
/// passive label needs: the first question name, uncompressed (queries never
/// use compression pointers).
fn dns_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if flags & 0x8000 != 0 || questions == 0 {
        return None; // a response, not a query
    }

    let mut at = 12usize;
    let mut labels: Vec<&str> = Vec::new();
    loop {
        let len = *payload.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        // 0b11xxxxxx is a compression pointer: not used by a fresh query.
        if len & 0xc0 != 0 {
            return None;
        }
        let label = payload.get(at..at + len)?;
        labels.push(std::str::from_utf8(label).ok()?);
        at += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dns_query_is_labelled_with_its_name() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(dns_query_name(&query), Some("www.example.com".into()));
    }

    #[test]
    fn a_dns_response_is_not_mistaken_for_a_query() {
        let mut response = [0u8; 12];
        response[2] = 0x81; // QR = 1 (response)
        response[5] = 0x01;
        assert_eq!(dns_query_name(&response), None);
    }

    #[test]
    fn a_compression_pointer_is_rejected() {
        let mut query = [0u8; 12];
        query[5] = 0x01;
        let mut bytes = query.to_vec();
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        assert_eq!(dns_query_name(&bytes), None);
    }
}
