//! Parser tests over packets built by hand: Ethernet/IPv4/TCP with a TLS
//! ClientHello, and UDP with a DNS query (IPv4 and IPv6). No capture device or
//! privilege is needed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use elliot_httpraw::Transport;
use elliot_sniff::parse::{parse_packet, LinkType};

fn ethernet_ipv4(payload: &[u8], protocol: u8) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut frame = Vec::with_capacity(14 + 20 + payload.len());
    // Destination, source, EtherType = IPv4.
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&[0x08, 0x00]);
    // IPv4 header, 20 bytes, no options.
    frame.push(0x45);
    frame.push(0);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x01, 0x40, 0x00]); // id, DF
    frame.push(64); // TTL
    frame.push(protocol);
    frame.extend_from_slice(&[0x00, 0x00]); // checksum (not validated)
    frame.extend_from_slice(&[10, 0, 0, 1]);
    frame.extend_from_slice(&[10, 0, 0, 2]);
    frame.extend_from_slice(payload);
    frame
}

fn ethernet_ipv6_udp(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut frame = Vec::with_capacity(14 + 40 + 8 + payload.len());
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    frame.extend_from_slice(&[0x86, 0xdd]); // EtherType = IPv6
    frame.push(0x60); // version 6
    frame.extend_from_slice(&[0, 0, 0]); // traffic class / flow label
    frame.extend_from_slice(&udp_len.to_be_bytes()); // payload length
    frame.push(17); // next header = UDP
    frame.push(64); // hop limit
    frame.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    frame.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    frame.extend_from_slice(&udp_header(src, dst, payload));
    frame
}

fn tcp_header(src: u16, dst: u16, flags: u8, payload_len: usize) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload_len);
    tcp.extend_from_slice(&src.to_be_bytes());
    tcp.extend_from_slice(&dst.to_be_bytes());
    tcp.extend_from_slice(&1u32.to_be_bytes()); // sequence
    tcp.extend_from_slice(&0u32.to_be_bytes()); // acknowledgment
    tcp.push(5 << 4); // data offset: 5 words
    tcp.push(flags);
    tcp.extend_from_slice(&64240u16.to_be_bytes());
    tcp.extend_from_slice(&[0x00, 0x00]); // checksum
    tcp.extend_from_slice(&[0x00, 0x00]); // urgent pointer
    tcp
}

fn udp_header(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&src.to_be_bytes());
    udp.extend_from_slice(&dst.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]); // checksum
    udp.extend_from_slice(payload);
    udp
}

fn client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes()); // list length
    sni.push(0); // name_type = host_name
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]); // server_name
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session id length
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    body.extend_from_slice(&[0x01, 0x00]); // compression methods
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len = body.len() as u32;
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16); // handshake record
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut dns = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // questions
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    dns
}

#[test]
fn parses_an_ipv4_tcp_client_hello_and_its_sni() {
    let hello = client_hello("example.com");
    let mut tcp = tcp_header(51000, 443, 0x18, hello.len());
    tcp.extend_from_slice(&hello);
    let frame = ethernet_ipv4(&tcp, 6);

    let parsed = parse_packet(&frame, LinkType::Ethernet).expect("a TCP IPv4 packet must parse");
    assert_eq!(parsed.transport, Transport::Tcp);
    assert_eq!(parsed.src.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(parsed.src.port(), 51000);
    assert_eq!(parsed.dst.port(), 443);
    assert_eq!(parsed.payload_len, hello.len());
    assert!(parsed.tls);
    assert_eq!(parsed.sni.as_deref(), Some("example.com"));
    assert_eq!(parsed.tcp_flags.as_deref(), Some("ACK, PSH"));
}

#[test]
fn parses_an_ipv4_udp_dns_query() {
    let query = dns_query("www.example.com");
    let frame = ethernet_ipv4(&udp_header(53000, 53, &query), 17);

    let parsed = parse_packet(&frame, LinkType::Ethernet).expect("a UDP IPv4 packet must parse");
    assert_eq!(parsed.transport, Transport::Udp);
    assert_eq!(parsed.dst.port(), 53);
    assert_eq!(parsed.payload_len, query.len());
    assert_eq!(parsed.dns_query.as_deref(), Some("www.example.com"));
    assert!(!parsed.tls);
    assert_eq!(parsed.tcp_flags, None);
}

#[test]
fn parses_an_ipv6_udp_dns_query() {
    let query = dns_query("example.org");
    let frame = ethernet_ipv6_udp(53000, 53, &query);

    let parsed = parse_packet(&frame, LinkType::Ethernet).expect("a UDP IPv6 packet must parse");
    assert_eq!(parsed.transport, Transport::Udp);
    assert!(parsed.src.ip().is_ipv6());
    assert_eq!(parsed.dns_query.as_deref(), Some("example.org"));
}

#[test]
fn bare_ip_packets_are_accepted_too() {
    // A DLT_RAW interface hands the same TCP segment without Ethernet framing.
    let body = b"GET / HTTP/1.1\r\n";
    let mut tcp = tcp_header(1234, 80, 0x02, body.len());
    tcp.extend_from_slice(body);
    let ethernet = ethernet_ipv4(&tcp, 6);
    let parsed = parse_packet(&ethernet[14..], LinkType::Raw).expect("bare IPv4 must parse");
    assert_eq!(parsed.src.port(), 1234);
    assert_eq!(parsed.dst.port(), 80);
    assert_eq!(parsed.tcp_flags.as_deref(), Some("SYN"));
}

#[test]
fn non_ip_frames_are_ignored() {
    let mut frame = vec![0u8; 14];
    frame[12] = 0x08;
    frame[13] = 0x06; // EtherType = ARP, not IP
    frame.extend_from_slice(&[0u8; 28]);
    assert!(parse_packet(&frame, LinkType::Ethernet).is_none());
    assert!(parse_packet(&[], LinkType::Ethernet).is_none());
}

/// DLT_NULL prepends a 4-byte address-family word to the IP packet. This is
/// the framing of `lo0` on macOS, the interface the UI preselects.
fn null_loopback(family: [u8; 4], ip: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + ip.len());
    frame.extend_from_slice(&family);
    frame.extend_from_slice(ip);
    frame
}

#[test]
fn parses_macos_loopback_null_framing() {
    let hello = client_hello("example.com");
    let mut tcp = tcp_header(51000, 443, 0x18, hello.len());
    tcp.extend_from_slice(&hello);
    let ip = ethernet_ipv4(&tcp, 6)[14..].to_vec();
    // AF_INET = 2, host byte order (little-endian on macOS).
    let frame = null_loopback([2, 0, 0, 0], &ip);

    let parsed = parse_packet(&frame, LinkType::Null).expect("DLT_NULL IPv4 must parse");
    assert_eq!(parsed.src.port(), 51000);
    assert_eq!(parsed.dst.port(), 443);
    assert_eq!(parsed.sni.as_deref(), Some("example.com"));
}

#[test]
fn parses_openbsd_loop_loopback_framing() {
    let query = dns_query("example.org");
    let ip = ethernet_ipv6_udp(53000, 53, &query)[14..].to_vec();
    // DLT_LOOP stores the address family in network byte order.
    let frame = null_loopback([0, 0, 0, 30], &ip);

    let parsed = parse_packet(&frame, LinkType::Loop).expect("DLT_LOOP IPv6 must parse");
    assert_eq!(parsed.dst.port(), 53);
    assert_eq!(parsed.dns_query.as_deref(), Some("example.org"));
}

#[test]
fn a_truncated_loopback_header_is_rejected() {
    assert!(parse_packet(&[2, 0, 0], LinkType::Null).is_none());
}
