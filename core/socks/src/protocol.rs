//! The SOCKS5 wire format, as little of it as Elliot needs.
//!
//! Hand-rolled on purpose: SOCKS5 (RFC 1928) plus user/password auth (RFC 1929)
//! is a small, fixed protocol, and keeping the parser pure (bytes in, values
//! out) makes every branch unit-testable without a socket.
//!
//! Nothing here resolves a domain name: a `DOMAIN` target stays a string, so the
//! name the client asked for is what gets scope-checked and what is handed to
//! the connector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const VERSION: u8 = 0x05;
pub const AUTH_VERSION: u8 = 0x01;

pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USER_PASS: u8 = 0x02;
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_UNSUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_UNSUPPORTED: u8 = 0x08;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// The address in a SOCKS request. A domain stays unresolved (see the module
/// docs); an IP keeps its literal form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl Target {
    pub fn host(&self) -> String {
        match self {
            Target::Ip(ip, _) => ip.to_string(),
            Target::Domain(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(_, port) | Target::Domain(_, port) => *port,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    /// A well-formed command we do not implement (the server answers
    /// [`REP_COMMAND_UNSUPPORTED`] rather than dropping the connection).
    Unsupported(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Not enough bytes yet: read more and try again.
    Incomplete,
    /// Structurally invalid. The connection must be closed.
    Malformed(&'static str),
    /// A UDP datagram marked as a fragment. RFC 1928 says to drop it; Elliot
    /// never implements fragmentation.
    Fragmented,
}

/// Which authentication method to select for the methods a client offered.
///
/// With credentials configured, only user/password is acceptable; without them,
/// only no-auth (the listener is loopback-only, so "trust the local user" is the
/// deliberate default).
pub fn select_method(offered: &[u8], credentials_required: bool) -> Option<u8> {
    let want = if credentials_required {
        METHOD_USER_PASS
    } else {
        METHOD_NO_AUTH
    };
    offered.contains(&want).then_some(want)
}

/// The server's method-selection reply.
pub fn method_reply(method: u8) -> [u8; 2] {
    [VERSION, method]
}

/// The RFC 1929 auth status reply (`status` 0x00 = success).
pub fn auth_reply(status: u8) -> [u8; 2] {
    [AUTH_VERSION, status]
}

/// Parse an RFC 1929 user/password sub-negotiation. Returns the user, the
/// password and the number of bytes consumed.
pub fn parse_auth(buf: &[u8]) -> Result<(String, String, usize), ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::Incomplete);
    }
    if buf[0] != AUTH_VERSION {
        return Err(ParseError::Malformed("unsupported auth version"));
    }
    let ulen = buf[1] as usize;
    if buf.len() < 2 + ulen + 1 {
        return Err(ParseError::Incomplete);
    }
    let plen = buf[2 + ulen] as usize;
    let total = 2 + ulen + 1 + plen;
    if buf.len() < total {
        return Err(ParseError::Incomplete);
    }
    let user = std::str::from_utf8(&buf[2..2 + ulen])
        .map_err(|_| ParseError::Malformed("username is not UTF-8"))?;
    let pass = std::str::from_utf8(&buf[2 + ulen + 1..total])
        .map_err(|_| ParseError::Malformed("password is not UTF-8"))?;
    Ok((user.to_string(), pass.to_string(), total))
}

/// Parse a SOCKS5 request. Returns the command, the target and the number of
/// bytes consumed (so an incremental reader can feed more bytes).
pub fn parse_request(buf: &[u8]) -> Result<(Command, Target, usize), ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::Incomplete);
    }
    if buf[0] != VERSION {
        return Err(ParseError::Malformed("unsupported SOCKS version"));
    }
    if buf[2] != 0x00 {
        return Err(ParseError::Malformed("reserved byte is not zero"));
    }
    let command = match buf[1] {
        CMD_CONNECT => Command::Connect,
        CMD_BIND => Command::Bind,
        CMD_UDP_ASSOCIATE => Command::UdpAssociate,
        other => Command::Unsupported(other),
    };
    let (target, consumed) = parse_address(&buf[3..])?;
    Ok((command, target, 3 + consumed))
}

/// Parse an address in `ATYP, ADDR, PORT` form. Returns it and the bytes used.
pub fn parse_address(buf: &[u8]) -> Result<(Target, usize), ParseError> {
    let atyp = *buf.first().ok_or(ParseError::Incomplete)?;
    match atyp {
        ATYP_IPV4 => {
            if buf.len() < 1 + 4 + 2 {
                return Err(ParseError::Incomplete);
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Target::Ip(IpAddr::V4(ip), port), 7))
        }
        ATYP_IPV6 => {
            if buf.len() < 1 + 16 + 2 {
                return Err(ParseError::Incomplete);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Target::Ip(IpAddr::V6(Ipv6Addr::from(octets)), port), 19))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Err(ParseError::Incomplete);
            }
            let len = buf[1] as usize;
            if len == 0 {
                return Err(ParseError::Malformed("empty domain name"));
            }
            if buf.len() < 2 + len + 2 {
                return Err(ParseError::Incomplete);
            }
            let host = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|_| ParseError::Malformed("domain is not UTF-8"))?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Target::Domain(host, port), 2 + len + 2))
        }
        _ => Err(ParseError::Malformed("unsupported address type")),
    }
}

/// Encode one target in `ATYP, ADDR, PORT` form.
pub fn encode_address(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match target {
        Target::Ip(IpAddr::V4(ip), _) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Target::Ip(IpAddr::V6(ip), _) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Target::Domain(host, _) => {
            out.push(ATYP_DOMAIN);
            let bytes = host.as_bytes();
            // A domain longer than 255 bytes cannot be encoded; truncating would
            // forge a valid-looking address, so the length is clamped and the
            // caller sees a shorter name rather than a corrupt message.
            out.push(bytes.len().min(255) as u8);
            out.extend_from_slice(&bytes[..bytes.len().min(255)]);
        }
    }
    match target {
        Target::Ip(_, port) | Target::Domain(_, port) => out.extend_from_slice(&port.to_be_bytes()),
    }
    out
}

/// The success reply, carrying the address the server bound to.
pub fn success_reply(bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![VERSION, REP_SUCCEEDED, 0x00];
    out.extend_from_slice(&encode_address(&Target::Ip(bound.ip(), bound.port())));
    out
}

/// An error reply. The bound address is `0.0.0.0:0`: meaningless by design,
/// which is why clients must look at the reply code.
pub fn error_reply(code: u8) -> Vec<u8> {
    vec![VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// Map a connect failure onto the closest SOCKS reply code.
pub fn reply_code_for(err: &std::io::Error) -> u8 {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        ErrorKind::NotFound => REP_HOST_UNREACHABLE,
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => REP_NETWORK_UNREACHABLE,
        ErrorKind::TimedOut => REP_TTL_EXPIRED,
        ErrorKind::PermissionDenied => REP_NOT_ALLOWED,
        _ => REP_GENERAL_FAILURE,
    }
}

/// Wrap a payload in a SOCKS UDP request header (`RSV, FRAG, ATYP, ADDR,
/// PORT`), as sent between a UDP-ASSOCIATE client and the relay.
pub fn encode_datagram(target: &Target, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 19);
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG = 0 (no fragmentation)
    out.extend_from_slice(&encode_address(target));
    out.extend_from_slice(payload);
    out
}

/// Parse a SOCKS UDP datagram. Returns the destination and the offset at which
/// the payload starts.
pub fn parse_datagram(buf: &[u8]) -> Result<(Target, usize), ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::Incomplete);
    }
    if buf[0] != 0x00 || buf[1] != 0x00 {
        return Err(ParseError::Malformed("reserved bytes are not zero"));
    }
    if buf[2] != 0x00 {
        return Err(ParseError::Fragmented);
    }
    let (target, consumed) = parse_address(&buf[3..])?;
    Ok((target, 3 + consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_selection_follows_the_configured_policy() {
        // No credentials: only no-auth is acceptable.
        assert_eq!(select_method(&[METHOD_NO_AUTH], false), Some(METHOD_NO_AUTH));
        assert_eq!(
            select_method(&[METHOD_USER_PASS, METHOD_NO_AUTH], false),
            Some(METHOD_NO_AUTH)
        );
        assert_eq!(select_method(&[METHOD_USER_PASS], false), None);
        // Credentials configured: only user/password is acceptable.
        assert_eq!(select_method(&[METHOD_NO_AUTH], true), None);
        assert_eq!(
            select_method(&[METHOD_NO_AUTH, METHOD_USER_PASS], true),
            Some(METHOD_USER_PASS)
        );
        assert_eq!(select_method(&[], true), None);
    }

    #[test]
    fn parses_a_connect_request_with_a_domain() {
        let mut buf = vec![VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, 11];
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&6379u16.to_be_bytes());

        let (cmd, target, consumed) = parse_request(&buf).unwrap();
        assert_eq!(cmd, Command::Connect);
        assert_eq!(target, Target::Domain("example.com".into(), 6379));
        assert_eq!(target.host(), "example.com");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parses_ipv4_and_ipv6_requests() {
        let v4 = [VERSION, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x1F, 0x90];
        let (cmd, target, consumed) = parse_request(&v4).unwrap();
        assert_eq!(cmd, Command::Connect);
        assert_eq!(target, Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        assert_eq!(consumed, v4.len());

        let mut v6 = vec![VERSION, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV6];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&53u16.to_be_bytes());
        let (cmd, target, _) = parse_request(&v6).unwrap();
        assert_eq!(cmd, Command::UdpAssociate);
        assert_eq!(target, Target::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 53));
    }

    #[test]
    fn an_incomplete_request_asks_for_more_bytes() {
        // Truncated at every point: never a panic, never a bogus parse.
        let full = {
            let mut b = vec![VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, 11];
            b.extend_from_slice(b"example.com");
            b.extend_from_slice(&6379u16.to_be_bytes());
            b
        };
        for cut in 0..full.len() {
            assert_eq!(
                parse_request(&full[..cut]),
                Err(ParseError::Incomplete),
                "cut at {cut}"
            );
        }
        // One byte more than the request itself must still parse (a client may
        // pipeline nothing, but the reader must not depend on exact framing).
        assert!(parse_request(&full).is_ok());
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert_eq!(
            parse_request(&[0x04, CMD_CONNECT, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(ParseError::Malformed("unsupported SOCKS version"))
        );
        assert_eq!(
            parse_request(&[VERSION, CMD_CONNECT, 0x01, ATYP_IPV4, 0, 0, 0, 0, 0, 0]),
            Err(ParseError::Malformed("reserved byte is not zero"))
        );
        assert_eq!(
            parse_request(&[VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, 0, 0, 0]),
            Err(ParseError::Malformed("empty domain name"))
        );
        assert_eq!(
            parse_request(&[VERSION, CMD_CONNECT, 0x00, 0x09, 0, 0, 0]),
            Err(ParseError::Malformed("unsupported address type"))
        );
    }

    #[test]
    fn unsupported_commands_parse_but_are_flagged() {
        let buf = [VERSION, 0x0A, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 80];
        let (cmd, _, _) = parse_request(&buf).unwrap();
        assert_eq!(cmd, Command::Unsupported(0x0A));
        let bind = [VERSION, CMD_BIND, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_request(&bind).unwrap().0, Command::Bind);
    }

    #[test]
    fn parses_user_password_auth() {
        let mut buf = vec![AUTH_VERSION, 4];
        buf.extend_from_slice(b"user");
        buf.push(6);
        buf.extend_from_slice(b"secret");
        let (user, pass, consumed) = parse_auth(&buf).unwrap();
        assert_eq!((user.as_str(), pass.as_str()), ("user", "secret"));
        assert_eq!(consumed, buf.len());
        // Empty password is legal (the length byte is 0).
        let empty = [AUTH_VERSION, 1, b'u', 0];
        assert_eq!(parse_auth(&empty).unwrap().1, "");
        // Wrong sub-negotiation version, and truncation, are errors.
        assert!(matches!(
            parse_auth(&[0x02, 1, b'u', 1, b'p']),
            Err(ParseError::Malformed(_))
        ));
        assert_eq!(
            parse_auth(&[AUTH_VERSION, 4, b'u', b's']),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn addresses_round_trip_through_the_encoder() {
        for target in [
            Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 443),
            Target::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
            Target::Domain("api.example.com".into(), 6379),
        ] {
            let encoded = encode_address(&target);
            let (decoded, consumed) = parse_address(&encoded).unwrap();
            assert_eq!(decoded, target);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn replies_carry_the_expected_shape() {
        let ok = success_reply("127.0.0.1:1080".parse().unwrap());
        assert_eq!(&ok[..4], &[VERSION, REP_SUCCEEDED, 0x00, ATYP_IPV4]);
        assert_eq!(&ok[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([ok[8], ok[9]]), 1080);

        let err = error_reply(REP_CONNECTION_REFUSED);
        assert_eq!(&err[..2], &[VERSION, REP_CONNECTION_REFUSED]);
        assert_eq!(err.len(), 10);
    }

    #[test]
    fn udp_datagrams_round_trip_and_keep_the_payload_intact() {
        let payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let framed = encode_datagram(&Target::Domain("dns.example".into(), 53), payload);
        let (target, offset) = parse_datagram(&framed).unwrap();
        assert_eq!(target, Target::Domain("dns.example".into(), 53));
        assert_eq!(&framed[offset..], payload);

        // Reserved bytes must be zero, and a fragment is surfaced separately so
        // the relay can drop it instead of tearing down the association.
        let mut bad = framed.clone();
        bad[0] = 0x01;
        assert!(matches!(parse_datagram(&bad), Err(ParseError::Malformed(_))));
        let mut frag = framed.clone();
        frag[2] = 0x01;
        assert_eq!(parse_datagram(&frag), Err(ParseError::Fragmented));
        assert_eq!(parse_datagram(&[0, 0, 0]), Err(ParseError::Incomplete));
    }
}
