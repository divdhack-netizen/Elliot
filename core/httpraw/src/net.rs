//! Shared, string-only parsing of hosts, ports and target loci.
//!
//! Host/port/scheme parsing used to be duplicated — with subtly different
//! defaults and IPv6 handling — across the runner and the proxy. This module is
//! the single implementation: the proxy (`convert`, `websocket`) and the tool
//! runner all derive their target information from here.
//!
//! Deliberately built on `&str` only: no dependency on the `http` crate, so it
//! stays usable from crate contexts that never see an `http::Uri`.

/// Split an authority (`host`, `host:port`, `[v6]`, `[v6]:port`) into the host
/// and an optional port. An IPv6 literal keeps its brackets.
///
/// A trailing colon (`"example.com:"`) or a non-numeric port is treated as "no
/// port": the whole input is the host. This mirrors what callers did before,
/// and never fails — a malformed authority degrades to a bare host.
pub fn split_host_port(authority: &str) -> (String, Option<u16>) {
    // IPv6 literal, with or without a port: [::1] / [::1]:8080.
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((addr, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            return (format!("[{addr}]"), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host.to_string(), port.parse().ok())
        }
        _ => (authority.to_string(), None),
    }
}

/// A target as seen by the scope engine: scheme, host, port and request path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locus<'a> {
    /// Scheme token (`"http"` / `"https"`), or `""` when the target carried no
    /// scheme (a bare host, `host:port` or CIDR — typically a port scanner).
    pub scheme: &'a str,
    pub host: String,
    pub port: u16,
    /// Request path, only present for URL targets; `""` otherwise.
    pub path: &'a str,
}

/// Derive a [`Locus`] from a target string for a scope check.
///
/// Best-effort and documented, covering the shapes the catalog allows:
/// - a URL (`http://` / `https://`) — host, path and the scheme's default port;
/// - `host:port`;
/// - a bare host;
/// - a CIDR block — the mask is stripped and the network address is checked.
///
/// A target with no recognisable port scope-checks with port `0` (and scheme
/// `""`), which matches a rule that does not constrain port or scheme.
pub fn target_locus(target: &str) -> Locus<'_> {
    if let Some((scheme, after_scheme)) = split_url_scheme(target) {
        // Authority ends at the first path/query/fragment delimiter.
        let authority_end = after_scheme
            .find(['/', '?', '#'])
            .unwrap_or(after_scheme.len());
        let (authority, rest) = after_scheme.split_at(authority_end);
        // Path is the URL path only, without query or fragment.
        let path = match rest.strip_prefix('/') {
            Some(after_slash) => {
                let cut = after_slash
                    .find(['?', '#'])
                    .map(|i| i + 1)
                    .unwrap_or(rest.len());
                &rest[..cut]
            }
            None => "",
        };
        let (host, port) = split_host_port(authority);
        let default_port = if scheme == "https" { 443 } else { 80 };
        return Locus {
            scheme,
            host,
            port: port.unwrap_or(default_port),
            path,
        };
    }

    // CIDR: scope-check the network address, mask stripped.
    let host_part = target.split('/').next().unwrap_or(target);
    let (host, port) = split_host_port(host_part);
    Locus {
        scheme: "",
        host,
        port: port.unwrap_or(0),
        path: "",
    }
}

/// Recognise `http://` / `https://` and return the scheme token plus the rest.
fn split_url_scheme(target: &str) -> Option<(&'static str, &str)> {
    if let Some(rest) = target.strip_prefix("https://") {
        Some(("https", rest))
    } else {
        target.strip_prefix("http://").map(|rest| ("http", rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_handles_host_only() {
        assert_eq!(split_host_port("example.com"), ("example.com".into(), None));
        // A suffix collision must not be read as a port.
        assert_eq!(split_host_port("notexample.com"), ("notexample.com".into(), None));
    }

    #[test]
    fn split_host_port_handles_host_and_port() {
        assert_eq!(
            split_host_port("example.com:8443"),
            ("example.com".into(), Some(8443))
        );
    }

    #[test]
    fn split_host_port_handles_ipv6() {
        assert_eq!(split_host_port("[::1]"), ("[::1]".into(), None));
        assert_eq!(split_host_port("[::1]:8080"), ("[::1]".into(), Some(8080)));
        assert_eq!(
            split_host_port("[2001:db8::1]:443"),
            ("[2001:db8::1]".into(), Some(443))
        );
    }

    #[test]
    fn split_host_port_degrades_on_malformed_input() {
        // Empty port → the whole input is the host, no panic.
        assert_eq!(split_host_port("example.com:"), ("example.com:".into(), None));
        // Non-numeric port.
        assert_eq!(
            split_host_port("example.com:http"),
            ("example.com:http".into(), None)
        );
        assert_eq!(split_host_port(""), (String::new(), None));
    }

    #[test]
    fn locus_of_bare_host_has_no_scheme_or_port() {
        let l = target_locus("scanme.example.com");
        assert_eq!(l.scheme, "");
        assert_eq!(l.host, "scanme.example.com");
        assert_eq!(l.port, 0);
        assert_eq!(l.path, "");
    }

    #[test]
    fn locus_of_host_and_port() {
        let l = target_locus("example.com:8080");
        assert_eq!(l.host, "example.com");
        assert_eq!(l.port, 8080);
    }

    #[test]
    fn locus_of_url_uses_scheme_default_port_and_path() {
        let l = target_locus("https://example.com/api/users?x=1");
        assert_eq!(l.scheme, "https");
        assert_eq!(l.host, "example.com");
        assert_eq!(l.port, 443);
        assert_eq!(l.path, "/api/users");

        let l = target_locus("http://example.com");
        assert_eq!(l.scheme, "http");
        assert_eq!(l.port, 80);
        assert_eq!(l.path, "");

        let l = target_locus("https://example.com:8443");
        assert_eq!(l.port, 8443);
    }

    #[test]
    fn locus_of_cidr_strips_the_mask() {
        let l = target_locus("10.0.0.0/24");
        assert_eq!(l.host, "10.0.0.0");
        assert_eq!(l.port, 0);
        assert_eq!(l.scheme, "");
    }

    #[test]
    fn locus_of_ipv6_host_and_port() {
        let l = target_locus("[2001:db8::1]:8080");
        assert_eq!(l.host, "[2001:db8::1]");
        assert_eq!(l.port, 8080);
    }
}
