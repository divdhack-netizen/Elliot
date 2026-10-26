//! elliot-scope — the scope policy engine.
//!
//! Elliot's **single source of truth** for which traffic is in scope (capture +
//! MITM), out of scope, or explicitly excluded (tunnelled transparently). It is
//! queried by the proxy today and, later, by the repeater, the intruder and the
//! tool runner, so that "am I allowed to touch this target?" is answered in one
//! place.
//!
//! # Model
//!
//! A [`ScopePolicy`] is two lists of [`Rule`]s: `include` says what is in scope,
//! `exclude` carves exceptions back out. A request is evaluated as:
//!
//! 1. **No include rules → [`ScopeDecision::Passthrough`].** Safe default: until
//!    the user defines a scope, Elliot captures *nothing* and tunnels every
//!    connection transparently (no MITM, no storage). A security proxy should
//!    not silently intercept and decrypt unrelated traffic (banking, mail, …)
//!    just by being left running.
//! 2. **Matches an exclude rule → [`ScopeDecision::Passthrough`].** Explicitly
//!    carved out: tunnel it, never MITM it.
//! 3. **Matches an include rule (and no exclude) → [`ScopeDecision::InScope`].**
//! 4. **A scope exists but nothing matches → [`ScopeDecision::OutOfScope`].**
//!
//! `Passthrough` and `OutOfScope` both lead the proxy to tunnel without
//! capturing; they are kept distinct so the UI can tell "explicitly excluded"
//! from "simply not in your scope".
//!
//! # Matching
//!
//! Host matching is by **exact host** or **domain suffix** (`.example.com`
//! matches `example.com` and any subdomain), case-insensitively. There is
//! deliberately **no regex**: in the spirit of the catalog's safe-by-
//! construction stance, the matchers cannot express a catastrophic
//! (ReDoS-prone) pattern. A glob/regex matcher can be added later behind the
//! same enum if a real need appears.

use serde::{Deserialize, Serialize};

pub use elliot_httpraw::{ScopeDecider, ScopeDecision};

/// A scope policy: `include` defines what is in scope, `exclude` carves
/// exceptions back out. Serializable so it can live in the project file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopePolicy {
    #[serde(default)]
    pub include: Vec<Rule>,
    #[serde(default)]
    pub exclude: Vec<Rule>,
}

impl ScopePolicy {
    /// An empty policy. Captures nothing (everything is [`Passthrough`]).
    ///
    /// [`Passthrough`]: ScopeDecision::Passthrough
    pub fn new() -> Self {
        Self::default()
    }

    /// A policy that includes a single host and all its subdomains.
    pub fn host_suffix(domain: &str) -> Self {
        Self {
            include: vec![Rule::host_suffix(domain)],
            exclude: Vec::new(),
        }
    }

    /// Add an include rule (builder-style).
    pub fn including(mut self, rule: Rule) -> Self {
        self.include.push(rule);
        self
    }

    /// Add an exclude rule (builder-style).
    pub fn excluding(mut self, rule: Rule) -> Self {
        self.exclude.push(rule);
        self
    }

    /// Evaluate a target against the policy. See the crate docs for the rules.
    pub fn evaluate(&self, scheme: &str, host: &str, port: u16, path: &str) -> ScopeDecision {
        if self.include.is_empty() {
            return ScopeDecision::Passthrough;
        }
        if self
            .exclude
            .iter()
            .any(|r| r.matches(scheme, host, port, path))
        {
            return ScopeDecision::Passthrough;
        }
        if self
            .include
            .iter()
            .any(|r| r.matches(scheme, host, port, path))
        {
            ScopeDecision::InScope
        } else {
            ScopeDecision::OutOfScope
        }
    }
}

impl ScopeDecider for ScopePolicy {
    fn decide(&self, scheme: &str, host: &str, port: u16, path: &str) -> ScopeDecision {
        self.evaluate(scheme, host, port, path)
    }
}

/// One matching rule. Every field is a matcher that defaults to "match
/// anything", so a rule constrains only the dimensions it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub scheme: SchemeMatch,
    #[serde(default)]
    pub host: HostMatch,
    #[serde(default)]
    pub port: PortMatch,
    #[serde(default)]
    pub path: PathMatch,
}

impl Rule {
    /// A rule matching one exact host, any scheme/port/path.
    pub fn host(host: &str) -> Self {
        Self {
            host: HostMatch::Exact(host.to_string()),
            ..Self::any()
        }
    }

    /// A rule matching a domain and its subdomains, any scheme/port/path.
    pub fn host_suffix(domain: &str) -> Self {
        Self {
            host: HostMatch::Suffix(normalize_suffix(domain)),
            ..Self::any()
        }
    }

    /// A rule that matches everything. Building block for the `host*` helpers.
    pub fn any() -> Self {
        Self {
            scheme: SchemeMatch::Any,
            host: HostMatch::Any,
            port: PortMatch::Any,
            path: PathMatch::Any,
        }
    }

    /// Constrain this rule to a port (builder-style).
    pub fn on_port(mut self, port: u16) -> Self {
        self.port = PortMatch::Exact(port);
        self
    }

    /// Constrain this rule to a path prefix (builder-style).
    pub fn with_path_prefix(mut self, prefix: &str) -> Self {
        self.path = PathMatch::Prefix(prefix.to_string());
        self
    }

    /// Constrain this rule to a scheme (builder-style).
    pub fn with_scheme(mut self, scheme: SchemeMatch) -> Self {
        self.scheme = scheme;
        self
    }

    fn matches(&self, scheme: &str, host: &str, port: u16, path: &str) -> bool {
        self.scheme.matches(scheme)
            && self.host.matches(host)
            && self.port.matches(port)
            && self.path.matches(path)
    }
}

/// Scheme matcher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemeMatch {
    #[default]
    Any,
    Http,
    Https,
}

impl SchemeMatch {
    fn matches(self, scheme: &str) -> bool {
        match self {
            SchemeMatch::Any => true,
            SchemeMatch::Http => scheme.eq_ignore_ascii_case("http"),
            SchemeMatch::Https => scheme.eq_ignore_ascii_case("https"),
        }
    }
}

/// Host matcher. `Exact` matches one host; `Suffix` matches a domain and its
/// subdomains. Matching is case-insensitive.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMatch {
    #[default]
    Any,
    Exact(String),
    Suffix(String),
}

impl HostMatch {
    fn matches(&self, host: &str) -> bool {
        match self {
            HostMatch::Any => true,
            HostMatch::Exact(h) => host.eq_ignore_ascii_case(h),
            HostMatch::Suffix(s) => {
                let needle = s.as_bytes();
                let hay = host.as_bytes();
                if needle.is_empty() {
                    return false;
                }
                // The apex (host == domain) …
                if hay.eq_ignore_ascii_case(needle) {
                    return true;
                }
                // … or a subdomain: host ends with ".<domain>".
                hay.len() > needle.len()
                    && hay[hay.len() - needle.len()..].eq_ignore_ascii_case(needle)
                    && hay[hay.len() - needle.len() - 1] == b'.'
            }
        }
    }
}

/// Port matcher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortMatch {
    #[default]
    Any,
    Exact(u16),
}

impl PortMatch {
    fn matches(self, port: u16) -> bool {
        match self {
            PortMatch::Any => true,
            PortMatch::Exact(p) => p == port,
        }
    }
}

/// Path matcher. `Prefix` matches request paths that start with the string.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatch {
    #[default]
    Any,
    Prefix(String),
}

impl PathMatch {
    fn matches(&self, path: &str) -> bool {
        match self {
            PathMatch::Any => true,
            PathMatch::Prefix(p) => path.starts_with(p.as_str()),
        }
    }
}

/// Drop a single leading dot so `.example.com` and `example.com` behave alike.
fn normalize_suffix(domain: &str) -> String {
    domain.strip_prefix('.').unwrap_or(domain).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_tunnels_everything() {
        let p = ScopePolicy::new();
        assert_eq!(
            p.evaluate("https", "example.com", 443, "/"),
            ScopeDecision::Passthrough
        );
    }

    #[test]
    fn host_suffix_matches_apex_and_subdomains_but_not_siblings() {
        let p = ScopePolicy::host_suffix("example.com");
        assert_eq!(
            p.evaluate("https", "example.com", 443, "/"),
            ScopeDecision::InScope
        );
        assert_eq!(
            p.evaluate("https", "api.example.com", 443, "/"),
            ScopeDecision::InScope
        );
        // Not a subdomain, just a suffix collision.
        assert_eq!(
            p.evaluate("https", "notexample.com", 443, "/"),
            ScopeDecision::OutOfScope
        );
        // Different domain entirely.
        assert_eq!(
            p.evaluate("https", "evil.com", 443, "/"),
            ScopeDecision::OutOfScope
        );
    }

    #[test]
    fn leading_dot_suffix_is_normalized() {
        let p = ScopePolicy::host_suffix(".example.com");
        assert_eq!(
            p.evaluate("http", "example.com", 80, "/"),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let p = ScopePolicy::new().including(Rule::host("Example.COM"));
        assert_eq!(
            p.evaluate("https", "example.com", 443, "/"),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn exclude_wins_over_include() {
        let p = ScopePolicy::host_suffix("example.com")
            .excluding(Rule::host("admin.example.com"));
        assert_eq!(
            p.evaluate("https", "api.example.com", 443, "/"),
            ScopeDecision::InScope
        );
        // Excluded subdomain is explicitly tunnelled.
        assert_eq!(
            p.evaluate("https", "admin.example.com", 443, "/"),
            ScopeDecision::Passthrough
        );
    }

    #[test]
    fn scheme_port_and_path_constraints_apply() {
        let p = ScopePolicy::new().including(
            Rule::host_suffix("example.com")
                .with_scheme(SchemeMatch::Https)
                .on_port(443)
                .with_path_prefix("/api/"),
        );
        assert_eq!(
            p.evaluate("https", "example.com", 443, "/api/users"),
            ScopeDecision::InScope
        );
        // Wrong scheme.
        assert_eq!(
            p.evaluate("http", "example.com", 443, "/api/users"),
            ScopeDecision::OutOfScope
        );
        // Wrong port.
        assert_eq!(
            p.evaluate("https", "example.com", 8443, "/api/users"),
            ScopeDecision::OutOfScope
        );
        // Wrong path.
        assert_eq!(
            p.evaluate("https", "example.com", 443, "/public"),
            ScopeDecision::OutOfScope
        );
    }

    #[test]
    fn works_through_the_trait_object() {
        let decider: std::sync::Arc<dyn ScopeDecider> =
            std::sync::Arc::new(ScopePolicy::host_suffix("example.com"));
        assert_eq!(
            decider.decide("https", "example.com", 443, "/"),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn policy_round_trips_through_json() {
        let p = ScopePolicy::host_suffix("example.com")
            .excluding(Rule::host("admin.example.com").with_path_prefix("/x"));
        let json = serde_json::to_string(&p).unwrap();
        let back: ScopePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn rule_json_uses_snake_case_tags() {
        let json = serde_json::to_string(&Rule::host_suffix("example.com")).unwrap();
        // Matcher variants serialize as snake_case, externally tagged.
        assert!(json.contains("\"suffix\""), "got: {json}");
        assert!(json.contains("\"any\""), "got: {json}");
    }
}
