//! elliot-intruder — automated multi-point attacks.
//!
//! Takes a base raw request, a set of **injection points** (byte ranges in the
//! base to substitute), **payload sets**, and an **attack mode**, expands them
//! into concrete requests, and replays each through [`elliot_repeater`] with
//! bounded concurrency, collecting per-request metrics.
//!
//! Like the repeater, the base request and every mutated request are sent
//! **byte-exact** — the point is to probe with crafted and malformed input.
//! Payloads are therefore raw bytes ([`Payload`]); a fuzzer must be able to send
//! values that are not valid UTF-8.
//!
//! Scope is checked **once, before anything is sent**: the attack's target host
//! must be [`ScopeDecision::InScope`], or [`run`] refuses and sends nothing.
//!
//! # Attack modes (Burp-compatible semantics)
//! - **Sniper**: one payload set; one position at a time, the rest left as-is.
//! - **Battering ram**: one payload set; the same payload in every position.
//! - **Pitchfork**: one payload set per position; iterated in lockstep.
//! - **Cluster bomb**: one payload set per position; full cartesian product.
//!
//! # Concurrency and limits
//!
//! Requests in flight are capped by [`Attack::concurrency`], and jobs are pulled
//! only as a slot frees up (a bounded stream, not one task spawned per job).
//!
//! The *plan* is still materialised: [`plan`] expands the whole job list in
//! memory, so a cluster bomb over several large sets grows as their cartesian
//! product. Streaming the expansion lazily is a known follow-up.

use std::ops::Range;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{self, StreamExt};

use elliot_httpraw::{ScopeDecider, ScopeDecision, Transport};
use elliot_repeater::{ReadMode, RepeatRequest, DEFAULT_READ_TIMEOUT};

/// One injection payload: raw bytes, so malformed and non-UTF-8 probes work.
pub type Payload = Vec<u8>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

/// A configured attack.
///
/// The target and the base are protocol-agnostic: the base is whatever bytes
/// came off a captured [`elliot_httpraw::Message`] (or were typed), and the
/// transport/read mode are those of the [`elliot_repeater`] that carries it.
#[derive(Clone, Debug)]
pub struct Attack {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The base request, sent byte-exact with injection points substituted.
    pub base: Bytes,
    /// Byte ranges in `base` to replace. Must be sorted, non-overlapping, and
    /// within `base`.
    pub positions: Vec<Range<usize>>,
    /// Payload sets. One set for Sniper/BatteringRam; one set **per position**
    /// for Pitchfork/ClusterBomb.
    pub payloads: Vec<Vec<Payload>>,
    pub mode: AttackMode,
    /// Maximum requests in flight at once (clamped to at least 1).
    pub concurrency: usize,
    /// Per-request response timeout.
    pub read_timeout: Duration,
    pub accept_invalid_certs: bool,
    /// TCP (stream) or UDP (datagram). Defaults to TCP.
    pub transport: Transport,
    /// How each response is framed. Defaults to [`ReadMode::Http`].
    pub read_mode: ReadMode,
}

impl Attack {
    pub fn new(host: impl Into<String>, port: u16, base: impl Into<Bytes>) -> Self {
        Self {
            host: host.into(),
            port,
            tls: false,
            base: base.into(),
            positions: Vec::new(),
            payloads: Vec::new(),
            mode: AttackMode::Sniper,
            concurrency: 8,
            read_timeout: DEFAULT_READ_TIMEOUT,
            accept_invalid_certs: false,
            transport: Transport::Tcp,
            read_mode: ReadMode::Http,
        }
    }

    /// Replay over UDP (one datagram per request).
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// How each response ends — see [`ReadMode`].
    pub fn with_read_mode(mut self, read_mode: ReadMode) -> Self {
        self.read_mode = read_mode;
        self
    }

    /// Payload sets for Sniper/Battering ram: a single set, from strings.
    ///
    /// The common case is textual, and building `Vec<Vec<u8>>` by hand is noisy;
    /// payloads are still stored as bytes.
    pub fn payloads_from_str(set: &[&str]) -> Vec<Vec<Payload>> {
        vec![bytes_of(set)]
    }

    /// Payload sets for Pitchfork/Cluster bomb: one set **per position**.
    pub fn payload_sets_from_str(sets: &[&[&str]]) -> Vec<Vec<Payload>> {
        sets.iter().map(|set| bytes_of(set)).collect()
    }
}

fn bytes_of(set: &[&str]) -> Vec<Payload> {
    set.iter().map(|s| s.as_bytes().to_vec()).collect()
}

/// One request's outcome.
#[derive(Clone, Debug)]
pub struct AttackResult {
    /// Position of this request in the generated sequence.
    pub index: usize,
    /// (position index, payload) pairs applied to the base.
    pub assignments: Vec<(usize, Payload)>,
    pub status: Option<u16>,
    pub response_len: usize,
    pub elapsed: Duration,
    pub error: Option<String>,
}

/// Aggregate metrics over a completed attack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttackSummary {
    pub total: usize,
    pub responses: usize,
    pub errors: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum IntruderError {
    #[error("no injection positions configured")]
    NoPositions,
    #[error("position {range:?} is out of bounds for a {len}-byte base")]
    PositionOutOfBounds { range: Range<usize>, len: usize },
    #[error("positions must be sorted and non-overlapping")]
    OverlappingPositions,
    #[error("{mode:?} needs {expected} payload set(s), got {got}")]
    PayloadSetCount {
        mode: AttackMode,
        expected: String,
        got: usize,
    },
    #[error("a payload set is empty")]
    EmptyPayloadSet,
    #[error("target {host}:{port} is not in scope ({decision:?})")]
    OutOfScope {
        host: String,
        port: u16,
        decision: ScopeDecision,
    },
}

/// Validate the attack and expand it into the concrete jobs that would run,
/// without sending anything. Useful for a dry-run / preview.
///
/// Materialises the whole expansion; see the crate docs for the limit.
pub fn plan(attack: &Attack) -> Result<Vec<Vec<(usize, Payload)>>, IntruderError> {
    validate_positions(&attack.base, &attack.positions)?;
    validate_payloads(attack)?;
    Ok(expand_jobs(attack))
}

/// Run the attack: scope-check the target, then replay every generated request
/// with bounded concurrency. Results are returned in generation order.
pub async fn run(
    attack: &Attack,
    scope: &dyn ScopeDecider,
) -> Result<(Vec<AttackResult>, AttackSummary), IntruderError> {
    let mut results = Vec::new();
    let summary = run_streaming(attack, scope, &mut |r| results.push(r.clone())).await?;
    results.sort_by_key(|r| r.index);
    Ok((results, summary))
}

/// Run the attack and hand each result to `on_result` **as it completes**
/// (completion order, not generation order), returning the aggregate metrics.
///
/// This is what the app uses: an attack over a slow target can run for minutes,
/// and a result table that fills in as replies arrive is far more useful than
/// one that appears all at once. [`run`] is the collecting wrapper.
pub async fn run_streaming(
    attack: &Attack,
    scope: &dyn ScopeDecider,
    // `Send` so the future stays `Send`: the app runs this on a runtime that
    // requires it for the command to be spawnable.
    on_result: &mut (dyn FnMut(&AttackResult) + Send),
) -> Result<AttackSummary, IntruderError> {
    let jobs = plan(attack)?;

    // The scope token follows the transport: a UDP attack is not an HTTP one,
    // and the policy must be able to tell them apart (rules that do not name a
    // transport still match, since `SchemeMatch::Any` is the default).
    let scheme = match (attack.transport, attack.tls) {
        (Transport::Udp, _) => "udp",
        (Transport::Tcp, true) => "https",
        (Transport::Tcp, false) => "http",
    };
    let decision = scope.decide(scheme, &attack.host, attack.port, "");
    if decision != ScopeDecision::InScope {
        return Err(IntruderError::OutOfScope {
            host: attack.host.clone(),
            port: attack.port,
            decision,
        });
    }

    // Build each request lazily from the job list, then replay with bounded
    // concurrency. `buffer_unordered` pulls a job only when a slot frees, so the
    // attack never spawns one task per job up front.
    let requests = jobs.into_iter().enumerate().map(|(index, assignments)| {
        let raw = apply_with(&attack.base, &attack.positions, &assignments);
        let req = RepeatRequest {
            host: attack.host.clone(),
            port: attack.port,
            tls: attack.tls,
            raw,
            read_timeout: attack.read_timeout,
            accept_invalid_certs: attack.accept_invalid_certs,
            transport: attack.transport,
            read_mode: attack.read_mode,
        };
        (index, assignments, req)
    });

    let mut in_flight = stream::iter(requests)
        .map(|(index, assignments, req)| async move {
            match elliot_repeater::send(req).await {
                Ok(resp) => AttackResult {
                    index,
                    assignments,
                    // Parsed status is `None` for non-HTTP replies; the byte
                    // count is what the table shows for those.
                    status: resp.response.as_ref().map(|r| r.status),
                    response_len: resp.raw.len(),
                    elapsed: resp.elapsed,
                    error: None,
                },
                Err(e) => AttackResult {
                    index,
                    assignments,
                    status: None,
                    response_len: 0,
                    elapsed: Duration::ZERO,
                    error: Some(e.to_string()),
                },
            }
        })
        .buffer_unordered(attack.concurrency.max(1));

    let mut summary = AttackSummary::default();
    while let Some(result) = in_flight.next().await {
        summary.total += 1;
        if result.error.is_none() {
            summary.responses += 1;
        } else {
            summary.errors += 1;
        }
        on_result(&result);
    }
    Ok(summary)
}

// --- validation + expansion -------------------------------------------------

fn validate_positions(base: &[u8], positions: &[Range<usize>]) -> Result<(), IntruderError> {
    if positions.is_empty() {
        return Err(IntruderError::NoPositions);
    }
    let mut prev_end = 0usize;
    for (i, r) in positions.iter().enumerate() {
        if r.start > r.end || r.end > base.len() {
            return Err(IntruderError::PositionOutOfBounds {
                range: r.clone(),
                len: base.len(),
            });
        }
        if i > 0 && r.start < prev_end {
            return Err(IntruderError::OverlappingPositions);
        }
        prev_end = r.end;
    }
    Ok(())
}

fn validate_payloads(attack: &Attack) -> Result<(), IntruderError> {
    let n = attack.positions.len();
    let (expected, ok) = match attack.mode {
        AttackMode::Sniper | AttackMode::BatteringRam => {
            ("1".to_string(), attack.payloads.len() == 1)
        }
        AttackMode::Pitchfork | AttackMode::ClusterBomb => {
            (format!("{n} (one per position)"), attack.payloads.len() == n)
        }
    };
    if !ok {
        return Err(IntruderError::PayloadSetCount {
            mode: attack.mode,
            expected,
            got: attack.payloads.len(),
        });
    }
    if attack.payloads.iter().any(|s| s.is_empty()) {
        return Err(IntruderError::EmptyPayloadSet);
    }
    Ok(())
}

fn expand_jobs(attack: &Attack) -> Vec<Vec<(usize, Payload)>> {
    let n = attack.positions.len();
    match attack.mode {
        AttackMode::Sniper => {
            let set = &attack.payloads[0];
            let mut jobs = Vec::with_capacity(n * set.len());
            for pos in 0..n {
                for pl in set {
                    jobs.push(vec![(pos, pl.clone())]);
                }
            }
            jobs
        }
        AttackMode::BatteringRam => {
            let set = &attack.payloads[0];
            set.iter()
                .map(|pl| (0..n).map(|pos| (pos, pl.clone())).collect())
                .collect()
        }
        AttackMode::Pitchfork => {
            let len = attack.payloads.iter().map(|s| s.len()).min().unwrap_or(0);
            (0..len)
                .map(|i| (0..n).map(|pos| (pos, attack.payloads[pos][i].clone())).collect())
                .collect()
        }
        AttackMode::ClusterBomb => {
            let mut jobs: Vec<Vec<(usize, Payload)>> = vec![Vec::new()];
            for (pos, set) in attack.payloads.iter().enumerate() {
                let mut next = Vec::with_capacity(jobs.len() * set.len());
                for prefix in &jobs {
                    for pl in set {
                        let mut j = prefix.clone();
                        j.push((pos, pl.clone()));
                        next.push(j);
                    }
                }
                jobs = next;
            }
            jobs
        }
    }
}

/// Apply replacements to the base. Assignments carry a position *index*; the
/// actual byte range comes from `positions`. Substituting from the rightmost
/// position first keeps earlier byte offsets valid as lengths change.
fn apply_with(base: &[u8], positions: &[Range<usize>], assignments: &[(usize, Payload)]) -> Bytes {
    let mut out = base.to_vec();
    let mut ordered: Vec<&(usize, Payload)> = assignments.iter().collect();
    ordered.sort_by_key(|(pos, _)| std::cmp::Reverse(*pos));
    for (pos, value) in ordered {
        let range = positions[*pos].clone();
        out.splice(range, value.iter().copied());
    }
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliot_scope::ScopePolicy;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn sniper_expands_one_position_at_a_time() {
        let base = Bytes::from_static(b"GET /AAA?x=BBB HTTP/1.1\r\n\r\n");
        // positions over AAA (5..8) and BBB (11..14)
        let attack = Attack {
            positions: vec![5..8, 11..14],
            payloads: Attack::payloads_from_str(&["1", "2"]),
            mode: AttackMode::Sniper,
            ..Attack::new("h", 80, base)
        };
        let jobs = plan(&attack).unwrap();
        // 2 positions * 2 payloads = 4 jobs, each assigning exactly one position
        assert_eq!(jobs.len(), 4);
        assert!(jobs.iter().all(|j| j.len() == 1));
    }

    #[test]
    fn cluster_bomb_is_cartesian() {
        let base = Bytes::from_static(b"AA BB");
        let attack = Attack {
            positions: vec![0..2, 3..5],
            payloads: Attack::payload_sets_from_str(&[&["1", "2"], &["x", "y", "z"]]),
            mode: AttackMode::ClusterBomb,
            ..Attack::new("h", 80, base)
        };
        let jobs = plan(&attack).unwrap();
        assert_eq!(jobs.len(), 6); // 2 * 3
    }

    #[test]
    fn overlapping_positions_are_rejected() {
        let attack = Attack {
            positions: vec![0..3, 2..5],
            payloads: Attack::payloads_from_str(&["a"]),
            mode: AttackMode::Sniper,
            ..Attack::new("h", 80, Bytes::from_static(b"abcdef"))
        };
        assert!(matches!(plan(&attack), Err(IntruderError::OverlappingPositions)));
    }

    #[test]
    fn pitchfork_requires_one_set_per_position() {
        let attack = Attack {
            positions: vec![0..1, 2..3],
            payloads: Attack::payloads_from_str(&["a"]), // only one set
            mode: AttackMode::Pitchfork,
            ..Attack::new("h", 80, Bytes::from_static(b"a b"))
        };
        assert!(matches!(
            plan(&attack),
            Err(IntruderError::PayloadSetCount { .. })
        ));
    }

    async fn counting_server() -> (std::net::SocketAddr, Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    buf.truncate(n);
                    seen.lock().await.push(buf);
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                        .await;
                    let _ = sock.flush().await;
                });
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn battering_ram_runs_and_collects_results() {
        let (addr, seen) = counting_server().await;
        let base = Bytes::from_static(b"GET /PAYLOAD HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
        let payload_point = 5..12; // "PAYLOAD"
        let attack = Attack {
            positions: vec![payload_point],
            payloads: Attack::payloads_from_str(&["a", "bb", "ccc"]),
            mode: AttackMode::BatteringRam,
            read_timeout: Duration::from_secs(2),
            ..Attack::new(addr.ip().to_string(), addr.port(), base)
        };
        let (results, summary) = run(&attack, &ScopePolicy::host_suffix(&addr.ip().to_string()))
            .await
            .unwrap();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.responses, 3);
        assert!(results.iter().all(|r| r.status == Some(200)));
        // Give the last server task a moment, then check it saw 3 requests.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(seen.lock().await.len(), 3);
    }

    #[tokio::test]
    async fn out_of_scope_target_sends_nothing() {
        let (addr, seen) = counting_server().await;
        let first_byte = 0..1;
        let attack = Attack {
            positions: vec![first_byte],
            payloads: Attack::payloads_from_str(&["a"]),
            mode: AttackMode::Sniper,
            ..Attack::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"XGET"))
        };
        // Scope allows only example.com, not 127.0.0.1.
        let err = run(&attack, &ScopePolicy::host_suffix("example.com"))
            .await
            .unwrap_err();
        assert!(matches!(err, IntruderError::OutOfScope { .. }));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(seen.lock().await.len(), 0, "nothing should be sent out of scope");
    }

    /// A byte range, built through a call so `vec![point(a, b)]` is not read as
    /// a single-range vector initialisation (clippy's `single_range_in_vec_init`).
    fn point(start: usize, end: usize) -> Range<usize> {
        start..end
    }

    /// A line-protocol server: reads one request, answers `+OK <request>` and
    /// then **stays open**, so only the read mode can end the reply.
    async fn line_server() -> (std::net::SocketAddr, Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    buf.truncate(n);
                    seen.lock().await.push(buf.clone());
                    let mut reply = b"+OK ".to_vec();
                    reply.extend_from_slice(&buf);
                    let _ = sock.write_all(&reply).await;
                    let _ = sock.flush().await;
                    tokio::time::sleep(Duration::from_millis(400)).await;
                });
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn battering_ram_runs_against_a_non_http_protocol() {
        let (addr, seen) = line_server().await;
        let base = Bytes::from_static(b"GET key\r\n");
        let attack = Attack {
            positions: vec![point(4, 7)], // "key"
            payloads: Attack::payloads_from_str(&["a", "bb"]),
            mode: AttackMode::BatteringRam,
            read_mode: ReadMode::UntilIdle(Duration::from_millis(80)),
            read_timeout: Duration::from_secs(2),
            ..Attack::new(addr.ip().to_string(), addr.port(), base)
        };
        let (results, summary) = run(&attack, &ScopePolicy::host_suffix(&addr.ip().to_string()))
            .await
            .unwrap();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.responses, 2);
        assert_eq!(summary.errors, 0);
        // Non-HTTP replies have no parsed status, but the bytes were read.
        assert!(results.iter().all(|r| r.status.is_none()));
        assert!(results.iter().all(|r| r.response_len > 0));

        tokio::time::sleep(Duration::from_millis(80)).await;
        let got = seen.lock().await;
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|r| r == b"GET a\r\n"));
        assert!(got.iter().any(|r| r == b"GET bb\r\n"));
    }

    #[tokio::test]
    async fn run_streaming_hands_every_result_to_the_callback() {
        let (addr, _seen) = line_server().await;
        let attack = Attack {
            positions: vec![point(4, 7)],
            payloads: Attack::payloads_from_str(&["a", "b", "c"]),
            mode: AttackMode::Sniper,
            read_mode: ReadMode::UntilIdle(Duration::from_millis(60)),
            read_timeout: Duration::from_secs(2),
            ..Attack::new(addr.ip().to_string(), addr.port(), Bytes::from_static(b"GET key\r\n"))
        };

        let mut streamed: Vec<AttackResult> = Vec::new();
        let summary = run_streaming(&attack, &ScopePolicy::host_suffix(&addr.ip().to_string()), &mut |r| {
            streamed.push(r.clone())
        })
        .await
        .unwrap();

        assert_eq!(summary.total, 3);
        assert_eq!(streamed.len(), 3, "every result is reported exactly once");
        let mut indices: Vec<usize> = streamed.iter().map(|r| r.index).collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![0, 1, 2]);
    }

    /// Payloads are bytes: a value that is not valid UTF-8 must reach the wire
    /// unchanged, and come back in the result's assignments.
    #[tokio::test]
    async fn binary_payload_is_sent_unchanged() {
        let (addr, seen) = counting_server().await;
        let base = Bytes::from_static(b"GET /AB HTTP/1.1\r\nHost: t\r\n\r\n");
        let binary: Payload = vec![0x00, 0xFF, 0x0A, 0x0D];
        let injection_point = 5..7; // "AB"

        let attack = Attack {
            positions: vec![injection_point],
            payloads: vec![vec![binary.clone()]],
            mode: AttackMode::Sniper,
            read_timeout: Duration::from_secs(2),
            ..Attack::new(addr.ip().to_string(), addr.port(), base)
        };
        let (results, summary) =
            run(&attack, &ScopePolicy::host_suffix(&addr.ip().to_string()))
                .await
                .unwrap();

        assert_eq!(summary.total, 1);
        assert_eq!(summary.responses, 1);
        assert_eq!(results[0].assignments, vec![(0, binary.clone())]);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let sent = seen.lock().await;
        assert_eq!(sent.len(), 1, "exactly one request is sent");
        let mut expected: Vec<u8> = b"GET /".to_vec();
        expected.extend_from_slice(&binary);
        expected.extend_from_slice(b" HTTP/1.1\r\nHost: t\r\n\r\n");
        assert_eq!(sent[0], expected, "payload bytes reach the wire verbatim");
    }
}
