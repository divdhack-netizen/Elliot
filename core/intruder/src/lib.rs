//! elliot-intruder — automated multi-point attacks.
//!
//! Takes a base raw request, a set of **injection points** (byte ranges in the
//! base to substitute), **payload sets**, and an **attack mode**, expands them
//! into concrete requests, and replays each through [`elliot_repeater`] with
//! bounded concurrency, collecting per-request metrics.
//!
//! Like the repeater, the base request and every mutated request are sent
//! **byte-exact** — the point is to probe with crafted and malformed input.
//!
//! Scope is checked **once, before anything is sent**: the attack's target host
//! must be [`ScopeDecision::InScope`], or [`run`] refuses and sends nothing.
//!
//! # Attack modes (Burp-compatible semantics)
//! - **Sniper**: one payload set; one position at a time, the rest left as-is.
//! - **Battering ram**: one payload set; the same payload in every position.
//! - **Pitchfork**: one payload set per position; iterated in lockstep.
//! - **Cluster bomb**: one payload set per position; full cartesian product.

use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use elliot_httpraw::{ScopeDecider, ScopeDecision};
use elliot_repeater::{RepeatRequest, DEFAULT_READ_TIMEOUT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

/// A configured attack.
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
    pub payloads: Vec<Vec<String>>,
    pub mode: AttackMode,
    /// Maximum requests in flight at once (clamped to at least 1).
    pub concurrency: usize,
    /// Per-request response timeout.
    pub read_timeout: Duration,
    pub accept_invalid_certs: bool,
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
        }
    }
}

/// One request's outcome.
#[derive(Clone, Debug)]
pub struct AttackResult {
    /// Position of this request in the generated sequence.
    pub index: usize,
    /// (position index, payload) pairs applied to the base.
    pub assignments: Vec<(usize, String)>,
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
pub fn plan(attack: &Attack) -> Result<Vec<Vec<(usize, String)>>, IntruderError> {
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
    let jobs = plan(attack)?;

    let scheme = if attack.tls { "https" } else { "http" };
    let decision = scope.decide(scheme, &attack.host, attack.port, "");
    if decision != ScopeDecision::InScope {
        return Err(IntruderError::OutOfScope {
            host: attack.host.clone(),
            port: attack.port,
            decision,
        });
    }

    let permits = Arc::new(tokio::sync::Semaphore::new(attack.concurrency.max(1)));
    let mut handles = Vec::with_capacity(jobs.len());

    for (index, assignments) in jobs.into_iter().enumerate() {
        let body = apply_with(&attack.base, &attack.positions, &assignments);
        let req = RepeatRequest {
            host: attack.host.clone(),
            port: attack.port,
            tls: attack.tls,
            raw: body,
            read_timeout: attack.read_timeout,
            accept_invalid_certs: attack.accept_invalid_certs,
        };
        let permits = permits.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permits.acquire_owned().await.expect("semaphore open");
            let outcome = elliot_repeater::send(req).await;
            (index, assignments, outcome)
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        let (index, assignments, outcome) = h.await.expect("intruder task panicked");
        let result = match outcome {
            Ok(resp) => AttackResult {
                index,
                assignments,
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
        };
        results.push(result);
    }
    results.sort_by_key(|r| r.index);

    let summary = AttackSummary {
        total: results.len(),
        responses: results.iter().filter(|r| r.error.is_none()).count(),
        errors: results.iter().filter(|r| r.error.is_some()).count(),
    };
    Ok((results, summary))
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

fn expand_jobs(attack: &Attack) -> Vec<Vec<(usize, String)>> {
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
            let mut jobs: Vec<Vec<(usize, String)>> = vec![Vec::new()];
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
fn apply_with(base: &[u8], positions: &[Range<usize>], assignments: &[(usize, String)]) -> Bytes {
    let mut out = base.to_vec();
    let mut ordered: Vec<&(usize, String)> = assignments.iter().collect();
    ordered.sort_by_key(|(pos, _)| std::cmp::Reverse(*pos));
    for (pos, value) in ordered {
        let range = positions[*pos].clone();
        out.splice(range, value.bytes());
    }
    Bytes::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliot_scope::ScopePolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn sniper_expands_one_position_at_a_time() {
        let base = Bytes::from_static(b"GET /AAA?x=BBB HTTP/1.1\r\n\r\n");
        // positions over AAA (5..8) and BBB (11..14)
        let attack = Attack {
            positions: vec![5..8, 11..14],
            payloads: vec![vec!["1".into(), "2".into()]],
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
            payloads: vec![vec!["1".into(), "2".into()], vec!["x".into(), "y".into(), "z".into()]],
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
            payloads: vec![vec!["a".into()]],
            mode: AttackMode::Sniper,
            ..Attack::new("h", 80, Bytes::from_static(b"abcdef"))
        };
        assert!(matches!(plan(&attack), Err(IntruderError::OverlappingPositions)));
    }

    #[test]
    fn pitchfork_requires_one_set_per_position() {
        let attack = Attack {
            positions: vec![0..1, 2..3],
            payloads: vec![vec!["a".into()]], // only one set
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
            payloads: vec![vec!["a".into(), "bb".into(), "ccc".into()]],
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
            payloads: vec![vec!["a".into()]],
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
}
