//! Tauri wiring for active work on captured traffic: the repeater, the
//! intruder, and the "send to …" hand-offs that turn a captured message into a
//! prepared replay or attack.
//!
//! The wire format is deliberately token-based (`"tcp"`, `"untilIdle"`, …):
//! the frontend should not have to know how the core's enums are laid out, and
//! a token that this build does not understand must be an error, never a silent
//! fallback to something that sends bytes somewhere unplanned.

use std::sync::Arc;
use std::time::Duration;

use elliot_httpraw::{Message, Response, Stream, Transport};
use elliot_intruder::{Attack, AttackMode, AttackResult, Payload};
use elliot_repeater::{ReadMode, RepeatRequest};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::scope::ScopeState;

/// Idle window handed to the repeater/intruder for a captured message: long
/// enough for a local service to answer, short enough to feel instant. The user
/// edits it — it is a starting point, not a guess about the protocol.
const DEFAULT_IDLE_MS: u64 = 500;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_CONCURRENCY: usize = 8;

fn default_transport() -> String {
    "tcp".into()
}

fn default_read_mode() -> String {
    "http".into()
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_concurrency() -> usize {
    DEFAULT_CONCURRENCY
}

fn parse_transport(token: &str) -> Result<Transport, String> {
    match token.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Transport::Tcp),
        "udp" => Ok(Transport::Udp),
        other => Err(format!("unknown transport {other:?} (expected \"tcp\" or \"udp\")")),
    }
}

fn parse_read_mode(
    token: &str,
    idle_ms: Option<u64>,
    exact_bytes: Option<usize>,
) -> Result<ReadMode, String> {
    match token {
        "http" => Ok(ReadMode::Http),
        "untilIdle" => Ok(ReadMode::UntilIdle(Duration::from_millis(
            idle_ms.unwrap_or(DEFAULT_IDLE_MS).max(1),
        ))),
        "exact" => Ok(ReadMode::Exact(
            exact_bytes.ok_or("read mode \"exact\" requires exactBytes")?,
        )),
        "untilClose" => Ok(ReadMode::UntilClose),
        "datagram" => Ok(ReadMode::Datagram),
        other => Err(format!(
            "unknown read mode {other:?} (expected \"http\", \"untilIdle\", \"exact\", \
             \"untilClose\" or \"datagram\")"
        )),
    }
}

fn parse_attack_mode(token: &str) -> Result<AttackMode, String> {
    match token {
        "sniper" => Ok(AttackMode::Sniper),
        "batteringRam" => Ok(AttackMode::BatteringRam),
        "pitchfork" => Ok(AttackMode::Pitchfork),
        "clusterBomb" => Ok(AttackMode::ClusterBomb),
        other => Err(format!(
            "unknown attack mode {other:?} (expected \"sniper\", \"batteringRam\", \
             \"pitchfork\" or \"clusterBomb\")"
        )),
    }
}

/// A payload rendered for the results table: text when it is text, hex
/// otherwise, so a binary payload is still identifiable at a glance.
fn payload_label(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            format!("0x{hex}")
        }
    }
}

// --- repeater ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeatArgs {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub tls: bool,
    /// "tcp" or "udp".
    #[serde(default = "default_transport")]
    pub transport: String,
    /// "http", "untilIdle", "exact", "untilClose" or "datagram".
    #[serde(default = "default_read_mode")]
    pub read_mode: String,
    /// Idle window, for `untilIdle`.
    #[serde(default)]
    pub idle_ms: Option<u64>,
    /// Byte count, for `exact`.
    #[serde(default)]
    pub exact_bytes: Option<usize>,
    #[serde(default = "default_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    /// The bytes to send, verbatim.
    pub raw: Vec<u8>,
}

impl RepeatArgs {
    fn to_request(&self) -> Result<RepeatRequest, String> {
        Ok(RepeatRequest {
            host: self.host.clone(),
            port: self.port,
            tls: self.tls,
            raw: self.raw.clone().into(),
            read_timeout: Duration::from_millis(self.read_timeout_ms.max(1)),
            accept_invalid_certs: self.accept_invalid_certs,
            transport: parse_transport(&self.transport)?,
            read_mode: parse_read_mode(&self.read_mode, self.idle_ms, self.exact_bytes)?,
        })
    }

    /// The replay defaults for a captured message: same target and transport,
    /// and a read mode that suits a protocol with no framing (one datagram for
    /// UDP, an idle window for TCP). The user edits from there.
    fn from_capture(stream: &Stream, message: &Message) -> Self {
        let udp = stream.transport == Transport::Udp;
        Self {
            host: stream.host.clone(),
            port: stream.port,
            tls: stream.tls,
            transport: stream.transport.as_token().to_string(),
            read_mode: if udp { "datagram".into() } else { "untilIdle".into() },
            idle_ms: (!udp).then_some(DEFAULT_IDLE_MS),
            exact_bytes: None,
            read_timeout_ms: DEFAULT_TIMEOUT_MS,
            accept_invalid_certs: false,
            raw: message.data.to_vec(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeatReply {
    /// Exact bytes received, whatever the protocol.
    pub raw: Vec<u8>,
    /// Best-effort HTTP parse; `None` for a non-HTTP reply (the bytes are still
    /// in `raw`).
    pub response: Option<Response>,
    pub elapsed_ms: u64,
}

#[tauri::command]
pub async fn repeater_send(args: RepeatArgs) -> Result<RepeatReply, String> {
    let req = args.to_request()?;
    let res = elliot_repeater::send(req)
        .await
        .map_err(|e| e.to_string())?;
    Ok(RepeatReply {
        raw: res.raw.to_vec(),
        response: res.response,
        elapsed_ms: res.elapsed.as_millis() as u64,
    })
}

// --- intruder ---------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackArgs {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default = "default_read_mode")]
    pub read_mode: String,
    #[serde(default)]
    pub idle_ms: Option<u64>,
    #[serde(default)]
    pub exact_bytes: Option<usize>,
    #[serde(default = "default_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    /// The base request, sent byte-exact with injection points substituted.
    pub base: Vec<u8>,
    /// Injection points as `[start, end)` byte ranges.
    #[serde(default)]
    pub positions: Vec<(usize, usize)>,
    /// One payload set for Sniper/Battering ram; one **per position** for
    /// Pitchfork/Cluster bomb. Payloads are typed as text in the UI; the core
    /// still carries them as bytes.
    #[serde(default)]
    pub payload_sets: Vec<Vec<String>>,
    /// "sniper", "batteringRam", "pitchfork" or "clusterBomb".
    #[serde(default = "default_attack_mode")]
    pub mode: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
}

fn default_attack_mode() -> String {
    "sniper".into()
}

impl AttackArgs {
    fn to_attack(&self) -> Result<Attack, String> {
        let transport = parse_transport(&self.transport)?;
        let read_mode = parse_read_mode(&self.read_mode, self.idle_ms, self.exact_bytes)?;
        let mode = parse_attack_mode(&self.mode)?;
        let positions = self
            .positions
            .iter()
            .map(|(start, end)| *start..*end)
            .collect();
        let payloads: Vec<Vec<Payload>> = self
            .payload_sets
            .iter()
            .map(|set| set.iter().map(|p| p.as_bytes().to_vec()).collect())
            .collect();

        Ok(Attack {
            host: self.host.clone(),
            port: self.port,
            tls: self.tls,
            base: self.base.clone().into(),
            positions,
            payloads,
            mode,
            concurrency: self.concurrency.max(1),
            read_timeout: Duration::from_millis(self.read_timeout_ms.max(1)),
            accept_invalid_certs: self.accept_invalid_certs,
            transport,
            read_mode,
        })
    }

    /// The attack defaults for a captured message: the base is the captured
    /// bytes, no injection points yet (the user selects them) and the same
    /// non-HTTP read mode the repeater would use.
    fn from_capture(stream: &Stream, message: &Message) -> Self {
        let repeater = RepeatArgs::from_capture(stream, message);
        Self {
            host: repeater.host,
            port: repeater.port,
            tls: repeater.tls,
            transport: repeater.transport,
            read_mode: repeater.read_mode,
            idle_ms: repeater.idle_ms,
            exact_bytes: None,
            read_timeout_ms: repeater.read_timeout_ms,
            accept_invalid_certs: false,
            base: message.data.to_vec(),
            positions: Vec::new(),
            payload_sets: Vec::new(),
            mode: "sniper".into(),
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackSummaryReply {
    pub total: usize,
    pub responses: usize,
    pub errors: usize,
}

/// One result, as it reaches the UI. Payloads are rendered because the table
/// shows what was sent, not a byte vector.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackResultPayload {
    index: usize,
    assignments: Vec<String>,
    status: Option<u16>,
    response_len: usize,
    elapsed_ms: u64,
    error: Option<String>,
}

impl From<&AttackResult> for AttackResultPayload {
    fn from(r: &AttackResult) -> Self {
        Self {
            index: r.index,
            assignments: r
                .assignments
                .iter()
                .map(|(_, payload)| payload_label(payload))
                .collect(),
            status: r.status,
            response_len: r.response_len,
            elapsed_ms: r.elapsed.as_millis() as u64,
            error: r.error.clone(),
        }
    }
}

/// Run the attack, streaming each result as `intruder://result` while it runs,
/// and return the aggregate metrics when it is done.
#[tauri::command]
pub async fn intruder_run(
    app: AppHandle,
    scope: State<'_, Arc<ScopeState>>,
    args: AttackArgs,
) -> Result<AttackSummaryReply, String> {
    let attack = args.to_attack()?;
    // The scope gate lives inside the intruder: it refuses an out-of-scope
    // target before sending anything.
    let decider = scope.decider();

    let app_for_events = app.clone();
    let mut emit = |result: &AttackResult| {
        let payload = AttackResultPayload::from(result);
        let _ = app_for_events.emit("intruder://result", payload);
    };

    let summary = elliot_intruder::run_streaming(&attack, decider.as_ref(), &mut emit)
        .await
        .map_err(|e| e.to_string())?;

    Ok(AttackSummaryReply {
        total: summary.total,
        responses: summary.responses,
        errors: summary.errors,
    })
}

// --- send to repeater / intruder --------------------------------------------

/// Load a captured message and its stream from the open project.
///
/// Only persisted traffic can be replayed this way, which is exactly the
/// privacy rule: without a project, nothing was written, so there is nothing to
/// hand off.
async fn load_persisted(
    scope: &ScopeState,
    stream_id: Uuid,
    message_id: Uuid,
) -> Result<(Stream, Message), String> {
    scope
        .with_store(|store| {
            let stream = store
                .get_stream(stream_id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("stream {stream_id} is not in the open project"))?;
            let message = store
                .messages_for(stream_id)
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|m| m.id == message_id)
                .ok_or_else(|| format!("message {message_id} is not in the open project"))?;
            Ok((stream, message))
        })
        .await
        .ok_or_else(|| {
            "no project open: captured traffic is persisted only inside a project".to_string()
        })?
}

/// Prepare a repeater request from a captured message.
#[tauri::command]
pub async fn send_to_repeater(
    scope: State<'_, Arc<ScopeState>>,
    stream_id: Uuid,
    message_id: Uuid,
) -> Result<RepeatArgs, String> {
    let (stream, message) = load_persisted(&scope, stream_id, message_id).await?;
    Ok(RepeatArgs::from_capture(&stream, &message))
}

/// Prepare an intruder attack (base bytes, no positions yet) from a captured
/// message.
#[tauri::command]
pub async fn send_to_intruder(
    scope: State<'_, Arc<ScopeState>>,
    stream_id: Uuid,
    message_id: Uuid,
) -> Result<AttackArgs, String> {
    let (stream, message) = load_persisted(&scope, stream_id, message_id).await?;
    Ok(AttackArgs::from_capture(&stream, &message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(transport: Transport, tls: bool) -> (Stream, Message) {
        let stream = Stream {
            id: Uuid::new_v4(),
            started_at: std::time::SystemTime::now(),
            completed_at: None,
            client_addr: "127.0.0.1:51000".parse().unwrap(),
            transport,
            host: "redis.internal".into(),
            port: 6379,
            tls,
            scope: elliot_httpraw::ScopeDecision::InScope,
            state: elliot_httpraw::FlowState::Completed,
            error: None,
        };
        let message = Message {
            id: Uuid::new_v4(),
            stream_id: stream.id,
            seq: 0,
            at: std::time::SystemTime::now(),
            direction: elliot_httpraw::Direction::ClientToServer,
            data: b"PING\r\n".as_slice().into(),
        };
        (stream, message)
    }

    #[test]
    fn repeat_args_accept_camel_case() {
        let a: RepeatArgs = serde_json::from_str(
            r#"{"host":"h","port":6379,"readMode":"untilIdle","idleMs":250,"raw":[1,2]}"#,
        )
        .unwrap();
        assert_eq!(a.transport, "tcp", "the transport defaults to TCP");
        assert_eq!(a.read_mode, "untilIdle");
        assert_eq!(a.idle_ms, Some(250));
        assert_eq!(a.read_timeout_ms, DEFAULT_TIMEOUT_MS);
        let req = a.to_request().unwrap();
        assert_eq!(req.read_mode, ReadMode::UntilIdle(Duration::from_millis(250)));
    }

    #[test]
    fn unknown_tokens_are_errors_not_fallbacks() {
        let mut a: RepeatArgs =
            serde_json::from_str(r#"{"host":"h","port":1,"raw":[]}"#).unwrap();
        a.transport = "sctp".into();
        assert!(a.to_request().unwrap_err().contains("sctp"));

        let mut a: RepeatArgs =
            serde_json::from_str(r#"{"host":"h","port":1,"raw":[]}"#).unwrap();
        a.read_mode = "whenever".into();
        assert!(a.to_request().unwrap_err().contains("whenever"));
    }

    #[test]
    fn exact_needs_a_length() {
        let a: RepeatArgs = serde_json::from_str(
            r#"{"host":"h","port":1,"readMode":"exact","raw":[]}"#,
        )
        .unwrap();
        assert!(a.to_request().unwrap_err().contains("exactBytes"));
    }

    #[test]
    fn a_captured_tcp_message_becomes_an_idle_framed_replay() {
        let (stream, message) = captured(Transport::Tcp, false);
        let args = RepeatArgs::from_capture(&stream, &message);
        assert_eq!(args.host, "redis.internal");
        assert_eq!(args.port, 6379);
        assert_eq!(args.raw, b"PING\r\n".to_vec());
        assert_eq!(args.read_mode, "untilIdle");
        let req = args.to_request().unwrap();
        assert_eq!(req.transport, Transport::Tcp);
        assert!(matches!(req.read_mode, ReadMode::UntilIdle(_)));
    }

    #[test]
    fn a_captured_udp_message_becomes_a_datagram_replay() {
        let (stream, message) = captured(Transport::Udp, false);
        let args = RepeatArgs::from_capture(&stream, &message);
        assert_eq!(args.read_mode, "datagram");
        assert_eq!(args.idle_ms, None);
        let req = args.to_request().unwrap();
        assert_eq!(req.transport, Transport::Udp);
        assert_eq!(req.read_mode, ReadMode::Datagram);
    }

    #[test]
    fn a_captured_message_becomes_an_attack_with_no_positions_yet() {
        let (stream, message) = captured(Transport::Tcp, true);
        let args = AttackArgs::from_capture(&stream, &message);
        assert_eq!(args.base, b"PING\r\n".to_vec());
        assert!(args.tls);
        assert!(args.positions.is_empty());
        let attack = args.to_attack().unwrap();
        assert_eq!(attack.mode, AttackMode::Sniper);
        assert_eq!(attack.read_mode, ReadMode::UntilIdle(Duration::from_millis(DEFAULT_IDLE_MS)));
    }

    #[test]
    fn attack_payload_sets_and_positions_map_to_the_core_types() {
        let a: AttackArgs = serde_json::from_str(
            r#"{"host":"h","port":53,"transport":"udp","readMode":"datagram",
                "base":[1,2,3],"positions":[[0,2]],"payloadSets":[["a","bb"]],
                "mode":"batteringRam","concurrency":0}"#,
        )
        .unwrap();
        let attack = a.to_attack().unwrap();
        assert_eq!(attack.positions, vec![0..2]);
        assert_eq!(attack.payloads, vec![vec![b"a".to_vec(), b"bb".to_vec()]]);
        assert_eq!(attack.mode, AttackMode::BatteringRam);
        assert_eq!(attack.concurrency, 1, "concurrency is clamped to at least 1");
    }

    #[test]
    fn binary_payloads_are_labelled_as_hex() {
        assert_eq!(payload_label(b"hello"), "hello");
        assert_eq!(payload_label(&[0x00, 0xFF]), "0x00ff");
    }

    // --- end to end: capture through SOCKS -> project store -> replay -------

    /// A line-protocol origin: reads one request, answers `+OK <request>`.
    /// No HTTP framing anywhere, so the replay has to be framed by the read
    /// mode rather than by the protocol.
    async fn line_origin() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let mut reply = b"+OK ".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = sock.write_all(&reply).await;
                    let _ = sock.flush().await;
                    // Stay open briefly: the reply must be complete because the
                    // read mode says so, not because the peer closed.
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                });
            }
        });
        addr
    }

    /// Drive the listener the way a real client does: handshake, then CONNECT.
    /// Returns the tunnel, already connected through the SOCKS listener.
    async fn socks_connect(socks: std::net::SocketAddr, target: std::net::SocketAddr) -> tokio::net::TcpStream {
        use elliot_socks::protocol;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut sock = tokio::net::TcpStream::connect(socks).await.unwrap();
        sock.write_all(&[protocol::VERSION, 1, protocol::METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method = [0u8; 2];
        sock.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [protocol::VERSION, protocol::METHOD_NO_AUTH]);

        let mut request = vec![protocol::VERSION, protocol::CMD_CONNECT, 0x00];
        request.extend_from_slice(&protocol::encode_address(&protocol::Target::Ip(
            target.ip(),
            target.port(),
        )));
        sock.write_all(&request).await.unwrap();
        sock.flush().await.unwrap();
        let mut reply = [0u8; 10];
        sock.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], protocol::REP_SUCCEEDED, "CONNECT should succeed");
        sock
    }

    /// The whole path the app runs, without the UI: a real client captured by
    /// the SOCKS listener, every event persisted into an open project, and the
    /// captured bytes then replayed by the repeater against the same target.
    #[tokio::test]
    async fn a_socks_capture_is_persisted_and_replayed_by_the_repeater() {
        use crate::scope::ScopeState;
        use elliot_httpraw::{Direction, FlowState as State, Message as RawMessage};
        use elliot_socks::{SocksConfig, StreamEvent};
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let origin = line_origin().await;

        // An open project: without one the pump persists nothing (by design).
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project.elliot");
        let scope = Arc::new(ScopeState::new(project.clone()));
        scope.create_project(project, "pw").await.unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let handle = elliot_socks::start(
            SocksConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                mitm_tls: false,
                verify_upstream: true,
                ca_dir: dir.path().join("ca"),
                credentials: None,
            },
            Arc::new(elliot_httpraw::AllowAll),
            tx,
        )
        .await
        .unwrap();

        // One request through the listener, then close: the relay half-closes
        // and the stream completes.
        let mut client = socks_connect(handle.local_addr(), origin).await;
        client.write_all(b"GET key\r\n").await.unwrap();
        client.flush().await.unwrap();
        let mut echoed = [0u8; 13];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"+OK GET key\r\n");
        drop(client);

        // What the app's pump does with each event: persist it.
        let mut stream_id = None;
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a capture event should arrive")
                .expect("the event channel should stay open");
            match ev {
                StreamEvent::StreamStarted(stream) => {
                    stream_id = Some(stream.id);
                    crate::socks::persist_stream(&scope, &stream).await;
                }
                StreamEvent::Message(message) => {
                    crate::socks::persist_message(&scope, &message).await;
                }
                StreamEvent::StreamCompleted(stream) => {
                    crate::socks::persist_stream(&scope, &stream).await;
                    break;
                }
                StreamEvent::Error(e) => panic!("unexpected listener error: {e}"),
            }
        }
        let stream_id = stream_id.expect("a stream started");
        handle.stop().await;

        // Read it back from the project: the store is the source of truth the
        // hand-off is built from.
        let (stream, messages) = scope
            .with_store(|store| {
                let stream = store
                    .get_stream(stream_id)
                    .expect("read the stream")
                    .expect("the stream was persisted");
                let messages = store.messages_for(stream_id).expect("read the messages");
                (stream, messages)
            })
            .await
            .expect("a project is open");

        assert_eq!(stream.host, origin.ip().to_string());
        assert_eq!(stream.port, origin.port());
        assert!(!stream.tls);
        assert_eq!(stream.state, State::Completed, "the terminal state was written last");

        let request: &RawMessage = messages
            .iter()
            .find(|m| m.direction == Direction::ClientToServer)
            .expect("the request bytes were captured");
        assert_eq!(&request.data[..], b"GET key\r\n".as_slice());
        assert!(
            messages.iter().any(|m| m.direction == Direction::ServerToClient),
            "the reply was captured too"
        );

        // The hand-off, then the replay itself.
        let args = RepeatArgs::from_capture(&stream, request);
        assert_eq!(args.host, origin.ip().to_string());
        assert_eq!(args.raw, request.data.to_vec());
        let reply = elliot_repeater::send(args.to_request().unwrap())
            .await
            .expect("the origin answers the replay");
        assert_eq!(&reply.raw[..], b"+OK GET key\r\n".as_slice());
        assert!(
            reply.response.is_none(),
            "a non-HTTP reply has no parsed status: the bytes are the result"
        );
    }
}
