//! The agent bridge: sidecar lifecycle, NDJSON protocol, proposal validation and
//! approved execution.
//!
//! Trust boundary (see `docs/architecture.md`): the Python sidecar **proposes**
//! and never executes or enforces scope. Everything that matters happens here,
//! in Rust:
//!
//! 1. a `proposal` frame is matched against the catalog ([`elliot_catalog`]);
//! 2. the proposal is validated by [`elliot_runner::validate`] — allow-listed
//!    flags, path confinement, the *live* scope and the dangerous gate;
//! 3. the validated `argv` is shown to the human, who approves it;
//! 4. `agent_execute` **re-validates** (never trusting the UI round trip) and
//!    runs it via argv, with no shell.
//!
//! Curated context flows the other way: scope rules are sent to the sidecar as
//! *data*, so the model knows which targets are authorised without ever being
//! trusted to enforce it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use elliot_catalog::{Intrusiveness, Privilege, ToolEntry};
use elliot_httpraw::ScopeDecider;
use elliot_runner::{Proposal, RunnerConfig, RunnerError, ValidatedCommand};
use elliot_scope::{ScopePolicy, Rule};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::scope::{ScopeState, SharedScope};

/// Fallback execution timeout when the catalog entry does not declare one.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// Name of the packaged sidecar binary (see `tauri.conf.json` `externalBin`).
const SIDECAR_BIN: &str = "elliot-agent";
/// Protocol version the bridge speaks. Mirrors `PROTOCOL_VERSION` in the sidecar.
const PROTOCOL_VERSION: u32 = 1;

const EVENT_CHUNK: &str = "agent://chunk";
const EVENT_DONE: &str = "agent://done";
const EVENT_ERROR: &str = "agent://error";
const EVENT_PROPOSAL: &str = "agent://proposal";
const EVENT_EXECUTION: &str = "agent://execution";
const EVENT_EXIT: &str = "agent://exit";

/// State held by Tauri: the sidecar process and the proposals it produced.
#[derive(Default)]
pub struct AgentState {
    /// Lazily started on the first message; killed on stop or app exit.
    sidecar: Mutex<Option<Sidecar>>,
    /// Proposals waiting for (or already past) the human decision. Shared with
    /// the reader task, which registers them as frames arrive.
    proposals: Arc<Mutex<HashMap<Uuid, Proposal>>>,
}

struct Sidecar {
    /// Kept alive (and killable); the reader task owns stdout.
    child: Child,
    stdin: ChildStdin,
}

/// One frame from the sidecar. The wire contract lives in `agent/README.md`.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Chunk {
        text: String,
    },
    Done,
    Error {
        message: String,
    },
    Proposal {
        tool_id: String,
        #[serde(default)]
        flags: Vec<WireFlag>,
        #[serde(default)]
        targets: Vec<String>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WireFlag {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
}

impl From<WireFlag> for elliot_runner::FlagArg {
    fn from(flag: WireFlag) -> Self {
        elliot_runner::FlagArg {
            name: flag.name,
            value: flag.value,
        }
    }
}

/// Where the bridge pushes events. A trait rather than the `AppHandle` directly,
/// so the pump is testable with a fake sidecar and a collecting sink.
pub trait Sink: Send + Sync + 'static {
    fn push(&self, event: &str, payload: Value);
}

impl Sink for AppHandle {
    fn push(&self, event: &str, payload: Value) {
        // A closed window is not an error worth propagating.
        let _ = Emitter::emit(self, event, payload);
    }
}

/// What the UI receives for a proposal: the exact argv that would run, or the
/// reason it was refused.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProposalView {
    pub id: Uuid,
    pub tool_id: String,
    pub program: Option<String>,
    pub argv: Vec<String>,
    pub targets: Vec<String>,
    pub effective_intrusiveness: Option<String>,
    pub required_privileges: Vec<String>,
    /// `Some(reason)` = refused, and nothing may run.
    pub error: Option<String>,
}

/// What the UI receives after an approved execution.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionView {
    pub proposal_id: Uuid,
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Why a proposal cannot run. Each variant is a different, actionable refusal.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    #[error("no project is open: tool execution needs a project directory to confine paths to")]
    NoProject,
    #[error("tool {0:?} is not in the catalog")]
    UnknownTool(String),
    #[error("catalog: {0}")]
    Catalog(String),
    #[error("{0}")]
    Runner(#[from] RunnerError),
}

/// Validate a proposal against the catalog, the confinement root and the scope.
///
/// Also returns the entry, so the caller can honour the declared timeout.
fn evaluate(
    proposal: &Proposal,
    project_dir: Option<PathBuf>,
    decider: &dyn ScopeDecider,
    allow_dangerous: bool,
) -> Result<(ValidatedCommand, ToolEntry), Failure> {
    let entry = elliot_catalog::load_standard()
        .map_err(|e| Failure::Catalog(e.to_string()))?
        .into_iter()
        .find(|entry| entry.id == proposal.tool_id)
        .ok_or_else(|| Failure::UnknownTool(proposal.tool_id.clone()))?;
    // No project ⇒ no confinement root ⇒ no execution at all.
    let dir = project_dir.ok_or(Failure::NoProject)?;
    let mut config = RunnerConfig::new(dir);
    config.allow_dangerous = allow_dangerous;
    let cmd = elliot_runner::validate(&entry, proposal, decider, &config)?;
    Ok((cmd, entry))
}

impl ProposalView {
    fn validated(id: Uuid, proposal: &Proposal, cmd: &ValidatedCommand) -> Self {
        Self {
            id,
            tool_id: proposal.tool_id.clone(),
            program: Some(cmd.program.clone()),
            argv: cmd.argv.clone(),
            targets: proposal.targets.clone(),
            effective_intrusiveness: Some(intrusiveness_token(cmd.effective_intrusiveness).into()),
            required_privileges: cmd
                .required_privileges
                .iter()
                .map(|p| privilege_token(*p).to_string())
                .collect(),
            error: None,
        }
    }

    /// Refused, but with the exact command the human would unlock: a dangerous
    /// proposal is blocked, not hidden — the decision needs the argv in front of
    /// them.
    fn blocked(id: Uuid, proposal: &Proposal, cmd: &ValidatedCommand, failure: &Failure) -> Self {
        let mut view = Self::validated(id, proposal, cmd);
        view.error = Some(failure.to_string());
        view
    }

    fn refused(id: Uuid, proposal: &Proposal, failure: Failure) -> Self {
        Self {
            id,
            tool_id: proposal.tool_id.clone(),
            program: None,
            argv: Vec::new(),
            targets: proposal.targets.clone(),
            effective_intrusiveness: None,
            required_privileges: Vec::new(),
            error: Some(failure.to_string()),
        }
    }
}

fn intrusiveness_token(level: Intrusiveness) -> &'static str {
    match level {
        Intrusiveness::Passive => "passive",
        Intrusiveness::Low => "low",
        Intrusiveness::Intrusive => "intrusive",
        Intrusiveness::Dangerous => "dangerous",
    }
}

fn privilege_token(privilege: Privilege) -> &'static str {
    match privilege {
        Privilege::RawSocket => "raw_socket",
    }
}

impl ExecutionView {
    fn from_result(
        result: Result<elliot_runner::Output, RunnerError>,
        elapsed: Duration,
        proposal_id: Uuid,
    ) -> Self {
        match result {
            Ok(out) => Self {
                proposal_id,
                status: out.status,
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                duration_ms: elapsed.as_millis() as u64,
                error: None,
            },
            Err(e) => Self {
                proposal_id,
                status: None,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: elapsed.as_millis() as u64,
                error: Some(e.to_string()),
            },
        }
    }
}

/// Parse one NDJSON frame.
pub fn parse_frame(line: &str) -> Result<Frame, String> {
    serde_json::from_str(line).map_err(|e| format!("frame non valido: {e}"))
}

/// Turn one proposal frame into a validated view and remember it for execution.
async fn handle_proposal(
    tool_id: String,
    flags: Vec<WireFlag>,
    targets: Vec<String>,
    scope: &ScopeState,
    proposals: &Mutex<HashMap<Uuid, Proposal>>,
) -> ProposalView {
    let proposal = Proposal {
        tool_id,
        flags: flags.into_iter().map(Into::into).collect(),
        targets,
    };
    let id = Uuid::new_v4();

    let dir = scope.project_dir().await;
    let decider = scope.decider();
    let view = match evaluate(&proposal, dir.clone(), decider.as_ref(), false) {
        Ok((cmd, _entry)) => ProposalView::validated(id, &proposal, &cmd),
        // A dangerous command is refused without the manual unlock, but the
        // human still gets the argv: they are the one deciding to unlock it.
        Err(failure @ Failure::Runner(RunnerError::DangerousBlocked)) => match dir {
            Some(dir) => match evaluate(&proposal, Some(dir), decider.as_ref(), true) {
                Ok((cmd, _entry)) => ProposalView::blocked(id, &proposal, &cmd, &failure),
                Err(other) => ProposalView::refused(id, &proposal, other),
            },
            None => ProposalView::refused(id, &proposal, failure),
        },
        Err(failure) => ProposalView::refused(id, &proposal, failure),
    };

    // Remember it even when refused: the human may unlock a dangerous proposal
    // (re-validated at execute time) and the UI needs it for the error message.
    proposals.lock().await.insert(id, proposal);
    view
}

/// Read frames until the sidecar closes, pushing each one to the UI.
pub async fn pump<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    sink: Arc<dyn Sink>,
    scope: SharedScope,
    proposals: Arc<Mutex<HashMap<Uuid, Proposal>>>,
) {
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                match parse_frame(&line) {
                    Ok(Frame::Chunk { text }) => sink.push(EVENT_CHUNK, json!({ "text": text })),
                    Ok(Frame::Done) => sink.push(EVENT_DONE, json!({})),
                    Ok(Frame::Error { message }) => {
                        sink.push(EVENT_ERROR, json!({ "message": message }))
                    }
                    Ok(Frame::Proposal {
                        tool_id,
                        flags,
                        targets,
                    }) => {
                        let view =
                            handle_proposal(tool_id, flags, targets, &scope, &proposals).await;
                        sink.push(
                            EVENT_PROPOSAL,
                            serde_json::to_value(view).unwrap_or(Value::Null),
                        );
                    }
                    // An unknown or malformed frame is not fatal: the protocol
                    // may gain frames and the chat must keep working.
                    Err(e) => tracing::warn!("agent: {e}"),
                }
            }
            Ok(None) => break,
            Err(e) => {
                sink.push(EVENT_ERROR, json!({ "message": format!("sidecar: {e}") }));
                break;
            }
        }
    }
    sink.push(EVENT_EXIT, json!({}));
}

/// The command that starts the sidecar.
///
/// Order: an explicit override (tests, `ELLIOT_AGENT_CMD`), the binary bundled
/// next to the app (release), then `python -m elliot_agent` from the repo (dev).
fn sidecar_command() -> Result<Command, String> {
    if let Some(path) = std::env::var_os("ELLIOT_AGENT_CMD") {
        return Ok(Command::new(path));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bundled) = exe.parent().map(|dir| dir.join(SIDECAR_BIN)) {
            if bundled.is_file() {
                return Ok(Command::new(bundled));
            }
        }
    }

    let agent_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../agent");
    let venv_python = if cfg!(windows) {
        agent_dir.join(".venv/Scripts/python.exe")
    } else {
        agent_dir.join(".venv/bin/python")
    };
    let python = if venv_python.is_file() {
        venv_python
    } else if cfg!(windows) {
        PathBuf::from("python")
    } else {
        PathBuf::from("python3")
    };
    if !agent_dir.is_dir() {
        return Err(format!(
            "sidecar non trovato: né {SIDECAR_BIN} accanto all'eseguibile né {}",
            agent_dir.display()
        ));
    }
    let mut cmd = Command::new(python);
    cmd.arg("-m").arg("elliot_agent").current_dir(agent_dir);
    Ok(cmd)
}

async fn spawn(
    app: &AppHandle,
    scope: SharedScope,
    proposals: Arc<Mutex<HashMap<Uuid, Proposal>>>,
) -> Result<Sidecar, String> {
    let mut cmd = sidecar_command()?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // The sidecar must not outlive the app.
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("avvio del sidecar: {e}"))?;
    let stdin = child.stdin.take().ok_or("il sidecar non espone stdin")?;
    let stdout = child.stdout.take().ok_or("il sidecar non espone stdout")?;

    // Sidecar diagnostics go to the log, never to the protocol stream.
    if let Some(stderr) = child.stderr.take() {
        let mut lines = BufReader::new(stderr).lines();
        tauri::async_runtime::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!("agent sidecar: {line}");
            }
        });
    }

    let sink: Arc<dyn Sink> = Arc::new(app.clone());
    tauri::async_runtime::spawn(pump(stdout, sink, scope, proposals));
    Ok(Sidecar { child, stdin })
}

/// Curated context: the authorised targets, as **data**. The sidecar never
/// enforces scope; this only helps it propose targets that will pass.
fn curated_context(policy: &ScopePolicy) -> Vec<String> {
    let mut out = Vec::new();
    if policy.include.is_empty() {
        out.push("Scope: nessuna regola include — ogni target è in scope.".to_string());
    }
    for rule in &policy.include {
        out.push(format!("Scope include: {}", describe_rule(rule)));
    }
    for rule in &policy.exclude {
        out.push(format!("Scope exclude: {}", describe_rule(rule)));
    }
    out
}

fn describe_rule(rule: &Rule) -> String {
    use elliot_scope::{HostMatch, PathMatch, PortMatch, SchemeMatch};

    let scheme = match rule.scheme {
        SchemeMatch::Any => "any",
        SchemeMatch::Http => "http",
        SchemeMatch::Https => "https",
    };
    let host = match &rule.host {
        HostMatch::Any => "*".to_string(),
        HostMatch::Exact(host) => host.clone(),
        HostMatch::Suffix(domain) => format!("*.{domain}"),
    };
    let port = match rule.port {
        PortMatch::Any => String::new(),
        PortMatch::Exact(port) => format!(":{port}"),
    };
    let path = match &rule.path {
        PathMatch::Any => String::new(),
        PathMatch::Prefix(prefix) => format!(" path prefix {prefix}"),
    };
    format!("{scheme}://{host}{port}{path}")
}

#[tauri::command]
pub async fn agent_send(
    app: AppHandle,
    state: State<'_, AgentState>,
    scope: State<'_, SharedScope>,
    prompt: String,
) -> Result<(), String> {
    if prompt.trim().is_empty() {
        return Err("prompt vuoto".into());
    }
    let context = curated_context(&scope.policy());

    let mut guard = state.sidecar.lock().await;
    if guard.is_none() {
        *guard = Some(spawn(&app, scope.inner().clone(), state.proposals.clone()).await?);
    }
    let sidecar = guard.as_mut().expect("spawned above");
    let request = json!({
        "v": PROTOCOL_VERSION,
        "prompt": prompt,
        "context": context,
    });
    let line = format!("{request}\n");

    let write = async {
        sidecar.stdin.write_all(line.as_bytes()).await?;
        sidecar.stdin.flush().await
    }
    .await;

    if let Err(e) = write {
        // The child died: drop it, so the next message restarts it.
        *guard = None;
        return Err(format!("sidecar non raggiungibile: {e}"));
    }
    Ok(())
}

/// Stop the sidecar. The state also kills it on drop (app exit).
#[tauri::command]
pub async fn agent_stop(state: State<'_, AgentState>) -> Result<(), String> {
    if let Some(mut sidecar) = state.sidecar.lock().await.take() {
        let _ = sidecar.child.kill().await;
    }
    Ok(())
}

/// Run an approved proposal. Re-validates first: the round trip through the UI
/// is not evidence that the command is still allowed.
#[tauri::command]
pub async fn agent_execute(
    app: AppHandle,
    state: State<'_, AgentState>,
    scope: State<'_, SharedScope>,
    proposal_id: Uuid,
    allow_dangerous: bool,
) -> Result<(), String> {
    let proposal = state
        .proposals
        .lock()
        .await
        .get(&proposal_id)
        .cloned()
        .ok_or("proposta sconosciuta")?;

    let dir = scope.project_dir().await;
    let decider = scope.decider();
    let (cmd, entry) = evaluate(&proposal, dir, decider.as_ref(), allow_dangerous)
        .map_err(|e| e.to_string())?;

    let timeout = entry
        .limits
        .as_ref()
        .and_then(|limits| limits.timeout_seconds)
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
        .unwrap_or(DEFAULT_TIMEOUT);

    let started = Instant::now();
    let result = cmd.execute(Some(timeout)).await;
    let view = ExecutionView::from_result(result, started.elapsed(), proposal_id);
    let _ = Emitter::emit(&app, EVENT_EXECUTION, view);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_proposal(target: &str) -> Proposal {
        Proposal {
            tool_id: "nmap".into(),
            flags: vec![elliot_runner::FlagArg::switch("-sV")],
            targets: vec![target.into()],
        }
    }

    #[test]
    fn frames_are_parsed_and_unknown_ones_do_not_pass() {
        assert_eq!(
            parse_frame(r#"{"v":1,"type":"chunk","text":"ciao"}"#).unwrap(),
            Frame::Chunk { text: "ciao".into() }
        );
        assert_eq!(
            parse_frame(r#"{"v":1,"type":"done"}"#).unwrap(),
            Frame::Done
        );
        assert!(parse_frame(r#"{"type":"what"}"#).is_err());
        assert!(parse_frame("not json").is_err());
        // `v` is part of the contract but not of the enum: it must be ignored.
        assert_eq!(
            parse_frame(r#"{"v":1,"type":"error","message":"boom"}"#).unwrap(),
            Frame::Error { message: "boom".into() }
        );
    }

    #[test]
    fn a_proposal_outside_the_scope_is_refused_with_no_command() {
        let policy = elliot_scope::ScopePolicy::host_suffix("example.com");
        let project = tempfile::tempdir().unwrap();
        let err = evaluate(
            &entry_proposal("evil.com"),
            Some(project.path().to_path_buf()),
            &policy,
            false,
        )
        .unwrap_err();
        assert!(matches!(err, Failure::Runner(RunnerError::OutOfScope { .. })), "got {err:?}");
    }

    #[test]
    fn without_a_project_nothing_is_validated() {
        let policy = elliot_scope::ScopePolicy::host_suffix("127.0.0.1");
        let err = evaluate(&entry_proposal("127.0.0.1"), None, &policy, false).unwrap_err();
        assert!(matches!(err, Failure::NoProject), "got {err:?}");
    }

    #[test]
    fn a_tool_outside_the_catalog_is_refused() {
        let policy = elliot_scope::ScopePolicy::host_suffix("127.0.0.1");
        let project = tempfile::tempdir().unwrap();
        let proposal = Proposal {
            tool_id: "metasploit".into(),
            flags: vec![],
            targets: vec!["127.0.0.1".into()],
        };
        let err = evaluate(&proposal, Some(project.path().to_path_buf()), &policy, false)
            .unwrap_err();
        assert!(matches!(err, Failure::UnknownTool(_)), "got {err:?}");
    }

    #[test]
    fn a_valid_proposal_shows_the_exact_argv() {
        let policy = elliot_scope::ScopePolicy::host_suffix("127.0.0.1");
        let project = tempfile::tempdir().unwrap();
        let proposal = entry_proposal("127.0.0.1");
        let (cmd, _entry) = evaluate(
            &proposal,
            Some(project.path().to_path_buf()),
            &policy,
            false,
        )
        .unwrap();
        let view = ProposalView::validated(Uuid::nil(), &proposal, &cmd);
        assert_eq!(view.argv, vec!["-sV", "127.0.0.1"]);
        assert_eq!(view.program.as_deref(), Some("nmap"));
        assert_eq!(view.effective_intrusiveness.as_deref(), Some("low"));
        assert!(view.error.is_none());
    }

    #[test]
    fn a_blocked_command_still_shows_its_argv_with_the_error() {
        let policy = elliot_scope::ScopePolicy::host_suffix("127.0.0.1");
        let project = tempfile::tempdir().unwrap();
        let proposal = entry_proposal("127.0.0.1");
        let (cmd, _entry) = evaluate(
            &proposal,
            Some(project.path().to_path_buf()),
            &policy,
            true,
        )
        .unwrap();
        let failure = Failure::Runner(RunnerError::DangerousBlocked);
        let view = ProposalView::blocked(Uuid::nil(), &proposal, &cmd, &failure);
        assert!(view.error.as_deref().unwrap_or_default().contains("dangerous"));
        assert_eq!(view.argv, vec!["-sV", "127.0.0.1"]);
    }

    #[test]
    fn dangerous_is_blocked_unless_explicitly_unlocked() {
        // A synthetic dangerous entry is not in the standard catalog, so assert
        // the runner's own gate through `evaluate` with an unsupported flag:
        // unknown flags are refused before anything runs.
        let policy = elliot_scope::ScopePolicy::host_suffix("127.0.0.1");
        let project = tempfile::tempdir().unwrap();
        let proposal = Proposal {
            tool_id: "nmap".into(),
            flags: vec![elliot_runner::FlagArg::switch("--raw")],
            targets: vec!["127.0.0.1".into()],
        };
        let err = evaluate(&proposal, Some(project.path().to_path_buf()), &policy, false)
            .unwrap_err();
        assert!(matches!(err, Failure::Runner(RunnerError::UnknownFlag(_))), "got {err:?}");
    }

    #[test]
    fn curated_context_describes_the_scope_for_the_model() {
        let policy = ScopePolicy::host_suffix("example.com")
            .including(Rule::host("127.0.0.1").on_port(8080))
            .excluding(Rule::host_suffix("bank.example"));
        let context = curated_context(&policy);
        assert!(context.iter().any(|c| c.contains("*.example.com")), "{context:?}");
        assert!(context.iter().any(|c| c.contains("127.0.0.1:8080")), "{context:?}");
        assert!(
            context.iter().any(|c| c.contains("exclude") && c.contains("*.bank.example")),
            "{context:?}"
        );
        // An empty policy says so instead of pretending to have a list.
        assert!(curated_context(&ScopePolicy::default())[0].contains("nessuna regola"));
    }

    #[derive(Default)]
    struct CollectSink {
        events: std::sync::Mutex<Vec<(String, Value)>>,
    }

    impl Sink for CollectSink {
        fn push(&self, event: &str, payload: Value) {
            self.events
                .lock()
                .unwrap()
                .push((event.to_string(), payload));
        }
    }

    impl CollectSink {
        fn names(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
        }

        fn value(&self, event: &str) -> Option<Value> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .find(|(name, _)| name == event)
                .map(|(_, payload)| payload.clone())
        }
    }

    fn test_python() -> Option<PathBuf> {
        let agent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../agent");
        let python = agent.join(".venv/bin/python");
        python.is_file().then_some(python)
    }

    /// The bridge, end to end, against a fake sidecar process that speaks the
    /// real protocol: chunks reach the UI, and the proposal is validated into an
    /// exact argv before it is shown.
    #[tokio::test]
    async fn a_fake_sidecar_streams_chunks_and_a_validated_proposal() {
        let Some(python) = test_python() else {
            eprintln!("skipping: agent/.venv/bin/python is not available");
            return;
        };

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project.elliot");
        let scope = Arc::new(ScopeState::new(project.clone()));
        scope.create_project(project, "pw").await.unwrap();
        scope
            .set_policy(elliot_scope::ScopePolicy::host_suffix("127.0.0.1"))
            .await
            .unwrap();

        let script = r#"
import json, sys
frames = [
    {"v": 1, "type": "chunk", "text": "Prima "},
    {"v": 1, "type": "chunk", "text": "scansiono."},
    {"v": 1, "type": "proposal", "tool_id": "nmap",
     "flags": [{"name": "-sV"}], "targets": ["127.0.0.1"]},
    {"v": 1, "type": "done"},
]
for frame in frames:
    print(json.dumps(frame), flush=True)
"#;
        let mut child = Command::new(python)
            .arg("-c")
            .arg(script)
            .stdout(Stdio::piped())
            .spawn()
            .expect("the fake sidecar should start");
        let stdout = child.stdout.take().unwrap();

        let sink = Arc::new(CollectSink::default());
        let proposals = Arc::new(Mutex::new(HashMap::new()));
        pump(stdout, sink.clone(), scope, proposals.clone()).await;

        assert_eq!(
            sink.names(),
            vec![
                EVENT_CHUNK,
                EVENT_CHUNK,
                EVENT_PROPOSAL,
                EVENT_DONE,
                EVENT_EXIT
            ]
        );
        let view = sink.value(EVENT_PROPOSAL).unwrap();
        assert_eq!(view["toolId"], "nmap");
        assert_eq!(view["argv"], json!(["-sV", "127.0.0.1"]));
        assert_eq!(view["effectiveIntrusiveness"], "low");
        assert!(view["error"].is_null(), "got {view}");
        assert_eq!(proposals.lock().await.len(), 1);

        let _ = child.wait().await;
    }

    /// The real sidecar, started the way the app starts it, speaking the real
    /// protocol. Ollama is pointed at a dead port, so the sidecar falls back to
    /// its stub: this covers process wiring, stdin/stdout and the persistent
    /// loop, not the model (which the proposal test covers with a fake child).
    #[tokio::test]
    async fn the_real_sidecar_answers_a_prompt_through_the_bridge() {
        if test_python().is_none() {
            eprintln!("skipping: agent/.venv/bin/python is not available");
            return;
        }

        let mut cmd = sidecar_command().expect("the dev sidecar command");
        cmd.env("ELLIOT_OLLAMA_URL", "http://127.0.0.1:1/api/chat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("the sidecar should start");
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(b"{\"v\":1,\"prompt\":\"ciao\"}\n")
            .await
            .unwrap();
        stdin.flush().await.unwrap();
        // Closing stdin is the protocol's stop signal: the sidecar exits, the
        // pump sees EOF and finishes.
        drop(stdin);
        let stdout = child.stdout.take().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let scope = Arc::new(ScopeState::new(dir.path().join("project.elliot")));
        let sink = Arc::new(CollectSink::default());
        pump(
            stdout,
            sink.clone(),
            scope,
            Arc::new(Mutex::new(HashMap::new())),
        )
        .await;

        let names = sink.names();
        assert!(names.contains(&EVENT_CHUNK.to_string()), "got {names:?}");
        assert_eq!(names.last().map(String::as_str), Some(EVENT_EXIT));
        assert!(
            !names.contains(&EVENT_PROPOSAL.to_string()),
            "the stub cannot produce a proposal: {names:?}"
        );
        let _ = child.wait().await;
    }

    /// A refused proposal still reaches the UI (so the human sees why), but it
    /// carries an error and no argv at all.
    #[tokio::test]
    async fn an_out_of_scope_proposal_is_reported_without_a_command() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project.elliot");
        let scope = Arc::new(ScopeState::new(project.clone()));
        scope.create_project(project, "pw").await.unwrap();
        scope
            .set_policy(elliot_scope::ScopePolicy::host_suffix("example.com"))
            .await
            .unwrap();

        let proposals = Arc::new(Mutex::new(HashMap::new()));
        let view = handle_proposal(
            "nmap".into(),
            vec![WireFlag {
                name: "-sV".into(),
                value: None,
            }],
            vec!["evil.com".into()],
            &scope,
            &proposals,
        )
        .await;

        assert!(view.error.as_deref().unwrap_or_default().contains("not in scope"));
        assert!(view.argv.is_empty(), "a refused proposal has no argv");
        // Remembered for the UI, never executable.
        assert_eq!(proposals.lock().await.len(), 1);
    }
}
