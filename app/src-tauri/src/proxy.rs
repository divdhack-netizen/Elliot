//! Tauri wiring for the proxy engine: commands the frontend calls, plus the
//! pump that forwards [`ProxyEvent`]s to the UI as `proxy://flow` events.

use elliot_httpraw::{Flow, WsMessage};
use elliot_proxy::{start, InterceptDecision, ProxyConfig, ProxyEvent, ProxyHandle, WsDecision};

use crate::scope::{ScopeState, SharedScope};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

/// Running-proxy state held by Tauri.
#[derive(Default)]
pub struct ProxyState {
    handle: Mutex<Option<ProxyHandle>>,
    /// The address the running proxy listens on, so `proxy_status` can report
    /// it to a UI that reloaded and lost its own copy.
    listen_addr: Mutex<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    /// e.g. "127.0.0.1:8080". Must be loopback (enforced by the engine).
    pub listen_addr: String,
    #[serde(default = "default_verify")]
    pub verify_upstream: bool,
}

fn default_verify() -> bool {
    true
}

/// How a flow event reaches the frontend. `kind` distinguishes the lifecycle;
/// `ws` carries a WebSocket message when `kind == "ws"`.
#[derive(Debug, Serialize, Clone)]
struct FlowEvent {
    kind: &'static str,
    flow: Option<Flow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ws: Option<WsMessage>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub flow_id: uuid::Uuid,
    /// "forward" | "forward_edited" | "drop".
    pub action: String,
    /// Raw bytes for "forward_edited".
    #[serde(default)]
    pub edited: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsDecideArgs {
    pub message_id: uuid::Uuid,
    /// "forward" | "forward_edited" | "drop".
    pub action: String,
    /// Payload bytes for "forward_edited" (text frames must be UTF-8).
    #[serde(default)]
    pub edited: Option<Vec<u8>>,
}

#[tauri::command]
pub async fn proxy_start(
    app: AppHandle,
    state: State<'_, ProxyState>,
    scope: State<'_, SharedScope>,
    args: StartArgs,
) -> Result<(), String> {
    let mut guard = state.handle.lock().await;
    if guard.is_some() {
        return Err("proxy already running".into());
    }

    let listen_addr = args.listen_addr.parse().map_err(|e| format!("bad listen_addr: {e}"))?;
    let ca_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?
        .join("ca");

    let config = ProxyConfig {
        listen_addr,
        ca_dir,
        // The desktop app is the only caller with a session keychain; the key
        // still falls back to an encrypted file if none is usable.
        ca_key_store: elliot_proxy::KeyStore::Keychain,
        verify_upstream: args.verify_upstream,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProxyEvent>(1024);
    // The decider follows the live policy, so scope edits made while the proxy
    // runs apply to the next request.
    let handle = start(config, scope.decider(), tx)
        .await
        .map_err(|e| e.to_string())?;
    *guard = Some(handle);
    *state.listen_addr.lock().await = Some(args.listen_addr);

    // Pump events to the UI until the channel closes (proxy stopped). Captured
    // flows are persisted here, so a project holds the HTTP history too.
    let app_for_pump = app.clone();
    let scope_for_pump = scope.inner().clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let payload = match ev {
                ProxyEvent::FlowStarted(f) => {
                    persist_flow(&scope_for_pump, &f).await;
                    FlowEvent { kind: "started", flow: Some(f), ws: None, error: None }
                }
                ProxyEvent::FlowUpdated(f) => {
                    persist_flow(&scope_for_pump, &f).await;
                    FlowEvent { kind: "updated", flow: Some(f), ws: None, error: None }
                }
                ProxyEvent::FlowCompleted(f) => {
                    // The terminal state is written last, so an interrupted
                    // capture leaves a pending flow, never a truncated one
                    // claiming to be complete.
                    persist_flow(&scope_for_pump, &f).await;
                    FlowEvent { kind: "completed", flow: Some(f), ws: None, error: None }
                }
                ProxyEvent::WebSocket(m) => {
                    // Only forwarded frames are history: a paused frame is a
                    // question, and a dropped one never reached the network.
                    if should_persist(&m) {
                        persist_ws(&scope_for_pump, &m).await;
                    }
                    FlowEvent { kind: "ws", flow: None, ws: Some(m), error: None }
                }
                ProxyEvent::Error(e) => FlowEvent { kind: "error", flow: None, ws: None, error: Some(e) },
            };
            let _ = app_for_pump.emit("proxy://flow", payload);
        }
    });

    Ok(())
}

/// Persist one flow into the open project, if there is one. A write failure is
/// logged rather than surfaced as a UI error: capture keeps working, the
/// project file just misses a flow.
async fn persist_flow(scope: &ScopeState, flow: &Flow) {
    if let Some(Err(e)) = scope.with_store(|store| store.upsert_flow(flow)).await {
        tracing::warn!("persisting flow {}: {e}", flow.id);
    }
}

/// Whether a WebSocket event belongs in the project history.
///
/// `paused: true` is the announcement of a frame held by intercept; the frame
/// that was actually forwarded arrives later with `paused: false` (and, for an
/// edit, the edited payload). A dropped frame arrives with neither, so it is
/// never stored.
async fn persist_ws(scope: &ScopeState, message: &WsMessage) {
    if let Some(Err(e)) = scope.with_store(|store| store.append_ws_message(message)).await {
        tracing::warn!("persisting ws frame {}: {e}", message.id);
    }
}

fn should_persist(message: &WsMessage) -> bool {
    !message.paused
}

#[tauri::command]
pub async fn proxy_stop(state: State<'_, ProxyState>) -> Result<(), String> {
    if let Some(handle) = state.handle.lock().await.take() {
        handle.stop().await;
    }
    *state.listen_addr.lock().await = None;
    Ok(())
}

/// The real backend proxy state, so a reloaded UI can reconcile its own view
/// instead of showing "Start" over a proxy that is still capturing.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub running: bool,
    /// The listen address while running; `None` when stopped.
    pub listen_addr: Option<String>,
    /// Whether intercept is currently holding requests.
    pub intercept: bool,
}

#[tauri::command]
pub async fn proxy_status(state: State<'_, ProxyState>) -> Result<ProxyStatus, String> {
    let guard = state.handle.lock().await;
    Ok(match guard.as_ref() {
        Some(handle) => ProxyStatus {
            running: true,
            listen_addr: state.listen_addr.lock().await.clone(),
            intercept: handle.intercept(),
        },
        None => ProxyStatus { running: false, listen_addr: None, intercept: false },
    })
}

#[tauri::command]
pub async fn proxy_set_intercept(
    state: State<'_, ProxyState>,
    on: bool,
) -> Result<(), String> {
    match &*state.handle.lock().await {
        Some(handle) => {
            handle.set_intercept(on);
            Ok(())
        }
        None => Err("proxy not running".into()),
    }
}

#[tauri::command]
pub async fn proxy_intercept_decide(
    state: State<'_, ProxyState>,
    decision: Decision,
) -> Result<(), String> {
    let guard = state.handle.lock().await;
    let handle = guard.as_ref().ok_or("proxy not running")?;
    let decided = match decision.action.as_str() {
        "forward" => InterceptDecision::Forward,
        "drop" => InterceptDecision::Drop,
        "forward_edited" => InterceptDecision::ForwardEdited(
            decision.edited.ok_or("forward_edited requires `edited` bytes")?,
        ),
        other => return Err(format!("unknown action: {other}")),
    };
    handle.decide(decision.flow_id, decided);
    Ok(())
}

#[tauri::command]
pub async fn proxy_ws_decide(
    state: State<'_, ProxyState>,
    args: WsDecideArgs,
) -> Result<(), String> {
    let guard = state.handle.lock().await;
    let handle = guard.as_ref().ok_or("proxy not running")?;
    let decided = match args.action.as_str() {
        "forward" => WsDecision::Forward,
        "drop" => WsDecision::Drop,
        "forward_edited" => WsDecision::ForwardEdited(
            args.edited
                .ok_or("forward_edited requires `edited` bytes")?,
        ),
        other => return Err(format!("unknown action: {other}")),
    };
    handle.decide_ws(args.message_id, decided);
    Ok(())
}

/// Forwarded WebSocket frames stored in the open project, oldest first.
///
/// Empty when no project is open: nothing is written without one.
#[tauri::command]
pub async fn ws_list(
    state: State<'_, SharedScope>,
    limit: Option<usize>,
) -> Result<Vec<WsMessage>, String> {
    let limit = limit.unwrap_or(500).min(2_000);
    match state.with_store(|store| store.list_ws_messages(limit)).await {
        None => Ok(Vec::new()),
        Some(res) => res.map_err(|e| e.to_string()),
    }
}

/// Where the CA private key lives for the running proxy, and whether a legacy
/// plaintext key was migrated away.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaStatus {
    /// "keychain" | "encrypted_file": the backend that actually answered.
    pub backend: &'static str,
    pub ca_dir: String,
    /// `ca.key.enc` present and `ca.key` gone: the key was migrated.
    pub legacy_migrated: bool,
}

/// A legacy plaintext key is migrated when the encrypted file exists and the
/// clear-text one no longer does.
fn legacy_migrated(ca_dir: &std::path::Path) -> bool {
    ca_dir.join("ca.key.enc").is_file() && !ca_dir.join("ca.key").exists()
}

#[tauri::command]
pub async fn proxy_ca_status(
    app: AppHandle,
    state: State<'_, ProxyState>,
) -> Result<CaStatus, String> {
    let guard = state.handle.lock().await;
    let handle = guard.as_ref().ok_or("proxy not running")?;
    let ca_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?
        .join("ca");
    Ok(CaStatus {
        backend: handle.ca_key_store().as_token(),
        legacy_migrated: legacy_migrated(&ca_dir),
        ca_dir: ca_dir.display().to_string(),
    })
}

#[tauri::command]
pub async fn proxy_get_ca_pem(state: State<'_, ProxyState>) -> Result<String, String> {
    match &*state.handle.lock().await {
        Some(handle) => Ok(handle.ca_pem()),
        None => Err("proxy not running".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The frontend sends camelCase keys; these must deserialize into the
    // snake_case Rust fields (regression guard for the rename_all).
    #[test]
    fn start_args_accepts_camel_case() {
        let a: StartArgs = serde_json::from_str(r#"{"listenAddr":"127.0.0.1:8080"}"#).unwrap();
        assert_eq!(a.listen_addr, "127.0.0.1:8080");
        assert!(a.verify_upstream, "verify_upstream defaults to true");
    }

    #[test]
    fn ws_decide_args_accept_camel_case() {
        let a: WsDecideArgs = serde_json::from_str(
            r#"{"messageId":"00000000-0000-0000-0000-000000000000","action":"forward_edited","edited":[104,105]}"#,
        )
        .unwrap();
        assert_eq!(a.action, "forward_edited");
        assert_eq!(a.edited.as_deref(), Some(&b"hi"[..]));
    }

    fn ws(paused: bool) -> WsMessage {
        WsMessage {
            id: uuid::Uuid::new_v4(),
            connection: "127.0.0.1:5000 <-> example.com:443".into(),
            connection_id: uuid::Uuid::new_v4(),
            at: std::time::SystemTime::now(),
            client_addr: "127.0.0.1:5000".parse().unwrap(),
            scheme: elliot_httpraw::Scheme::Https,
            host: "example.com".into(),
            port: 443,
            direction: elliot_httpraw::WsDirection::ClientToServer,
            kind: elliot_httpraw::WsKind::Text,
            payload: b"hi".to_vec().into(),
            paused,
        }
    }

    #[test]
    fn a_migrated_key_is_recognised_and_an_unmigrated_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path();
        // Fresh install: neither file yet.
        assert!(!legacy_migrated(ca));
        // Legacy file still there: nothing was migrated.
        std::fs::write(ca.join("ca.key"), b"plaintext").unwrap();
        assert!(!legacy_migrated(ca));
        // Migrated: encrypted file present, plaintext removed.
        std::fs::write(ca.join("ca.key.enc"), b"sealed").unwrap();
        std::fs::remove_file(ca.join("ca.key")).unwrap();
        assert!(legacy_migrated(ca));
    }

    #[test]
    fn only_forwarded_ws_frames_are_persisted() {
        assert!(!should_persist(&ws(true)), "a held frame is not history yet");
        assert!(should_persist(&ws(false)), "a forwarded frame is history");
    }

    #[test]
    fn decision_accepts_camel_case() {
        let d: Decision = serde_json::from_str(
            r#"{"flowId":"00000000-0000-0000-0000-000000000000","action":"forward"}"#,
        )
        .unwrap();
        assert_eq!(d.action, "forward");
        assert!(d.flow_id.is_nil());
    }
}
