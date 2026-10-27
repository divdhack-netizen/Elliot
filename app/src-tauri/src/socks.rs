//! Tauri wiring for the generic (non-HTTP) capture listener: the commands the
//! UI calls, the pump that forwards [`StreamEvent`]s as `socks://stream`, and
//! the persistence of every captured stream and message into the open project.
//!
//! Persisting here (rather than in the core listener) keeps the core free of
//! the store and keeps the privacy rule in one place: with **no project open**
//! nothing is written anywhere, and an out-of-scope connection never reaches
//! this pump at all.

use std::sync::Arc;

use elliot_httpraw::{Message, Stream};
use elliot_socks::{start, SocksConfig, SocksHandle, StreamEvent};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::scope::ScopeState;

/// Running-listener state held by Tauri.
#[derive(Default)]
pub struct SocksState {
    handle: Mutex<Option<SocksHandle>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    /// e.g. "127.0.0.1:1080". Must be loopback (enforced by the listener).
    pub listen_addr: String,
    /// Terminate TLS for in-scope connections, capturing the plaintext.
    #[serde(default)]
    pub mitm_tls: bool,
    #[serde(default = "default_verify")]
    pub verify_upstream: bool,
}

fn default_verify() -> bool {
    true
}

/// How a capture event reaches the frontend. `kind` distinguishes the
/// lifecycle; exactly one of `stream`/`message` is set, except for errors.
#[derive(Debug, Serialize, Clone)]
struct StreamEventPayload {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<Stream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tauri::command]
pub async fn socks_start(
    app: AppHandle,
    state: State<'_, SocksState>,
    scope: State<'_, Arc<ScopeState>>,
    args: StartArgs,
) -> Result<(), String> {
    let mut guard = state.handle.lock().await;
    if guard.is_some() {
        return Err("SOCKS listener already running".into());
    }

    let listen_addr = args
        .listen_addr
        .parse()
        .map_err(|e| format!("bad listen_addr: {e}"))?;
    // The same CA directory the HTTP proxy uses: one certificate to install.
    let ca_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?
        .join("ca");

    let config = SocksConfig {
        listen_addr,
        mitm_tls: args.mitm_tls,
        verify_upstream: args.verify_upstream,
        ca_dir,
        credentials: None,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<StreamEvent>(1024);
    // The scope decider follows the live policy, like the proxy's.
    let handle = start(config, scope.decider(), tx)
        .await
        .map_err(|e| e.to_string())?;
    *guard = Some(handle);

    let app_for_pump = app.clone();
    let scope_for_pump = scope.inner().clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let payload = match ev {
                StreamEvent::StreamStarted(stream) => {
                    persist_stream(&scope_for_pump, &stream).await;
                    StreamEventPayload {
                        kind: "started",
                        stream: Some(stream),
                        message: None,
                        error: None,
                    }
                }
                StreamEvent::Message(message) => {
                    persist_message(&scope_for_pump, &message).await;
                    StreamEventPayload {
                        kind: "message",
                        stream: None,
                        message: Some(message),
                        error: None,
                    }
                }
                StreamEvent::StreamCompleted(stream) => {
                    // The terminal state (completed/error) is written last, so a
                    // crash mid-capture leaves a pending stream, never a
                    // truncated one claiming to be complete.
                    persist_stream(&scope_for_pump, &stream).await;
                    StreamEventPayload {
                        kind: "completed",
                        stream: Some(stream),
                        message: None,
                        error: None,
                    }
                }
                StreamEvent::Error(error) => StreamEventPayload {
                    kind: "error",
                    stream: None,
                    message: None,
                    error: Some(error),
                },
            };
            let _ = app_for_pump.emit("socks://stream", payload);
        }
    });

    Ok(())
}

#[tauri::command]
pub async fn socks_stop(state: State<'_, SocksState>) -> Result<(), String> {
    if let Some(handle) = state.handle.lock().await.take() {
        handle.stop().await;
    }
    Ok(())
}

/// Streams persisted in the open project, most recent first. Empty when no
/// project is open: nothing is written without one.
#[tauri::command]
pub async fn capture_list(
    state: State<'_, Arc<ScopeState>>,
    limit: Option<usize>,
) -> Result<Vec<Stream>, String> {
    let limit = limit.unwrap_or(500).min(5_000);
    match state.with_store(|store| store.list_streams(limit)).await {
        None => Ok(Vec::new()),
        Some(res) => res.map_err(|e| e.to_string()),
    }
}

/// Every message of one persisted stream, in sequence order.
#[tauri::command]
pub async fn capture_messages(
    state: State<'_, Arc<ScopeState>>,
    stream_id: Uuid,
) -> Result<Vec<Message>, String> {
    match state
        .with_store(|store| store.messages_for(stream_id))
        .await
    {
        None => Ok(Vec::new()),
        Some(res) => res.map_err(|e| e.to_string()),
    }
}

// Crate-visible so the end-to-end test in `replay` can drive the pump's work
// (persist what the listener emitted) without a running Tauri app.
pub(crate) async fn persist_stream(scope: &ScopeState, stream: &Stream) {
    if let Some(Err(e)) = scope.with_store(|store| store.upsert_stream(stream)).await {
        tracing::warn!("persisting stream {}: {e}", stream.id);
    }
}

pub(crate) async fn persist_message(scope: &ScopeState, message: &Message) {
    if let Some(Err(e)) = scope.with_store(|store| store.append_message(message)).await {
        tracing::warn!("persisting message {}: {e}", message.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The frontend sends camelCase keys; these must deserialize into the
    // snake_case Rust fields (regression guard for the rename_all).
    #[test]
    fn start_args_accept_camel_case_and_default_to_strict_tls() {
        let a: StartArgs =
            serde_json::from_str(r#"{"listenAddr":"127.0.0.1:1080","mitmTls":true}"#).unwrap();
        assert_eq!(a.listen_addr, "127.0.0.1:1080");
        assert!(a.mitm_tls);
        assert!(a.verify_upstream, "upstream verification defaults to on");
    }
}
