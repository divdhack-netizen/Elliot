//! Tauri wiring for the proxy engine: commands the frontend calls, plus the
//! pump that forwards [`ProxyEvent`]s to the UI as `proxy://flow` events.

use std::sync::Arc;

use elliot_httpraw::Flow;
use elliot_proxy::{
    start, AllowAll, InterceptDecision, ProxyConfig, ProxyEvent, ProxyHandle,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

/// Running-proxy state held by Tauri.
#[derive(Default)]
pub struct ProxyState {
    handle: Mutex<Option<ProxyHandle>>,
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

/// How a flow event reaches the frontend. `kind` distinguishes the lifecycle.
#[derive(Debug, Serialize, Clone)]
struct FlowEvent {
    kind: &'static str,
    flow: Option<Flow>,
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

#[tauri::command]
pub async fn proxy_start(
    app: AppHandle,
    state: State<'_, ProxyState>,
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
        verify_upstream: args.verify_upstream,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProxyEvent>(1024);
    let handle = start(config, Arc::new(AllowAll), tx)
        .await
        .map_err(|e| e.to_string())?;
    *guard = Some(handle);

    // Pump events to the UI until the channel closes (proxy stopped).
    let app_for_pump = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let payload = match ev {
                ProxyEvent::FlowStarted(f) => FlowEvent { kind: "started", flow: Some(f), error: None },
                ProxyEvent::FlowUpdated(f) => FlowEvent { kind: "updated", flow: Some(f), error: None },
                ProxyEvent::FlowCompleted(f) => FlowEvent { kind: "completed", flow: Some(f), error: None },
                ProxyEvent::Error(e) => FlowEvent { kind: "error", flow: None, error: Some(e) },
            };
            let _ = app_for_pump.emit("proxy://flow", payload);
        }
    });

    Ok(())
}

#[tauri::command]
pub async fn proxy_stop(state: State<'_, ProxyState>) -> Result<(), String> {
    if let Some(handle) = state.handle.lock().await.take() {
        handle.stop().await;
    }
    Ok(())
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
    fn decision_accepts_camel_case() {
        let d: Decision = serde_json::from_str(
            r#"{"flowId":"00000000-0000-0000-0000-000000000000","action":"forward"}"#,
        )
        .unwrap();
        assert_eq!(d.action, "forward");
        assert!(d.flow_id.is_nil());
    }
}
