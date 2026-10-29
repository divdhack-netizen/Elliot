//! Tauri wiring for the passive sniffer: the commands the UI calls and the pump
//! that forwards [`SniffEvent`]s as `sniff://packet`.
//!
//! Unlike the proxy and SOCKS pumps this one writes nothing: v1 is live-only,
//! so the open project is not touched. The scope decider is shared with the
//! other listeners and is used here only to label flows once an SNI or DNS
//! name identifies the host.

use std::sync::Arc;

use elliot_sniff::{
    list_interfaces, start, validate_filter, FlowMeta, IfaceInfo, PacketMeta, SniffConfig,
    SniffEvent, SniffHandle,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use crate::scope::ScopeState;

/// Running-capture state held by Tauri.
#[derive(Default)]
pub struct SniffState {
    handle: Mutex<Option<SniffHandle>>,
    /// The interface/filter of the running capture, so a reloaded UI can show
    /// the real state instead of an empty picker.
    running: Mutex<Option<Running>>,
}

#[derive(Clone, Debug)]
struct Running {
    interface: String,
    bpf_filter: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    /// Interface name from `sniff_interfaces`, e.g. "lo0" or "en0".
    pub interface: String,
    /// Optional BPF capture filter, e.g. "tcp port 8080".
    #[serde(default)]
    pub bpf_filter: Option<String>,
    /// Promiscuous mode; irrelevant on loopback, on by default elsewhere.
    #[serde(default = "default_promisc")]
    pub promisc: bool,
    #[serde(default = "default_snaplen")]
    pub snaplen: i32,
}

fn default_promisc() -> bool {
    true
}

fn default_snaplen() -> i32 {
    elliot_sniff::DEFAULT_SNAPLEN
}

/// How a capture event reaches the frontend. `kind` distinguishes the
/// lifecycle; exactly one of `flow`/`packet`/`error` is set.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SniffEventPayload {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<FlowMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet: Option<PacketMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tauri::command]
pub async fn sniff_interfaces() -> Result<Vec<IfaceInfo>, String> {
    tokio::task::spawn_blocking(list_interfaces)
        .await
        .map_err(|e| format!("listing interfaces: {e}"))?
        .map_err(|e| format!("{e:#}"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateArgs {
    /// The BPF expression to check; empty means "capture everything".
    #[serde(default)]
    pub bpf: String,
}

/// Compile a BPF filter without opening a device, so the UI can tell the user
/// whether the expression is well-formed as they type. Needs no privileges and
/// touches no interface; the authoritative check still happens at `sniff_start`.
#[tauri::command]
pub async fn sniff_validate(args: ValidateArgs) -> Result<(), String> {
    validate_filter(&args.bpf).map_err(|e| format!("{e:#}"))
}

#[tauri::command]
pub async fn sniff_start(
    app: AppHandle,
    state: State<'_, SniffState>,
    scope: State<'_, Arc<ScopeState>>,
    args: StartArgs,
) -> Result<(), String> {
    let mut guard = state.handle.lock().await;
    if let Some(previous) = guard.take() {
        if previous.is_running() {
            *guard = Some(previous);
            return Err("sniffer already running".into());
        }
        // A capture that stopped on its own (the interface went away, a BPF
        // read failed) leaves a finished handle behind. Join it before opening
        // the next device, so its BPF descriptor is released and Start
        // recovers immediately instead of asking for a Stop first.
        previous.stop().await;
    }
    *state.running.lock().await = None;

    let interface = args.interface.trim().to_string();
    let bpf_filter = args
        .bpf_filter
        .map(|filter| filter.trim().to_string())
        .filter(|filter| !filter.is_empty());
    let config = SniffConfig {
        interface: interface.clone(),
        bpf_filter: bpf_filter.clone(),
        snaplen: args.snaplen,
        promisc: args.promisc,
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<SniffEvent>(4096);
    // The decider follows the live policy, exactly like the proxy's and
    // SOCKS listener's; only used to tag flows, never to gate the capture.
    let handle = start(config, scope.decider(), tx)
        .await
        .map_err(|e| format!("{e:#}"))?;
    // Publish the metadata before the handle: the handle lock is still held,
    // so a concurrent status query cannot observe a running capture without
    // the interface/filter it should display.
    *state.running.lock().await = Some(Running {
        interface,
        bpf_filter,
    });
    *guard = Some(handle);

    let app_for_pump = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            let payload = match event {
                SniffEvent::FlowStarted(flow) => SniffEventPayload {
                    kind: "started",
                    flow: Some(flow),
                    packet: None,
                    error: None,
                },
                SniffEvent::FlowUpdated(flow) => SniffEventPayload {
                    kind: "updated",
                    flow: Some(flow),
                    packet: None,
                    error: None,
                },
                SniffEvent::Packet(packet) => SniffEventPayload {
                    kind: "packet",
                    flow: None,
                    packet: Some(packet),
                    error: None,
                },
                SniffEvent::Error(error) => SniffEventPayload {
                    kind: "error",
                    flow: None,
                    packet: None,
                    error: Some(error),
                },
            };
            let _ = app_for_pump.emit("sniff://packet", payload);
        }
    });

    Ok(())
}

#[tauri::command]
pub async fn sniff_stop(state: State<'_, SniffState>) -> Result<(), String> {
    if let Some(handle) = state.handle.lock().await.take() {
        handle.stop().await;
    }
    *state.running.lock().await = None;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SniffStatus {
    pub running: bool,
    /// Set while running; `None` when stopped.
    pub interface: Option<String>,
    pub bpf_filter: Option<String>,
}

#[tauri::command]
pub async fn sniff_status(state: State<'_, SniffState>) -> Result<SniffStatus, String> {
    // `Some(handle)` is not enough: a loop that died on its own leaves the
    // handle in place until the next start or stop.
    let running = state
        .handle
        .lock()
        .await
        .as_ref()
        .is_some_and(SniffHandle::is_running);
    let current = state.running.lock().await.clone();
    Ok(match current {
        Some(current) if running => SniffStatus {
            running: true,
            interface: Some(current.interface),
            bpf_filter: current.bpf_filter,
        },
        _ => SniffStatus {
            running: false,
            interface: None,
            bpf_filter: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The frontend sends camelCase keys; these must deserialize into the
    // snake_case Rust fields (regression guard for the rename_all).
    #[test]
    fn start_args_accept_camel_case_and_default_to_promiscuous_full_frames() {
        let a: StartArgs =
            serde_json::from_str(r#"{"interface":"lo0","bpfFilter":"tcp port 8080"}"#).unwrap();
        assert_eq!(a.interface, "lo0");
        assert_eq!(a.bpf_filter.as_deref(), Some("tcp port 8080"));
        assert!(a.promisc);
        assert_eq!(a.snaplen, elliot_sniff::DEFAULT_SNAPLEN);
    }

    // The frontend types mirror these exact keys; a rename on the Rust side
    // must fail here instead of silently emptying the Sniffer screen.
    #[test]
    fn flow_events_use_camel_case_keys() {
        let flow = FlowMeta {
            id: uuid::Uuid::nil(),
            started_at: std::time::SystemTime::now(),
            last_seen_at: std::time::SystemTime::now(),
            client_addr: "127.0.0.1:51000".parse().unwrap(),
            server_addr: "93.184.216.34:443".parse().unwrap(),
            transport: elliot_httpraw::Transport::Tcp,
            host: Some("example.com".into()),
            scope: Some(elliot_httpraw::ScopeDecision::InScope),
            packets: 3,
            bytes: 900,
            tls: true,
        };
        let json = serde_json::to_value(SniffEventPayload {
            kind: "updated",
            flow: Some(flow),
            packet: None,
            error: None,
        })
        .unwrap();
        assert_eq!(json["kind"], "updated");
        assert!(json["flow"]["startedAt"]["secs_since_epoch"].is_number());
        assert_eq!(json["flow"]["clientAddr"], "127.0.0.1:51000");
        assert_eq!(json["flow"]["serverAddr"], "93.184.216.34:443");
        assert!(json["flow"]["lastSeenAt"]["nanos_since_epoch"].is_number());
        assert_eq!(json["flow"]["transport"], "Tcp");
        assert_eq!(json["flow"]["scope"], "InScope");
        assert_eq!(json["flow"]["packets"], 3);
        assert!(json["flow"].get("client_addr").is_none());
    }

    #[test]
    fn an_empty_filter_is_serialized_as_absent() {
        let payload = SniffEventPayload {
            kind: "packet",
            flow: None,
            packet: None,
            error: None,
        };
        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["kind"], "packet");
        assert!(json.get("flow").is_none());
        assert!(json.get("packet").is_none());
        assert!(json.get("error").is_none());
    }
}
