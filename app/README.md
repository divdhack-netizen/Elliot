# app — the Tauri desktop application

One window, with tabs: **Proxy / Capture / Repeater / Intruder / Agent**. Tabs
are logically separate and share no state between themselves — all shared state
lives in `../core`, so detaching a tab into its own window later is a
frontend-only change.

## `src-tauri/` — Rust shell

- Tauri shell and window management.
- IPC commands exposed to the React frontend.
- **Agent bridge** (`agent.rs`): spawns and manages the Python sidecar
  (`../../agent`) as a Tauri sidecar process, relays the NDJSON frames, and
  validates each proposal with `elliot-catalog` + `elliot-runner` against the
  live scope and the open project before the UI is allowed to approve it.
  `agent_execute` re-validates and runs it; the round trip through the UI is
  never trusted.
- Depends on the `core/*` crates for all engine work.

## `src/` — React + TypeScript frontend

- **Proxy:** virtualized traffic list, raw request/response viewer, filter bar,
  intercept controls (HTTP requests and paused WebSocket frames, with
  forward/edit/drop).
- **Repeater:** raw request editor (byte-level) + send + response viewer; multiple tabs.
- **Intruder:** base request + injection-point marking, payload config, attack mode, results table.
- **Agent:** chat window; streaming replies; proposed tool calls rendered as
  review blocks with the exact argv, effective intrusiveness and required
  privileges. Confirmation gets more explicit with the risk level (`intrusive`
  needs a tick, `dangerous` needs a manual unlock); nothing runs before the
  click, and the backend re-validates anyway.
- **Shared:** scope configuration UI, and the "send to Repeater/Intruder" actions
  that operate on the shared raw-request object.
