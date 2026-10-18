# app — the Tauri desktop application

One window, with tabs: **Proxy / Repeater / Intruder / Agent**. Tabs are
logically separate and share no state between themselves — all shared state
lives in `../core`, so detaching a tab into its own window later is a
frontend-only change.

## `src-tauri/` — Rust shell

- Tauri shell and window management.
- IPC commands exposed to the React frontend.
- **Agent bridge:** spawns and manages the Python sidecar (`../../agent`) as a
  Tauri sidecar process, relays chat messages and the "send to agent" context
  payloads.
- Depends on the `core/*` crates for all engine work.

## `src/` — React + TypeScript frontend

- **Proxy:** virtualized traffic list, raw request/response viewer, filter bar, intercept controls.
- **Repeater:** raw request editor (byte-level) + send + response viewer; multiple tabs.
- **Intruder:** base request + injection-point marking, payload config, attack mode, results table.
- **Agent:** chat window; streaming replies; proposed tool calls rendered as
  review/approve blocks — only after approval does a proposal reach the runner.
- **Shared:** scope configuration UI, and the "send to Repeater/Intruder/Agent"
  actions that operate on the shared raw-request object.

Build tooling (Vite, Cargo workspace wiring, Tauri config) is not initialized
yet — that is the next scaffolding step.
