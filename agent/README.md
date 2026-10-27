# agent — the Python sidecar

A conversational agent, run as a Tauri sidecar process. It **proposes**; it does
**not** execute and does **not** enforce scope — those live in `../core` (Rust).

## Responsibilities

- Chat loop: receive user messages plus curated context (scope rules, selected
  captures), stream a reply.
- Call a local **Ollama** model (`localhost:11434`) with streaming.
- Read the tool catalog (`../catalog/standard/*.yaml`) directly, as grounding for
  which tools and flags exist — this is what keeps a small model from inventing
  flags.
- Emit a **structured tool-call proposal** (tool id + flags + targets), already
  checked against the catalog, back to the Rust agent bridge.

## Protocol (NDJSON on stdin/stdout)

One process per session: it stays alive and reads one request per line until
stdin closes. Every frame carries `"v": 1` (the protocol version the Rust bridge
in `app/src-tauri/src/agent.rs` speaks).

Request:

```json
{"v": 1, "prompt": "scan 127.0.0.1", "model": "llama3.2:1b",
 "context": ["Scope include: https://127.0.0.1"]}
```

`model` and `context` are optional. `context` is **data** (scope rules, banners,
headers): it is framed as untrusted data in every prompt, never as instructions.

Frames out:

```json
{"v": 1, "type": "chunk", "text": "..."}                 // streaming reply
{"v": 1, "type": "proposal", "tool_id": "nmap",
 "flags": [{"name": "-sV"}], "targets": ["127.0.0.1"]}    // optional
{"v": 1, "type": "error", "message": "..."}               // bad request
{"v": 1, "type": "done"}                                  // always last
```

A request that yields no usable tool call simply emits no `proposal` frame.
stdout is reserved for these frames; diagnostics go to stderr.

## Hard limits (by design)

- Never executes a command and never enforces scope.
- Cannot propose anything outside the catalog allow-list: `catalog.py` validates
  the tool, every flag (type, values, repeatability) and the target cardinality
  **before** the frame leaves the process. Anything else is dropped with a
  stderr note.
- Target output (banners, headers) entering the context is **data, not
  instructions** — a manipulated agent can still only emit a proposal, which
  stays caged by the schema + scope + human confirmation on the Rust side.

## Tests

```bash
cd agent && .venv/bin/python -m unittest discover -s tests -v
```

They need no network and no Ollama: `stream_reply` is replaced by a fake model.

## Packaging

Development runs `python -m elliot_agent` from this directory (the bridge finds
`agent/.venv/bin/python`). For a release bundle:

```bash
bash scripts/build-sidecar.sh              # PyInstaller → app/src-tauri/binaries/
npm --prefix app run tauri:build:sidecar   # tauri build with the sidecar overlay
```

The overlay (`app/src-tauri/tauri.sidecar.conf.json`) declares the
`bundle.externalBin`; the base `tauri.conf.json` does not, so a normal
`tauri build` keeps working without the generated binary. At runtime the bridge
prefers `elliot-agent` next to the app executable and only then falls back to
the Python module.
