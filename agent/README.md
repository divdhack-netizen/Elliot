# agent — the Python sidecar

A conversational agent, run as a Tauri sidecar process. It **proposes**; it does
**not** execute and does **not** enforce scope — those live in `../core` (Rust).

## Responsibilities

- Chat loop: receive user messages, the conversation history and the curated
  context (scope rules, captures the user attached), stream a reply.
- Call a local **Ollama** model (`localhost:11434`) with streaming.
- Read the tool catalog (`../catalog/standard/*.yaml`) directly, as grounding for
  which tools and flags exist — this is what keeps a small model from inventing
  flags. The catalog ships inside the packaged binary as data.
- End a reply with a **structured proposal** line (tool id + flags + targets),
  already checked against the catalog, back to the Rust agent bridge. The line
  is filtered out of the stream the UI sees.

## Protocol (NDJSON on stdin/stdout)

One process per session: it stays alive and reads one request per line until
stdin closes. Every frame carries `"v": 2` (the protocol version the Rust bridge
in `app/src-tauri/src/agent.rs` speaks). The sidecar still accepts `v: 1`
requests: the new fields are optional and fall back to their defaults.

Request:

```json
{"v": 2, "prompt": "scan 127.0.0.1", "model": "llama3.2:1b",
 "context": ["Scope include: https://127.0.0.1"],
 "history": [{"role": "user", "text": "..."},
              {"role": "assistant", "text": "..."}],
 "propose": true, "propose_only": false}
```

`model`, `context`, `history` and the two flags are optional. `history` is the
conversation memory composed by the bridge (bounded there, and cleared when the
project changes). `context` is **data** (scope rules, banners, headers, attached
captures): it is framed as untrusted data in the **last user message only**,
never repeated across turns and never treated as instructions. `propose_only`
asks for one strict proposal call with no chat and no chunks; `propose: false`
turns the proposal instruction (and the catalog) off for a plain chat.

### One model call per request

A normal request makes **one** call to Ollama. The reply is ordinary text and,
when the request maps to a catalog command, ends with a single line:

```
ELLIOT_PROPOSAL {"tool_id": "nmap", "flags": [{"name": "-sV"}], "targets": ["127.0.0.1"]}
```

The sidecar holds back a tail as long as the marker, so the marker is never
emitted in a `chunk` — even when it is split across stream chunks. After the
marker, everything is the trailer (never shown); it is validated against the
catalog and only then becomes a `proposal` frame. A missing or invalid trailer
means no proposal and **no second round trip**.

Frames out:

```json
{"v": 2, "type": "chunk", "text": "..."}                 // streaming reply
{"v": 2, "type": "proposal", "tool_id": "nmap",
 "flags": [{"name": "-sV"}], "targets": ["127.0.0.1"]}    // optional
{"v": 2, "type": "error", "message": "..."}               // bad request
{"v": 2, "type": "done"}                                  // always last
```

A request that yields no usable tool call simply emits no `proposal` frame.
stdout is reserved for these frames; diagnostics go to stderr.

## Hard limits (by design)

- Never executes a command and never enforces scope.
- Cannot propose anything outside the catalog allow-list: `catalog.py` validates
  the tool, every flag (type, values, repeatability) and the target cardinality
  **before** the frame leaves the process. Anything else is dropped with a
  stderr note. The proposal is validated again in Rust: this layer is a filter,
  not a trust boundary.
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
