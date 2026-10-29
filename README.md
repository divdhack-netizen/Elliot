# Elliot

A single-user desktop proxy for **authorized** web security testing (VA/PT), in
the spirit of Burp Suite: traffic analysis with full request/response
inspection, automated multi-point attacks, raw request editing and replay,
scope-bound operation, and a local AI agent that *proposes* tool invocations
grounded in a vetted tool catalog.

## Stack

- **Core engine + desktop shell:** Rust + Tauri
- **Frontend:** TypeScript + React
- **Agent:** Python sidecar, calling a local Ollama model
- **Storage:** SQLite (SQLCipher-encrypted), one portable per-project file

## Trust boundary

The Python agent only *proposes* a structured tool call. The Rust core
**validates** it against the catalog schema + the scope engine and **executes**
it. Scope enforcement and execution live in Rust, behind a single trust
boundary — never in the agent.

## Layout

```
elliot/
├── catalog/        # tool catalog — schema + vetted standard entries (built)
├── core/           # Rust workspace: the engine (no UI)
│   ├── proxy/      # MITM proxy (TLS CA, HTTP/1.1 & 2, WebSocket)
│   ├── socks/      # SOCKS5 listener for non-HTTP traffic (CONNECT + UDP ASSOCIATE)
│   ├── tls/        # TLS policy, local CA and per-host leaves, key storage
│   ├── scope/      # scope policy engine — single source of truth
│   ├── store/      # SQLite/SQLCipher project store (per-project file)
│   ├── httpraw/    # shared raw-bytes editable request model + serializer
│   ├── repeater/   # raw request client (no normalization)
│   ├── intruder/   # automated multi-point attacks
│   ├── runner/     # tool runner: validate vs catalog + execute sandboxed
│   └── catalog/    # catalog loader + schema validation
├── app/            # Tauri desktop app
│   ├── src-tauri/  # Rust: shell, IPC commands, agent bridge (depends on core/*)
│   └── src/        # React + TypeScript frontend (Proxy/Capture/Repeater/Intruder/Agent)
├── agent/          # Python sidecar: chat loop, Ollama client, proposal builder
└── docs/           # design record
```

See [docs/architecture.md](docs/architecture.md) for the full design record and
current status.
