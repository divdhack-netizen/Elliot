# core — the Rust engine

A Cargo workspace of focused crates. **No UI here.** The engine is independent
of Tauri so it can be tested on its own; the desktop app (`../app/src-tauri`)
depends on these crates.

| crate | responsibility |
|---|---|
| `proxy` | MITM proxy: local CA + on-the-fly per-host certs, HTTP/1.1, HTTP/2, WebSocket. Produces request/response *flows* and `WsMessage` frames. Passive and intercept modes, for both HTTP and WebSocket data frames (control frames are never held). |
| `socks` | SOCKS5 listener (CONNECT + UDP ASSOCIATE) for **non-HTTP** traffic: a second, generic way in beside the HTTP proxy. Capture is scope-gated (out of scope = transparent tunnel), optional TLS termination on the shared CA, produces `Stream`/`Message` values. Loopback-only bind. |
| `tls` | The single place TLS policy is decided: rustls client configs (verified or the explicit permissive opt-out), the local root CA and the minting of per-host leaves (shared by the proxy and the SOCKS listener). The CA private key is never at rest in the clear: OS keychain when the caller requests it (the desktop app), otherwise an XChaCha20-Poly1305 `ca.key.enc`; a legacy plaintext `ca.key` is imported and removed. |
| `scope` | Scope policy engine. The **single source of truth** for what is in/out of scope. Queried by proxy, intruder, repeater, and the tool runner. Include/exclude rules on scheme/host/port/path; host by exact or domain-suffix match (no regex, safe-by-construction). An empty scope captures everything; the include list narrows it, exclusions carve targets back out. |
| `store` | Per-project SQLite store, SQLCipher-encrypted. The project file *is* the database. Bodies and WebSocket payloads as blobs. Schema **v3**: HTTP `flows` + `settings` (v1), non-HTTP `streams`/`messages` (v2), forwarded WebSocket frames `ws_messages` and agent executions `agent_runs` (v3); older files migrate on open along the chain 1→2→3. History for flows, streams, frames and runs. |
| `httpraw` | The shared **raw-bytes editable request** model and its serializer — deliberately non-normalizing so requests can be malformed. Also the transport-agnostic `Stream`/`Message`/`Transport`/`Direction` model for non-HTTP capture and the `WsMessage` frame model. Used by proxy, socks, repeater, intruder, store. |
| `repeater` | Takes one request, resends it (via a raw client that does not normalize), returns the response. Works over TCP (optionally TLS) or UDP, with an explicit `ReadMode` for protocols that have no HTTP framing. |
| `intruder` | Automated attacks: injection points, payload sets, attack modes, concurrent execution, results with metrics. Checks `scope` before running. |
| `runner` | The **tool runner**: receives an approved agent proposal, validates it against the catalog schema + `scope`, executes via argv (never a shell), sandboxed, captures/parses output. Verifies the binary exists first. |
| `catalog` | Loads catalog entries and validates them against `../../catalog/schema`. Used by `runner` and by the Tauri agent bridge. (The Python agent reads the same YAML directly for grounding.) |

## Invariants

- Allow-list, default-deny: only flags present in a catalog entry may execute.
- Effective intrusiveness = max(tool, used flags) → drives mandatory confirmation.
- The agent proposes; `runner` validates and executes. Nothing else executes tools.
  The bridge that wires the two lives in `../app/src-tauri/src/agent.rs`; it
  re-validates at execution time, so a UI round trip is never trusted.
- Out-of-scope traffic is never intercepted, decrypted or persisted — including
  WebSocket frames, which are not even paused.
