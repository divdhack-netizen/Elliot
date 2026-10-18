# core — the Rust engine

A Cargo workspace of focused crates. **No UI here.** The engine is independent
of Tauri so it can be tested on its own; the desktop app (`../app/src-tauri`)
depends on these crates.

| crate | responsibility |
|---|---|
| `proxy` | MITM proxy: local CA + on-the-fly per-host certs, HTTP/1.1, HTTP/2, WebSocket. Produces request/response *flows*. Passive and intercept modes. |
| `scope` | Scope policy engine. The **single source of truth** for what is in/out of scope. Queried by proxy, intruder, repeater, and the tool runner. Include/exclude rules on host/port/path/regex. |
| `store` | Per-project SQLite store, SQLCipher-encrypted. The project file *is* the database. Bodies as blobs. Flow history, search, the filter DSL. |
| `httpraw` | The shared **raw-bytes editable request** model and its serializer — deliberately non-normalizing so requests can be malformed. Used by proxy, repeater, intruder. |
| `repeater` | Takes one request, resends it (via a raw client that does not normalize), returns the response. |
| `intruder` | Automated attacks: injection points, payload sets, attack modes, concurrent execution, results with metrics. Checks `scope` before running. |
| `runner` | The **tool runner**: receives an approved agent proposal, validates it against the catalog schema + `scope`, executes via argv (never a shell), sandboxed, captures/parses output. Verifies the binary exists first. |
| `catalog` | Loads catalog entries and validates them against `../../catalog/schema`. Used by `runner`. (The Python agent reads the same YAML directly for grounding.) |

## Invariants

- Allow-list, default-deny: only flags present in a catalog entry may execute.
- Effective intrusiveness = max(tool, used flags) → drives mandatory confirmation.
- The agent proposes; `runner` validates and executes. Nothing else executes tools.
