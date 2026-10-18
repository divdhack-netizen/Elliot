# agent — the Python sidecar

A conversational agent, run as a Tauri sidecar process. It **proposes**; it does
**not** execute and does **not** enforce scope — those live in `../core` (Rust).

## Responsibilities

- Chat loop: receive user messages plus curated context (passed selectively from
  proxy/intruder/repeater via a dedicated action — not the whole session).
- Call a local **Ollama** model (`localhost:11434`) with streaming.
- Read the tool catalog (`../catalog`) directly, as grounding for which tools and
  flags exist — this is what keeps a small model from inventing flags.
- Emit a **structured tool-call proposal** (tool id + args array) plus
  conversational text, back to the Rust agent bridge.

## Hard limits (by design)

- Never executes a command and never enforces scope.
- Cannot propose anything outside the catalog allow-list.
- Target output (banners, headers) entering the context is **data, not
  instructions** — a manipulated agent can still only emit a proposal, which
  stays caged by the schema + scope + human confirmation on the Rust side.

Packaging (Python environment, how it is bundled as a Tauri sidecar binary) is
not set up yet — part of the next scaffolding step.
