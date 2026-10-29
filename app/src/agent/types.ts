// Wire types for the `agent://*` events emitted by `app/src-tauri/src/agent.rs`.
// Field names mirror the Rust `#[serde(rename_all = "camelCase")]` structs.

/// A validated (or refused) proposal. `error` is `null` only when the command
/// passed catalog + scope + dangerous checks and may be approved.
export type Proposal = {
  id: string;
  toolId: string;
  program: string | null;
  argv: string[];
  targets: string[];
  effectiveIntrusiveness: string | null;
  requiredPrivileges: string[];
  error: string | null;
};

/// One recorded execution, as the "Runs" panel shows it. Survivors of a
/// project reopen, unlike the transcript.
export type AgentRun = {
  id: string;
  proposalId: string | null;
  toolId: string;
  program: string;
  argv: string[];
  effectiveIntrusiveness: string;
  requiredPrivileges: string[];
  startedMs: number;
  status: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  error: string | null;
};

/// The result of one approved execution.
export type Execution = {
  proposalId: string;
  status: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  error: string | null;
};

/// One piece of material attached to the session (a captured flow or message).
/// It reaches the model as data, marked as untrusted by the sidecar.
export type ContextItem = {
  id: string;
  label: string;
  target: string;
  source: string | null;
  text: string;
};

/// What the UI sends to attach an item; the backend assigns the id.
export type ContextInput = {
  label: string;
  target: string;
  text: string;
  source?: string | null;
};

/// One item of the conversation, oldest first.
export type Item =
  | { kind: "user"; id: string; text: string }
  | { kind: "agent"; id: string; text: string; streaming: boolean; latencyMs?: number }
  | { kind: "proposal"; id: string; proposal: Proposal }
  | { kind: "execution"; id: string; execution: Execution }
  | { kind: "error"; id: string; text: string };

export const INTRUSIVENESS_LABEL: Record<string, string> = {
  passive: "Passive",
  low: "Low",
  intrusive: "Intrusive",
  dangerous: "Dangerous",
};
