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

/// The result of one approved execution.
export type Execution = {
  proposalId: string;
  status: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  error: string | null;
};

/// One item of the conversation, oldest first.
export type Item =
  | { kind: "user"; id: string; text: string }
  | { kind: "agent"; id: string; text: string; streaming: boolean }
  | { kind: "proposal"; id: string; proposal: Proposal }
  | { kind: "execution"; id: string; execution: Execution }
  | { kind: "error"; id: string; text: string };

export const INTRUSIVENESS_LABEL: Record<string, string> = {
  passive: "Passive",
  low: "Low",
  intrusive: "Intrusive",
  dangerous: "Dangerous",
};
