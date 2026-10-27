// Wire types for the replay commands. They mirror `RepeatArgs` / `AttackArgs`
// in `app/src-tauri/src/replay.rs` (serde, camelCase). Tokens are used instead
// of raw enum layouts on purpose: an unknown token is rejected by the backend
// rather than silently reinterpreted.

import type { Response } from "../proxy/types";

export type Transport = "tcp" | "udp";
export type ReadMode = "http" | "untilIdle" | "exact" | "untilClose" | "datagram";
export type AttackMode = "sniper" | "batteringRam" | "pitchfork" | "clusterBomb";

export const TRANSPORTS: Array<[Transport, string]> = [
  ["tcp", "TCP"],
  ["udp", "UDP"],
];

export const READ_MODES: Array<[ReadMode, string]> = [
  ["http", "HTTP framing"],
  ["untilIdle", "until idle"],
  ["exact", "exact bytes"],
  ["untilClose", "until close"],
  ["datagram", "one datagram"],
];

/** Read modes that are valid for a transport (the backend rejects the rest). */
export function readModesFor(transport: Transport): Array<[ReadMode, string]> {
  return transport === "udp"
    ? [["datagram", "one datagram"]]
    : READ_MODES.filter(([m]) => m !== "datagram");
}

export const ATTACK_MODES: Array<[AttackMode, string]> = [
  ["sniper", "Sniper"],
  ["batteringRam", "Battering ram"],
  ["pitchfork", "Pitchfork"],
  ["clusterBomb", "Cluster bomb"],
];

/** Pitchfork and cluster bomb need one payload set per position. */
export function needsSetPerPosition(mode: AttackMode): boolean {
  return mode === "pitchfork" || mode === "clusterBomb";
}

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_IDLE_MS = 500;

export type RepeatArgs = {
  host: string;
  port: number;
  tls: boolean;
  transport: Transport;
  readMode: ReadMode;
  idleMs: number | null;
  exactBytes: number | null;
  readTimeoutMs: number;
  acceptInvalidCerts: boolean;
  raw: number[];
};

export type RepeatReply = {
  /** Exact bytes received, whatever the protocol. */
  raw: number[];
  /** Best-effort HTTP parse; null for a non-HTTP reply. */
  response: Response | null;
  elapsedMs: number;
};

export type AttackArgs = {
  host: string;
  port: number;
  tls: boolean;
  transport: Transport;
  readMode: ReadMode;
  idleMs: number | null;
  exactBytes: number | null;
  readTimeoutMs: number;
  acceptInvalidCerts: boolean;
  base: number[];
  /** Injection points as [start, end) byte ranges. */
  positions: Array<[number, number]>;
  /** One set for Sniper/Battering ram, one per position otherwise. */
  payloadSets: string[][];
  mode: AttackMode;
  concurrency: number;
};

export type AttackSummary = { total: number; responses: number; errors: number };

export type AttackResult = {
  index: number;
  assignments: string[];
  status: number | null;
  responseLen: number;
  elapsedMs: number;
  error: string | null;
};

export function defaultRepeatArgs(): RepeatArgs {
  return {
    host: "127.0.0.1",
    port: 6379,
    tls: false,
    transport: "tcp",
    readMode: "untilIdle",
    idleMs: DEFAULT_IDLE_MS,
    exactBytes: null,
    readTimeoutMs: DEFAULT_TIMEOUT_MS,
    acceptInvalidCerts: false,
    raw: [],
  };
}

export function defaultAttackArgs(): AttackArgs {
  return {
    host: "127.0.0.1",
    port: 6379,
    tls: false,
    transport: "tcp",
    readMode: "untilIdle",
    idleMs: DEFAULT_IDLE_MS,
    exactBytes: null,
    readTimeoutMs: DEFAULT_TIMEOUT_MS,
    acceptInvalidCerts: false,
    base: [],
    positions: [],
    payloadSets: [],
    mode: "sniper",
    concurrency: 8,
  };
}
