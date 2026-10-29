// Wire types for the passive sniffer (`elliot-sniff` via the Tauri shell).
// They mirror the Rust structs as serde serializes them: camelCase fields,
// `SystemTime` as seconds + nanos, and the shared enums as variant names.

import type { Time } from "../proxy/types";

export type SniffTransport = "Tcp" | "Udp";
export type SniffDirection = "ClientToServer" | "ServerToClient";
export type SniffScope = "InScope" | "OutOfScope" | "Passthrough";

/** An interface libpcap can capture on. */
export type SniffIface = {
  name: string;
  description: string | null;
  addresses: string[];
  loopback: boolean;
};

/** A 5-tuple observed on the wire, with cumulative counters. */
export type FlowMeta = {
  id: string;
  startedAt: Time;
  lastSeenAt: Time;
  clientAddr: string;
  serverAddr: string;
  transport: SniffTransport;
  /** SNI from a ClientHello or the name from a DNS query, once seen. */
  host: string | null;
  /** Best-effort tag; null until a host identifies the flow. */
  scope: SniffScope | null;
  packets: number;
  bytes: number;
  /** A TLS handshake was seen: the payload stays encrypted. */
  tls: boolean;
};

/** Metadata for one captured packet; the payload itself is not retained. */
export type PacketMeta = {
  flowId: string;
  at: Time;
  direction: SniffDirection;
  srcAddr: string;
  dstAddr: string;
  wireLen: number;
  payloadLen: number;
  tcpFlags: string | null;
  info: string | null;
};

export type SniffEvent = {
  kind: "started" | "updated" | "packet" | "error";
  flow?: FlowMeta;
  packet?: PacketMeta;
  error?: string;
};

export type SniffStatus = {
  running: boolean;
  interface: string | null;
  bpfFilter: string | null;
};
