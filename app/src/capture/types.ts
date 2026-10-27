// Wire types for the `socks://stream` event and the persisted capture
// commands. They mirror `elliot_httpraw::{Stream, Message}` as serde
// serializes them: `Bytes`/`Vec<u8>` arrive as number arrays, `SystemTime` as
// seconds + nanos, and the enums as their variant names.

import type { Time } from "../proxy/types";

export type Transport = "Tcp" | "Udp";
export type Direction = "ClientToServer" | "ServerToClient";
export type StreamState = "Pending" | "Paused" | "Completed" | "Dropped" | "Error";

/** A captured connection (TCP) or association (UDP) that is not HTTP. */
export type StreamWire = {
  id: string;
  started_at: Time;
  completed_at: Time | null;
  client_addr: string;
  transport: Transport;
  host: string;
  port: number;
  /** True when the bytes are application plaintext behind a terminated TLS. */
  tls: boolean;
  scope: "InScope" | "OutOfScope" | "Passthrough";
  state: StreamState;
  error: string | null;
};

/** One observed chunk (TCP) or datagram (UDP). */
export type MessageWire = {
  id: string;
  stream_id: string;
  seq: number;
  at: Time;
  direction: Direction;
  data: number[];
};

export type CaptureEvent = {
  kind: "started" | "message" | "completed" | "error";
  stream?: StreamWire;
  message?: MessageWire;
  error?: string;
};
