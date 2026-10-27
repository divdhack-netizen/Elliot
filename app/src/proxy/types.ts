// Wire types for the `proxy://flow` event. They mirror `elliot_httpraw::Flow`
// as serde serializes it: `Bytes`/`Vec<u8>` arrive as number arrays and
// `SystemTime` as seconds + nanos since the epoch.

export type Bytes = number[];
export type Header = { name: string; value: Bytes };
export type Time = { secs_since_epoch: number; nanos_since_epoch: number };
export type HttpVersion = "Http10" | "Http11" | "H2";
export type FlowState = "Pending" | "Paused" | "Completed" | "Dropped" | "Error";

export type Request = {
  method: string;
  target: string;
  version: HttpVersion;
  headers: Header[];
  body: Bytes;
  raw: Bytes;
};

export type Response = {
  status: number;
  reason: string;
  version: HttpVersion;
  headers: Header[];
  body: Bytes;
  raw: Bytes;
};

export type Flow = {
  id: string;
  started_at: Time;
  completed_at: Time | null;
  client_addr: string;
  scheme: "Http" | "Https";
  host: string;
  port: number;
  request: Request;
  response: Response | null;
  state: FlowState;
  scope: "InScope" | "OutOfScope" | "Passthrough";
  error: string | null;
};

export type WsDirection = "ClientToServer" | "ServerToClient";
export type WsKind = "Text" | "Binary" | "Ping" | "Pong" | "Close";

/// One WebSocket frame observed on an in-scope connection. `connection` is the
/// readable label; `connection_id` is stable for every frame of one socket.
/// `paused` marks a frame held by intercept, awaiting the user's decision.
export type WsMessage = {
  id: string;
  connection: string;
  connection_id: string;
  at: Time;
  client_addr: string;
  scheme: "Http" | "Https";
  host: string;
  port: number;
  direction: WsDirection;
  kind: WsKind;
  payload: Bytes;
  paused: boolean;
};

export type FlowEvent = {
  kind: string;
  flow: Flow | null;
  ws?: WsMessage | null;
  error: string | null;
};

/// A flow plus the frontend-only metadata the history table needs.
export type Row = {
  seq: number;
  flow: Flow;
  url: string;
  path: string;
  ext: string;
  mime: string;
  length: number | null;
  durationMs: number | null;
  startedMs: number;
  edited: boolean;
};

export type Highlight = "red" | "orange" | "yellow" | "green" | "cyan" | "blue" | "purple";
export const HIGHLIGHTS: Highlight[] = ["red", "orange", "yellow", "green", "cyan", "blue", "purple"];
