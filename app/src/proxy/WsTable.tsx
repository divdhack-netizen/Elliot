import { fmtBytes, fmtClock, timeMs } from "./format";
import type { WsMessage } from "./types";

/// The WebSocket history table: one row per forwarded frame.
///
/// A frame is not a request, so there is no status/method column here — only
/// what a frame actually has: direction, target, kind, size and a preview.
type Props = {
  rows: WsMessage[];
  selectedId: string | null;
  onSelect: (id: string) => void;
};

export function WsTable({ rows, selectedId, onSelect }: Props) {
  return (
    <div className="viewer">
      <header className="viewer-head">
        <span className="viewer-title">WebSocket</span>
        <span className="spacer" />
        <span className="muted mono small">{rows.length}</span>
      </header>
      <div className="viewer-body">
        <table className="grid-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Dir</th>
              <th>Host</th>
              <th>Kind</th>
              <th className="right">Size</th>
              <th>Preview</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr
                key={m.id}
                className={m.id === selectedId ? "selected" : ""}
                onClick={() => onSelect(m.id)}
              >
                <td className="mono">{fmtClock(timeMs(m.at))}</td>
                <td>
                  <span className={`dir ${m.direction === "ClientToServer" ? "c2s" : "s2c"}`}>
                    {m.direction === "ClientToServer" ? "→" : "←"}
                  </span>
                </td>
                <td className="mono ellipsis" title={`${m.host}:${m.port}`}>
                  {m.host}:{m.port}
                </td>
                <td className="mono">{m.kind.toLowerCase()}</td>
                <td className="mono right">{fmtBytes(m.payload.length)}</td>
                <td className="mono ellipsis preview">{preview(m)}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="placeholder">
                  No WebSocket frames yet: connect a client through the proxy, or open a project
                  and press Reload
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/// A short, single-line rendering of a payload. Text is shown as text; binary
/// is hex, because decoding it would produce noise.
export function preview(m: WsMessage): string {
  if (m.kind === "Close") return "(close)";
  if (m.kind === "Ping" || m.kind === "Pong") return "";
  const text = isText(m)
    ? new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(m.payload))
    : m.payload
        .slice(0, 48)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > 120 ? `${oneLine.slice(0, 120)}…` : oneLine;
}

/// Text frames are text by protocol. A binary frame is still shown as text when
/// its bytes look like UTF-8 text, which is the common case for JSON app
/// protocols that (wrongly) use binary.
export function isText(m: WsMessage): boolean {
  if (m.kind === "Text") return true;
  if (m.kind !== "Binary") return false;
  const sample = m.payload.slice(0, 512);
  if (sample.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(sample));
    return true;
  } catch {
    return false;
  }
}
