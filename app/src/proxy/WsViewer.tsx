import { useState } from "react";
import { decode } from "./format";
import { HexDump } from "./MessageViewer";
import type { WsMessage } from "./types";
import { isText } from "./WsTable";

type Tab = "text" | "hex";

/// One WebSocket frame, as text or hex. Copy takes the payload only: there is
/// no raw HTTP request to reproduce, so there is no Repeater hand-off here.
export function WsViewer({ message }: { message: WsMessage | null }) {
  const [tab, setTab] = useState<Tab>("text");
  const [copied, setCopied] = useState(false);

  function copy() {
    if (!message) return;
    navigator.clipboard.writeText(decode(message.payload)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  }

  return (
    <section className="viewer">
      <header className="viewer-head">
        <span className="viewer-title">Frame</span>
        <nav className="seg">
          <button className={tab === "text" ? "active" : ""} onClick={() => setTab("text")}>
            Text
          </button>
          <button className={tab === "hex" ? "active" : ""} onClick={() => setTab("hex")}>
            Hex
          </button>
        </nav>
        <span className="spacer" />
        {message && (
          <>
            <span className="muted mono small">
              {message.direction === "ClientToServer" ? "→ server" : "← client"} · {message.kind} ·{" "}
              {message.host}:{message.port} · {message.payload.length} B
            </span>
            <span className="muted small" title="Stable identity of this socket">
              {message.connection_id.slice(0, 8)}
            </span>
            <button className="icon-btn" onClick={copy} title="Copy payload">
              {copied ? "✓" : "⧉"}
            </button>
          </>
        )}
      </header>
      <div className="viewer-body">
        {!message ? (
          <div className="placeholder">Select a frame</div>
        ) : tab === "text" ? (
          isText(message) ? (
            <pre className="code">{decode(message.payload)}</pre>
          ) : (
            <div className="placeholder">Binary payload — see Hex</div>
          )
        ) : (
          <HexDump bytes={message.payload} />
        )}
      </div>
    </section>
  );
}
