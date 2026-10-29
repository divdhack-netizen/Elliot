import { useEffect, useMemo, useState } from "react";
import { SplitPane } from "../components/SplitPane";
import { invoke } from "../proxy/backend";
import { decode, fmtBytes, fmtClock, isProbablyText, timeMs } from "../proxy/format";
import type { ContextInput } from "../agent/types";
import { HexDump } from "../proxy/MessageViewer";
import { DEFAULT_IDLE_MS, DEFAULT_TIMEOUT_MS, type AttackArgs, type RepeatArgs } from "../replay/types";
import type { MessageWire, StreamWire } from "./types";
import { useCapture } from "./useCapture";

type Props = {
  onSendToRepeater: (args: RepeatArgs) => void;
  onSendToIntruder: (args: AttackArgs) => void;
  /// Attach the selected message to the agent's context tray.
  onSendToAgent?: (item: ContextInput) => void;
};

type ByteTab = "hex" | "text";

/// Capture of non-HTTP traffic: point a client (or `proxychains`) at the SOCKS
/// listener and the raw streams show up here, ready to hand to the repeater or
/// the intruder.
export function CaptureScreen({ onSendToRepeater, onSendToIntruder, onSendToAgent }: Props) {
  const api = useCapture();
  const [selectedStream, setSelectedStream] = useState<string | null>(null);
  const [selectedMessage, setSelectedMessage] = useState<string | null>(null);
  const [tab, setTab] = useState<ByteTab>("hex");

  const running = api.status === "running";
  const messages = selectedStream ? api.messagesFor(selectedStream) : [];
  const stream = useMemo(
    () => api.rows.find((r) => r.stream.id === selectedStream)?.stream ?? null,
    [api.rows, selectedStream],
  );
  const message = messages.find((m) => m.id === selectedMessage) ?? null;

  // A stream's persisted messages are fetched the first time it is shown.
  useEffect(() => {
    if (selectedStream) void api.loadMessages(selectedStream);
  }, [selectedStream, api.loadMessages]);

  useEffect(() => {
    if (!message && messages.length) setSelectedMessage(messages[messages.length - 1].id);
  }, [message, messages]);

  /// The target and read-mode defaults for a captured message, mirroring what
  /// the backend builds from the store (used when there is no project open, so
  /// the bytes are only in memory here).
  function localArgs(s: StreamWire, m: MessageWire) {
    const udp = s.transport === "Udp";
    return {
      host: s.host,
      port: s.port,
      tls: s.tls,
      transport: udp ? ("udp" as const) : ("tcp" as const),
      readMode: udp ? ("datagram" as const) : ("untilIdle" as const),
      idleMs: udp ? null : DEFAULT_IDLE_MS,
      exactBytes: null,
      readTimeoutMs: DEFAULT_TIMEOUT_MS,
      acceptInvalidCerts: false,
      raw: m.data,
    };
  }

  async function handToRepeater(m: MessageWire) {
    const s = api.rows.find((r) => r.stream.id === m.stream_id)?.stream ?? null;
    try {
      // The backend builds the request from the *persisted* stream and message
      // (the store is the source of truth), which needs an open project.
      const args = await invoke<RepeatArgs>("send_to_repeater", {
        streamId: m.stream_id,
        messageId: m.id,
      });
      onSendToRepeater(args);
    } catch (e) {
      // Nothing is persisted without a project, but the bytes are right here:
      // hand them over from memory rather than refusing.
      if (s) onSendToRepeater(localArgs(s, m));
      else api.setError(String(e));
    }
  }

  async function handToIntruder(m: MessageWire) {
    const s = api.rows.find((r) => r.stream.id === m.stream_id)?.stream ?? null;
    try {
      const args = await invoke<AttackArgs>("send_to_intruder", {
        streamId: m.stream_id,
        messageId: m.id,
      });
      onSendToIntruder(args);
    } catch (e) {
      if (s) {
        const { raw, ...target } = localArgs(s, m);
        onSendToIntruder({
          ...target,
          base: raw,
          positions: [],
          payloadSets: [],
          mode: "sniper",
          concurrency: 8,
        });
      } else {
        api.setError(String(e));
      }
    }
  }

  return (
    <div className="proxy">
      <div className="toolbar">
        <span className="viewer-title">Capture</span>
        <span className="muted small">non-HTTP (SOCKS5)</span>
        <span className="divider" />
        <label className="addr">
          <span className="muted small">Listen</span>
          <input
            className="mono"
            value={api.listenAddr}
            disabled={api.status !== "stopped"}
            onChange={(e) => api.setListenAddr(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void api.start()}
            spellCheck={false}
          />
        </label>
        <label className="toggle-inline" title="Terminate TLS in scope and capture the plaintext">
          <input
            type="checkbox"
            checked={api.mitmTls}
            disabled={api.status !== "stopped"}
            onChange={(e) => api.setMitmTls(e.target.checked)}
          />
          MITM TLS
        </label>
        <span className="spacer" />
        <button className="btn ghost" onClick={() => void api.reload()} title="Load streams saved in the open project">
          ⟳ Reload
        </button>
        {running ? (
          <button className="btn danger" onClick={() => void api.stop()}>
            ■ Stop
          </button>
        ) : (
          <button className="btn primary" disabled={api.status === "starting"} onClick={() => void api.start()}>
            ▶ {api.status === "starting" ? "Starting…" : "Start"}
          </button>
        )}
      </div>

      {api.error && (
        <div className="banner error">
          <span>{api.error}</span>
          <button className="icon-btn" onClick={() => api.setError(null)}>
            ✕
          </button>
        </div>
      )}

      <div className="proxy-body">
        <SplitPane direction="column" initial={0.4}>
          <div className="viewer-body">
            <table className="grid-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Transport</th>
                  <th>TLS</th>
                  <th>Client</th>
                  <th className="right">Msgs</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {api.rows.map((row, i) => (
                  <tr
                    key={row.stream.id}
                    className={`${row.stream.id === selectedStream ? "selected" : ""} ${row.stream.state === "Error" ? "c-error" : ""}`}
                    onClick={() => {
                      setSelectedStream(row.stream.id);
                      setSelectedMessage(null);
                    }}
                  >
                    <td className="mono">{i + 1}</td>
                    <td className="mono">{fmtClock(timeMs(row.stream.started_at))}</td>
                    <td className="mono ellipsis">{row.stream.host}</td>
                    <td className="mono">{row.stream.port}</td>
                    <td className="mono">{row.stream.transport.toLowerCase()}</td>
                    <td className="mono">{row.stream.tls ? "🔒" : ""}</td>
                    <td className="mono">{row.stream.client_addr}</td>
                    <td className="mono right">{row.messages}</td>
                    <td className="mono">{stateLabel(row.stream)}</td>
                  </tr>
                ))}
                {api.rows.length === 0 && (
                  <tr>
                    <td colSpan={9} className="placeholder">
                      {running
                        ? "Listening — point a client at the listener (e.g. curl --socks5-hostname, proxychains) or press Reload to load a saved project"
                        : "No streams yet: start the listener, or open a project and press Reload"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <SplitPane direction="row" initial={0.32}>
            <section className="viewer">
              <header className="viewer-head">
                <span className="viewer-title">Messages</span>
                <span className="spacer" />
                <span className="muted mono small">{messages.length}</span>
              </header>
              <div className="viewer-body">
                <table className="grid-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Dir</th>
                      <th className="right">Size</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {messages.map((m) => (
                      <tr
                        key={m.id}
                        className={m.id === selectedMessage ? "selected" : ""}
                        onClick={() => setSelectedMessage(m.id)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setSelectedMessage(m.id);
                        }}
                      >
                        <td className="mono">{m.seq}</td>
                        <td className="mono">{m.direction === "ClientToServer" ? "→" : "←"}</td>
                        <td className="mono right">{fmtBytes(m.data.length)}</td>
                        <td className="mono">{fmtClock(timeMs(m.at))}</td>
                      </tr>
                    ))}
                    {messages.length === 0 && (
                      <tr>
                        <td colSpan={4} className="placeholder">
                          {stream ? "No messages captured on this stream" : "Select a stream"}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="viewer">
              <header className="viewer-head">
                <span className="viewer-title">Bytes</span>
                <nav className="seg">
                  <button className={tab === "hex" ? "active" : ""} onClick={() => setTab("hex")}>
                    Hex
                  </button>
                  <button className={tab === "text" ? "active" : ""} onClick={() => setTab("text")}>
                    Text
                  </button>
                </nav>
                <span className="spacer" />
                {stream && <span className="muted mono small">{stream.transport.toLowerCase()}</span>}
                {message && <span className="muted mono small">{fmtBytes(message.data.length)} B</span>}
                <button
                  className="btn ghost"
                  disabled={!message}
                  onClick={() => message && void handToRepeater(message)}
                >
                  → Repeater
                </button>
                <button
                  className="btn ghost"
                  disabled={!message}
                  onClick={() => message && void handToIntruder(message)}
                >
                  → Intruder
                </button>
                <button
                  className="btn ghost"
                  disabled={!message || !stream || !onSendToAgent}
                  onClick={() => message && stream && onSendToAgent?.(agentItem(stream, message))}
                  title="Attach these bytes to the agent's context"
                >
                  → Agent
                </button>
              </header>
              <div className="viewer-body">
                {!message ? (
                  <div className="placeholder">Select a message to see its bytes</div>
                ) : tab === "hex" ? (
                  <HexDump bytes={message.data} />
                ) : (
                  <pre className="code">{decode(message.data)}</pre>
                )}
              </div>
            </section>
          </SplitPane>
        </SplitPane>
      </div>

      <footer className="statusbar">
        <span className={`dot ${running ? "on" : api.status === "starting" ? "busy" : ""}`} />
        <span>
          {running
            ? `SOCKS5 listening on ${api.listenAddr}`
            : api.status === "starting"
              ? "Starting…"
              : "Listener stopped"}
        </span>
        <span className="sep" />
        <span>capture-all by default · out of scope is tunnelled, never captured</span>
        <span className="spacer" />
        <span>Streams: {api.rows.length}</span>
        {stream && (
          <>
            <span className="sep" />
            <span className="mono">
              {stream.host}:{stream.port}
            </span>
          </>
        )}
      </footer>
    </div>
  );
}

/// The context item for one captured message. Binary payloads carry a hex
/// preview plus their length instead of a lossy decode.
function agentItem(s: StreamWire, m: MessageWire): ContextInput {
  const text = isProbablyText(m.data)
    ? decode(m.data)
    : `[binary, ${m.data.length} bytes]\n${m.data
        .slice(0, 256)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ")}`;
  return {
    label: `${s.transport} ${s.host}:${s.port} message ${m.seq}`,
    target: `${s.transport.toLowerCase()}://${s.host}:${s.port}`,
    text,
    source: `message:${m.id}`,
  };
}

function stateLabel(stream: StreamWire): string {
  if (stream.state === "Error") return stream.error ? `error: ${stream.error}` : "error";
  return stream.state.toLowerCase();
}
