import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SplitPane } from "../components/SplitPane";
import { invoke } from "../proxy/backend";
import { decode, fmtBytes, fmtDuration } from "../proxy/format";
import { HexDump } from "../proxy/MessageViewer";
import {
  bytesToEditor,
  EDITOR_MODES,
  editorToBytes,
  type EditorMode,
} from "../replay/bytes";
import {
  defaultRepeatArgs,
  readModesFor,
  READ_MODES,
  TRANSPORTS,
  type ReadMode,
  type RepeatArgs,
  type RepeatReply,
  type Transport,
} from "../replay/types";

type Props = {
  /** A request handed over from Capture or HTTP history. */
  seed: RepeatArgs | null;
};

type Params = Omit<RepeatArgs, "raw">;

type ResTab = "pretty" | "raw" | "hex" | "headers";

/// Burp's Repeater: send exactly the bytes in the editor and inspect the reply.
///
/// The request is never normalised — that is the whole point of the tool — and
/// the read mode tells the backend how the reply ends, so non-HTTP protocols
/// work as well as HTTP.
export function RepeaterScreen({ seed }: Props) {
  const [params, setParams] = useState<Params>(defaultRepeatArgs);
  const [mode, setMode] = useState<EditorMode>("text");
  const [editor, setEditor] = useState("");
  const [reply, setReply] = useState<RepeatReply | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<ResTab>("pretty");
  const editorRef = useRef<HTMLTextAreaElement>(null);

  // A hand-off replaces the whole form: it is a different request, not an edit.
  useEffect(() => {
    if (!seed) return;
    const { raw, ...rest } = seed;
    setParams(rest);
    setEditor(bytesToEditor(raw, "text"));
    setMode("text");
    setReply(null);
    setError(null);
  }, [seed]);

  const bytes = useMemo(() => editorToBytes(editor, mode), [editor, mode]);
  const byteCount = bytes.ok ? bytes.bytes.length : null;

  const set = useCallback(<K extends keyof Params>(key: K, value: Params[K]) => {
    setParams((p) => ({ ...p, [key]: value }));
  }, []);

  const send = useCallback(async () => {
    const parsed = editorToBytes(editor, mode);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // `response` is null for a non-HTTP reply: show Raw/Hex and say why.
      const res = await invoke<RepeatReply>("repeater_send", {
        args: { ...params, raw: parsed.bytes },
      });
      setReply(res);
      setTab(res.response ? "pretty" : "raw");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }, [editor, mode, params]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      void send();
    }
  };

  const http = reply?.response ?? null;

  return (
    <div className="proxy">
      <div className="toolbar">
        <span className="viewer-title">Repeater</span>
        <span className="divider" />
        <label className="addr">
          <span className="muted small">Host</span>
          <input
            className="mono"
            value={params.host}
            onChange={(e) => set("host", e.target.value)}
            spellCheck={false}
          />
        </label>
        <label className="addr">
          <span className="muted small">Port</span>
          <input
            className="mono num"
            type="number"
            value={params.port}
            onChange={(e) => set("port", Number(e.target.value) || 0)}
          />
        </label>
        <label className="toggle-inline" title="Wrap the connection in TLS">
          <input
            type="checkbox"
            checked={params.tls}
            onChange={(e) => set("tls", e.target.checked)}
          />
          TLS
        </label>
        <span className="divider" />
        <label className="addr">
          <span className="muted small">Transport</span>
          <select
            value={params.transport}
            onChange={(e) => {
              const transport = e.target.value as Transport;
              set("transport", transport);
              // A UDP replay is one datagram; a TCP one keeps the current mode.
              if (transport === "udp") set("readMode", "datagram");
              else if (params.readMode === "datagram") set("readMode", "untilIdle");
            }}
          >
            {TRANSPORTS.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="addr">
          <span className="muted small">Read</span>
          <select
            value={params.readMode}
            onChange={(e) => set("readMode", e.target.value as ReadMode)}
          >
            {readModesFor(params.transport).map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        {params.readMode === "untilIdle" && (
          <label className="addr" title="Stop reading after this much silence">
            <span className="muted small">Idle ms</span>
            <input
              className="num"
              type="number"
              value={params.idleMs ?? 0}
              onChange={(e) => set("idleMs", Number(e.target.value) || 0)}
            />
          </label>
        )}
        {params.readMode === "exact" && (
          <label className="addr" title="Read exactly this many bytes">
            <span className="muted small">Bytes</span>
            <input
              className="num"
              type="number"
              value={params.exactBytes ?? 0}
              onChange={(e) => set("exactBytes", Number(e.target.value) || 0)}
            />
          </label>
        )}
        <label className="addr">
          <span className="muted small">Timeout ms</span>
          <input
            className="num"
            type="number"
            value={params.readTimeoutMs}
            onChange={(e) => set("readTimeoutMs", Number(e.target.value) || 1)}
          />
        </label>
        <label className="toggle-inline" title="Skip upstream certificate verification">
          <input
            type="checkbox"
            checked={params.acceptInvalidCerts}
            onChange={(e) => set("acceptInvalidCerts", e.target.checked)}
          />
          Ignore TLS errors
        </label>
        <span className="spacer" />
        <button className="btn primary" disabled={busy} onClick={() => void send()} title="Ctrl/Cmd+Enter">
          {busy ? "Sending…" : "▶ Send"}
        </button>
      </div>

      {error && (
        <div className="banner error">
          <span>{error}</span>
          <button className="icon-btn" onClick={() => setError(null)}>
            ✕
          </button>
        </div>
      )}

      <div className="proxy-body">
        <SplitPane direction="row" initial={0.5}>
          <section className="viewer">
            <header className="viewer-head">
              <span className="viewer-title">Request</span>
              <nav className="seg">
                {EDITOR_MODES.map(([k, label]) => (
                  <button
                    key={k}
                    className={mode === k ? "active" : ""}
                    onClick={() => {
                      // Switching modes converts the buffer rather than clearing
                      // it, so the user can start in text and finish in hex.
                      if (k === mode) return;
                      const parsed = editorToBytes(editor, mode);
                      setEditor(parsed.ok ? bytesToEditor(parsed.bytes, k) : "");
                      if (!parsed.ok) setError(parsed.error);
                      setMode(k);
                    }}
                  >
                    {label}
                  </button>
                ))}
              </nav>
              <span className="spacer" />
              {byteCount == null ? (
                <span className="muted small">{bytes.ok ? "" : bytes.error}</span>
              ) : (
                <span className="muted mono small">{fmtBytes(byteCount)} B</span>
              )}
            </header>
            <div className="editor-wrap">
              <textarea
                ref={editorRef}
                className="editor"
                value={editor}
                spellCheck={false}
                placeholder="Request bytes — e.g. PING&#10;"
                onChange={(e) => setEditor(e.target.value)}
                onKeyDown={onKeyDown}
              />
            </div>
          </section>

          <section className="viewer">
            <header className="viewer-head">
              <span className="viewer-title">Response</span>
              <nav className="seg">
                {http && (
                  <button className={tab === "pretty" ? "active" : ""} onClick={() => setTab("pretty")}>
                    Pretty
                  </button>
                )}
                <button className={tab === "raw" ? "active" : ""} onClick={() => setTab("raw")}>
                  Raw
                </button>
                <button className={tab === "hex" ? "active" : ""} onClick={() => setTab("hex")}>
                  Hex
                </button>
                {http && (
                  <button className={tab === "headers" ? "active" : ""} onClick={() => setTab("headers")}>
                    Headers
                  </button>
                )}
              </nav>
              <span className="spacer" />
              {reply && (
                <>
                  {http && (
                    <span className={`status-pill s${Math.floor(http.status / 100)}`}>
                      {http.status} {http.reason}
                    </span>
                  )}
                  <span className="muted mono small">{fmtBytes(reply.raw.length)} B</span>
                  <span className="muted mono small">{fmtDuration(reply.elapsedMs)}</span>
                </>
              )}
            </header>
            <div className="viewer-body">
              {!reply ? (
                <div className="placeholder">Send the request to see the response</div>
              ) : tab === "pretty" && http ? (
                <pre className="code">
                  <span className="tok-start">
                    {http.version.replace("Http", "HTTP/")} {http.status} {http.reason}
                  </span>
                  {"\n"}
                  {http.headers.map((h, i) => (
                    <span key={i}>
                      <span className="tok-hname">{h.name}</span>
                      <span className="tok-punct">: </span>
                      <span className="tok-hval">{decode(h.value)}</span>
                      {"\n"}
                    </span>
                  ))}
                  {"\n"}
                  {decode(http.body)}
                </pre>
              ) : tab === "hex" ? (
                <HexDump bytes={reply.raw} />
              ) : tab === "headers" && http ? (
                <table className="kv">
                  <tbody>
                    {http.headers.map((h, i) => (
                      <tr key={i}>
                        <td className="tok-hname">{h.name}</td>
                        <td>{decode(h.value)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <>
                  {!http && (
                    <div className="notice">
                      Not a parseable HTTP response — the exact bytes are below.
                    </div>
                  )}
                  <pre className="code">{decode(reply.raw)}</pre>
                </>
              )}
            </div>
          </section>
        </SplitPane>
      </div>

      <footer className="statusbar">
        <span className="dot on" />
        <span className="mono">
          {params.transport === "udp" ? "udp" : params.tls ? "tls+tcp" : "tcp"} →{" "}
          {params.host}:{params.port}
        </span>
        <span className="sep" />
        <span>Read: {READ_MODES.find(([m]) => m === params.readMode)?.[1] ?? params.readMode}</span>
        <span className="spacer" />
        <span>Ctrl/Cmd+Enter to send</span>
      </footer>
    </div>
  );
}
