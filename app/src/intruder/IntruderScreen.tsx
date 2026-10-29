import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SplitPane } from "../components/SplitPane";
import { invoke, listen } from "../proxy/backend";
import { decode, fmtBytes, fmtDuration } from "../proxy/format";
import {
  byteOffsetOf,
  bytesToEditor,
  EDITOR_MODES,
  editorToBytes,
  type EditorMode,
} from "../replay/bytes";
import {
  ATTACK_MODES,
  defaultAttackArgs,
  needsSetPerPosition,
  readModesFor,
  READ_MODES,
  TRANSPORTS,
  type AttackArgs,
  type AttackMode,
  type AttackResult,
  type AttackSummary,
  type ReadMode,
  type Transport,
} from "../replay/types";

type Props = {
  /** An attack handed over from Capture: base bytes, no positions yet. */
  seed: AttackArgs | null;
};

type Params = Omit<AttackArgs, "base" | "positions" | "payloadSets" | "mode">;

type Point = { start: number; end: number };

/// Burp's Intruder over raw bytes: injection points are byte ranges, payloads
/// are lines of text, and the attack runs in the backend with bounded
/// concurrency. Results stream in as they complete.
export function IntruderScreen({ seed }: Props) {
  const [params, setParams] = useState<Params>(defaultAttackArgs);
  const [mode, setMode] = useState<EditorMode>("text");
  const [base, setBase] = useState("");
  const [points, setPoints] = useState<Point[]>([]);
  const [newPoint, setNewPoint] = useState<Point>({ start: 0, end: 0 });
  const [sets, setSets] = useState<string[]>([""]);
  const [attackMode, setAttackMode] = useState<AttackMode>("sniper");
  const [results, setResults] = useState<AttackResult[]>([]);
  const [summary, setSummary] = useState<AttackSummary | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const baseRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!seed) return;
    const { base: baseBytes, positions, payloadSets, mode: am, ...rest } = seed;
    setParams(rest);
    setBase(bytesToEditor(baseBytes, "text"));
    setMode("text");
    setPoints(positions.map(([start, end]) => ({ start, end })));
    setSets(payloadSets.length ? payloadSets.map((s) => s.join("\n")) : [""]);
    setAttackMode(am);
    setResults([]);
    setSummary(null);
    setError(null);
  }, [seed]);

  // Results arrive while the attack runs, so the table fills in live.
  useEffect(() => {
    const un = listen<AttackResult>("intruder://result", (r) => {
      setResults((prev) => [...prev, r]);
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  // Pitchfork and cluster bomb need one set per position; keep the editors in
  // step with the points instead of failing at run time.
  useEffect(() => {
    if (!needsSetPerPosition(attackMode)) return;
    setSets((prev) => {
      const next = prev.slice(0, Math.max(points.length, 1));
      while (next.length < Math.max(points.length, 1)) next.push("");
      return next;
    });
  }, [attackMode, points.length]);

  const baseBytes = useMemo(() => editorToBytes(base, mode), [base, mode]);

  const set = useCallback(<K extends keyof Params>(key: K, value: Params[K]) => {
    setParams((p) => ({ ...p, [key]: value }));
  }, []);

  const addPointFromSelection = useCallback(() => {
    if (mode !== "text" || !baseBytes.ok) {
      setError("select the bytes in Text mode, or type the offsets");
      return;
    }
    const el = baseRef.current;
    if (!el || el.selectionStart === el.selectionEnd) {
      setError("select the bytes to inject into");
      return;
    }
    const start = byteOffsetOf(base, el.selectionStart);
    const end = byteOffsetOf(base, el.selectionEnd);
    setPoints((prev) => [...prev, { start, end }]);
    setError(null);
  }, [base, baseBytes.ok, mode]);

  const run = useCallback(async () => {
    const parsed = editorToBytes(base, mode);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    if (points.length === 0) {
      setError("add at least one injection point");
      return;
    }
    const payloadSets = sets.map((text) =>
      text
        .split("\n")
        .map((l) => l.replace(/\r$/, ""))
        .filter((l) => l.length > 0),
    );
    setRunning(true);
    setResults([]);
    setSummary(null);
    setError(null);
    try {
      const done = await invoke<AttackSummary>("intruder_run", {
        args: {
          ...params,
          base: parsed.bytes,
          positions: points.map((p) => [p.start, p.end] as [number, number]),
          payloadSets,
          mode: attackMode,
        },
      });
      setSummary(done);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  }, [attackMode, base, mode, params, points, sets]);

  return (
    <div className="proxy">
      <div className="toolbar">
        <span className="viewer-title">Intruder</span>
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
        <label className="toggle-inline">
          <input type="checkbox" checked={params.tls} onChange={(e) => set("tls", e.target.checked)} />
          TLS
        </label>
        <label className="addr">
          <span className="muted small">Transport</span>
          <select
            value={params.transport}
            onChange={(e) => {
              const transport = e.target.value as Transport;
              set("transport", transport);
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
          <select value={params.readMode} onChange={(e) => set("readMode", e.target.value as ReadMode)}>
            {readModesFor(params.transport).map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        {params.readMode === "untilIdle" && (
          <label className="addr">
            <span className="muted small">Idle ms</span>
            <input
              className="num"
              type="number"
              value={params.idleMs ?? 0}
              onChange={(e) => set("idleMs", Number(e.target.value) || 0)}
            />
          </label>
        )}
        <label className="addr">
          <span className="muted small">Concurrency</span>
          <input
            className="num"
            type="number"
            value={params.concurrency}
            onChange={(e) => set("concurrency", Number(e.target.value) || 1)}
          />
        </label>
        <label className="addr">
          <span className="muted small">Mode</span>
          <select value={attackMode} onChange={(e) => setAttackMode(e.target.value as AttackMode)}>
            {ATTACK_MODES.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <span className="spacer" />
        <button className="btn primary" disabled={running} onClick={() => void run()}>
          {running ? "Attacking…" : "▶ Start attack"}
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
        <SplitPane direction="column" initial={0.45}>
          <div className="intruder-config">
            <section className="viewer">
              <header className="viewer-head">
                <span className="viewer-title">Base</span>
                <nav className="seg">
                  {EDITOR_MODES.map(([k, label]) => (
                    <button
                      key={k}
                      className={mode === k ? "active" : ""}
                      onClick={() => {
                        if (k === mode) return;
                        const parsed = editorToBytes(base, mode);
                        setBase(parsed.ok ? bytesToEditor(parsed.bytes, k) : "");
                        if (!parsed.ok) setError(parsed.error);
                        setMode(k);
                      }}
                    >
                      {label}
                    </button>
                  ))}
                </nav>
                <span className="spacer" />
                <button className="btn ghost" onClick={addPointFromSelection}>
                  + Point from selection
                </button>
                {baseBytes.ok && <span className="muted mono small">{fmtBytes(baseBytes.bytes.length)} B</span>}
              </header>
              <div className="editor-wrap">
                <textarea
                  ref={baseRef}
                  className="editor"
                  value={base}
                  spellCheck={false}
                  placeholder="Base request bytes — select a range and add it as a point"
                  onChange={(e) => setBase(e.target.value)}
                />
              </div>
            </section>

            <section className="viewer side">
              <header className="viewer-head">
                <span className="viewer-title">Points</span>
                <span className="spacer" />
                <span className="muted small">{points.length}</span>
              </header>
              <div className="viewer-body">
                <div className="row">
                  <input
                    className="num mono"
                    type="number"
                    value={newPoint.start}
                    onChange={(e) => setNewPoint((p) => ({ ...p, start: Number(e.target.value) || 0 }))}
                    title="Start offset"
                  />
                  <input
                    className="num mono"
                    type="number"
                    value={newPoint.end}
                    onChange={(e) => setNewPoint((p) => ({ ...p, end: Number(e.target.value) || 0 }))}
                    title="End offset (exclusive)"
                  />
                  <button
                    className="btn ghost"
                    onClick={() => {
                      if (newPoint.end < newPoint.start) {
                        setError("the end offset must not precede the start");
                        return;
                      }
                      setPoints((prev) => [...prev, newPoint]);
                      setError(null);
                    }}
                  >
                    + Add
                  </button>
                </div>
                {points.length === 0 ? (
                  <div className="placeholder">No injection points yet</div>
                ) : (
                  <ul className="point-list">
                    {points.map((p, i) => (
                      <li key={`${p.start}-${p.end}-${i}`}>
                        <span className="mono">
                          [{p.start}, {p.end})
                        </span>
                        <span className="mono muted ellipsis">{preview(baseBytes, p)}</span>
                        <button
                          className="icon-btn"
                          title="Remove"
                          onClick={() => setPoints((prev) => prev.filter((_, j) => j !== i))}
                        >
                          ✕
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>

            <section className="viewer side">
              <header className="viewer-head">
                <span className="viewer-title">Payloads</span>
                <span className="spacer" />
                <span className="muted small">
                  {needsSetPerPosition(attackMode)
                    ? "one set per position, one payload per line"
                    : "one payload per line"}
                </span>
              </header>
              <div className="viewer-body payloads">
                {(needsSetPerPosition(attackMode) ? sets : [sets[0] ?? ""]).map((text, i) => (
                  <div className="set" key={i}>
                    <label className="muted small">
                      {needsSetPerPosition(attackMode) ? `Set ${i + 1} (position ${i + 1})` : "Set 1"}
                    </label>
                    <textarea
                      className="editor"
                      value={text}
                      spellCheck={false}
                      placeholder="one payload per line"
                      onChange={(e) =>
                        setSets((prev) => {
                          const next = [...prev];
                          next[i] = e.target.value;
                          return next;
                        })
                      }
                    />
                  </div>
                ))}
              </div>
            </section>
          </div>

          <section className="viewer">
            <header className="viewer-head">
              <span className="viewer-title">Results</span>
              <span className="spacer" />
              {running && <span className="spinner" />}
              <span className="muted mono small">
                {results.length} shown
                {summary ? ` · ${summary.responses} ok · ${summary.errors} errors` : ""}
              </span>
            </header>
            <div className="viewer-body">
              <table className="grid-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Payloads</th>
                    <th>Status</th>
                    <th className="right">Length</th>
                    <th className="right">Elapsed</th>
                    <th>Error</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r) => (
                    <tr key={r.index} className={r.error ? "c-error" : ""}>
                      <td className="mono">{r.index}</td>
                      <td className="mono ellipsis">{r.assignments.join(" · ")}</td>
                      <td className="mono">{r.status ?? ""}</td>
                      <td className="mono right">{r.error ? "" : fmtBytes(r.responseLen)}</td>
                      <td className="mono right">{r.error ? "" : fmtDuration(r.elapsedMs)}</td>
                      <td className="mono ellipsis">{r.error ?? ""}</td>
                    </tr>
                  ))}
                  {results.length === 0 && (
                    <tr>
                      <td colSpan={6} className="placeholder">
                        {running ? "Waiting for the first reply…" : "No results yet"}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </SplitPane>
      </div>

      <footer className="statusbar">
        <span className={`dot ${running ? "busy" : ""}`} />
        <span className="mono">
          {params.transport}:{params.tls ? "tls" : "plain"} → {params.host}:{params.port}
        </span>
        <span className="sep" />
        <span>Read: {READ_MODES.find(([m]) => m === params.readMode)?.[1] ?? params.readMode}</span>
        <span className="sep" />
        <span>{points.length} point(s)</span>
        <span className="spacer" />
        <span>{running ? "Attack running" : summary ? "Attack finished" : "Idle"}</span>
      </footer>
    </div>
  );
}

/// The bytes a point covers, as text when they are text.
function preview(bytes: { ok: true; bytes: number[] } | { ok: false }, p: { start: number; end: number }): string {
  if (!bytes.ok) return "";
  const slice = bytes.bytes.slice(p.start, p.end);
  if (!slice.length) return "(empty)";
  const text = decode(slice);
  return /[^\x20-\x7e]/.test(text) ? `0x${slice.map((b) => b.toString(16).padStart(2, "0")).join("")}` : text;
}
