import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { fmtBytes, fmtClock, fmtDuration } from "./format";
import type { Highlight, Row } from "./types";

const ROW_H = 22;
const OVERSCAN = 12;

type SortKey = "seq" | "host" | "method" | "path" | "status" | "length" | "mime" | "ext" | "tls" | "time" | "duration";
type Column = { key: SortKey; label: string; width: string; align?: "right"; cell: (r: Row) => React.ReactNode; title?: (r: Row) => string };

const COLUMNS: Column[] = [
  { key: "seq", label: "#", width: "52px", align: "right", cell: (r) => r.seq },
  { key: "host", label: "Host", width: "minmax(140px, 1.1fr)", cell: (r) => r.flow.host, title: (r) => `${r.flow.host}:${r.flow.port}` },
  { key: "method", label: "Method", width: "70px", cell: (r) => <span className={`method m-${r.flow.request.method.toLowerCase()}`}>{r.flow.request.method}</span> },
  { key: "path", label: "URL", width: "minmax(200px, 3fr)", cell: (r) => r.path, title: (r) => r.url },
  { key: "status", label: "Status", width: "62px", align: "right", cell: statusCell },
  { key: "length", label: "Length", width: "68px", align: "right", cell: (r) => fmtBytes(r.length) },
  { key: "mime", label: "MIME", width: "64px", cell: (r) => r.mime },
  { key: "ext", label: "Ext", width: "48px", cell: (r) => r.ext },
  { key: "tls", label: "TLS", width: "36px", cell: (r) => (r.flow.scheme === "Https" ? <span className="tls" title="HTTPS">🔒</span> : "") },
  { key: "time", label: "Time", width: "96px", cell: (r) => fmtClock(r.startedMs) },
  { key: "duration", label: "Duration", width: "76px", align: "right", cell: (r) => fmtDuration(r.durationMs) },
];

const GRID = COLUMNS.map((c) => c.width).join(" ");

function statusCell(r: Row) {
  const f = r.flow;
  if (f.response) return f.response.status;
  switch (f.state) {
    case "Paused": return <span className="badge badge-paused">held</span>;
    case "Dropped": return <span className="badge badge-dropped">drop</span>;
    case "Error": return <span className="badge badge-error">err</span>;
    default: return <span className="spinner" />;
  }
}

function sortValue(r: Row, k: SortKey): string | number {
  switch (k) {
    case "seq": return r.seq;
    case "host": return r.flow.host;
    case "method": return r.flow.request.method;
    case "path": return r.path;
    case "status": return r.flow.response?.status ?? -1;
    case "length": return r.length ?? -1;
    case "mime": return r.mime;
    case "ext": return r.ext;
    case "tls": return r.flow.scheme;
    case "time": return r.startedMs;
    case "duration": return r.durationMs ?? -1;
  }
}

/// Wireshark-style automatic colouring, overridden by a manual Burp highlight.
function rowClass(r: Row, hl: Highlight | undefined): string {
  if (hl) return `hl-${hl}`;
  const f = r.flow;
  if (f.state === "Paused") return "c-paused";
  if (f.state === "Error") return "c-error";
  if (f.state === "Dropped") return "c-dropped";
  const s = f.response?.status;
  if (s == null) return "c-pending";
  if (s >= 500) return "c-5xx";
  if (s >= 400) return "c-4xx";
  if (s >= 300) return "c-3xx";
  return "";
}

type Props = {
  rows: Row[];
  selectedId: string | null;
  highlights: Record<string, Highlight>;
  onSelect: (id: string) => void;
  onContextMenu: (row: Row, x: number, y: number) => void;
};

export function FlowTable({ rows, selectedId, highlights, onSelect, onContextMenu }: Props) {
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "seq", dir: 1 });
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(400);
  const body = useRef<HTMLDivElement>(null);
  const stick = useRef(true); // auto-scroll while the view is pinned to the newest row

  const sorted = useMemo(() => {
    if (sort.key === "seq" && sort.dir === 1) return rows;
    const out = rows.slice();
    out.sort((a, b) => {
      const va = sortValue(a, sort.key), vb = sortValue(b, sort.key);
      return (va < vb ? -1 : va > vb ? 1 : a.seq - b.seq) * sort.dir;
    });
    return out;
  }, [rows, sort]);

  useLayoutEffect(() => {
    const el = body.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const el = body.current;
    if (el && stick.current && sort.key === "seq" && sort.dir === 1) el.scrollTop = el.scrollHeight;
  }, [sorted.length, sort]);

  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last = Math.min(sorted.length, Math.ceil((scrollTop + height) / ROW_H) + OVERSCAN);

  function onKeyDown(e: React.KeyboardEvent) {
    if (!["ArrowDown", "ArrowUp", "Home", "End", "PageDown", "PageUp"].includes(e.key) || !sorted.length) return;
    e.preventDefault();
    const idx = sorted.findIndex((r) => r.flow.id === selectedId);
    const page = Math.max(1, Math.floor(height / ROW_H) - 1);
    let next = idx;
    if (e.key === "ArrowDown") next = idx < 0 ? 0 : idx + 1;
    if (e.key === "ArrowUp") next = idx < 0 ? 0 : idx - 1;
    if (e.key === "PageDown") next = idx + page;
    if (e.key === "PageUp") next = idx - page;
    if (e.key === "Home") next = 0;
    if (e.key === "End") next = sorted.length - 1;
    next = Math.max(0, Math.min(sorted.length - 1, next));
    onSelect(sorted[next].flow.id);
    const el = body.current;
    if (el) {
      const top = next * ROW_H;
      if (top < el.scrollTop) el.scrollTop = top;
      else if (top + ROW_H > el.scrollTop + el.clientHeight) el.scrollTop = top + ROW_H - el.clientHeight;
    }
  }

  return (
    <div className="table" style={{ ["--grid" as string]: GRID }}>
      <div className="thead">
        {COLUMNS.map((c) => (
          <button
            key={c.key}
            className={`th ${c.align === "right" ? "right" : ""} ${sort.key === c.key ? "sorted" : ""}`}
            onClick={() => setSort((s) => (s.key === c.key ? { key: c.key, dir: s.dir === 1 ? -1 : 1 } : { key: c.key, dir: 1 }))}
          >
            {c.label}
            {sort.key === c.key && <span className="sort-arrow">{sort.dir === 1 ? "▲" : "▼"}</span>}
          </button>
        ))}
      </div>
      <div
        ref={body}
        className="tbody"
        tabIndex={0}
        onKeyDown={onKeyDown}
        onScroll={(e) => {
          const el = e.currentTarget;
          setScrollTop(el.scrollTop);
          stick.current = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_H;
        }}
      >
        {sorted.length === 0 ? (
          <div className="empty">
            <div className="empty-title">No traffic captured yet</div>
            <div className="empty-sub">Start the proxy and point your browser at it to see requests here.</div>
          </div>
        ) : (
          <div style={{ height: sorted.length * ROW_H, position: "relative" }}>
            {sorted.slice(first, last).map((r, i) => {
              const sel = r.flow.id === selectedId;
              return (
                <div
                  key={r.flow.id}
                  className={`tr ${rowClass(r, highlights[r.flow.id])} ${sel ? "selected" : ""} ${r.flow.scope !== "InScope" ? "out-of-scope" : ""}`}
                  style={{ top: (first + i) * ROW_H, height: ROW_H }}
                  onMouseDown={() => onSelect(r.flow.id)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    onSelect(r.flow.id);
                    onContextMenu(r, e.clientX, e.clientY);
                  }}
                >
                  {COLUMNS.map((c) => (
                    <div key={c.key} className={`td ${c.align === "right" ? "right" : ""}`} title={c.title?.(r)}>
                      {c.cell(r)}
                    </div>
                  ))}
                  {r.edited && <span className="edited-mark" title="Edited in intercept" />}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
