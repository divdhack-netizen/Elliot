import { useCallback, useMemo, useState } from "react";
import { ContextMenu, type MenuItem } from "../components/ContextMenu";
import { SplitPane } from "../components/SplitPane";
import { CaDialog } from "./CaDialog";
import { FlowTable } from "./FlowTable";
import { compileFilter, FIELD_NAMES } from "./filter";
import { decode, toCurl } from "./format";
import { InterceptView } from "./InterceptView";
import { MessageViewer, type Message, type ViewerTab } from "./MessageViewer";
import { HIGHLIGHTS, type Row } from "./types";
import { useProxy } from "./useProxy";
import { ScopePanel } from "../scope/ScopePanel";
import { useScope } from "../scope/useScope";
import { DEFAULT_TIMEOUT_MS, type AttackArgs, type RepeatArgs } from "../replay/types";

type SubTab = "intercept" | "history" | "scope";

type Props = {
  /// Hand an HTTP request over to the active tools (the same path a captured
  /// non-HTTP message takes).
  onSendToRepeater?: (args: RepeatArgs) => void;
  onSendToIntruder?: (args: AttackArgs) => void;
};

const FILTER_EXAMPLES = [
  "host contains api",
  "status >= 400",
  "method == POST && mime == JSON",
  "status == 5xx || state == error",
  "!(ext == js || ext == css || mime == image)",
];

export function ProxyScreen({ onSendToRepeater, onSendToIntruder }: Props = {}) {
  const api = useProxy();
  const scope = useScope();
  const [sub, setSub] = useState<SubTab>("history");
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [layout, setLayout] = useState<"row" | "column">("row");
  const [reqTab, setReqTab] = useState<ViewerTab>("pretty");
  const [resTab, setResTab] = useState<ViewerTab>("pretty");
  const [menu, setMenu] = useState<{ row: Row; x: number; y: number } | null>(null);
  const [pem, setPem] = useState<string | null>(null);

  const compiled = useMemo(() => compileFilter(filter), [filter]);
  const visible = useMemo(() => {
    if (!compiled.ok || !compiled.pred) return api.rows;
    const pred = compiled.pred;
    return api.rows.filter((r) => {
      try {
        return pred(r);
      } catch {
        return false;
      }
    });
  }, [api.rows, compiled]);

  const selected = api.rows.find((r) => r.flow.id === selectedId) ?? null;
  const reqMsg: Message | null = selected && {
    startLine: decode(selected.flow.request.raw).split("\r\n", 1)[0],
    headers: selected.flow.request.headers,
    body: selected.flow.request.body,
    raw: selected.flow.request.raw,
  };
  const res = selected?.flow.response;
  const resMsg: Message | null = res
    ? { startLine: decode(res.raw).split("\r\n", 1)[0], headers: res.headers, body: res.body, raw: res.raw }
    : null;

  const closeMenu = useCallback(() => setMenu(null), []);
  const copy = (s: string) => navigator.clipboard.writeText(s);

  /// The repeater/intruder arguments for one captured HTTP request. HTTP is
  /// just one more protocol over the generic replay path.
  function replayArgs(r: Row): RepeatArgs {
    return {
      host: r.flow.host,
      port: r.flow.port,
      tls: r.flow.scheme === "Https",
      transport: "tcp",
      readMode: "http",
      idleMs: null,
      exactBytes: null,
      readTimeoutMs: DEFAULT_TIMEOUT_MS,
      acceptInvalidCerts: false,
      raw: r.flow.request.raw,
    };
  }

  function menuItems(r: Row): MenuItem[] {
    const soon = "soon";
    return [
      {
        kind: "item",
        label: "Send to Repeater",
        disabled: !onSendToRepeater,
        onSelect: () => onSendToRepeater?.(replayArgs(r)),
      },
      {
        kind: "item",
        label: "Send to Intruder",
        disabled: !onSendToIntruder,
        onSelect: () => {
          const { raw, ...target } = replayArgs(r);
          onSendToIntruder?.({
            ...target,
            base: raw,
            // No injection points yet: the user picks them in the Intruder tab.
            positions: [],
            payloadSets: [],
            mode: "sniper",
            concurrency: 8,
          });
        },
      },
      { kind: "item", label: "Send to Agent", disabled: true, hint: soon },
      { kind: "separator" },
      { kind: "item", label: "Copy URL", onSelect: () => copy(r.url) },
      { kind: "item", label: "Copy as cURL", onSelect: () => copy(toCurl(r.flow)) },
      { kind: "item", label: "Copy raw request", onSelect: () => copy(decode(r.flow.request.raw)) },
      ...(r.flow.response
        ? [{ kind: "item" as const, label: "Copy raw response", onSelect: () => copy(decode(r.flow.response!.raw)) }]
        : []),
      { kind: "separator" },
      {
        kind: "submenu",
        label: "Highlight",
        items: [
          ...HIGHLIGHTS.map((h): MenuItem => ({
            kind: "item",
            label: h[0].toUpperCase() + h.slice(1),
            swatch: h,
            onSelect: () => api.setHighlight(r.flow.id, h),
          })),
          { kind: "separator" },
          { kind: "item", label: "None", onSelect: () => api.setHighlight(r.flow.id, null) },
        ],
      },
      { kind: "item", label: "Filter on this host", onSelect: () => setFilter(`host == "${r.flow.host}"`) },
      { kind: "separator" },
      {
        kind: "item",
        label: "Remove from history",
        disabled: r.flow.state === "Paused",
        onSelect: () => {
          api.remove(r.flow.id);
          if (selectedId === r.flow.id) setSelectedId(null);
        },
      },
    ];
  }

  const running = api.status === "running";

  return (
    <div className="proxy">
      {/* Toolbar: Burp's sub-tabs on the left, capture controls on the right. */}
      <div className="toolbar">
        <nav className="subtabs">
          <button className={sub === "intercept" ? "active" : ""} onClick={() => setSub("intercept")}>
            Intercept
            {api.queue.length > 0 && <span className="count warn">{api.queue.length}</span>}
          </button>
          <button className={sub === "history" ? "active" : ""} onClick={() => setSub("history")}>
            HTTP history
            {api.rows.length > 0 && <span className="count">{api.rows.length}</span>}
          </button>
          <button className={sub === "scope" ? "active" : ""} onClick={() => setSub("scope")}>
            Scope
            {/* No include rule captures everything, which a bare count of 0
                would not say. */}
            {scope.policy.include.length > 0 ? (
              <span className="count">{scope.policy.include.length}</span>
            ) : (
              <span className="count" title="No include rule: everything is in scope">
                all
              </span>
            )}
            {scope.project?.open && <span className="dot ok tiny" title="Scope is saved to the project file" />}
          </button>
        </nav>
        <span className="spacer" />
        <label className="addr">
          <span className="muted small">Listen</span>
          <input
            className="mono"
            value={api.listenAddr}
            disabled={api.status !== "stopped"}
            onChange={(e) => api.setListenAddr(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && api.start()}
            spellCheck={false}
          />
        </label>
        {running ? (
          <button className="btn danger" onClick={api.stop}>■ Stop</button>
        ) : (
          <button className="btn primary" disabled={api.status === "starting"} onClick={api.start}>
            ▶ {api.status === "starting" ? "Starting…" : "Start"}
          </button>
        )}
        <button
          className={`toggle ${api.intercept ? "on" : ""}`}
          disabled={!running}
          onClick={() => api.setIntercept(!api.intercept)}
          title="Hold requests for review before forwarding"
        >
          <span className="toggle-dot" />
          Intercept {api.intercept ? "on" : "off"}
        </button>
        <button
          className="btn"
          disabled={!running}
          onClick={async () => {
            const p = await api.getCaPem();
            if (p) setPem(p);
          }}
        >
          CA certificate
        </button>
      </div>

      {api.error && (
        <div className="banner error">
          <span>{api.error}</span>
          <button className="icon-btn" onClick={() => api.setError(null)}>✕</button>
        </div>
      )}

      <div className="proxy-body">
        {sub === "scope" ? (
          <ScopePanel api={scope} />
        ) : sub === "intercept" ? (
          <InterceptView api={api} />
        ) : (
          <>
            {/* Wireshark display-filter bar: green when valid, red when not. */}
            <div className="filterbar">
              <span className="filter-icon">⏷</span>
              <input
                className={`filter-input mono ${filter ? (compiled.ok ? "valid" : "invalid") : ""}`}
                placeholder={`Display filter — e.g. ${FILTER_EXAMPLES[2]}`}
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                onKeyDown={(e) => e.key === "Escape" && setFilter("")}
                spellCheck={false}
                list="filter-examples"
                title={`Fields: ${FIELD_NAMES.join(", ")}\nOps: == != > < >= <= contains matches ~\nCombine: && || ! ( )`}
              />
              <datalist id="filter-examples">
                {FILTER_EXAMPLES.map((f) => <option key={f} value={f} />)}
              </datalist>
              {filter && (
                <button className="icon-btn" onClick={() => setFilter("")} title="Clear filter">✕</button>
              )}
              {!compiled.ok && <span className="filter-error">{compiled.error}</span>}
              <span className="spacer" />
              <button
                className="icon-btn"
                title={layout === "row" ? "Stack request/response" : "Side by side"}
                onClick={() => setLayout((l) => (l === "row" ? "column" : "row"))}
              >
                {layout === "row" ? "◫" : "⬒"}
              </button>
              <button className="btn ghost" disabled={!api.rows.length} onClick={() => { api.clear(); setSelectedId(null); }}>
                Clear
              </button>
            </div>

            <SplitPane direction="column" initial={0.45}>
              <FlowTable
                rows={visible}
                selectedId={selectedId}
                highlights={api.highlights}
                onSelect={setSelectedId}
                onContextMenu={(row, x, y) => setMenu({ row, x, y })}
              />
              <SplitPane key={layout} direction={layout}>
                <MessageViewer
                  title="Request"
                  message={reqMsg}
                  placeholder="Select a request in the history"
                  tab={reqTab}
                  onTab={setReqTab}
                />
                <MessageViewer
                  title="Response"
                  message={resMsg}
                  placeholder={
                    !selected ? "" : selected.flow.error ? `Error: ${selected.flow.error}`
                      : selected.flow.state === "Paused" ? "Request is held in Intercept"
                      : selected.flow.state === "Dropped" ? "Request was dropped"
                      : "Waiting for response…"
                  }
                  tab={resTab}
                  onTab={setResTab}
                  extra={res && <span className={`status-pill s${Math.floor(res.status / 100)}`}>{res.status} {res.reason}</span>}
                />
              </SplitPane>
            </SplitPane>
          </>
        )}
      </div>

      {/* Wireshark-style status bar. */}
      <footer className="statusbar">
        <span className={`dot ${running ? "on" : api.status === "starting" ? "busy" : ""}`} />
        <span>{running ? `Listening on ${api.listenAddr}` : api.status === "starting" ? "Starting…" : "Proxy stopped"}</span>
        <span className="sep" />
        <span>Intercept: {api.intercept ? "on" : "off"}</span>
        {api.queue.length > 0 && (
          <>
            <span className="sep" />
            <button className="link warn" onClick={() => setSub("intercept")}>{api.queue.length} held</button>
          </>
        )}
        <span className="spacer" />
        <span>Captured: {api.rows.length}</span>
        <span className="sep" />
        <span>Displayed: {visible.length}{filter && compiled.ok ? ` (${api.rows.length ? Math.round((visible.length / api.rows.length) * 100) : 0}%)` : ""}</span>
        {selected && (
          <>
            <span className="sep" />
            <span>Selected: #{selected.seq}</span>
          </>
        )}
      </footer>

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menuItems(menu.row)} onClose={closeMenu} />}
      {pem && <CaDialog pem={pem} onClose={() => setPem(null)} />}
    </div>
  );
}
