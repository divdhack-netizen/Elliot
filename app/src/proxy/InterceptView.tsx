import { useEffect, useState } from "react";
import { editedToWire, fmtClock, rawForEditing } from "./format";
import type { ProxyApi } from "./useProxy";

/// Burp's Intercept tab: the held-request queue plus an editable raw request.
export function InterceptView({ api }: { api: ProxyApi }) {
  const { queue, intercept, status } = api;
  const [currentId, setCurrentId] = useState<string | null>(null);
  const current = queue.find((r) => r.flow.id === currentId) ?? queue[0] ?? null;
  const [text, setText] = useState("");
  const [original, setOriginal] = useState("");

  // Load the request into the editor whenever the head of the queue changes.
  const loadedId = current?.flow.id ?? null;
  useEffect(() => {
    const t = current ? rawForEditing(current.flow.request.raw) : "";
    setText(t);
    setOriginal(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadedId]);

  const dirty = text !== original;

  function forward() {
    if (!current) return;
    if (dirty) api.decide(current.flow.id, "forward_edited", editedToWire(text));
    else api.decide(current.flow.id, "forward");
    setCurrentId(null);
  }

  function drop() {
    if (!current) return;
    api.decide(current.flow.id, "drop");
    setCurrentId(null);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && e.key === "Enter") {
      e.preventDefault();
      forward();
    } else if (mod && e.key === "Backspace" && e.shiftKey) {
      e.preventDefault();
      drop();
    }
  }

  return (
    <div className="intercept" onKeyDown={onKeyDown}>
      <div className="intercept-bar">
        <button className="btn primary" disabled={!current} onClick={forward} title="Forward (⌘↵)">
          {dirty ? "Forward edited" : "Forward"}
        </button>
        <button className="btn danger" disabled={!current} onClick={drop} title="Drop (⌘⇧⌫)">
          Drop
        </button>
        <button className="btn" disabled={queue.length < 2} onClick={api.forwardAll}>
          Forward all ({queue.length})
        </button>
        <span className="divider" />
        <button
          className={`toggle ${intercept ? "on" : ""}`}
          disabled={status !== "running"}
          onClick={() => api.setIntercept(!intercept)}
        >
          <span className="toggle-dot" />
          Intercept is {intercept ? "on" : "off"}
        </button>
        <span className="spacer" />
        {current && (
          <span className="mono small muted ellipsis">
            {current.flow.scheme === "Https" ? "🔒 " : ""}
            {current.flow.host}:{current.flow.port}
          </span>
        )}
        {dirty && (
          <button className="btn ghost" onClick={() => setText(original)}>
            Revert
          </button>
        )}
      </div>

      <div className="intercept-main">
        <aside className="queue">
          <div className="queue-head">Queue</div>
          {queue.length === 0 ? (
            <div className="queue-empty">Nothing held</div>
          ) : (
            queue.map((r) => (
              <button
                key={r.flow.id}
                className={`queue-item ${r.flow.id === current?.flow.id ? "active" : ""}`}
                onClick={() => setCurrentId(r.flow.id)}
              >
                <span className={`method m-${r.flow.request.method.toLowerCase()}`}>{r.flow.request.method}</span>
                <span className="ellipsis">{r.flow.host}{r.path}</span>
                <span className="muted small mono">{fmtClock(r.startedMs).slice(0, 8)}</span>
              </button>
            ))
          )}
        </aside>

        <div className="editor-wrap">
          {current ? (
            <textarea
              className="editor"
              spellCheck={false}
              value={text}
              onChange={(e) => setText(e.target.value)}
              autoFocus
            />
          ) : (
            <div className="placeholder big">
              {status !== "running" ? (
                <>Start the proxy to intercept requests.</>
              ) : intercept ? (
                <>Waiting for requests… held requests appear here for editing.</>
              ) : (
                <>
                  Intercept is off — requests pass straight through.
                  <button className="btn primary" onClick={() => api.setIntercept(true)}>
                    Turn intercept on
                  </button>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
