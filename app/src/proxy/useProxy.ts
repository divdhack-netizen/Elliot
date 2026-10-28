import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, listen } from "./backend";
import { timeMs, toRow } from "./format";
import type { Flow, FlowEvent, Highlight, Row, WsMessage } from "./types";

export type ProxyStatus = "stopped" | "starting" | "running";

/// The real backend proxy state, mirrored from `proxy_status`.
type BackendStatus = {
  running: boolean;
  listenAddr: string | null;
  intercept: boolean;
};

/// How many forwarded frames the live view keeps in memory. The project file
/// keeps everything; this is only the window shown until "Reload".
const WS_MEMORY_LIMIT = 2_000;

/// All Proxy-screen state: the flow store, proxy lifecycle and intercept queue.
export function useProxy() {
  const [status, setStatus] = useState<ProxyStatus>("stopped");
  const [listenAddr, setListenAddr] = useState("127.0.0.1:8080");
  const [intercept, setInterceptState] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [highlights, setHighlights] = useState<Record<string, Highlight>>({});
  // WebSocket frames held by intercept: a held frame disappears from the queue
  // once decided.
  const [wsQueue, setWsQueue] = useState<WsMessage[]>([]);
  // Forwarded frames, live plus whatever "Reload" brought back from the
  // project. Kept in a ref with a version bump, like the flow history, so a
  // burst of frames does not copy the array once per event.
  const wsRowsRef = useRef<WsMessage[]>([]);
  const [wsVersion, setWsVersion] = useState(0);
  const wsBumpQueued = useRef(false);

  // Flows keyed by id, plus insertion order for the "#" column. Kept in refs
  // and bumped via `version` so bursts of events don't copy the array per event.
  const flows = useRef(new Map<string, Flow>());
  const seqs = useRef(new Map<string, number>());
  const edited = useRef(new Set<string>());
  const nextSeq = useRef(1);
  const pending = useRef(false);

  useEffect(() => {
    const un = listen<FlowEvent>("proxy://flow", ({ kind, flow, ws, error }) => {
      if (kind === "error") {
        setError(error);
        return;
      }
      if (ws?.paused) {
        // Held frame: announce it in the intercept queue (one entry per id).
        setWsQueue((q) => [...q.filter((m) => m.id !== ws.id), ws]);
        return;
      }
      if (ws) {
        // Resolved frame: it went on the wire, so it belongs to the history.
        if (!wsRowsRef.current.some((m) => m.id === ws.id)) {
          const next = [...wsRowsRef.current, ws];
          wsRowsRef.current =
            next.length > WS_MEMORY_LIMIT ? next.slice(next.length - WS_MEMORY_LIMIT) : next;
          if (!wsBumpQueued.current) {
            wsBumpQueued.current = true;
            requestAnimationFrame(() => {
              wsBumpQueued.current = false;
              setWsVersion((v) => v + 1);
            });
          }
        }
        return;
      }
      if (!flow) return;
      flows.current.set(flow.id, flow);
      if (!seqs.current.has(flow.id)) seqs.current.set(flow.id, nextSeq.current++);
      if (!pending.current) {
        pending.current = true;
        requestAnimationFrame(() => {
          pending.current = false;
          setVersion((v) => v + 1);
        });
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  // A webview reload re-mounts this hook with `status: "stopped"`, but the
  // proxy handle lives in the backend and keeps running. Reconcile the UI with
  // the real backend state on mount, so a reloaded window shows (and can stop)
  // a proxy that is still capturing instead of a dead "Start" button.
  useEffect(() => {
    let live = true;
    invoke<BackendStatus>("proxy_status")
      .then((s) => {
        if (!live || !s.running) return;
        setStatus("running");
        setInterceptState(s.intercept);
        if (s.listenAddr) setListenAddr(s.listenAddr);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);

  const rows: Row[] = useMemo(() => {
    const out: Row[] = [];
    for (const f of flows.current.values()) {
      out.push(toRow(f, seqs.current.get(f.id) ?? 0, edited.current.has(f.id)));
    }
    return out.sort((a, b) => a.seq - b.seq);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version]);

  const queue = useMemo(() => rows.filter((r) => r.flow.state === "Paused"), [rows]);

  const wsRows = useMemo(() => wsRowsRef.current, [wsVersion]);

  const run = useCallback(async <T,>(p: Promise<T>): Promise<T | undefined> => {
    try {
      setError(null);
      return await p;
    } catch (e) {
      setError(String(e));
      return undefined;
    }
  }, []);

  const start = useCallback(async () => {
    setStatus("starting");
    const ok = await run(invoke("proxy_start", { args: { listenAddr } }).then(() => true));
    setStatus(ok ? "running" : "stopped");
  }, [listenAddr, run]);

  const decide = useCallback(
    (flowId: string, action: "forward" | "drop" | "forward_edited", bytes?: number[]) => {
      if (action === "forward_edited") edited.current.add(flowId);
      return run(
        invoke("proxy_intercept_decide", {
          decision: { flowId, action, edited: bytes },
        }),
      );
    },
    [run],
  );

  const decideWs = useCallback(
    async (messageId: string, action: "forward" | "drop" | "forward_edited", bytes?: number[]) => {
      const ok = await run(
        invoke("proxy_ws_decide", {
          args: { messageId, action, edited: bytes },
        }).then(() => true),
      );
      if (ok) setWsQueue((q) => q.filter((m) => m.id !== messageId));
      return ok;
    },
    [run],
  );

  const forwardAll = useCallback(async () => {
    for (const r of queue) await decide(r.flow.id, "forward");
    for (const m of wsQueue) await decideWs(m.id, "forward");
  }, [queue, wsQueue, decide, decideWs]);

  const stop = useCallback(async () => {
    await run(invoke("proxy_stop"));
    setStatus("stopped");
    setInterceptState(false);
    // Held frames lost their channel with the engine: they will never resume
    // from this UI, so drop them instead of showing a dead queue.
    setWsQueue([]);
  }, [run]);

  const setIntercept = useCallback(
    async (on: boolean) => {
      const ok = await run(invoke("proxy_set_intercept", { on }).then(() => true));
      if (!ok) return;
      setInterceptState(on);
      // Like Burp: turning intercept off releases everything still queued.
      if (!on) await forwardAll();
    },
    [run, forwardAll],
  );

  const getCaPem = useCallback(() => run(invoke<string>("proxy_get_ca_pem")), [run]);

  const clear = useCallback(() => {
    for (const [id, f] of flows.current) {
      if (f.state !== "Paused") flows.current.delete(id);
    }
    setVersion((v) => v + 1);
  }, []);

  const remove = useCallback((id: string) => {
    if (flows.current.get(id)?.state === "Paused") return;
    flows.current.delete(id);
    setVersion((v) => v + 1);
  }, []);

  const setHighlight = useCallback((id: string, h: Highlight | null) => {
    setHighlights((prev) => {
      const next = { ...prev };
      if (h) next[id] = h;
      else delete next[id];
      return next;
    });
  }, []);

  const clearWs = useCallback(() => setWsQueue([]), []);

  /// Load the frames saved in the open project. Live frames captured since the
  /// snapshot are kept, and the whole window stays chronological.
  const loadWs = useCallback(async () => {
    const persisted = await run(invoke<WsMessage[]>("ws_list", { limit: 500 }));
    if (!persisted) return;
    const byId = new Map<string, WsMessage>();
    for (const m of [...persisted, ...wsRowsRef.current]) byId.set(m.id, m);
    const merged = [...byId.values()].sort((a, b) => timeMs(a.at) - timeMs(b.at));
    wsRowsRef.current =
      merged.length > WS_MEMORY_LIMIT ? merged.slice(merged.length - WS_MEMORY_LIMIT) : merged;
    setWsVersion((v) => v + 1);
  }, [run]);

  const clearWsRows = useCallback(() => {
    wsRowsRef.current = [];
    setWsVersion((v) => v + 1);
  }, []);

  return {
    status, listenAddr, setListenAddr, intercept, error, setError,
    rows, queue, wsQueue, wsRows, highlights,
    start, stop, setIntercept, decide, decideWs, forwardAll, clearWs,
    loadWs, clearWsRows,
    getCaPem, clear, remove, setHighlight,
  };
}

export type ProxyApi = ReturnType<typeof useProxy>;
