import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, listen } from "./backend";
import { toRow } from "./format";
import type { Flow, FlowEvent, Highlight, Row } from "./types";

export type ProxyStatus = "stopped" | "starting" | "running";

/// All Proxy-screen state: the flow store, proxy lifecycle and intercept queue.
export function useProxy() {
  const [status, setStatus] = useState<ProxyStatus>("stopped");
  const [listenAddr, setListenAddr] = useState("127.0.0.1:8080");
  const [intercept, setInterceptState] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const [highlights, setHighlights] = useState<Record<string, Highlight>>({});

  // Flows keyed by id, plus insertion order for the "#" column. Kept in refs
  // and bumped via `version` so bursts of events don't copy the array per event.
  const flows = useRef(new Map<string, Flow>());
  const seqs = useRef(new Map<string, number>());
  const edited = useRef(new Set<string>());
  const nextSeq = useRef(1);
  const pending = useRef(false);

  useEffect(() => {
    const un = listen<FlowEvent>("proxy://flow", ({ kind, flow, error }) => {
      if (kind === "error") {
        setError(error);
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

  const rows: Row[] = useMemo(() => {
    const out: Row[] = [];
    for (const f of flows.current.values()) {
      out.push(toRow(f, seqs.current.get(f.id) ?? 0, edited.current.has(f.id)));
    }
    return out.sort((a, b) => a.seq - b.seq);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version]);

  const queue = useMemo(() => rows.filter((r) => r.flow.state === "Paused"), [rows]);

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

  const forwardAll = useCallback(async () => {
    for (const r of queue) await decide(r.flow.id, "forward");
  }, [queue, decide]);

  const stop = useCallback(async () => {
    await run(invoke("proxy_stop"));
    setStatus("stopped");
    setInterceptState(false);
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

  return {
    status, listenAddr, setListenAddr, intercept, error, setError,
    rows, queue, highlights,
    start, stop, setIntercept, decide, forwardAll, getCaPem, clear, remove, setHighlight,
  };
}

export type ProxyApi = ReturnType<typeof useProxy>;
