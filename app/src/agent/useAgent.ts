import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen } from "../proxy/backend";
import type { AgentRun, ContextItem, Execution, Item, Proposal } from "./types";

/// Agent chat state: the transcript, the sidecar lifecycle and the proposal
/// approval path.
///
/// The Rust bridge validates every proposal before it reaches this hook, so
/// `Proposal.error === null` is the only case in which the UI offers to run.
export function useAgent() {
  const [items, setItems] = useState<Item[]>([]);
  const [busy, setBusy] = useState(false);
  const [alive, setAlive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The explicit context tray, owned by the Rust side and mirrored here.
  const [context, setContext] = useState<ContextItem[]>([]);
  // Executions recorded in the open project.
  const [runs, setRuns] = useState<AgentRun[]>([]);
  // The message a stream of `chunk` events appends to.

  const loadRuns = useCallback(async () => {
    try {
      setRuns(await invoke<AgentRun[]>("agent_runs", { limit: 100 }));
    } catch {
      // No project open: there is nothing to list.
      setRuns([]);
    }
  }, []);
  const streamingId = useRef<string | null>(null);
  const nextId = useRef(1);

  useEffect(() => {
    // The tray lives in Rust (it is cleared there on a project change); this is
    // only the mirror the chips render.
    void invoke<ContextItem[]>("agent_context_list")
      .then(setContext)
      .catch(() => {});
    const unlisteners = [
      listen<{ text: string }>("agent://chunk", ({ text }) => {
        setItems((prev) => {
          const id = streamingId.current;
          if (id) {
            return prev.map((item) =>
              item.kind === "agent" && item.id === id
                ? { ...item, text: item.text + text }
                : item,
            );
          }
          // A chunk with no open message (unexpected): start one rather than
          // dropping text on the floor.
          return [...prev, { kind: "agent", id: `a${nextId.current++}`, text, streaming: true }];
        });
      }),
      listen("agent://done", () => {
        streamingId.current = null;
        setBusy(false);
        setItems((prev) =>
          prev.map((item) => (item.kind === "agent" ? { ...item, streaming: false } : item)),
        );
      }),
      listen<{ message: string }>("agent://error", ({ message }) => {
        setItems((prev) => [...prev, { kind: "error", id: `e${nextId.current++}`, text: message }]);
      }),
      listen<Proposal>("agent://proposal", (proposal) => {
        setItems((prev) => [...prev, { kind: "proposal", id: proposal.id, proposal }]);
      }),
      listen<Execution>("agent://execution", (execution) => {
        setItems((prev) => [
          ...prev,
          { kind: "execution", id: `x${nextId.current++}`, execution },
        ]);
        // The run was persisted before the event, so it is already listable.
        void loadRuns();
      }),
      listen<ContextItem[]>("agent://context", (items) => setContext(items)),
      listen("agent://exit", () => {
        streamingId.current = null;
        setBusy(false);
        setAlive(false);
      }),
    ];
    return () => {
      for (const un of unlisteners) void un.then((off) => off());
    };
  }, [loadRuns]);

  const send = useCallback(async (prompt: string) => {
    const text = prompt.trim();
    if (!text) return;
    const agentId = `a${nextId.current++}`;
    streamingId.current = agentId;
    setError(null);
    setBusy(true);
    setAlive(true);
    setItems((prev) => [
      ...prev,
      { kind: "user", id: `u${nextId.current++}`, text },
      { kind: "agent", id: agentId, text: "", streaming: true },
    ]);
    try {
      await invoke("agent_send", { prompt: text });
    } catch (e) {
      // The sidecar could not be started or reached: surface it as a turn.
      streamingId.current = null;
      setBusy(false);
      setAlive(false);
      setError(String(e));
      setItems((prev) => [
        ...prev,
        { kind: "error", id: `e${nextId.current++}`, text: String(e) },
      ]);
    }
  }, []);

  /// "Propose": one strict model call that only returns a proposal. There is
  /// no chat turn, so no empty agent bubble is created.
  const propose = useCallback(async (prompt: string) => {
    const text = prompt.trim();
    if (!text) return;
    setError(null);
    setBusy(true);
    setAlive(true);
    setItems((prev) => [...prev, { kind: "user", id: `u${nextId.current++}`, text }]);
    try {
      await invoke("agent_propose", { prompt: text });
    } catch (e) {
      setBusy(false);
      setAlive(false);
      setError(String(e));
      setItems((prev) => [
        ...prev,
        { kind: "error", id: `e${nextId.current++}`, text: String(e) },
      ]);
    }
  }, []);

  const run = useCallback(async (proposalId: string, allowDangerous: boolean) => {
    try {
      setError(null);
      await invoke("agent_execute", { proposalId, allowDangerous });
    } catch (e) {
      setError(String(e));
      setItems((prev) => [
        ...prev,
        { kind: "error", id: `e${nextId.current++}`, text: String(e) },
      ]);
    }
  }, []);

  const stop = useCallback(async () => {
    try {
      await invoke("agent_stop");
    } catch (e) {
      setError(String(e));
    }
    streamingId.current = null;
    setBusy(false);
    setAlive(false);
  }, []);

  const clear = useCallback(() => {
    setItems([]);
    setError(null);
  }, []);

  const removeContext = useCallback(async (id: string) => {
    try {
      setContext(await invoke<ContextItem[]>("agent_context_remove", { id }));
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const clearContext = useCallback(async () => {
    try {
      setContext(await invoke<ContextItem[]>("agent_context_clear"));
    } catch (e) {
      setError(String(e));
    }
  }, []);

  return {
    items, busy, alive, error, context, runs,
    send, propose, run, stop, clear, removeContext, clearContext, loadRuns,
  };
}

export type AgentApi = ReturnType<typeof useAgent>;
