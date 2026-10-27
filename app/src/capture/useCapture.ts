import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, listen } from "../proxy/backend";
import { timeMs } from "../proxy/format";
import type { CaptureEvent, MessageWire, StreamWire } from "./types";

export type CaptureStatus = "stopped" | "starting" | "running";

export type CaptureRow = {
  stream: StreamWire;
  messages: number;
};

/// Listener lifecycle + captured streams for the Capture screen.
///
/// Live events and the persisted history are merged by id, so a stream that is
/// both still open and already in the project file is listed once. Messages are
/// fetched lazily per stream and deduplicated the same way.
export function useCapture() {
  const [status, setStatus] = useState<CaptureStatus>("stopped");
  const [listenAddr, setListenAddr] = useState("127.0.0.1:1080");
  const [mitmTls, setMitmTls] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  const streams = useRef(new Map<string, StreamWire>());
  const messages = useRef(new Map<string, MessageWire[]>());
  const fetched = useRef(new Set<string>());
  const pending = useRef(false);

  // Bursts (a busy stream) bump the version at most once per frame, so a
  // capture never re-renders per message.
  const bump = useCallback(() => {
    if (pending.current) return;
    pending.current = true;
    requestAnimationFrame(() => {
      pending.current = false;
      setVersion((v) => v + 1);
    });
  }, []);

  const mergeMessages = useCallback((streamId: string, incoming: MessageWire[]) => {
    const current = messages.current.get(streamId) ?? [];
    const byId = new Map(current.map((m) => [m.id, m]));
    for (const m of incoming) byId.set(m.id, m);
    messages.current.set(
      streamId,
      [...byId.values()].sort((a, b) => a.seq - b.seq),
    );
  }, []);

  useEffect(() => {
    const un = listen<CaptureEvent>("socks://stream", (ev) => {
      if (ev.kind === "error") {
        setError(ev.error ?? "capture error");
        return;
      }
      if (ev.stream) streams.current.set(ev.stream.id, ev.stream);
      if (ev.message) mergeMessages(ev.message.stream_id, [ev.message]);
      bump();
    });
    return () => {
      un.then((f) => f());
    };
  }, [bump, mergeMessages]);

  const rows: CaptureRow[] = useMemo(() => {
    const out: CaptureRow[] = [];
    for (const stream of streams.current.values()) {
      out.push({ stream, messages: messages.current.get(stream.id)?.length ?? 0 });
    }
    return out.sort((a, b) => timeMs(a.stream.started_at) - timeMs(b.stream.started_at));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version]);

  const start = useCallback(async () => {
    setStatus("starting");
    setError(null);
    try {
      // The listener rejects a non-loopback address, like the HTTP proxy.
      await invoke("socks_start", { args: { listenAddr, mitmTls } });
      setStatus("running");
    } catch (e) {
      setError(String(e));
      setStatus("stopped");
    }
  }, [listenAddr, mitmTls]);

  const stop = useCallback(async () => {
    try {
      await invoke("socks_stop");
    } catch (e) {
      setError(String(e));
    }
    setStatus("stopped");
  }, []);

  /// Pull the streams persisted in the open project (nothing without one).
  const reload = useCallback(async () => {
    try {
      const persisted = await invoke<StreamWire[]>("capture_list", { limit: 500 });
      for (const stream of persisted) {
        if (!streams.current.has(stream.id)) streams.current.set(stream.id, stream);
      }
      bump();
    } catch (e) {
      setError(String(e));
    }
  }, [bump]);

  /// Fetch a stream's persisted messages once, when it is first selected.
  const loadMessages = useCallback(
    async (streamId: string) => {
      if (fetched.current.has(streamId)) return;
      fetched.current.add(streamId);
      try {
        const persisted = await invoke<MessageWire[]>("capture_messages", { streamId });
        if (persisted.length) {
          mergeMessages(streamId, persisted);
          bump();
        }
      } catch (e) {
        setError(String(e));
      }
    },
    [bump, mergeMessages],
  );

  const messagesFor = useCallback(
    (streamId: string): MessageWire[] => messages.current.get(streamId) ?? [],
    [],
  );

  return {
    status, listenAddr, setListenAddr, mitmTls, setMitmTls, error, setError,
    rows, start, stop, reload, loadMessages, messagesFor,
  };
}

export type CaptureApi = ReturnType<typeof useCapture>;
