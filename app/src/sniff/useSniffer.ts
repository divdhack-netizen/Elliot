import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, listen } from "../proxy/backend";
import { timeMs } from "../proxy/format";
import type { FlowMeta, PacketMeta, SniffEvent, SniffIface, SniffStatus } from "./types";

export type SnifferStatus = "stopped" | "starting" | "running";

/// Packets are metadata, but a busy interface can still produce millions:
/// keep a bounded ring per flow so a long session cannot exhaust memory.
/// `FlowMeta.packets` remains the authoritative count.
export const MAX_KEPT_PACKETS = 2_000;

/// Listener lifecycle + live flows/packets for the Sniffer screen.
///
/// Unlike the Capture screen there is no persistence: v1 is in-memory only, so
/// nothing is fetched from the open project and nothing is written to it.
export function useSniffer() {
  const [status, setStatus] = useState<SnifferStatus>("stopped");
  const [interfaces, setInterfaces] = useState<SniffIface[]>([]);
  const [iface, setIface] = useState("");
  const [bpf, setBpf] = useState("");
  // The filter the *running* capture actually compiled. libpcap compiles a BPF
  // once, at open time, so changing `bpf` mid-capture only takes effect on the
  // next start; this lets the UI show an "Apply" affordance when they diverge.
  const [appliedBpf, setAppliedBpf] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Live BPF validation: `null` means the current filter compiles (or is empty).
  const [bpfError, setBpfError] = useState<string | null>(null);
  const [bpfChecking, setBpfChecking] = useState(false);
  // Set once the Tauri backend answers, so validation never fires against the
  // vite preview (where `invoke` rejects and would flag every filter).
  const [backendReady, setBackendReady] = useState(false);
  const [version, setVersion] = useState(0);

  const flows = useRef(new Map<string, FlowMeta>());
  const packets = useRef(new Map<string, PacketMeta[]>());
  const pending = useRef(false);

  // Bursts bump the version at most once per frame, so a busy capture never
  // re-renders per packet.
  const bump = useCallback(() => {
    if (pending.current) return;
    pending.current = true;
    requestAnimationFrame(() => {
      pending.current = false;
      setVersion((v) => v + 1);
    });
  }, []);

  const refreshInterfaces = useCallback(async () => {
    try {
      const list = await invoke<SniffIface[]>("sniff_interfaces");
      setBackendReady(true);
      setInterfaces(list);
      // Prefer loopback for the usual local-debug session; fall back to the
      // first device libpcap reports.
      setIface((current) => current || list.find((i) => i.loopback)?.name || list[0]?.name || "");
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void refreshInterfaces();

    // A webview reload loses this state but not the Rust-side capture: adopt
    // the running one instead of showing "stopped" over a live sniffer.
    void invoke<SniffStatus>("sniff_status")
      .then((s) => {
        setBackendReady(true);
        if (!s.running) return;
        setStatus("running");
        if (s.interface) setIface(s.interface);
        setBpf(s.bpfFilter ?? "");
        setAppliedBpf(s.bpfFilter ?? "");
      })
      .catch(() => {
        // Not running inside Tauri (vite preview): the screen stays idle.
      });

    const un = listen<SniffEvent>("sniff://packet", (ev) => {
      if (ev.kind === "error") {
        setError(ev.error ?? "sniffer error");
        // The Rust loop stops right after reporting the error. Reflect that
        // here so the toolbar offers Start again instead of a dead Stop; the
        // next start drops the finished handle.
        setStatus("stopped");
        return;
      }
      if (ev.flow) {
        flows.current.set(ev.flow.id, ev.flow);
        bump();
      }
      if (ev.packet) {
        const list = packets.current.get(ev.packet.flowId) ?? [];
        list.push(ev.packet);
        if (list.length > MAX_KEPT_PACKETS) {
          list.splice(0, list.length - MAX_KEPT_PACKETS);
        }
        packets.current.set(ev.packet.flowId, list);
        bump();
      }
    });
    return () => {
      un.then((f) => f());
    };
  }, [bump, refreshInterfaces]);

  // Validate the filter as the user types, debounced, by compiling it in the
  // backend without opening a device. Empty filters are always valid.
  useEffect(() => {
    const filter = bpf.trim();
    if (!backendReady || !filter) {
      setBpfError(null);
      setBpfChecking(false);
      return;
    }
    let live = true;
    setBpfChecking(true);
    const timer = setTimeout(() => {
      invoke("sniff_validate", { args: { bpf: filter } })
        .then(() => {
          if (live) {
            setBpfError(null);
            setBpfChecking(false);
          }
        })
        .catch((e) => {
          if (live) {
            setBpfError(String(e));
            setBpfChecking(false);
          }
        });
    }, 350);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [bpf, backendReady]);

  const rows: FlowMeta[] = useMemo(
    () =>
      [...flows.current.values()].sort(
        (a, b) => timeMs(a.startedAt) - timeMs(b.startedAt),
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [version],
  );

  const start = useCallback(async () => {
    setStatus("starting");
    setError(null);
    try {
      // The device is opened and the BPF program compiled before this returns,
      // so a permission or filter error lands in the banner, not in the task.
      await invoke("sniff_start", {
        args: { interface: iface, bpfFilter: bpf.trim() || null, promisc: true },
      });
      // A fresh session starts from an empty list; a failed start keeps the
      // previous capture visible.
      flows.current.clear();
      packets.current.clear();
      setVersion((v) => v + 1);
      // Record what the capture actually compiled, so the "Apply" affordance
      // only shows once the user edits the filter away from this.
      setAppliedBpf(bpf.trim());
      // A capture can also die immediately after it starts (the interface is
      // removed, the BPF device is revoked). Ask the backend instead of
      // painting "running" over a loop that has already ended; an error event
      // is shown by the listener above.
      try {
        const current = await invoke<SniffStatus>("sniff_status");
        setStatus(current.running ? "running" : "stopped");
      } catch {
        setStatus("running");
      }
    } catch (e) {
      setError(String(e));
      setStatus("stopped");
    }
  }, [iface, bpf]);

  const stop = useCallback(async () => {
    try {
      await invoke("sniff_stop");
    } catch (e) {
      setError(String(e));
    }
    setStatus("stopped");
  }, []);

  /// Re-arm a running capture with the current filter. libpcap cannot swap a
  /// BPF program on an open device, so this stops and reopens it — the only
  /// honest way to change the filter without the user doing Stop/Start by hand.
  const apply = useCallback(async () => {
    if (status !== "running") return;
    try {
      // Stop first: the backend refuses `sniff_start` while a capture is live.
      await invoke("sniff_stop");
    } catch (e) {
      setError(String(e));
      return;
    }
    await start();
  }, [status, start]);

  const packetsFor = useCallback(
    (flowId: string): PacketMeta[] => packets.current.get(flowId) ?? [],
    [],
  );

  // The edited filter no longer matches the one the live capture is using.
  const bpfDirty = status === "running" && bpf.trim() !== appliedBpf;

  return {
    status, interfaces, iface, setIface, bpf, setBpf, error, setError,
    bpfError, bpfChecking, bpfDirty,
    rows, start, stop, apply, packetsFor, refreshInterfaces,
  };
}

export type SnifferApi = ReturnType<typeof useSniffer>;
