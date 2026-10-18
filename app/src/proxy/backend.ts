// Thin seam over Tauri IPC, so the Proxy screen never imports Tauri directly.

import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";

export type Unlisten = () => void;

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!inTauri) return Promise.reject(new Error("not running inside Tauri"));
  return tauriInvoke<T>(cmd, args);
}

export async function listen<T>(event: string, cb: (payload: T) => void): Promise<Unlisten> {
  if (!inTauri) return () => {};
  return tauriListen<T>(event, (e) => cb(e.payload));
}
