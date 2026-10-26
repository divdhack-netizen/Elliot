import { useCallback, useEffect, useState } from "react";
import { invoke } from "../proxy/backend";
import { EMPTY_POLICY, type ProjectStatus, type ScopePolicy } from "./types";

/// Scope + project state for the Scope sub-tab.
///
/// Edits are pushed to the backend on every change: the policy is live (a
/// running proxy picks it up on the next request), so there is no separate
/// "save" step to forget.
export function useScope() {
  const [policy, setPolicy] = useState<ScopePolicy>(EMPTY_POLICY);
  const [project, setProject] = useState<ProjectStatus | null>(null);
  /// Did the last write reach the project file? `false` means session-only.
  const [persisted, setPersisted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const run = useCallback(async <T,>(p: Promise<T>): Promise<T | undefined> => {
    try {
      setError(null);
      return await p;
    } catch (e) {
      setError(String(e));
      return undefined;
    }
  }, []);

  const refresh = useCallback(async () => {
    const [p, status] = await Promise.all([
      run(invoke<ScopePolicy>("scope_get")),
      run(invoke<ProjectStatus>("project_status")),
    ]);
    if (p) setPolicy(p);
    if (status) {
      setProject(status);
      setPersisted(status.open);
    }
    setLoading(false);
  }, [run]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const update = useCallback(
    async (next: ScopePolicy) => {
      // Optimistic: the UI should not lag behind a keystroke.
      setPolicy(next);
      const ok = await run(invoke<boolean>("scope_set", { policy: next }));
      if (ok === undefined) {
        // The write failed, so what the proxy enforces may no longer be what we
        // are showing: resync from the backend instead of guessing.
        await refresh();
        return;
      }
      setPersisted(ok);
    },
    [run, refresh],
  );

  const createProject = useCallback(
    async (passphrase: string, path?: string) => {
      const status = await run(
        invoke<ProjectStatus>("project_create", { passphrase, path: path || null }),
      );
      if (!status) return false;
      setProject(status);
      setPersisted(true);
      return true;
    },
    [run],
  );

  const openProject = useCallback(
    async (passphrase: string, path?: string) => {
      const status = await run(
        invoke<ProjectStatus>("project_open", { passphrase, path: path || null }),
      );
      if (!status) return false;
      setProject(status);
      setPersisted(true);
      // The file carries its own policy: adopt it.
      const p = await run(invoke<ScopePolicy>("scope_get"));
      if (p) setPolicy(p);
      return true;
    },
    [run],
  );

  const closeProject = useCallback(async () => {
    const status = await run(invoke<ProjectStatus>("project_close"));
    if (status) {
      setProject(status);
      setPersisted(false);
    }
  }, [run]);

  return {
    policy, project, persisted, error, loading,
    setError, update, createProject, openProject, closeProject, refresh,
  };
}

export type ScopeApi = ReturnType<typeof useScope>;
