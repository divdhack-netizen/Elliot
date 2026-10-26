import { useState } from "react";
import {
  anyRule,
  hostKind,
  hostText,
  pathText,
  portText,
  withHostKind,
  withHostText,
  withPath,
  withPort,
  type HostKind,
  type Rule,
  type SchemeMatch,
} from "./types";
import type { ScopeApi } from "./useScope";

const SCHEMES: SchemeMatch[] = ["any", "http", "https"];
const HOST_KINDS: HostKind[] = ["any", "exact", "suffix"];

const HOST_KIND_LABEL: Record<HostKind, string> = {
  any: "any",
  exact: "exact host",
  suffix: "domain + subdomains",
};

export function ScopePanel({ api }: { api: ScopeApi }) {
  return (
    <div className="scope">
      {api.error && (
        <div className="banner error">
          <span>{api.error}</span>
          <button className="icon-btn" onClick={() => api.setError(null)}>
            ✕
          </button>
        </div>
      )}
      <ProjectCard api={api} />
      <RuleCard api={api} list="include" title="In scope" />
      <RuleCard api={api} list="exclude" title="Excluded" />
    </div>
  );
}

/// Create/open/close the encrypted project file the policy is saved to.
function ProjectCard({ api }: { api: ScopeApi }) {
  const [path, setPath] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);

  const project = api.project;
  const target = path.trim() || project?.defaultPath || "";

  async function submit(kind: "create" | "open") {
    if (!passphrase || busy) return;
    setBusy(true);
    const ok =
      kind === "create"
        ? await api.createProject(passphrase, target)
        : await api.openProject(passphrase, target);
    if (ok) setPassphrase("");
    setBusy(false);
  }

  return (
    <section className="scope-card">
      <header>
        <span>Project file</span>
        <span className="spacer" />
        {project?.open ? (
          <span className="tag ok">saved</span>
        ) : (
          <span className="tag warn">session only</span>
        )}
      </header>
      <div className="body">
        {project?.open ? (
          <>
            <p className="muted small">
              Scope edits are written to this file, encrypted with its passphrase.
            </p>
            <div className="row">
              <code className="mono ellipsis">{project.path}</code>
              <span className="spacer" />
              <button className="btn" onClick={() => void api.closeProject()}>
                Close project
              </button>
            </div>
          </>
        ) : (
          <>
            <p className="muted small">
              No project is open, so scope changes last for this session only.
            </p>
            <input
              className="mono"
              value={path}
              placeholder={project?.defaultPath ?? "path to a .elliot file"}
              onChange={(e) => setPath(e.target.value)}
              spellCheck={false}
            />
            <div className="row">
              <input
                type="password"
                value={passphrase}
                placeholder="Passphrase"
                onChange={(e) => setPassphrase(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void submit("create")}
              />
              <button
                className="btn primary"
                disabled={!passphrase || busy}
                onClick={() => void submit("create")}
              >
                Create
              </button>
              <button className="btn" disabled={!passphrase || busy} onClick={() => void submit("open")}>
                Open
              </button>
            </div>
            <p className="muted small">
              The file is encrypted at rest with this passphrase. There is no recovery if you lose it.
            </p>
          </>
        )}
      </div>
    </section>
  );
}

/// One list of rules. The safe default is stated plainly: with no include rule
/// nothing is captured, which is easy to misread as "the proxy is broken".
function RuleCard({
  api,
  list,
  title,
}: {
  api: ScopeApi;
  list: "include" | "exclude";
  title: string;
}) {
  const rules = api.policy[list];
  const set = (next: Rule[]) =>
    void api.update(
      list === "include"
        ? { ...api.policy, include: next }
        : { ...api.policy, exclude: next },
    );
  const patch = (index: number, fn: (r: Rule) => Rule) =>
    set(rules.map((r, i) => (i === index ? fn(r) : r)));

  return (
    <section className="scope-card">
      <header>
        <span>{title}</span>
        <span className="count">{rules.length}</span>
        <span className="spacer" />
        <button className="btn ghost" onClick={() => set([...rules, anyRule()])}>
          + Add rule
        </button>
      </header>
      <div className="body">
        {rules.length === 0 ? (
          <p className="muted small">
            {list === "include"
              ? "Nothing is in scope yet: Elliot tunnels everything and captures nothing."
              : "No exclusions. Excluded hosts are never intercepted, even if in scope."}
          </p>
        ) : (
          <>
            <div className="rule-row rule-head" aria-hidden="true">
              <span>Scheme</span>
              <span>Host match</span>
              <span>Host</span>
              <span>Port</span>
              <span>Path prefix</span>
              <span />
            </div>
            {rules.map((rule, i) => {
              const kind = hostKind(rule.host);
              return (
                // Rules have no stable id on the wire, so the index is the key;
                // inputs are controlled, so a removal re-renders the right values.
                <div className="rule-row" key={i}>
                  <select
                    value={rule.scheme}
                    onChange={(e) =>
                      patch(i, (r) => ({ ...r, scheme: e.target.value as SchemeMatch }))
                    }
                  >
                    {SCHEMES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                  <select
                    value={kind}
                    onChange={(e) => patch(i, (r) => withHostKind(r, e.target.value as HostKind))}
                  >
                    {HOST_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {HOST_KIND_LABEL[k]}
                      </option>
                    ))}
                  </select>
                  <input
                    className="mono"
                    value={hostText(rule.host)}
                    placeholder={kind === "any" ? "—" : "example.com"}
                    disabled={kind === "any"}
                    spellCheck={false}
                    onChange={(e) => patch(i, (r) => withHostText(r, e.target.value))}
                  />
                  <input
                    className="mono"
                    value={portText(rule.port)}
                    placeholder="any"
                    spellCheck={false}
                    onChange={(e) => patch(i, (r) => withPort(r, e.target.value))}
                  />
                  <input
                    className="mono"
                    value={pathText(rule.path)}
                    placeholder="any"
                    spellCheck={false}
                    onChange={(e) => patch(i, (r) => withPath(r, e.target.value))}
                  />
                  <button
                    className="icon-btn"
                    title="Remove rule"
                    onClick={() => set(rules.filter((_, j) => j !== i))}
                  >
                    ✕
                  </button>
                </div>
              );
            })}
          </>
        )}
      </div>
    </section>
  );
}
