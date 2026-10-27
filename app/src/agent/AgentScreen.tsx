import { useEffect, useRef, useState } from "react";
import { INTRUSIVENESS_LABEL, type Execution, type Proposal } from "./types";
import { useAgent } from "./useAgent";

/// The Agent screen: chat with the local model, and the human gate in front of
/// everything it proposes.
///
/// Nothing runs from here without an explicit click, and the backend re-validates
/// the proposal at execution time — this screen is a confirmation, not a policy.
export function AgentScreen() {
  const api = useAgent();
  const [draft, setDraft] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [api.items.length, api.busy]);

  function submit() {
    const text = draft;
    setDraft("");
    void api.send(text);
  }

  function proposeOnly() {
    const text = draft;
    setDraft("");
    void api.propose(text);
  }

  return (
    <div className="agent">
      <div className="toolbar">
        <span className="muted small">
          L'agente <strong>propone</strong>: schema, scope ed esecuzione restano nel core Rust.
        </span>
        <span className="spacer" />
        <span className={`dot ${api.alive ? (api.busy ? "busy" : "on") : ""}`} />
        <span className="muted small">
          {api.alive ? (api.busy ? "Thinking…" : "Sidecar running") : "Sidecar stopped"}
        </span>
        <button className="btn ghost" disabled={!api.alive} onClick={() => void api.stop()}>
          Stop
        </button>
        <button className="btn ghost" disabled={!api.items.length} onClick={api.clear}>
          Clear
        </button>
      </div>

      {api.error && (
        <div className="banner error">
          <span>{api.error}</span>
        </div>
      )}

      <div className="chat">
        {api.items.length === 0 && (
          <div className="placeholder big">
            Chiedi qualcosa che porti a un tool del catalogo.
            <br />
            <span className="muted small">
              Serve un progetto aperto e uno scope che includa il target.
            </span>
          </div>
        )}

        {api.items.map((item) => {
          if (item.kind === "user") {
            return (
              <div key={item.id} className="bubble user">
                {item.text}
              </div>
            );
          }
          if (item.kind === "agent") {
            return (
              <div key={item.id} className="bubble agent">
                {item.text || (item.streaming ? "…" : "")}
                {item.streaming && <span className="caret" />}
              </div>
            );
          }
          if (item.kind === "proposal") {
            return <ProposalCard key={item.id} proposal={item.proposal} onRun={api.run} />;
          }
          if (item.kind === "execution") {
            return <ExecutionCard key={item.id} execution={item.execution} />;
          }
          return (
            <div key={item.id} className="banner error">
              <span>{item.text}</span>
            </div>
          );
        })}
        <div ref={endRef} />
      </div>

      <div className="composer">
        <textarea
          value={draft}
          spellCheck={false}
          placeholder="Descrivi cosa vuoi fare… (⌘↵ per inviare)"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
              e.preventDefault();
              submit();
            }
          }}
        />
        <button className="btn primary" disabled={api.busy || !draft.trim()} onClick={submit}>
          Send
        </button>
        <button
          className="btn"
          disabled={api.busy || !draft.trim()}
          onClick={proposeOnly}
          title="One call that only asks for a proposal (no chat)"
        >
          Propose
        </button>
      </div>
    </div>
  );
}

/// A proposal card: the exact argv, the risk level, and the confirmation the
/// level requires.
function ProposalCard({
  proposal,
  onRun,
}: {
  proposal: Proposal;
  onRun: (id: string, allowDangerous: boolean) => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [unlocked, setUnlocked] = useState(false);

  const refused = proposal.error !== null;
  // The runner refuses a dangerous effective level unless the caller unlocks it
  // explicitly; that is the one refusal the human can override from here.
  const dangerous = refused && /dangerous/i.test(proposal.error ?? "");
  const needsAck = proposal.effectiveIntrusiveness === "intrusive";
  const runnable = !refused && (!needsAck || acknowledged);

  return (
    <div className={`proposal ${refused ? "refused" : ""}`}>
      <div className="proposal-head">
        <span className="mono">{proposal.toolId}</span>
        {proposal.effectiveIntrusiveness && (
          <span className={`status-pill risk ${proposal.effectiveIntrusiveness}`}>
            {INTRUSIVENESS_LABEL[proposal.effectiveIntrusiveness] ?? proposal.effectiveIntrusiveness}
          </span>
        )}
        <span className="spacer" />
        <span className="muted small">targets: {proposal.targets.join(", ") || "—"}</span>
      </div>

      {proposal.argv.length > 0 ? (
        <pre className="argv">
          <span className="muted">$ </span>
          {proposal.program} {proposal.argv.map((arg) => JSON.stringify(arg)).join(" ")}
        </pre>
      ) : (
        <div className="muted small">Nessun comando da eseguire.</div>
      )}

      {proposal.requiredPrivileges.length > 0 && (
        <div className="muted small">
          Richiede privilegi: <span className="mono">{proposal.requiredPrivileges.join(", ")}</span>
        </div>
      )}

      {refused && (
        <div className="banner error">
          <span>{proposal.error}</span>
        </div>
      )}

      <div className="proposal-actions">
        {!refused && (
          <>
            {needsAck && (
              <label className="check">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.checked)}
                />
                Capisco che questo invia traffico <strong>intrusive</strong> al target.
              </label>
            )}
            <button
              className={`btn ${proposal.effectiveIntrusiveness === "low" || proposal.effectiveIntrusiveness === "passive" ? "primary" : "danger"}`}
              disabled={!runnable}
              onClick={() => onRun(proposal.id, false)}
            >
              Approve &amp; run
            </button>
          </>
        )}

        {dangerous && (
          <>
            <label className="check">
              <input
                type="checkbox"
                checked={unlocked}
                onChange={(e) => setUnlocked(e.target.checked)}
              />
              Sblocco manuale: capisco che il livello è <strong>dangerous</strong>.
            </label>
            <button
              className="btn danger"
              disabled={!unlocked}
              onClick={() => onRun(proposal.id, true)}
            >
              Unlock &amp; run
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function ExecutionCard({ execution }: { execution: Execution }) {
  const failed = execution.error !== null || execution.status !== 0;
  return (
    <div className={`execution ${failed ? "failed" : ""}`}>
      <div className="proposal-head">
        <span className="mono small">
          {execution.error
            ? "execution failed"
            : `exit ${execution.status ?? "?"}`}{" "}
          · {(execution.durationMs / 1000).toFixed(2)}s
        </span>
      </div>
      {execution.error && (
        <div className="banner error">
          <span>{execution.error}</span>
        </div>
      )}
      {execution.stdout && <pre className="output">{execution.stdout}</pre>}
      {execution.stderr && <pre className="output stderr">{execution.stderr}</pre>}
    </div>
  );
}
