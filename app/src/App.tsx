import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Header = { name: string; value: number[] };
type Request = { method: string; target: string; headers: Header[] };
type Response = { status: number; reason: string; headers: Header[] } | null;
type Flow = {
  id: string;
  scheme: "Http" | "Https";
  host: string;
  port: number;
  request: Request;
  response: Response;
  state: string;
};
type FlowEvent = { kind: string; flow: Flow | null; error: string | null };

// Minimal Proxy screen. Full UI (virtualized list, raw editor, guided CA
// install) is a dedicated task; this proves the event/command contract.
export default function App() {
  const [running, setRunning] = useState(false);
  const [intercept, setIntercept] = useState(false);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const byId = useRef(new Map<string, Flow>());

  useEffect(() => {
    const un = listen<FlowEvent>("proxy://flow", (e) => {
      const { kind, flow, error } = e.payload;
      if (kind === "error") {
        setErr(error);
        return;
      }
      if (!flow) return;
      byId.current.set(flow.id, flow);
      setFlows(Array.from(byId.current.values()));
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  async function run<T>(p: Promise<T>) {
    try {
      setErr(null);
      return await p;
    } catch (e) {
      setErr(String(e));
    }
  }

  const detail = selected ? byId.current.get(selected) : null;

  return (
    <main style={{ padding: 16, fontFamily: "system-ui", display: "grid", gap: 12 }}>
      <h2>Elliot — Proxy</h2>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        {!running ? (
          <button
            onClick={() =>
              run(invoke("proxy_start", { args: { listenAddr: "127.0.0.1:8080" } })).then(() =>
                setRunning(true),
              )
            }
          >
            Start on 127.0.0.1:8080
          </button>
        ) : (
          <button onClick={() => run(invoke("proxy_stop")).then(() => setRunning(false))}>
            Stop
          </button>
        )}
        <label>
          <input
            type="checkbox"
            checked={intercept}
            disabled={!running}
            onChange={(e) => {
              const on = e.target.checked;
              run(invoke("proxy_set_intercept", { on })).then(() => setIntercept(on));
            }}
          />{" "}
          Intercept
        </label>
        <button
          disabled={!running}
          onClick={() =>
            run(invoke<string>("proxy_get_ca_pem")).then((pem) => pem && alert(pem))
          }
        >
          Show CA certificate
        </button>
      </div>

      {err && <div style={{ color: "crimson" }}>Error: {err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: "left" }}>
              <th>Host</th>
              <th>Method</th>
              <th>Target</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((f) => (
              <tr
                key={f.id}
                onClick={() => setSelected(f.id)}
                style={{
                  cursor: "pointer",
                  background: selected === f.id ? "#eef" : undefined,
                }}
              >
                <td>{f.host}</td>
                <td>{f.request.method}</td>
                <td style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {f.request.target}
                </td>
                <td>{f.response ? f.response.status : f.state}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <div style={{ fontSize: 13 }}>
          {detail ? (
            <>
              <h4>
                {detail.request.method} {detail.scheme.toLowerCase()}://{detail.host}
                {detail.request.target}
              </h4>
              {detail.state === "Paused" && (
                <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                  <button
                    onClick={() =>
                      run(
                        invoke("proxy_intercept_decide", {
                          decision: { flowId: detail.id, action: "forward" },
                        }),
                      )
                    }
                  >
                    Forward
                  </button>
                  <button
                    onClick={() =>
                      run(
                        invoke("proxy_intercept_decide", {
                          decision: { flowId: detail.id, action: "drop" },
                        }),
                      )
                    }
                  >
                    Drop
                  </button>
                </div>
              )}
              <pre style={{ whiteSpace: "pre-wrap", background: "#f6f6f6", padding: 8 }}>
                {detail.request.headers.map((h) => `${h.name}: ${bytesToStr(h.value)}`).join("\n")}
              </pre>
              {detail.response && (
                <pre style={{ whiteSpace: "pre-wrap", background: "#f6f6f6", padding: 8 }}>
                  {detail.response.status} {detail.response.reason}
                  {"\n"}
                  {detail.response.headers
                    .map((h) => `${h.name}: ${bytesToStr(h.value)}`)
                    .join("\n")}
                </pre>
              )}
            </>
          ) : (
            <p style={{ color: "#888" }}>Select a flow.</p>
          )}
        </div>
      </div>
    </main>
  );
}

function bytesToStr(b: number[]): string {
  try {
    return new TextDecoder().decode(new Uint8Array(b));
  } catch {
    return "<binary>";
  }
}
