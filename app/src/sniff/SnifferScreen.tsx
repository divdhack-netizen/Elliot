import { useEffect, useMemo, useState } from "react";
import { SplitPane } from "../components/SplitPane";
import { fmtBytes, fmtClock, timeMs } from "../proxy/format";
import type { PacketMeta, SniffScope } from "./types";
import { useSniffer } from "./useSniffer";

const NO_PACKETS: PacketMeta[] = [];

/// Passive capture screen: pick an interface, optionally narrow it with a BPF
/// filter, and watch flows/packets without routing anything through Elliot.
///
/// Only metadata is available here. TLS payloads are ciphertext on the wire and
/// this tab never terminates them; the Proxy/Capture tabs remain the way to see
/// decrypted content.
export function SnifferScreen() {
  const api = useSniffer();
  const [selectedFlow, setSelectedFlow] = useState<string | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<number | null>(null);

  const running = api.status === "running";
  const flow = useMemo(
    () => api.rows.find((f) => f.id === selectedFlow) ?? null,
    [api.rows, selectedFlow],
  );
  const packets = selectedFlow ? api.packetsFor(selectedFlow) : NO_PACKETS;
  const packet = selectedPacket !== null ? packets[selectedPacket] ?? null : null;

  // Show the newest packet of the selected flow until the user picks another;
  // new arrivals after that never move the selection under their cursor.
  useEffect(() => {
    if (selectedPacket === null && packets.length > 0) {
      setSelectedPacket(packets.length - 1);
    }
  }, [selectedPacket, packets]);

  // Starting a new capture clears the live maps: drop the selection with them
  // rather than leaving an id that no longer resolves.
  useEffect(() => {
    if (selectedFlow && !api.rows.some((f) => f.id === selectedFlow)) {
      setSelectedFlow(null);
      setSelectedPacket(null);
    }
  }, [api.rows, selectedFlow]);

  const totalPackets = api.rows.reduce((sum, row) => sum + row.packets, 0);

  return (
    <div className="proxy">
      <div className="toolbar">
        <span className="viewer-title">Sniffer</span>
        <span className="muted small">passive (libpcap)</span>
        <span className="divider" />
        <label className="addr">
          <span className="muted small">Interface</span>
          <select
            className="mono"
            value={api.iface}
            disabled={api.status !== "stopped"}
            onChange={(e) => api.setIface(e.target.value)}
            title="The network adapter to observe (nothing is routed through Elliot)"
          >
            {api.interfaces.length === 0 && <option value="">No interfaces</option>}
            {api.interfaces.map((iface) => (
              <option
                key={iface.name}
                value={iface.name}
                title={[iface.description, iface.addresses.join(", ")]
                  .filter(Boolean)
                  .join(" · ")}
              >
                {iface.name}
                {iface.loopback ? " (loopback)" : ""}
              </option>
            ))}
          </select>
        </label>
        <label className="addr" style={{ flex: 1, minWidth: 220 }}>
          <span className="muted small">BPF</span>
          <input
            className="mono"
            style={{
              flex: 1,
              minWidth: 0,
              ...(api.bpfError ? { borderColor: "var(--danger, #e5484d)" } : {}),
            }}
            value={api.bpf}
            // Editable while running too: pressing Apply re-arms the capture.
            disabled={api.status === "starting"}
            placeholder="tcp port 8080  —  e.g. tcp port 443 or udp port 53"
            spellCheck={false}
            onChange={(e) => api.setBpf(e.target.value)}
            onKeyDown={(e) => {
              if (e.key !== "Enter" || api.bpfError) return;
              if (api.status === "stopped") void api.start();
              else if (api.bpfDirty) void api.apply();
            }}
            title="Capture filter, compiled by libpcap. Edit while running and press Apply to re-arm."
          />
          <BpfStatus checking={api.bpfChecking} error={api.bpfError} filter={api.bpf} />
        </label>
        {running && api.bpfDirty && (
          <button
            className="btn"
            disabled={!!api.bpfError}
            onClick={() => void api.apply()}
            title="Restart the capture with the edited filter (clears the current view)"
          >
            ⟳ Apply
          </button>
        )}
        {running ? (
          <button className="btn danger" onClick={() => void api.stop()}>
            ■ Stop
          </button>
        ) : (
          <button
            className="btn primary"
            disabled={!api.iface || api.status === "starting" || !!api.bpfError}
            onClick={() => void api.start()}
          >
            ▶ {api.status === "starting" ? "Starting…" : "Start"}
          </button>
        )}
      </div>

      {api.error && (
        <div className="banner error">
          <span>{api.error}</span>
          <button className="icon-btn" onClick={() => api.setError(null)}>
            ✕
          </button>
        </div>
      )}

      <div className="notice">
        TLS content is not available in passive mode: HTTPS/<span className="mono">wss</span>{" "}
        flows show metadata only (SNI, ports, timing, sizes). The BPF filter decides what
        is captured; scope only labels known hosts.
      </div>

      <div className="proxy-body">
        <SplitPane direction="column" initial={0.5}>
          <section className="viewer">
            <header className="viewer-head">
              <span className="viewer-title">Flows</span>
              <span className="spacer" />
              <span className="muted mono small">{api.rows.length}</span>
            </header>
            <div className="viewer-body">
              <table className="grid-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Time</th>
                    <th>Client</th>
                    <th>Server</th>
                    <th>Proto</th>
                    <th>Host</th>
                    <th className="right">Pkts</th>
                    <th className="right">Bytes</th>
                    <th>TLS</th>
                    <th>Scope</th>
                  </tr>
                </thead>
                <tbody>
                  {api.rows.map((row, i) => (
                    <tr
                      key={row.id}
                      className={row.id === selectedFlow ? "selected" : ""}
                      onClick={() => {
                        setSelectedFlow(row.id);
                        setSelectedPacket(null);
                      }}
                    >
                      <td className="mono">{i + 1}</td>
                      <td className="mono">{fmtClock(timeMs(row.startedAt))}</td>
                      <td className="mono ellipsis">{row.clientAddr}</td>
                      <td className="mono ellipsis">{row.serverAddr}</td>
                      <td className="mono">{row.transport.toLowerCase()}</td>
                      <td className="mono ellipsis">{row.host ?? "—"}</td>
                      <td className="mono right">{row.packets}</td>
                      <td className="mono right">{fmtBytes(row.bytes)}</td>
                      <td className="mono">{row.tls ? "🔒" : ""}</td>
                      <td>
                        <ScopeTag scope={row.scope} />
                      </td>
                    </tr>
                  ))}
                  {api.rows.length === 0 && (
                    <tr>
                      <td colSpan={10} className="placeholder">
                        {api.interfaces.length === 0
                          ? "No capture interfaces — libpcap is unavailable or the device list was refused"
                          : running
                            ? `Capturing on ${api.iface} — generate traffic, or narrow it with a BPF filter`
                            : "Select an interface (loopback is preselected), optionally set a BPF filter, then press Start"}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <SplitPane direction="row" initial={0.58}>
            <section className="viewer">
              <header className="viewer-head">
                <span className="viewer-title">Packets</span>
                <span className="spacer" />
                {flow && (
                  <span className="muted mono small">
                    {flow.transport.toLowerCase()} {flow.serverAddr}
                  </span>
                )}
                <span className="muted mono small">{packets.length}</span>
              </header>
              <div className="viewer-body">
                <table className="grid-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Time</th>
                      <th>Dir</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th className="right">Wire</th>
                      <th className="right">Payload</th>
                      <th>Flags</th>
                      <th>Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packets.map((p, i) => (
                      <tr
                        key={`${p.flowId}:${i}`}
                        className={i === selectedPacket ? "selected" : ""}
                        onClick={() => setSelectedPacket(i)}
                      >
                        <td className="mono">{i + 1}</td>
                        <td className="mono">{fmtClock(timeMs(p.at))}</td>
                        <td className="mono">
                          {p.direction === "ClientToServer" ? "→" : "←"}
                        </td>
                        <td className="mono ellipsis">{p.srcAddr}</td>
                        <td className="mono ellipsis">{p.dstAddr}</td>
                        <td className="mono right">{p.wireLen}</td>
                        <td className="mono right">{p.payloadLen}</td>
                        <td className="mono ellipsis">{p.tcpFlags ?? "—"}</td>
                        <td className="mono ellipsis">{p.info ?? ""}</td>
                      </tr>
                    ))}
                    {packets.length === 0 && (
                      <tr>
                        <td colSpan={9} className="placeholder">
                          {flow ? "No packets kept for this flow" : "Select a flow"}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="viewer">
              <header className="viewer-head">
                <span className="viewer-title">Packet</span>
                <span className="spacer" />
                {packet && (
                  <span className="dir c2s">
                    {packet.direction === "ClientToServer" ? "→ client → server" : "← server → client"}
                  </span>
                )}
              </header>
              <div className="viewer-body">
                {!packet ? (
                  <div className="placeholder">Select a packet to see its metadata</div>
                ) : (
                  <>
                    <table className="kv">
                      <tbody>
                        <tr>
                          <td>Time</td>
                          <td className="mono">{fmtClock(timeMs(packet.at))}</td>
                        </tr>
                        <tr>
                          <td>Source</td>
                          <td className="mono">{packet.srcAddr}</td>
                        </tr>
                        <tr>
                          <td>Destination</td>
                          <td className="mono">{packet.dstAddr}</td>
                        </tr>
                        <tr>
                          <td>Transport</td>
                          <td className="mono">{flow?.transport.toLowerCase() ?? "—"}</td>
                        </tr>
                        <tr>
                          <td>Wire length</td>
                          <td className="mono">{packet.wireLen} B</td>
                        </tr>
                        <tr>
                          <td>Payload length</td>
                          <td className="mono">{packet.payloadLen} B</td>
                        </tr>
                        <tr>
                          <td>TCP flags</td>
                          <td className="mono">{packet.tcpFlags ?? "—"}</td>
                        </tr>
                        <tr>
                          <td>Label</td>
                          <td className="mono">{packet.info ?? "—"}</td>
                        </tr>
                        <tr>
                          <td>Flow</td>
                          <td className="mono ellipsis">{flow?.id ?? packet.flowId}</td>
                        </tr>
                      </tbody>
                    </table>
                    {flow?.tls && (
                      <div className="notice">
                        This flow carries TLS: the payload is encrypted and is not captured or
                        decrypted here. Use the Proxy or Capture tab for readable content.
                      </div>
                    )}
                  </>
                )}
              </div>
            </section>
          </SplitPane>
        </SplitPane>
      </div>

      <footer className="statusbar">
        <span className={`dot ${running ? "on" : api.status === "starting" ? "busy" : ""}`} />
        <span>
          {running
            ? `Capturing on ${api.iface}${api.bpf.trim() ? ` · ${api.bpf.trim()}` : ""}`
            : api.status === "starting"
              ? "Starting…"
              : "Sniffer stopped"}
        </span>
        <span className="sep" />
        <span>passive · metadata only · nothing persisted</span>
        <span className="spacer" />
        <span>Flows: {api.rows.length}</span>
        <span className="sep" />
        <span>Packets: {totalPackets}</span>
        {flow && (
          <>
            <span className="sep" />
            <span className="mono">{flow.host ?? flow.serverAddr}</span>
          </>
        )}
      </footer>
    </div>
  );
}

/// Inline validity hint for the BPF field: a spinner while the backend
/// compiles the expression, then a check or a cross with the compiler message.
/// Nothing is shown for an empty filter (which means "capture everything").
function BpfStatus({
  checking,
  error,
  filter,
}: {
  checking: boolean;
  error: string | null;
  filter: string;
}) {
  if (!filter.trim()) return null;
  if (checking) return <span className="muted small">…</span>;
  if (error) {
    return (
      <span className="tag warn" title={error}>
        invalid
      </span>
    );
  }
  return (
    <span className="tag ok" title="Filter compiles">
      ✓
    </span>
  );
}

/// The scope tag is advisory: it appears once an SNI/DNS name identifies the
/// host, and never gates the capture (the BPF filter does that).
function ScopeTag({ scope }: { scope: SniffScope | null }) {
  if (!scope) return <span className="muted small">unknown</span>;
  const [label, cls] =
    scope === "InScope"
      ? ["in scope", "tag ok"]
      : scope === "OutOfScope"
        ? ["out of scope", "tag warn"]
        : ["passthrough", "tag"];
  return <span className={cls}>{label}</span>;
}

