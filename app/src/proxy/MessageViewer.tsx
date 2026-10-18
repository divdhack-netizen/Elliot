import { useMemo, useState } from "react";
import { decode, fmtBytes, header, isProbablyText } from "./format";
import type { Bytes, Header } from "./types";

export type Message = {
  startLine: string;
  headers: Header[];
  body: Bytes;
  raw: Bytes;
};

type Tab = "pretty" | "raw" | "hex" | "headers";
const TABS: Array<[Tab, string]> = [
  ["pretty", "Pretty"],
  ["raw", "Raw"],
  ["hex", "Hex"],
  ["headers", "Headers"],
];

const HEX_LIMIT = 64 * 1024;

type Props = {
  title: string;
  message: Message | null;
  placeholder: string;
  tab: Tab;
  onTab: (t: Tab) => void;
  extra?: React.ReactNode;
};

/// One side of Burp's Request/Response split: Pretty / Raw / Hex / Headers.
export function MessageViewer({ title, message, placeholder, tab, onTab, extra }: Props) {
  const [copied, setCopied] = useState(false);

  function copy() {
    if (!message) return;
    navigator.clipboard.writeText(decode(message.raw)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  }

  return (
    <section className="viewer">
      <header className="viewer-head">
        <span className="viewer-title">{title}</span>
        <nav className="seg">
          {TABS.map(([k, label]) => (
            <button key={k} className={tab === k ? "active" : ""} onClick={() => onTab(k)}>
              {label}
            </button>
          ))}
        </nav>
        <span className="spacer" />
        {extra}
        {message && <span className="muted mono small">{fmtBytes(message.raw.length)} B</span>}
        <button className="icon-btn" disabled={!message} onClick={copy} title="Copy raw message">
          {copied ? "✓" : "⧉"}
        </button>
      </header>
      <div className="viewer-body">
        {!message ? (
          <div className="placeholder">{placeholder}</div>
        ) : tab === "pretty" ? (
          <Pretty m={message} />
        ) : tab === "raw" ? (
          <pre className="code">{decode(message.raw)}</pre>
        ) : tab === "hex" ? (
          <HexDump bytes={message.raw} />
        ) : (
          <HeaderTable headers={message.headers} />
        )}
      </div>
    </section>
  );
}

export type { Tab as ViewerTab };

function Pretty({ m }: { m: Message }) {
  const body = useMemo(() => prettyBody(m), [m]);
  const [method, ...rest] = m.startLine.split(" ");
  return (
    <pre className="code">
      <span className="tok-start">
        <span className="tok-method">{method}</span> {rest.join(" ")}
      </span>
      {"\n"}
      {m.headers.map((h, i) => (
        <span key={i}>
          <span className="tok-hname">{h.name}</span>
          <span className="tok-punct">: </span>
          <span className="tok-hval">{decode(h.value)}</span>
          {"\n"}
        </span>
      ))}
      {body != null && (
        <>
          {"\n"}
          {body}
        </>
      )}
    </pre>
  );
}

function prettyBody(m: Message): React.ReactNode {
  if (!m.body.length) return null;
  if (!isProbablyText(m.body)) {
    return <span className="muted">{`<binary body, ${m.body.length} bytes — see Hex>`}</span>;
  }
  const text = decode(m.body);
  const ct = (header(m.headers, "content-type") ?? "").toLowerCase();
  if (ct.includes("json") || /^\s*[[{]/.test(text)) {
    try {
      return <JsonHighlight text={JSON.stringify(JSON.parse(text), null, 2)} />;
    } catch {
      /* not JSON after all */
    }
  }
  if (ct.includes("x-www-form-urlencoded")) {
    return text.split("&").map((kv, i) => {
      const [k, v = ""] = kv.split("=");
      return (
        <span key={i}>
          {i > 0 && <span className="tok-punct">&amp;</span>}
          <span className="tok-hname">{safeDecode(k)}</span>
          <span className="tok-punct">=</span>
          <span className="tok-str">{safeDecode(v)}</span>
        </span>
      );
    });
  }
  return text;
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

function JsonHighlight({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let k = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) {
      parts.push(<span key={k++} className={m[2] ? "tok-key" : "tok-str"}>{m[1]}</span>);
      if (m[2]) parts.push(m[2]);
    } else if (m[3]) parts.push(<span key={k++} className="tok-lit">{m[3]}</span>);
    else parts.push(<span key={k++} className="tok-num">{m[4]}</span>);
    last = re.lastIndex;
  }
  parts.push(text.slice(last));
  return <>{parts}</>;
}

/// Wireshark "packet bytes" pane: offset | 16 hex bytes | ASCII.
function HexDump({ bytes }: { bytes: Bytes }) {
  const lines = useMemo(() => {
    const n = Math.min(bytes.length, HEX_LIMIT);
    const out: string[] = [];
    for (let off = 0; off < n; off += 16) {
      const chunk = bytes.slice(off, Math.min(off + 16, n));
      const hex = chunk.map((b) => b.toString(16).padStart(2, "0"));
      const left = hex.slice(0, 8).join(" ");
      const right = hex.slice(8).join(" ");
      const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
      out.push(`${off.toString(16).padStart(8, "0")}  ${left.padEnd(23)}  ${right.padEnd(23)}  ${ascii}`);
    }
    return out;
  }, [bytes]);
  return (
    <pre className="code hex">
      {lines.map((l, i) => (
        <span key={i}>
          <span className="hex-off">{l.slice(0, 8)}</span>
          <span className="hex-bytes">{l.slice(8, 58)}</span>
          <span className="hex-ascii">{l.slice(58)}</span>
          {"\n"}
        </span>
      ))}
      {bytes.length > HEX_LIMIT && <span className="muted">{`… ${bytes.length - HEX_LIMIT} more bytes not shown`}</span>}
    </pre>
  );
}

function HeaderTable({ headers }: { headers: Header[] }) {
  if (!headers.length) return <div className="placeholder">No headers</div>;
  return (
    <table className="kv">
      <thead>
        <tr>
          <th>Name</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {headers.map((h, i) => (
          <tr key={i}>
            <td className="tok-hname">{h.name}</td>
            <td>{decode(h.value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
