import type { Bytes, Flow, Header, Row, Time } from "./types";

const decoder = new TextDecoder("utf-8", { fatal: false });
const encoder = new TextEncoder();

export function decode(b: Bytes): string {
  return decoder.decode(new Uint8Array(b));
}

export function encode(s: string): number[] {
  return Array.from(encoder.encode(s));
}

export function header(headers: Header[], name: string): string | null {
  const lower = name.toLowerCase();
  const h = headers.find((h) => h.name.toLowerCase() === lower);
  return h ? decode(h.value) : null;
}

export function timeMs(t: Time): number {
  return t.secs_since_epoch * 1000 + Math.floor(t.nanos_since_epoch / 1e6);
}

/// Full URL of a flow; the target may already be in absolute form.
export function flowUrl(f: Flow): string {
  const t = f.request.target;
  if (/^https?:\/\//i.test(t)) return t;
  const scheme = f.scheme === "Https" ? "https" : "http";
  const defaultPort = scheme === "https" ? 443 : 80;
  const port = f.port && f.port !== defaultPort ? `:${f.port}` : "";
  return `${scheme}://${f.host}${port}${t.startsWith("/") ? t : `/${t}`}`;
}

function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

function extOf(path: string): string {
  const p = path.split(/[?#]/)[0];
  const last = p.split("/").pop() ?? "";
  const dot = last.lastIndexOf(".");
  return dot > 0 ? last.slice(dot + 1).toLowerCase().slice(0, 8) : "";
}

/// Burp-style short MIME label ("JSON", "HTML", "script"...).
export function mimeLabel(contentType: string | null): string {
  if (!contentType) return "";
  const ct = contentType.split(";")[0].trim().toLowerCase();
  if (ct.includes("json")) return "JSON";
  if (ct.includes("html")) return "HTML";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "script";
  if (ct.includes("css")) return "CSS";
  if (ct.includes("xml")) return "XML";
  if (ct.startsWith("image/")) return ct === "image/svg+xml" ? "SVG" : "image";
  if (ct.startsWith("font/") || ct.includes("font")) return "font";
  if (ct.startsWith("text/")) return "text";
  if (ct.startsWith("video/") || ct.startsWith("audio/")) return "media";
  return ct.split("/").pop() ?? ct;
}

export function toRow(flow: Flow, seq: number, edited: boolean): Row {
  const url = flowUrl(flow);
  const path = pathOf(url);
  const res = flow.response;
  const startedMs = timeMs(flow.started_at);
  return {
    seq,
    flow,
    url,
    path,
    ext: extOf(path),
    mime: res ? mimeLabel(header(res.headers, "content-type")) : "",
    length: res ? res.raw.length || res.body.length : null,
    durationMs: flow.completed_at ? Math.max(0, timeMs(flow.completed_at) - startedMs) : null,
    startedMs,
    edited,
  };
}

export function fmtBytes(n: number | null): string {
  if (n == null) return "";
  if (n < 1024) return `${n}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}k`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

export function fmtClock(ms: number): string {
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export function fmtDuration(ms: number | null): string {
  if (ms == null) return "";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

/// The request as the user edits it: CRLF line endings shown as LF.
export function rawForEditing(raw: Bytes): string {
  return decode(raw).replace(/\r\n/g, "\n");
}

/// Turn edited text back into wire bytes: CRLF in the head, body untouched,
/// and Content-Length recomputed (as Burp does) when the header is present.
export function editedToWire(text: string): number[] {
  const split = text.indexOf("\n\n");
  const headText = split >= 0 ? text.slice(0, split) : text.replace(/\n+$/, "");
  const body = split >= 0 ? text.slice(split + 2) : "";
  const bodyBytes = encoder.encode(body);
  const lines = headText.split("\n").map((l) =>
    /^content-length\s*:/i.test(l) ? `Content-Length: ${bodyBytes.length}` : l,
  );
  const head = encoder.encode(lines.join("\r\n") + "\r\n\r\n");
  const out = new Uint8Array(head.length + bodyBytes.length);
  out.set(head);
  out.set(bodyBytes, head.length);
  return Array.from(out);
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function toCurl(f: Flow): string {
  const parts = ["curl", "-i", "-X", f.request.method, shellQuote(flowUrl(f))];
  for (const h of f.request.headers) {
    const name = h.name.toLowerCase();
    if (name === "content-length" || name === "host") continue;
    parts.push("-H", shellQuote(`${h.name}: ${decode(h.value)}`));
  }
  if (f.request.body.length) parts.push("--data-binary", shellQuote(decode(f.request.body)));
  return parts.join(" ");
}

export function isProbablyText(b: Bytes): boolean {
  const n = Math.min(b.length, 2048);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32)) bad++;
  }
  return bad / Math.max(n, 1) < 0.05;
}
