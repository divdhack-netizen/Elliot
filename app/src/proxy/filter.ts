// Wireshark-style display filter over the history rows.
//
//   expr    := or
//   or      := and (("||" | "or") and)*
//   and     := not (("&&" | "and") not)*
//   not     := ("!" | "not") not | primary
//   primary := "(" expr ")" | field [op value] | bare-word
//   op      := == != > < >= <= contains matches ~
//
// A bare word (or quoted string) is a free-text search on the URL. A field
// with no operator tests that the value is non-empty, e.g. `resp` or `edited`.

import { decode } from "./format";
import type { Row } from "./types";

export type Predicate = (r: Row) => boolean;
export type Compiled = { ok: true; pred: Predicate | null } | { ok: false; error: string };

type Value = string | number | boolean | null;

const FIELDS: Record<string, (r: Row) => Value> = {
  host: (r) => r.flow.host,
  method: (r) => r.flow.request.method,
  url: (r) => r.url,
  path: (r) => r.path,
  ext: (r) => r.ext,
  mime: (r) => r.mime,
  status: (r) => r.flow.response?.status ?? null,
  len: (r) => r.length,
  time: (r) => r.durationMs,
  port: (r) => r.flow.port,
  scheme: (r) => r.flow.scheme.toLowerCase(),
  tls: (r) => r.flow.scheme === "Https",
  state: (r) => r.flow.state.toLowerCase(),
  edited: (r) => r.edited,
  resp: (r) => r.flow.response != null,
  "req.body": (r) => decode(r.flow.request.body),
  "resp.body": (r) => (r.flow.response ? decode(r.flow.response.body) : null),
  "req.headers": (r) => r.flow.request.headers.map((h) => `${h.name}: ${decode(h.value)}`).join("\n"),
  "resp.headers": (r) =>
    r.flow.response?.headers.map((h) => `${h.name}: ${decode(h.value)}`).join("\n") ?? null,
};

// Wireshark spells these with a protocol prefix; accept both forms.
const ALIASES: Record<string, string> = {
  "http.host": "host",
  "http.request.method": "method",
  "http.request.uri": "path",
  "http.request.full_uri": "url",
  "http.response.code": "status",
  "http.content_type": "mime",
  "http.content_length": "len",
  "http.response": "resp",
  "http.request.body": "req.body",
  "http.response.body": "resp.body",
};

export const FIELD_NAMES = Object.keys(FIELDS);

type Tok = { t: "op" | "word" | "str" | "lp" | "rp" | "and" | "or" | "not"; v: string };

function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "(") { out.push({ t: "lp", v: c }); i++; continue; }
    if (c === ")") { out.push({ t: "rp", v: c }); i++; continue; }
    const two = src.slice(i, i + 2);
    if (two === "&&") { out.push({ t: "and", v: two }); i += 2; continue; }
    if (two === "||") { out.push({ t: "or", v: two }); i += 2; continue; }
    if (["==", "!=", ">=", "<="].includes(two)) { out.push({ t: "op", v: two }); i += 2; continue; }
    if (c === ">" || c === "<" || c === "~") { out.push({ t: "op", v: c }); i++; continue; }
    if (c === "!") { out.push({ t: "not", v: c }); i++; continue; }
    if (c === '"' || c === "'") {
      let j = i + 1;
      let s = "";
      while (j < src.length && src[j] !== c) {
        if (src[j] === "\\" && j + 1 < src.length) j++;
        s += src[j++];
      }
      if (j >= src.length) throw new Error("unterminated string");
      out.push({ t: "str", v: s });
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < src.length && !/[\s()!=<>~&|"']/.test(src[j])) j++;
    if (j === i) throw new Error(`unexpected '${c}'`);
    const w = src.slice(i, j);
    const lw = w.toLowerCase();
    if (lw === "and") out.push({ t: "and", v: w });
    else if (lw === "or") out.push({ t: "or", v: w });
    else if (lw === "not") out.push({ t: "not", v: w });
    else if (lw === "contains" || lw === "matches") out.push({ t: "op", v: lw });
    else out.push({ t: "word", v: w });
    i = j;
  }
  return out;
}

function compare(a: Value, op: string, raw: string): boolean {
  if (a == null) return op === "!=";
  if (op === "contains") return String(a).toLowerCase().includes(raw.toLowerCase());
  if (op === "matches" || op === "~") return new RegExp(raw, "i").test(String(a));
  if (typeof a === "boolean") {
    const b = raw === "true" || raw === "1";
    return op === "==" ? a === b : op === "!=" ? a !== b : false;
  }
  if (typeof a === "number") {
    // `status == 4xx` style class match.
    const cls = /^([1-5])xx$/i.exec(raw);
    if (cls && (op === "==" || op === "!=")) {
      const hit = Math.floor(a / 100) === Number(cls[1]);
      return op === "==" ? hit : !hit;
    }
    const b = Number(raw);
    if (Number.isNaN(b)) throw new Error(`'${raw}' is not a number`);
    switch (op) {
      case "==": return a === b;
      case "!=": return a !== b;
      case ">": return a > b;
      case "<": return a < b;
      case ">=": return a >= b;
      case "<=": return a <= b;
    }
  }
  const sa = String(a).toLowerCase();
  const sb = raw.toLowerCase();
  switch (op) {
    case "==": return sa === sb;
    case "!=": return sa !== sb;
    case ">": return sa > sb;
    case "<": return sa < sb;
    case ">=": return sa >= sb;
    case "<=": return sa <= sb;
  }
  return false;
}

function parse(toks: Tok[]): Predicate {
  let i = 0;
  const peek = () => toks[i];

  function or(): Predicate {
    let l = and();
    while (peek()?.t === "or") {
      i++;
      const a = l, b = and();
      l = (r) => a(r) || b(r);
    }
    return l;
  }
  function and(): Predicate {
    let l = not();
    while (peek()?.t === "and") {
      i++;
      const a = l, b = not();
      l = (r) => a(r) && b(r);
    }
    return l;
  }
  function not(): Predicate {
    if (peek()?.t === "not") {
      i++;
      const p = not();
      return (r) => !p(r);
    }
    return primary();
  }
  function primary(): Predicate {
    const tok = toks[i++];
    if (!tok) throw new Error("expression expected");
    if (tok.t === "lp") {
      const p = or();
      if (toks[i++]?.t !== "rp") throw new Error("missing ')'");
      return p;
    }
    if (tok.t === "str") {
      const needle = tok.v.toLowerCase();
      return (r) => r.url.toLowerCase().includes(needle);
    }
    if (tok.t !== "word") throw new Error(`unexpected '${tok.v}'`);

    const name = ALIASES[tok.v.toLowerCase()] ?? tok.v.toLowerCase();
    const get = FIELDS[name];
    if (peek()?.t === "op") {
      if (!get) throw new Error(`unknown field '${tok.v}'`);
      const op = toks[i++].v;
      const val = toks[i++];
      if (!val || (val.t !== "word" && val.t !== "str")) throw new Error(`value expected after '${op}'`);
      if (op === "matches" || op === "~") new RegExp(val.v); // surface bad regex now
      // Fail fast on type errors by probing a numeric field once.
      if (["status", "len", "time", "port"].includes(name) && !["contains", "matches", "~"].includes(op)
        && !/^[1-5]xx$/i.test(val.v) && Number.isNaN(Number(val.v))) {
        throw new Error(`'${val.v}' is not a number`);
      }
      return (r) => compare(get(r), op, val.v);
    }
    if (get) return (r) => { const v = get(r); return v != null && v !== false && v !== ""; };
    // Bare word: free-text URL search.
    const needle = tok.v.toLowerCase();
    return (r) => r.url.toLowerCase().includes(needle);
  }

  const p = or();
  if (i < toks.length) throw new Error(`unexpected '${toks[i].v}'`);
  return p;
}

export function compileFilter(src: string): Compiled {
  if (!src.trim()) return { ok: true, pred: null };
  try {
    return { ok: true, pred: parse(lex(src)) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
