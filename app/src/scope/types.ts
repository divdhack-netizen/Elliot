// Wire types for the scope policy. They mirror `elliot_scope::{ScopePolicy,
// Rule}` as serde serializes it: field names are snake_case, and the matcher
// enums are snake_case-tagged unit variants or externally tagged newtypes
// (`{"exact": "example.com"}`, `{"prefix": "/api/"}`).

export type SchemeMatch = "any" | "http" | "https";
export type HostMatch = "any" | { exact: string } | { suffix: string };
export type PortMatch = "any" | { exact: number };
export type PathMatch = "any" | { prefix: string };

export type Rule = {
  scheme: SchemeMatch;
  host: HostMatch;
  port: PortMatch;
  path: PathMatch;
};

export type ScopePolicy = { include: Rule[]; exclude: Rule[] };

export type ProjectStatus = {
  open: boolean;
  path: string | null;
  defaultPath: string;
};

export const EMPTY_POLICY: ScopePolicy = { include: [], exclude: [] };

/// A rule that constrains nothing; a building block the UI edits from.
export function anyRule(): Rule {
  return { scheme: "any", host: "any", port: "any", path: "any" };
}

export type HostKind = "any" | "exact" | "suffix";

export function hostKind(h: HostMatch): HostKind {
  if (h === "any") return "any";
  return "exact" in h ? "exact" : "suffix";
}

export function hostText(h: HostMatch): string {
  if (h === "any") return "";
  return "exact" in h ? h.exact : h.suffix;
}

export function withHostKind(rule: Rule, kind: HostKind): Rule {
  if (kind === "any") return { ...rule, host: "any" };
  const text = hostText(rule.host);
  return { ...rule, host: kind === "exact" ? { exact: text } : { suffix: text } };
}

export function withHostText(rule: Rule, text: string): Rule {
  const kind = hostKind(rule.host);
  if (kind === "any") return rule;
  return { ...rule, host: kind === "exact" ? { exact: text } : { suffix: text } };
}

export function portText(p: PortMatch): string {
  return p === "any" ? "" : String(p.exact);
}

/// An empty or non-numeric port clears the constraint rather than guessing one.
export function withPort(rule: Rule, text: string): Rule {
  const digits = text.replace(/[^0-9]/g, "");
  if (!digits) return { ...rule, port: "any" };
  return { ...rule, port: { exact: Number(digits) } };
}

export function pathText(p: PathMatch): string {
  return p === "any" ? "" : p.prefix;
}

export function withPath(rule: Rule, text: string): Rule {
  return { ...rule, path: text ? { prefix: text } : "any" };
}

/// A one-line description of a rule, for the summary/empty states.
export function describe(rule: Rule): string {
  const parts: string[] = [];
  if (rule.scheme !== "any") parts.push(rule.scheme);
  const kind = hostKind(rule.host);
  const text = hostText(rule.host);
  if (kind === "exact") parts.push(`host == ${text}`);
  else if (kind === "suffix") parts.push(`*.${text}`);
  else parts.push("any host");
  if (rule.port !== "any") parts.push(`:${rule.port.exact}`);
  if (rule.path !== "any") parts.push(rule.path.prefix);
  return parts.join(" ");
}
