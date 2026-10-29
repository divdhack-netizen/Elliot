// Byte <-> editor conversions for the repeater and intruder editors.
//
// The editor works in either text (UTF-8) or hex, because the bytes being
// replayed are arbitrary: a crafted request may not be text at all. Hex input
// is strict — a stray character is an error, never a silently dropped nibble.

import { decode, encode } from "../proxy/format";

export type EditorMode = "text" | "hex";

export const EDITOR_MODES: Array<[EditorMode, string]> = [
  ["text", "Text"],
  ["hex", "Hex"],
];

export function bytesToHex(bytes: number[], perLine = 32): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += perLine) {
    lines.push(
      bytes
        .slice(i, i + perLine)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" "),
    );
  }
  return lines.join("\n");
}

export function hexToBytes(
  text: string,
): { ok: true; bytes: number[] } | { ok: false; error: string } {
  // Whitespace and separators are ignored: a pasted dump and `0a,0d` both work.
  const clean = text.replace(/[\s,:]/g, "");
  if (!/^[0-9a-fA-F]*$/.test(clean)) {
    return { ok: false, error: "not hex" };
  }
  if (clean.length % 2 !== 0) {
    return { ok: false, error: "odd number of hex digits" };
  }
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.slice(i, i + 2), 16));
  }
  return { ok: true, bytes };
}

export function bytesToEditor(bytes: number[], mode: EditorMode): string {
  return mode === "text" ? decode(bytes) : bytesToHex(bytes);
}

export function editorToBytes(
  text: string,
  mode: EditorMode,
): { ok: true; bytes: number[] } | { ok: false; error: string } {
  return mode === "text" ? { ok: true, bytes: encode(text) } : hexToBytes(text);
}

/** The byte length of a prefix of a text buffer (for selection -> offsets). */
export function byteOffsetOf(text: string, charIndex: number): number {
  return encode(text.slice(0, charIndex)).length;
}
