# Tool catalog

The catalog is the contract shared by three parties:

- the **Python agent** reads it for *grounding* — which tools exist and which flags it may propose;
- the **Rust Tool runner** uses it as the *validation* schema — a proposal is executed only if it conforms;
- the **user** consults and extends it.

## The two artifacts

1. **`schema/tool-entry.schema.yaml`** — the machine-enforced contract. JSON Schema
   (draft 2020-12). Both Rust and Python validate every entry against it. It is
   *safe-by-construction*: the only valid way to write a field is the safe way
   (strings must be patterned, paths must be confined, enums must list their
   values, intrusiveness must be declared, scope checking cannot be disabled,
   and there is no free-form raw-args field anywhere).

2. **`standard/nmap.yaml`** — the reference ("golden") entry. The template every
   other `standard` entry follows. Hand-vetted; the security annotations are
   human judgment, not auto-generated.

## Entry sources

- `source: standard` — bundled and vetted by maintainers. Picked by the user
  from a curated list; the vetted YAML is activated, and the binary is detected
  and (with confirmation) the user is guided to install it if missing.
- `source: custom` — authored by a user for a tool not in the list. The schema
  enforces structure; a `--help`-based drafting aid may propose a skeleton, but
  a human always reviews it. A lax custom entry stays local — the catalog is not
  inherited when a project is handed off.

## Enforcement invariants

- **Allow-list, default-deny.** Only listed flags may be proposed or executed.
- **Effective intrusiveness = max(tool, used flags)** — drives mandatory human
  confirmation.
- **Catalog entry ≠ binary.** The runner verifies the binary exists before
  executing and degrades gracefully (read-only) when a tool or binary is absent.
- The agent only *proposes*; the Rust runner *validates and executes*.
