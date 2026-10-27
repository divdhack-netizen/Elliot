"""Catalogo dei tool: grounding dell'agente e validazione delle proposte.

Il catalogo è lo stesso insieme di YAML che il crate Rust `catalog` impacchetta
(``catalog/standard/*.yaml``). Qui serve a due cose:

- costruire il testo di grounding nel prompt, così un modello piccolo non
  inventa tool o flag;
- rifiutare una proposta che nomina qualcosa che non esiste, **prima** che
  arrivi al core Rust.

Quello che questo modulo *non* fa, di proposito: non controlla lo scope e non
esegue nulla. L'agente propone soltanto; la frontiera di fiducia (schema + scope
+ conferma umana) vive nel core Rust.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

# Override d'ambiente per test e installazioni non-standard.
CATALOG_DIR_ENV = "ELLIOT_CATALOG_DIR"


class ProposalError(ValueError):
    """La proposta non rispetta il catalogo."""


@dataclass(frozen=True)
class Flag:
    name: str
    flag_type: str
    intrusiveness: str | None
    values: tuple[str, ...]
    repeatable: bool
    requires_privilege: str | None


@dataclass(frozen=True)
class Tool:
    id: str
    binary: str
    description: str
    base_intrusiveness: str
    target_kind: str
    target_type: str
    cardinality: str
    flags: tuple[Flag, ...]

    def flag(self, name: str) -> Flag | None:
        return next((f for f in self.flags if f.name == name), None)


def catalog_dir() -> Path:
    """La cartella ``catalog/`` del repo, salvo override d'ambiente."""
    override = os.environ.get(CATALOG_DIR_ENV)
    if override:
        return Path(override)
    # .../agent/elliot_agent/catalog.py -> .../catalog
    return Path(__file__).resolve().parents[2] / "catalog"


def load_catalog(directory: Path | None = None) -> dict[str, Tool]:
    """Carica tutte le voci ``standard/``. Una voce invalida viene saltata.

    Tollerare una voce rotta è deliberato: il catalogo è dato di configurazione,
    non deve poter fermare la chat. La diagnostica resta su stderr.
    """
    root = (directory or catalog_dir()) / "standard"
    tools: dict[str, Tool] = {}
    if not root.is_dir():
        _log(f"catalogo non trovato in {root}")
        return tools

    for path in sorted(root.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            tool = _to_tool(raw)
        except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
            _log(f"voce di catalogo ignorata ({path.name}): {exc!r}")
            continue
        if tool.id in tools:
            _log(f"id duplicato nel catalogo: {tool.id} ({path.name})")
            continue
        tools[tool.id] = tool
    return tools


def _to_tool(raw: object) -> Tool:
    if not isinstance(raw, dict):
        raise ValueError("la voce non è un oggetto")
    target = raw["target"]
    if not isinstance(target, dict):
        raise ValueError("target non è un oggetto")
    flags: list[Flag] = []
    for item in raw.get("flags") or []:
        if not isinstance(item, dict):
            raise ValueError("flag non è un oggetto")
        flags.append(
            Flag(
                name=str(item["name"]),
                flag_type=str(item["type"]),
                intrusiveness=item.get("intrusiveness"),
                values=tuple(str(v) for v in item.get("values") or ()),
                repeatable=bool(item.get("repeatable", False)),
                requires_privilege=item.get("requires_privilege"),
            )
        )
    return Tool(
        id=str(raw["id"]),
        binary=str(raw["binary"]),
        description=str(raw["description"]),
        base_intrusiveness=str(raw["base_intrusiveness"]),
        target_kind=str(target["kind"]),
        target_type=str(target["type"]),
        cardinality=str(target["cardinality"]),
        flags=tuple(flags),
    )


def describe(tools: dict[str, Tool]) -> str:
    """Il blocco di grounding: solo questi tool e queste flag sono nominabili."""
    lines: list[str] = []
    for tool in tools.values():
        lines.append(
            f"- {tool.id} (binario {tool.binary}): {tool.description} "
            f"base_intrusiveness={tool.base_intrusiveness}; "
            f"target={tool.target_kind}/{tool.target_type}/{tool.cardinality}"
        )
        if tool.flags:
            lines.append("  flags ammesse:")
            for flag in tool.flags:
                details = [flag.flag_type]
                if flag.values:
                    details.append("valori: " + ", ".join(flag.values))
                if flag.intrusiveness:
                    details.append(f"intrusiveness={flag.intrusiveness}")
                if flag.requires_privilege:
                    details.append(f"privilegio={flag.requires_privilege}")
                lines.append(f"    {flag.name} ({'; '.join(details)})")
    return "\n".join(lines)


def validate_proposal(raw: object, tools: dict[str, Tool]) -> dict:
    """Normalizza una proposta o solleva :class:`ProposalError`.

    Rifiuta qualunque tool o flag fuori catalogo, i valori mancanti o non
    ammessi e le cardinalità sbagliate. Non guarda lo scope: quello è del runner.
    """
    if not isinstance(raw, dict):
        raise ProposalError("la proposta non è un oggetto JSON")

    tool_id = raw.get("tool_id")
    if not isinstance(tool_id, str) or tool_id not in tools:
        raise ProposalError(f"tool fuori catalogo: {tool_id!r}")
    tool = tools[tool_id]

    targets = raw.get("targets") or []
    if not isinstance(targets, list) or not all(isinstance(t, str) and t.strip() for t in targets):
        raise ProposalError("targets deve essere una lista di stringhe non vuote")
    if tool.cardinality == "one" and len(targets) != 1:
        raise ProposalError(f"{tool_id} vuole esattamente un target, ne ho {len(targets)}")
    if tool.cardinality == "one_or_more" and not targets:
        raise ProposalError(f"{tool_id} vuole almeno un target")

    flags = raw.get("flags") or []
    if not isinstance(flags, list):
        raise ProposalError("flags deve essere una lista")
    normalised: list[dict] = []
    seen: dict[str, int] = {}
    for item in flags:
        if not isinstance(item, dict):
            raise ProposalError("ogni flag deve essere un oggetto")
        name = item.get("name")
        if not isinstance(name, str):
            raise ProposalError("flag senza nome")
        spec = tool.flag(name)
        if spec is None:
            raise ProposalError(f"flag {name!r} non ammessa per {tool_id}")
        seen[name] = seen.get(name, 0) + 1
        if seen[name] > 1 and not spec.repeatable:
            raise ProposalError(f"flag {name!r} non ripetibile")
        value = item.get("value")
        if spec.flag_type == "bool":
            if value is not None:
                raise ProposalError(f"flag booleana {name!r} non prende valore")
        else:
            if not isinstance(value, (str, int, float)):
                raise ProposalError(f"flag {name!r} richiede un valore")
            value = str(value)
            if spec.values and value not in spec.values:
                raise ProposalError(f"{value!r} non è tra i valori ammessi di {name!r}")
        normalised.append({"name": name} if value is None else {"name": name, "value": value})

    return {"tool_id": tool_id, "flags": normalised, "targets": targets}


def parse_proposal_json(text: str) -> dict | None:
    """Il primo oggetto JSON completo nel testo del modello, o None.

    I modelli piccoli incorniciano il JSON con prose o code fence: si prova ogni
    ``{`` come inizio e si tiene la prima decodifica riuscita.
    """
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            candidate, _end = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            return candidate
    return None


def _log(message: str) -> None:
    print(f"elliot-agent: {message}", file=sys.stderr, flush=True)
