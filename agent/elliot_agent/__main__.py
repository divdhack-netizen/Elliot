"""Entry point del sidecar: protocollo NDJSON su stdin/stdout.

Legge una richiesta JSON (una riga) da stdin e scrive frame NDJSON su stdout:
  {"type": "chunk", "text": ...}    testo in streaming
  {"type": "done"}                   fine risposta (sempre l'ultimo frame)
  {"type": "error", "message": ...}  richiesta non valida

stdout è esclusivamente per questi frame; ogni diagnostica va su stderr.
"""
import json
import os
import sys

from .ollama_client import stream_reply


def main() -> None:
    try:
        _run()
    except BrokenPipeError:
        # Il consumatore (il core Rust) è sparito a metà stream: usciamo in
        # silenzio, senza traceback. Si reindirizza lo stdout su /dev/null così
        # Python non ritenta il flush sul fd rotto allo shutdown.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)


def _run() -> None:
    raw = sys.stdin.readline()
    if not raw:
        return

    request = _parse_request(raw)
    if request is None:
        _emit({"type": "error", "message": "richiesta JSON non valida"})
        _emit({"type": "done"})
        return

    for piece in stream_reply(request.get("prompt", ""), request.get("model")):
        _emit({"type": "chunk", "text": piece})
    _emit({"type": "done"})


def _parse_request(raw: str) -> dict | None:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _emit(frame: dict) -> None:
    sys.stdout.write(json.dumps(frame) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
