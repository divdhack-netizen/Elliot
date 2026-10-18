"""Client di streaming verso Ollama, con fallback stub.

Frontiera di fiducia: il sidecar produce solo testo, non esegue nulla e non
applica scope. La diagnostica va su stderr; stdout è riservato al protocollo
NDJSON (vedi ``__main__``).
"""
import json
import os
import sys
from collections.abc import Iterator

import httpx

DEFAULT_OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.2:1b"
REQUEST_TIMEOUT_S = 60
STUB_PREFIX = "[stub] Ollama non raggiungibile. Eco:"

# Override d'ambiente: comodo per i test e per puntare a un host diverso in dev.
OLLAMA_URL_ENV = "ELLIOT_OLLAMA_URL"


def stream_reply(prompt: str, model: str | None = None) -> Iterator[str]:
    """Produce i pezzi di testo della risposta di Ollama.

    Se Ollama è irraggiungibile *prima* di produrre output, degrada a uno stub
    (degrado controllato). Un errore a metà stream interrompe in modo pulito,
    senza riemettere lo stub sopra i chunk già prodotti.
    """
    payload = {
        "model": model or DEFAULT_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
    }
    produced = False
    try:
        with httpx.stream(
            "POST", _ollama_url(), json=payload, timeout=REQUEST_TIMEOUT_S
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                message = _parse(line)
                if message is None:
                    continue
                piece = message.get("message", {}).get("content", "")
                if piece:
                    produced = True
                    yield piece
                if message.get("done"):
                    return
    except httpx.HTTPError as exc:
        if produced:
            _log(f"ollama: stream interrotto dopo output parziale: {exc!r}")
            return
        _log(f"ollama: irraggiungibile, uso lo stub: {exc!r}")
        yield from _stub_reply(prompt)


def _parse(line: str) -> dict | None:
    """Una riga NDJSON di Ollama come dict, o None se vuota o non-JSON.

    Una riga non-JSON a metà stream viene saltata (loggata), senza far fallire
    la risposta già in corso.
    """
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        _log(f"ollama: riga non-JSON ignorata: {line!r}")
        return None


def _stub_reply(prompt: str) -> Iterator[str]:
    for word in f"{STUB_PREFIX} {prompt}".split(" "):
        yield word + " "


def _ollama_url() -> str:
    return os.environ.get(OLLAMA_URL_ENV, DEFAULT_OLLAMA_URL)


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
