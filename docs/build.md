# Build & avvio (sviluppo)

Come compilare e avviare Elliot in locale. Per l'architettura e lo stato di
avanzamento vedi [`architecture.md`](./architecture.md).

## Prerequisiti (Fase 0)

Toolchain di sistema, da installare una volta:

```bash
# Rust (stable, aarch64)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Ollama (opzionale: serve solo per la slice con modello reale)
ollama serve &            # avvia il daemon su :11434
ollama pull llama3.2:1b   # modello piccolo
```

Verifica che rispondano:

```bash
cargo --version
node --version      # atteso >= 26
python3 --version   # atteso >= 3.14
```

La CLI di Tauri **non** va installata globalmente: è una devDependency npm
(`@tauri-apps/cli`) e si invoca via `npm run tauri`.

## Setup del sidecar Python

Crea il virtualenv di sviluppo e installa le dipendenze (`httpx`):

```bash
bash scripts/dev.sh agent:setup
```

In alternativa, a mano:

```bash
python3 -m venv agent/.venv
agent/.venv/bin/pip install -r agent/requirements.txt
```

Prova rapida del sidecar in isolamento (protocollo NDJSON su stdin/stdout):

```bash
cd agent
echo '{"prompt":"ciao"}' | .venv/bin/python -m elliot_agent
```

Attesi: righe `{"type":"chunk", ...}` in streaming e infine `{"type":"done"}`.
Se Ollama è spento arriva comunque una risposta **stub** in streaming (degrado
controllato).

## Avvio dell'app

```bash
cd app && npm install        # la prima volta, risolve e fissa le versioni
bash scripts/dev.sh dev       # oppure: cd app && npm run tauri dev
```

La prima build Rust/Tauri è lunga (compila l'albero delle dipendenze): atteso.
Si apre la finestra dell'app con la vista Agent.

## Verifica end-to-end

1. Prerequisiti fatti; opzionale `ollama serve` + `ollama pull llama3.2:1b`.
2. `bash scripts/dev.sh agent:setup`
3. `bash scripts/dev.sh dev` → si apre la finestra.
4. Nella vista Agent, scrivi un prompt e premi **Invia**.
5. **Atteso:** il testo arriva in streaming chunk dopo chunk — da Ollama se
   attivo, altrimenti dallo stub. Percorso: React → Tauri → Rust → sidecar →
   Ollama → ritorno in UI.
6. **Controprova offline:** ferma Ollama e ripeti → arriva lo stub in streaming.

## Note

- **CLI Tauri non trovata:** è in `devDependencies`, usa `npm run tauri`.
- **rustls, non OpenSSL:** `pkg-config`/OpenSSL non sono richiesti; in questo
  milestone il lato Rust non fa rete.
- **Python 3.14 + macOS 27** molto recenti: `httpx` è puro Python, basso
  rischio di wheel mancanti.
