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

Crea il virtualenv di sviluppo e installa le dipendenze (`httpx` per Ollama,
`PyYAML` per leggere il catalogo):

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

Attesi: righe `{"v":1,"type":"chunk", ...}` in streaming, eventualmente una
`{"type":"proposal", ...}` e infine `{"type":"done"}`. Il processo resta vivo
finché stdin è aperto (una richiesta per riga). Se Ollama è spento arriva
comunque una risposta **stub** in streaming (degrado controllato).

Test del sidecar (senza rete, modello finto):

```bash
cd agent && .venv/bin/python -m unittest discover -s tests -v
```

## Avvio dell'app

```bash
cd app && npm install        # la prima volta, risolve e fissa le versioni
bash scripts/dev.sh dev       # oppure: cd app && npm run tauri dev
```

La prima build Rust/Tauri è lunga (compila l'albero delle dipendenze): atteso.
Si apre la finestra dell'app sulla vista Proxy.

## Verifica end-to-end

1. Prerequisiti fatti; opzionale `ollama serve` + `ollama pull llama3.2:1b`.
2. `bash scripts/dev.sh agent:setup`
3. `bash scripts/dev.sh dev` → si apre la finestra.
4. Nella vista Agent, scrivi un prompt e premi **Send**.
5. **Atteso:** il testo arriva in streaming chunk dopo chunk — da Ollama se
   attivo, altrimenti dallo stub. Percorso: React → Tauri → Rust → sidecar →
   Ollama → ritorno in UI.
6. **Controprova offline:** ferma Ollama e ripeti → arriva lo stub in streaming.

### Verticale agente (chat → proposta → esecuzione)

1. Apri un progetto (tab Proxy ▸ Scope) e imposta uno scope che includa un
   target locale, per esempio `127.0.0.1`.
2. Chiedi all'agente qualcosa che porti a un tool del catalogo contro quel
   target (e.g. "scansiona le porte di 127.0.0.1").
3. **Atteso:** arriva una proposta con l'**argv esatto**, il livello di
   intrusività e i privilegi richiesti. Niente parte prima del tuo consenso.
4. Approva → l'output (stdout/stderr/exit/durata) compare nella chat.
5. Ripeti con un target **fuori scope**: la proposta è rifiutata ("not in
   scope"), nessun comando viene eseguito.

## Bundle con il sidecar impacchettato

In sviluppo il ponte Rust usa `python -m elliot_agent`. Per un bundle che non
dipenda da un Python di sistema:

```bash
bash scripts/build-sidecar.sh           # PyInstaller → app/src-tauri/binaries/
npm --prefix app run tauri:build:sidecar  # tauri build + tauri.sidecar.conf.json
```

Lo script produce `app/src-tauri/binaries/elliot-agent-<target-triple>` (il
nome che Tauri si aspetta per un `externalBin`). Il percorso è in `.gitignore`:
va rigenerato su ogni macchina. Senza quel file `tauri build` normale continua a
funzionare (il sidecar non è dichiarato nella config base), ma il bundle non
conterrà l'agente.

## Note

- **CLI Tauri non trovata:** è in `devDependencies`, usa `npm run tauri`.
- **rustls, non OpenSSL:** `pkg-config`/OpenSSL non sono richiesti; in questo
  milestone il lato Rust non fa rete.
- **Python 3.14 + macOS 27** molto recenti: `httpx` è puro Python, basso
  rischio di wheel mancanti.
