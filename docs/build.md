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

Attesi: righe `{"v":2,"type":"chunk", ...}` in streaming, eventualmente una
`{"type":"proposal", ...}` e infine `{"type":"done"}`. Il processo resta vivo
finché stdin è aperto (una richiesta per riga). Se Ollama è spento arriva
comunque una risposta **stub** in streaming (degrado controllato). Con una
domanda che porta a un tool, il trailer `ELLIOT_PROPOSAL {json}` non compare in
nessun `chunk`: diventa un frame `proposal` solo se il catalogo lo valida.

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

## Sniffer passivo e permessi BPF (macOS)

La tab **Sniffer** osserva la scheda di rete con libpcap **senza instradare**
traffico e **senza decifrare**: mostra metadati (IP, porte, protocollo, SNI,
query DNS, dimensioni, tempi). Sul traffico TLS il contenuto resta cifrato e
illeggibile — per il chiaro restano Proxy e Capture. La cattura è live-only: in
v1 non viene scritto nulla nel progetto.

libpcap apre i device `/dev/bpf*`, che su macOS appartengono a root. Senza
permessi `sniff_start` fallisce subito e la UI mostra un banner esplicito, senza
crash e senza toccare proxy/SOCKS:

```
cannot capture on lo0: libpcap error: (cannot open BPF device) /dev/bpf0:
Permission denied (on macOS the BPF devices require privileges: install
ChmodBPF, e.g. with Wireshark, or run Elliot with sudo)
```

Due modi per concedere l'accesso:

1. **ChmodBPF (consigliato).** L'installer di Wireshark include
   `Install ChmodBPF.pkg`: crea il gruppo `access_bpf` e un LaunchDaemon che
   mantiene i permessi anche sui device creati dinamicamente. Se Wireshark è
   già installato ma l'helper non è attivo:

   ```bash
   sudo /Library/Application\ Support/Wireshark/ChmodBPF/ChmodBPF
   ```

   Dopo logout/login l'utente è nel gruppo e non serve `sudo`.

2. **Sessione privilegiata**, per una prova rapida:

   ```bash
   sudo -E bash scripts/dev.sh dev
   ```

   `-E` conserva l'ambiente (PATH di cargo/npm). È una deroga temporanea, non la
   configurazione consigliata per l'uso quotidiano.

Nella toolbar si sceglie l'interfaccia (`lo0` per il traffico locale, `en0` per
la rete) e, se serve, un filtro **BPF** (es. `tcp port 8080`, `udp port 53`).
Un filtro non valido viene rifiutato all'avvio, prima di leggere pacchetti.

### Test live dello Sniffer

Il test live è marcato `#[ignore]` perché apre un device BPF reale e genera
traffico su loopback. Con ChmodBPF attivo:

```bash
cargo test -p elliot-sniff --test live -- --ignored --nocapture
```

Copre cattura su `lo0` (DLT_NULL su macOS), stop e ripresa immediata su una
nuova porta. Senza permessi BPF, o se tutti i device sono occupati, il test si
salta con un messaggio e non fallisce; la suite normale (`cargo test`) lo
ignora comunque.

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

Il **catalogo** viaggia dentro il binario (`--add-data catalog:catalog`): senza
sarebbe un sidecar che non può proporre nulla. Il controllo rapido, con Ollama
spento, deve mostrare i chunk e **non** `catalogo non trovato` su stderr:

```bash
TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
printf '{"v":2,"prompt":"ciao"}\n' \
  | ELLIOT_OLLAMA_URL=http://127.0.0.1:1/api/chat \
    app/src-tauri/binaries/elliot-agent-$TRIPLE
```

PyInstaller gira nel venv di sviluppo. Su Python molto nuovi (3.14 al momento
in cui questo è stato scritto) serve `pyinstaller>=6.22`; se una versione non
fosse supportata, puntare `ELLIOT_PACK_PYTHON` a un interprete supportato senza
toccare il venv di sviluppo:

```bash
ELLIOT_PACK_PYTHON=/path/to/python3.13 bash scripts/build-sidecar.sh
```

Dopo il bundle, il sidecar deve stare accanto all'eseguibile e rispondere al
protocollo:

```bash
ls target/release/bundle/macos/Elliot.app/Contents/MacOS/
printf '{"v":2,"prompt":"ciao"}\n' \
  | ELLIOT_OLLAMA_URL=http://127.0.0.1:1/api/chat \
    target/release/bundle/macos/Elliot.app/Contents/MacOS/elliot-agent
```

Il ponte (`sidecar_command`) preferisce `<dir dell'eseguibile>/elliot-agent`, poi
`python -m elliot_agent` in sviluppo: nel bundle non serve un Python di
sistema.

## Note

- **CLI Tauri non trovata:** è in `devDependencies`, usa `npm run tauri`.
- **rustls, non OpenSSL:** il lato rete (proxy, SOCKS, repeater, intruder) usa
  rustls, quindi non servono `pkg-config` né un'OpenSSL di sistema. Lo store
  SQLCipher compila una copia statica di OpenSSL (vendored) per cifrare il file
  di progetto, anch'essa senza dipendenze di sistema.
- **Python 3.14 + macOS 27** molto recenti: `httpx` è puro Python, basso
  rischio di wheel mancanti. PyInstaller 6.22+ supporta la 3.14 (verificato).
- **Chiave della CA:** l'app usa il keychain quando c'è; in caso contrario il
  file cifrato `ca.key.enc`. Il backend effettivo è mostrato in `CaDialog`
  (comando `proxy_ca_status`).
