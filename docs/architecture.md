# Elliot — registro di progettazione

Documento di riferimento sulle decisioni prese. Ultimo aggiornamento: 2026-10-18.

## Visione

Proxy desktop single-user per security testing **autorizzato** (VA/PT), nello
spirito di Burp Suite:

- analisi del traffico web (stile Wireshark ma con request **e** response);
- attacchi automatizzati multi-punto;
- malformazione ed editing raw delle request (repeater);
- lavoro vincolato a uno **scope**;
- un **agente AI locale** che, da una descrizione in linguaggio naturale,
  *propone* tool e flag, con grounding su un catalogo accessibile all'utente.

## Stack (deciso)

| ambito | scelta | note |
|---|---|---|
| Core + guscio desktop | Rust + Tauri | il backend di Tauri è Rust → un solo linguaggio per core e app |
| Frontend | TypeScript + React | dentro Tauri |
| Agente | Python (sidecar) | chiama Ollama locale |
| Inferenza | Ollama off-the-shelf | nessun motore scritto da noi |
| Storage | SQLite + SQLCipher | un unico file di progetto portabile e cifrato |

Perché Rust e non C: il core parsa input ostile/malformato (è il mestiere di un
proxy), dominio in cui la memory safety conta di più; Rust dà prestazioni a
livello C senza rinunciarvi, e si incastra con Tauri.

## Frontiera di fiducia

L'agente Python **propone soltanto** una tool call strutturata (id tool + array
di argomenti). Il core Rust **valida** la proposta contro lo schema del catalogo
e il motore di scope, poi **esegue** (via argv, mai shell, sandboxato).
Esecuzione e scope vivono in Rust, dietro un'unica frontiera. Motivo: l'output
dei target entra nel contesto dell'agente e potrebbe contenere istruzioni
iniettate; un agente manipolato può comunque solo emettere una proposta, che
resta ingabbiata da schema + scope + conferma umana.

## Moduli

Vedi [../core/README.md](../core/README.md), [../app/README.md](../app/README.md),
[../agent/README.md](../agent/README.md). In sintesi:

- **core (Rust, senza UI):** `proxy`, `scope` (fonte di verità unica), `store`
  (SQLite/SQLCipher), `httpraw` (request raw editabile condivisa), `repeater`,
  `intruder`, `runner` (valida+esegue), `catalog` (loader+validazione).
- **app (Tauri):** `src-tauri` (guscio, IPC, agent bridge) + `src` (React, 4
  schermate). Tab Proxy/Repeater/Intruder/Agente; staccabili in futuro, gratis
  perché lo stato sta nel core.
- **agent (Python):** loop di chat, client Ollama, costruzione della proposta.

## Storage e file di progetto

- SQLite embedded; **il file di progetto *è* il database** (un file `.elliot`,
  body come blob interni, autosave transazionale, hand-off = copia del file).
- **Cifratura con passphrase** da subito via SQLCipher: il file contiene
  traffico sensibile (credenziali, token, PII, dati del cliente).
- Versione dello schema salvata nel file per le migrazioni.
- Storico **per progetto**.

## Catalogo tool

Contratto condiviso fra agente (grounding), runner (validazione) e utente
(estensione). Dettaglio in [../catalog/README.md](../catalog/README.md).

- Popolamento: l'utente sceglie da una **lista curata di voci pre-vagliate**
  (`source: standard`), non autogenerate. `--help`/man page solo come aiuto alla
  stesura, sempre con revisione umana. Voci `custom` per tool fuori lista.
- Due artefatti: **lo schema** (contratto validato da Rust e Python) e una
  **voce di riferimento** (`nmap`).
- **Safe-by-construction:** la scelta sicura è l'unica valida (string → serve
  `pattern`; path → serve `confined_to`+`access`; enum → serve `values`;
  `base_intrusiveness` obbligatorio; `scope_checked` sempre true; nessun campo
  raw-args). Garantisce la struttura, non il giudizio (le voci standard restano
  revisionate a mano).
- Default decisi: formato **YAML**; `requires`/`conflicts` tra flag rimandati;
  binario **rilevato + install guidata con conferma** (non silenziosa); catalogo
  standard **impacchettato con l'app** (feed firmato più avanti).
- Livelli di intrusività: `passive` / `low` / `intrusive` / `dangerous`.
  Effettivo = max(tool, flag usati) → guida la conferma umana obbligatoria.

## Stato

- **Fatto:** catalogo — schema `catalog/schema/tool-entry.schema.yaml`, voce di
  riferimento `catalog/standard/nmap.yaml`, README. Validato in positivo e in
  negativo (lo schema rifiuta le costruzioni insicure).
- **Fatto:** scheletro del repo (questo albero di cartelle + README dei moduli).
- **Fatto (2026-10-18):** Fase 0 del build tooling — toolchain installati e
  verificati: Rust 1.99.1 (rustup, stable aarch64), Node 26.10 / npm 12.1,
  Python 3.14.7 (venv + `httpx` 0.28 ok), Xcode CLT (clang 21, SDK macOS),
  Ollama 0.40.4 con `llama3.2:1b` (streaming `/api/chat` ok). Risoluzione
  dipendenze controllata: `tauri` 2.12.4 / `tauri-build` 2.7.3 ↔
  `@tauri-apps/cli` 2.12.3 / `@tauri-apps/api` 2.12.4; Vite 8 +
  `@vitejs/plugin-react` 6; React 18.3; TypeScript 5.9.
- **Fatto (2026-10-18):** Fase 1 — workspace Cargo alla root (`Cargo.toml`,
  resolver 2, dipendenze condivise) + 8 crate core stub (`elliot-proxy`,
  `-scope`, `-store`, `-httpraw`, `-repeater`, `-intruder`, `-runner`,
  `-catalog`), ciascuno con `Cargo.toml` + `src/lib.rs`. `.gitkeep` rimossi.
  `cargo build` verde dalla root.
- **Fatto (2026-10-18):** Fase 2 — app Tauri 2 + frontend Vite/React/TS.
  Frontend in `app/` (`package.json`, `vite.config.ts`, `tsconfig.json`,
  `index.html`, `src/main.tsx`, `src/App.tsx` placeholder); shell Rust in
  `app/src-tauri/` (`Cargo.toml`, `build.rs`, `main.rs`, `lib.rs`,
  `tauri.conf.json`, `capabilities/default.json`); icone generate con
  `tauri icon`; `app/src-tauri` aggiunto ai members del workspace.
  `npm install` + `npm run tauri dev` → build Rust completata (~58s), app
  avviata, Vite su :1420 HTTP 200.
- **Fatto (2026-10-18):** refactoring di robustezza/sicurezza sullo scaffolding
  Fasi 1–2. Workspace: lint condivisi ereditati da tutti i crate
  (`unsafe_code = "deny"`, `clippy::all` warn) + profilo `release` ottimizzato
  (`lto`, `codegen-units=1`, `strip`; panic unwind mantenuto). Tauri: CSP
  restrittiva al posto di `csp: null` (`default-src 'self'`, `object-src
  'none'`, `base-uri`, `frame-ancestors 'none'`; script/style/connect
  permissivi quel tanto che basta all'HMR dev — **da stringere per i build di
  produzione**, dove il preamble di react-refresh non c'è). Frontend: mount
  React con guardia su `#root` mancante e import nominale di `StrictMode`.
  Verificato: `cargo build` + clippy puliti, `tsc --noEmit` ok, `tauri dev`
  riparte e React monta senza errori console.
- **Fatto (2026-10-18):** Fase 3 — sidecar Python. Pacchetto
  `agent/elliot_agent/` (`__init__.py`, `ollama_client.py` con streaming
  `/api/chat` + fallback stub, `__main__.py` protocollo NDJSON su
  stdin/stdout); `agent/requirements.txt` (`httpx>=0.27`); venv di sviluppo
  `agent/.venv` (httpx 0.28.1). Verifica: `echo '{"prompt":"ciao"}' | python -m
  elliot_agent` → chunk NDJSON in streaming + `{"type":"done"}`, sia dal
  modello reale (Ollama su :11434 raggiungibile, `llama3.2:1b`) sia dallo stub
  (controprova offline forzando l'URL su porta morta). La frontiera di fiducia
  resta: il sidecar emette solo testo, non esegue nulla.
- **Fatto (2026-10-18):** Fase 5 — ergonomia + documentazione. `.gitignore`
  esteso (`target/`, `node_modules/`, `app/dist/`, `agent/.venv/`,
  `__pycache__/`, `*.db`); `scripts/dev.sh` con sottocomandi `agent:setup`
  (venv + requirements) e `dev` (`tauri dev`), root risolta relativa allo
  script; `docs/build.md` (prerequisiti, setup sidecar, avvio, verifica
  end-to-end). Smoke test del dispatch dello script ok.
- **Fatto (2026-10-18):** refactoring di robustezza/performance/sicurezza sul
  sidecar (Fase 3) e su `scripts/dev.sh` (Fase 5). `ollama_client`: costanti
  estratte (URL/modello/timeout/stub), override `ELLIOT_OLLAMA_URL`, eccezioni
  ristrette a `httpx.HTTPError`, parsing JSON una volta per riga (niente doppio
  parse), righe non-JSON a metà stream saltate invece di far ripartire lo stub,
  fallback stub solo se nessun output è stato ancora prodotto, diagnostica su
  stderr (stdout riservato al protocollo). `__main__`: richieste JSON
  malformate o non-oggetto → frame `error` + `done` invece di traceback;
  `BrokenPipeError` (consumatore sparito) gestito con uscita pulita; `_emit`
  DRY; default del modello a sorgente unica. `dev.sh`: `usage()` da heredoc
  invece di `sed` sul proprio sorgente. Verificato: path reale + stub (via env)
  + input malformati/non-oggetto/vuoti + consumatore che molla a metà;
  `py_compile` ok.
- **Prossimo:** Fase 4 — cablare la slice (Tauri → sidecar → stream → UI).

## Non ancora deciso

- Topologia esatta Rust↔Python del sidecar (stdin/stdout vs socket locale).
- Formato e DSL dei filtri del proxy.
- Modalità "raw" manuale per l'utente esperto (valvola di sfogo fuori allow-list,
  con conferma, non disponibile all'agente).
