# Elliot — registro di progettazione

Documento di riferimento sulle decisioni prese. Ultimo aggiornamento: 2026-10-27.

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

- **core (Rust, senza UI):** `proxy`, `socks` (listener SOCKS5 per traffico
  **non-HTTP**, con scope-gate e MITM TLS opzionale), `scope` (fonte di verità
  unica), `store` (SQLite/SQLCipher), `httpraw` (request raw editabile condivisa
  + modello generico `Stream`/`Message`), `repeater`, `intruder`, `runner`
  (valida+esegue), `catalog` (loader+validazione), `tls` (politica TLS: config
  rustls + verifier permissivo dietro opt-in + CA locale con minting dei leaf
  per-host, condivisa da proxy e socks).
- **app (Tauri):** `src-tauri` (guscio, IPC, agent bridge) + `src` (React, 5
  schermate). Tab Proxy/Capture/Repeater/Intruder/Agent, tutti attivi; staccabili
  in futuro, gratis perché lo stato sta nel core. Capture/Repeater/Intruder/Agent
  restano montati anche quando si cambia tab, così un payload o una chat in corso
  non si perdono.
- **agent (Python):** loop di chat, client Ollama, costruzione della proposta.

## Segreti e chiave della CA

La chiave privata della CA è la capacità di intercettare TLS: non è mai a riposo
in chiaro. `elliot-tls` espone un confine unico, `KeyStore`, con due backend:

- **keychain di sistema** (`keyring`: macOS Keychain, Secret Service su Linux,
  Credential Manager su Windows), voce `service="elliot"`, `account="ca-key"`.
  Lo sceglie il guscio desktop; il certificato **pubblico** resta un file
  (`ca.crt`) accanto, perché l'utente lo installa e non è un segreto.
- **file cifrato** (`ca.key.enc`, XChaCha20-Poly1305 con seed casuale in
  `ca.seed`, entrambi `0600`): il default della libreria, usato dai test,
  dagli esempi e da qualunque chiamante senza sessione desktop. Onesto limite:
  il seed sta sullo stesso disco, quindi difende da copie/backup del file e da
  esposizioni accidentali, non da chi legge già i file dell'utente.

Non c'è un terzo backend in chiaro. Il vecchio `ca.key` PEM viene **importato**
nel backend configurato e **rimosso** al primo avvio; se il keychain non è
disponibile (headless, CI, permesso negato) si degrada al file cifrato con un
warning, mai al plaintext. Una CA il cui certificato esiste ma la cui chiave è
sparita è un errore esplicito: rigenerarla invaliderebbe ogni trust-store
installato.

## Storage e file di progetto

- SQLite embedded; **il file di progetto *è* il database** (un file `.elliot`,
  body come blob interni, autosave transazionale, hand-off = copia del file).
- **Cifratura con passphrase** da subito via SQLCipher: il file contiene
  traffico sensibile (credenziali, token, PII, dati del cliente).
- Versione dello schema salvata nel file per le migrazioni. Stato attuale:
  **v2** — `flows` + `settings` (v1) e `streams` + `messages` (v2, traffico non
  HTTP). Un file v1 viene **migrato all'apertura** in una transazione, senza
  perdita di dati.
- Storico **per progetto**. Niente progetto aperto ⇒ niente scritture: la
  persistenza di flow, stream e messaggi avviene solo dentro il file cifrato.

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
- **Fatto (2026-10-26):** Fase 4 — slice agente cablata end-to-end (Tauri →
  sidecar → stream → UI), insieme allo scaffolding dei comandi lato app.
- **Fatto (2026-10-26):** modulo **proxy** — crate `elliot-proxy`
  (`core/proxy/`, ~1560 righe) su `hudsucker` + `rustls` + `rcgen`, con il tipo
  condiviso `Flow` in `elliot-httpraw`. Rispetto a
  [`docs/plans/proxy.md`](plans/proxy.md): **Fase A** (cattura passiva + MITM
  TLS — `engine.rs`, `handler.rs`, `convert.rs`, CA locale in `tls/ca.rs` con
  export del solo certificato pubblico via `ca_pem()`, guardia open-proxy che
  rifiuta i bind non-loopback) e **Fase B** (intercept — `intercept.rs`,
  `set_intercept`/`decide`) implementate; `AllowAll` come decider finché
  `elliot-scope` non è pronto. Esempio `examples/run.rs` + smoke test
  `tests/smoke.rs`.
- **Fatto (2026-10-26):** proxy Fasi **C** e **D**. Fase C (HTTP/2): feature
  `http2` di hudsucker attiva e `HttpVersion::from_http` mappa `HTTP_2 → H2`
  nel `Flow` (cattura h2 trasparente; il `raw` ricostruito usa comunque la
  start-line 1.1, h2 non ne ha una testuale — best-effort documentato). Fase D
  (WebSocket): nuovo `websocket.rs` con un `WebSocketHandler` **observe-only**
  (inoltra i frame intatti) che emette `ProxyEvent::WebSocket(WsMessage)` per i
  messaggi su connessioni in-scope; tipi `WsMessage`/`WsDirection`/`WsKind` in
  `elliot-httpraw`; scope ri-controllato lato WS (fuori scope = non catturato;
  il `wss` fuori scope è già tunnelato senza MITM). L'editing/intercept dei
  frame WS e lo stitching al flow di upgrade restano follow-up. Verifica:
  `cargo test` (mappatura h2 + classify/scope WS) e `clippy -D warnings` verdi
  sull'intero workspace; esempio `run` e glue Tauri estesi al nuovo evento.
- **Fatto (2026-10-26):** UI della schermata **Proxy** — `app/src/proxy/`
  (`ProxyScreen`, `FlowTable`, `MessageViewer`, `InterceptView`, `CaDialog`,
  filtri, hook `useProxy`, `backend.ts`) + comando Tauri
  `app/src-tauri/src/proxy.rs` e `.claude/launch.json` per l'avvio.
- **Fatto (2026-10-26):** crate **`elliot-scope`** — il motore di policy, fonte
  di verità unica. `ScopePolicy { include, exclude }` di `Rule` (matcher per
  scheme/host/porta/path), serializzabile (vivrà nel file di progetto).
  Valutazione: nessuna include → `InScope` (**default: si cattura tutto**, come
  un proxy di cattura appena avviato — la lista include *restringe*, non accende);
  match su exclude → `Passthrough` (escluso esplicito, l'unica regola che vale
  anche senza include); match su include → `InScope`; include presente ma nessun
  match → `OutOfScope`.
  Host per **esatto** o **suffisso di dominio** (`.example.com` ⇒ apex +
  sottodomini), case-insensitive; **niente regex** di proposito (coerente con la
  safe-by-construction del catalogo: nessun pattern ReDoS — deviazione
  consapevole dalla riga "host/port/path/regex" di `core/README.md`, estendibile
  dietro lo stesso enum se servirà). Il trait `ScopeDecider` è stato **spostato
  in `elliot-httpraw`** (contratto condiviso) e ri-esportato da `elliot-proxy`:
  così `elliot-scope` lo implementa senza dipendere dal proxy, e proxy/repeater/
  intruder dipendono solo dal trait. 9 unit test (match, include/exclude,
  default, case-insensitive, round-trip JSON, trait object); `clippy -D warnings`
  verde su tutto il workspace.
- **Fatto (2026-10-26):** gli ultimi crate core stub, ora implementati e testati
  (`cargo test --workspace` + `clippy -D warnings` verdi):
  - **`elliot-store`** — file di progetto SQLite **cifrato con SQLCipher**
    (passphrase, come deciso). `rusqlite` con feature
    `bundled-sqlcipher-vendored-openssl`: cifratura reale a riposo e build
    self-contained (OpenSSL vendored staticamente, niente OpenSSL di sistema né
    pkg-config — il principio "niente OpenSSL" valeva per il lato rete, qui è
    una copia statica di build). Schema v1 (`PRAGMA user_version`), tabella
    `flows` con i campi interrogabili + body/raw come BLOB, header come blob
    binario length-prefixed (i valori sono byte arbitrari, non UTF-8);
    `create`/`open` (passphrase errata → errore),
    `upsert_flow`/`upsert_flows`/`get_flow`/`list_flows`/`count_flows`.
    Migrazioni oltre la v1 = follow-up.
  - **`elliot-repeater`** — client **raw** TCP/TLS: invia i byte della request
    **verbatim** (nessuna normalizzazione — è il punto del repeater), parsa la
    response best-effort nel tipo condiviso ma conserva sempre i byte grezzi.
    TLS via `elliot-tls` (rustls, provider aws-lc-rs, niente OpenSSL);
    `accept_invalid_certs` opt-in. Framing derivato parsando gli header **una
    volta** con `httparse` (Transfer-Encoding ha la precedenza su
    Content-Length) e decoder chunked reale (estensioni, trailer, chunk
    finale), sotto timeout. Lo scope **non** è controllato qui: il gate è del
    chiamante.
  - **`elliot-catalog`** — modello tipizzato + loader YAML + validazione che
    rispecchia `catalog/schema/tool-entry.schema.yaml` (deny_unknown_fields,
    `scope_checked` sempre true, string→pattern, path→confined_to+access,
    enum→values, pattern di id/flag). Test: la voce golden `nmap.yaml` carica e
    valida. Espone `load_standard()` (voci standard impacchettate con
    `include_str!`) e `load_file()` (voci `custom`), più un test anti-drift che
    confronta i `required` di primo livello dello schema con i campi
    obbligatori del modello Rust. Era anch'esso stub ed è dipendenza necessaria
    del runner.
  - **`elliot-runner`** — la **frontiera di fiducia in esecuzione**: valida una
    proposta approvata contro la voce di catalogo (allow-list dei flag, vincoli
    di tipo, regex sui valori string, confinamento dei path nel project dir) e
    contro lo scope (ogni target deve essere `InScope`), calcola l'intrusività
    effettiva = max(tool, flag), rifiuta `dangerous` senza sblocco manuale,
    verifica il binario e **costruisce l'argv** (mai shell); `execute` lancia il
    processo con timeout e cattura stdout/stderr.
  - **`elliot-intruder`** — attacchi multi-punto: injection point (range di byte
    nella request base), payload set **come byte** (`Payload = Vec<u8>`, così i
    fuzz case non-UTF8 passano), modi **Sniper/BatteringRam/Pitchfork/
    ClusterBomb**, espansione dei job, invio concorrente **bounded** (uno stream
    che tira un job solo quando un posto si libera, non uno `spawn` per job) via
    repeater con metriche per richiesta; **scope controllato una volta prima di
    inviare** (fuori scope ⇒ non parte nulla). Limite noto: `plan()`
    materializza ancora l'intera espansione, quindi un cluster bomb enorme è
    grande in memoria.
- **Fatto (2026-10-26):** refactoring dei crate core, a comportamento
  osservabile invariato (48 → 79 test, tutti verdi):
  - **`elliot-httpraw`** — nuovo modulo `net` con l'unica implementazione di
    `split_host_port` e del "locus" passato allo scope (il runner e il proxy ne
    avevano tre copie divergenti, con default port e IPv6 diversi);
    `AllowAll`/`DenyAll` accanto al trait `ScopeDecider`; token canonici sugli
    enum (`as_str`/`as_token`/`from_token`) con un test che li congela, perché
    sono il formato su disco dello store.
  - **`elliot-tls`** — nuovo crate: `ClientConfig` rustls (webpki roots) e
    `insecure_client_config()` dietro opt-in esplicito. Il repeater lo usa e
    perde il proprio `tls.rs`; il proxy lo usa per `verify_upstream=false`.
  - **`elliot-proxy`** — `verify_upstream=false` **ora implementato davvero**
    (era accettato e ignorato): connector `hyper-rustls` sulla config
    permissiva, applicato anche al client WebSocket. Coperto da un test
    end-to-end su loopback con upstream self-signed.
  - **`elliot-runner`** — `validate` spezzato in helper puri
    (`check_tool_match`/`validate_flags`/`validate_targets`/`build_argv`); il
    confinamento dei path canonicalizza la radice del progetto e risolve il più
    profondo antenato esistente, quindi **scopre i symlink** che escono (limite
    TOCTOU residuo documentato); il PATH lookup vive nel modulo privato `which`.
  - **`elliot-store`** — `upsert_flows` batch in **una** transazione (il proxy
    scriverà a raffica: un fsync per burst, non per flow); header in blob
    binario compatto con decoder stretto (input troncato → errore, mai panic).
    Il formato su disco cambia qui (nessun file reale esisteva); le dipendenze
    `serde`/`serde_json` dello store sono state rimosse.
  - **Decisione aperta R10a — il repeater non ha scope-gate.** Scelta esplicita:
    il gate resta al chiamante (l'intruder lo fa prima di inviare), documentato
    nel crate. Se in futuro il repeater accettasse target dall'esterno, andrebbe
    aggiunto un `Option<&dyn ScopeDecider>` a `send`.
- **Fatto (2026-10-26):** **scope collegato al guscio Tauri.** In `elliot-scope`
  `SharedPolicy` tiene la policy dietro lock e la rilegge a **ogni** decisione:
  il proxy la riceve una volta e una modifica fatta nella UI vale dalla
  richiesta successiva, senza riavvio. La policy vive nel **file di progetto**:
  lo store espone una tabella `settings` (chiave + valore byte opachi) e l'app
  la serializza lì sotto la chiave `scope_policy`. Comandi Tauri:
  `project_create`/`project_open`/`project_close`/`project_status` (passphrase,
  SQLCipher) e `scope_get`/`scope_set`. Senza progetto aperto le modifiche
  restano di sessione, e la UI lo dichiara. `Store::create` ora **rifiuta
davvero** un file esistente: prima lo documentava soltanto e SQLite lo avrebbe
  aperto in place, mescolando due progetti. UI: sub-tab **Scope** nella
  schermata Proxy, con file di progetto e liste include/exclude (scheme, host
  esatto o dominio+sottodomini, porta, prefisso di path); con lista include
  vuota il badge mostra `all`, perché la policy vuota **cattura tutto**. Verificato
  da un test end-to-end sul proxy reale: policy vuota ⇒ catturata; ristretta a un
  altro host ⇒ la richiesta passa ma non viene catturata; azzerata ⇒ catturata di
  nuovo — sempre sullo stesso processo.
- **Fatto (2026-10-27):** **intercettazione generica non-HTTP** (piano
  `docs/plans/non-http-intercept.md`, fasi G1–G9 senza le estensioni opzionali
  G-DISS/G-FILT/G-SESS, rimandate per scelta esplicita):
  - **`elliot-httpraw`** — modello trasporto-agnostico: `Transport` (tcp/udp),
    `Direction` (c2s/s2c), `Stream` (connessione/associazione catturata, con
    host/porta/tls/scope/stato) e `Message` (un blocco TCP o un datagramma, byte
    grezzi). Token canonici anche per `Transport`/`Direction` (formato su disco
    congelato da un test) e round-trip JSON testato: è il contratto con
    listener, store e UI.
  - **nuovo crate `elliot-socks`** — listener SOCKS5 **solo loopback** (come il
    proxy: bind non-loopback rifiutato) che implementa a mano CONNECT e UDP
    ASSOCIATE (RFC 1928) più l'autenticazione user/password opzionale (RFC 1929,
    confronto a tempo costante), perché è il modo in cui `curl`,
    `proxychains` o l'OS instradano traffico arbitrario. Il **gate di scope
    decide la cattura, non la raggiungibilità**: fuori scope (o escluso) il
    relay è trasparente — nessun evento, nessuna decifratura, niente
    persistenza; in scope si emettono `StreamStarted`/`Message`/
    `StreamCompleted`. **MITM TLS opzionale**: si sbircia il primo record con
    `peek` (senza consumarlo) e, se è un ClientHello, si terminano due TLS
    (leaf per-host firmato dalla CA condivisa + TLS verso l'upstream) e si
    cattura il **chiaro applicativo**; qualunque altro primo byte viene
    relayato opaco. **UDP**: relay su `127.0.0.1`, scope-check per datagramma,
    risposte accettate solo dagli indirizzi a cui si è già inviato (mai
    forwardare datagrammi non sollecitati), fragment droppati, correlazione
    best-effort documentata. Stop cooperativo: i relay in corso vedono il
    segnale e **chiudono lo stream** (nessuno stream resta pendente).
    24 test (parsing su vettori di byte, cattura TCP nei due versi, tunnel
    fuori scope, MITM in chiaro vs opaco, UDP, credenziali, guardie).
  - **CA spostata in `elliot-tls`** (`Ca::load_or_create`, `cert_pem`,
    `into_issuer` invariati + `leaf_for_host` che minta un leaf per host/IP con
    SAN corretto, e `server_config_with_leaf`). Il proxy HTTP usa
    `elliot_tls::Ca` senza cambi di API pubblica (i suoi test restano verdi);
    la CA è una sola, quindi l'utente installa un solo certificato. Il test
    della CA fa un handshake TLS vero contro un client che si fida **solo**
    della CA locale.
  - **`elliot-repeater`** — `RepeatRequest` guadagna `transport` e `read_mode`,
    con default `Tcp`+`Http` (comportamento HTTP **invariato**, coperto da un
    test di regressione): i nuovi modi sono `UntilIdle(ms)` (prima lettura sotto
    il timeout complessivo, poi stop dopo il silenzio), `Exact(n)` (con cap di
    16 MiB e risposta parziale se il peer chiude), `UntilClose` e `Datagram`
    (UDP: un datagramma out, uno in, socket nella famiglia giusta). Modo e
    trasporto incoerenti sono rifiutati **prima** di aprire un socket; TLS su
    UDP è un errore esplicito (niente DTLS).
  - **`elliot-intruder`** — eredita `transport`/`read_mode` dal repeater; lo
    scheme passato allo scope segue il trasporto (`udp`/`https`/`http`); nuova
    `run_streaming` che consegna **ogni risultato appena completa** (la UI lo
    mostra mentre l'attacco gira), con `run` che resta il wrapper che raccoglie
    e ordina.
  - **`elliot-store` schema v2** — tabelle `streams` e `messages` (+ indici),
    `upsert_stream`/`append_message`/`append_messages` (batch transazionale),
    `get_stream`/`list_streams`/`messages_for`/`count_streams`; apertura di un
    file **v1 migrata a v2** in transazione, verificata da un test che conserva
    flow e impostazioni esistenti.
  - **guscio Tauri** — `socks_start`/`socks_stop` (CA nella stessa `ca_dir` del
    proxy, policy di scope live), pump `socks://stream` con **persistenza**
    degli stream e dei messaggi nel progetto aperto, `repeater_send`,
    `intruder_run` (con eventi `intruder://result`), `send_to_repeater`/
    `send_to_intruder` dalle byte del messaggio + target dello stream, e
    `capture_list`/`capture_messages` per ricaricare la storia. Colmato anche
    il gap di persistenza dei **flow HTTP**: il pump del proxy ora scrive i flow
    nel progetto aperto. Argomenti validati per token (un token sconosciuto è un
    errore, mai un fallback silenzioso) e test unitari sul mapping.
  - **UI React** — nuova schermata **Capture** (liste stream/messaggi, viewer
    hex/testo, filtro di scope già esistente) e tab **Repeater** e **Intruder**
    funzionanti: editor byte in modalità testo/hex, parametri di target e read
    mode, invio e vista risposta (Pretty/Raw/Hex/Headers per l'HTTP); base +
    injection point a byte (dalla selezione o a offset), payload set (uno per
    posizione per Pitchfork/Cluster bomb), modi, tabella risultati in streaming.
    "Send to Repeater/Intruder" ora funziona sia dal capture non-HTTP sia dalla
    storia HTTP (che costruisce l'argomento in locale), e le schermate restano
    montate per non perdere un payload in editing.
- **Fatto (2026-10-27):** chiusura delle lacune del piano
  [`chiusura-lacune.md`](plans/chiusura-lacune.md) — **A** intercept
  WebSocket: `WsDecision` + `WsRegistry` in `intercept.rs` (registro dedicato,
  non un `Registry<T>` generico), pausa in `WsHandler::handle_message` quando
  l'intercept è attivo (lo **stesso** toggle dell'HTTP), ricostruzione del frame
  dello stesso kind per `ForwardEdited` (un edit non-UTF-8 su un frame Text viene
  rifiutato e l'originale passa), `Drop` = `None` sulla rete. I frame di
  controllo Ping/Pong/Close non si intercettano mai. Fuori scope non si pausa
  nulla. `EngineHandle::decide_ws`, `ProxyHandle::decide_ws`, `WsDecision`
  riesportato; comando Tauri `proxy_ws_decide` e coda WS nella UI di Intercept
  (editor del payload, Forward/edited/Drop, stesso ⌘↵ ma sul frame). Il messaggio
  in pausa viaggia come `WsMessage { paused: true }` (D2), non come variante di
  evento nuova.
- **Fatto (2026-10-27):** **B** chiave CA a riposo (dettagli in “Segreti e
  chiave della CA”): `KeyStore::{Keychain, EncryptedFile}` con `ca.key.enc`
  XChaCha20-Poly1305, migrazione dal `ca.key` in chiaro, fallback automatico
  quando il keychain non c'è. Il guscio passa `KeyStore::Keychain` sia al proxy
  sia al SOCKS (una CA, un key, due listener); test, esempi e default della
  libreria restano su `EncryptedFile`, così la suite non tocca il keychain di
  chi sviluppa. Verificato: nessun `ca.key` in chiaro dopo l'avvio, handshake
  reale ancora verde, ramo di fallback esercitato con un keychain forzato a
  fallire, `TODO(hardening)` rimosso.
- **Fatto (2026-10-27):** **C** prima verticale dell'agente end-to-end:
  chat → proposta → validazione → approvazione umana → esecuzione → output.
  Sidecar **persistente** (`agent/elliot_agent/__main__.py`, una richiesta per
  riga finché stdin è aperto) con protocollo versionato (`v: 1`), catalogo reale
  come grounding (`catalog.py`) e validazione pre-invio della proposta (tool,
  flag, valori, cardinalità: un tool fuori catalogo non lascia mai il processo).
  Ponte Rust `app/src-tauri/src/agent.rs`: avvio pigro del sidecar (binario
  accanto all'eseguibile, altrimenti `python -m elliot_agent`), NDJSON su
  stdin/stdout, eventi `agent://chunk|done|error|proposal|execution|exit`,
  proposta validata con `runner::validate` contro catalogo + scope live +
  `project_dir` del progetto aperto (senza progetto: rifiuto, nessuna
  esecuzione). `agent_execute` **rivalida** e esegue via argv (timeout dal
  catalogo), quindi un round-trip UI non è mai una prova. UI `app/src/agent/`:
  chat in streaming e scheda proposta con argv esatto, intrusività e privilegi;
  le conferme crescono col rischio (`intrusive` richiede una spunta, `dangerous`
  è bloccato finché l'utente non sblocca esplicitamente, coerente con
  `RunnerError::DangerousBlocked`). Test: 13 Python (senza rete, modello finto),
  ponte provato con un sidecar finto e con il sidecar reale, rifiuto fuori scope
  verificato.
- **Fatto (2026-10-27):** packaging del sidecar: `scripts/build-sidecar.sh`
  (PyInstaller, output `app/src-tauri/binaries/elliot-agent-<target-triple>`) e
  overlay `app/src-tauri/tauri.sidecar.conf.json` (`bundle.externalBin`), usato
  da `npm run tauri:build:sidecar`. La config base resta senza `externalBin`, così
  `cargo build`/`tauri build` continuano a funzionare su una macchina senza il
  binario generato.
- **Prossimo:** contesto curato selettivo (C7: flow/cattura scelti, non l'intera
  sessione), rotazione/revoca della CA, e le estensioni rimandate del piano
  non-HTTP (dissector, DSL di filtro, session-replay).

## Non ancora deciso

- Formato e DSL dei filtri del proxy.
- Estensioni rimandate del piano non-HTTP: **G-DISS** (dissector: quali
  protocolli come primi esempi), **G-FILT** (DSL di filtro in Rust condivisa
  UI/store), **G-SESS** (session-replay per protocolli stateful). Scelte già
  prese e da ricordare: `SchemeMatch` **non** è stato esteso a tcp/udp (basta
  `Any`: sul path SOCKS si passa `scheme="tcp"|"udp"`), e il SOCKS resta un
  listener **separato** dal proxy HTTP.
- Modalità "raw" manuale per l'utente esperto (valvola di sfogo fuori allow-list,
  con conferma, non disponibile all'agente).
