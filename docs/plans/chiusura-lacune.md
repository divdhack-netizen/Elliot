# Piano — chiusura delle lacune note

Piano autosufficiente per chiudere le tre lacune rimaste dopo l'integrazione
non-HTTP, ed eventualmente dichiarare "finita" la parte proxy/cattura + la prima
verticale dell'agente. Pensato per essere eseguito da una chat separata: cita
simboli reali del codice attuale e non dà per scontato nulla del contesto.

Stile e vincoli come gli altri piani in `docs/plans/`: ogni fase ha file, API
concrete e una verifica propria; nessuna fase deve lasciare il workspace non
compilante.

---

## 1. Contesto e stato attuale

- **Repo**: workspace Cargo in radice; app Tauri 2 in `app/src-tauri` (Rust) +
  `app/src` (React/TS); sidecar Python in `agent/`. Branch di lavoro:
  `feat/proxy-module`.
- **Comandi**: `cargo build --workspace`, `cargo test --workspace`,
  `cargo clippy --workspace --all-targets` (deve restare a zero warning);
  frontend `npm --prefix app run build`.
- **Principi non negoziabili**: bind solo loopback; gate di scope prima di ogni
  cattura/MITM (fuori scope = passthrough trasparente, niente decrittazione né
  persistenza); chiave privata della CA mai esportata (solo il certificato
  pubblico); `#![deny(unsafe_code)]`; esecuzione tool via argv, mai shell;
  confinamento dei path a `project_dir`.

Le tre lacune, con il punto esatto del codice da cui partire:

| # | Lacuna | Dov'è oggi | Cosa manca |
|---|---|---|---|
| A | WebSocket **observe-only** | `core/proxy/src/websocket.rs`: `WsHandler::handle_message` ritorna sempre `Some(message)` invariato | Pausa + decisione (forward / edita / drop) sul frame WS, sul modello dell'intercept HTTP |
| B | Chiave CA **in chiaro a riposo** | `core/tls/src/ca.rs`: `write_secret` scrive `ca.key` PEM `0600` in `app_data/ca` (globale, non per-progetto) — vedi TODO a `ca.rs:14` | Cifratura a riposo / OS keychain, senza rompere il flusso "una CA, due listener" |
| C | **Slice agent non cablata** | Esistono il sidecar `agent/elliot_agent` (one-shot) e i crate `runner`/`catalog` completi; nessun ponte Tauri; tab "agent" disabilitata in `app/src/App.tsx:14` | Sidecar persistente con proposte, ponte Rust, pipeline validazione→approvazione→esecuzione, UI |

Il modello dell'intercept HTTP da **specchiare** per la traccia A (già in
`core/proxy/src`):

- `intercept.rs`: `Registry` = `HashMap<Uuid, oneshot::Sender<InterceptDecision>>`;
  `register(id) -> Receiver`, `resolve(id, decision)`. `InterceptDecision` =
  `Forward | ForwardEdited(Vec<u8>) | Drop`.
- `handler.rs::intercept`: setta `FlowState::Paused`, emette `FlowUpdated`,
  `rx.await`, poi agisce sulla decisione (default `Forward` se il canale cade).
- `engine.rs`: `EngineHandle::decide(flow_id, decision)` → `registry.resolve`.
  Il `WsHandler` è costruito a `engine.rs:51` e condivide `events`+`scope` con
  l'`Handler` HTTP; va wired con `.with_websocket_handler(...)` in entrambi i
  rami (verify on/off).
- `app/src-tauri/src/proxy.rs`: comando `proxy_intercept_decide` + evento
  `proxy://flow` (`FlowEvent{kind, flow, ws, error}`), già con un ramo
  `ProxyEvent::WebSocket(m)` (`kind:"ws"`).

Per la traccia C, i simboli già pronti lato Rust:

- `catalog`: `load_standard() -> Vec<ToolEntry>`, `ToolEntry::flag(name)`,
  `Intrusiveness` (ordinato), `Privilege`.
- `runner`: `validate(entry, proposal, scope, config) -> Result<ValidatedCommand, RunnerError>`;
  `Proposal{tool_id, flags: Vec<FlagArg>, targets}`,
  `FlagArg::{switch,valued}`, `RunnerConfig{project_dir, allow_dangerous}`,
  `ValidatedCommand{program, argv, effective_intrusiveness, required_privileges}`,
  `Output`, ed `execute(...)` (argv, no shell, timeout). `RunnerError` ha una
  variante per ogni rifiuto (fuori scope, flag sconosciuta, path che evade,
  `DangerousBlocked`, binario assente, …).
- `agent/elliot_agent/__main__.py`: oggi protocollo **NDJSON one-shot** su
  stdin/stdout — legge `{prompt, model}`, emette `{type:"chunk"|"done"|"error"}`.
  `ollama_client.stream_reply(prompt, model)`. Non c'è loop di chat, non legge il
  catalogo, non emette proposte. Packaging come binario sidecar Tauri **non
  ancora impostato** (dichiarato in `agent/README.md`).

---

## 2. Obiettivo

Chiudere A e B dentro la parte proxy/cattura, e portare C fino a una prima
verticale **end-to-end** (l'agente propone un comando dal catalogo, l'umano
approva, il runner esegue, l'output torna in UI), restando dentro i principi di
§1. Le tre tracce sono indipendenti: si possono eseguire e committare in
qualunque ordine. C è di gran lunga la più grande ed è tenuta autonoma.

---

## 3. Traccia A — intercept WebSocket

Obiettivo: su connessione **in scope**, poter mettere in pausa un frame WS,
inoltrarlo invariato, sostituirne il payload, o scartarlo — come per l'HTTP.
Fuori scope resta tunnel trasparente (non arriva nemmeno all'handler). Osservare
resta il comportamento quando l'intercept è spento.

### A1 — tipo decisione e registry WS (`core/proxy/src/intercept.rs`)
- Aggiungi `WsDecision { Forward, ForwardEdited(Vec<u8>), Drop }` (il payload
  sostituito è bytes: vale per Text e Binary).
- Aggiungi un `WsRegistry` gemello di `Registry`, keyed sull'`id: Uuid` di
  `WsMessage`. In alternativa generalizza `Registry<T>`; valuta il costo contro
  la chiarezza (vedi §6 D1).
- **Verifica**: unit test `register`/`resolve` come per l'HTTP.

### A2 — pausa nell'handler WS (`core/proxy/src/websocket.rs`)
- `WsHandler` prende `intercept_on: Arc<AtomicBool>` e `registry: WsRegistry`
  (clonati in `engine.rs` dallo stesso `intercept_on` dell'HTTP, così un unico
  toggle governa entrambi).
- In `handle_message`, dopo `observe(...)` e solo se `intercept_on`:
  emetti l'evento di pausa (riusa `ProxyEvent::WebSocket` con un `WsMessage` il
  cui stato segnala "paused", oppure aggiungi `ProxyEvent::WebSocketPaused` — vedi
  §6 D2), registra `id`, `await` la decisione. Poi:
  - `Forward` → `Some(message)`;
  - `ForwardEdited(bytes)` → ricostruisci il `Message` **dello stesso kind**
    (`Message::Text` solo se i bytes sono UTF-8 valido, altrimenti errore
    risolto a forward dell'originale, come fa l'HTTP coi parse falliti);
  - `Drop` → `None` (hudsucker non inoltra il frame).
- I frame di controllo (`Ping`/`Pong`/`Close`) **non** si intercettano: inoltrali
  sempre, per non rompere il keep-alive/handshake di chiusura.
- **Verifica**: test che con `intercept_on=false` il frame passa invariato
  (comportamento attuale); con una decisione `ForwardEdited` il payload esce
  cambiato; con `Drop` esce `None`.

### A3 — controlli runtime (`core/proxy/src/engine.rs`, `lib.rs`)
- `EngineHandle::decide_ws(id, WsDecision)` → `ws_registry.resolve`.
- Esponi su `ProxyHandle` e ri-esporta `WsDecision` da `lib.rs`.
- **Verifica**: `cargo test -p elliot-proxy`.

### A4 — comando e UI (`app/src-tauri/src/proxy.rs`, `app/src/proxy/`)
- Comando `proxy_ws_decide { message_id, action, edited? }` gemello di
  `proxy_intercept_decide`; registralo in `app/src-tauri/src/lib.rs`.
- Nel pump, inoltra l'evento di pausa WS alla UI; in `ProxyScreen`/`MessageViewer`
  mostra i frame WS in pausa con Forward/Edit/Drop quando l'intercept è attivo.
- **Verifica**: `npm --prefix app run build`; prova manuale §5.

> Nota di perimetro: l'intercept **live dei flussi SOCKS non-HTTP** (TCP/UDP) è
> un problema diverso (flusso continuo, non richiesta/risposta) e **non** è in
> questa traccia: per quelli il lavoro attivo passa già da repeater/intruder
> sulla cattura. Vedi §7.

---

## 4. Traccia B — hardening della chiave CA a riposo

Obiettivo: la `ca.key` non deve stare in chiaro sul disco. Vincolo: la CA è
**globale** (`app_data/ca`) e serve a far partire il proxy anche **senza** un
progetto aperto, quindi non si può semplicemente legarla alla passphrase del
progetto (SQLCipher). La scelta dell'approccio è la decisione aperta principale
di questa traccia (§6 D3) — di seguito la via raccomandata.

### B1 — astrazione di storage della chiave (`core/tls/src/ca.rs`)
- Introduci un piccolo confine: `load_key()/store_key()` dietro un trait o un
  enum `KeyStore`, così l'algoritmo di persistenza è un dettaglio e `Ca` non
  cambia firma pubblica (`load_or_create`, `leaf_for_host`, `cert_pem`,
  `into_issuer` restano).
- **Verifica**: i test esistenti di `ca.rs` continuano a passare
  (`generates_once_and_reloads_the_same_certificate`, l'handshake reale).

### B2 — implementazione raccomandata: OS keychain, con fallback cifrato
- Chiave nel **keychain di sistema** via `keyring` (macOS Keychain, Secret
  Service su Linux, Credential Manager su Windows): il certificato pubblico
  resta un file (`ca.crt`), la chiave diventa una voce del keychain
  (`service = "elliot", account = "ca-key"`).
- Fallback quando il keychain non è disponibile (headless/CI): file cifrato
  `ca.key.enc` con AEAD (XChaCha20-Poly1305) e chiave derivata da un segreto a
  livello app; **mai** di nuovo in chiaro. Il `0600` resta come difesa in più.
- Migrazione: se esiste una vecchia `ca.key` in chiaro, importala nel nuovo
  storage e **rimuovi** il file in chiaro al primo avvio.
- **Verifica**: test che dopo `load_or_create` non resti `ca.key` in chiaro;
  round-trip store→load→handshake; test del ramo di fallback forzando "keychain
  assente".

### B3 — aggiorna il TODO e la doc
- Togli il `TODO(hardening)` a `ca.rs:14`; aggiorna `docs/architecture.md`
  (sezione CA/segreti) con l'approccio scelto.
- **Verifica**: `rg "TODO\(hardening" core/` vuoto.

---

## 5. Traccia C — cablare l'agente (la più grande)

Obiettivo della prima verticale: **chat → proposta → validazione → approvazione
umana → esecuzione → output in UI**, con l'agente che non esegue mai e non
conosce lo scope (lo impone il Rust). Suddivisa in fasi piccole; C1–C2 e C6 sono
scaffolding, C3–C5 sono il cuore.

### C1 — protocollo sidecar persistente + proposte (`agent/elliot_agent/`)
- Passa da one-shot a **loop**: leggi richieste NDJSON riga-per-riga finché
  stdin non chiude; ogni richiesta porta `prompt`, `model`, e il **contesto
  curato** passato dal Rust (non l'intera sessione).
- Carica il catalogo (`../catalog`, gli stessi YAML del crate `catalog`) come
  grounding: l'agente può nominare solo tool/flag esistenti.
- Nuovi frame in uscita oltre a `chunk`/`done`/`error`:
  `{"type":"proposal","tool_id":...,"flags":[{"name":...,"value"?:...}],"targets":[...]}`.
  Lo schema del frame è contratto con il ponte Rust (§6 D4).
- **Verifica**: test Python che una richiesta produca `chunk*` poi
  (eventualmente) un `proposal` ben formato poi `done`; un tool fuori catalogo
  non deve mai comparire in un `proposal`.

### C2 — ponte Rust del sidecar (`app/src-tauri/src/agent.rs`, nuovo)
- Spawna il sidecar come processo figlio (in dev: `python -m elliot_agent`; in
  release: il binario sidecar di C6), ne gestisce il ciclo di vita (avvio pigro
  al primo messaggio, kill allo stop), e parla NDJSON su stdin/stdout.
- `AgentState` gestito da Tauri come gli altri (`Mutex<Option<...>>`); comando
  `agent_send { prompt }` che streamma i `chunk` alla UI via evento
  `agent://chunk` e, al `proposal`, emette `agent://proposal`.
- Il testo dei target (banner, header) che entra nel contesto è **dato, non
  istruzioni**: passa dal Rust come contesto curato, mai interpretato come
  comandi.
- **Verifica**: test d'integrazione che con un sidecar finto (script che emette
  frame noti) il ponte inoltri chunk e proposta.

### C3 — pipeline proposta → validazione (`app/src-tauri/src/agent.rs`)
- Alla ricezione di un `proposal`: trova il `ToolEntry` (`catalog::load_standard`),
  costruisci `runner::Proposal`, e chiama `runner::validate(entry, &proposal,
  scope.decider().as_ref(), &RunnerConfig::new(project_dir))`.
- `project_dir` = la cartella del progetto aperto (da `ScopeState`); se nessun
  progetto è aperto, **rifiuta** (niente confinamento path, niente esecuzione).
- L'esito va alla UI come proposta **validata o rifiutata** (`agent://proposal`
  con il `ValidatedCommand` o il `RunnerError` reso leggibile): l'utente vede
  l'argv esatto che verrebbe eseguito e il motivo di un eventuale rifiuto.
- **Verifica**: test che una proposta fuori scope dia `RunnerError::OutOfScope`
  e **nessuna** esecuzione.

### C4 — UI di approvazione (`app/src/agent/`, nuovo; abilita il tab in `App.tsx`)
- `AgentScreen`: chat con streaming; quando arriva una proposta validata,
  mostra l'**argv esatto**, l'`effective_intrusiveness` e i `required_privileges`.
- Gate di conferma obbligatoria: più alta l'intrusiveness, più esplicita la
  conferma; `Dangerous` è bloccato salvo unlock manuale esplicito
  (`RunnerConfig::allow_dangerous`), coerente con `RunnerError::DangerousBlocked`.
- Nessuna esecuzione parte senza un sì esplicito dell'umano in questa schermata.
- **Verifica**: `npm --prefix app run build`; prova manuale (sotto).

### C5 — esecuzione e output (`app/src-tauri/src/agent.rs`, `app/src/agent/`)
- Comando `agent_execute { proposal_id }`: ri-valida (non fidarti del round-trip
  UI) ed esegue con `runner::execute` (argv, no shell, timeout). Streamma/mostra
  l'`Output` (stdout/stderr/exit/durata). Opzionale: persistenza dell'esecuzione
  nello store del progetto.
- **Verifica**: end-to-end con un tool innocuo del catalogo contro un target in
  scope locale; vedi sotto.

### C6 — packaging del sidecar (impostazione, dichiarata mancante in `agent/README.md`)
- Impacchetta l'ambiente Python come **binario sidecar Tauri** (es. PyInstaller)
  e dichiaralo in `tauri.conf.json` (`bundle.externalBin`), con naming
  per-target. In dev si resta su `python -m elliot_agent`.
- **Come è stato fatto:** `externalBin` sta in un **overlay**
  (`tauri.sidecar.conf.json`, usato da `npm run tauri:build:sidecar`) e non nella
  config base: `tauri-build` copia i sidecar dichiarati a ogni `cargo build` e
  fallisce se il file non esiste, il che renderebbe il workspace non compilante
  su una macchina senza PyInstaller (contrario al vincolo di §0).
- **Verifica**: build dell'app che includa il sidecar; avvio che trova il binario.

### C7 — contesto curato (opzionale, dopo la verticale)
- Azione dedicata per passare **selettivamente** all'agente un flow/una cattura
  da proxy/repeater/intruder (non l'intera sessione), come grounding.
- **Verifica**: un flow scelto compare nel contesto; nulla di non scelto trapela.

### Verifica end-to-end della traccia C (manuale)
1. Ollama locale attivo; apri un progetto; definisci uno scope che include un
   target locale.
2. In Agent, chiedi qualcosa che porti a un tool del catalogo contro quel target.
3. Verifica: arriva una proposta con argv esatto e intrusiveness; **approva**;
   l'output compare; **nessuna** esecuzione è avvenuta prima del sì.
4. Ripeti con un target **fuori scope**: la proposta risulta rifiutata
   (`OutOfScope`), nessuna esecuzione.

---

## 6. Decisioni aperte — esito

- **D1 (A)**: `WsRegistry` dedicato vs `Registry<T>` generico. Raccomando il
  dedicato: poche righe, zero rischio sul percorso HTTP esistente.
  **Scelto:** `WsRegistry` dedicato (`intercept.rs`).
- **D2 (A)**: evento di pausa WS come variante nuova (`WebSocketPaused`) vs stato
  dentro `WsMessage`. Raccomando lo stato in `WsMessage` per non moltiplicare le
  varianti dell'evento. **Scelto:** campo `paused: bool` in `WsMessage`
  (`#[serde(default)]`, così un frame osservato resta compatibile).
- **D3 (B)**: OS keychain (raccomandato) vs file cifrato con chiave app vs
  chiave CA dentro lo store del progetto. L'ultima rompe l'avvio-senza-progetto,
  quindi è sconsigliata come unica via. **Scelto:** keychain con fallback
  cifrato. Nota: il **default della libreria** è il file cifrato e solo il guscio
  desktop chiede il keychain, così test/esempi/CI non toccano il keychain di chi
  sviluppa (un entry condiviso fra più CA di test produrrebbe coppie
  certificato/chiave incoerenti). Il keychain resta la via del prodotto.
- **D4 (C)**: schema esatto del frame `proposal` tra Python e Rust e versioning
  del protocollo NDJSON (un campo `v`); confermare prima di C1/C2. **Scelto:**
  `{"v":1,"type":"proposal","tool_id","flags":[{"name","value"?}],"targets"}`;
  `v` su **ogni** frame, ignorato lato Rust (contratto in `agent/README.md`).
- **D5 (C)**: modello del processo sidecar — uno persistente per sessione
  (raccomandato) vs uno per richiesta. **Scelto:** uno persistente, avviato
  pigro al primo messaggio e ucciso allo stop/uscita dell'app.
- **D6 (C)**: come derivare `targets` del `Proposal` dallo scope/contesto quando
  l'utente non li scrive a mano. **Scelto:** li propone il modello dalla
  richiesta; il Rust gli manda le regole di scope come contesto **dato** e il
  runner valida ogni target. Nessuna derivazione automatica lato Rust.

---

## 7. Fuori perimetro (per questo piano)

- Intercept **live** dei flussi SOCKS non-HTTP (TCP/UDP a flusso continuo):
  il lavoro attivo su quei protocolli resta via repeater/intruder sulla cattura.
- Tamper dei frame di controllo WebSocket (Ping/Pong/Close).
- Rotazione/revoca della CA; gestione multi-CA.
- Autonomia dell'agente oltre la singola proposta approvata dall'umano.

---

## 8. "Definito finito" (definition of done per chiudere la parte)

- A: con intercept attivo, un frame WS in scope si può forward/edit/drop dalla
  UI; con intercept spento resta observe-only. Test verdi in `elliot-proxy`.
- B: nessuna `ca.key` in chiaro dopo l'avvio; handshake ancora valido; TODO
  rimosso; architettura aggiornata.
- C: verticale end-to-end verde (chat→proposta→approvazione→esecuzione→output),
  con il rifiuto fuori-scope dimostrato da un test.
- Globale: `cargo build/test/clippy --workspace` e `npm run build` verdi;
  `docs/architecture.md` e `core/README.md` allineati; commit per traccia con
  messaggi sensati (`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`).

---

## 9. Checklist

- [x] A1 `WsDecision` + `WsRegistry`
- [x] A2 pausa/edit/drop in `WsHandler`
- [x] A3 `decide_ws` su engine/handle + re-export
- [x] A4 comando Tauri + UI, `npm run build`
- [x] B1 astrazione `KeyStore` in `ca.rs`
- [x] B2 keychain + fallback cifrato + migrazione dal file in chiaro
- [x] B3 TODO rimosso + doc aggiornata
- [x] C1 sidecar persistente + frame `proposal`
- [x] C2 ponte Rust `agent.rs` + `agent_send`
- [x] C3 pipeline validazione con `runner::validate` + scope + `project_dir`
- [x] C4 `AgentScreen` + gate di conferma per intrusiveness
- [x] C5 `agent_execute` + output in UI
- [x] C6 packaging sidecar (`externalBin`)
- [ ] C7 contesto curato (opzionale) — non fatto: il contesto curato di questa
      verticale è lo scope; la selezione di flow/capture resta il prossimo passo
- [x] Doc e commit per traccia
