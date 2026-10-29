# Piano — follow-up dopo la prima verticale

Piano autosufficiente per i follow-up rimasti dopo la chiusura di A/B/C
([`chiusura-lacune.md`](chiusura-lacune.md)): usabilità dell'agente, storico
WebSocket, packaging reale e verifiche sul bundle. Come gli altri piani in
`docs/plans/`, ogni fase indica file, API concrete e una verifica propria;
nessuna fase deve lasciare il workspace non compilante.

Stato di partenza: branch `feat/proxy-module`, commit `b45ac3a` (intercept WS),
`5ac42f8` (chiave CA), `699a1b6` (verticale agente). Comandi di riferimento:
`cargo build/test/clippy --workspace`, `npm --prefix app run build`,
`cd agent && .venv/bin/python -m unittest discover -s tests -v`.

---

## 1. Contesto e stato attuale

### 1.1 WebSocket

- `core/proxy/src/websocket.rs`: `WsHandler { events, scope, intercept_on,
  registry }` con pausa/forward/edit/drop; `observe()` costruisce `WsMessage`
  con `id` nuovo per frame e `connection: String` = `"{client} <-> {host}:{port}"`.
  I frame di controllo non si interceptano.
- `core/httpraw/src/lib.rs`: `WsMessage { id, connection, at, client_addr,
  scheme, host, port, direction, kind, payload, paused }`. `WsDirection` e
  `WsKind` **non** hanno token canonici (li hanno invece `Direction`, `Transport`,
  `FlowState`…), quindi oggi non sono persistibili senza inventare un formato.
- `ProxyEvent::WebSocket(WsMessage)` viene emesso solo alla pausa; dopo la
  decisione non c'è un evento "risolto". `app/src-tauri/src/proxy.rs` inoltra
  l'evento alla UI (`kind:"ws"`) ma **non** lo persiste: `persist_flow` copre solo
  i flow HTTP.
- `app/src/proxy/useProxy.ts` tiene `wsQueue` (solo frame in pausa) e
  `decideWs`; non esiste uno storico WS, che oggi si perde alla chiusura.
- Test: unit in `websocket.rs` e `intercept.rs`; **nessun** test che attraversa
  hudsucker (il cablaggio `with_websocket_handler` è verificato solo per
  compilazione).
- Limite noto: hudsucker 0.25 espone `WebSocketContext` con **solo** `src`/`dst`
  (`hudsucker/src/lib.rs:91`) e `WebSocketHandler::handle_websocket` senza id
  della richiesta di upgrade: lo stitching al `Flow` HTTP non è ottenibile senza
  patchare la dipendenza. hudsucker **clona** l'handler per connessione
  (`proxy/mod.rs:149`, `proxy/internal.rs:420`), quindi un `Clone` custom può
  assegnare un'identità stabile per socket.

### 1.2 Store

- `core/store/src/lib.rs`: `SCHEMA_VERSION = 2`; `open` migra solo `1 => v2`
  (`migrate_v1_to_v2`), altrimenti `SchemaVersion { found, supported }`.
  Tabelle: `flows`, `settings`, `streams`, `messages`. Helper `millis` /
  `from_millis`.
- Non esiste alcuna tabella per frame WS né per esecuzioni dell'agente.
- Pattern di scrittura: batch in transazione (`upsert_flows`, `append_messages`).

### 1.3 Agente

- `agent/elliot_agent/__main__.py`: loop persistente, `PROTOCOL_VERSION = 1`,
  frame `chunk|proposal|error|done`, `propose()` fa una **seconda** chiamata a
  `stream_reply` per ottenere il JSON, `_chat_prompt(prompt, context)`.
- `agent/elliot_agent/catalog.py`: `load_catalog`, `describe`,
  `validate_proposal`, `parse_proposal_json` (contratto con il Rust).
- `agent/elliot_agent/ollama_client.py`: `stream_reply(prompt, model)` con stub
  quando Ollama è irraggiungibile.
- `app/src-tauri/src/agent.rs`: `AgentState { sidecar, proposals }`,
  `agent_send` (contesto = solo regole di scope via `curated_context`),
  `agent_execute` (rivalida + `runner::execute`), `pump`, eventi
  `agent://chunk|done|error|proposal|execution|exit`.
- `app/src/agent/`: `AgentScreen` (chat + `ProposalCard` con gate per
  intrusività), `useAgent` (transcript in memoria, `send`, `run`, `stop`).
- Nessuna memoria di conversazione: ogni richiesta è indipendente. Nessuna
  persistenza di proposte/esecuzioni. `ProxyScreen.tsx:116` ha ancora
  `"Send to Agent"` disabilitato; `CaptureScreen` offre solo Repeater/Intruder.

### 1.4 Packaging e chiave CA

- `scripts/build-sidecar.sh` (PyInstaller → `app/src-tauri/binaries/elliot-agent-<triple>`)
  e overlay `app/src-tauri/tauri.sidecar.conf.json` (`bundle.externalBin`), usato
  da `npm run tauri:build:sidecar`. **Mai eseguiti**: il binario non è mai stato
  prodotto, né provato dentro un bundle.
- `sidecar_command()` in `agent.rs` preferisce `<exe dir>/elliot-agent`, poi
  `python -m elliot_agent`.
- `elliot-tls`: `Ca::load_or_create_with(dir, KeyStore)`, `KeyStore::{Keychain,
  EncryptedFile}`; l'app passa `KeyStore::Keychain`, il default della libreria è
  il file cifrato. Non c'è modo, dalla UI, di sapere quale backend è in uso né se
  una vecchia `ca.key` è stata migrata.

---

## 2. Obiettivo e ordine

Due fasi di fondamenta condivise (W1, S1) più tre tracce indipendenti:

| fase | contenuto | dipende da | taglia |
|---|---|---|---|
| **W1** | identità di connessione WS (`connection_id` stabile) | — | S |
| **S1** | store schema v3: `ws_messages` + `agent_runs`, migrazione a catena | W1 | M |
| **W2** | evento "risolto" + persistenza dei frame inoltrati | W1, S1 | S |
| **W3** | test end-to-end WS attraverso hudsucker | W1 | M |
| **W4** | storico WS in UI (sub-tab + reload dal progetto) | W2 | M |
| **AG1** | memoria di conversazione (storico limitato lato Rust) | — | M |
| **AG2** | una sola chiamata al modello con trailer di proposta | AG1 | M |
| **AG3** | C7: contesto curato selettivo + "Send to Agent" | AG1 | M |
| **AG4** | persistenza delle esecuzioni + pannello "Runs" | S1 | M |
| **AG5** | rifiniture UI: modello, latenza, reset, "Propose" | AG2 | S |
| **P1** | build reale del sidecar e bundle | — | M |
| **P2** | verifica keychain sul bundle + `ca_status` | P1 | S |
| **P3** | decisione su `externalBin` nella config base | P1 | S |

Regola d'ordine: **W1** (campo nuovo, nessuna dipendenza), poi **S1**
(W2/W4 e AG4 scrivono nel file di progetto), poi una traccia alla volta. Ogni
fase è committabile da sola; niente push.

---

## 3. Decisioni da confermare prima dell'esecuzione

- **D1 (AG2)** — Una chiamata sola: il modello riceve l'istruzione di appendere
  una riga finale `ELLIOT_PROPOSAL {json}`, che il sidecar filtra dallo stream e
  valida. Se il trailer manca **non** si fa un secondo giro automatico (era il
  costo che volevamo togliere): la UI espone un pulsante **Propose** che invia
  `propose_only: true` e fa **una** chiamata con l'istruzione stretta.
  *Raccomandato*: sì. Alternativa: secondo giro sempre (comportamento attuale).
- **D2 (W2)** — Cosa persistere: solo i frame **effettivamente inoltrati**
  (payload post-edit; i drop non entrano nello storico) oppure anche i drop.
  *Raccomandato*: solo gli inoltrati — lo storico è "cosa è passato", non un
  registro di decisioni.
- **D3 (AG3)** — Contesto: tray esplicito per sessione (l'utente allega
  flow/messaggi, restano finché non li toglie) vs solo l'ultima selezione.
  *Raccomandato*: tray, cap 8 elementi / 8 KiB per elemento, svuotato al cambio
  progetto.
- **D4 (AG1/AG2)** — Protocollo: bump a `v: 2` per `history`/`propose`/`models`
  (il sidecar accetta `v: 1` senza i campi nuovi) vs campi opzionali senza bump.
  *Raccomandato*: bump a 2, così una versione vecchia del sidecar si riconosce
  subito.
- **D5 (W1)** — Identità connessione: `Clone` custom che rigenera un
  `connection_id: Uuid` (hudsucker clona per connessione) vs lasciare la stringa
  attuale. *Raccomandato*: `Clone` custom, con test e2e che dimostra la stabilità
  sullo stesso socket (se hudsucker cambiasse e clonasse per frame, il test
  fallisce e lo si scopre subito).
- **D6 (W-stitching)** — Stitching frame ↔ flow di upgrade: **fuori perimetro**
  con hudsucker 0.25 (nessun id esposto). Servirebbe un fork o un `on_upgrade`
  upstream. *Raccomandato*: fuori perimetro, documentato.
- **D7 (P3)** — `externalBin` nella config base: **no**, resta l'overlay, perché
  `tauri-build` copia i sidecar a ogni `cargo build` e fallisce se il file non
  esiste (vedi `tauri-build-2.7.3/src/lib.rs:735`). Promuoverlo solo se in futuro
  il binario entra in un flusso di build automatico.

---

## 4. Fondamenta condivise — W1 e S1

Sono le due fasi da cui dipende tutto il resto: l'identità di connessione
(`WsMessage.connection_id`) serve alla tabella `ws_messages`, quindi **W1 va
eseguita prima di S1**. Entrambe non toccano la UI e lasciano il workspace
compilante da sole.

### W1 — Identità di connessione (S)

**File:** `core/httpraw/src/lib.rs`, `core/proxy/src/websocket.rs`,
`core/proxy/src/engine.rs` (costruzione handler), `app/src/proxy/types.ts`
(il tipo wire deve dichiarare `connection_id`).

- Aggiungere a `WsMessage`:

```rust
/// Identità stabile della connessione: tutti i frame dello stesso socket la
/// condividono. `connection` resta l'etichetta leggibile per la UI.
pub connection_id: Uuid,
```

- In `WsHandler` aggiungere `connection_id: Uuid` e implementare `Clone` **a
  mano**:

```rust
impl Clone for WsHandler {
    fn clone(&self) -> Self {
        Self {
            events: self.events.clone(),
            scope: self.scope.clone(),
            intercept_on: self.intercept_on.clone(),
            registry: self.registry.clone(),
            // hudsucker clona l'handler una volta per connessione: è qui che
            // nasce l'identità del socket.
            connection_id: Uuid::new_v4(),
        }
    }
}
```

- `engine.rs` costruisce l'handler con `connection_id: Uuid::new_v4()`;
  `observe()` copia `self.connection_id`. I due letterali `WsMessage { … }`
  in `websocket.rs` (produzione, riga ~149, e helper `observed()` dei test,
  riga ~235) vanno estesi; nessun altro crate costruisce il tipo.
- Test unit: due `clone()` hanno `connection_id` diversi e ogni `observe()`
  riporta quello dell'handler.

**Verifica:** `cargo test -p elliot-proxy`; il test W3 conferma che sullo stesso
socket tutti i frame condividono l'id.

### S1 — Store schema v3

**File:** `core/store/src/lib.rs`, `core/httpraw/src/lib.rs`,
`core/store/Cargo.toml`. Il crate **non** dipende da `serde_json` oggi: per
`argv`/`targets`/`required_privileges` aggiungere solo
`serde_json = { workspace = true }` e salvare i vettori come JSON, leggibili a
mano ispezionando il file. **Non** reintrodurre `serde` nello store: `AgentRun`
resta un tipo a campi semplici e la serializzazione verso la UI è una `View`
del guscio Tauri (AG4).

#### S1.1 Token canonici per i frame

`WsDirection` ha già `ClientToServer`/`ServerToClient`, `WsKind` ha
`Text|Binary|Ping|Pong|Close`. Aggiungere, accanto agli altri enum congelati:

```rust
impl WsDirection {
    pub fn as_token(self) -> &'static str { /* "c2s" | "s2c" */ }
    pub fn from_token(token: &str) -> Self { /* default ClientToServer */ }
}
impl WsKind {
    pub fn as_token(self) -> &'static str { /* "text" | "binary" | "ping" | "pong" | "close" */ }
    pub fn from_token(token: &str) -> Self { /* default Text */ }
}
```

Estendere `enum_tokens_are_frozen_for_the_store` con i nuovi token e con il
round-trip/degradazione sicura.

#### S1.2 DDL v3

```sql
CREATE TABLE IF NOT EXISTS ws_messages (
    id            TEXT PRIMARY KEY,
    connection_id TEXT NOT NULL,
    at            INTEGER NOT NULL,
    client_addr   TEXT NOT NULL,
    scheme        TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    direction     TEXT NOT NULL,
    kind          TEXT NOT NULL,
    payload       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ws_messages_at ON ws_messages (at);
CREATE INDEX IF NOT EXISTS idx_ws_messages_connection ON ws_messages (connection_id, at);

CREATE TABLE IF NOT EXISTS agent_runs (
    id                     TEXT PRIMARY KEY,
    proposal_id            TEXT,
    tool_id                TEXT NOT NULL,
    program                TEXT NOT NULL,
    argv                   TEXT NOT NULL,   -- JSON array di stringhe
    targets                TEXT NOT NULL,   -- JSON array di stringhe
    effective_intrusiveness TEXT NOT NULL,
    required_privileges    TEXT NOT NULL,   -- JSON array di token
    started_at             INTEGER NOT NULL,
    completed_at           INTEGER NOT NULL,
    status                 INTEGER,
    stdout                 BLOB NOT NULL,
    stderr                 BLOB NOT NULL,
    duration_ms            INTEGER NOT NULL,
    error                  TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_started ON agent_runs (started_at);
```

Nessuna FK: i frame WS non appartengono a uno `Stream`, e un run non appartiene
a un flow.

#### S1.3 Migrazione a catena

```rust
pub const SCHEMA_VERSION: i64 = 3;

match version {
    v if v == SCHEMA_VERSION => {}
    1 => { migrate_v1_to_v2(&conn)?; migrate_v2_to_v3(&conn)?; }
    2 => migrate_v2_to_v3(&conn)?,
    other => return Err(StoreError::SchemaVersion { found: other, supported: SCHEMA_VERSION }),
}
```

`init_schema` deve includere le nuove DDL (idempotenti), come già fa.

#### S1.4 API

```rust
// Nessun derive serde: lo store resta indipendente dalla serializzazione
// (la UI riceve un `AgentRunView` costruito in `app/src-tauri/src/agent.rs`).
pub struct AgentRun {
    pub id: Uuid,
    pub proposal_id: Option<Uuid>,
    pub tool_id: String,
    pub program: String,
    pub argv: Vec<String>,
    pub targets: Vec<String>,
    pub effective_intrusiveness: String,
    pub required_privileges: Vec<String>,
    pub started_at: SystemTime,
    pub completed_at: SystemTime,
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl Store {
    pub fn append_ws_messages(&mut self, messages: &[WsMessage]) -> Result<(), StoreError>;
    pub fn append_ws_message(&self, message: &WsMessage) -> Result<(), StoreError>;
    pub fn list_ws_messages(&self, limit: usize) -> Result<Vec<WsMessage>, StoreError>;
    pub fn count_ws_messages(&self) -> Result<i64, StoreError>;
    pub fn append_agent_run(&self, run: &AgentRun) -> Result<(), StoreError>;
    pub fn list_agent_runs(&self, limit: usize) -> Result<Vec<AgentRun>, StoreError>;
}
```

`append_ws_message` usa `INSERT OR REPLACE` (l'id è del frame: un secondo evento
con lo stesso id non deve duplicare la riga). `list_ws_messages` ordina per `at`
crescente e ricostruisce i token con `from_token`.

#### S1.5 Verifica

- Test: un file **v1** migra a v3 conservando flow e settings; un file **v2**
  migra a v3 conservando streams/messages; `user_version` finale = 3.
- Test round-trip: un `WsMessage` e un `AgentRun` scritti e riletti sono uguali
  (payload binario non-UTF8 compreso).
- `cargo test -p elliot-store` e `cargo clippy --workspace --all-targets` verdi.

---

## 5. Traccia W — WebSocket

W1 è in §4, perché l'identità di connessione serve allo schema dello store.
Qui restano evento risolto, persistenza, test e UI.

### W2 — Evento "risolto" e persistenza (S)

**File:** `core/proxy/src/websocket.rs`, `app/src-tauri/src/proxy.rs`,
`app/src/proxy/useProxy.ts`.

Oggi dopo la decisione non viene emesso nulla: lo storico non può riflettere il
payload editato. `apply()` deve restituire **due** cose: il frame da mandare
sulla rete e quello che è stato effettivamente inoltrato, da annunciare. Il
pump Tauri usa il secondo per la UI e per il file di progetto.

```rust
fn apply(&self, decision: WsDecision, original: Message, observed: WsMessage)
    -> (Option<Message>, Option<WsMessage>)   // (frame sulla rete, frame risolto)
```

Comportamento di `apply()`:

- `Forward` → `(Some(original), Some(observed con paused=false))`;
- `ForwardEdited` valido → `(Some(edited), Some(observed con payload editato,
  paused=false))`;
- `ForwardEdited` non-UTF-8 su Text → `(Some(original), Some(observed
  paused=false))` più l'evento `Error` già esistente;
- `Drop` → `(None, None)` (D2: un frame buttato non è storia né traffico);
- la pausa continua a emettere `WebSocket(paused=true)` come oggi, prima che
  `apply()` venga chiamata.

`handle_message` emette il secondo valore (se c'è) e manda il primo sulla
rete, con l'ordine invariato: pausa, risoluzione, evento risolto, write.

Tre test esistenti in `websocket.rs` (`a_forward_edit_replaces_the_payload…`,
`a_binary_edit_may_carry_non_utf8_bytes`,
`a_text_edit_that_is_not_utf8_forwards_the_original`) chiamano `apply()` e
asseriscono su `Option<Message>`: vanno aggiornati al tuple, altrimenti la
fase non compila.

Il pump Tauri (`proxy.rs`, ramo `ProxyEvent::WebSocket`) persiste solo i frame
non in pausa:

```rust
ProxyEvent::WebSocket(m) => {
    if !m.paused { persist_ws(&scope_for_pump, &m).await; }
    FlowEvent { kind: "ws", flow: None, ws: Some(m), error: None }
}
```

con

```rust
async fn persist_ws(scope: &ScopeState, message: &WsMessage) {
    if let Some(Err(e)) = scope.with_store(|s| s.append_ws_message(message)).await {
        tracing::warn!("persisting ws frame {}: {e}", message.id);
    }
}
```

**Verifica:** test unit in `websocket.rs` che `apply()` restituisca il frame
risolto atteso (payload editato / originale / `None` su drop) e il frame di
rete corrispondente; test in
`app/src-tauri/src/proxy.rs` sul mapping "paused ⇒ non persistito" (si può
estrarre una funzione pura `should_persist(&WsMessage) -> bool`).

### W3 — Test end-to-end attraverso hudsucker (M)

**File nuovo:** `core/proxy/tests/websocket.rs`; `core/proxy/Cargo.toml`
(dev-dependency `tokio-tungstenite = "0.30"`, la stessa versione usata da
hudsucker 0.25; in alternativa `hudsucker` come dev-dep e il suo re-export).

Struttura del test (uno solo, con tre asserzioni indipendenti):

1. **Upstream**: `tokio::net::TcpListener` su `127.0.0.1:0`, un task che accetta
   e fa `tokio_tungstenite::accept_async`, poi legge i frame e li manda a un
   `mpsc` per le asserzioni.
2. **Proxy**: `start(ProxyConfig { listen_addr: proxy_addr, ca_dir: dir,
   ca_key_store: KeyStore::EncryptedFile, verify_upstream: true },
   Arc::new(AllowAll), tx)`, poi `handle.set_intercept(true)`.
3. **Client**: `TcpStream::connect(proxy_addr)`, richiesta di handshake in forma
   **assoluta** (`GET ws://127.0.0.1:<origin>/chat HTTP/1.1` con `Host`) e
   `tokio_tungstenite::client_async(request, stream)`.
   *Nota di implementazione:* se `client_async` rifiuta l'URI assoluto, inviare
   l'handshake a mano e avvolgere lo stream con
   `WebSocketStream::from_raw_socket`; il test deve restare sul percorso
   "proxy HTTP" (niente CONNECT), così copre anche `ws://`.
4. **Forward+edit**: il client invia `Text("hello")`; il test attende
   `ProxyEvent::WebSocket(m)` con `m.paused` e `payload == b"hello"`, chiama
   `handle.decide_ws(m.id, WsDecision::ForwardEdited(b"edited".to_vec()))`, e
   asserisce che l'upstream riceve `"edited"`.
5. **Drop**: il client invia `"drop me"`; alla pausa si decide `Drop` e si
   asserisce che l'upstream non riceve nulla entro 300 ms (e che un frame
   successivo passa ancora, per dimostrare che il socket non è rotto).
6. **Identità**: tutti i `m` osservati sullo stesso socket hanno lo stesso
   `connection_id`, e un **secondo** client che apre una nuova connessione
   ne riceve uno diverso (D5). Il secondo assert è quello che dimostra che il
   `Clone` avviene per connessione e non è un id globale; se hudsucker
   cambiasse strategia, questo test lo dice subito.

**Verifica:** `cargo test -p elliot-proxy --test websocket -- --nocapture`.

### W4 — Storico WebSocket in UI (M)

**File:** `app/src-tauri/src/proxy.rs` (comando `ws_list`), `app/src-tauri/src/lib.rs`
(registrazione), `app/src/proxy/{useProxy.ts,ProxyScreen.tsx}`, nuovi
`app/src/proxy/WsTable.tsx` e `WsViewer.tsx`, `app/src/styles.css`.

- Comando:

```rust
#[tauri::command]
pub async fn ws_list(scope: State<'_, SharedScope>, limit: usize) -> Result<Vec<WsMessage>, String> {
    scope.with_store(|s| s.list_ws_messages(limit)).await
        .unwrap_or(Ok(Vec::new()))
        .map_err(|e| e.to_string())
}
```

(nome/limite come gli altri: default 500, cap lato store).
- `useProxy`: oltre a `wsQueue` (pausa), tenere `wsRows` alimentato dagli eventi
  `!paused` (cap in memoria, es. 2000) e una `loadWs()` che chiama `ws_list`
  (pulsante "Reload" come in Capture). `wsQueue` resta invariato.
- `ProxyScreen`: quarto sub-tab `"ws"` con contatore; filtro semplice (testo su
  host/kind/payload), tabella Time/Dir/Host/Kind/Size/Preview, viewer
  testo/hex (`HexDump` già esportato da `MessageViewer.tsx:167`).
- Nessun "send to Repeater": un frame WS non è una richiesta raw. Solo copia
  payload.
- `styles.css`: riusare `.grid-table`, `.viewer`, `.seg`; niente CSS nuovo se non
  il badge direzione.

**Verifica:** `npm --prefix app run build`; manuale: aprire un sito WS dietro il
proxy, vedere i frame live; chiudere e riaprire il progetto → "Reload" li
riporta.

---

## 6. Traccia AG — agente

### AG1 — Memoria di conversazione (M)

**File:** `agent/elliot_agent/{__main__.py,ollama_client.py}`,
`agent/tests/test_sidecar.py`, `app/src-tauri/src/agent.rs`, `app/src/agent/useAgent.ts`.

- Protocollo v2 (D4). Richiesta: `{v:2, prompt, model?, context?: [string],
  history?: [{role:"user"|"assistant", text}], propose?: bool,
  propose_only?: bool}`.
- `ollama_client`: nuova `stream_chat(messages: list[dict], model) -> Iterator[str]`
  (payload Ollama `messages` già composto). `stream_reply(prompt, model)` resta
  come wrapper per compatibilità e per i test esistenti.
- Sidecar: comporre `messages = history + [{"role":"user","content": prompt}]`;
  il contesto curato va **solo** nell'ultimo messaggio utente (non replicato in
  ogni turno); l'istruzione di sistema (catalogo) solo nella chiamata di
  proposta. Se `history` manca → `[]`.
- Rust: `AgentState` guadagna `history: Mutex<Vec<ChatTurn>>` con
  `ChatTurn { role: String, text: String }`; limiti `HISTORY_TURNS = 12`,
  `HISTORY_CHARS = 6_000` (si scartano le coppie più vecchie). Su `agent_send`
  si accoda il turno utente; al frame `done` si accoda la risposta accumulata
  (`last_reply: Mutex<String>` alimentato dai chunk). `agent_reset` svuota
  history + transcript.
- **Ponte:** `pump` oggi riceve `proposals`; aggiungere un `Arc<Session>`
  (`history`, `last_reply`, `streaming`, `propose_only`) e passarlo sia a
  `agent_send` sia al task di lettura: `agent_send` accoda il turno utente
  **prima** di scrivere la richiesta, il ramo `Frame::Done` accoda
  `last_reply` (solo se la richiesta non era `propose_only`) e azzera
  `streaming`. I chunk alimentano `last_reply` senza essere mostrati due
  volte.
- **Una richiesta alla volta:** `Session.streaming` è un flag; `agent_send` e
  `agent_propose` rifiutano con "attendi la risposta corrente" se è già
  attivo, e lo azzerano su `done`, su `agent://exit` e su errore di scrittura.
  Il protocollo è seriale: due richieste intrecciate corromperebbero lo
  storico e il `last_reply`.
- Cambio progetto: `AgentState` tiene `last_project: Mutex<Option<PathBuf>>`;
  in `agent_send` confronta con `scope.project_dir().await` e, se diverso,
  svuota history e contesto (D3) prima di inviare.
- Sidecar: i turni di storico sono testo dell'utente/modello, non output dei
  target; il contesto resta marcato come dato.

**Verifica:** Python: `stream_chat` riceve i messaggi in ordine (utente/modello/
prompt) e il contesto compare solo nell'ultimo; il limite è lato Rust (test con
15 turni → ne restano 12). Rust: test che `history` serializzato non superi i
limiti e che un cambio di `project_dir` lo azzeri.

### AG2 — Una sola chiamata al modello (M)

**File:** `agent/elliot_agent/__main__.py`, `agent/tests/test_sidecar.py`,
`app/src-tauri/src/agent.rs`, `app/src/agent/{useAgent.ts,AgentScreen.tsx}`.

- **Contratto (D1):** un'unica chiamata; l'istruzione chiede di terminare con
  una riga:

```
ELLIOT_PROPOSAL {"tool_id": "...", "flags": [...], "targets": [...]}
```

  (una sola riga, JSON compatto; nessun code fence).
- **Filtro dello stream:** accumulare i chunk e non emettere mai il trailer.
  Algoritmo:

```
tail = ""  # parte non ancora emessa
per ogni chunk:
    tail += chunk
    se marker in tail:
        emetti tail[..pos] (se non vuoto); trailer = tail[pos+len(marker):]; stop
    altrimenti:
        safe = tail.len() - (len(marker) - 1)
        emetti tail[..safe]; tail = tail[safe:]
a fine stream: emetti tail (se il marker non è mai comparso)
```

  Il trailer viene parsato con `parse_proposal_json` e validato con
  `validate_proposal`; se invalido → nessuna proposta (solo log su stderr). Il
  marker non deve mai finire in un frame `chunk` (test esplicito).
- **`propose_only: true`:** una sola chiamata con `PROPOSAL_INSTRUCTION`, nessun
  `chunk` (o chunk soppressi), poi `proposal` se valida, poi `done`. È il
  pulsante **Propose** della UI; non c'è nessun secondo giro automatico.
- Rust: inoltra `propose`/`propose_only` nel JSON della richiesta e li espone in
  `agent_send`/`agent_propose` (nuovo comando sottile che chiama lo stesso
  percorso con `propose_only=true`, così la UI non deve conoscere il
  protocollo). Entrambi rispettano il flag `Session.streaming` di AG1 e
  `propose_only` non aggiunge turni allo storico.
- `useAgent`: `propose()` per il pulsante; il transcript mostra la risposta della
  chat senza il trailer.

**Nota:** i 13 test Python esistenti patchano `stream_reply` e il prompt di
proposta; vanno migrati a `stream_chat` e al trailer (il `fake_model` diventa
"risposta + riga `ELLIOT_PROPOSAL`"), altrimenti la suite resta verde ma non
copre più il nuovo percorso.

**Verifica:** Python: contatore delle chiamate a `stream_chat` == 1 per
richiesta; il trailer non compare in nessun `chunk`; marker parziale a fine
stream emesso integralmente; `propose_only` → `proposal`+`done` senza chunk.
Rust: test del frame in uscita con `propose`/`propose_only`.

### AG3 — C7: contesto curato selettivo (M)

**File:** `app/src-tauri/src/agent.rs`, `app/src-tauri/src/lib.rs`,
`app/src/{App.tsx,proxy/ProxyScreen.tsx,capture/CaptureScreen.tsx,agent/AgentScreen.tsx,agent/useAgent.ts}`,
`app/src/proxy/types.ts`.

- Tipi:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextItem {
    pub id: Uuid,
    pub label: String,        // "HTTP GET api.example.com/login"
    pub target: String,       // "https://api.example.com:443"
    pub source: Option<String>, // "flow:<uuid>" | "message:<uuid>" (debug/dedupe)
    pub text: String,         // bytes resi come testo (lossy), troncati
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextInput { pub label: String, pub target: String,
                          pub text: String, pub source: Option<String> }
```

- `AgentState.context: Mutex<Vec<ContextItem>>`; comandi:
  `agent_attach_context(item) -> Vec<ContextItem>`,
  `agent_context_list() -> Vec<ContextItem>`,
  `agent_context_remove(id) -> Vec<ContextItem>`,
  `agent_context_clear()`.
  Limiti: `MAX_CONTEXT_ITEMS = 8`, `MAX_CONTEXT_CHARS = 8 * 1024` per item, con
  marcatore `\n…[truncated]`; il troncamento avviene in Rust (il testo è dato,
  non istruzioni: il sidecar lo incornicia già con `CONTEXT_HEADER`).
- `agent_send` compone `context` come oggi (regole di scope) **più** una stringa
  per ogni item: `format!("{label} — {target}\n{text}")`. Ordine stabile.
- UI:
  - `App.tsx`: `agentSeed` opzionale + `toAgent(item)` (stesso pattern di
    `toRepeater`) che invoca `agent_attach_context` e cambia tab; listener
    `agent://context` per aggiornare i chip.
  - `ProxyScreen` menu: abilitare `"Send to Agent"` (oggi `disabled: true`,
    riga 116) costruendo `{label, target, text}` dal `Row` selezionato (request +
    opzionale response, `decode`); hint "aggiunto al contesto".
  - `CaptureScreen`: terzo pulsante `→ Agent` accanto a Repeater/Intruder
    (`text` = `decode(message.data)` con nota della lunghezza se binario).
  - `AgentScreen`: barra "Context (N)" con chip rimovibili e "Clear"; se non c'è
    progetto, il contesto funziona lo stesso (sono byte passati dalla UI).
- Il contesto si svuota al cambio progetto (stesso hook di AG1).

**Verifica:** Rust: cap 8/8 KiB, ordine, e che il JSON inviato al sidecar
contenga esattamente gli item allegati (funzione pura `build_request(...)`
testabile). Python: un item che contiene `"ignore previous instructions"` resta
dentro il blocco `CONTESTO (dati non fidati)` e non può produrre un tool fuori
catalogo (la validazione è indipendente). Manuale: allegare un solo flow e
verificare che nel contesto compaia solo quello.

### AG4 — Persistenza delle esecuzioni (M)

**File:** `app/src-tauri/src/agent.rs`, `app/src-tauri/src/lib.rs`,
`app/src/agent/AgentScreen.tsx`.

- Dopo `cmd.execute(...)` in `agent_execute`, costruire:

```rust
AgentRun {
    id: Uuid::new_v4(),
    proposal_id: Some(proposal_id),
    tool_id: proposal.tool_id.clone(),
    program: cmd.program.clone(),
    argv: cmd.argv.clone(),
    targets: proposal.targets.clone(),
    effective_intrusiveness: intrusiveness_token(cmd.effective_intrusiveness).into(),
    required_privileges: cmd.required_privileges.iter().map(|p| privilege_token(*p).into()).collect(),
    started_at, completed_at: SystemTime::now(),
    status: out.status, stdout, stderr, duration_ms, error,
}
```

e `scope.with_store(|s| s.append_agent_run(&run))`. Un errore di persistenza è
un warning, non un fallimento dell'esecuzione (il tool è già girato).
- `AgentRunView` in `agent.rs` (Serialize, campi camelCase) mappato da
  `store::AgentRun`; comando `agent_runs(limit) -> Vec<AgentRunView>` (solo con
  progetto aperto).
- UI: pannello "Runs" collassabile in `AgentScreen` (tool, argv, exit, durata,
  ora), caricato all'apertura e dopo ogni `agent://execution`.

**Verifica:** store round-trip (S1) + test della funzione pura che costruisce
`AgentRun` dal risultato (status/errore/stdout). Manuale: eseguire un tool,
chiudere e riaprire il progetto → il run è nel pannello.

### AG5 — Rifiniture UI (S)

**File:** `app/src/agent/{AgentScreen.tsx,useAgent.ts}`, `app/src/styles.css`.

- Campo **Modello** (default `llama3.2:1b`, persistito in `localStorage`) passato
  in `agent_send`; badge di latenza accanto al turno (tempo tra invio e `done`);
  pulsante **Propose**; **Reset** (`agent_reset`); avviso quando cambia il
  progetto ("contesto e storico azzerati").
- Il gate di approvazione resta **identico**: nessuna scorciatoia.

**Verifica:** `npm --prefix app run build`; manuale.

---

## 7. Traccia P — packaging e piattaforma

### P1 — Build reale del sidecar e bundle (M)

**File:** `scripts/build-sidecar.sh`, `agent/README.md`, `docs/build.md`
(eventuali ritocchi).

Procedura:

1. `bash scripts/build-sidecar.sh` (PyInstaller nel venv). Rischi noti:
   - PyInstaller vs **Python 3.14**: se non supportato, creare un venv di
     packaging con 3.12/3.13 e documentarlo (es. variabile
     `ELLIOT_PACK_PYTHON` nello script);
   - PyYAML: se il binario fallisce a importarlo, aggiungere
     `--collect-all yaml`;
   - `--onefile` su macOS: verificare l'avvio (estrazione in tmp).
2. Provare il binario **da solo**:
   `printf '{"v":2,"prompt":"ciao"}\n' | app/src-tauri/binaries/elliot-agent-$(rustc -vV | sed -n 's/^host: //p')`
   con `ELLIOT_OLLAMA_URL=http://127.0.0.1:1/api/chat` → `chunk` … `done`
   (stub), exit 0. Poi senza URL morto, con Ollama attivo.
3. `npm --prefix app run tauri:build:sidecar`; verificare che
   `Elliot.app/Contents/MacOS/elliot-agent` esista e che l'app avviata usi
   quello (log "agent sidecar:" assente dal percorso Python; il processo figlio
   è `elliot-agent`).
4. End-to-end: progetto aperto + scope locale, chat → proposta → approvazione →
   output, con il solo binario impacchettato.

**Verifica:** i tre passi sopra; `cargo test -p elliot-app` resta verde (i test
usano il venv, non il binario: `sidecar_command` cerca accanto a
`current_exe`, che nei test è `target/debug/deps/…`).

### P2 — Keychain sul bundle (S)

**File:** `core/tls/src/{ca.rs,keystore.rs,lib.rs}`,
`app/src-tauri/src/{proxy.rs,lib.rs}`, `app/src/proxy/CaDialog.tsx`.

- `elliot-tls` espone il backend effettivamente in uso. `Secrets::load` e
  `Secrets::store` registrano quale backend ha davvero risposto in un campo
  con mutabilità interna (`std::cell::Cell<Option<EffectiveKeyStore>>`);
  `Ca::load_or_create_in` lo copia in `Ca`, che lo espone:

```rust
// `elliot-tls` non dipende da serde: è il guscio a mappare il valore su un
// token per la UI (`"keychain"` / `"encrypted_file"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectiveKeyStore { Keychain, EncryptedFile }

impl Ca { pub fn key_store(&self) -> EffectiveKeyStore; }
```

  `Secrets`/`Ca` tengono traccia se il keychain ha risposto o se si è degradati
  (il file cifrato ha la precedenza in lettura, quindi "effective" = dove la
  chiave è stata **letta/scritta** in questo avvio).
- Il backend deve arrivare fino all'handle: `engine.rs` costruisce la CA e la
  consuma in `into_issuer()`, quindi salvare `key_store: EffectiveKeyStore` in
  `EngineHandle` (letto prima di consumare la CA) ed esporre
  `ProxyHandle::ca_key_store()`.
- Comando `proxy_ca_status -> { backend, caDir, legacyMigrated: bool }` in
  `proxy.rs` (errore "proxy not running" se non c'è handle; il backend è
  quello dell'ultimo avvio). `legacyMigrated` si deduce da `ca.key.enc`
  presente **e** `ca.key` assente. Mostrarlo in `CaDialog` accanto al PEM
  ("chiave protetta da: macOS Keychain / file cifrato").
- Manuale sul bundle: primo avvio (eventuale prompt macOS), riavvio (nessun
  prompt), item rimosso da Accesso Portachiavi → l'app parte con il file cifrato
  (se esiste) o mostra l'errore esplicito; `ca.key` legacy → migrata e rimossa.
- **Opzionale (da confermare):** `ca_reset` con conferma digitata, che cancella
  `ca.crt`, `ca.key.enc`, `ca.seed` e la voce keychain, forzando una nuova CA.
  Invaliderebbe il trust installato: solo su richiesta esplicita, mai automatico.

**Verifica:** manuale sul bundle P1; `cargo test -p elliot-tls` verde.

### P3 — `externalBin` nella config base (S, decisione)

Con P1 funzionante, decidere se promuovere `externalBin` in `tauri.conf.json`.
Raccomandato **no** (D7): `tauri-build` fallisce se il file manca, e la config
base deve restare compilabile su una macchina senza PyInstaller. Se si promuove,
serve un job di build che produca sempre il binario prima di `cargo build`, e il
piano deve includerlo; altrimenti resta l'overlay documentato.

**Verifica:** `cargo build --workspace` su un clone pulito senza binario.

---

## 8. Fuori perimetro di questo piano

- **Stitching frame WS ↔ flow di upgrade** (hudsucker 0.25 non espone l'id della
  richiesta; servirebbe un fork o un `on_upgrade` upstream).
- **Intercept live dei flussi SOCKS non-HTTP**: il lavoro attivo resta via
  repeater/intruder sulla cattura.
- **Tamper dei frame di controllo** Ping/Pong/Close.
- **Invio di un frame WS a Repeater/Intruder**: non è una richiesta raw.
- **Rotazione/revoca della CA e multi-CA**: la voce keychain è fissa
  (`service="elliot"`, `account="ca-key"`); il multi-CA richiede account
  per-certificato e un flusso di re-trust.
- **G-DISS** (dissector), **G-FILT** (DSL di filtro), **G-SESS**
  (session-replay): restano i piani separati già rimandati.
- **Firma e notarizzazione macOS**: richiede un account Apple e un flusso di
  release; P2 verifica il keychain sul bundle *non firmato*.

---

## 9. Verifica end-to-end

Per ogni fase: i comandi della sua sezione. Prima di ogni commit:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets        # zero warning
npm --prefix app run build
cd agent && .venv/bin/python -m unittest discover -s tests -v
```

Prova manuale integrata (dopo W1 + S1 + W2/W4 + AG1–AG4 + P1):

1. Apri un progetto, scope su un target locale; avvia proxy e listener SOCKS.
2. **WS**: apri un client WS (o una pagina) dietro il proxy; con intercept on
   metti in pausa un frame, editalo, inoltra; verifica che il server riceva il
   payload modificato; un drop non arriva. Con intercept off i frame passano e
   finiscono nello storico; "Reload" dopo riapertura progetto li riporta.
3. **Agente**: allega un flow dal menu "Send to Agent" (contesto = 1 elemento);
   chiedi un comando; verifica che la risposta segua il formato (nessun trailer
   visibile), che arrivi la proposta con argv esatto, approva e controlla
   l'output; il run appare in "Runs" dopo riapertura.
4. **Memoria**: fai una seconda domanda che richiami la prima; la risposta deve
   tenerne conto. Cambia progetto → contesto e storico azzerati.
5. **Propose**: chiedi una proposta esplicita senza chat; una sola chiamata,
   nessun chunk.
6. **Bundle**: ripeti 2–3 con l'app impacchettata (P1) e verifica `ca_status`.

---

## 10. Definizione di fatto

- **W**: con intercept attivo forward/edit/drop funzionano anche attraverso
  hudsucker (test e2e); i frame inoltrati sono persistiti e ricaricabili dalla
  UI; ogni socket ha un `connection_id` stabile.
- **AG**: la chat ha memoria limitata e azzerabile; una richiesta = una chiamata
  al modello (il trailer non si vede); il contesto è un tray esplicito con cap;
  le esecuzioni sopravvivono alla riapertura del progetto.
- **P**: `scripts/build-sidecar.sh` produce un binario che parla il protocollo;
  il bundle parte senza Python di sistema e usa la CA via keychain (o il file
  cifrato, dichiarato in `CaDialog`).
- **Globale**: i comandi di §9 verdi; documentazione (`architecture.md`,
  `build.md`, `agent/README.md`, questo piano) allineata; un commit per fase con
  messaggi nel formato del repo.

---

## 11. Checklist

- [x] W1 `connection_id` stabile (Clone custom) + test
- [x] S1 token WS + schema v3 + migrazione a catena + API e test
- [x] W2 evento risolto + persistenza dei soli frame inoltrati
- [x] W3 test e2e WS (forward/edit/drop/identità) attraverso hudsucker
- [x] W4 sub-tab WebSocket + `ws_list` + reload dal progetto
- [x] AG1 storico conversazione (protocollo v2) + reset al cambio progetto
- [x] AG2 una chiamata con trailer + filtro dello stream + `propose_only`
- [x] AG3 tray di contesto + "Send to Agent" da Proxy e Capture
- [x] AG4 persistenza `agent_runs` + pannello Runs
- [x] AG5 modello/latenza/Propose/Reset in UI
- [x] P1 build PyInstaller + bundle verificato (sidecar nel bundle e protocollo)
- [x] P2 `ca_status` + backend effettivo in `CaDialog` (verifica keychain reale
      rimandata al primo avvio manuale sul bundle)
- [x] P3 decisione su `externalBin`: resta l'overlay (D7), build senza binario
      verificata
- [x] Doc e commit per fase

### Note di esecuzione

- D1–D7 applicate come raccomandato: una chiamata con trailer, solo frame
  inoltrati persistiti, tray con cap 8/8 KiB, protocollo v2, `Clone` custom,
  stitching fuori perimetro, `externalBin` nell'overlay.
- W3: hudsucker 0.25 converte `http://` in `ws://` prima di aprire l'upstream;
  un URI che dice già `ws` viene trattato come sicuro e il connect tenta TLS.
  Il test usa quindi la forma assoluta `GET http://host:port/…` con gli header
  `Upgrade`.
- P1: il catalogo va incluso come dato PyInstaller (`--add-data`), altrimenti
  il binario impacchettato non può proporre nulla.
