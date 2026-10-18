# Piano — Modulo Proxy di Elliot (crate `elliot-proxy`)

> Documento autosufficiente, pensato per essere eseguito in una chat separata.
> Non presuppone la conversazione in cui è nato.

---

## 1. Contesto (per chi esegue da zero)

**Elliot** è un proxy desktop **single-user** per security testing **autorizzato**
(VA/PT), nello spirito di Burp Suite: analisi del traffico con request/response,
attacchi automatizzati multi-punto, editing/replay raw delle request, lavoro
vincolato a uno **scope**, e un agente AI locale che *propone* comandi di tool.

- **Repo:** `/Users/davidhack/Documents/elliot` (monorepo, non ancora committato
  oltre all'initial commit).
- **Stack:** core + guscio desktop in **Rust + Tauri 2**; frontend **TypeScript +
  React** (Vite); agente **Python** (sidecar) che chiama **Ollama**; storage
  **SQLite + SQLCipher** (un file di progetto portabile cifrato).
- **Frontiera di fiducia:** l'agente *propone soltanto*; il core Rust *valida ed
  esegue*. Non rilevante per questo modulo, ma è il principio del progetto.

**Cosa esiste già (build tooling completato):**
- Workspace Cargo alla root (`Cargo.toml`, resolver 2, `[workspace.dependencies]`
  con `serde`, `serde_json`, `tokio` [feat. rt-multi-thread, process, io-util,
  macros], `anyhow`, `thiserror`). Lint condivisi: `unsafe_code = "deny"`,
  `clippy::all = warn`.
- 8 crate core **stub** (solo `//!` doc-comment): `elliot-proxy`, `elliot-scope`,
  `elliot-store`, `elliot-httpraw`, `elliot-repeater`, `elliot-intruder`,
  `elliot-runner`, `elliot-catalog`. Directory `core/<nome>/{Cargo.toml,src/lib.rs}`.
- App Tauri 2 in `app/` + `app/src-tauri/` (compila e parte). Sidecar Python in
  `agent/` (funziona). `cargo build` verde dalla root.
- Toolchain: Rust 1.99 (stable aarch64), macOS 27 arm64, Xcode CLT. **Niente
  OpenSSL/pkg-config** → si usa **rustls**, mai crate che forzano `openssl-sys`.

**Questo piano implementa:** il crate `elliot-proxy` (proxy MITM intercettante) +
il tipo condiviso `Flow` nel crate `elliot-httpraw`, e il cablaggio verso
`scope`, `store` e la UI.

---

## 2. Cosa deve fare il proxy

- Ascolta su una porta **locale** (default `127.0.0.1`); il browser lo usa come
  proxy HTTP.
- Gestisce **HTTP/1.1** in chiaro e **CONNECT** per l'HTTPS (il tunnel).
- Fa **MITM TLS**: CA locale, genera il certificato per-host al volo, lo presenta
  al browser, apre una TLS separata verso il server reale.
- Produce **flow** (coppie request/response) con forma **parsata** + **byte
  grezzi** (ricostruiti, vedi §3).
- Due modalità: **passiva** (osserva e logga) e **intercept** (pausa → edita →
  inoltra/droppa).
- Interroga lo **scope** per decidere cosa loggare/intercettare e cosa lasciar
  passare trasparente.
- Emette i flow verso lo **store** e in **streaming** alla UI.

---

## 3. Decisioni (già risolte — default raccomandati)

1. **Il proxy parsa con un parser HTTP vero.** Cattura traffico reale di un
   browser, che è ben formato. La **malformazione** di request vive nel
   **repeater/intruder** (crate `httpraw`, su TCP grezzo), NON nel proxy.
2. **Libreria MITM: `hudsucker`.** Libreria Rust pensata per proxy MITM
   (hyper + rustls sotto); offre CONNECT, handshake TLS, generazione CA (basata
   su `rcgen`) e gestione WebSocket, con trait di handler per request/response.
   Teniamo il **nostro** tipo `Flow` come modello condiviso.
   - **Trade-off da sapere:** con hudsucker gli handler ricevono il messaggio
     **parsato** (`http::Request`/`Response`). I "byte grezzi" del flow sono
     quindi **ricostruiti** riserializzando il messaggio parsato — fedele per il
     traffico ben formato di un browser, ma **non byte-exact**. Se un domani
     serve fedeltà byte-exact in cattura, si scende a `hyper` + `rustls` +
     `rcgen` fatto a mano. Per ora va benissimo così.
3. **CA: globale, chiave cifrata, installazione esplicita.** Una root CA
   generata **una volta**, **globale** (non per-progetto), chiave privata
   protetta a riposo, mai fuori dalla macchina. L'installazione nel trust store
   del sistema/browser è un'azione **esplicita e guidata** dell'utente. I cert
   per-host sono generati al volo e cachati in memoria.
4. **TLS: rustls** (niente OpenSSL).
5. **Default di sicurezza:** bind solo su `127.0.0.1` (mai `0.0.0.0` → niente
   open proxy); traffico **fuori scope** = **tunnel trasparente senza MITM e
   senza storage** (privacy + meno rumore); verifica dei cert upstream attiva di
   default, con opzione *accept-invalid* esplicita e loggata per target rotti.
6. **Il tipo `Flow` vive in `elliot-httpraw`** (contratto condiviso fra proxy,
   repeater, intruder, store).
7. **Fasatura:** A (passiva + TLS) → B (intercept) → C (HTTP/2) → D (WebSocket).

> Nota per l'esecutore: le API di `hudsucker`/`rustls`/`rcgen` cambiano tra
> versioni. **Verifica la versione corrente e la firma esatta dei trait/builder**
> prima di scrivere; gli snippet qui sotto sono **indicativi**, non copia-incolla
> garantito.

---

## 4. Il tipo `Flow` (crate `elliot-httpraw`)

Definire in `core/httpraw/src/lib.rs` (eventualmente suddiviso in moduli). È il
contratto condiviso; tutti gli altri moduli lo importano.

```rust
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flow {
    pub id: Uuid,
    pub started_at: SystemTime,
    pub completed_at: Option<SystemTime>,
    pub client_addr: SocketAddr,
    pub scheme: Scheme,            // Http | Https
    pub host: String,
    pub port: u16,
    pub request: Request,
    pub response: Option<Response>,
    pub state: FlowState,
    pub scope: ScopeDecision,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub target: String,            // path + query come visto
    pub version: HttpVersion,
    pub headers: Vec<Header>,      // ordinati, preservano ordine e duplicati
    pub body: Bytes,
    pub raw: Bytes,                // byte ricostruiti dal messaggio parsato
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<Header>,
    pub body: Bytes,
    pub raw: Bytes,
}

/// Il valore è `Vec<u8>`: i valori di header possono non essere UTF-8 validi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header { pub name: String, pub value: Vec<u8> }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Scheme { Http, Https }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum HttpVersion { Http10, Http11, H2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState { Pending, Paused, Completed, Dropped, Error }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeDecision { InScope, OutOfScope, Passthrough }
```

- `bytes::Bytes` per body/raw (cheap clone). Per JSON, serde su `Bytes` richiede
  encoding (base64) o si serializza come blob in SQLite; lo store deciderà.
- Dipendenze di `elliot-httpraw`: `serde`, `bytes` (feat. serde), `uuid`
  (feat. v4, serde), eventualmente `http` per i tipi comodi.

---

## 5. API pubblica del crate `elliot-proxy`

```rust
// core/proxy/src/lib.rs (contratto, non implementazione)
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use elliot_httpraw::Flow;

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,     // default 127.0.0.1:8080
    pub ca_dir: std::path::PathBuf,  // dove persistere la CA (lo passa il core)
    pub verify_upstream: bool,       // default true
}

#[derive(Clone, Debug)]
pub enum ProxyEvent {
    FlowStarted(Flow),
    FlowUpdated(Flow),   // es. response arrivata, o stato cambiato
    FlowCompleted(Flow),
    Error(String),
}

/// Interfaccia di scope: il proxy dipende da un trait, non dal crate scope.
pub trait ScopeDecider: Send + Sync {
    fn decide(&self, scheme: &str, host: &str, port: u16, path: &str) -> elliot_httpraw::ScopeDecision;
}

/// Decider banale per la Fase A finché `elliot-scope` non è pronto.
pub struct AllowAll;
impl ScopeDecider for AllowAll { /* -> InScope */ }

pub struct ProxyHandle { /* join handle + canale di stop + controlli intercept */ }
impl ProxyHandle {
    pub fn set_intercept(&self, on: bool);
    pub fn decide(&self, flow_id: uuid::Uuid, decision: InterceptDecision); // Fase B
    pub async fn stop(self);
    pub fn ca_pem(&self) -> String; // per l'installazione guidata
}

pub async fn start(
    config: ProxyConfig,
    scope: Arc<dyn ScopeDecider>,
    events: mpsc::Sender<ProxyEvent>,
) -> anyhow::Result<ProxyHandle>;

pub enum InterceptDecision { Forward, ForwardEdited(Vec<u8>), Drop } // Fase B
```

Il **core** (in `app/src-tauri`, o un crate `elliot-core` dedicato) chiama
`start(...)`, consuma `ProxyEvent` dal canale e li smista verso `store` e verso
la UI (eventi Tauri). Lo `scope` è un trait → in Fase A si passa `AllowAll`, poi
`elliot-scope` implementa `ScopeDecider`.

---

## 6. Struttura interna del crate

```
core/proxy/src/
├── lib.rs          # API pubblica: ProxyConfig, ProxyEvent, start(), ProxyHandle
├── engine.rs       # orchestrazione: avvia hudsucker, instrada eventi, stop
├── handler.rs      # HttpHandler di hudsucker: costruisce Flow, scope, emit, (B) pausa
├── tls/
│   ├── mod.rs
│   ├── ca.rs       # genera/carica la root CA (rcgen/RcgenAuthority), export PEM
│   └── certs.rs    # (se non coperto da hudsucker) cache cert per-host
├── intercept.rs    # (Fase B) registry pendenti + macchina a stati
├── websocket.rs    # (Fase D) WebSocketHandler
└── convert.rs      # http::Request/Response  <->  elliot_httpraw::{Request,Response}
```

Dipendenze di `elliot-proxy` (verificare versioni correnti):
`hudsucker`, `tokio` (workspace), `rustls`/`tokio-rustls` (spesso ri-esportati da
hudsucker), `rcgen` (se non si usa l'authority di hudsucker), `http`, `bytes`,
`uuid`, `serde`/`serde_json` (workspace), `anyhow`, `thiserror`, `tracing`,
`elliot-httpraw` (path), e in Fase B+ `elliot-scope` (path) dal lato core.

---

## 7. Fasi di implementazione

### Fase A — Cattura passiva + MITM TLS (il grosso)

**A1. `elliot-httpraw`:** definire `Flow` e tipi correlati (§4) + helper
`convert` per passare da `http::*` ai tipi serde. `cargo build` verde.

**A2. CA (`tls/ca.rs`):**
- Alla prima esecuzione genera una root CA (cert + chiave) con `rcgen` (o
  l'authority di hudsucker). Persistila in `config.ca_dir` (es. `ca.crt` + chiave).
- **Sicurezza:** la chiave CA è critica. Per ora salvala in una dir protetta
  dell'app (permessi `600`). **TODO di hardening** (task separato): cifratura a
  riposo / OS Keychain del macOS — da fare quando esiste la gestione chiavi del
  progetto. Documentare il TODO nel codice.
- Esporre `ca_pem()` per l'installazione guidata lato UI.

**A3. Handler passivo (`handler.rs`):**
- Implementa `HttpHandler` di hudsucker.
- In `handle_request`: costruisci un `Flow` (nuovo `id`), estrai method/target/
  version/headers/body, ricostruisci `raw` via `convert`, consulta
  `scope.decide(...)`:
  - `OutOfScope` → NON loggare, NON decifrare oltre il necessario: lascia passare
    (idealmente tunnel trasparente; con hudsucker, almeno non emettere eventi né
    salvare).
  - `InScope` → emetti `ProxyEvent::FlowStarted(flow)` sul canale.
  - inoltra la request upstream (ritorno `RequestOrResponse::Request`).
- In `handle_response`: completa il `Flow` con la response (status/headers/body/
  raw), stato `Completed`, emetti `FlowCompleted`.
- Clona il `mpsc::Sender<ProxyEvent>` e l'`Arc<dyn ScopeDecider>` dentro l'handler.

**A4. Engine + `start()` (`engine.rs`, `lib.rs`):**
- Costruisci il proxy hudsucker: indirizzo di ascolto, client rustls, authority
  (CA), handler. Avvialo come task tokio; restituisci `ProxyHandle` (con canale
  di stop).
- `listen_addr` default `127.0.0.1:8080`.

**Verifica Fase A:**
- Unit: `start()` fa il bind senza errori; `OutOfScope` non emette eventi.
- Manuale con curl (CA esportata su `ca.pem`):
  ```bash
  curl -x http://127.0.0.1:8080 https://example.com --cacert ca.pem -s -o /dev/null -v
  ```
  → nel log/eventi compare un `Flow` per `example.com` con request e response.
- Manuale con browser: configurare il proxy su `127.0.0.1:8080`, installare la CA
  nel trust store, visitare un sito HTTPS → i flow vengono catturati.

### Fase B — Modalità intercept

- `intercept.rs`: `HashMap<Uuid, oneshot::Sender<InterceptDecision>>` dei flow in
  pausa, dietro `Mutex`/`RwLock`.
- Nell'handler, se `set_intercept(true)` e flow `InScope`: imposta stato
  `Paused`, emetti `FlowUpdated`, crea un `oneshot`, registra il sender,
  **await** sul receiver. La UI chiama `ProxyHandle::decide(flow_id, decision)`
  che invia sul sender.
- `Forward` → prosegui; `ForwardEdited(bytes)` → ri-parsa i byte editati in una
  request e prosegui; `Drop` → stato `Dropped`, rispondi al client con una
  risposta minima (o chiudi), emetti `FlowCompleted`.
- **Verifica:** con intercept on, una navigazione resta in pausa finché non si
  invia la decisione; `Drop` interrompe; `ForwardEdited` modifica la request a
  valle.

### Fase C — HTTP/2

- Abilitare h2 nel client/relay hudsucker (spesso trasparente). Mappare la
  versione su `HttpVersion::H2` nel `Flow`.
- **Verifica:** un sito solo-h2 viene catturato con `version = H2`.

### Fase D — WebSocket

- Implementare il `WebSocketHandler` di hudsucker: catturare i messaggi WS
  (direzione, payload) come parte del flow o come flow dedicato.
- **Verifica:** una connessione WS mostra i messaggi catturati.

---

## 8. Cablaggio nel core / app (contratto, task a valle della Fase A)

- Il core avvia il proxy, consuma `ProxyEvent` e li smista: `store.upsert(flow)`
  + `app.emit("proxy://flow", flow)` verso il frontend.
- **Comandi Tauri** (`app/src-tauri`): `proxy_start(config)`, `proxy_stop()`,
  `proxy_set_intercept(bool)`, `proxy_intercept_decide(flow_id, decision)`,
  `proxy_get_ca_pem()`.
- **Frontend (schermata Proxy):** sottoscrive `proxy://flow`, lista virtualizzata
  dei flow, dettaglio request/response, controlli di intercept e un bottone
  "Installa certificato CA" con istruzioni guidate. (Dettaglio UI = task proprio.)

---

## 9. Test end-to-end

1. Avviare il core con il proxy su `127.0.0.1:8080`.
2. Esportare/installare la CA; verificare con `curl -x ... --cacert ca.pem` e con
   un browser reale.
3. Verificare: flow catturati con request+response; host fuori scope non loggati;
   (Fase B) intercept che mette in pausa, inoltra edita, droppa; (C) h2; (D) WS.

---

## 10. Note di sicurezza (non negoziabili)

- **Bind solo su loopback** (`127.0.0.1`), mai `0.0.0.0`: niente open proxy.
- **Chiave CA** = capacità di intercettare TLS → protetta (permessi stretti ora,
  cifratura/Keychain come TODO di hardening), generata localmente, mai esportata
  se non il **certificato pubblico** per l'installazione.
- **Fuori scope = passthrough trasparente**, senza decifrare né salvare (privacy).
- **Verifica cert upstream** attiva di default; *accept-invalid* solo esplicito e
  loggato.
- L'installazione della CA nel trust store è **un'azione dell'utente**, guidata,
  mai silenziosa.

---

## 11. Fuori scope (per questo piano)

- DSL dei filtri stile Wireshark (a valle, quando c'è traffico da filtrare).
- Repeater/Intruder (altri crate; condividono solo il tipo `Flow`).
- Persistenza reale su SQLCipher (è del crate `store`; qui si emette solo il
  `Flow`).
- Cifratura a riposo della chiave CA (TODO di hardening separato).
- Dettaglio della UI della schermata Proxy (task proprio; qui si definisce solo
  il contratto di eventi/comandi).
```
