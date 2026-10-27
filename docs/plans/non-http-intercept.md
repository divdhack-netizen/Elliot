# Piano — Intercettazione generica non-HTTP (TCP/UDP) + lavoro attivo

> Documento **autosufficiente**, pensato per essere eseguito in una chat separata.
> Non presuppone la conversazione in cui è nato. Aggiunge a Elliot la capacità di
> **catturare, filtrare e manipolare attivamente** traffico non-HTTP (TCP e UDP),
> portandolo su repeater e intruder, senza rompere il proxy HTTP esistente.

> **Stato al 27 ottobre 2026 — piano implementato (G1→G9).** Modello
> `Stream`/`Message`, crate `elliot-socks` (CONNECT, MITM TLS, UDP ASSOCIATE), CA
> condivisa in `elliot-tls`, repeater con `Transport`/`ReadMode`, intruder su
> stream generici, store schema v2 con migrazione, cablaggio Tauri (`socks_*`,
> `repeater_send`, `intruder_run`, `send_to_*`) e schermate Capture/Repeater/
> Intruder sono nel repository. I **test end-to-end già presenti** sono elencati in
> **§8.1**; lo stato fase per fase è in **§6.0**. Le estensioni opzionali G-DISS,
> G-FILT e G-SESS non sono implementate.
>
> Il §1.1 resta la fotografia **pre-piano** (utile come storico: descrive com'era
> il codice prima di questo lavoro). Per lo stato attuale valgono questa nota,
> §6.0 e §8.1.

---

## 1. Contesto (per chi esegue da zero)

**Elliot** è un proxy desktop **single-user** per security testing **autorizzato**
(VA/PT), nello spirito di Burp Suite. Monorepo in `/Users/davidhack/Documents/elliot`.

- **Stack:** core **Rust** (workspace Cargo alla root); guscio **Tauri 2** in
  `app/src-tauri`; frontend **React/TS** in `app/src`; agente **Python** (sidecar,
  non toccato da questo piano); storage **SQLite + SQLCipher**.
- **Toolchain:** Rust stable, macOS arm64, Xcode CLT. **Niente OpenSSL/pkg-config
  di sistema** sul lato rete → **rustls** (provider `aws-lc-rs`); unica eccezione
  lo `store` (SQLCipher con OpenSSL **vendored statico**).
- **Principi non negoziabili:** bind **solo loopback** (mai open proxy); **scope =
  fonte di verità unica**; chiave CA = segreto (mai esportata se non il cert
  pubblico); `#![deny(unsafe_code)]`; **clippy `-D warnings`**; esecuzione tool via
  argv mai shell (riguarda il runner, non questo piano).

**Build & test (a ogni fase):**
```bash
source "$HOME/.cargo/env"
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### 1.1 Stato pre-piano (verificato nel codice, prima di questo lavoro)

> Fotografia di partenza, tenuta come storico. Per lo stato attuale: §6.0 (fasi) e
> §8.1 (test end-to-end presenti).

| elemento | stato | simboli reali da riusare |
|---|---|---|
| `elliot-httpraw` | modello condiviso | `Flow`, `Request`/`Response`, `Header`, enum (`Scheme`, `HttpVersion`, `FlowState`, `ScopeDecision`), trait `ScopeDecider` (+ `AllowAll`/`DenyAll`), `WsMessage`/`WsDirection`, modulo **`pub mod net`** (`split_host_port`, `target_locus`) |
| `elliot-scope` | motore policy, **cattura-tutto di default** | `ScopePolicy`, `Rule`, matcher host esatto/suffisso; implementa `ScopeDecider` |
| `elliot-proxy` | MITM **HTTP/S** su `hudsucker` | `ProxyEvent` (`FlowStarted/Updated/Completed/WebSocket/Error`), `start()`, `ProxyHandle`; **CA** in `core/proxy/src/tls/ca.rs`: `Ca::load_or_create(dir)`, `cert_pem()`, `into_issuer() -> rcgen::Issuer<'static, KeyPair>` |
| `elliot-tls` | politica TLS condivisa | `verified_client_config()`, `insecure_client_config()`, `client_config(bool)`, `connector(bool)` — **NON** contiene ancora la CA/minting dei cert per-host |
| `elliot-repeater` | client raw TCP/TLS | `RepeatRequest { host, port, tls, raw: Bytes, read_timeout, accept_invalid_certs }`, `send(RepeatRequest) -> RepeatResponse`; framing della response **HTTP-oriented** (Content-Length/chunked/EOF) |
| `elliot-intruder` | attacchi multi-punto | `Attack { host, port, tls, base: Bytes, positions: Vec<Range<usize>>, payloads: Vec<Vec<Payload>>, mode, concurrency, read_timeout, accept_invalid_certs }`, `pub type Payload = Vec<u8>` (**già byte**), `AttackMode::{Sniper,BatteringRam,Pitchfork,ClusterBomb}`, `run()` concorrente via repeater |
| `elliot-store` | file progetto SQLCipher **schema v1** | `Store::{create,open,upsert_flow,get_flow,list_flows,count_flows}`, `SCHEMA_VERSION = 1` |
| `app/src-tauri` | cablato: **proxy + scope + file progetto** | comandi `proxy_*`, `scope_*`, `project_*`; repeater/intruder/runner/catalog/agente **non** cablati |

**Conseguenza chiave (perché questo piano è fattibile a costo contenuto):**
`elliot-repeater` è già *invio raw di byte su TCP/TLS + lettura risposta*, e
`elliot-intruder` muta **range di byte** su un `base: Bytes` con payload **già
`Vec<u8>`**. Sono **già protocollo-agnostici**. Il grosso del lavoro non è
riscriverli, ma: (a) **catturare** il traffico non-HTTP, (b) dargli un **modello
`Stream`/`Message`** generico, (c) estendere il repeater con framing non-HTTP e
UDP.

---

## 2. Obiettivo e definizione di "lavoro attivo"

1. **Catturare** connessioni TCP (e datagrammi UDP) arbitrari, non solo HTTP.
2. **Filtrare** ciò che è catturato per trasporto/host/porta (e, in fase opzionale,
   per campi via dissector e DSL).
3. **Lavorare attivamente**: da un messaggio catturato poter fare *"invia al
   Repeater"* (ri-mandare byte editati e vedere la risposta) e *"invia
   all'Intruder"* (injection point a range di byte, payload set, modi).

"Lavoro attivo" dipende dalla **forma** del protocollo:
- **richiesta/risposta orientato al messaggio** (DNS, Redis, molti RPC, protocolli
  a righe): mappa diretta su repeater/intruder → supportato dall'MVP;
- **UDP** (datagramma): singolo datagramma facile da rimandare, risposta con
  correlazione più debole → supportato, con caveat;
- **stateful/handshake/streaming** (SSH, DB con auth, long-lived): il singolo
  messaggio da solo non basta → serve **session-replay** (fase dedicata, G-SESS).

---

## 3. Decisioni architetturali (con motivazione)

**D1 — Meccanismo di cattura: server SOCKS5 su loopback (nuovo crate `elliot-socks`).**
Perché SOCKS5 e non un transparent proxy: SOCKS5 è cross-platform, non richiede
privilegi/redirezione di pacchetti a livello OS (pf/iptables), ed è il modo con
cui app/OS/`proxychains`/mobile instradano traffico arbitrario. Supporta
**CONNECT** (TCP) e **UDP ASSOCIATE** (UDP). È l'approccio di Burp+NoPE /
InterceptSuite. Il **proxy HTTP esistente resta** (hudsucker): SOCKS è un
*secondo listener* generico, non lo sostituisce.
> Il bind resta **solo loopback**; nessuna autenticazione di default (ascolta solo
> su 127.0.0.1), con opzione user/pass come hardening.

**D2 — Modello dati generico `Stream`/`Message` in `elliot-httpraw`.**
Il `Flow` è HTTP-shaped e va tenuto. Accanto, un modello trasporto-agnostico
condiviso (contratto per socks, repeater, intruder, store, UI). Vedi §4.

**D3 — Decisione di scope identica al proxy.** Lo scope è già host/porta e
cattura-tutto di default. Su CONNECT/UDP si consulta `ScopeDecider`:
`OutOfScope`/`Passthrough` → **tunnel trasparente** (relay senza cattura né
MITM); `InScope` → cattura. Per filtrare *per trasporto* si potrà estendere
`SchemeMatch` con `Tcp`/`Udp` (fase opzionale, non necessaria all'MVP: oggi si
passa `scheme="tcp"|"udp"` e `SchemeMatch::Any` matcha).

**D4 — MITM TLS generico opzionale, con CA condivisa.** Dopo il CONNECT si
"sbircia" il primo record client: se è un **TLS ClientHello** (`0x16 0x03`) e il
MITM-TLS è abilitato per quel target, si terminano due TLS (verso client con cert
per-host firmato dalla CA, verso server reale) e si cattura il **chiaro
applicativo**; altrimenti si fa relay dei byte **opachi**. Serve **condividere la
CA**: oggi vive in `core/proxy/src/tls/ca.rs`. **Spostare `Ca` in `elliot-tls`**
ed esporre un *minting* di cert per-host (rcgen) riusabile sia da hudsucker
(HTTP) sia dal path SOCKS. Vedi G3.

**D5 — Repeater esteso con framing non-HTTP e UDP (retro-compatibile).**
Aggiungere un `ReadMode` esplicito; default per non-HTTP = *until idle*. Vedi G5.
`RepeatRequest` guadagna `transport: Transport` e `read_mode: ReadMode` con default
che preservano il comportamento HTTP attuale.

**D6 — Intruder: già byte-generico.** Serve solo che la `base` provenga da un
`Message` e che `Attack` erediti `transport`/`read_mode` dal repeater esteso.

**D7 — Dissector come layer opzionale (fase G-DISS).** Un trait che trasforma byte
in campi etichettati per display e per injection point *a campo* invece che a
offset. Nessun dissector nell'MVP (si lavora a byte, come i capture-filter di
Wireshark prima della dissezione).

**D8 — DSL di filtro display (fase G-FILT, opzionale).** Linguaggio stile barra
Wireshark valutabile **sia** su `Flow` **sia** su `Stream` (campi: `transport`,
`host`, `port`, `tls`, `direction`, `len`, `contains`). Crate `elliot-filter`
(Rust, testabile, condiviso UI/store). Niente regex catastrofiche
(safe-by-construction).

**D9 — Store schema v2 con migrazione.** Nuove tabelle `streams` + `messages`.
Bump `SCHEMA_VERSION` 1→2 con migrazione idempotente all'apertura.

---

## 4. Modello `Stream`/`Message` (in `elliot-httpraw`)

Aggiungere a `core/httpraw/src/lib.rs` (serde, come gli altri tipi):

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport { Tcp, Udp }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction { ClientToServer, ServerToClient }

/// Una connessione (TCP) o un'associazione (UDP) catturata dal listener SOCKS.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stream {
    pub id: Uuid,
    pub started_at: SystemTime,
    pub completed_at: Option<SystemTime>,
    pub client_addr: SocketAddr,
    pub transport: Transport,
    pub host: String,
    pub port: u16,
    /// true se il contenuto catturato è il chiaro applicativo dietro un MITM TLS.
    pub tls: bool,
    pub scope: ScopeDecision,
    pub state: FlowState,          // riusa l'enum esistente (Pending/Completed/Error/…)
    pub error: Option<String>,
}

/// Un messaggio/datagramma osservato su uno Stream. I byte sono grezzi.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub stream_id: Uuid,
    pub seq: u64,                  // ordine all'interno dello stream
    pub at: SystemTime,
    pub direction: Direction,
    pub data: Bytes,
}
```

> Nota: `WsDirection` esiste già; **non** fonderla in questa fase per non toccare
> `elliot-proxy`. Opzionale (fase cleanup): unificare `WsDirection` → `Direction`.

Aggiungere test di (de)serializzazione minimi.

---

## 5. Nuovi/ modificati crate

```
core/socks/            # NUOVO — elliot-socks: server SOCKS5 + cattura
core/tls/              # elliot-tls: + CA condivisa e minting cert per-host (da proxy)
core/httpraw/          # + Stream/Message/Transport/Direction
core/repeater/         # + Transport, ReadMode, UDP
core/intruder/         # + transport/read_mode ereditati; base da Message
core/store/            # + tabelle streams/messages, schema v2 + migrazione
core/filter/           # NUOVO (opz, G-FILT) — elliot-filter: DSL display
app/src-tauri/         # + comandi socks_*, repeater_*, intruder_*, send-to-*
app/src/               # + viste capture/repeater/intruder
```
Aggiornare i `members` del workspace in `/Cargo.toml` per i nuovi crate.

---

## 6. Fasi di implementazione

> Ogni fase: **compila**, `cargo test --workspace` verde, `clippy -D warnings`
> pulito, un commit `feat(<area>): …`. Le fasi G1→G7 sono il nucleo; G8/G9 sono il
> cablaggio+UI; G-DISS/G-FILT/G-SESS sono estensioni.

### 6.0 Stato di implementazione (aggiornato al 27 ottobre 2026)

| fase | stato | dove |
|---|---|---|
| G1 — modello `Stream`/`Message` | ✅ | `core/httpraw/src/lib.rs` |
| G2 — `elliot-socks` CONNECT + cattura | ✅ | `core/socks/src/{lib,relay,protocol}.rs`, test in `core/socks/tests/tcp.rs` |
| G3 — CA condivisa + MITM TLS | ✅ | `core/tls/src/ca.rs` (`Ca::leaf_for_host`), MITM nel listener, test in `core/socks/tests/tcp.rs` |
| G4 — UDP ASSOCIATE | ✅ | `core/socks/src/lib.rs`, test in `core/socks/tests/udp.rs` |
| G5 — repeater generico | ✅ | `core/repeater/src/lib.rs` (`Transport`, `ReadMode`) |
| G6 — intruder su stream generici | ✅ | `core/intruder/src/lib.rs` (`transport`/`read_mode`, `run_streaming`) |
| G7 — store v2 + migrazione | ✅ | `core/store/src/lib.rs` (`SCHEMA_VERSION = 2`, `migrate_v1_to_v2`) |
| G8 — cablaggio Tauri | ✅ | `app/src-tauri/src/{socks,replay}.rs` |
| G9 — UI Capture/Repeater/Intruder | ✅ | `app/src/{capture,repeater,intruder}/` |

**G-DISS**, **G-FILT** e **G-SESS** non sono implementate. I test end-to-end che
coprono il percorso completo sono in **§8.1**.

### G1 — Modello `Stream`/`Message` in httpraw
- Implementare §4 + test.
- **Verifica:** round-trip serde; workspace verde.

### G2 — `elliot-socks`: server SOCKS5 CONNECT (solo TCP, no TLS) con cattura
- Nuovo crate. Dipendenze: `tokio` (net, io-util, macros, rt), `bytes`, `uuid`,
  `thiserror`, `tracing`, `elliot-httpraw` (modello + `ScopeDecider`).
- Implementare un **SOCKS5 minimale** a mano (è un protocollo piccolo):
  - handshake metodi (supportare `0x00` no-auth; opzionale `0x02` user/pass);
  - richiesta `CONNECT` (`CMD=0x01`), address types `IPv4`/`DOMAIN`/`IPv6`;
  - risolvere/connettere upstream; rispondere con reply SOCKS.
- API pubblica (speculare a `elliot-proxy`):
  ```rust
  pub struct SocksConfig { pub listen_addr: SocketAddr, /* loopback */ pub mitm_tls: bool, pub ca_dir: PathBuf }
  pub enum StreamEvent { StreamStarted(Stream), Message(Message), StreamCompleted(Stream), Error(String) }
  pub async fn start(cfg: SocksConfig, scope: Arc<dyn ScopeDecider>, events: mpsc::Sender<StreamEvent>) -> anyhow::Result<SocksHandle>;
  pub struct SocksHandle { /* stop */ }
  ```
- Per connessione CONNECT: `scope.decide("tcp", host, port, "")`.
  - non `InScope` → **splice trasparente** bidirezionale, nessun evento, nessuna
    cattura;
  - `InScope` → `StreamStarted`; relay bidirezionale che, a ogni blocco letto,
    emette `Message { direction, data }` e inoltra; a chiusura `StreamCompleted`.
- **Rifiutare il bind non-loopback** (come fa `elliot-proxy::start`).
- **Verifica:**
  - unit: parsing dell'handshake e della request SOCKS5 (vettori di byte noti);
  - integrazione: server TCP "echo" locale + `curl --socks5-hostname 127.0.0.1:PORT http://127.0.0.1:ECHO` *oppure* un client SOCKS minimale nel test → arrivano `StreamStarted` + `Message` c→s e s→c + `StreamCompleted`;
  - out-of-scope: con scope ristretto a un altro host, nessun evento ma il byte-relay funziona (tunnel).

### G3 — CA condivisa + MITM TLS opzionale nel path SOCKS
- **Spostare** `Ca` da `core/proxy/src/tls/ca.rs` a `elliot-tls` (es.
  `elliot_tls::Ca`), mantenendo `load_or_create`, `cert_pem`, `into_issuer`, e
  aggiungendo un **minter per-host**: `fn leaf_for_host(&self, host: &str) ->
  (CertificateDer, PrivateKeyDer)` (rcgen, firmato dalla CA). Aggiornare
  `elliot-proxy` perché usi `elliot_tls::Ca` (ri-export o path) senza cambiare la
  sua API pubblica.
- In `elliot-socks`, se `cfg.mitm_tls` e il primo record del client è un
  ClientHello (`data[0]==0x16 && data[1]==0x03`):
  - terminare TLS verso il client con un `rustls::ServerConfig` che usa un cert
    per-host appena mintato;
  - aprire TLS verso l'upstream con `elliot_tls::client_config(accept_invalid)`;
  - relay + cattura come in G2, ma sui **byte applicativi decifrati** (`tls=true`
    nello `Stream`).
  - altrimenti relay opaco (`tls=false`), come G2.
- **Sicurezza:** la chiave CA resta segreta; nessun MITM per target non `InScope`
  (già tunnelati prima della sbirciata TLS).
- **Verifica:** server TLS self-signed locale (rcgen nel test) raggiunto via SOCKS
  con `mitm_tls=true` → i `Message` catturati sono in **chiaro**; con
  `mitm_tls=false` → opachi (cifrati).

### G4 — UDP ASSOCIATE (datagrammi)
- Implementare `CMD=0x03` (UDP ASSOCIATE): aprire un socket UDP relay su loopback,
  incapsulare/decapsulare l'header SOCKS UDP, inoltrare i datagrammi verso il
  target e indietro, emettendo un `Message` per datagramma (direzione + data) su
  uno `Stream { transport: Udp }`.
- Correlazione risposta: best-effort (per coppia client/target); documentare che
  UDP è connectionless e la correlazione è euristica.
- **Verifica:** un resolver DNS locale fittizio o un echo UDP locale raggiunto via
  SOCKS UDP → datagrammi catturati nei due versi.

### G5 — Repeater generico (framing non-HTTP + UDP)
- In `core/repeater/src/lib.rs`:
  - aggiungere `pub enum Transport { Tcp, Udp }` (o riusare quello di httpraw) e
    `pub enum ReadMode { Http, UntilIdle(Duration), Exact(usize), UntilClose, Datagram }`;
  - `RepeatRequest` guadagna `transport: Transport` e `read_mode: ReadMode`, con
    **default** `Tcp` + `ReadMode::Http` (comportamento attuale invariato →
    nessuna regressione);
  - implementare i nuovi `ReadMode` per TCP (idle-timeout, exact N byte, fino a
    chiusura) e il path **UDP** (send datagramma, `recv` con timeout →
    `Datagram`).
- **Verifica:** test con server TCP che risponde senza header HTTP (UntilIdle);
  Exact(N); UDP echo; i test HTTP esistenti restano verdi.

### G6 — Intruder su stream generici
- `Attack` eredita `transport` e `read_mode` e li passa al repeater; `base` può
  provenire da un `Message.data`. I modi e il motore concorrente restano.
- **Verifica:** attacco BatteringRam su un server TCP non-HTTP locale con
  `ReadMode::UntilIdle` → risultati raccolti; test esistenti verdi.

### G7 — Store schema v2: `streams` + `messages` + migrazione
- `SCHEMA_VERSION = 2`. In `open`, se `user_version == 1` eseguire la migrazione
  (CREATE TABLE streams/messages + indici) e portare a 2; `create` parte già a 2.
- Tabelle:
  - `streams(id TEXT PK, started_at, completed_at, client_addr, transport, host, port, tls, scope, state, error)`;
  - `messages(id TEXT PK, stream_id TEXT, seq INTEGER, at INTEGER, direction TEXT, data BLOB, FOREIGN KEY(stream_id) REFERENCES streams(id))` + indice su `(stream_id, seq)`.
- Metodi: `upsert_stream`, `append_message`, `list_streams(limit)`,
  `messages_for(stream_id)`. Riusare i token enum di httpraw (come per `Flow`).
- **Verifica:** round-trip stream+messaggi; apertura di un file v1 → migrato a v2
  (test che crea un v1 "a mano" via PRAGMA e poi apre).

### G8 — Cablaggio app (Tauri)
- Dipendenze di `elliot-app`: aggiungere `elliot-socks`, `elliot-repeater`,
  `elliot-intruder`.
- Comandi: `socks_start(listen_addr, mitm_tls)`, `socks_stop`, pump eventi
  `socks://stream` (speculare al pump `proxy://flow`, con persistenza nello
  `store` via `upsert_stream`/`append_message` — **colmando anche il gap attuale
  di persistenza**); `repeater_send(req)`; `intruder_run(attack)` con streaming
  risultati; `send_to_repeater(stream_id, message_id)` /
  `send_to_intruder(...)` che costruiscono `RepeatRequest`/`Attack` dai byte del
  `Message` + (host, port, tls, transport) dello `Stream`.
- **Verifica:** `cargo check -p elliot-app`; percorso completo coperto dal test
  end-to-end in `app/src-tauri/src/replay.rs` (vedi §8.1) più lo smoke manuale
  della UI (vedi §8.2).

### G9 — UI (React)
- Vista **Capture** (o estensione della schermata Proxy) che mostra `Flow` HTTP
  **e** `Stream` generici; **viewer esadecimale/byte** per i `Message`; filtro per
  trasporto/host/porta; azioni **"Send to Repeater/Intruder"**.
- Implementare davvero i tab **Repeater** e **Intruder** (oggi stub in
  `app/src/App.tsx`): editor byte/hex + invio + risposta; base + injection point +
  payload set + modo + tabella risultati.
- **Verifica:** `npm run build` (tsc) ok; prova manuale end-to-end.

### G-DISS (opzionale) — Dissector
- Trait `Dissector { fn dissect(&self, data: &[u8]) -> DissectedView }` con 1–2
  esempi (es. text/line-based; DNS). Abilita injection point **a campo** e display
  strutturato. Nessun impatto sull'MVP.

### G-FILT (opzionale) — DSL di filtro display
- Crate `elliot-filter`: grammatica ridotta stile Wireshark (`transport == tcp`,
  `port == 53`, `host contains "example"`, `tls`, `len > 100`,
  `direction == c2s`), parser + valutatore su `Flow` e `Stream`. Niente regex
  catastrofiche. Usato da store (query) e UI (barra filtri).
- **Verifica:** unit test del parser/valutatore su casi noti.

### G-SESS (opzionale, protocolli stateful) — Session-replay nel repeater
- Un `SessionRepeater` che, data una sequenza di `Message` client→server
  catturati, **rigioca il prefisso** (handshake/auth) prima del messaggio editato,
  mantenendo la connessione aperta, così i protocolli stateful (SSH, DB con auth)
  diventano manipolabili. Definire `SessionPlan { prelude: Vec<Message>, edited:
  Message, read_mode }`.
- **Verifica:** server TCP stateful fittizio che accetta solo dopo un "hello".

---

## 7. Sicurezza (non negoziabile)

- **Bind solo loopback** sia per il listener SOCKS sia per il relay UDP; rifiutare
  indirizzi non-loopback (come `elliot-proxy::start`).
- **Scope gate prima della cattura e prima del MITM:** fuori scope = tunnel
  trasparente, nessuna decifratura, nessuna persistenza (privacy).
- **Chiave CA** condivisa: resta segreta, generata localmente, mai esportata se
  non il cert pubblico; resta il TODO di hardening (cifratura a riposo/Keychain)
  già annotato in `ca.rs`.
- **UDP:** attenzione all'amplificazione/spoofing; relay solo su loopback e solo
  per target in scope.
- Nessun `unsafe`; nessun open proxy; nessuna auth-bypass.

---

## 8. Verifica end-to-end

### 8.1 Test automatizzati già presenti

Girano con `cargo test --workspace` (oppure per crate: `cargo test -p
elliot-socks`, `cargo test -p elliot-repeater`, `cargo test -p elliot-intruder`,
`cargo test -p elliot-store`, `cargo test -p elliot-app`). Nessuno richiede rete
o servizi esterni: origini e client sono avviati dai test su `127.0.0.1:0`.

**`core/socks/tests/tcp.rs` — cattura TCP end-to-end**, con un client SOCKS5
scritto a mano (`core/socks/tests/support/mod.rs`) e origini reali:

| test | cosa dimostra |
|---|---|
| `captures_both_directions_of_a_tcp_stream` | CONNECT → `StreamStarted`, `Message` c→s e s→c con i byte esatti, `StreamCompleted` |
| `out_of_scope_traffic_is_tunnelled_but_not_captured` | target fuori scope: relay trasparente, **nessun** evento (privacy) |
| `mitm_tls_captures_the_application_plaintext` | origine TLS self-signed: si cattura il **chiaro** applicativo, `tls = true` |
| `without_mitm_tls_the_bytes_are_captured_opaque` | senza MITM si catturano i byte cifrati |
| `credentials_are_required_when_configured` | RFC 1929: senza le credenziali giuste nessun tunnel |
| `unsupported_commands_are_answered_with_the_right_code` | BIND e comandi ignoti → reply SOCKS corretta |
| `an_unreachable_target_becomes_a_socks_error_reply` | errore di connessione → reply SOCKS, non un close silenzioso |
| `stopping_the_listener_completes_open_streams` | `SocksHandle::stop()` non lascia stream `Pending` |

**`core/socks/tests/udp.rs` — UDP ASSOCIATE:**

| test | cosa dimostra |
|---|---|
| `udp_associate_forwards_and_captures_both_directions` | un'associazione → uno `Stream { transport: Udp }`, un `Message` per datagramma nei due versi |
| `out_of_scope_datagrams_are_dropped_and_never_captured` | gating dello scope per singolo datagramma |
| `a_datagram_from_an_unknown_source_is_never_forwarded_to_the_client` | nessun inoltro di risposte non sollecitate |
| `fragmented_datagrams_are_dropped_without_ending_the_association` | frammenti scartati, associazione ancora viva |

**`app/src-tauri/src/replay.rs` — il percorso completo dell'app, senza UI.**
`a_socks_capture_is_persisted_and_replayed_by_the_repeater` attraversa, in
ordine: client SOCKS5 reale → listener `elliot_socks::start` → pump di
persistenza del guscio (`socks::persist_stream`/`persist_message`, gli stessi
chiamati da `socks_start`) → progetto **cifrato** creato con
`ScopeState::create_project` → rilettura dal `Store` (`get_stream`,
`messages_for`) → hand-off `RepeatArgs::from_capture` →
`elliot_repeater::send`. L'origine parla un protocollo a righe (niente HTTP),
quindi verifica anche che il replay sia incorniciato dal read mode (`untilIdle`)
e che una risposta non-HTTP produca `raw` esatto con `response = None`.
Copre i punti 5 e 7 dello smoke manuale (il punto 3 resta la conferma con un
client vero, eseguita a mano).

Altre verifiche "dal byte al socket", a valle del listener: in
`core/repeater/src/lib.rs` (`until_idle_reads_a_reply_without_http_framing`,
`exact_reads_exactly_the_requested_length`,
`udp_replay_sends_and_receives_one_datagram`), in `core/intruder/src/lib.rs`
(`battering_ram_runs_and_collects_results`,
`battering_ram_runs_against_a_non_http_protocol`,
`run_streaming_hands_every_result_to_the_callback`,
`out_of_scope_target_sends_nothing`) e in `core/store/src/lib.rs`
(`streams_and_messages_round_trip`, `udp_streams_and_ordering_survive_a_reopen`,
`a_v1_file_is_migrated_to_v2_and_keeps_its_data`).

**Non ancora automatizzato** (resta smoke manuale, §8.2): l'attacco Intruder
lanciato *dai byte di un `Message` catturato* passando per i comandi Tauri
(l'esecuzione dell'intruder è coperta contro origini locali, la mappatura
`send_to_intruder` → `Attack` è coperta da unit test, ma le due cose non sono
ancora legate in un unico test) e il percorso del proxy HTTP (test preesistenti:
`core/proxy/tests/smoke.rs`, `scope_live.rs`, `upstream_verification.rs`).

### 8.2 Smoke manuale

I punti marcati ✔ sono già coperti da §8.1: servono come conferma a mano della
UI, non come unica verifica.

1. Avviare l'app; creare/aprire un progetto (passphrase).
2. Avviare il listener SOCKS dalla schermata Capture (es. `127.0.0.1:1080`),
   `mitm_tls` on.
3. Puntare un client al SOCKS: `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
   (HTTP su SOCKS, per sanity) e un client **non-HTTP** (es. `redis-cli` via
   `proxychains`, o `dig` per UDP) verso un target **in scope**.
4. Attese: nella vista Capture compaiono gli `Stream` con i `Message` nei due
   versi; fuori scope → niente cattura ma la connessione funziona.
5. ✔ "Send to Repeater" su un messaggio → editarlo → inviarlo → vedere la risposta.
6. "Send to Intruder" → injection point a byte + payload set → eseguire → tabella
   risultati con metriche.
7. ✔ Riaprire il progetto → gli stream catturati sono **persistiti** (store v2).

> Smoke già eseguito una volta a mano: `curl --socks5-hostname` attraverso il
> listener verso un `python3 -m http.server` locale, con cattura confermata nei
> due versi. La ricetta resta valida per ricontrollare la UI dopo modifiche.

---

## 9. Decisioni aperte (DA CONFERMARE prima/durante l'esecuzione)

- **A — Perimetro dell'MVP:** G1–G3+G5–G8 (TCP + MITM TLS + repeater, senza UDP e
  senza UI completa) come primo traguardo utile? Oppure includere subito UDP (G4)
  e/o la UI (G9)?
- **B — MITM TLS nell'MVP o dopo:** G3 è il pezzo più delicato (CA condivisa +
  due TLS). Se si vuole un primo risultato rapido, G2→G5→G6 (solo byte opachi) e
  G3 subito dopo.
- **C — Scope per trasporto:** estendere `SchemeMatch` con `Tcp`/`Udp` ora o
  lasciare `Any` (basta per l'MVP)?
- **D — DSL di filtro (G-FILT):** in Rust (`elliot-filter`, condiviso/testabile) o
  solo lato frontend? E con quale sottoinsieme di operatori?
- **E — Dissector (G-DISS):** quali protocolli come primi esempi (DNS? Redis?
  text/line-based)?
- **F — Session-replay (G-SESS):** quando serve davvero (quali protocolli
  stateful target)?
- **G — Rapporto col proxy HTTP:** il SOCKS resta un listener **separato** (scelta
  di questo piano) o in futuro si unifica l'ingestione (HTTP riconosciuto sopra lo
  stream generico via dissector)?

---

## 10. Checklist finale

- [x] `cargo test --workspace` verde, inclusi i test end-to-end di §8.1
      (httpraw/socks/repeater/intruder/store/app).
- [x] `cargo clippy --workspace --all-targets -- -D warnings` senza output.
- [x] `cargo check -p elliot-app` verde.
- [x] Nessun `unsafe`; bind solo loopback (socks + UDP) — rifiuto del bind
      non-loopback coperto da test — e scope gate verificato (fuori scope:
      tunnel, nessun evento, nessuna persistenza).
- [x] Comportamento del **proxy HTTP esistente invariato** (regressione: i test di
      `elliot-proxy` restano verdi; `RepeatRequest` default = HTTP come prima,
      coperto da `the_defaults_are_still_http_over_tcp`).
- [x] CA condivisa: `elliot-proxy` continua a compilare e i suoi test passano dopo
      lo spostamento in `elliot-tls`.
- [x] Store: apertura di un file **v1** migrato a **v2** senza perdita dati
      (`a_v1_file_is_migrated_to_v2_and_keeps_its_data`).
- [x] `docs/architecture.md` aggiornato (nuovo listener SOCKS, modello `Stream`,
      store v2, CA spostata in `elliot-tls`).
- [ ] Le decisioni di §9 sono state confermate o esplicitamente rimandate.
      (Di fatto il perimetro realizzato è quello massimo: tutte le fasi G1→G9,
      inclusi UDP e UI; G-DISS/G-FILT/G-SESS restano aperte.)

---

## 11. Fuori scope (per questo piano)

- Il percorso **agente → runner → catalog** (frontiera di fiducia per i tool
  esterni): è un altro cablaggio, indipendente.
- Sniffer passivo pcap (vero Wireshark): scelta scartata in design (sola lettura,
  privilegi elevati, niente intercept) — eventuale pannello osservativo separato,
  non qui.
- UI pixel-perfect: qui si definiscono contratti (comandi/eventi) e viewer minimi;
  il design di dettaglio è task proprio.
