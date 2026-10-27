# Piano — Refactoring dei crate core (scope, store, repeater, catalog, runner, intruder, proxy Fasi C/D)

> Documento **autosufficiente**, pensato per essere eseguito in una chat separata.
> Non presuppone la conversazione in cui è nato. Esegue un refactoring, **non**
> nuove feature: salvo i punti marcati esplicitamente come cambi di
> comportamento, l'output osservabile resta identico e la suite di test resta
> verde a ogni passo.

---

## 1. Contesto (per chi esegue da zero)

**Elliot** è un proxy desktop **single-user** per security testing **autorizzato**
(VA/PT), nello spirito di Burp Suite. Monorepo in `/Users/davidhack/Documents/elliot`.

- **Stack:** core in **Rust** (workspace Cargo alla root); guscio desktop
  **Tauri 2** in `app/src-tauri`; frontend **React/TS** in `app/src`; agente
  **Python** (sidecar) in `agent/` che chiama Ollama; storage **SQLite +
  SQLCipher**.
- **Toolchain:** Rust stable (≥1.90), macOS arm64, Xcode CLT. **Niente
  OpenSSL/pkg-config di sistema** sul lato rete → si usa **rustls** (provider
  `aws-lc-rs`). L'unica eccezione è lo `store`, che compila una copia **vendored
  statica** di OpenSSL dentro SQLCipher (vedi §2).
- **Principi non negoziabili** (valgono durante tutto il refactoring):
  - **Frontiera di fiducia:** l'agente *propone soltanto*; il core Rust *valida
    ed esegue*. L'esecuzione avviene via **argv, mai shell**.
  - **Safe-by-construction:** la scelta sicura è l'unica rappresentabile (vale
    per il catalogo e per lo scope: niente regex arbitrarie lato scope, niente
    campi raw-args nel catalogo).
  - **Scope = fonte di verità unica** interrogata da proxy, repeater, intruder,
    runner.
  - `#![deny(unsafe_code)]` è ereditato dal workspace; **clippy è `-D warnings`**.

**Build & test (da ripetere a ogni fase):**

```bash
source "$HOME/.cargo/env"
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

> **Nota SQLCipher:** la prima build di `elliot-store` compila OpenSSL vendored
> da sorgente (~30–60 s). È normale; le build successive sono cachate. Non serve
> OpenSSL di sistema.

**Crate core oggetto del refactoring** (tutti sotto `core/<nome>/`):

| crate | ruolo | file principali |
|---|---|---|
| `elliot-httpraw` | modello condiviso: `Flow`, `Request`/`Response`, `Header`, enum (`Scheme`, `HttpVersion`, `FlowState`, `ScopeDecision`), trait `ScopeDecider`, tipi WS | `src/lib.rs` |
| `elliot-scope` | motore di policy (`ScopePolicy`, `Rule`, matcher) | `src/lib.rs` |
| `elliot-store` | file di progetto SQLite/SQLCipher, persistenza `Flow` | `src/lib.rs` |
| `elliot-repeater` | client raw TCP/TLS, invio verbatim | `src/lib.rs`, `src/tls.rs` |
| `elliot-catalog` | modello + loader YAML + validazione schema | `src/lib.rs` |
| `elliot-runner` | valida proposta vs catalogo+scope, costruisce argv, esegue | `src/lib.rs` |
| `elliot-intruder` | attacchi multi-punto, invio concorrente via repeater | `src/lib.rs` |
| `elliot-proxy` | proxy MITM; qui rileva solo `src/websocket.rs` (Fase D) e `src/convert.rs` | — |

Questi crate sono stati scritti rapidamente e **funzionano con i test verdi**;
il refactoring elimina duplicazioni, irrobustisce alcuni punti fragili e
centralizza contratti condivisi, **senza** regressioni.

---

## 2. Vincoli e definizione di "fatto" per OGNI fase

1. `cargo test --workspace` verde.
2. `cargo clippy --workspace --all-targets -- -D warnings` **senza output**.
3. Nessun `unsafe`, nessun `#[allow(...)]` nuovo salvo quelli esplicitamente
   indicati e commentati.
4. Nessun cambio dell'API pubblica dei crate **senza** aggiornare tutti i
   chiamanti nello stesso commit (incluso `app/src-tauri`).
5. Un commit per fase, messaggio `refactor(<crate|scope>): <cosa>`, in italiano,
   con in calce:
   ```
   Co-Authored-By: Claude <noreply@anthropic.com>
   ```
6. **Non** modificare il formato su disco dello `store` (token stringa, schema)
   se non nella fase R2, e lì mantenendo i token byte-identici a oggi.

Le fasi sono ordinate per dipendenza: R1→R2 toccano `httpraw` (base di tutti);
R3–R9 sono per lo più indipendenti tra loro e si possono fare in qualsiasi
ordine dopo R1/R2. R7 conviene subito dopo R1 (sposta helper di test).

---

## 3. Inventario del debito (sintesi, dettaglio nelle fasi)

- **D1 — parsing host/porta/scheme duplicato 3–4 volte** con firme diverse:
  `core/proxy/src/convert.rs:129` (`split_host_port`), `:91` (`target_info`),
  `core/proxy/src/websocket.rs:98` (`uri_target`),
  `core/runner/src/lib.rs:351` (`split_host_port`), `:333` (`target_locus`).
- **D2 — mappe enum↔stringa a mano nello store** (8 funzioni,
  `core/store/src/lib.rs:285–346`) che duplicano conoscenza che appartiene agli
  enum in `httpraw`.
- **D3 — framing della response nel repeater fragile**: `detect_framing`
  (`core/repeater/src/lib.rs:192`) e il rilevamento chunked via sottostringa
  `0\r\n\r\n` (`is_complete`) possono dare falsi positivi; gli header vengono
  ri-scansionati a mano (`header_value`) benché `httparse` li abbia già parsati.
  Inoltre `exchange` (`:134`) è vincolato ai trait **Ext** invece che a
  `AsyncRead`/`AsyncWrite`.
- **D4 — `AllowAll`/`DenyAll` duplicati** in `core/proxy/src/scope.rs:13`,
  `core/proxy/src/websocket.rs:138`, `core/proxy/tests/smoke.rs:9,36`, e nei
  test di runner/intruder.
- **D5 — runner: funzione `validate` monolitica**, confinamento path
  **solo lessicale** (non risolve i symlink), mini-`which` interno.
- **D6 — intruder: payload vincolati a UTF-8 (`String`)** e `run` che fa
  `tokio::spawn` di **tutti** i job in anticipo (una cluster bomb grande crea
  tantissime task).
- **D7 — catalog: nessun loader del catalogo bundled** e **rischio di drift**
  tra `catalog/schema/tool-entry.schema.yaml` e il modello Rust (il modello
  rispecchia lo schema a mano, nessun test lo verifica su tutte le voci).
- **D8 — store: nessun inserimento batch/transazionale** (il proxy farà molte
  upsert) e header serializzati come array JSON di interi (spreco).
- **D9 — (decisione aperta) repeater senza scope-gate**: l'architettura dice che
  lo scope è interrogato anche dal repeater, ma `elliot-repeater::send` non lo fa.
- **D10 — (decisione aperta) verifier TLS permissivo duplicato/mancante**:
  il repeater ha `NoVerification` (`core/repeater/src/tls.rs`); il proxy ha un
  **TODO** per l'`accept-invalid` upstream (`core/proxy/src/engine.rs`,
  `verify_upstream=false` non implementato).

---

## 4. Fasi di refactoring

### R1 — Centralizzare parsing host/porta/scheme e derivazione del "locus" di scope

**Motivazione:** D1. Quattro implementazioni divergenti dello stesso parsing
sono una fonte di bug (già divergono su default port e forma IPv6).

**Dove:** nuovo modulo `net` in **`elliot-httpraw`** (è il crate contratto, già
dipendenza di tutti; aggiungere logica di sola stringa non introduce dipendenze
pesanti — **non** usare il crate `http` qui, restare su `&str`).

**Modifiche:**
1. In `core/httpraw/src/lib.rs` aggiungere (modulo `pub mod net`):
   ```rust
   /// Divide "host[:port]" (gestendo "[v6]:port") in (host, Option<port>).
   pub fn split_host_port(authority: &str) -> (String, Option<u16>);

   /// Locus passato allo scope engine.
   pub struct Locus<'a> { pub scheme: &'a str, pub host: String, pub port: u16, pub path: &'a str }

   /// Deriva un Locus da una stringa target (bare host, host:port, CIDR con
   /// maschera rimossa, URL http/https). `default_scheme` e `default_port`
   /// coprono la forma origin. Best-effort e documentato.
   pub fn target_locus(target: &str) -> Locus<'_>;
   ```
   Portare qui la logica più completa tra quelle esistenti (quella di
   `runner::target_locus` + `runner::split_host_port`, che già gestisce URL e
   CIDR), unificando il caso IPv6 di `convert::split_host_port`.
2. **Sostituire** le implementazioni locali:
   - `core/runner/src/lib.rs`: eliminare `split_host_port` e `target_locus`,
     usare `elliot_httpraw::net::target_locus`. Adattare il punto in cui il
     runner chiama `scope.decide(scheme,&host,port,path)`.
   - `core/proxy/src/convert.rs`: far usare a `target_info` e a
     `split_host_port` l'helper condiviso (mantenendo la firma pubblica di
     `target_info` → `(Scheme, String, u16)`, mappando `scheme:&str`→`Scheme`).
   - `core/proxy/src/websocket.rs`: far usare a `uri_target` l'helper (resta la
     mappatura `ws`/`wss`→`Scheme`).
3. Spostare in `httpraw` i test di parsing host:port (inclusi i casi IPv6 e
   `notexample.com`), aggiungendo casi URL e CIDR.

**Rischi:** differenze di default port tra scheme; verificare che proxy e runner
mantengano lo stesso esito sui loro test. La firma di `target_locus` restituisce
riferimenti con lifetime del target: attenzione ai borrow nei chiamanti.

**Verifica:** test httpraw nuovi; `-p elliot-proxy -p elliot-runner` verdi;
workspace verde.

---

### R2 — Canonicalizzare le stringhe degli enum condivisi (eliminare le mappe dello store)

**Motivazione:** D2.

**Dove:** `elliot-httpraw` (enum) + `elliot-store`.

**Modifiche:**
1. Sugli enum in `core/httpraw/src/lib.rs` aggiungere metodi canonici
   **con token identici a quelli già scritti dallo store** (obbligatorio per non
   rompere i file esistenti):
   - `Scheme::as_str` esiste già (`"http"`/`"https"`): riusarlo.
   - `HttpVersion`: `as_token() -> &'static str` = `"1.0"|"1.1"|"2"` e
     `from_token(&str) -> HttpVersion` (fallback `Http11`).
   - `FlowState`: `as_token()` = `"pending"|"paused"|"completed"|"dropped"|"error"`
     + `from_token`.
   - `ScopeDecision`: `as_token()` = `"in"|"out"|"passthrough"` + `from_token`.
2. In `core/store/src/lib.rs` **eliminare** `scheme_str/from`, `version_str/from`,
   `state_str/from`, `scope_str/from` (`:285–346`) e usare i metodi di `httpraw`.
3. Aggiungere in `httpraw` un test che **blinda i token** (asserzioni sulle
   stringhe esatte), così un cambio accidentale che romperebbe i file `.elliot`
   fallisce in CI.

**Rischi:** i token DEVONO restare identici. Non introdurre `strum`/derive che
cambierebbe le stringhe.

**Verifica:** `-p elliot-store` round-trip verde; test token in httpraw.

---

### R3 — repeater: framing della response via httparse + chunked robusto

**Motivazione:** D3.

**Dove:** `core/repeater/src/lib.rs`.

**Modifiche:**
1. In `read_response`, quando trovi `\r\n\r\n`, **parsa gli header una volta**
   con `httparse::Response` (già usato in `parse_response`) e deriva il framing
   da lì, eliminando `header_value` e `detect_framing` fatti a mano.
2. Implementare un **decoder chunked** vero (leggi la dimensione di ogni chunk in
   esadecimale, salta eventuali chunk-extension dopo `;`, consuma i dati +
   `\r\n`, termina al chunk di dimensione 0 seguito dagli eventuali trailer e
   `\r\n`), sostituendo il match su sottostringa `0\r\n\r\n` in `is_complete`.
3. Cambiare il bound di `exchange` da `AsyncReadExt + AsyncWriteExt` a
   `AsyncRead + AsyncWrite + Unpin`, tenendo i trait Ext **in scope** con `use`.
4. Mantenere invariata la semantica "sotto timeout" e il fatto che i **byte
   grezzi** della response sono sempre preservati.

**Test nuovi:** (a) response chunked multi-chunk parsata correttamente;
(b) response il cui **body contiene** la sequenza `0\r\n\r\n` con un
`Content-Length` corretto → NON deve terminare in anticipo (regressione del bug
del vecchio rilevamento); (c) i test esistenti restano verdi.

**Rischi:** il decoder chunked è delicato: coprire chunk-extension e assenza di
trailer. Usare un `TcpListener` locale one-shot come negli altri test del
repeater.

---

### R4 — Estrarre helper TLS condivisi (prerequisito di R10, opzionale ma consigliato)

**Motivazione:** D10 (parte infrastrutturale).

**Dove:** nuovo crate `core/tls` (`elliot-tls`) **oppure** modulo in `httpraw`
(preferibile un crate dedicato perché tira dipendenze rustls che non vogliamo in
`httpraw`).

**Modifiche:**
1. Creare `elliot-tls` con: builder di `rustls::ClientConfig` (provider
   `aws-lc-rs`, root `webpki-roots`) e il verifier permissivo oggi in
   `core/repeater/src/tls.rs` (`NoVerification`).
2. `elliot-repeater` dipende da `elliot-tls` ed elimina il proprio `tls.rs`.
3. Aggiungere `elliot-tls` ai membri del workspace (`/Cargo.toml`).

**Nota:** il cablaggio dell'`accept-invalid` upstream nel **proxy** (hudsucker usa
un connector proprio) è più invasivo → spostato in §5 (decisione aperta R10).
Se non si fa R10, R4 resta comunque utile ma è facoltativa.

**Verifica:** test repeater TLS (vedi sotto, servirà un server TLS self-signed
con `rcgen` in un test `#[ignore]` o con cert di test).

---

### R5 — runner: spezzare `validate`, irrobustire il confinamento path, isolare `which`

**Motivazione:** D5.

**Dove:** `core/runner/src/lib.rs`.

**Modifiche:**
1. Spezzare `validate` in sottofunzioni pure e testabili:
   `check_tool_match`, `validate_flags(entry, proposal) -> (argv, effective,
   privileges)`, `validate_targets(entry, proposal, scope)`,
   `build_argv(...)`. `validate` diventa l'orchestratore.
2. Confinamento path: oggi `is_within`/`lexical_normalize` è **solo lessicale**.
   Irrobustire:
   - canonicalizzare il `project_dir` (deve esistere) con
     `std::fs::canonicalize`;
   - se il file non esiste ancora, canonicalizzare la **directory padre**
     esistente più vicina e ricomporre, così un symlink che punta fuori dal
     project dir viene scoperto;
   - mantenere il rifiuto lessicale di `..` come primo filtro.
   Documentare chiaramente il limite residuo (TOCTOU) con un commento.
3. `target_locus` → usare l'helper di R1.
4. `find_in_path`/`is_executable`: lasciarli ma spostarli in un modulo privato
   `which.rs` del crate (nessuna dipendenza nuova), oppure valutare il crate
   `which` (decisione minore: preferire **nessuna** nuova dipendenza).

**Test nuovi:** (a) symlink dentro il tempdir che punta fuori → `-oX` via symlink
deve essere rifiutato; (b) i test esistenti restano verdi.

**Rischi:** `canonicalize` richiede che il percorso (o il padre) esista; gestire
il caso in cui nemmeno il project dir esiste → errore chiaro, non panic.

---

### R6 — intruder: payload come byte + concorrenza bounded senza spawn anticipato

**Motivazione:** D6. **Cambio di API** (payload `Vec<u8>`): aggiornare i test e i
futuri chiamanti.

**Dove:** `core/intruder/src/lib.rs`.

**Modifiche:**
1. `Attack::payloads: Vec<Vec<Vec<u8>>>`? No: mantenere `Vec<Vec<Payload>>` dove
   `Payload = Vec<u8>` (alias `pub type Payload = Vec<u8>;`). Un fuzzer deve poter
   inviare byte non-UTF8. `AttackResult::assignments` diventa `Vec<(usize,
   Vec<u8>)>`. `apply_with` usa direttamente i byte (via `splice(range,
   value.iter().copied())`).
   - Fornire helper ergonomici: `Attack::payloads_from_str(&[&str])` per i casi
     comuni testuali, così i test restano leggibili.
2. Concorrenza: sostituire "spawn di tutti i job + semaforo" con uno **stream
   bounded**. Due opzioni:
   - (consigliata) `futures::stream::iter(jobs).map(|job| async {…})
     .buffer_unordered(concurrency).collect().await` — aggiunge la dipendenza
     `futures` (già nel lock via hudsucker/altri). Mantiene l'ordine via `index`
     e ri-ordina a fine raccolta (come ora).
   - in alternativa `tokio::task::JoinSet` con riempimento a finestra.
   Evitare di materializzare **tutte** le task in anticipo.
3. (Follow-up, non obbligatorio in questa fase) generare i job in modo **lazy**
   per cluster bomb molto grandi: oggi `expand_jobs` costruisce un `Vec`.
   Documentarlo come limite; se si vuole, convertire in `Iterator`.

**Test nuovi:** (a) payload binario (es. `vec![0x00, 0xFF]`) attraversa invariato
e viene inviato; (b) i test esistenti riscritti con `payloads_from_str`;
(c) il conteggio delle richieste resta corretto.

**Rischi:** aggiornare `elliot-repeater::RepeatRequest::raw` accetta già `Bytes`,
quindi `apply_with` deve restituire `Bytes` da byte arbitrari (ok).

---

### R7 — Unificare `AllowAll`/`DenyAll` e deduplicare gli helper di test di scope

**Motivazione:** D4.

**Dove:** `elliot-httpraw` (accanto al trait `ScopeDecider`) + consumatori.

**Modifiche:**
1. Spostare `AllowAll` da `core/proxy/src/scope.rs` a `core/httpraw/src/lib.rs`
   (accanto al trait) e aggiungere `DenyAll`. Entrambi `pub`.
2. In `core/proxy/src/scope.rs` ri-esportare (`pub use elliot_httpraw::AllowAll;`)
   per **non** cambiare l'API pubblica del proxy (`elliot_proxy::AllowAll` deve
   continuare a esistere).
3. Rimuovere le definizioni duplicate in `core/proxy/src/websocket.rs` (test),
   `core/proxy/tests/smoke.rs`, e nei test di `runner`/`intruder`, usando quelle
   condivise.

**Rischi:** `elliot_proxy::ScopeDecider` è già un re-export da httpraw: assicurarsi
che `AllowAll`/`DenyAll` siano raggiungibili dagli stessi percorsi usati oggi.

**Verifica:** tutti i crate che li usavano compilano e i test passano.

---

### R8 — catalog: loader del catalogo bundled + test anti-drift

**Motivazione:** D7. **Aggiunge funzionalità minima necessaria** (oggi nulla
carica il catalogo da disco) ma resta nello spirito del refactoring perché
chiude un buco lasciato aperto.

**Dove:** `core/catalog/src/lib.rs`.

**Modifiche:**
1. Aggiungere `pub fn load_standard() -> Result<Vec<ToolEntry>, CatalogError>`
   che carica **tutte** le voci standard impacchettate con l'app via
   `include_str!` (elencare esplicitamente i file di `catalog/standard/`, oggi
   solo `nmap.yaml`; niente `include_dir` per non aggiungere dipendenze).
2. Aggiungere `pub fn load_file(path) -> Result<ToolEntry, CatalogError>` per le
   voci `custom`.
3. Test: iterare tutte le voci di `load_standard()` e verificare che carichino e
   validino; asserire `id` univoci.
4. **Guardia anti-drift** (best-effort): un test che apre
   `catalog/schema/tool-entry.schema.yaml` (via `include_str!`), ne estrae i
   campi `required` top-level e verifica che corrispondano ai campi obbligatori
   del modello Rust (lista hard-coded confrontata). Documentare che è un
   controllo parziale (non un validatore JSON Schema completo).

**Rischi:** i percorsi `include_str!` sono relativi al file sorgente
(`core/catalog/src/lib.rs` → `../../../catalog/standard/...`). Verificarli.

---

### R9 — store: inserimenti transazionali/batch

**Motivazione:** D8.

**Dove:** `core/store/src/lib.rs`.

**Modifiche:**
1. Aggiungere `pub fn upsert_flows(&mut self, flows: &[Flow]) -> Result<(),
   StoreError>` che apre **una** transazione (`self.conn.transaction()`) e fa le
   upsert in blocco. Nota: `transaction()` richiede `&mut self` → valutare se
   `upsert_flow` singola resta `&self` (ok) e solo la batch prende `&mut self`,
   oppure usare `unchecked_transaction()` per restare su `&self` (documentare la
   scelta; preferire `&mut self` esplicito).
2. (Opzionale) Estrarre la stringa SQL di INSERT in una `const` condivisa tra
   `upsert_flow` e `upsert_flows` per non duplicarla.
3. (Opzionale, valutare) header: oggi `serde_json::to_vec(&Vec<Header>)` produce
   array di interi per i valori. Lasciare così (correttezza ok) **oppure**
   passare a un encoding compatto (lunghezza-prefissata o base64) — se lo si fa,
   aggiornare sia scrittura sia lettura e un test di round-trip con header
   non-UTF8. Marcare come facoltativo.

**Test nuovi:** batch di N flow in una transazione → `count_flows() == N`;
round-trip di un flow con header dal valore non-UTF8.

**Rischi:** cambiare la firma di una funzione pubblica dello store impatta
`app/src-tauri` solo se la usa (oggi non ancora). Verificare.

---

## 5. Decisioni aperte (DA CONFERMARE con l'autore prima di implementarle)

Queste **non** vanno eseguite d'ufficio: cambiano comportamento o aggiungono
superficie. Chi esegue il piano le porti all'autore.

- **R10a — Scope-gate nel repeater (D9).** L'architettura dice che lo scope è
  interrogato anche dal repeater. Oggi `elliot_repeater::send` invia a qualunque
  host. Opzioni: (a) aggiungere un parametro `scope: Option<&dyn ScopeDecider>`
  e rifiutare i target non `InScope`; (b) lasciare il gate al chiamante
  (app/core) e **documentarlo**. Impatto di sicurezza: (a) è più difensivo ma
  cambia la firma di `send`.
- **R10b — accept-invalid upstream nel proxy (D10).** Implementare davvero
  `verify_upstream=false` in `core/proxy/src/engine.rs` costruendo un
  `rustls::ClientConfig` permissivo e cablandolo nel connector di hudsucker
  (`with_http_connector`/connector custom). È più feature che refactoring;
  richiede R4. Decidere se farlo ora.
- **R6.3 — generazione lazy dei job intruder** per cluster bomb enormi (vedi R6):
  implica cambiare `plan()`/`run()` verso iteratori. Decidere se serve ora o se
  basta documentare il limite.
- **R9.3 — encoding compatto degli header nello store**: cambia il formato su
  disco → farlo ora (prima che esistano file reali) o mai senza migrazione.

---

## 6. Ordine consigliato e raggruppamento dei commit

1. **R1** (httpraw: `net`) — base per runner/proxy.
2. **R2** (httpraw: token enum; store usa i token).
3. **R7** (httpraw: `AllowAll`/`DenyAll`; dedup test).
4. **R3** (repeater: framing/chunked).
5. **R5** (runner: split + path hardening).
6. **R6** (intruder: payload byte + concorrenza) — concordare prima il cambio API.
7. **R8** (catalog: loader + anti-drift).
8. **R9** (store: batch).
9. **R4** solo se si fa **R10b**; altrimenti opzionale.

Un commit per fase (vedi §2.5). Dopo ogni fase: i due comandi di build/test di §1.

---

## 7. Checklist finale (prima di consegnare)

- [ ] `cargo test --workspace` verde (contare i test: non devono **diminuire**;
      attesi in crescita per i casi nuovi di R1/R3/R5/R6/R8/R9).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` senza output.
- [ ] `cargo check -p elliot-app` verde (il guscio Tauri compila con le API
      eventualmente cambiate).
- [ ] Nessun `unsafe`, nessun nuovo `#[allow]` non commentato.
- [ ] `docs/architecture.md` aggiornato se un'API pubblica o una decisione è
      cambiata (es. scope-gate del repeater, token store, nuovo crate
      `elliot-tls`).
- [ ] I token su disco dello store sono invariati (test di R2 presente).
- [ ] Le decisioni di §5 sono state confermate o esplicitamente rimandate.

---

## 8. Fuori scope (per questo piano)

- Cablaggio dei crate nell'app (comandi Tauri per scope/store/runner, UI di
  repeater/intruder, persistenza dei flow dal proxy): è il **passo successivo**,
  non un refactoring.
- UI dei messaggi WebSocket e correlazione dei flow WS all'upgrade HTTP
  (già annotati come follow-up in `docs/architecture.md`).
- Migrazioni dello schema store oltre la v1.
- Il modulo proxy MITM core (`engine`/`handler`/`intercept`/`tls`) **non** è
  oggetto di questo piano, tranne i punti `convert.rs`/`websocket.rs` toccati da
  R1/R7.
