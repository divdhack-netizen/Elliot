//! elliot-store — the per-project, passphrase-encrypted SQLite store.
//!
//! The project file **is** the database: a single SQLCipher file holding the
//! captured traffic, encrypted at rest from the first write (the file carries
//! credentials, tokens, PII and client data). Handing a project off is copying
//! one file.
//!
//! This crate owns the schema and the persistence of captured traffic: HTTP
//! [`Flow`]s and generic (non-HTTP) [`Stream`]/[`Message`] pairs. It is
//! deliberately synchronous (rusqlite); the app wraps a [`Store`] behind its
//! own lock and calls it off the UI thread.
//!
//! Writes come in two shapes: one-at-a-time ([`Store::upsert_flow`],
//! [`Store::append_message`]) and in a burst, in one transaction
//! ([`Store::upsert_flows`], [`Store::append_messages`]). Header lists are
//! stored as a compact length-prefixed binary blob (values are arbitrary
//! bytes).
//!
//! # Schema versioning
//!
//! `PRAGMA user_version` holds the schema version, and migrations run as a
//! chain: a **v1** file (HTTP flows only) gains the non-HTTP tables (v2), then
//! WebSocket frames and agent runs (v3). An existing project keeps opening, and
//! nothing has to be re-imported.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use elliot_httpraw::{
    Direction, Flow, FlowState, Header, HttpVersion, Message, Request, Response, Scheme,
    ScopeDecision, Stream, Transport, WsDirection, WsKind, WsMessage,
};

/// Current on-disk schema version, stored in `PRAGMA user_version`.
///
/// v1: HTTP flows + settings. v2: captured non-HTTP streams and their messages.
/// v3: WebSocket frames and agent execution runs.
pub const SCHEMA_VERSION: i64 = 3;

/// One approved execution of a catalog tool, as recorded by the Tauri shell.
///
/// Plain fields on purpose: the store owns persistence, not the wire format.
/// `argv`/`targets`/`required_privileges` are written as JSON arrays so the
/// rows stay readable by hand.
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
    /// Process exit status, when the tool ran to completion.
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("header encoding: {0}")]
    HeaderEncoding(String),
    #[error("project file {path:?} already exists")]
    AlreadyExists { path: String },
    #[error(
        "schema version mismatch: file is v{found}, this build supports v{supported}"
    )]
    SchemaVersion { found: i64, supported: i64 },
}

/// A handle to an open, encrypted project store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Create a new encrypted project file and initialize the schema.
    ///
    /// Fails if the file already exists, so an existing project is never
    /// clobbered (SQLite would otherwise happily open it in place).
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if path.exists() {
            return Err(StoreError::AlreadyExists {
                path: path.display().to_string(),
            });
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", passphrase)?;
        // Touch the database so the key actually takes effect, then build it.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Open an existing encrypted project file. Returns an error if the
    /// passphrase is wrong (the first query fails to decrypt) or the schema
    /// version is newer than this build understands.
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", passphrase)?;
        // The first real read decrypts a page; a wrong key fails right here.
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match version {
            v if v == SCHEMA_VERSION => {}
            // Upgrade in place: an existing project must keep opening, and
            // gaining capture must not require re-importing anything. Each
            // step is idempotent, so the chain is safe to re-run.
            1 => {
                migrate_v1_to_v2(&conn)?;
                migrate_v2_to_v3(&conn)?;
            }
            2 => migrate_v2_to_v3(&conn)?,
            other => {
                return Err(StoreError::SchemaVersion {
                    found: other,
                    supported: SCHEMA_VERSION,
                })
            }
        }
        // Idempotent, so a file written before a table existed still gains it.
        init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Insert or replace a named setting (scope policy, UI preferences, …).
    /// Values are opaque bytes; the caller owns their format.
    pub fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Read a setting, or `None` if it was never written.
    pub fn get_setting(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Forget a setting. A missing key is not an error.
    pub fn delete_setting(&self, key: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }

    /// Insert or replace a flow.
    pub fn upsert_flow(&self, flow: &Flow) -> Result<(), StoreError> {
        upsert_on(&self.conn, flow)
    }

    /// Insert or replace a captured non-HTTP stream.
    pub fn upsert_stream(&self, stream: &Stream) -> Result<(), StoreError> {
        self.conn.execute(UPSERT_STREAM_SQL, stream_params(stream))?;
        Ok(())
    }

    /// Append one observed message (a TCP chunk or a UDP datagram).
    pub fn append_message(&self, message: &Message) -> Result<(), StoreError> {
        self.conn.execute(APPEND_MESSAGE_SQL, message_params(message))?;
        Ok(())
    }

    /// Append many messages in **one** transaction: the capture path produces
    /// them in bursts, and a transaction per message costs an fsync each.
    pub fn append_messages(&mut self, messages: &[Message]) -> Result<(), StoreError> {
        if messages.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        for message in messages {
            tx.execute(APPEND_MESSAGE_SQL, message_params(message))?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Fetch one stream by id.
    pub fn get_stream(&self, id: Uuid) -> Result<Option<Stream>, StoreError> {
        self.conn
            .query_row(
                &format!("SELECT {STREAM_COLUMNS} FROM streams WHERE id = ?1"),
                [id.to_string()],
                row_to_stream,
            )
            .optional()?
            .transpose()
    }

    /// List streams, most recent first, up to `limit`.
    pub fn list_streams(&self, limit: usize) -> Result<Vec<Stream>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {STREAM_COLUMNS} FROM streams ORDER BY started_at DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit as i64], row_to_stream)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Every message of one stream, in sequence order.
    pub fn messages_for(&self, stream_id: Uuid) -> Result<Vec<Message>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, stream_id, seq, at, direction, data FROM messages \
             WHERE stream_id = ?1 ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([stream_id.to_string()], row_to_message)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Number of stored streams.
    pub fn count_streams(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM streams", [], |r| r.get(0))?)
    }

    /// Insert or replace many flows in **one** transaction.
    ///
    /// The capture path produces flows in bursts, and one transaction per burst
    /// costs a single fsync instead of one per flow. A failure anywhere rolls
    /// the whole batch back, so a partial burst is never committed.
    pub fn upsert_flows(&mut self, flows: &[Flow]) -> Result<(), StoreError> {
        if flows.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        for flow in flows {
            upsert_on(&tx, flow)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Fetch one flow by id.
    pub fn get_flow(&self, id: Uuid) -> Result<Option<Flow>, StoreError> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM flows WHERE id = ?1"),
                [id.to_string()],
                row_to_flow,
            )
            .optional()?
            .transpose()
    }

    /// List flows, most recent first, up to `limit`.
    pub fn list_flows(&self, limit: usize) -> Result<Vec<Flow>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM flows ORDER BY started_at DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map([limit as i64], row_to_flow)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Number of stored flows.
    pub fn count_flows(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))?)
    }

    /// Append many forwarded WebSocket frames in **one** transaction.
    ///
    /// Only frames that actually went on the wire are stored: a dropped frame
    /// is a decision, not traffic.
    pub fn append_ws_messages(&mut self, messages: &[WsMessage]) -> Result<(), StoreError> {
        if messages.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        for message in messages {
            tx.execute(APPEND_WS_MESSAGE_SQL, ws_params(message))?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Append one forwarded frame. `INSERT OR REPLACE` on the frame id, so a
    /// second event for the same frame never duplicates the row.
    pub fn append_ws_message(&self, message: &WsMessage) -> Result<(), StoreError> {
        self.conn
            .execute(APPEND_WS_MESSAGE_SQL, ws_params(message))?;
        Ok(())
    }

    /// The most recent `limit` stored frames, **oldest first** so the history
    /// reads chronologically like the HTTP one.
    pub fn list_ws_messages(&self, limit: usize) -> Result<Vec<WsMessage>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {WS_COLUMNS} FROM (\
                 SELECT {WS_COLUMNS} FROM ws_messages ORDER BY at DESC LIMIT ?1\
             ) ORDER BY at ASC"
        ))?;
        let rows = stmt.query_map([limit as i64], row_to_ws_message)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Number of stored WebSocket frames.
    pub fn count_ws_messages(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM ws_messages", [], |r| r.get(0))?)
    }

    /// Record one approved tool execution.
    pub fn append_agent_run(&self, run: &AgentRun) -> Result<(), StoreError> {
        self.conn.execute(
            UPSERT_AGENT_RUN_SQL,
            rusqlite::params![
                run.id.to_string(),
                run.proposal_id.map(|id| id.to_string()),
                run.tool_id,
                run.program,
                encode_string_list(&run.argv),
                encode_string_list(&run.targets),
                run.effective_intrusiveness,
                encode_string_list(&run.required_privileges),
                millis(run.started_at),
                millis(run.completed_at),
                run.status,
                run.stdout.clone(),
                run.stderr.clone(),
                run.duration_ms as i64,
                run.error,
            ],
        )?;
        Ok(())
    }

    /// Recorded runs, most recent first, up to `limit`.
    pub fn list_agent_runs(&self, limit: usize) -> Result<Vec<AgentRun>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, proposal_id, tool_id, program, argv, targets, \
             effective_intrusiveness, required_privileges, started_at, completed_at, \
             status, stdout, stderr, duration_ms, error \
             FROM agent_runs ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], row_to_agent_run)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// Create the schema. Every statement is `IF NOT EXISTS`, so this is safe on a
/// fresh file and on one written by an earlier build.
fn init_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(&format!(
        "{FLOWS_AND_SETTINGS_DDL}{STREAMS_AND_MESSAGES_DDL}{WS_AND_AGENT_DDL}"
    ))?;
    Ok(())
}

/// Upgrade a v1 file (HTTP flows only) to v2 by adding the non-HTTP tables.
///
/// Runs in one transaction, so a failure leaves the file at v1 rather than at a
/// half-migrated version. Every statement is `IF NOT EXISTS`, so re-running the
/// migration against a file that already has the tables is harmless.
fn migrate_v1_to_v2(conn: &Connection) -> Result<(), StoreError> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(STREAMS_AND_MESSAGES_DDL)?;
    tx.pragma_update(None, "user_version", 2)?;
    tx.commit()?;
    Ok(())
}

/// Upgrade a v2 file to v3 by adding WebSocket frames and agent runs.
fn migrate_v2_to_v3(conn: &Connection) -> Result<(), StoreError> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(WS_AND_AGENT_DDL)?;
    tx.pragma_update(None, "user_version", 3)?;
    tx.commit()?;
    Ok(())
}

/// The v1 tables: HTTP flows plus key/value settings.
const FLOWS_AND_SETTINGS_DDL: &str = r#"
        CREATE TABLE IF NOT EXISTS flows (
            id            TEXT PRIMARY KEY,
            started_at    INTEGER NOT NULL,
            completed_at  INTEGER,
            client_addr   TEXT NOT NULL,
            scheme        TEXT NOT NULL,
            host          TEXT NOT NULL,
            port          INTEGER NOT NULL,
            method        TEXT NOT NULL,
            target        TEXT NOT NULL,
            req_version   TEXT NOT NULL,
            req_headers   BLOB NOT NULL,
            req_body      BLOB NOT NULL,
            req_raw       BLOB NOT NULL,
            status        INTEGER,
            resp_reason   TEXT,
            resp_version  TEXT,
            resp_headers  BLOB,
            resp_body     BLOB,
            resp_raw      BLOB,
            state         TEXT NOT NULL,
            scope         TEXT NOT NULL,
            error         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_flows_started ON flows (started_at);
        CREATE INDEX IF NOT EXISTS idx_flows_host ON flows (host);
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
"#;

/// The v2 tables: captured non-HTTP streams and their messages.
///
/// The foreign key is declared for documentation and for tools that inspect the
/// file; SQLite does not enforce it unless `PRAGMA foreign_keys` is on, which is
/// deliberate — capture events are written as they arrive, and a message must
/// never be dropped because its stream row has not been flushed yet.
const STREAMS_AND_MESSAGES_DDL: &str = r#"
        CREATE TABLE IF NOT EXISTS streams (
            id            TEXT PRIMARY KEY,
            started_at    INTEGER NOT NULL,
            completed_at  INTEGER,
            client_addr   TEXT NOT NULL,
            transport     TEXT NOT NULL,
            host          TEXT NOT NULL,
            port          INTEGER NOT NULL,
            tls           INTEGER NOT NULL,
            scope         TEXT NOT NULL,
            state         TEXT NOT NULL,
            error         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_streams_started ON streams (started_at);
        CREATE INDEX IF NOT EXISTS idx_streams_host ON streams (host);
        CREATE TABLE IF NOT EXISTS messages (
            id         TEXT PRIMARY KEY,
            stream_id  TEXT NOT NULL,
            seq        INTEGER NOT NULL,
            at         INTEGER NOT NULL,
            direction  TEXT NOT NULL,
            data       BLOB NOT NULL,
            FOREIGN KEY (stream_id) REFERENCES streams (id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_stream ON messages (stream_id, seq);
"#;

/// The v3 tables: forwarded WebSocket frames and agent execution runs.
///
/// No foreign keys: a frame does not belong to a [`Stream`], and a run does not
/// belong to a [`Flow`]. `argv`/`targets`/`required_privileges` hold JSON
/// arrays of strings.
const WS_AND_AGENT_DDL: &str = r#"
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
            id                      TEXT PRIMARY KEY,
            proposal_id             TEXT,
            tool_id                 TEXT NOT NULL,
            program                 TEXT NOT NULL,
            argv                    TEXT NOT NULL,
            targets                 TEXT NOT NULL,
            effective_intrusiveness TEXT NOT NULL,
            required_privileges     TEXT NOT NULL,
            started_at              INTEGER NOT NULL,
            completed_at            INTEGER NOT NULL,
            status                  INTEGER,
            stdout                  BLOB NOT NULL,
            stderr                  BLOB NOT NULL,
            duration_ms             INTEGER NOT NULL,
            error                   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_agent_runs_started ON agent_runs (started_at);
"#;

const COLUMNS: &str = "id, started_at, completed_at, client_addr, scheme, host, port, \
     method, target, req_version, req_headers, req_body, req_raw, \
     status, resp_reason, resp_version, resp_headers, resp_body, resp_raw, \
     state, scope, error";

/// The single upsert statement, shared by the one-at-a-time and batch writers
/// so the column list exists in exactly one place.
const UPSERT_SQL: &str = r#"
    INSERT OR REPLACE INTO flows (
        id, started_at, completed_at, client_addr, scheme, host, port,
        method, target, req_version, req_headers, req_body, req_raw,
        status, resp_reason, resp_version, resp_headers, resp_body, resp_raw,
        state, scope, error
    ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7,
        ?8, ?9, ?10, ?11, ?12, ?13,
        ?14, ?15, ?16, ?17, ?18, ?19,
        ?20, ?21, ?22
    )
    "#;

/// Upsert one flow on any connection-ish handle (a `Connection` or the
/// `Transaction` that derefs to it).
fn upsert_on(conn: &Connection, flow: &Flow) -> Result<(), StoreError> {
    let req_headers = encode_headers(&flow.request.headers);
    let (status, resp_reason, resp_version, resp_headers, resp_body, resp_raw) =
        match &flow.response {
            Some(r) => (
                Some(i64::from(r.status)),
                Some(r.reason.clone()),
                Some(r.version.as_token().to_string()),
                Some(encode_headers(&r.headers)),
                Some(r.body.to_vec()),
                Some(r.raw.to_vec()),
            ),
            None => (None, None, None, None, None, None),
        };

    conn.execute(
        UPSERT_SQL,
        rusqlite::params![
            flow.id.to_string(),
            millis(flow.started_at),
            flow.completed_at.map(millis),
            flow.client_addr.to_string(),
            flow.scheme.as_str(),
            flow.host,
            i64::from(flow.port),
            flow.request.method,
            flow.request.target,
            flow.request.version.as_token(),
            req_headers,
            flow.request.body.to_vec(),
            flow.request.raw.to_vec(),
            status,
            resp_reason,
            resp_version,
            resp_headers,
            resp_body,
            resp_raw,
            flow.state.as_token(),
            flow.scope.as_token(),
            flow.error,
        ],
    )?;
    Ok(())
}

const STREAM_COLUMNS: &str = "id, started_at, completed_at, client_addr, transport, host, \
     port, tls, scope, state, error";

const UPSERT_STREAM_SQL: &str = r#"
    INSERT OR REPLACE INTO streams (
        id, started_at, completed_at, client_addr, transport, host,
        port, tls, scope, state, error
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
"#;

const APPEND_MESSAGE_SQL: &str = r#"
    INSERT OR REPLACE INTO messages (id, stream_id, seq, at, direction, data)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
"#;

const WS_COLUMNS: &str = "id, connection_id, at, client_addr, scheme, host, port, \
     direction, kind, payload";

const APPEND_WS_MESSAGE_SQL: &str = r#"
    INSERT OR REPLACE INTO ws_messages (
        id, connection_id, at, client_addr, scheme, host, port, direction, kind, payload
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
"#;

const UPSERT_AGENT_RUN_SQL: &str = r#"
    INSERT OR REPLACE INTO agent_runs (
        id, proposal_id, tool_id, program, argv, targets, effective_intrusiveness,
        required_privileges, started_at, completed_at, status, stdout, stderr,
        duration_ms, error
    ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
    )
"#;

fn stream_params(stream: &Stream) -> impl rusqlite::Params {
    (
        stream.id.to_string(),
        millis(stream.started_at),
        stream.completed_at.map(millis),
        stream.client_addr.to_string(),
        stream.transport.as_token(),
        stream.host.clone(),
        i64::from(stream.port),
        i64::from(stream.tls),
        stream.scope.as_token(),
        stream.state.as_token(),
        stream.error.clone(),
    )
}

fn message_params(message: &Message) -> impl rusqlite::Params {
    (
        message.id.to_string(),
        message.stream_id.to_string(),
        message.seq as i64,
        millis(message.at),
        message.direction.as_token(),
        message.data.to_vec(),
    )
}

fn ws_params(message: &WsMessage) -> impl rusqlite::Params {
    (
        message.id.to_string(),
        message.connection_id.to_string(),
        millis(message.at),
        message.client_addr.to_string(),
        message.scheme.as_str(),
        message.host.clone(),
        i64::from(message.port),
        message.direction.as_token(),
        message.kind.as_token(),
        message.payload.to_vec(),
    )
}

fn row_to_ws_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<WsMessage> {
    let id: String = row.get(0)?;
    let connection_id: String = row.get(1)?;
    let at: i64 = row.get(2)?;
    let client_addr: String = row.get(3)?;
    let scheme: String = row.get(4)?;
    let host: String = row.get(5)?;
    let port: i64 = row.get(6)?;
    let direction: String = row.get(7)?;
    let kind: String = row.get(8)?;
    let payload: Vec<u8> = row.get(9)?;

    // Same degradation policy as the other readers: a row written by this
    // build always parses, a damaged one must not abort the listing.
    let client_addr = client_addr
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let port = port as u16;
    // The label is derived, not stored: it is exactly what `observe()` builds.
    let connection = format!("{client_addr} <-> {host}:{port}");

    Ok(WsMessage {
        id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
        connection,
        connection_id: Uuid::parse_str(&connection_id).unwrap_or_else(|_| Uuid::nil()),
        at: from_millis(at),
        client_addr,
        scheme: Scheme::from_token(&scheme),
        host,
        port,
        direction: WsDirection::from_token(&direction),
        kind: WsKind::from_token(&kind),
        payload: Bytes::from(payload),
        // A stored frame is by definition one that was forwarded.
        paused: false,
    })
}

fn row_to_agent_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentRun> {
    let id: String = row.get(0)?;
    let proposal_id: Option<String> = row.get(1)?;
    let tool_id: String = row.get(2)?;
    let program: String = row.get(3)?;
    let argv: String = row.get(4)?;
    let targets: String = row.get(5)?;
    let effective_intrusiveness: String = row.get(6)?;
    let required_privileges: String = row.get(7)?;
    let started_at: i64 = row.get(8)?;
    let completed_at: i64 = row.get(9)?;
    let status: Option<i64> = row.get(10)?;
    let stdout: Vec<u8> = row.get(11)?;
    let stderr: Vec<u8> = row.get(12)?;
    let duration_ms: i64 = row.get(13)?;
    let error: Option<String> = row.get(14)?;

    Ok(AgentRun {
        id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
        proposal_id: proposal_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok()),
        tool_id,
        program,
        argv: decode_string_list(&argv),
        targets: decode_string_list(&targets),
        effective_intrusiveness,
        required_privileges: decode_string_list(&required_privileges),
        started_at: from_millis(started_at),
        completed_at: from_millis(completed_at),
        status: status.map(|s| s as i32),
        stdout,
        stderr,
        duration_ms: duration_ms.max(0) as u64,
        error,
    })
}

/// JSON-encode a string vector. The encoding is plain JSON so a person can
/// read the column with any SQLite browser.
fn encode_string_list(values: &[String]) -> String {
    serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string())
}

/// Inverse of [`encode_string_list`]; a damaged value degrades to empty rather
/// than failing the whole listing.
fn decode_string_list(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

fn row_to_stream(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Stream, StoreError>> {
    Ok(build_stream(row))
}

fn build_stream(row: &rusqlite::Row<'_>) -> Result<Stream, StoreError> {
    let id: String = row.get(0)?;
    let started_at: i64 = row.get(1)?;
    let completed_at: Option<i64> = row.get(2)?;
    let client_addr: String = row.get(3)?;
    let transport: String = row.get(4)?;
    let host: String = row.get(5)?;
    let port: i64 = row.get(6)?;
    let tls: i64 = row.get(7)?;
    let scope: String = row.get(8)?;
    let state: String = row.get(9)?;
    let error: Option<String> = row.get(10)?;

    Ok(Stream {
        id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
        started_at: from_millis(started_at),
        completed_at: completed_at.map(from_millis),
        // A malformed address cannot happen for rows this build wrote; degrade
        // to a placeholder rather than failing the whole listing.
        client_addr: client_addr
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        transport: Transport::from_token(&transport),
        host,
        port: port as u16,
        tls: tls != 0,
        scope: ScopeDecision::from_token(&scope),
        state: FlowState::from_token(&state),
        error,
    })
}

fn row_to_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    let id: String = row.get(0)?;
    let stream_id: String = row.get(1)?;
    let seq: i64 = row.get(2)?;
    let at: i64 = row.get(3)?;
    let direction: String = row.get(4)?;
    let data: Vec<u8> = row.get(5)?;

    Ok(Message {
        id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
        stream_id: Uuid::parse_str(&stream_id).unwrap_or_else(|_| Uuid::nil()),
        seq: seq.max(0) as u64,
        at: from_millis(at),
        direction: Direction::from_token(&direction),
        data: Bytes::from(data),
    })
}

/// Map a row (selected as `COLUMNS`) back into a [`Flow`]. The inner result
/// carries deserialization errors without aborting the row callback.
fn row_to_flow(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Flow, StoreError>> {
    Ok(build_flow(row))
}

fn build_flow(row: &rusqlite::Row<'_>) -> Result<Flow, StoreError> {
    let id: String = row.get(0)?;
    let started_at: i64 = row.get(1)?;
    let completed_at: Option<i64> = row.get(2)?;
    let client_addr: String = row.get(3)?;
    let scheme: String = row.get(4)?;
    let host: String = row.get(5)?;
    let port: i64 = row.get(6)?;
    let method: String = row.get(7)?;
    let target: String = row.get(8)?;
    let req_version: String = row.get(9)?;
    let req_headers: Vec<u8> = row.get(10)?;
    let req_body: Vec<u8> = row.get(11)?;
    let req_raw: Vec<u8> = row.get(12)?;
    let status: Option<i64> = row.get(13)?;
    let resp_reason: Option<String> = row.get(14)?;
    let resp_version: Option<String> = row.get(15)?;
    let resp_headers: Option<Vec<u8>> = row.get(16)?;
    let resp_body: Option<Vec<u8>> = row.get(17)?;
    let resp_raw: Option<Vec<u8>> = row.get(18)?;
    let state: String = row.get(19)?;
    let scope: String = row.get(20)?;
    let error: Option<String> = row.get(21)?;

    let request = Request {
        method,
        target,
        version: HttpVersion::from_token(&req_version),
        headers: decode_headers(&req_headers)?,
        body: req_body.into(),
        raw: req_raw.into(),
    };

    let response = match status {
        Some(code) => Some(Response {
            status: code as u16,
            reason: resp_reason.unwrap_or_default(),
            version: resp_version
                .as_deref()
                .map(HttpVersion::from_token)
                .unwrap_or(HttpVersion::Http11),
            headers: match resp_headers {
                Some(h) => decode_headers(&h)?,
                None => Vec::new(),
            },
            body: resp_body.unwrap_or_default().into(),
            raw: resp_raw.unwrap_or_default().into(),
        }),
        None => None,
    };

    Ok(Flow {
        id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
        started_at: from_millis(started_at),
        completed_at: completed_at.map(from_millis),
        client_addr: client_addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
        scheme: Scheme::from_token(&scheme),
        host,
        port: port as u16,
        request,
        response,
        state: FlowState::from_token(&state),
        scope: ScopeDecision::from_token(&scope),
        error,
    })
}

// --- header encoding ---------------------------------------------------------
//
// Header values are arbitrary bytes, so they are stored length-prefixed rather
// than as a JSON array of integers (which cost ~4 bytes of text per input
// byte).
//
// Layout: `u32` count, then per header a `u32`-length-prefixed name (UTF-8) and
// a `u32`-length-prefixed value (raw bytes), all little-endian.

fn encode_headers(headers: &[Header]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + headers.len() * 16);
    out.extend_from_slice(&(headers.len() as u32).to_le_bytes());
    for h in headers {
        let name = h.name.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(h.value.len() as u32).to_le_bytes());
        out.extend_from_slice(&h.value);
    }
    out
}

/// Inverse of [`encode_headers`]. A truncated or inconsistent blob is an error,
/// never a panic or a silent truncation.
fn decode_headers(bytes: &[u8]) -> Result<Vec<Header>, StoreError> {
    let mut cur = bytes;
    let count = read_u32(&mut cur)? as usize;
    // Do not trust `count` enough to pre-allocate it.
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let name_len = read_u32(&mut cur)? as usize;
        let name = std::str::from_utf8(take(&mut cur, name_len)?)
            .map_err(|e| StoreError::HeaderEncoding(format!("header name is not UTF-8: {e}")))?
            .to_string();
        let value_len = read_u32(&mut cur)? as usize;
        let value = take(&mut cur, value_len)?.to_vec();
        out.push(Header { name, value });
    }
    Ok(out)
}

fn read_u32(cur: &mut &[u8]) -> Result<u32, StoreError> {
    let bytes = take(cur, 4)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("take(4) yields exactly 4 bytes"),
    ))
}

fn take<'a>(cur: &mut &'a [u8], len: usize) -> Result<&'a [u8], StoreError> {
    if cur.len() < len {
        return Err(StoreError::HeaderEncoding(format!(
            "truncated header blob: wanted {len} bytes, {} left",
            cur.len()
        )));
    }
    let (head, rest) = cur.split_at(len);
    *cur = rest;
    Ok(head)
}

// --- time helpers ------------------------------------------------------------
//
// Enum names are NOT mapped here: the on-disk tokens live next to the enums in
// `elliot-httpraw` (`as_str` / `as_token` / `from_token`), so there is a single
// definition of the store format.

fn millis(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
fn from_millis(ms: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn sample_flow() -> Flow {
        let headers = vec![Header {
            name: "Host".into(),
            value: b"example.com".to_vec(),
        }];
        Flow {
            id: Uuid::new_v4(),
            started_at: UNIX_EPOCH + Duration::from_millis(1_700_000_000_000),
            completed_at: Some(UNIX_EPOCH + Duration::from_millis(1_700_000_000_100)),
            client_addr: "127.0.0.1:54321".parse().unwrap(),
            scheme: Scheme::Https,
            host: "example.com".into(),
            port: 443,
            request: Request {
                method: "GET".into(),
                target: "/".into(),
                version: HttpVersion::H2,
                headers: headers.clone(),
                body: Bytes::from_static(b""),
                raw: Bytes::from_static(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            },
            response: Some(Response {
                status: 200,
                reason: "OK".into(),
                version: HttpVersion::H2,
                headers,
                body: Bytes::from_static(b"hi"),
                raw: Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\nhi"),
            }),
            state: FlowState::Completed,
            scope: ScopeDecision::InScope,
            error: None,
        }
    }

    #[test]
    fn create_upsert_get_and_list_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        let store = Store::create(&path, "correct horse").unwrap();

        let flow = sample_flow();
        store.upsert_flow(&flow).unwrap();
        assert_eq!(store.count_flows().unwrap(), 1);

        let got = store.get_flow(flow.id).unwrap().expect("flow present");
        assert_eq!(got.host, "example.com");
        assert_eq!(got.port, 443);
        assert_eq!(got.request.version, HttpVersion::H2);
        assert_eq!(&got.request.raw[..], &flow.request.raw[..]);
        assert_eq!(got.response.unwrap().status, 200);

        let listed = store.list_flows(10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, flow.id);
    }

    #[test]
    fn data_persists_across_reopen_with_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        let id = {
            let store = Store::create(&path, "s3cret").unwrap();
            let flow = sample_flow();
            store.upsert_flow(&flow).unwrap();
            flow.id
        };
        let store = Store::open(&path, "s3cret").unwrap();
        assert!(store.get_flow(id).unwrap().is_some());
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        {
            let store = Store::create(&path, "right-key").unwrap();
            store.upsert_flow(&sample_flow()).unwrap();
        }
        let err = Store::open(&path, "wrong-key");
        assert!(err.is_err(), "opening with the wrong passphrase must fail");
    }

    /// `create` must never adopt an existing file: that would silently mix two
    /// projects (SQLite opens a file in place rather than failing).
    #[test]
    fn create_refuses_to_clobber_an_existing_project() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        {
            let store = Store::create(&path, "first").unwrap();
            store.set_setting("k", b"v1").unwrap();
        }
        // `.err()` rather than `unwrap_err()`: `Store` is deliberately not
        // `Debug` (it holds a live keyed connection).
        let err = Store::create(&path, "second")
            .err()
            .expect("an existing project must be refused");
        assert!(matches!(err, StoreError::AlreadyExists { .. }), "got {err:?}");

        // The original file is untouched.
        let store = Store::open(&path, "first").unwrap();
        assert_eq!(store.get_setting("k").unwrap().unwrap(), b"v1".to_vec());
    }

    #[test]
    fn settings_round_trip_overwrite_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();

        assert!(store.get_setting("scope").unwrap().is_none());
        store.set_setting("scope", b"{\"include\":[]}").unwrap();
        assert_eq!(
            store.get_setting("scope").unwrap().unwrap(),
            b"{\"include\":[]}".to_vec()
        );

        // Overwrite in place.
        store.set_setting("scope", b"v2").unwrap();
        assert_eq!(store.get_setting("scope").unwrap().unwrap(), b"v2".to_vec());

        // Values are opaque bytes, not text.
        store.set_setting("bin", &[0x00, 0xFF]).unwrap();
        assert_eq!(store.get_setting("bin").unwrap().unwrap(), vec![0x00, 0xFF]);

        store.delete_setting("scope").unwrap();
        assert!(store.get_setting("scope").unwrap().is_none());
        // Deleting a key that is not there is not an error.
        store.delete_setting("scope").unwrap();
    }

    #[test]
    fn settings_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        {
            let store = Store::create(&path, "pw").unwrap();
            store.set_setting("scope", b"saved").unwrap();
        }
        let store = Store::open(&path, "pw").unwrap();
        assert_eq!(store.get_setting("scope").unwrap().unwrap(), b"saved".to_vec());
    }

    /// A file written before the `settings` table existed must still open: the
    /// schema is ensured idempotently on open.
    #[test]
    fn opening_ensures_the_settings_table_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        {
            let store = Store::create(&path, "pw").unwrap();
            // Stand in for an older file that predates the table.
            store.conn.execute_batch("DROP TABLE settings").unwrap();
        }
        let store = Store::open(&path, "pw").unwrap();
        assert!(store.get_setting("scope").unwrap().is_none());
        store.set_setting("scope", b"ok").unwrap();
        assert_eq!(store.get_setting("scope").unwrap().unwrap(), b"ok".to_vec());
    }

    #[test]
    fn batch_upsert_writes_every_flow_in_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();

        let flows: Vec<Flow> = (0..25).map(|_| sample_flow()).collect();
        store.upsert_flows(&flows).unwrap();
        assert_eq!(store.count_flows().unwrap(), 25);
        assert!(store.get_flow(flows[7].id).unwrap().is_some());

        // Re-upserting the same ids replaces rather than duplicates.
        store.upsert_flows(&flows).unwrap();
        assert_eq!(store.count_flows().unwrap(), 25);

        // An empty batch is a no-op, not an error.
        store.upsert_flows(&[]).unwrap();
        assert_eq!(store.count_flows().unwrap(), 25);
    }

    /// Within one batch, a repeated id replaces rather than duplicates (the
    /// statement is `INSERT OR REPLACE`).
    #[test]
    fn a_repeated_id_within_a_batch_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();

        let mut first = sample_flow();
        first.id = Uuid::nil();
        let mut second = sample_flow();
        second.id = Uuid::nil();

        store.upsert_flows(&[first, second]).unwrap();
        assert_eq!(store.count_flows().unwrap(), 1);
    }

    /// Header values are arbitrary bytes; the compact codec must round-trip them
    /// (this is what the old JSON encoding could do, but at ~4x the size).
    #[test]
    fn non_utf8_header_values_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();

        let mut flow = sample_flow();
        flow.request.headers = vec![
            Header {
                name: "Host".into(),
                value: b"example.com".to_vec(),
            },
            Header {
                name: "X-Odd".into(),
                value: vec![0x00, 0xFF, 0x80, 0x0A, 0x0D],
            },
        ];
        store.upsert_flow(&flow).unwrap();

        let got = store.get_flow(flow.id).unwrap().expect("flow present");
        assert_eq!(got.request.headers, flow.request.headers);
    }

    fn sample_stream() -> Stream {
        Stream {
            id: Uuid::new_v4(),
            started_at: UNIX_EPOCH + Duration::from_millis(1_700_000_100_000),
            completed_at: None,
            client_addr: "127.0.0.1:51000".parse().unwrap(),
            transport: Transport::Tcp,
            host: "redis.internal".into(),
            port: 6379,
            tls: false,
            scope: ScopeDecision::InScope,
            state: FlowState::Pending,
            error: None,
        }
    }

    fn sample_message(stream_id: Uuid, seq: u64, direction: Direction, data: &[u8]) -> Message {
        Message {
            id: Uuid::new_v4(),
            stream_id,
            seq,
            at: UNIX_EPOCH + Duration::from_millis(1_700_000_100_000 + seq),
            direction,
            data: Bytes::copy_from_slice(data),
        }
    }

    #[test]
    fn streams_and_messages_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();

        let mut stream = sample_stream();
        store.upsert_stream(&stream).unwrap();

        // Binary payloads, both directions, and a completed state written back.
        let c2s = sample_message(stream.id, 0, Direction::ClientToServer, b"PING\r\n");
        let s2c = sample_message(stream.id, 1, Direction::ServerToClient, &[0x00, 0xFF, 0x0A]);
        store.append_messages(&[c2s.clone(), s2c.clone()]).unwrap();

        stream.completed_at = Some(UNIX_EPOCH + Duration::from_millis(1_700_000_200_000));
        stream.state = FlowState::Completed;
        store.upsert_stream(&stream).unwrap();

        let got = store.get_stream(stream.id).unwrap().expect("stream present");
        assert_eq!(got.host, "redis.internal");
        assert_eq!(got.port, 6379);
        assert_eq!(got.transport, Transport::Tcp);
        assert!(!got.tls);
        assert_eq!(got.state, FlowState::Completed);
        assert_eq!(got.client_addr, "127.0.0.1:51000".parse().unwrap());
        assert_eq!(got.completed_at, stream.completed_at);

        let messages = store.messages_for(stream.id).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].seq, 0);
        assert_eq!(messages[0].direction, Direction::ClientToServer);
        assert_eq!(&messages[0].data[..], b"PING\r\n");
        assert_eq!(messages[1].direction, Direction::ServerToClient);
        assert_eq!(&messages[1].data[..], &[0x00, 0xFF, 0x0A]);

        assert_eq!(store.count_streams().unwrap(), 1);
        assert_eq!(store.list_streams(10).unwrap().len(), 1);
        // A stream from another association is not mixed in.
        assert!(store.messages_for(Uuid::new_v4()).unwrap().is_empty());
    }

    #[test]
    fn udp_streams_and_ordering_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        let stream_id = {
            let mut store = Store::create(&path, "pw").unwrap();
            let stream = Stream {
                transport: Transport::Udp,
                tls: false,
                ..sample_stream()
            };
            store.upsert_stream(&stream).unwrap();
            // Appended out of order on purpose: reading must sort by seq.
            store
                .append_messages(&[
                    sample_message(stream.id, 2, Direction::ServerToClient, b"third"),
                    sample_message(stream.id, 0, Direction::ClientToServer, b"first"),
                    sample_message(stream.id, 1, Direction::ClientToServer, b"second"),
                ])
                .unwrap();
            stream.id
        };

        let store = Store::open(&path, "pw").unwrap();
        let got = store.get_stream(stream_id).unwrap().expect("stream present");
        assert_eq!(got.transport, Transport::Udp);
        let messages = store.messages_for(stream_id).unwrap();
        let seqs: Vec<u64> = messages.iter().map(|m| m.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2], "messages come back in sequence order");
        assert_eq!(&messages[2].data[..], b"third");
    }

    fn sample_ws() -> WsMessage {
        WsMessage {
            id: Uuid::new_v4(),
            connection: "127.0.0.1:5000 <-> example.com:443".into(),
            connection_id: Uuid::new_v4(),
            at: UNIX_EPOCH + Duration::from_millis(1_700_000_300_000),
            client_addr: "127.0.0.1:5000".parse().unwrap(),
            scheme: Scheme::Https,
            host: "example.com".into(),
            port: 443,
            direction: WsDirection::ServerToClient,
            kind: WsKind::Binary,
            payload: Bytes::from_static(&[0x00, 0xff, 0x0a]),
            paused: false,
        }
    }

    fn sample_run(proposal_id: Uuid) -> AgentRun {
        AgentRun {
            id: Uuid::new_v4(),
            proposal_id: Some(proposal_id),
            tool_id: "nmap".into(),
            program: "nmap".into(),
            argv: vec!["-sV".into(), "127.0.0.1".into()],
            targets: vec!["127.0.0.1".into()],
            effective_intrusiveness: "low".into(),
            required_privileges: vec![],
            started_at: UNIX_EPOCH + Duration::from_millis(1_700_000_400_000),
            completed_at: UNIX_EPOCH + Duration::from_millis(1_700_000_400_250),
            status: Some(0),
            stdout: b"80/tcp open\n".to_vec(),
            stderr: vec![0x00, 0xff],
            duration_ms: 250,
            error: None,
        }
    }

    #[test]
    fn ws_frames_round_trip_including_binary_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        let frame = sample_ws();
        {
            let mut store = Store::create(&path, "pw").unwrap();
            store.append_ws_message(&frame).unwrap();
            store.append_ws_messages(&[sample_ws(), sample_ws()]).unwrap();
            assert_eq!(store.count_ws_messages().unwrap(), 3);
            // Same id twice: replaced, not duplicated.
            store.append_ws_message(&frame).unwrap();
            assert_eq!(store.count_ws_messages().unwrap(), 3);
            // An empty batch is a no-op.
            store.append_ws_messages(&[]).unwrap();
        }

        let store = Store::open(&path, "pw").unwrap();
        let frames = store.list_ws_messages(10).unwrap();
        assert_eq!(frames.len(), 3);
        let got = frames.iter().find(|f| f.id == frame.id).unwrap();
        assert_eq!(got.connection_id, frame.connection_id);
        assert_eq!(got.connection, frame.connection);
        assert_eq!(got.host, "example.com");
        assert_eq!(got.port, 443);
        assert_eq!(got.scheme, Scheme::Https);
        assert_eq!(got.direction, WsDirection::ServerToClient);
        assert_eq!(got.kind, WsKind::Binary);
        assert_eq!(&got.payload[..], &[0x00, 0xff, 0x0a]);
        assert_eq!(got.at, frame.at);
        assert!(!got.paused, "stored frames are by definition forwarded");
    }

    #[test]
    fn the_recent_ws_window_comes_back_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();
        for i in 0..5u64 {
            let mut frame = sample_ws();
            frame.at = UNIX_EPOCH + Duration::from_millis(1_700_000_300_000 + i);
            frame.payload = Bytes::from(i.to_string());
            store.append_ws_message(&frame).unwrap();
        }
        let last_two = store.list_ws_messages(2).unwrap();
        assert_eq!(last_two.len(), 2);
        assert_eq!(&last_two[0].payload[..], b"3");
        assert_eq!(&last_two[1].payload[..], b"4");
    }

    #[test]
    fn agent_runs_round_trip_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proj.elliot");
        let proposal = Uuid::new_v4();
        let run = sample_run(proposal);
        {
            let store = Store::create(&path, "pw").unwrap();
            store.append_agent_run(&run).unwrap();
            let mut older = sample_run(Uuid::new_v4());
            older.started_at = UNIX_EPOCH + Duration::from_millis(1_700_000_300_000);
            older.completed_at = older.started_at;
            older.status = None;
            older.error = Some("timeout".into());
            older.required_privileges = vec!["raw_socket".into()];
            store.append_agent_run(&older).unwrap();
        }

        let store = Store::open(&path, "pw").unwrap();
        let runs = store.list_agent_runs(10).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].id, run.id, "newest first");
        let got = &runs[0];
        assert_eq!(got.proposal_id, Some(proposal));
        assert_eq!(got.tool_id, "nmap");
        assert_eq!(got.program, "nmap");
        assert_eq!(got.argv, vec!["-sV", "127.0.0.1"]);
        assert_eq!(got.targets, vec!["127.0.0.1"]);
        assert_eq!(got.effective_intrusiveness, "low");
        assert!(got.required_privileges.is_empty());
        assert_eq!(got.started_at, run.started_at);
        assert_eq!(got.completed_at, run.completed_at);
        assert_eq!(got.status, Some(0));
        assert_eq!(got.stdout, b"80/tcp open\n".to_vec());
        assert_eq!(got.stderr, vec![0x00, 0xff], "stderr is bytes, not text");
        assert_eq!(got.duration_ms, 250);
        assert!(got.error.is_none());

        assert_eq!(runs[1].status, None);
        assert_eq!(runs[1].error.as_deref(), Some("timeout"));
        assert_eq!(runs[1].required_privileges, vec!["raw_socket"]);
    }

    /// A file written by the first release (HTTP flows only, `user_version` 1)
    /// must open and gain the new tables **without losing anything**.
    #[test]
    fn a_v1_file_is_migrated_to_v3_and_keeps_its_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.elliot");

        let flow_id = {
            let store = Store::create(&path, "pw").unwrap();
            let flow = sample_flow();
            store.upsert_flow(&flow).unwrap();
            store.set_setting("scope_policy", b"kept").unwrap();

            // Stand in for a v1 file: none of the later tables, old stamp.
            store
                .conn
                .execute_batch(
                    "DROP TABLE agent_runs; DROP TABLE ws_messages; \
                     DROP TABLE messages; DROP TABLE streams;",
                )
                .unwrap();
            store.conn.pragma_update(None, "user_version", 1).unwrap();
            flow.id
        };

        let store = Store::open(&path, "pw").unwrap();

        // Migrated, and the new tables are usable straight away.
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let stream = sample_stream();
        store.upsert_stream(&stream).unwrap();
        store
            .append_message(&sample_message(stream.id, 0, Direction::ClientToServer, b"hi"))
            .unwrap();
        store.append_ws_message(&sample_ws()).unwrap();
        store.append_agent_run(&sample_run(Uuid::new_v4())).unwrap();

        // Old data survived.
        assert!(store.get_flow(flow_id).unwrap().is_some());
        assert_eq!(store.get_setting("scope_policy").unwrap().unwrap(), b"kept".to_vec());
        assert_eq!(store.count_flows().unwrap(), 1);
    }

    /// A v2 project (streams + messages, no WebSocket/agent tables) must gain
    /// the v3 tables without losing the streams it holds.
    #[test]
    fn a_v2_file_is_migrated_to_v3_and_keeps_its_streams() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v2.elliot");

        let (stream_id, message_id) = {
            let mut store = Store::create(&path, "pw").unwrap();
            let stream = sample_stream();
            store.upsert_stream(&stream).unwrap();
            let message = sample_message(stream.id, 0, Direction::ClientToServer, b"kept");
            store.append_messages(std::slice::from_ref(&message)).unwrap();

            // Stand in for a v2 file: the v3 tables and stamp were introduced
            // after it was written.
            store
                .conn
                .execute_batch("DROP TABLE agent_runs; DROP TABLE ws_messages;")
                .unwrap();
            store.conn.pragma_update(None, "user_version", 2).unwrap();
            (stream.id, message.id)
        };

        let store = Store::open(&path, "pw").unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Old data survived.
        let stream = store.get_stream(stream_id).unwrap().expect("stream kept");
        assert_eq!(stream.host, "redis.internal");
        let messages = store.messages_for(stream_id).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, message_id);
        assert_eq!(&messages[0].data[..], b"kept");

        // And the new tables work.
        store.append_ws_message(&sample_ws()).unwrap();
        assert_eq!(store.count_ws_messages().unwrap(), 1);
        store.append_agent_run(&sample_run(Uuid::new_v4())).unwrap();
        assert_eq!(store.list_agent_runs(1).unwrap().len(), 1);
    }

    #[test]
    fn opening_a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.elliot");
        {
            let store = Store::create(&path, "pw").unwrap();
            store
                .conn
                .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = Store::open(&path, "pw")
            .err()
            .expect("a newer schema must not be opened");
        assert!(matches!(err, StoreError::SchemaVersion { .. }), "got {err:?}");
    }

    #[test]
    fn appending_an_empty_batch_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(dir.path().join("proj.elliot"), "pw").unwrap();
        store.append_messages(&[]).unwrap();
        assert_eq!(store.count_streams().unwrap(), 0);
    }

    #[test]
    fn header_codec_round_trips_and_is_strict() {
        let headers = vec![
            Header {
                name: "Host".into(),
                value: b"example.com".to_vec(),
            },
            Header {
                name: "X-Odd".into(),
                value: vec![0x00, 0x80, 0xFF],
            },
        ];
        let encoded = encode_headers(&headers);
        assert_eq!(decode_headers(&encoded).unwrap(), headers);
        // Binary, length-prefixed — not a JSON array of integers.
        assert!(encoded.len() < 64, "encoding is {} bytes", encoded.len());

        // Empty list round-trips to empty.
        assert!(decode_headers(&encode_headers(&[])).unwrap().is_empty());

        // Truncated or inconsistent input is an error, never a panic.
        assert!(decode_headers(&[]).is_err());
        assert!(decode_headers(&encoded[..3]).is_err());
        assert!(decode_headers(&encoded[..encoded.len() - 1]).is_err());
    }
}
