//! elliot-store — the per-project, passphrase-encrypted SQLite store.
//!
//! The project file **is** the database: a single SQLCipher file holding the
//! captured traffic, encrypted at rest from the first write (the file carries
//! credentials, tokens, PII and client data). Handing a project off is copying
//! one file.
//!
//! This crate owns the schema and the [`Flow`] persistence. It is deliberately
//! synchronous (rusqlite); the app wraps a [`Store`] behind its own lock and
//! calls it off the UI thread.
//!
//! Writes come in two shapes: [`Store::upsert_flow`] for a single flow and
//! [`Store::upsert_flows`] for a burst in one transaction. Header lists are
//! stored as a compact length-prefixed binary blob (values are arbitrary
//! bytes).
//!
//! Scope of this first cut: open/create an encrypted file, version the schema,
//! and upsert / fetch / list [`Flow`]s. Migrations beyond v1, the catalog and
//! repeater/intruder history, and streaming queries are follow-ups.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use elliot_httpraw::{
    Flow, FlowState, Header, HttpVersion, Request, Response, Scheme, ScopeDecision,
};

/// Current on-disk schema version, stored in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

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
    /// version is not understood by this build.
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", passphrase)?;
        // The first real read decrypts a page; a wrong key fails right here.
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::SchemaVersion {
                found: version,
                supported: SCHEMA_VERSION,
            });
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
}

/// Create the schema. Every statement is `IF NOT EXISTS`, so this is safe on a
/// fresh file and on one written by an earlier build.
fn init_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        r#"
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
        "#,
    )?;
    Ok(())
}

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
