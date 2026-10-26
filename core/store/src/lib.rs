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
//! Scope of this first cut: open/create an encrypted file, version the schema,
//! and upsert / fetch / list [`Flow`]s. Migrations beyond v1, the catalog and
//! repeater/intruder history, and streaming queries are follow-ups.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use elliot_httpraw::{Flow, FlowState, Header, HttpVersion, Request, Response, Scheme, ScopeDecision};

/// Current on-disk schema version, stored in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialize headers: {0}")]
    Json(#[from] serde_json::Error),
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
    /// Create a new encrypted project file and initialize the schema. Fails if
    /// the file already exists so an existing project is never clobbered.
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", passphrase)?;
        // Touch the database so the key actually takes effect, then build it.
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
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
        Ok(Self { conn })
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
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
            "#,
        )?;
        Ok(())
    }

    /// Insert or replace a flow.
    pub fn upsert_flow(&self, flow: &Flow) -> Result<(), StoreError> {
        let req_headers = serde_json::to_vec(&flow.request.headers)?;
        let (status, resp_reason, resp_version, resp_headers, resp_body, resp_raw) =
            match &flow.response {
                Some(r) => (
                    Some(i64::from(r.status)),
                    Some(r.reason.clone()),
                    Some(r.version.as_token().to_string()),
                    Some(serde_json::to_vec(&r.headers)?),
                    Some(r.body.to_vec()),
                    Some(r.raw.to_vec()),
                ),
                None => (None, None, None, None, None, None),
            };

        self.conn.execute(
            r#"
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
            "#,
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

const COLUMNS: &str = "id, started_at, completed_at, client_addr, scheme, host, port, \
     method, target, req_version, req_headers, req_body, req_raw, \
     status, resp_reason, resp_version, resp_headers, resp_body, resp_raw, \
     state, scope, error";

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
        headers: serde_json::from_slice(&req_headers)?,
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
                Some(h) => serde_json::from_slice::<Vec<Header>>(&h)?,
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
}
