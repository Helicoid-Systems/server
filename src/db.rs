//! SQLite storage: open/create, explicit schema install, transactions.
//!
//! Fresh empty databases get schema v1. Databases that already contain
//! unrelated tables are refused. Schema mismatches are refused; this build
//! never auto-migrates existing user data.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::error::{AppError, AppResult};

/// Schema version installed by this build. Refuses to open a newer schema.
pub const SCHEMA_VERSION: i64 = 1;

/// Opens (or creates) the database file and ensures schema version matches.
pub fn open(path: &Path) -> AppResult<Db> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| AppError::Api {
                code: crate::error::ErrorCode::Internal,
                message: format!("failed to create data directory: {err}"),
                detail: None,
            })?;
        }
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    ensure_schema(&conn)?;
    Ok(Db {
        conn: Mutex::new(conn),
    })
}

/// In-memory database for tests.
pub fn open_in_memory() -> AppResult<Db> {
    let conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    ensure_schema(&conn)?;
    Ok(Db {
        conn: Mutex::new(conn),
    })
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn lock(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| AppError::internal("database lock poisoned"))
    }

    /// Run `f` inside a single immediate transaction.
    ///
    /// Commits on `Ok`. On `Err` the transaction is rolled back on drop and
    /// the original error is returned. Constraint failures surface as
    /// `AppError::Storage` (or mapped conflict) so callers can latch
    /// security-state checks without inventing success.
    pub fn transaction<T>(&self, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        let mut conn = self.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AppError::Storage)?;
        match f(&tx) {
            Ok(value) => {
                tx.commit().map_err(AppError::Storage)?;
                Ok(value)
            }
            Err(err) => {
                // `tx` drops and rolls back before returning the error.
                drop(tx);
                Err(err)
            }
        }
    }
}

fn table_exists(conn: &Connection, name: &str) -> AppResult<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn user_table_count(conn: &Connection) -> AppResult<i64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

/// Install schema only on a truly empty database; refuse unrelated content
/// and refuse version mismatches instead of auto-migrating.
fn ensure_schema(conn: &Connection) -> AppResult<()> {
    if !table_exists(conn, "schema_meta")? {
        let existing_tables = user_table_count(conn)?;
        if existing_tables > 0 {
            return Err(AppError::unprocessable(
                "database is not empty and has no hs-server schema; refusing to initialize over unrelated data",
            ));
        }
        install_schema(conn)?;
        return Ok(());
    }

    let version: Option<i64> = conn
        .query_row(
            "SELECT schema_version FROM schema_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;

    match version {
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(v) => Err(AppError::unprocessable(format!(
            "database schema version {v} is not supported by this build (expected {SCHEMA_VERSION}); refusing automatic migration"
        ))),
        None => Err(AppError::unprocessable(
            "schema_meta exists but has no version row; refusing to initialize",
        )),
    }
}

fn install_schema(conn: &Connection) -> AppResult<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(SCHEMA_SQL)?;
    tx.execute(
        "INSERT INTO schema_meta (id, schema_version) VALUES (1, ?1)",
        params![SCHEMA_VERSION],
    )?;
    tx.execute(
        "INSERT INTO deployment (
            id, bootstrap_completed, security_state_ok, created_at
         ) VALUES (1, 0, 1, ?1)",
        params![now_unix()],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE schema_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL
);

CREATE TABLE deployment (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    bootstrap_completed INTEGER NOT NULL DEFAULT 0,
    bootstrap_completed_at INTEGER,
    security_state_ok INTEGER NOT NULL DEFAULT 1,
    security_state_note TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE bootstrap_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    can_operate INTEGER NOT NULL DEFAULT 0,
    can_manage_enrollment INTEGER NOT NULL DEFAULT 0,
    can_manage_access INTEGER NOT NULL DEFAULT 0,
    can_manage_accounts INTEGER NOT NULL DEFAULT 0,
    can_manage_security INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX accounts_username_unique ON accounts (username COLLATE NOCASE);

CREATE TABLE managers (
    id TEXT PRIMARY KEY,
    public_identity TEXT NOT NULL,
    friendly_name TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('pending', 'approved', 'revoked')),
    approved_by_account_id TEXT REFERENCES accounts(id),
    approved_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX managers_public_identity_unique ON managers (public_identity);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    manager_id TEXT REFERENCES managers(id),
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE UNIQUE INDEX sessions_token_hash_unique ON sessions (token_hash);
CREATE INDEX sessions_account_idx ON sessions (account_id);

CREATE TABLE computers (
    id TEXT PRIMARY KEY,
    public_identity TEXT NOT NULL,
    friendly_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    enrollment_state TEXT NOT NULL CHECK (enrollment_state IN ('pending', 'enrolled', 'quarantined', 'revoked')),
    enrollment_epoch INTEGER NOT NULL DEFAULT 1,
    approved_incarnation_identity TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX computers_public_identity_unique ON computers (public_identity);

CREATE TABLE access_assignments (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    capability TEXT NOT NULL CHECK (capability IN ('operate', 'observe', 'install_maintain')),
    computer_scope_all INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX access_assignment_unique ON access_assignments (account_id, capability);

CREATE TABLE access_computer_scope (
    assignment_id TEXT NOT NULL REFERENCES access_assignments(id) ON DELETE CASCADE,
    computer_id TEXT NOT NULL REFERENCES computers(id),
    PRIMARY KEY (assignment_id, computer_id)
);

CREATE TABLE login_attempts (
    username_key TEXT PRIMARY KEY,
    failure_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    updated_at INTEGER NOT NULL
);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_installs_once_on_fresh_db() {
        let db = open_in_memory().expect("open");
        {
            let conn = db.lock().expect("lock");
            let version: i64 = conn
                .query_row(
                    "SELECT schema_version FROM schema_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .expect("version");
            assert_eq!(version, SCHEMA_VERSION);
            // Core tables exist after first install.
            assert!(table_exists(&conn, "accounts").expect("exists"));
            assert!(table_exists(&conn, "deployment").expect("exists"));
            assert!(table_exists(&conn, "bootstrap_tokens").expect("exists"));
        }
        {
            let conn = db.lock().expect("lock");
            ensure_schema(&conn).expect("ensure again is a no-op");
        }
    }

    #[test]
    fn refuses_unrelated_nonempty_database() {
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
            .expect("create unrelated");
        let err = ensure_schema(&conn).expect_err("must refuse");
        match err {
            AppError::Api { code, message, .. } => {
                assert_eq!(code, crate::error::ErrorCode::Unprocessable);
                assert!(message.contains("refusing"), "message={message}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fresh_empty_db_initializes_without_querying_missing_table() {
        // Regression: ensure_schema must not SELECT from schema_meta before it exists.
        let conn = Connection::open_in_memory().expect("open");
        assert!(!table_exists(&conn, "schema_meta").expect("probe"));
        ensure_schema(&conn).expect("install on empty");
        assert!(table_exists(&conn, "schema_meta").expect("probe after"));
    }

    #[test]
    fn transaction_rolls_back_on_error() {
        let db = open_in_memory().expect("open");
        let result: AppResult<()> = db.transaction(|conn| {
            conn.execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    enrollment_epoch, created_at, updated_at
                 ) VALUES ('c1', 'pub-1', 'Lab A', 'windows', 'pending', 1, 1, 1)",
                [],
            )?;
            Err(AppError::conflict("forced", None))
        });
        assert!(result.is_err());
        let conn = db.lock().expect("lock");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM computers", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn unique_claims_conflict() {
        let db = open_in_memory().expect("open");
        db.transaction(|conn| {
            conn.execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    enrollment_epoch, created_at, updated_at
                 ) VALUES ('c1', 'pub-1', 'Lab A', 'windows', 'pending', 1, 1, 1)",
                [],
            )?;
            Ok(())
        })
        .expect("first insert");
        let second = db.transaction(|conn| {
            conn.execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    enrollment_epoch, created_at, updated_at
                 ) VALUES ('c2', 'pub-1', 'Lab B', 'windows', 'pending', 1, 1, 1)",
                [],
            )?;
            Ok(())
        });
        assert!(matches!(second, Err(AppError::Storage(_))));
    }
}
