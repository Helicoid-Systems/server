//! SQLite storage: open/create, explicit schema install, versioned migrations.
//!
//! Fresh empty databases get the current schema. Databases that already
//! contain unrelated tables are refused. Schema mismatches are refused;
//! this build never auto-migrates existing user data on startup. Operators
//! run `hs-server migrate`, which takes a consistent pre-migration backup.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::error::{AppError, AppResult};

/// Schema version installed by this build. Refuses to open a newer schema.
pub const SCHEMA_VERSION: i64 = 2;

/// Opens (or creates) the database file and ensures schema version matches.
///
/// Never migrates: an older nonempty schema is refused with instructions
/// to run the explicit `migrate` command.
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

/// In-memory database for tests. Installs the current schema directly.
pub fn open_in_memory() -> AppResult<Db> {
    let conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    install_schema(&conn)?;
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

fn schema_version(conn: &Connection) -> AppResult<Option<i64>> {
    if !table_exists(conn, "schema_meta")? {
        return Ok(None);
    }
    let version: Option<i64> = conn
        .query_row(
            "SELECT schema_version FROM schema_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(version)
}

/// Install schema only on a truly empty database; refuse unrelated content
/// and refuse version mismatches instead of auto-migrating.
fn ensure_schema(conn: &Connection) -> AppResult<()> {
    match schema_version(conn)? {
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(v) if v < SCHEMA_VERSION => Err(AppError::unprocessable(format!(
            "database schema version {v} is older than this build ({SCHEMA_VERSION}); \
             run `hs-server migrate` after taking a backup — startup never auto-migrates"
        ))),
        Some(v) => Err(AppError::unprocessable(format!(
            "database schema version {v} is not supported by this build (expected {SCHEMA_VERSION}); refusing automatic migration"
        ))),
        None => {
            let existing_tables = user_table_count(conn)?;
            if existing_tables > 0 {
                return Err(AppError::unprocessable(
                    "database is not empty and has no hs-server schema; refusing to initialize over unrelated data",
                ));
            }
            install_schema(conn)
        }
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
            id, bootstrap_completed, security_state_ok, created_at, deployment_key
         ) VALUES (1, 0, 1, ?1, ?2)",
        params![now_unix(), new_deployment_key()],
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

/// Server-owned deployment identity (not client-selectable). Used in auth v2
/// proof messages so a challenge cannot be replayed across deployments.
pub fn new_deployment_key() -> String {
    format!("dep_{}", uuid::Uuid::new_v4().simple())
}

/// Max retained auth challenges (pending + recently consumed). Older rows are
/// pruned; request-driven growth is bounded.
pub const MAX_AUTH_CHALLENGE_ROWS: i64 = 4096;
/// Max retained TOTP consumption rows per account (time-step ledger).
pub const MAX_TOTP_CONSUMPTIONS_PER_ACCOUNT: i64 = 64;
/// Max durable challenge-throttle keys.
pub const MAX_CHALLENGE_THROTTLE_KEYS: i64 = 4096;

/// Read the server-owned deployment key. Missing/empty fails closed.
pub fn deployment_key(conn: &Connection) -> AppResult<String> {
    let key: Option<String> = conn
        .query_row(
            "SELECT deployment_key FROM deployment WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match key {
        Some(k) if !k.is_empty() => Ok(k),
        _ => Err(AppError::internal(
            "deployment_key missing; refusing auth v2 proof binding",
        )),
    }
}

/// Prune expired/consumed auth challenges past the storage cap.
pub fn prune_auth_challenges(conn: &Connection, now: i64) -> AppResult<()> {
    // Drop consumed/expired rows first, then enforce the hard cap.
    conn.execute(
        "DELETE FROM auth_challenges
         WHERE (consumed_at IS NOT NULL AND consumed_at < ?1)
            OR (consumed_at IS NULL AND expires_at < ?1)",
        params![now - 3600],
    )?;
    conn.execute(
        "DELETE FROM auth_challenges WHERE id IN (
            SELECT id FROM auth_challenges
            ORDER BY created_at DESC LIMIT -1 OFFSET ?1
         )",
        params![MAX_AUTH_CHALLENGE_ROWS],
    )?;
    Ok(())
}

/// Prune the TOTP consumption ledger to a bounded per-account window.
pub fn prune_totp_consumptions(conn: &Connection, account_id: &str) -> AppResult<()> {
    conn.execute(
        "DELETE FROM totp_consumptions WHERE account_id = ?1 AND time_step NOT IN (
            SELECT time_step FROM totp_consumptions
            WHERE account_id = ?1
            ORDER BY time_step DESC LIMIT ?2
         )",
        params![account_id, MAX_TOTP_CONSUMPTIONS_PER_ACCOUNT],
    )?;
    Ok(())
}

/// Prune durable challenge-throttle rows past the key cap (oldest first).
pub fn prune_challenge_throttle(conn: &Connection, now: i64) -> AppResult<()> {
    conn.execute(
        "DELETE FROM challenge_throttle
         WHERE (locked_until IS NULL OR locked_until < ?1) AND updated_at < ?2",
        params![now, now - 3600],
    )?;
    conn.execute(
        "DELETE FROM challenge_throttle WHERE throttle_key IN (
            SELECT throttle_key FROM challenge_throttle
            ORDER BY updated_at DESC LIMIT -1 OFFSET ?1
         )",
        params![MAX_CHALLENGE_THROTTLE_KEYS],
    )?;
    Ok(())
}

// ----- explicit migration -----

/// Result of a successful explicit migration.
#[derive(Debug)]
pub struct MigrationReport {
    pub from_version: i64,
    pub to_version: i64,
    pub backup_path: PathBuf,
}

/// Consistent pre-migration backup + schema-versioned upgrade.
///
/// Never runs on startup. Takes a WAL-checkpointed file copy backup before
/// any DDL, then applies migrations in a single transaction. On any failure
/// the original database is left untouched and the error is returned.
pub fn migrate(path: &Path, backup_dir: &Path) -> AppResult<MigrationReport> {
    if !path.exists() {
        return Err(AppError::unprocessable(
            "database file does not exist; nothing to migrate",
        ));
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;

    let from = schema_version(&conn)?.ok_or_else(|| {
        AppError::unprocessable("database has no hs-server schema; refusing to migrate")
    })?;
    if from == SCHEMA_VERSION {
        return Err(AppError::unprocessable(format!(
            "database schema is already at version {SCHEMA_VERSION}; no migration needed"
        )));
    }
    if from > SCHEMA_VERSION {
        return Err(AppError::unprocessable(format!(
            "database schema version {from} is newer than this build ({SCHEMA_VERSION})"
        )));
    }

    let backup_path = backup_database(&conn, backup_dir, from)?;
    apply_migrations(&conn, from)?;

    Ok(MigrationReport {
        from_version: from,
        to_version: SCHEMA_VERSION,
        backup_path,
    })
}

/// WAL-checkpointed consistent copy of the live database.
fn backup_database(conn: &Connection, backup_dir: &Path, from: i64) -> AppResult<PathBuf> {
    std::fs::create_dir_all(backup_dir)
        .map_err(|err| AppError::internal(format!("failed to create backup directory: {err}")))?;
    // Flush WAL so the main file is consistent before copy.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let file_name = format!(
        "hs-server-pre-migrate-v{}-{}.db",
        from,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let backup_path = backup_dir.join(file_name);
    let backup_str = backup_path.to_string_lossy().into_owned();
    conn.execute("VACUUM INTO ?1", params![backup_str])?;
    Ok(backup_path)
}

fn apply_migrations(conn: &Connection, from: i64) -> AppResult<()> {
    let tx = conn.unchecked_transaction()?;
    if from < 2 {
        migrate_v1_to_v2(&tx)?;
        // Mint a server-owned deployment key for existing databases.
        let key = new_deployment_key();
        tx.execute(
            "UPDATE deployment SET deployment_key = ?1 WHERE id = 1 AND (deployment_key IS NULL OR deployment_key = '')",
            params![key],
        )?;
    }
    tx.execute(
        "UPDATE schema_meta SET schema_version = ?1 WHERE id = 1",
        params![SCHEMA_VERSION],
    )?;
    tx.commit()?;
    Ok(())
}

/// v1 → v2: MFA factors, recovery codes, auth challenges, manager device keys.
///
/// Accounts gain `pending_mfa` state (inactive until MFA confirmation and
/// independently stored recovery material). Managers gain an Ed25519
/// `public_key`. New tables carry TOTP secrets, hashed recovery codes,
/// consumed time steps, and durable one-use challenges.
fn migrate_v1_to_v2(conn: &Connection) -> AppResult<()> {
    // Rebuild accounts to widen the state CHECK constraint.
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys=off;

        CREATE TABLE accounts_v2 (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending_mfa', 'active', 'disabled')),
            can_operate INTEGER NOT NULL DEFAULT 0,
            can_manage_enrollment INTEGER NOT NULL DEFAULT 0,
            can_manage_access INTEGER NOT NULL DEFAULT 0,
            can_manage_accounts INTEGER NOT NULL DEFAULT 0,
            can_manage_security INTEGER NOT NULL DEFAULT 0,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        INSERT INTO accounts_v2 (
            id, username, password_hash, state,
            can_operate, can_manage_enrollment, can_manage_access,
            can_manage_accounts, can_manage_security,
            revision, created_at, updated_at
        )
        SELECT
            id, username, password_hash, state,
            can_operate, can_manage_enrollment, can_manage_access,
            can_manage_accounts, can_manage_security,
            revision, created_at, updated_at
        FROM accounts;

        DROP TABLE accounts;
        ALTER TABLE accounts_v2 RENAME TO accounts;
        CREATE UNIQUE INDEX accounts_username_unique ON accounts (username COLLATE NOCASE);

        ALTER TABLE managers ADD COLUMN public_key TEXT;
        CREATE UNIQUE INDEX managers_public_key_unique
            ON managers (public_key) WHERE public_key IS NOT NULL;

        ALTER TABLE deployment ADD COLUMN deployment_key TEXT NOT NULL DEFAULT '';

        CREATE TABLE account_mfa (
            account_id TEXT PRIMARY KEY REFERENCES accounts(id),
            totp_secret TEXT NOT NULL,
            totp_confirmed_at INTEGER,
            recovery_stored_at INTEGER,
            status TEXT NOT NULL CHECK (status IN ('pending', 'active')),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE recovery_codes (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            code_hash TEXT NOT NULL,
            used_at INTEGER,
            created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX recovery_codes_hash_unique ON recovery_codes (code_hash);
        CREATE INDEX recovery_codes_account_idx ON recovery_codes (account_id);

        CREATE TABLE totp_consumptions (
            account_id TEXT NOT NULL REFERENCES accounts(id),
            time_step INTEGER NOT NULL,
            consumed_at INTEGER NOT NULL,
            PRIMARY KEY (account_id, time_step)
        );

        CREATE TABLE auth_challenges (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            manager_public_key TEXT NOT NULL,
            operation TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            deployment_key TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX auth_challenges_token_hash_unique ON auth_challenges (token_hash);
        CREATE INDEX auth_challenges_account_idx ON auth_challenges (account_id);

        CREATE TABLE mfa_enrollments (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            totp_secret TEXT NOT NULL,
            recovery_committed INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER
        );
        CREATE INDEX mfa_enrollments_account_idx ON mfa_enrollments (account_id);

        CREATE TABLE challenge_throttle (
            throttle_key TEXT PRIMARY KEY,
            failure_count INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER,
            updated_at INTEGER NOT NULL
        );

        PRAGMA foreign_keys=on;
        "#,
    )?;
    Ok(())
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
    created_at INTEGER NOT NULL,
    deployment_key TEXT NOT NULL DEFAULT ''
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
    state TEXT NOT NULL CHECK (state IN ('pending_mfa', 'active', 'disabled')),
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
    updated_at INTEGER NOT NULL,
    public_key TEXT
);

CREATE UNIQUE INDEX managers_public_identity_unique ON managers (public_identity);
CREATE UNIQUE INDEX managers_public_key_unique
    ON managers (public_key) WHERE public_key IS NOT NULL;

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

CREATE TABLE account_mfa (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id),
    totp_secret TEXT NOT NULL,
    totp_confirmed_at INTEGER,
    recovery_stored_at INTEGER,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    code_hash TEXT NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX recovery_codes_hash_unique ON recovery_codes (code_hash);
CREATE INDEX recovery_codes_account_idx ON recovery_codes (account_id);

CREATE TABLE totp_consumptions (
    account_id TEXT NOT NULL REFERENCES accounts(id),
    time_step INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, time_step)
);

CREATE TABLE auth_challenges (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    manager_public_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    deployment_key TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX auth_challenges_token_hash_unique ON auth_challenges (token_hash);
CREATE INDEX auth_challenges_account_idx ON auth_challenges (account_id);

CREATE TABLE mfa_enrollments (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    totp_secret TEXT NOT NULL,
    recovery_committed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE INDEX mfa_enrollments_account_idx ON mfa_enrollments (account_id);

CREATE TABLE challenge_throttle (
    throttle_key TEXT PRIMARY KEY,
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
            assert!(table_exists(&conn, "accounts").expect("exists"));
            assert!(table_exists(&conn, "deployment").expect("exists"));
            assert!(table_exists(&conn, "bootstrap_tokens").expect("exists"));
            assert!(table_exists(&conn, "account_mfa").expect("exists"));
            assert!(table_exists(&conn, "recovery_codes").expect("exists"));
            assert!(table_exists(&conn, "auth_challenges").expect("exists"));
            assert!(table_exists(&conn, "totp_consumptions").expect("exists"));
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

    #[test]
    fn open_refuses_older_schema_without_auto_migrate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("old.db");
        {
            let conn = Connection::open(&path).expect("open");
            conn.execute_batch(
                "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL);
                 INSERT INTO schema_meta (id, schema_version) VALUES (1, 1);
                 CREATE TABLE accounts (id TEXT PRIMARY KEY, username TEXT NOT NULL,
                     password_hash TEXT NOT NULL, state TEXT NOT NULL,
                     can_operate INTEGER NOT NULL DEFAULT 0,
                     can_manage_enrollment INTEGER NOT NULL DEFAULT 0,
                     can_manage_access INTEGER NOT NULL DEFAULT 0,
                     can_manage_accounts INTEGER NOT NULL DEFAULT 0,
                     can_manage_security INTEGER NOT NULL DEFAULT 0,
                     revision INTEGER NOT NULL DEFAULT 1,
                     created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);",
            )
            .expect("seed v1");
        }
        let err = match open(&path) {
            Ok(_) => panic!("must refuse older schema"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("migrate"), "msg={msg}");
        assert!(
            msg.contains("auto-migrates") || msg.contains("never"),
            "msg={msg}"
        );
    }

    #[test]
    fn migrate_takes_backup_and_upgrades() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v1.db");
        let backup_dir = dir.path().join("backups");
        {
            let conn = Connection::open(&path).expect("open");
            conn.execute_batch(
                "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL);
                 INSERT INTO schema_meta (id, schema_version) VALUES (1, 1);
                 CREATE TABLE deployment (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    bootstrap_completed INTEGER NOT NULL DEFAULT 0,
                    bootstrap_completed_at INTEGER,
                    security_state_ok INTEGER NOT NULL DEFAULT 1,
                    security_state_note TEXT,
                    created_at INTEGER NOT NULL
                 );
                 INSERT INTO deployment (id, bootstrap_completed, security_state_ok, created_at)
                    VALUES (1, 1, 1, 100);
                 CREATE TABLE bootstrap_tokens (
                    token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL, consumed_at INTEGER);
                 CREATE TABLE accounts (
                    id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
                    can_operate INTEGER NOT NULL DEFAULT 0,
                    can_manage_enrollment INTEGER NOT NULL DEFAULT 0,
                    can_manage_access INTEGER NOT NULL DEFAULT 0,
                    can_manage_accounts INTEGER NOT NULL DEFAULT 0,
                    can_manage_security INTEGER NOT NULL DEFAULT 0,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 INSERT INTO accounts (id, username, password_hash, state, created_at, updated_at)
                    VALUES ('a1', 'admin', 'hash', 'active', 100, 100);
                 CREATE UNIQUE INDEX accounts_username_unique ON accounts (username COLLATE NOCASE);
                 CREATE TABLE managers (
                    id TEXT PRIMARY KEY, public_identity TEXT NOT NULL,
                    friendly_name TEXT NOT NULL,
                    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('pending', 'approved', 'revoked')),
                    approved_by_account_id TEXT REFERENCES accounts(id),
                    approved_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 CREATE UNIQUE INDEX managers_public_identity_unique ON managers (public_identity);
                 CREATE TABLE sessions (
                    id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
                    manager_id TEXT REFERENCES managers(id), token_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
                 CREATE TABLE computers (
                    id TEXT PRIMARY KEY, public_identity TEXT NOT NULL,
                    friendly_name TEXT NOT NULL, platform TEXT NOT NULL,
                    enrollment_state TEXT NOT NULL,
                    enrollment_epoch INTEGER NOT NULL DEFAULT 1,
                    approved_incarnation_identity TEXT,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 CREATE TABLE access_assignments (
                    id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
                    capability TEXT NOT NULL, computer_scope_all INTEGER NOT NULL DEFAULT 0,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 CREATE TABLE access_computer_scope (
                    assignment_id TEXT NOT NULL REFERENCES access_assignments(id) ON DELETE CASCADE,
                    computer_id TEXT NOT NULL REFERENCES computers(id),
                    PRIMARY KEY (assignment_id, computer_id));
                 CREATE TABLE login_attempts (
                    username_key TEXT PRIMARY KEY, failure_count INTEGER NOT NULL DEFAULT 0,
                    locked_until INTEGER, updated_at INTEGER NOT NULL);",
            )
            .expect("seed v1");
        }

        let report = migrate(&path, &backup_dir).expect("migrate");
        assert_eq!(report.from_version, 1);
        assert_eq!(report.to_version, SCHEMA_VERSION);
        assert!(report.backup_path.exists(), "backup must exist");

        let db = open(&path).expect("reopen after migrate");
        let conn = db.lock().expect("lock");
        let version = schema_version(&conn).expect("version").expect("row");
        assert_eq!(version, SCHEMA_VERSION);
        assert!(table_exists(&conn, "account_mfa").expect("mfa table"));
        assert!(table_exists(&conn, "recovery_codes").expect("recovery table"));
        assert!(table_exists(&conn, "auth_challenges").expect("challenge table"));
        let state: String = conn
            .query_row("SELECT state FROM accounts WHERE id = 'a1'", [], |r| {
                r.get(0)
            })
            .expect("account state");
        assert_eq!(state, "active");
    }

    #[test]
    fn migrate_is_idempotent_refusal_when_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("current.db");
        {
            let conn = Connection::open(&path).expect("open");
            ensure_schema(&conn).expect("install");
        }
        let err = match migrate(&path, dir.path()) {
            Ok(_) => panic!("must refuse when already current"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("already"), "err={err}");
    }
}
