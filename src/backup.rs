//! Encrypted, portable snapshots of the server's SQLite database.
//!
//! This is a database backup primitive. It does not include service packages,
//! TLS keys, proxy configuration, or other files outside SQLite. An archive
//! includes database-resident authority material, but restore fences old
//! sessions and rotates the deployment grant signer before publishing the
//! recovered database. This primitive does not perform a host cutover. Each
//! archive uses an independent passphrase-derived encryption key; the
//! package-signing authority is not reused for backup confidentiality.

use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};

const MAGIC: &[u8; 8] = b"HSDBAK01";
const HEADER_BYTES: usize = 8 + 16 + 4;
const SALT_BYTES: usize = 16;
const NONCE_PREFIX_BYTES: usize = 4;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_DATABASE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const ARGON_MEMORY_KIB: u32 = 19 * 1024;
const ARGON_ITERATIONS: u32 = 2;

/// Metadata verified from an encrypted SQLite backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub database_bytes: u64,
    pub encrypted_bytes: u64,
    pub schema_version: i64,
}

/// Result of pruning timestamped archives made by the unattended schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPruneReport {
    pub matching_archives: usize,
    pub retained_archives: usize,
    pub removed_archives: usize,
}

/// Metadata for one encrypted archive in a private backup directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupArchiveSummary {
    pub file_name: String,
    pub encrypted_bytes: u64,
    pub modified_at_unix: u64,
}

/// List encrypted database archives in an owner-private directory.
/// Filenames are escaped before display because directory entries are data.
#[cfg(unix)]
pub fn list_database_backups(directory: &Path) -> AppResult<Vec<BackupArchiveSummary>> {
    use std::fs;

    let directory_metadata = fs::symlink_metadata(directory)
        .map_err(|error| io_error("inspect backup directory", error))?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(AppError::bad_request(
            "backup path must be a private directory",
        ));
    }
    let directory = crate::private_file::ensure_private_store_dir(directory)?;
    let mut archives = Vec::new();
    for entry in
        fs::read_dir(&directory).map_err(|error| io_error("list backup directory", error))?
    {
        let entry = entry.map_err(|error| io_error("read backup directory entry", error))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            AppError::unprocessable(
                "backup archive name is not valid UTF-8; refusing ambiguous inventory",
            )
        })?;
        if !name.ends_with(".hsb") {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect backup archive", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::bad_request(
                "backup archive must be a regular private file",
            ));
        }
        crate::private_file::verify_private_store_file(&path)?;
        let modified_at_unix = metadata
            .modified()
            .map_err(|error| io_error("read backup modification time", error))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                AppError::unprocessable("backup modification time predates the Unix epoch")
            })?
            .as_secs();
        let file_name = name.chars().flat_map(char::escape_default).collect();
        archives.push(BackupArchiveSummary {
            file_name,
            encrypted_bytes: metadata.len(),
            modified_at_unix,
        });
        if archives.len() > 10_000 {
            return Err(AppError::unprocessable(
                "backup directory contains more than 10000 encrypted archives",
            ));
        }
    }
    archives.sort_by(|left, right| {
        right
            .modified_at_unix
            .cmp(&left.modified_at_unix)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });
    Ok(archives)
}

#[cfg(not(unix))]
pub fn list_database_backups(_directory: &Path) -> AppResult<Vec<BackupArchiveSummary>> {
    Err(AppError::not_implemented(
        "encrypted database listing currently requires the verified Unix private-file boundary",
    ))
}

/// Make an encrypted snapshot at a new owner-private output path.
///
/// The password is never accepted through argv. The caller must provide it
/// through a bounded secret input and keep it in zeroizing memory.
#[cfg(unix)]
pub fn create_database_backup(
    database_path: &Path,
    output_path: &Path,
    passphrase: &[u8],
) -> AppResult<BackupReport> {
    use rusqlite::params;
    use std::fs;

    validate_passphrase(passphrase)?;
    if !database_path.exists() {
        return Err(AppError::not_found("server database does not exist"));
    }
    crate::private_file::verify_private_store_file(database_path)?;

    let output = new_private_output_path(output_path)?;
    let output_parent = output
        .parent()
        .ok_or_else(|| AppError::bad_request("backup output must have a parent directory"))?;
    let snapshot_path =
        output_parent.join(format!(".helicoid-snapshot-{}.db", uuid::Uuid::new_v4()));
    let snapshot_cleanup = NewPrivateFile::create(snapshot_path.clone())?;

    // `VACUUM INTO` reads a transactionally consistent view, including WAL
    // content, without checkpointing or otherwise mutating the live database.
    let database = crate::db::open(database_path)?;
    {
        let connection = database.lock()?;
        let snapshot_name = snapshot_path
            .to_str()
            .ok_or_else(|| AppError::bad_request("backup path must be valid UTF-8"))?;
        connection.execute("VACUUM INTO ?1", params![snapshot_name])?;
    }
    crate::private_file::verify_private_store_file(&snapshot_path)?;
    let database_bytes = fs::metadata(&snapshot_path)
        .map_err(|error| io_error("inspect database snapshot", error))?
        .len();
    if database_bytes == 0 || database_bytes > MAX_DATABASE_BYTES {
        return Err(AppError::unprocessable(format!(
            "database snapshot size is outside the supported range (maximum {MAX_DATABASE_BYTES} bytes)"
        )));
    }

    let temporary_archive =
        output_parent.join(format!(".helicoid-backup-{}.tmp", uuid::Uuid::new_v4()));
    let archive_cleanup = NewPrivateFile::create(temporary_archive.clone())?;
    let snapshot = open_private_read(&snapshot_path)?;
    let mut archive = open_private_write(&temporary_archive)?;
    encrypt_stream(snapshot, &mut archive, passphrase, database_bytes)?;
    archive
        .sync_all()
        .map_err(|error| io_error("sync encrypted backup", error))?;
    drop(archive);
    crate::private_file::verify_private_store_file(&temporary_archive)?;

    // A same-directory hard link publishes the complete archive atomically
    // and fails if any file or symlink already occupies the destination.
    fs::hard_link(&temporary_archive, &output)
        .map_err(|error| io_error("publish encrypted backup without overwrite", error))?;
    drop(archive_cleanup);
    let encrypted_bytes = match (|| {
        crate::private_file::verify_private_store_file(&output)?;
        let size = fs::metadata(&output)
            .map_err(|error| io_error("inspect encrypted backup", error))?
            .len();
        std::fs::File::open(output_parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync backup directory", error))?;
        Ok::<u64, AppError>(size)
    })() {
        Ok(size) => size,
        Err(error) => {
            let _ = fs::remove_file(&output);
            return Err(error);
        }
    };
    drop(snapshot_cleanup);

    Ok(BackupReport {
        database_bytes,
        encrypted_bytes,
        schema_version: crate::db::SCHEMA_VERSION,
    })
}

/// Decrypt and validate an archive without publishing a restored database.
#[cfg(unix)]
pub fn verify_database_backup(input_path: &Path, passphrase: &[u8]) -> AppResult<BackupReport> {
    use std::fs;

    validate_passphrase(passphrase)?;
    crate::private_file::verify_private_store_file(input_path)?;
    let input_path = std::fs::canonicalize(input_path)
        .map_err(|error| io_error("resolve encrypted backup", error))?;
    crate::private_file::verify_private_store_file(&input_path)?;
    let input = open_private_read(&input_path)?;

    let scratch_dir =
        std::env::temp_dir().join(format!("helicoid-verify-{}", uuid::Uuid::new_v4()));
    let scratch_dir = crate::private_file::ensure_private_store_dir(&scratch_dir)?;
    let directory_cleanup = PrivateDirectory(scratch_dir.clone());
    let snapshot_path = scratch_dir.join("verified-snapshot.db");
    let snapshot_cleanup = NewPrivateFile::create(snapshot_path.clone())?;
    let mut snapshot = open_private_write(&snapshot_path)?;
    let (database_bytes, encrypted_bytes) = decrypt_stream(input, &mut snapshot, passphrase)?;
    snapshot
        .sync_all()
        .map_err(|error| io_error("sync verified snapshot", error))?;
    drop(snapshot);
    crate::private_file::verify_private_store_file(&snapshot_path)?;

    let schema_version = validate_database_snapshot(&snapshot_path)?;
    drop(snapshot_cleanup);
    drop(directory_cleanup);
    let _ = fs::remove_dir(&scratch_dir);

    Ok(BackupReport {
        database_bytes,
        encrypted_bytes,
        schema_version,
    })
}

/// Restore an encrypted database snapshot to a new private file. Before the
/// restored file is published, old sessions, identities, credentials,
/// challenges, invitations, grants, and interaction claims are fenced. The
/// restored deployment remains quarantined until a fresh Manager identity and
/// administrator complete local MFA bootstrap.
#[cfg(unix)]
pub fn restore_database_backup(
    input_path: &Path,
    output_path: &Path,
    passphrase: &[u8],
) -> AppResult<BackupReport> {
    use std::fs;

    validate_passphrase(passphrase)?;
    crate::private_file::verify_private_store_file(input_path)?;
    let input_path = fs::canonicalize(input_path)
        .map_err(|error| io_error("resolve encrypted backup", error))?;
    crate::private_file::verify_private_store_file(&input_path)?;
    let input = open_private_read(&input_path)?;

    let output = new_private_output_path(output_path)?;
    let output_parent = output
        .parent()
        .ok_or_else(|| AppError::bad_request("restore output must have a parent directory"))?;
    let temporary_database =
        output_parent.join(format!(".helicoid-restore-{}.db", uuid::Uuid::new_v4()));
    let temporary_cleanup = NewPrivateFile::create(temporary_database.clone())?;
    let mut database = open_private_write(&temporary_database)?;
    let (database_bytes, encrypted_bytes) = decrypt_stream(input, &mut database, passphrase)?;
    database
        .sync_all()
        .map_err(|error| io_error("sync restored database", error))?;
    drop(database);
    crate::private_file::verify_private_store_file(&temporary_database)?;
    let schema_version = validate_database_snapshot(&temporary_database)?;
    fence_restored_authority(&temporary_database)?;
    validate_database_snapshot(&temporary_database)?;

    // The final path appears only after decryption, schema/integrity checks,
    // and authority fencing have all succeeded. A hard link refuses replace.
    fs::hard_link(&temporary_database, &output)
        .map_err(|error| io_error("publish restored database without overwrite", error))?;
    drop(temporary_cleanup);
    let publish_result = (|| {
        crate::private_file::verify_private_store_file(&output)?;
        fs::File::open(output_parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync restored database directory", error))?;
        Ok::<(), AppError>(())
    })();
    if let Err(error) = publish_result {
        let _ = fs::remove_file(&output);
        return Err(error);
    }

    Ok(BackupReport {
        database_bytes,
        encrypted_bytes,
        schema_version,
    })
}

#[cfg(not(unix))]
pub fn create_database_backup(
    _database_path: &Path,
    _output_path: &Path,
    _passphrase: &[u8],
) -> AppResult<BackupReport> {
    Err(AppError::not_implemented(
        "encrypted database backups currently require the verified Unix private-file boundary",
    ))
}

#[cfg(not(unix))]
pub fn verify_database_backup(_input_path: &Path, _passphrase: &[u8]) -> AppResult<BackupReport> {
    Err(AppError::not_implemented(
        "encrypted database verification currently requires the verified Unix private-file boundary",
    ))
}

#[cfg(not(unix))]
pub fn restore_database_backup(
    _input_path: &Path,
    _output_path: &Path,
    _passphrase: &[u8],
) -> AppResult<BackupReport> {
    Err(AppError::not_implemented(
        "encrypted database restore currently requires the verified Unix private-file boundary",
    ))
}

/// Keep the newest scheduled archives and remove older archives created by
/// `backup scheduled-create`. This never touches manual archives or other
/// files in the directory.
#[cfg(unix)]
pub fn prune_scheduled_database_backups(
    directory: &Path,
    keep: usize,
) -> AppResult<BackupPruneReport> {
    use std::fs;

    if !(1..=10_000).contains(&keep) {
        return Err(AppError::bad_request(
            "backup retention must keep between 1 and 10000 scheduled archives",
        ));
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| io_error("inspect backup directory", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::bad_request(
            "backup retention path must be a private directory",
        ));
    }
    let directory = crate::private_file::ensure_private_store_dir(directory)?;

    let mut candidates = Vec::new();
    for entry in
        fs::read_dir(&directory).map_err(|error| io_error("list backup directory", error))?
    {
        let entry = entry.map_err(|error| io_error("read backup directory entry", error))?;
        let name = entry.file_name();
        let Some(timestamp) = scheduled_backup_timestamp(&name) else {
            continue;
        };
        let path = entry.path();
        crate::private_file::verify_private_store_file(&path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect scheduled backup", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::bad_request(
                "scheduled backup is not a regular private file",
            ));
        }
        candidates.push((timestamp, name, path));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let matching_archives = candidates.len();
    let remove_count = matching_archives.saturating_sub(keep);
    let mut removed_archives = 0;
    for (_, _, path) in candidates.iter().take(remove_count) {
        match fs::remove_file(path) {
            Ok(()) => removed_archives += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AppError::conflict(
                    format!(
                        "scheduled backup list changed during pruning after {removed_archives} archive(s) were removed; review the directory and retry"
                    ),
                    None,
                ));
            }
            Err(error) => {
                return Err(AppError::internal(format!(
                    "backup retention stopped after removing {removed_archives} archive(s): {}",
                    io_error("remove expired scheduled backup", error)
                )));
            }
        }
    }
    if removed_archives > 0 {
        fs::File::open(&directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                AppError::internal(format!(
                    "removed {removed_archives} archive(s) but could not sync the backup directory: {}",
                    io_error("sync backup directory after retention", error)
                ))
            })?;
    }

    Ok(BackupPruneReport {
        matching_archives,
        retained_archives: matching_archives.saturating_sub(removed_archives),
        removed_archives,
    })
}

#[cfg(not(unix))]
pub fn prune_scheduled_database_backups(
    _directory: &Path,
    _keep: usize,
) -> AppResult<BackupPruneReport> {
    Err(AppError::not_implemented(
        "scheduled backup retention currently requires the verified Unix private-file boundary",
    ))
}

fn scheduled_backup_timestamp(name: &std::ffi::OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let rest = name.strip_prefix("hs-server-")?;
    let (timestamp, suffix) = rest.split_once('-')?;
    let identifier = suffix.strip_suffix(".hsb")?;
    if timestamp.is_empty()
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
        || !identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let timestamp = timestamp.parse::<u64>().ok()?;
    let uuid = uuid::Uuid::parse_str(identifier).ok()?;
    (uuid.simple().to_string() == identifier.to_ascii_lowercase()).then_some(timestamp)
}

#[cfg(unix)]
fn validate_database_snapshot(path: &Path) -> AppResult<i64> {
    use rusqlite::{Connection, OpenFlags};

    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(AppError::unprocessable(
            "decrypted backup failed SQLite integrity validation",
        ));
    }
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(AppError::unprocessable(
            "decrypted backup contains foreign-key violations",
        ));
    }
    let schema_version: i64 = connection
        .query_row(
            "SELECT schema_version FROM schema_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AppError::unprocessable("decrypted file is not a Helicoid server database"))?;
    if schema_version != crate::db::SCHEMA_VERSION {
        return Err(AppError::unprocessable(format!(
            "backup schema version {schema_version} does not match this server build ({})",
            crate::db::SCHEMA_VERSION
        )));
    }
    Ok(schema_version)
}

#[cfg(unix)]
fn fence_restored_authority(path: &Path) -> AppResult<()> {
    use rusqlite::{OptionalExtension, TransactionBehavior};

    let mut connection = rusqlite::Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now = crate::db::now_unix();

    transaction.execute(
        "UPDATE sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
        [now],
    )?;
    transaction.execute(
        "UPDATE endpoint_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
        [now],
    )?;
    transaction.execute(
        "UPDATE auth_challenges SET consumed_at = ?1 WHERE consumed_at IS NULL",
        [now],
    )?;
    transaction.execute(
        "UPDATE endpoint_auth_challenges SET consumed_at = ?1 WHERE consumed_at IS NULL",
        [now],
    )?;
    transaction.execute("DELETE FROM observation_admission_grants", [])?;
    transaction.execute(
        "UPDATE mfa_enrollments SET consumed_at = ?1 WHERE consumed_at IS NULL",
        [now],
    )?;
    transaction.execute(
        "UPDATE bootstrap_tokens SET consumed_at = ?1 WHERE consumed_at IS NULL",
        [now],
    )?;
    transaction.execute(
        "UPDATE computer_enrollment_invitations SET revoked_at = ?1
         WHERE redeemed_at IS NULL AND revoked_at IS NULL",
        [now],
    )?;

    let active_computers: i64 = transaction.query_row(
        "SELECT COUNT(DISTINCT computer_id) FROM interaction_claims
         WHERE state NOT IN ('ended', 'failed')",
        [],
        |row| row.get(0),
    )?;
    let missing_revisions: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM (
            SELECT DISTINCT claim.computer_id
            FROM interaction_claims AS claim
            LEFT JOIN computer_interaction_revisions AS revision
                ON revision.computer_id = claim.computer_id
            WHERE claim.state NOT IN ('ended', 'failed')
              AND revision.computer_id IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if missing_revisions != 0 {
        return Err(AppError::unprocessable(
            "restored interaction state has no revision fence",
        ));
    }
    let fenced_revisions = transaction.execute(
        "UPDATE computer_interaction_revisions SET revision = revision + 1
         WHERE revision < 9223372036854775807
           AND computer_id IN (
             SELECT DISTINCT computer_id FROM interaction_claims
             WHERE state NOT IN ('ended', 'failed')
           )",
        [],
    )? as i64;
    if fenced_revisions != active_computers {
        return Err(AppError::unprocessable(
            "restored interaction revision cannot be advanced safely",
        ));
    }
    let (predecessor_id, prior_generation): (String, i64) = transaction.query_row(
        "SELECT deployment_key, authority_generation FROM deployment WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let next_generation = prior_generation
        .checked_add(1)
        .filter(|generation| prior_generation > 0 && *generation > 0)
        .ok_or_else(|| AppError::unprocessable("authority generation is exhausted"))?;
    let pending_cutover: Option<(String, i64, Option<String>)> = transaction
        .query_row(
            "SELECT id, generation, initiated_by_account_id
             FROM authority_cutovers
             WHERE predecessor_authority_id = ?1 AND state = 'draining'
             ORDER BY created_at DESC, id DESC LIMIT 1",
            [&predecessor_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (cutover_id, cutover_generation, initiator_id) = match pending_cutover {
        Some((id, generation, initiator)) if generation == next_generation => {
            (id, generation, initiator)
        }
        Some(_) => {
            return Err(AppError::conflict(
                "pending cutover generation does not match the restored authority",
                Some("cutover_generation_changed".to_string()),
            ));
        }
        None => (uuid::Uuid::new_v4().to_string(), next_generation, None),
    };

    let signing_secret = crate::db::new_grant_signing_secret();
    let deployment_key = crate::db::new_deployment_key();
    let rotated_signer = transaction.execute(
        "UPDATE deployment
         SET grant_signing_secret = ?1, deployment_key = ?2,
             bootstrap_completed = 0, bootstrap_completed_at = NULL,
             recovery_quarantined = 1, authority_state = 'awaiting_cutover',
             authority_generation = ?3, predecessor_deployment_key = ?4
         WHERE id = 1",
        rusqlite::params![
            signing_secret.as_slice(),
            deployment_key,
            cutover_generation,
            predecessor_id
        ],
    )?;
    if rotated_signer != 1 {
        return Err(AppError::unprocessable(
            "restored deployment identity is missing; refusing restore cutover",
        ));
    }
    let review_changed = transaction.execute(
        "UPDATE authority_cutovers
         SET replacement_authority_id = ?1, generation = ?2, state = 'awaiting_review',
             initiated_by_account_id = ?3
         WHERE id = ?4 AND state = 'draining'",
        rusqlite::params![deployment_key, cutover_generation, initiator_id, cutover_id],
    )?;
    if review_changed == 0 {
        transaction.execute(
            "INSERT INTO authority_cutovers (
                id, predecessor_authority_id, replacement_authority_id,
                generation, state, created_at
             ) VALUES (?1, ?2, ?3, ?4, 'awaiting_review', ?5)",
            rusqlite::params![
                cutover_id,
                predecessor_id,
                deployment_key,
                cutover_generation,
                now
            ],
        )?;
    }
    transaction.execute(
        "UPDATE interaction_claims SET state = 'failed', updated_at = ?1
         WHERE state NOT IN ('ended', 'failed')",
        [now],
    )?;

    let account_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
    let invalid_account_revisions: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM accounts WHERE revision < 1 OR revision >= 9223372036854775807",
        [],
        |row| row.get(0),
    )?;
    if invalid_account_revisions != 0 {
        return Err(AppError::unprocessable(
            "restored account revisions cannot be advanced safely",
        ));
    }
    let fenced_accounts = transaction.execute(
        "UPDATE accounts
         SET state = 'disabled', recovery_quarantined = 1,
             revision = revision + 1, updated_at = ?1
         WHERE revision < 9223372036854775807",
        [now],
    )? as i64;
    if fenced_accounts != account_count {
        return Err(AppError::unprocessable(
            "restored account revisions cannot be advanced safely",
        ));
    }
    transaction.execute(
        "UPDATE managers SET lifecycle_state = 'revoked', updated_at = ?1
         WHERE lifecycle_state IN ('pending', 'approved')",
        [now],
    )?;

    let computer_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM computers", [], |row| row.get(0))?;
    let invalid_computer_epochs: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM computers
         WHERE enrollment_epoch <= 0 OR enrollment_epoch >= 9223372036854775807",
        [],
        |row| row.get(0),
    )?;
    if invalid_computer_epochs != 0 {
        return Err(AppError::unprocessable(
            "restored endpoint enrollment epochs cannot be advanced safely",
        ));
    }
    let fenced_computers = transaction.execute(
        "UPDATE computers
         SET enrollment_state = CASE
                 WHEN enrollment_state = 'revoked' THEN 'revoked'
                 ELSE 'quarantined'
             END,
             enrollment_epoch = enrollment_epoch + 1,
             approved_incarnation_identity = NULL,
             updated_at = ?1
         WHERE enrollment_epoch < 9223372036854775807",
        [now],
    )? as i64;
    if fenced_computers != computer_count {
        return Err(AppError::unprocessable(
            "restored endpoint enrollment epochs cannot be advanced safely",
        ));
    }
    transaction.commit()?;
    Ok(())
}

#[cfg(unix)]
fn validate_passphrase(passphrase: &[u8]) -> AppResult<()> {
    if !(16..=4096).contains(&passphrase.len())
        || passphrase.contains(&b'\n')
        || passphrase.contains(&b'\r')
    {
        return Err(AppError::bad_request(
            "backup passphrase must contain 16 to 4096 bytes on one line",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn new_private_output_path(path: &Path) -> AppResult<PathBuf> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AppError::bad_request("backup output must include a file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let private_parent = crate::private_file::ensure_private_store_dir(parent)?;
    Ok(private_parent.join(name))
}

#[cfg(unix)]
struct NewPrivateFile(PathBuf);

#[cfg(unix)]
impl NewPrivateFile {
    fn create(path: PathBuf) -> AppResult<Self> {
        crate::private_file::create_private_store_file(&path)?;
        Ok(Self(path))
    }
}

#[cfg(unix)]
impl Drop for NewPrivateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
struct PrivateDirectory(PathBuf);

#[cfg(unix)]
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn open_private_read(path: &Path) -> AppResult<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| io_error("open private backup file", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect private backup file", error))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(AppError::bad_request(
            "backup file is not a private owner-owned regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_private_write(path: &Path) -> AppResult<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io_error("open private backup output", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect private backup output", error))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(AppError::bad_request(
            "backup output is not a private owner-owned regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn encrypt_stream(
    mut source: std::fs::File,
    destination: &mut std::fs::File,
    passphrase: &[u8],
    expected_bytes: u64,
) -> AppResult<()> {
    use ring::aead::{self, Aad, LessSafeKey, UnboundKey};
    use ring::rand::{SecureRandom, SystemRandom};
    use std::io::Write;
    use zeroize::Zeroizing;

    let rng = SystemRandom::new();
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    rng.fill(&mut salt)
        .map_err(|_| AppError::Random("backup salt generation failed".into()))?;
    rng.fill(&mut nonce_prefix)
        .map_err(|_| AppError::Random("backup nonce generation failed".into()))?;
    let mut header = [0_u8; HEADER_BYTES];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()..MAGIC.len() + SALT_BYTES].copy_from_slice(&salt);
    header[MAGIC.len() + SALT_BYTES..].copy_from_slice(&nonce_prefix);
    let key_bytes = derive_key(passphrase, &salt)?;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key_bytes[..])
        .map_err(|_| AppError::internal("initialize backup encryption"))?;
    let key = LessSafeKey::new(unbound);
    destination
        .write_all(&header)
        .map_err(|error| io_error("write encrypted backup header", error))?;

    let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_BYTES]);
    let mut total_bytes = 0_u64;
    let mut index = 0_u64;
    loop {
        let count = read_chunk(&mut source, &mut buffer)
            .map_err(|error| io_error("read database snapshot", error))?;
        if count == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(count as u64)
            .ok_or_else(|| AppError::unprocessable("database snapshot size overflow"))?;
        if total_bytes > MAX_DATABASE_BYTES {
            return Err(AppError::unprocessable(
                "database snapshot exceeds the backup size limit",
            ));
        }
        buffer.truncate(count);
        let aad = record_aad(&header, index, count as u32, false);
        key.seal_in_place_append_tag(
            nonce(&nonce_prefix, index),
            Aad::from(aad.as_slice()),
            &mut *buffer,
        )
        .map_err(|_| AppError::internal("encrypt database snapshot"))?;
        destination
            .write_all(&(count as u32).to_be_bytes())
            .and_then(|_| destination.write_all(&buffer[..]))
            .map_err(|error| io_error("write encrypted database chunk", error))?;
        buffer.resize(CHUNK_BYTES, 0);
        index = index
            .checked_add(1)
            .ok_or_else(|| AppError::unprocessable("backup record count overflow"))?;
    }
    if total_bytes != expected_bytes {
        return Err(AppError::unprocessable(
            "database snapshot changed while the backup was being created",
        ));
    }

    let aad = record_aad(&header, index, 0, true);
    let mut final_tag = Vec::new();
    key.seal_in_place_append_tag(
        nonce(&nonce_prefix, index),
        Aad::from(aad.as_slice()),
        &mut final_tag,
    )
    .map_err(|_| AppError::internal("authenticate encrypted backup end"))?;
    destination
        .write_all(&0_u32.to_be_bytes())
        .and_then(|_| destination.write_all(&final_tag))
        .map_err(|error| io_error("write encrypted backup terminator", error))?;
    Ok(())
}

#[cfg(unix)]
fn decrypt_stream(
    mut source: std::fs::File,
    destination: &mut std::fs::File,
    passphrase: &[u8],
) -> AppResult<(u64, u64)> {
    use ring::aead::{self, Aad, LessSafeKey, UnboundKey};
    use std::io::{Read, Write};
    use zeroize::Zeroizing;

    let mut header = [0_u8; HEADER_BYTES];
    source
        .read_exact(&mut header)
        .map_err(|_| AppError::unprocessable("encrypted backup header is truncated"))?;
    if &header[..MAGIC.len()] != MAGIC {
        return Err(AppError::unprocessable(
            "unsupported encrypted backup format",
        ));
    }
    let mut salt = [0_u8; SALT_BYTES];
    salt.copy_from_slice(&header[MAGIC.len()..MAGIC.len() + SALT_BYTES]);
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    nonce_prefix.copy_from_slice(&header[MAGIC.len() + SALT_BYTES..]);
    let key_bytes = derive_key(passphrase, &salt)?;
    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key_bytes[..])
        .map_err(|_| AppError::internal("initialize backup decryption"))?;
    let key = LessSafeKey::new(unbound);

    let mut total_bytes = 0_u64;
    let mut index = 0_u64;
    loop {
        let mut length_bytes = [0_u8; 4];
        source
            .read_exact(&mut length_bytes)
            .map_err(|_| AppError::unprocessable("encrypted backup record is truncated"))?;
        let plaintext_len = u32::from_be_bytes(length_bytes) as usize;
        if plaintext_len > CHUNK_BYTES {
            return Err(AppError::unprocessable(
                "encrypted backup record exceeds the chunk limit",
            ));
        }
        let final_record = plaintext_len == 0;
        let ciphertext_len = plaintext_len + TAG_BYTES;
        let mut buffer = Zeroizing::new(vec![0_u8; ciphertext_len]);
        source
            .read_exact(&mut buffer)
            .map_err(|_| AppError::unprocessable("encrypted backup record is truncated"))?;
        let aad = record_aad(&header, index, plaintext_len as u32, final_record);
        let cleartext_len = key
            .open_in_place(
                nonce(&nonce_prefix, index),
                Aad::from(aad.as_slice()),
                &mut buffer[..],
            )
            .map_err(|_| {
                AppError::unprocessable(
                    "backup authentication failed; passphrase is wrong or archive data is damaged",
                )
            })?
            .len();
        if cleartext_len != plaintext_len {
            return Err(AppError::unprocessable(
                "encrypted backup record length is invalid",
            ));
        }
        if final_record {
            let mut trailing = [0_u8; 1];
            if source
                .read(&mut trailing)
                .map_err(|error| io_error("read encrypted backup terminator", error))?
                != 0
            {
                return Err(AppError::unprocessable(
                    "encrypted backup contains trailing data",
                ));
            }
            break;
        }

        total_bytes = total_bytes
            .checked_add(plaintext_len as u64)
            .ok_or_else(|| AppError::unprocessable("restored database size overflow"))?;
        if total_bytes > MAX_DATABASE_BYTES {
            return Err(AppError::unprocessable(
                "decrypted database exceeds the backup size limit",
            ));
        }
        buffer.truncate(cleartext_len);
        destination
            .write_all(&buffer[..])
            .map_err(|error| io_error("write decrypted database snapshot", error))?;
        index = index
            .checked_add(1)
            .ok_or_else(|| AppError::unprocessable("backup record count overflow"))?;
    }
    if total_bytes == 0 {
        return Err(AppError::unprocessable(
            "encrypted backup contains an empty database",
        ));
    }
    let encrypted_bytes = source
        .metadata()
        .map_err(|error| io_error("inspect encrypted backup", error))?
        .len();
    Ok((total_bytes, encrypted_bytes))
}

#[cfg(unix)]
fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_BYTES],
) -> AppResult<zeroize::Zeroizing<[u8; 32]>> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use zeroize::Zeroizing;

    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, 1, Some(32))
        .map_err(|error| AppError::internal(format!("invalid backup KDF parameters: {error}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|error| AppError::PasswordHash(error.to_string()))?;
    Ok(key)
}

#[cfg(unix)]
fn nonce(prefix: &[u8; NONCE_PREFIX_BYTES], index: u64) -> ring::aead::Nonce {
    let mut bytes = [0_u8; NONCE_BYTES];
    bytes[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    bytes[NONCE_PREFIX_BYTES..].copy_from_slice(&index.to_be_bytes());
    ring::aead::Nonce::assume_unique_for_key(bytes)
}

#[cfg(unix)]
fn record_aad(header: &[u8; HEADER_BYTES], index: u64, length: u32, final_record: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_BYTES + 13);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&length.to_be_bytes());
    aad.push(u8::from(final_record));
    aad
}

#[cfg(unix)]
fn read_chunk(reader: &mut impl std::io::Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

#[cfg(unix)]
fn io_error(context: &str, error: std::io::Error) -> AppError {
    AppError::bad_request(format!("{context}: {error}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rusqlite::params;

    fn fixture_database(path: &Path) {
        let database = crate::db::open(path).expect("open fixture store");
        let connection = database.lock().expect("lock fixture store");
        let now = crate::db::now_unix();
        connection
            .execute(
                "INSERT INTO accounts (id, username, password_hash, state, created_at, updated_at)
                 VALUES ('account-1', 'operator', 'test-hash', 'active', ?1, ?1)",
                params![now],
            )
            .expect("insert account");
        connection
            .execute(
                "INSERT INTO managers (
                    id, public_identity, friendly_name, lifecycle_state,
                    approved_by_account_id, approved_at, created_at, updated_at, public_key
                 ) VALUES (
                    'manager-1', 'manager-key', 'Manager', 'approved',
                    'account-1', ?1, ?1, ?1, 'manager-public-key'
                 )",
                params![now],
            )
            .expect("insert manager");
        connection
            .execute(
                "INSERT INTO sessions (
                    id, account_id, manager_id, token_hash, created_at, expires_at
                 ) VALUES ('session-1', 'account-1', 'manager-1', 'session-hash', ?1, ?2)",
                params![now, now + 3600],
            )
            .expect("insert manager session");
        connection
            .execute(
                "INSERT INTO computers (
                    id, public_identity, friendly_name, platform, enrollment_state,
                    created_at, updated_at
                 ) VALUES (
                    'computer-1', 'endpoint-key', 'Computer', 'windows', 'enrolled', ?1, ?1
                 )",
                params![now],
            )
            .expect("insert computer");
        connection
            .execute(
                "INSERT INTO endpoint_sessions (
                    id, token_hash, computer_id, enrollment_epoch, created_at, expires_at
                 ) VALUES ('endpoint-session-1', 'endpoint-token-hash', 'computer-1', 1, ?1, ?2)",
                params![now, now + 3600],
            )
            .expect("insert endpoint session");
        connection
            .execute(
                "INSERT INTO auth_challenges (
                    id, token_hash, account_id, manager_public_key, operation,
                    created_at, expires_at
                 ) VALUES (
                    'manager-challenge-1', 'manager-challenge-hash', 'account-1',
                    'manager-public-key', 'login', ?1, ?2
                 )",
                params![now, now + 300],
            )
            .expect("insert manager challenge");
        connection
            .execute(
                "INSERT INTO endpoint_auth_challenges (
                    id, token_hash, computer_id, client_nonce, issued_at, public_key,
                    enrollment_epoch, deployment_key, created_at, expires_at
                 ) VALUES (
                    'endpoint-challenge-1', 'endpoint-challenge-hash', 'computer-1',
                    'client-nonce', ?1, 'endpoint-public-key', 1, 'deployment', ?1, ?2
                 )",
                params![now, now + 300],
            )
            .expect("insert endpoint challenge");
        connection
            .execute(
                "INSERT INTO mfa_enrollments (
                    id, account_id, totp_secret, created_at, expires_at
                 ) VALUES ('mfa-enrollment-1', 'account-1', 'pending-secret', ?1, ?2)",
                params![now, now + 300],
            )
            .expect("insert pending mfa enrollment");
        connection
            .execute(
                "INSERT INTO computer_interaction_revisions (computer_id, revision)
                 VALUES ('computer-1', 3)",
                [],
            )
            .expect("insert interaction revision");
        connection
            .execute(
                "INSERT INTO interaction_claims (
                    id, computer_id, owner_account_id, owner_manager_id, kind,
                    operation_fingerprint, state, affected_computer_ids_json,
                    created_at, updated_at
                 ) VALUES (
                    'interaction-1', 'computer-1', 'account-1', 'manager-1', 'observation',
                    ?1, 'live', '[]', ?2, ?2
                 )",
                params![vec![7_u8; 32], now],
            )
            .expect("insert live interaction");
        connection
            .execute(
                "INSERT INTO bootstrap_tokens (token_hash, created_at)
                 VALUES ('bootstrap-hash', ?1)",
                params![now],
            )
            .expect("insert bootstrap token");
        connection
            .execute(
                "INSERT INTO computer_enrollment_invitations (
                    id, code_hash, friendly_name, platform, created_by_account_id,
                    created_at, expires_at
                 ) VALUES (
                    'invite-1', 'invite-hash', 'New Computer', 'windows',
                    'account-1', ?1, ?2
                 )",
                params![now, now + 600],
            )
            .expect("insert invitation");
    }

    #[test]
    fn restore_fences_prior_authority_and_never_overwrites_destination() {
        let directory = tempfile::tempdir().expect("private temp directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("make test store private");
        }
        let source = directory.path().join("source.db");
        let archive = directory.path().join("backup.hsb");
        let restored = directory.path().join("restored.db");
        let passphrase = b"a sufficiently long backup passphrase";
        fixture_database(&source);
        let (source_signer, source_authority_id) = {
            let db = crate::db::open(&source).expect("open source store");
            let connection = db.lock().expect("lock source store");
            let signer = crate::db::grant_signing_secret(&connection).expect("read source signer");
            let authority_id = connection
                .query_row(
                    "SELECT deployment_key FROM deployment WHERE id = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("read source authority");
            (signer, authority_id)
        };

        create_database_backup(&source, &archive, passphrase).expect("create backup");
        let wrong_passphrase = restore_database_backup(
            &archive,
            &restored,
            b"a different sufficiently long passphrase",
        )
        .expect_err("wrong passphrase must refuse restore");
        assert!(wrong_passphrase
            .to_string()
            .contains("authentication failed"));
        assert!(!restored.exists(), "failed restore must not publish a file");

        let report =
            restore_database_backup(&archive, &restored, passphrase).expect("restore backup");
        assert_eq!(report.schema_version, crate::db::SCHEMA_VERSION);
        crate::private_file::verify_private_store_file(&restored).expect("private restore");

        let restored_db = crate::db::open(&restored).expect("open restored store");
        let connection = restored_db.lock().expect("lock restored store");
        let restored_signer =
            crate::db::grant_signing_secret(&connection).expect("restored signer remains valid");
        assert_ne!(
            restored_signer, source_signer,
            "restore cutover must rotate endpoint grant signing authority"
        );
        let (authority_id, authority_state, authority_generation, predecessor_id): (
            String,
            String,
            i64,
            Option<String>,
        ) = connection
            .query_row(
                "SELECT deployment_key, authority_state, authority_generation,
                        predecessor_deployment_key
                 FROM deployment WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read restored authority lifecycle");
        assert_eq!(authority_state, "awaiting_cutover");
        assert_eq!(authority_generation, 2);
        assert_eq!(
            predecessor_id.as_deref(),
            Some(source_authority_id.as_str())
        );
        let cutover: (String, Option<String>, i64, String) = connection
            .query_row(
                "SELECT predecessor_authority_id, replacement_authority_id,
                        generation, state
                 FROM authority_cutovers WHERE replacement_authority_id = ?1",
                [&authority_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read restored cutover review");
        assert_eq!(cutover.0, source_authority_id);
        assert_eq!(cutover.1.as_deref(), Some(authority_id.as_str()));
        assert_eq!(cutover.2, 2);
        assert_eq!(cutover.3, "awaiting_review");
        let manager_revoked: Option<i64> = connection
            .query_row(
                "SELECT revoked_at FROM sessions WHERE id = 'session-1'",
                [],
                |row| row.get(0),
            )
            .expect("read restored manager session");
        let endpoint_revoked: Option<i64> = connection
            .query_row(
                "SELECT revoked_at FROM endpoint_sessions WHERE id = 'endpoint-session-1'",
                [],
                |row| row.get(0),
            )
            .expect("read restored endpoint session");
        let interaction: (String, i64) = connection
            .query_row(
                "SELECT claim.state, revision.revision
                 FROM interaction_claims AS claim
                 JOIN computer_interaction_revisions AS revision
                   ON revision.computer_id = claim.computer_id
                 WHERE claim.id = 'interaction-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read restored interaction fence");
        let invite_revoked: Option<i64> = connection
            .query_row(
                "SELECT revoked_at FROM computer_enrollment_invitations WHERE id = 'invite-1'",
                [],
                |row| row.get(0),
            )
            .expect("read restored invitation");
        let pending_authorities: (Option<i64>, Option<i64>, Option<i64>, Option<i64>) = connection
            .query_row(
                "SELECT
                    (SELECT consumed_at FROM auth_challenges WHERE id = 'manager-challenge-1'),
                    (SELECT consumed_at FROM endpoint_auth_challenges WHERE id = 'endpoint-challenge-1'),
                    (SELECT consumed_at FROM mfa_enrollments WHERE id = 'mfa-enrollment-1'),
                    (SELECT consumed_at FROM bootstrap_tokens WHERE token_hash = 'bootstrap-hash')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("read restored pending authority");
        assert!(manager_revoked.is_some());
        assert!(endpoint_revoked.is_some());
        assert_eq!(interaction, ("failed".to_owned(), 4));
        assert!(invite_revoked.is_some());
        assert!(pending_authorities.0.is_some());
        assert!(pending_authorities.1.is_some());
        assert!(pending_authorities.2.is_some());
        assert!(pending_authorities.3.is_some());
        drop(connection);

        let overwrite = restore_database_backup(&archive, &restored, passphrase)
            .expect_err("existing restore destination must be refused");
        assert!(overwrite.to_string().contains("without overwrite"));
    }
}
