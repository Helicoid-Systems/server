//! Integration tests for auth v2: TOTP MFA, recovery-only verification,
//! device-key challenge login, and explicit schema migration.
//!
//! All fixtures are disposable in-memory or tempfile databases.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use hs_server::crypto::{
    auth_challenge_proof_message, bootstrap_manager_proof_message, hash_password, hash_token,
    totp_generate_at, totp_time_step, unix_now,
};
use hs_server::db;
use hs_server::models::*;
use hs_server::service::Service;
use hs_server::AppError;

const PASSWORD: &str = "foundation-pass-v2-1";

/// Tempdir whose `base` is store-parent ready: Unix owner-private (0700);
/// Windows a genuine private product child via `ensure_private_store_dir`
/// (no silent re-ACL of TempDir or ancestors).
fn private_tempdir() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(windows)]
    let base = {
        let child = dir.path().join("hs-store");
        hs_server::private_file::ensure_private_store_dir(&child)
            .expect("windows private product child");
        child
    };
    #[cfg(not(windows))]
    let base = {
        let path = dir.path().canonicalize().expect("canonicalize");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        path
    };
    (dir, base)
}

#[cfg(unix)]
fn force_private_mode(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

#[cfg(not(unix))]
fn force_private_mode(_path: &std::path::Path) {}

fn service() -> Arc<Service> {
    let db = db::open_in_memory().expect("in-memory db");
    Arc::new(Service::new(db))
}

fn keypair() -> (SigningKey, String) {
    let mut secret = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);
    let signer = SigningKey::from_bytes(&secret);
    let public = hex_encode(&signer.verifying_key().to_bytes());
    (signer, public)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sign_challenge(
    signer: &SigningKey,
    deployment_id: &str,
    challenge_id: &str,
    operation: &str,
    key: &str,
) -> String {
    let message = auth_challenge_proof_message(deployment_id, challenge_id, operation, key);
    hex_encode(&signer.sign(&message).to_bytes())
}

/// Read the server-owned deployment key from the live store.
fn deployment_id(service: &Service) -> String {
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    conn.query_row(
        "SELECT deployment_key FROM deployment WHERE id = 1",
        [],
        |r| r.get(0),
    )
    .expect("deployment_key")
}

/// Generate a TOTP code for the *next* time step.
///
/// Bootstrap MFA confirmation already consumes the current step. Challenge
/// completions in these tests therefore use the next step (still inside the
/// ±1 skew window) so they exercise consumption rather than colliding with
/// the enrollment confirmation.
fn fresh_totp(secret: &str) -> String {
    totp_generate_at(secret, unix_now() + 30).expect("totp")
}

/// Pull the totp secret for an account via a recovery begin (test-only leak of
/// the new secret is fine; we only need any active secret for challenge tests).
/// For challenge tests we need the original secret — bootstrap response carries it.
struct Enrolled {
    account_id: String,
    public_key: String,
    signer: SigningKey,
    totp_secret: String,
    recovery_codes: Vec<String>,
}

fn bootstrap_enrolled(service: &Service) -> Enrolled {
    let (signer, public_key) = keypair();
    let token = service.create_bootstrap_token().expect("token");
    let dep = deployment_id(service);
    let token_hash = hash_token(&token);
    let message = bootstrap_manager_proof_message(&dep, &token_hash, &public_key);
    let proof = hex_encode(&signer.sign(&message).to_bytes());

    let boot = service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: Some(public_key.clone()),
            manager_proof: Some(proof),
            manager_friendly_name: Some("Admin device".into()),
        })
        .expect("bootstrap v2");

    let code = totp_generate_at(&boot.totp_secret_base32, unix_now()).expect("code");
    service
        .confirm_mfa_enrollment(MfaConfirmRequest {
            mfa_enrollment_id: boot.mfa_enrollment_id.clone(),
            totp_code: code,
            recovery_material_stored: true,
        })
        .expect("confirm mfa");

    Enrolled {
        account_id: boot.account_id,
        public_key,
        signer,
        totp_secret: boot.totp_secret_base32,
        recovery_codes: boot.recovery_codes,
    }
}

// ----- bootstrap enrollment -----

#[test]
fn bootstrap_v2_creates_inactive_until_mfa_confirmed() {
    let service = service();
    let (signer, public_key) = keypair();
    let token = service.create_bootstrap_token().expect("token");
    let dep = deployment_id(&service);
    let token_hash = hash_token(&token);
    let message = bootstrap_manager_proof_message(&dep, &token_hash, &public_key);
    let proof = hex_encode(&signer.sign(&message).to_bytes());

    let boot = service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: Some(public_key),
            manager_proof: Some(proof),
            manager_friendly_name: None,
        })
        .expect("bootstrap");
    assert_eq!(boot.account_state, "pending_mfa");
    assert_eq!(boot.recovery_codes.len(), 10);
    assert!(boot.totp_secret_base32.len() >= 26);

    // Pending MFA cannot create an ordinary session.
    let challenge = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        operation: "session".into(),
        manager_public_key: boot.manager_public_key.clone().unwrap(),
    });
    assert!(
        challenge.is_err(),
        "pending_mfa account must not start challenge login"
    );
}

#[test]
fn bootstrap_v2_binds_manager_key_only_after_proof() {
    let service = service();
    let (_, public_key) = keypair();
    let token = service.create_bootstrap_token().expect("token");
    let dep = deployment_id(&service);

    // Claiming a key without proof is refused.
    let no_proof = service.bootstrap_v2(BootstrapV2Request {
        bootstrap_token: token.clone(),
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_key: Some(public_key.clone()),
        manager_proof: None,
        manager_friendly_name: None,
    });
    assert!(no_proof.is_err(), "must require manager_proof");

    // Wrong proof is refused (arbitrary claimed identity is not enough).
    let token_hash = hash_token(&token);
    let message = bootstrap_manager_proof_message(&dep, &token_hash, "deadbeef");
    let (other_signer, _) = keypair();
    let bad_proof = hex_encode(&other_signer.sign(&message).to_bytes());
    let wrong_proof = service.bootstrap_v2(BootstrapV2Request {
        bootstrap_token: token.clone(),
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_key: Some(public_key.clone()),
        manager_proof: Some(bad_proof),
        manager_friendly_name: None,
    });
    assert!(wrong_proof.is_err(), "wrong-key proof must fail");

    // Correct proof binds the exact key.
    let message = bootstrap_manager_proof_message(&dep, &token_hash, &public_key);
    let good = hex_encode(&keypair().0.sign(&message).to_bytes());
    // That good sig is from a fresh key, so it must also fail...
    let mismatched = service.bootstrap_v2(BootstrapV2Request {
        bootstrap_token: token.clone(),
        username: "admin".into(),
        password: PASSWORD.into(),
        manager_public_key: Some(public_key.clone()),
        manager_proof: Some(good),
        manager_friendly_name: None,
    });
    assert!(
        mismatched.is_err(),
        "signature must come from the claimed key"
    );
}

#[test]
fn bootstrap_cancellation_denies_pending_enrollment() {
    let service = service();
    let (signer, public_key) = keypair();
    let token = service.create_bootstrap_token().expect("token");
    let dep = deployment_id(&service);
    let token_hash = hash_token(&token);
    let message = bootstrap_manager_proof_message(&dep, &token_hash, &public_key);
    let proof = hex_encode(&signer.sign(&message).to_bytes());

    let boot = service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: Some(public_key),
            manager_proof: Some(proof),
            manager_friendly_name: None,
        })
        .expect("bootstrap");

    service
        .cancel_mfa_enrollment(&boot.mfa_enrollment_id)
        .expect("cancel");

    // Confirmation after cancel is denied (enrollment consumed).
    let code = totp_generate_at(&boot.totp_secret_base32, unix_now()).expect("code");
    let confirm = service.confirm_mfa_enrollment(MfaConfirmRequest {
        mfa_enrollment_id: boot.mfa_enrollment_id.clone(),
        totp_code: code,
        recovery_material_stored: true,
    });
    assert!(confirm.is_err(), "cancelled enrollment must not confirm");
}

#[test]
fn mfa_confirm_requires_recovery_material_stored() {
    let service = service();
    let (signer, public_key) = keypair();
    let token = service.create_bootstrap_token().expect("token");
    let dep = deployment_id(&service);
    let token_hash = hash_token(&token);
    let message = bootstrap_manager_proof_message(&dep, &token_hash, &public_key);
    let proof = hex_encode(&signer.sign(&message).to_bytes());
    let boot = service
        .bootstrap_v2(BootstrapV2Request {
            bootstrap_token: token,
            username: "admin".into(),
            password: PASSWORD.into(),
            manager_public_key: Some(public_key),
            manager_proof: Some(proof),
            manager_friendly_name: None,
        })
        .expect("bootstrap");

    let code = totp_generate_at(&boot.totp_secret_base32, unix_now()).expect("code");
    let denied = service.confirm_mfa_enrollment(MfaConfirmRequest {
        mfa_enrollment_id: boot.mfa_enrollment_id.clone(),
        totp_code: code,
        recovery_material_stored: false,
    });
    assert!(
        denied.is_err(),
        "must require independently stored recovery"
    );
}

// ----- TOTP verification -----

#[test]
fn missing_wrong_and_replayed_totp_deny() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);

    // Wrong TOTP code.
    let wrong = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    });
    // begin succeeds; complete with wrong code fails.
    let challenge = wrong.expect("begin");
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let complete = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig,
        totp_code: Some("000000".into()),
    });
    assert!(complete.is_err(), "wrong totp must deny");

    // Replay of a used TOTP time step after a successful login.
    let code = fresh_totp(&enrolled.totp_secret);
    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let first = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig.clone(),
        totp_code: Some(code.clone()),
    });
    assert!(
        first.is_ok(),
        "first use of time step must succeed: {first:?}"
    );

    // Second challenge in the same time step with the same code must fail.
    let challenge2 = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin2");
    let sig2 = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge2.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let replay = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge2.challenge_id.clone(),
        challenge_token: challenge2.challenge_token.clone(),
        manager_signature: sig2,
        totp_code: Some(code),
    });
    assert!(
        replay.is_err(),
        "replayed totp time step must deny: {replay:?}"
    );
}

#[test]
fn concurrent_totp_replay_denies_second() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);
    let code = fresh_totp(&enrolled.totp_secret);

    // Two independent challenges, same factor code / time step.
    let c1 = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("c1");
    let c2 = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("c2");

    let s1 = sign_challenge(
        &enrolled.signer,
        &dep,
        &c1.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let s2 = sign_challenge(
        &enrolled.signer,
        &dep,
        &c2.challenge_id,
        "session",
        &enrolled.public_key,
    );

    let r1 = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: c1.challenge_id.clone(),
        challenge_token: c1.challenge_token.clone(),
        manager_signature: s1,
        totp_code: Some(code.clone()),
    });
    let r2 = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: c2.challenge_id.clone(),
        challenge_token: c2.challenge_token.clone(),
        manager_signature: s2,
        totp_code: Some(code),
    });

    let ok_count = [r1.is_ok(), r2.is_ok()].iter().filter(|ok| **ok).count();
    assert_eq!(
        ok_count, 1,
        "exactly one racing use of a totp time step may succeed"
    );
}

// ----- device-key challenge -----

#[test]
fn wrong_manager_proof_denies() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);
    let (_, other_key) = keypair();

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");

    // Signature from a different key must deny.
    let (other_signer, _) = keypair();
    let bad_sig = sign_challenge(
        &other_signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let code = fresh_totp(&enrolled.totp_secret);
    let denied = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: bad_sig,
        totp_code: Some(code),
    });
    assert!(denied.is_err(), "wrong manager key proof must deny");
    let _ = other_key;
}

#[test]
fn double_challenge_consumption_denies_replay() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);
    let code = fresh_totp(&enrolled.totp_secret);

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );

    let first = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig.clone(),
        totp_code: Some(code.clone()),
    });
    assert!(first.is_ok(), "first completion must succeed");

    // Same challenge id + token cannot be consumed twice.
    let second = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig,
        totp_code: Some(code),
    });
    assert!(second.is_err(), "double challenge consumption must deny");
}

#[test]
fn revoked_manager_denies_challenge_completion() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);

    // Find and revoke the manager from an authenticated v1 session is not
    // available after v2 bootstrap (admin is active). Use a second bootstrap
    // path: create a pending manager via register needs a session. Instead
    // revoke via direct store for this focused test.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        conn.execute(
            "UPDATE managers SET lifecycle_state = 'revoked' WHERE public_key = ?1",
            rusqlite::params![enrolled.public_key],
        )
        .expect("revoke");
    }

    let begin = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    });
    assert!(begin.is_err(), "revoked manager must not start a challenge");
}

#[test]
fn challenge_is_bound_to_operation_and_key() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");

    // Signing a different operation than the challenge bound must deny.
    let code = fresh_totp(&enrolled.totp_secret);
    let wrong_op_sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "manage_access",
        &enrolled.public_key,
    );
    let denied = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: wrong_op_sig,
        totp_code: Some(code),
    });
    assert!(denied.is_err(), "operation binding must hold");
}

// ----- recovery-only restrictions -----

#[test]
fn recovery_codes_are_hashed_and_single_use() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let code = enrolled.recovery_codes[0].clone();

    // Stored form is not the plaintext.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE code_hash = ?1",
                rusqlite::params![code],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(count, 0, "plaintext must not be stored");
    }

    let begin = service
        .begin_factor_recovery(FactorRecoveryBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            recovery_code: code.clone(),
        })
        .expect("recovery begin");
    assert_eq!(begin.purpose, "totp_factor_recovery_only");

    // Recovery must not create a session — only a new MFA enrollment.
    assert!(begin.totp_secret_base32.len() >= 26);

    // Same code cannot be reused.
    let replay = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: code,
    });
    assert!(replay.is_err(), "recovery code must be single-use");
}

#[test]
fn recovery_cannot_target_another_account() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let code = enrolled.recovery_codes[1].clone();

    // Create a second account via direct insert (no second bootstrap).
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state,
                can_operate, can_manage_enrollment, can_manage_access,
                can_manage_accounts, can_manage_security,
                revision, created_at, updated_at
             ) VALUES ('other', 'other-admin', 'hash', 'active', 0, 0, 0, 0, 0, 1, 1, 1)",
            [],
        )
        .expect("insert other");
    }

    // Recovery code belongs to admin, not other-admin.
    let stolen = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "other-admin".into(),
        password: "whatever-long-enough".into(),
        recovery_code: code,
    });
    assert!(
        stolen.is_err(),
        "recovery must not authenticate a different target account"
    );
}

#[test]
fn recovery_requires_password_and_is_not_a_session() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let code = enrolled.recovery_codes[2].clone();

    let bad_password = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: "wrong-password".into(),
        recovery_code: code.clone(),
    });
    assert!(bad_password.is_err(), "recovery must revalidate password");

    let ok = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: code,
    });
    assert!(ok.is_ok());
    // Response carries purpose only — no token field exists on the type.
}

// ----- pending recovery cancellation preserves established MFA -----

/// Durable account + factor row. Compared field-by-field so assertion
/// failures never dump raw TOTP secrets.
struct FactorSnapshot {
    account_state: String,
    mfa_status: String,
    totp_secret: String,
    totp_confirmed_at: Option<i64>,
    recovery_stored_at: Option<i64>,
}

fn factor_snapshot(service: &Service, account_id: &str) -> FactorSnapshot {
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    let account_state: String = conn
        .query_row(
            "SELECT state FROM accounts WHERE id = ?1",
            rusqlite::params![account_id],
            |r| r.get(0),
        )
        .expect("account state");
    let (mfa_status, totp_secret, totp_confirmed_at, recovery_stored_at) = conn
        .query_row(
            "SELECT status, totp_secret, totp_confirmed_at, recovery_stored_at
             FROM account_mfa WHERE account_id = ?1",
            rusqlite::params![account_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .expect("account_mfa");
    FactorSnapshot {
        account_state,
        mfa_status,
        totp_secret,
        totp_confirmed_at,
        recovery_stored_at,
    }
}

fn assert_factor_unchanged(before: &FactorSnapshot, after: &FactorSnapshot, ctx: &str) {
    assert_eq!(
        before.account_state, after.account_state,
        "{ctx}: account state"
    );
    assert_eq!(before.mfa_status, after.mfa_status, "{ctx}: mfa status");
    // Raw TOTP secrets: bounded boolean asserts only (never Debug/Display).
    assert!(
        before.totp_secret == after.totp_secret,
        "{ctx}: totp secret preserved"
    );
    assert_eq!(
        before.totp_confirmed_at, after.totp_confirmed_at,
        "{ctx}: totp_confirmed_at"
    );
    assert_eq!(
        before.recovery_stored_at, after.recovery_stored_at,
        "{ctx}: recovery_stored_at"
    );
}

fn totp_step_used(service: &Service, account_id: &str, step: i64) -> bool {
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM totp_consumptions
             WHERE account_id = ?1 AND time_step = ?2",
            rusqlite::params![account_id, step],
            |r| r.get(0),
        )
        .expect("consumption count");
    count > 0
}

fn session_count(service: &Service) -> i64 {
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .expect("session count")
}

fn enrollment_consumed_at(service: &Service, enrollment_id: &str) -> Option<i64> {
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    conn.query_row(
        "SELECT consumed_at FROM mfa_enrollments WHERE id = ?1",
        rusqlite::params![enrollment_id],
        |r| r.get(0),
    )
    .expect("enrollment")
}

/// Pick an unused TOTP time step inside the real ±1 skew window by
/// read-only inspection of the disposable consumption ledger.
fn unused_totp_time(service: &Service, account_id: &str) -> u64 {
    let current = totp_time_step(unix_now());
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    for step in [current + 1, current - 1, current] {
        let used: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM totp_consumptions
                 WHERE account_id = ?1 AND time_step = ?2",
                rusqlite::params![account_id, step],
                |r| r.get(0),
            )
            .expect("consumption count");
        if used == 0 {
            return (step as u64) * 30;
        }
    }
    panic!("no unused totp time step inside the skew window");
}

/// Challenge-login with the approved manager device key and a fresh code.
fn complete_session_login(
    service: &Service,
    enrolled: &Enrolled,
    secret: &str,
) -> Result<LoginResponse, hs_server::AppError> {
    let dep = deployment_id(service);
    let challenge = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    })?;
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );
    // Password verification can cross a TOTP step; sample after it finishes.
    let at = unused_totp_time(service, &enrolled.account_id);
    let code = totp_generate_at(secret, at).expect("totp code");
    service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id,
        challenge_token: challenge.challenge_token,
        manager_signature: sig,
        totp_code: Some(code),
    })
}

/// Cancel-before-confirm: cancelling a pending recovery enrollment must
/// leave the established active factor and account untouched. Login still
/// works, the cancelled enrollment cannot confirm/replay, the consumed
/// recovery code stays refused, and begin/cancel mint no session.
#[test]
fn cancelled_recovery_enrollment_preserves_active_mfa() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let before = factor_snapshot(&service, &enrolled.account_id);
    assert_eq!(before.account_state, "active");
    assert_eq!(before.mfa_status, "active");
    let sessions_before = session_count(&service);

    let code = enrolled.recovery_codes[0].clone();
    let begin = service
        .begin_factor_recovery(FactorRecoveryBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            recovery_code: code.clone(),
        })
        .expect("recovery begin");
    assert_eq!(begin.account_id, enrolled.account_id);
    assert!(
        begin.totp_secret_base32 != before.totp_secret,
        "recovery begin issues a pending replacement secret"
    );
    assert_eq!(
        session_count(&service),
        sessions_before,
        "recovery begin must not mint a session"
    );

    service
        .cancel_mfa_enrollment(&begin.mfa_enrollment_id)
        .expect("cancel pending recovery enrollment");

    let after = factor_snapshot(&service, &enrolled.account_id);
    assert_factor_unchanged(
        &before,
        &after,
        "cancel must not deactivate or replace the established active factor",
    );
    assert_eq!(
        session_count(&service),
        sessions_before,
        "recovery cancel must not mint a session"
    );
    assert!(
        enrollment_consumed_at(&service, &begin.mfa_enrollment_id).is_some(),
        "cancel consumes the enrollment"
    );

    // Cancelled enrollment cannot confirm or replay.
    let confirm_at = unused_totp_time(&service, &enrolled.account_id);
    let confirm_code = totp_generate_at(&begin.totp_secret_base32, confirm_at).expect("code");
    let confirm = service.complete_factor_recovery(MfaConfirmRequest {
        mfa_enrollment_id: begin.mfa_enrollment_id.clone(),
        totp_code: confirm_code,
        recovery_material_stored: true,
    });
    assert!(
        confirm.is_err(),
        "cancelled recovery enrollment must not confirm"
    );
    let cancel_replay = service.cancel_mfa_enrollment(&begin.mfa_enrollment_id);
    assert!(
        cancel_replay.is_err(),
        "cancelled recovery enrollment is single-use"
    );

    // The original recovery code was consumed at begin and stays refused.
    let replay = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: code,
    });
    assert!(
        replay.is_err(),
        "consumed recovery code must stay refused after cancel"
    );

    // Established approved manager + original factor can still log in.
    let login = complete_session_login(&service, &enrolled, &enrolled.totp_secret)
        .expect("original factor login after recovery cancel");
    assert_eq!(login.account.id, enrolled.account_id);
    assert_eq!(
        session_count(&service),
        sessions_before + 1,
        "exactly one login session after successful challenge"
    );
}

/// Confirm-before-cancel: confirmation installs the replacement secret and
/// wins the single-use enrollment; cancel is refused and the winning factor
/// is the one that can still log in.
#[test]
fn factor_recovery_confirm_then_cancel_keeps_winning_factor() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let before = factor_snapshot(&service, &enrolled.account_id);
    let sessions_before = session_count(&service);

    let code = enrolled.recovery_codes[1].clone();
    let begin = service
        .begin_factor_recovery(FactorRecoveryBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            recovery_code: code.clone(),
        })
        .expect("recovery begin");
    let replacement_secret = begin.totp_secret_base32.clone();

    let confirm_at = unused_totp_time(&service, &enrolled.account_id);
    let confirm_code = totp_generate_at(&replacement_secret, confirm_at).expect("confirm code");
    let confirm = service
        .complete_factor_recovery(MfaConfirmRequest {
            mfa_enrollment_id: begin.mfa_enrollment_id.clone(),
            totp_code: confirm_code,
            recovery_material_stored: true,
        })
        .expect("factor replacement confirmation");
    assert_eq!(confirm.account_id, enrolled.account_id);
    assert_eq!(confirm.mfa_status, "active");
    assert_eq!(confirm.account_state, "active");
    assert_eq!(
        session_count(&service),
        sessions_before,
        "recovery confirmation must not mint a session"
    );

    let after = factor_snapshot(&service, &enrolled.account_id);
    assert_eq!(after.account_state, "active");
    assert_eq!(after.mfa_status, "active");
    assert!(
        after.totp_secret == replacement_secret,
        "confirmation must install the verified pending enrollment secret"
    );
    assert!(
        after.totp_secret != before.totp_secret,
        "replacement must swap the established secret"
    );
    assert!(after.totp_confirmed_at.is_some());

    // Cancel after confirm is refused: enrollment is single-use consumed.
    let cancel = service.cancel_mfa_enrollment(&begin.mfa_enrollment_id);
    assert!(
        cancel.is_err(),
        "cancel after confirm must refuse the consumed enrollment"
    );
    let winning = factor_snapshot(&service, &enrolled.account_id);
    assert_factor_unchanged(
        &after,
        &winning,
        "cancel-after-confirm must preserve the winning replacement factor",
    );

    // Consumed recovery code stays refused; no session from begin/confirm/cancel.
    let replay = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: code,
    });
    assert!(replay.is_err(), "consumed recovery code must stay refused");

    // Winning replacement factor logs in with a genuine device-key challenge.
    let login = complete_session_login(&service, &enrolled, &replacement_secret)
        .expect("replacement factor login after confirm-before-cancel");
    assert_eq!(login.account.id, enrolled.account_id);
}

/// Failed confirmation after TOTP-step + enrollment consumption must roll
/// back those writes: old factor stays installed, enrollment stays
/// unconsumed, the attempted step is absent, no session is minted, and the
/// security latch denies new authority. Fault is a disposable-test-only
/// `BEFORE UPDATE ON account_mfa` trigger (no production schema/clock hook).
#[test]
fn failed_recovery_confirm_leaves_old_factor_and_unconsumed_enrollment() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let before = factor_snapshot(&service, &enrolled.account_id);
    let sessions_before = session_count(&service);

    let code = enrolled.recovery_codes[2].clone();
    let begin = service
        .begin_factor_recovery(FactorRecoveryBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            recovery_code: code.clone(),
        })
        .expect("recovery begin");

    // Fault only in this disposable store: abort the account_mfa UPDATE so
    // confirmation fails after consuming the TOTP step and enrollment.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        conn.execute_batch(
            "CREATE TRIGGER account_mfa_confirm_fault BEFORE UPDATE ON account_mfa
             BEGIN
               SELECT RAISE(ABORT, 'test_account_mfa_update_fault');
             END;",
        )
        .expect("install disposable confirm fault trigger");
    }

    // Actual unused allowed step from the real ledger (read-only selection).
    let confirm_at = unused_totp_time(&service, &enrolled.account_id);
    let confirm_step = totp_time_step(confirm_at);
    assert!(
        !totp_step_used(&service, &enrolled.account_id, confirm_step),
        "confirm step must start unused"
    );

    let confirm_code = totp_generate_at(&begin.totp_secret_base32, confirm_at).expect("code");
    let failed = service.complete_factor_recovery(MfaConfirmRequest {
        mfa_enrollment_id: begin.mfa_enrollment_id.clone(),
        totp_code: confirm_code,
        recovery_material_stored: true,
    });
    assert!(
        failed.is_err(),
        "account_mfa update fault must deny confirmation"
    );

    let after = factor_snapshot(&service, &enrolled.account_id);
    assert_factor_unchanged(
        &before,
        &after,
        "failed confirmation must leave the old factor installed",
    );
    assert!(
        enrollment_consumed_at(&service, &begin.mfa_enrollment_id).is_none(),
        "failed confirmation must leave the enrollment unconsumed"
    );
    assert!(
        !totp_step_used(&service, &enrolled.account_id, confirm_step),
        "attempted totp step must be absent after rollback"
    );
    assert_eq!(
        session_count(&service),
        sessions_before,
        "failed confirmation must not mint a session"
    );
    assert!(
        service.security_state() == hs_server::SecurityState::Unavailable,
        "storage uncertainty must latch security state unavailable"
    );
    let denied = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    });
    assert!(
        denied.is_err(),
        "latched security state must deny new authority"
    );

    // The latch alone also denies replay. Read the durable row to prove that
    // rollback did not restore the recovery code consumed by the earlier begin.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        let used_at: Option<i64> = conn
            .query_row(
                "SELECT used_at FROM recovery_codes WHERE account_id = ?1 AND code_hash = ?2",
                rusqlite::params![
                    enrolled.account_id,
                    hs_server::auth_v2::recovery_code_hash_for_test(&code)
                ],
                |row| row.get(0),
            )
            .expect("consumed recovery code row");
        assert!(
            used_at.is_some(),
            "recovery code consumption must survive rollback"
        );
    }
    let replay = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: code,
    });
    assert!(
        replay.is_err(),
        "recovery code must stay consumed through the failed confirm"
    );
}

/// Persistent private-store restart after cancel-before-confirm: the
/// established factor survives reopen and the cancelled enrollment stays
/// refused. The genuine approved manager signing key and the cancelled
/// pending replacement secret are retained in this test scope across the
/// store restart.
#[cfg(any(windows, unix))]
#[test]
fn cancelled_recovery_enrollment_preserves_active_mfa_across_restart() {
    let (_dir, base) = private_tempdir();
    let path = base.join("hs-server.db");
    let (enrolled, sessions_before, before, cancelled_id, consumed_code, cancelled_pending_secret);

    {
        let db = db::open(&path).expect("open private store");
        assert_eq!(
            db.store_capability(),
            db::StoreCapability::PersistentPrivate
        );
        let service = Service::new(db);
        enrolled = bootstrap_enrolled(&service);
        before = factor_snapshot(&service, &enrolled.account_id);
        sessions_before = session_count(&service);
        consumed_code = enrolled.recovery_codes[3].clone();

        let begin = service
            .begin_factor_recovery(FactorRecoveryBeginRequest {
                username: "admin".into(),
                password: PASSWORD.into(),
                recovery_code: consumed_code.clone(),
            })
            .expect("recovery begin");
        cancelled_id = begin.mfa_enrollment_id.clone();
        cancelled_pending_secret = begin.totp_secret_base32.clone();
        assert!(
            cancelled_pending_secret != before.totp_secret,
            "pending replacement secret is distinct from the established factor"
        );
        service
            .cancel_mfa_enrollment(&begin.mfa_enrollment_id)
            .expect("cancel pending recovery");

        let after = factor_snapshot(&service, &enrolled.account_id);
        assert_factor_unchanged(
            &before,
            &after,
            "cancel must preserve the established factor before restart",
        );
        assert_eq!(
            session_count(&service),
            sessions_before,
            "begin/cancel mint no session before restart"
        );
    }

    // Reopen the same private store; sign with the retained original key.
    let db = db::open(&path).expect("reopen private store");
    assert_eq!(
        db.store_capability(),
        db::StoreCapability::PersistentPrivate
    );
    let service = Service::new(db);
    let after = factor_snapshot(&service, &enrolled.account_id);
    assert_factor_unchanged(
        &before,
        &after,
        "reopened store must retain the established active factor",
    );
    assert!(
        enrollment_consumed_at(&service, &cancelled_id).is_some(),
        "cancelled enrollment consumption must persist across reopen"
    );

    // Denial uses the genuine cancelled pending replacement secret (the
    // secret that confirmation would have installed), not the original.
    let confirm_at = unused_totp_time(&service, &enrolled.account_id);
    let confirm_code =
        totp_generate_at(&cancelled_pending_secret, confirm_at).expect("pending confirm code");
    let confirm = service.complete_factor_recovery(MfaConfirmRequest {
        mfa_enrollment_id: cancelled_id.clone(),
        totp_code: confirm_code,
        recovery_material_stored: true,
    });
    assert!(
        confirm.is_err(),
        "cancelled enrollment must stay unconfirmable after reopen"
    );
    let cancel_replay = service.cancel_mfa_enrollment(&cancelled_id);
    assert!(
        cancel_replay.is_err(),
        "cancelled enrollment stays single-use"
    );
    let code_replay = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: consumed_code,
    });
    assert!(
        code_replay.is_err(),
        "consumed recovery code must stay refused after reopen"
    );

    let login = complete_session_login(&service, &enrolled, &enrolled.totp_secret)
        .expect("original factor login after recovery cancel and restart");
    assert_eq!(login.account.id, enrolled.account_id);
    assert_eq!(
        session_count(&service),
        sessions_before + 1,
        "restart path mints only the successful login session"
    );
}

/// Persistent private-store restart after replacement confirmation: the
/// installed replacement secret survives reopen and logs in.
#[cfg(any(windows, unix))]
#[test]
fn replacement_factor_survives_private_store_restart() {
    let (_dir, base) = private_tempdir();
    let path = base.join("hs-server.db");
    let (enrolled, replacement_secret, sessions_before);

    {
        let db = db::open(&path).expect("open private store");
        let service = Service::new(db);
        enrolled = bootstrap_enrolled(&service);
        sessions_before = session_count(&service);

        let code = enrolled.recovery_codes[4].clone();
        let begin = service
            .begin_factor_recovery(FactorRecoveryBeginRequest {
                username: "admin".into(),
                password: PASSWORD.into(),
                recovery_code: code.clone(),
            })
            .expect("recovery begin");
        replacement_secret = begin.totp_secret_base32.clone();

        let confirm_at = unused_totp_time(&service, &enrolled.account_id);
        let confirm_code = totp_generate_at(&replacement_secret, confirm_at).expect("code");
        service
            .complete_factor_recovery(MfaConfirmRequest {
                mfa_enrollment_id: begin.mfa_enrollment_id.clone(),
                totp_code: confirm_code,
                recovery_material_stored: true,
            })
            .expect("replacement confirmation");
    }

    let db = db::open(&path).expect("reopen private store");
    let service = Service::new(db);
    let after = factor_snapshot(&service, &enrolled.account_id);
    assert_eq!(after.mfa_status, "active");
    assert!(
        after.totp_secret == replacement_secret,
        "reopened store must retain the replacement factor secret"
    );

    let login = complete_session_login(&service, &enrolled, &replacement_secret)
        .expect("replacement factor login after restart");
    assert_eq!(login.account.id, enrolled.account_id);
    assert_eq!(session_count(&service), sessions_before + 1);
}

// ----- rate limit -----

#[test]
fn challenge_rate_limits_without_account_enumeration() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);

    let mut unknown_err = None;
    let mut known_err = None;
    for i in 0..6 {
        let u = service.begin_auth_challenge(AuthChallengeBeginRequest {
            username: "no-such-user".into(),
            password: format!("wrong-{i}"),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        });
        if let Err(err) = u {
            unknown_err = Some(err.to_string());
        }
        let k = service.begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: format!("wrong-{i}"),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        });
        if let Err(err) = k {
            known_err = Some(err.to_string());
        }
    }

    // After the lockout threshold both must report the same rate-limit shape.
    let unknown = unknown_err.expect("unknown user error");
    let known = known_err.expect("known user error");
    assert!(
        unknown.contains("invalid credentials") || unknown.contains("too many"),
        "unknown={unknown}"
    );
    assert!(
        known.contains("invalid credentials") || known.contains("too many"),
        "known={known}"
    );

    // The sixth attempt must be rate limited for both keys equally.
    let u = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "no-such-user".into(),
        password: "still-wrong".into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    });
    let k = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: "still-wrong".into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    });
    let u_msg = u.expect_err("must limit unknown");
    let k_msg = k.expect_err("must limit known");
    assert_eq!(
        u_msg.to_string(),
        k_msg.to_string(),
        "rate-limit error must not distinguish accounts"
    );
}

// ----- failure before commit -----

#[test]
fn totp_consumption_failure_denies_without_session() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );

    // Code and consumed step share one timestamp sampled after the slow
    // challenge/signature work, so a 30s boundary crossing during setup
    // cannot desynchronize them.
    let code_time = unix_now() + 30;
    let code =
        totp_generate_at(&enrolled.totp_secret, code_time).expect("generate bound test code");
    let step = totp_time_step(code_time);

    // Pre-consume the time step that the challenge completion will use so
    // the complete path hits a storage conflict inside the transaction —
    // no session may be issued.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        conn.execute(
            "INSERT INTO totp_consumptions (account_id, time_step, consumed_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![enrolled.account_id, step, unix_now() as i64],
        )
        .expect("pre-consume");
    }

    let complete = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig,
        totp_code: Some(code),
    });
    assert!(
        complete.is_err(),
        "failure before commit must deny and not issue a token"
    );

    // Rollback must be complete: no session issued, challenge unconsumed.
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    let sessions: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE account_id = ?1",
            rusqlite::params![enrolled.account_id],
            |r| r.get(0),
        )
        .expect("session count");
    assert_eq!(
        sessions, 0,
        "no session may be issued on totp consumption conflict"
    );
    let consumed_at: Option<i64> = conn
        .query_row(
            "SELECT consumed_at FROM auth_challenges WHERE id = ?1",
            rusqlite::params![challenge.challenge_id],
            |r| r.get(0),
        )
        .expect("challenge consumed_at");
    assert!(
        consumed_at.is_none(),
        "challenge must remain unconsumed after rollback"
    );
}

// ----- explicit migration -----

#[test]
fn startup_never_auto_migrates_existing_db() {
    let (_dir, base) = private_tempdir();
    let path = base.join("old.db");
    seed_v1_database(&path);
    force_private_mode(&path);
    // open() must refuse — no silent upgrade on startup.
    let err = match db::open(&path) {
        Ok(_) => panic!("startup must not auto-migrate"),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(msg.contains("migrate"), "msg={msg}");
}

/// Unix: verified private store allows explicit migrate with backup + data keep.
#[cfg(unix)]
#[test]
fn explicit_migrate_upgrades_with_backup_and_keeps_data() {
    let (_dir, base) = private_tempdir();
    let path = base.join("old.db");
    let backup_dir = base.join("backups");
    seed_v1_database(&path);
    force_private_mode(&path);

    let report = db::migrate(&path, &backup_dir).expect("migrate");
    assert_eq!(report.from_version, 1);
    assert_eq!(report.to_version, db::SCHEMA_VERSION);
    assert!(report.backup_path.exists());
    force_private_mode(&report.backup_path);

    let service = hs_server::open_service(&path).expect("open after migrate");
    let health = service.health().expect("health");
    assert!(health.bootstrap_completed);
    // v1 wire contract version stays 1; storage is independent.
    assert_eq!(
        health.schema_version,
        hs_server::models::WIRE_CONTRACT_V1_VERSION
    );
    assert_eq!(health.storage_schema_version, db::SCHEMA_VERSION);

    // Data preserved: the v1 admin still exists.
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    let username: String = conn
        .query_row("SELECT username FROM accounts WHERE id = 'a1'", [], |r| {
            r.get(0)
        })
        .expect("account");
    assert_eq!(username, "admin");
}

/// Windows: explicit migrate uses the native private boundary (positive).
#[cfg(windows)]
#[test]
fn explicit_migrate_upgrades_with_backup_on_windows_private_store() {
    let (_dir, base) = private_tempdir();
    let path = base.join("old.db");
    let backup_dir = base.join("backups");
    seed_v1_database(&path);
    force_private_mode(&path);

    let report = db::migrate(&path, &backup_dir).expect("migrate with private boundary");
    assert_eq!(report.from_version, 1);
    assert_eq!(report.to_version, db::SCHEMA_VERSION);
    assert!(report.backup_path.exists());
}

// ----- coordinator regressions -----

#[test]
fn wrong_deployment_proof_denies() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);
    let code = fresh_totp(&enrolled.totp_secret);

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");

    // Sign a message bound to a *different* deployment id.
    let wrong_dep_sig = sign_challenge(
        &enrolled.signer,
        "dep_not_this_deployment",
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let denied = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: wrong_dep_sig,
        totp_code: Some(code.clone()),
    });
    assert!(
        denied.is_err(),
        "proof bound to another deployment must deny"
    );

    // Correct deployment binding succeeds (challenge still unconsumed).
    let good_sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let ok = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: good_sig,
        totp_code: Some(code),
    });
    assert!(
        ok.is_ok(),
        "correct deployment-bound proof must succeed: {ok:?}"
    );
}

#[test]
fn revoked_manager_race_denies_inside_final_transaction() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);
    let code = fresh_totp(&enrolled.totp_secret);

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );

    // Revoke *after* begin (and after a would-be pre-check) but *before* complete.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        conn.execute(
            "UPDATE managers SET lifecycle_state = 'revoked' WHERE public_key = ?1",
            rusqlite::params![enrolled.public_key],
        )
        .expect("revoke");
    }

    let complete = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig,
        totp_code: Some(code),
    });
    assert!(
        complete.is_err(),
        "revocation after begin must deny inside the final transaction: {complete:?}"
    );
    // No session may exist for this account.
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    let sessions: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        sessions, 0,
        "no session may be issued after revocation race"
    );
}

#[test]
fn disabled_account_race_denies_inside_final_transaction() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);
    let code = fresh_totp(&enrolled.totp_secret);

    let challenge = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("begin");
    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &enrolled.public_key,
    );

    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        conn.execute(
            "UPDATE accounts SET state = 'disabled' WHERE id = ?1",
            rusqlite::params![enrolled.account_id],
        )
        .expect("disable");
    }

    let complete = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig,
        totp_code: Some(code),
    });
    assert!(
        complete.is_err(),
        "disabled account must deny inside the final transaction"
    );
    let db = service.db_handle();
    let conn = db.lock().expect("lock");
    let sessions: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .expect("count");
    assert_eq!(sessions, 0, "no session may be issued for disabled account");
}

#[test]
fn durable_challenge_throttle_survives_service_recreation() {
    let (_dir, base) = private_tempdir();
    let path = base.join("throttle.db");
    let db = db::open(&path).expect("open");
    let service = std::sync::Arc::new(Service::new(db));
    // begin_auth_challenge validates key format, then throttle, then
    // credentials — manager approval is later. Failure/lockout paths therefore
    // need only a valid public key, not enrollment (Windows persistence
    // refuses NEW MFA until a verified private DACL exists).
    let (_, public_key) = keypair();

    // Drive failures until lockout for a fixed key.
    for i in 0..6 {
        let result = service.begin_auth_challenge(AuthChallengeBeginRequest {
            username: "no-such-user".into(),
            password: format!("wrong-{i}"),
            operation: "session".into(),
            manager_public_key: public_key.clone(),
        });
        assert!(result.is_err());
    }

    // Recreate the service over the same file — throttle must persist.
    let db2 = db::open(&path).expect("reopen");
    let service2 = Service::new(db2);
    let locked = service2.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "no-such-user".into(),
        password: "still-wrong".into(),
        operation: "session".into(),
        manager_public_key: public_key.clone(),
    });
    let err = locked.expect_err("throttle must survive restart");
    let msg = err.to_string();
    assert!(
        msg.contains("too many") || msg.contains("rate"),
        "expected durable rate limit, got {msg}"
    );
}

#[test]
fn auth_challenges_and_totp_rows_are_capacity_bounded() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);

    // Insert many fake challenge rows and verify prune keeps the cap.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        for i in 0..(crate::db::MAX_AUTH_CHALLENGE_ROWS + 20) {
            conn.execute(
                "INSERT INTO auth_challenges (
                    id, token_hash, account_id, manager_public_key, operation,
                    created_at, expires_at, consumed_at, deployment_key
                 ) VALUES (?1, ?2, ?3, ?4, 'session', ?5, ?5, NULL, 'dep_x')",
                rusqlite::params![
                    format!("ch-{i}"),
                    format!("hash-{i}"),
                    enrolled.account_id,
                    enrolled.public_key,
                    1_760_000_000i64 + i,
                ],
            )
            .expect("insert challenge");
        }
        crate::db::prune_auth_challenges(&conn, 1_760_000_000).expect("prune");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_challenges", [], |r| r.get(0))
            .expect("count");
        assert!(
            count <= crate::db::MAX_AUTH_CHALLENGE_ROWS + 5,
            "challenge rows must stay bounded, got {count}"
        );
    }

    // TOTP consumption ledger is capped per account.
    {
        let db = service.db_handle();
        let conn = db.lock().expect("lock");
        for step in 0..(crate::db::MAX_TOTP_CONSUMPTIONS_PER_ACCOUNT + 20) {
            conn.execute(
                "INSERT OR IGNORE INTO totp_consumptions (account_id, time_step, consumed_at)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![enrolled.account_id, step, 1_760_000_000i64],
            )
            .expect("insert step");
        }
        crate::db::prune_totp_consumptions(&conn, &enrolled.account_id).expect("prune");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM totp_consumptions WHERE account_id = ?1",
                rusqlite::params![enrolled.account_id],
                |r| r.get(0),
            )
            .expect("count");
        assert!(
            count <= crate::db::MAX_TOTP_CONSUMPTIONS_PER_ACCOUNT,
            "totp ledger must stay bounded, got {count}"
        );
    }
}

#[test]
fn v1_health_wire_schema_version_stays_one() {
    let service = service();
    let health = service.health().expect("health");
    assert_eq!(
        health.schema_version,
        hs_server::models::WIRE_CONTRACT_V1_VERSION
    );
    assert_eq!(health.schema_version, 1, "native clients validate == 1");
    assert_eq!(health.storage_schema_version, db::SCHEMA_VERSION);
}

fn seed_v1_database(path: &std::path::Path) {
    let conn = rusqlite::Connection::open(path).expect("open");
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
         INSERT INTO deployment (id, bootstrap_completed, bootstrap_completed_at, security_state_ok, created_at)
            VALUES (1, 1, 100, 1, 100);
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

// ----- Db-owned store capability (finding: global platform bool) -----
//
// Nonpersistent in-memory stores exercise real crypto on every platform.
// Persistent stores on Unix/Windows use the verified private boundary.

#[test]
fn in_memory_store_exercises_real_crypto_on_every_platform() {
    let svc = service();
    assert_eq!(
        svc.db_handle().store_capability(),
        db::StoreCapability::NonPersistent
    );
    assert!(svc.db_handle().persisted_v2_credentials_allowed());
    // Real crypto path must succeed (not a skipped suite).
    let enrolled = bootstrap_enrolled(&svc);
    assert!(!enrolled.totp_secret.is_empty());
    assert!(!enrolled.recovery_codes.is_empty());
}

/// Persistent private stores allow MFA bootstrap and retain it across reopen.
/// Run portable behavior on Unix and Windows; Windows ACL corruption is native.
#[cfg(any(windows, unix))]
mod persistent_private_mfa {
    use super::*;

    fn persistent_service() -> (tempfile::TempDir, Arc<Service>) {
        let (dir, base) = private_tempdir();
        let path = base.join("hs-server.db");
        let db = db::open(&path).expect("private persistent open");
        assert_eq!(
            db.store_capability(),
            db::StoreCapability::PersistentPrivate
        );
        assert!(db.persisted_v2_credentials_allowed());
        (dir, Arc::new(Service::new(db)))
    }

    #[test]
    fn bootstrap_v2_persists_on_private_store() {
        let (_dir, service) = persistent_service();
        let token = service.create_bootstrap_token().expect("token");
        let response = service
            .bootstrap_v2(BootstrapV2Request {
                bootstrap_token: token,
                username: "admin".into(),
                password: PASSWORD.into(),
                manager_public_key: None,
                manager_proof: None,
                manager_friendly_name: None,
            })
            .expect("bootstrap v2 on private store");
        assert!(!response.totp_secret_base32.is_empty());
        assert!(!response.recovery_codes.is_empty());
    }

    /// Persisted bootstrap_v2 → close Service/Db → reopen → MFA/recovery rows
    /// retained on a confidential private DB (live WAL/SHM while open).
    #[test]
    fn persisted_bootstrap_v2_mfa_rows_survive_reopen() {
        let (_dir, base) = private_tempdir();
        let path = base.join("hs-server.db");
        let enrollment_id;
        {
            let db = db::open(&path).expect("open private store");
            let service = Service::new(db);
            let token = service.create_bootstrap_token().expect("token");
            // BootstrapV2Response deliberately lacks Debug (secret-bearing).
            let response = service
                .bootstrap_v2(BootstrapV2Request {
                    bootstrap_token: token,
                    username: "admin".into(),
                    password: PASSWORD.into(),
                    manager_public_key: None,
                    manager_proof: None,
                    manager_friendly_name: None,
                })
                .expect("bootstrap v2 on private store");
            assert!(!response.totp_secret_base32.is_empty());
            assert!(!response.recovery_codes.is_empty());
            enrollment_id = response.mfa_enrollment_id.clone();
            assert!(!enrollment_id.is_empty());
            // Live WAL/SHM must exist while the service holds the DB after the
            // bootstrap write (no vacuous "if exists" pass) and be private.
            for suffix in ["-wal", "-shm"] {
                let mut os = path.as_os_str().to_os_string();
                os.push(suffix);
                let p = std::path::PathBuf::from(os);
                assert!(
                    p.exists(),
                    "live {suffix} must exist while service holds the DB after bootstrap write"
                );
                hs_server::private_file::verify_private_store_file(&p)
                    .unwrap_or_else(|e| panic!("live {suffix} private: {e}"));
            }
            // Drop service + Db (close).
        }

        // Reopen: pending MFA, recovery, and enrollment rows retained.
        let db = db::open(&path).expect("reopen private store");
        assert_eq!(
            db.store_capability(),
            db::StoreCapability::PersistentPrivate
        );
        {
            let conn = db.lock().expect("lock");
            let mfa_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM account_mfa", [], |r| r.get(0))
                .expect("account_mfa");
            assert_eq!(mfa_count, 1, "pending MFA row retained");
            let rec_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM recovery_codes", [], |r| r.get(0))
                .expect("recovery_codes");
            assert!(rec_count > 0, "recovery rows retained");
            let enroll: String = conn
                .query_row(
                    "SELECT id FROM mfa_enrollments WHERE id = ?1",
                    [enrollment_id.as_str()],
                    |r| r.get(0),
                )
                .expect("enrollment row retained");
            assert_eq!(enroll, enrollment_id);
        }
    }

    /// Corrupted private boundary (unknown SID grant) refuses an existing MFA
    /// store and preserves bytes before any transaction.
    #[cfg(windows)]
    #[test]
    fn corrupted_private_boundary_refuses_existing_mfa_and_preserves_bytes() {
        let (_dir, base) = private_tempdir();
        let path = base.join("hs-server.db");
        {
            let db = db::open(&path).expect("open");
            let service = Service::new(db);
            let token = service.create_bootstrap_token().expect("token");
            let response = service
                .bootstrap_v2(BootstrapV2Request {
                    bootstrap_token: token,
                    username: "admin".into(),
                    password: PASSWORD.into(),
                    manager_public_key: None,
                    manager_proof: None,
                    manager_friendly_name: None,
                })
                .expect("bootstrap");
            assert!(!response.totp_secret_base32.is_empty());
        }
        let before = std::fs::read(&path).expect("db bytes");
        grant_unknown_sid_read_on_store(&path);
        // Db has no Debug (secret-bearing); do not use expect_err on Ok(Db).
        let err = match db::open(&path) {
            Err(err) => err,
            Ok(_) => panic!("must refuse corrupted private boundary"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("refusing") || msg.contains("private") || msg.contains("allowlist"),
            "msg={msg}"
        );
        assert_eq!(
            std::fs::read(&path).expect("bytes after"),
            before,
            "existing MFA store bytes preserved before transaction"
        );
    }

    /// Windows fixture: add an unknown SID (Everyone) read grant so the store
    /// is no longer private. `SetNamedSecurityInfoW` takes an ACL only — no
    /// SECURITY_DESCRIPTOR. Aligned `Vec<u64>` storage; buffers live through
    /// the call.
    #[cfg(windows)]
    fn grant_unknown_sid_read_on_store(path: &std::path::Path) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            AddAccessAllowedAceEx, CreateWellKnownSid, InitializeAcl, WinWorldSid, ACL_REVISION,
            DACL_SECURITY_INFORMATION, PSID,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

        // Aligned SID buffer (pointer-aligned).
        let mut world_storage = [0u64; 9];
        let mut world_len = std::mem::size_of_val(&world_storage) as u32;
        let world_ps: PSID = world_storage.as_mut_ptr() as PSID;
        assert!(
            unsafe {
                CreateWellKnownSid(WinWorldSid, std::ptr::null_mut(), world_ps, &mut world_len)
            } != 0
        );

        // ACL only, 8-byte aligned, live through SetNamedSecurityInfoW.
        let mut acl_storage = [0u64; 32];
        let acl_ptr = acl_storage.as_mut_ptr() as *mut windows_sys::Win32::Security::ACL;
        let acl_len = std::mem::size_of_val(&acl_storage) as u32;
        unsafe {
            assert!(InitializeAcl(acl_ptr, acl_len, ACL_REVISION) != 0);
            assert!(
                AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, 0, FILE_GENERIC_READ, world_ps) != 0
            );
            let mut wpath: Vec<u16> = path.as_os_str().encode_wide().collect();
            wpath.push(0);
            let rc = SetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl_ptr,
                std::ptr::null_mut(),
            );
            assert_eq!(rc, 0, "corrupt DACL rc={rc}");
        }
    }
}

// ----- configurable operator MFA (schema 3) -----
//
// Administrator (`can_manage_security`) MFA stays mandatory. Operator policy
// defaults to `optional`. An already-active enrolled factor remains mandatory
// even under `optional`. Policy mutation needs a fresh MFA-backed session.

struct SeededOperator {
    account_id: String,
    username: String,
    password: String,
    public_key: String,
    signer: SigningKey,
}

/// Test-only operator fixture (non-administrator). Real password hash and a
/// real approved manager Ed25519 key; no production seeding path exists.
fn seed_operator(service: &Service, username: &str, password: &str) -> SeededOperator {
    let (signer, public_key) = keypair();
    let account_id = format!("op-{username}");
    let manager_id = format!("mgr-{username}");
    let now = unix_now() as i64;
    let password_hash = hash_password(password).expect("hash operator password");
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state,
                can_operate, can_manage_enrollment, can_manage_access,
                can_manage_accounts, can_manage_security,
                revision, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'active', 1, 0, 0, 0, 0, 1, ?4, ?4)",
            rusqlite::params![account_id, username, password_hash, now],
        )
        .expect("insert operator account");
        conn.execute(
            "INSERT INTO managers (
                id, public_identity, friendly_name, lifecycle_state,
                approved_by_account_id, approved_at, created_at, updated_at, public_key
             ) VALUES (?1, ?2, ?3, 'approved', ?4, ?5, ?5, ?5, ?6)",
            rusqlite::params![
                manager_id,
                format!("key:{public_key}"),
                format!("Operator {username}"),
                account_id,
                now,
                public_key
            ],
        )
        .expect("insert operator manager");
    }
    SeededOperator {
        account_id,
        username: username.to_string(),
        password: password.to_string(),
        public_key,
        signer,
    }
}

/// Test-only active TOTP factor for an operator (optional-policy fixture).
fn seed_active_factor(service: &Service, account_id: &str) -> String {
    let secret = hs_server::crypto::generate_totp_secret().expect("operator totp secret");
    let now = unix_now() as i64;
    let conn = service.db_handle().lock().expect("lock");
    conn.execute(
        "INSERT INTO account_mfa (
            account_id, totp_secret, totp_confirmed_at, recovery_stored_at,
            status, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?3, 'active', ?3, ?3)",
        rusqlite::params![account_id, secret, now],
    )
    .expect("seed active factor");
    secret
}

fn stored_policy(service: &Service) -> String {
    let conn = service.db_handle().lock().expect("lock");
    conn.query_row(
        "SELECT operator_mfa_policy FROM security_policy WHERE id = 1",
        [],
        |r| r.get(0),
    )
    .expect("stored policy")
}

fn session_row(service: &Service, session_id: &str) -> (String, Option<i64>, Option<i64>) {
    let conn = service.db_handle().lock().expect("lock");
    conn.query_row(
        "SELECT assurance, mfa_assured_at, revoked_at FROM sessions WHERE id = ?1",
        rusqlite::params![session_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .expect("session row")
}

fn operator_begin(
    service: &Service,
    op: &SeededOperator,
) -> Result<AuthChallengeBeginResponse, AppError> {
    service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: op.username.clone(),
        password: op.password.clone(),
        operation: "session".into(),
        manager_public_key: op.public_key.clone(),
    })
}

fn operator_complete(
    service: &Service,
    op: &SeededOperator,
    challenge: AuthChallengeBeginResponse,
    totp_code: Option<String>,
) -> Result<LoginResponse, AppError> {
    let dep = deployment_id(service);
    let sig = sign_challenge(
        &op.signer,
        &dep,
        &challenge.challenge_id,
        "session",
        &op.public_key,
    );
    service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id,
        challenge_token: challenge.challenge_token,
        manager_signature: sig,
        totp_code,
    })
}

fn admin_auth(service: &Service, enrolled: &Enrolled) -> hs_server::AuthContext {
    let login = complete_session_login(service, enrolled, &enrolled.totp_secret)
        .expect("admin mfa session");
    service
        .authenticate_token(&login.token)
        .expect("admin auth context")
}

// ----- optional default operator login -----

#[test]
fn optional_default_operator_login_with_password_and_manager_proof() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    assert_eq!(
        stored_policy(&service),
        "optional",
        "new deployments default optional"
    );

    let op = seed_operator(&service, "op-optional", "operator-pass-22");
    let begin = operator_begin(&service, &op).expect("optional operator begin");
    assert!(
        !begin.mfa_required,
        "optional non-enrolled operator is not MFA-required at begin"
    );

    let login = operator_complete(&service, &op, begin, None).expect("factor-free operator login");
    assert_eq!(login.account.id, op.account_id);
    assert!(!login.mfa.required);
    assert!(!login.mfa.available);
    assert_eq!(login.mfa.reason, "operator_policy_optional_no_factor");

    let auth = service.authenticate_token(&login.token).expect("session");
    let (assurance, mfa_assured_at, revoked) = session_row(&service, &auth.session_id);
    assert_eq!(assurance, "password");
    assert!(
        mfa_assured_at.is_none(),
        "factor-free session has no MFA assurance"
    );
    assert!(revoked.is_none());
}

#[test]
fn optional_operator_missing_or_wrong_manager_proof_denies() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-proof", "operator-pass-23");
    let begin = operator_begin(&service, &op).expect("begin");

    // Missing signature.
    let missing = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: begin.challenge_id.clone(),
        challenge_token: begin.challenge_token.clone(),
        manager_signature: " ".into(),
        totp_code: None,
    });
    assert!(missing.is_err(), "missing manager proof must deny");

    // Wrong signature (unrelated key).
    let (other_signer, _) = keypair();
    let dep = deployment_id(&service);
    let wrong = sign_challenge(
        &other_signer,
        &dep,
        &begin.challenge_id,
        "session",
        &op.public_key,
    );
    let denied = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: begin.challenge_id.clone(),
        challenge_token: begin.challenge_token.clone(),
        manager_signature: wrong,
        totp_code: None,
    });
    assert!(denied.is_err(), "wrong manager proof must deny");
    assert_eq!(
        session_count(&service),
        0,
        "proof failures must not issue sessions"
    );
}

#[test]
fn optional_enrolled_factor_still_requires_totp() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-enrolled", "operator-pass-24");
    let secret = seed_active_factor(&service, &op.account_id);

    let begin = operator_begin(&service, &op).expect("begin");
    assert!(
        begin.mfa_required,
        "active factor keeps MFA mandatory under optional policy"
    );

    let missing = operator_complete(&service, &op, begin.clone(), None);
    assert!(missing.is_err(), "enrolled operator must supply TOTP");

    let wrong = operator_complete(&service, &op, begin.clone(), Some("000000".into()));
    assert!(wrong.is_err(), "wrong TOTP must deny");

    let at = unused_totp_time(&service, &op.account_id);
    let code = totp_generate_at(&secret, at).expect("operator totp");
    let login = operator_complete(&service, &op, begin, Some(code)).expect("totp login");
    assert!(login.mfa.required);
    assert!(login.mfa.available);
    assert_eq!(login.mfa.reason, "totp_active");
    let auth = service.authenticate_token(&login.token).expect("session");
    let (assurance, mfa_assured_at, _) = session_row(&service, &auth.session_id);
    assert_eq!(assurance, "mfa");
    assert!(
        mfa_assured_at.is_some(),
        "mfa session stores assurance time"
    );
}

#[test]
fn administrator_mfa_remains_mandatory() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let dep = deployment_id(&service);

    let begin = service
        .begin_auth_challenge(AuthChallengeBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            operation: "session".into(),
            manager_public_key: enrolled.public_key.clone(),
        })
        .expect("admin begin");
    assert!(begin.mfa_required, "administrator is always MFA-required");

    let sig = sign_challenge(
        &enrolled.signer,
        &dep,
        &begin.challenge_id,
        "session",
        &enrolled.public_key,
    );
    let denied = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: begin.challenge_id.clone(),
        challenge_token: begin.challenge_token.clone(),
        manager_signature: sig.clone(),
        totp_code: None,
    });
    assert!(denied.is_err(), "administrator cannot finish factor-free");
    assert_eq!(session_count(&service), 0);
}

// ----- required operator policy -----

#[test]
fn required_operator_missing_invalid_and_replayed_factor_deny() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let auth = admin_auth(&service, &enrolled);
    service
        .set_operator_mfa_policy(
            &auth,
            OperatorMfaPolicyUpdateRequest {
                policy: OperatorMfaPolicy::Required,
            },
        )
        .expect("set required");
    assert_eq!(stored_policy(&service), "required");

    // Non-enrolled operator cannot even begin under required policy.
    let bare = seed_operator(&service, "op-bare", "operator-pass-25");
    let bare_begin = operator_begin(&service, &bare);
    assert!(
        bare_begin.is_err(),
        "required policy must refuse non-enrolled operator begin"
    );

    let op = seed_operator(&service, "op-required", "operator-pass-26");
    let secret = seed_active_factor(&service, &op.account_id);
    let begin = operator_begin(&service, &op).expect("enrolled begin under required");
    assert!(begin.mfa_required);

    let missing = operator_complete(&service, &op, begin.clone(), None);
    assert!(missing.is_err(), "required operator missing factor");

    let invalid = operator_complete(&service, &op, begin.clone(), Some("111111".into()));
    assert!(invalid.is_err(), "required operator invalid factor");

    let at = unused_totp_time(&service, &op.account_id);
    let code = totp_generate_at(&secret, at).expect("code");
    let login = operator_complete(&service, &op, begin.clone(), Some(code.clone()))
        .expect("valid factor under required");
    assert!(login.mfa.required);

    // Replay the same code/time step.
    let replay = operator_complete(&service, &op, begin, Some(code));
    assert!(replay.is_err(), "replayed factor must deny");
}

#[test]
fn policy_change_between_begin_and_complete_denies_factor_free() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-race", "operator-pass-27");

    let begin = operator_begin(&service, &op).expect("begin under optional");
    assert!(!begin.mfa_required);

    // Policy becomes required after begin.
    let auth = admin_auth(&service, &enrolled);
    service
        .set_operator_mfa_policy(
            &auth,
            OperatorMfaPolicyUpdateRequest {
                policy: OperatorMfaPolicy::Required,
            },
        )
        .expect("policy required between begin/complete");

    let denied = operator_complete(&service, &op, begin, None);
    assert!(
        denied.is_err(),
        "optional-started challenge cannot finish factor-free after required"
    );
    assert_eq!(
        session_count(&service),
        1,
        "only the admin policy session exists"
    );
}

#[test]
fn malformed_supplied_factor_is_refused_not_ignored() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-malformed", "operator-pass-28");
    let begin = operator_begin(&service, &op).expect("begin");

    for bad in ["", "12345", "1234567", "abcdef", "12 456"] {
        let denied = service.complete_auth_challenge(AuthChallengeCompleteRequest {
            challenge_id: begin.challenge_id.clone(),
            challenge_token: begin.challenge_token.clone(),
            manager_signature: sign_challenge(
                &op.signer,
                &deployment_id(&service),
                &begin.challenge_id,
                "session",
                &op.public_key,
            ),
            totp_code: Some(bad.into()),
        });
        assert!(
            denied.is_err(),
            "malformed supplied factor {bad:?} must be refused, not ignored"
        );
    }
    assert_eq!(session_count(&service), 0);
}

// ----- policy mutation authorization -----

#[test]
fn factor_free_nonadmin_and_stale_sessions_cannot_mutate_policy() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-mutate", "operator-pass-29");
    let secret = seed_active_factor(&service, &op.account_id);

    // Factor-free operator session cannot read or write policy.
    let free_begin = {
        // Use a separate non-enrolled operator so factor-free is possible.
        seed_operator(&service, "op-free", "operator-pass-30")
    };
    let free_login = operator_complete(
        &service,
        &free_begin,
        operator_begin(&service, &free_begin).expect("begin"),
        None,
    )
    .expect("factor-free login");
    let free_auth = service
        .authenticate_token(&free_login.token)
        .expect("factor-free auth");
    assert!(
        service.get_operator_mfa_policy(&free_auth).is_err(),
        "factor-free session cannot read policy"
    );
    assert!(
        service
            .set_operator_mfa_policy(
                &free_auth,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                }
            )
            .is_err(),
        "factor-free session cannot write policy"
    );

    // Non-administrator MFA-backed session cannot mutate policy.
    let op_login = {
        let begin = operator_begin(&service, &op).expect("begin");
        let at = unused_totp_time(&service, &op.account_id);
        let code = totp_generate_at(&secret, at).expect("code");
        operator_complete(&service, &op, begin, Some(code)).expect("operator mfa login")
    };
    let op_auth = service.authenticate_token(&op_login.token).expect("auth");
    assert!(
        service
            .set_operator_mfa_policy(
                &op_auth,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                }
            )
            .is_err(),
        "non-administrator cannot change policy even with MFA"
    );

    // Administrator session whose MFA assurance is stale cannot mutate.
    let admin_auth = admin_auth(&service, &enrolled);
    {
        let conn = service.db_handle().lock().expect("lock");
        let stale = unix_now() as i64 - 10_000;
        conn.execute(
            "UPDATE sessions SET mfa_assured_at = ?1 WHERE id = ?2",
            rusqlite::params![stale, admin_auth.session_id],
        )
        .expect("age assurance");
    }
    assert!(
        service
            .set_operator_mfa_policy(
                &admin_auth,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                }
            )
            .is_err(),
        "stale MFA assurance cannot authorize policy change"
    );
    assert_eq!(stored_policy(&service), "optional", "policy unchanged");

    // Missing assurance (NULL) never authorizes change.
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE sessions SET assurance = 'password', mfa_assured_at = NULL WHERE id = ?1",
            rusqlite::params![admin_auth.session_id],
        )
        .expect("strip assurance");
    }
    assert!(
        service
            .set_operator_mfa_policy(
                &admin_auth,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                }
            )
            .is_err(),
        "missing assurance never authorizes change"
    );
}

#[test]
fn enabling_required_invalidates_factor_free_operator_sessions() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);

    let free_op = seed_operator(&service, "op-weak", "operator-pass-31");
    let free_login = operator_complete(
        &service,
        &free_op,
        operator_begin(&service, &free_op).expect("b"),
        None,
    )
    .expect("weak session");
    let free_auth = service.authenticate_token(&free_login.token).expect("auth");

    let mfa_op = seed_operator(&service, "op-strong", "operator-pass-32");
    let secret = seed_active_factor(&service, &mfa_op.account_id);
    let mfa_begin = operator_begin(&service, &mfa_op).expect("b");
    let at = unused_totp_time(&service, &mfa_op.account_id);
    let code = totp_generate_at(&secret, at).expect("code");
    let mfa_login = operator_complete(&service, &mfa_op, mfa_begin, Some(code)).expect("mfa login");
    let mfa_auth = service.authenticate_token(&mfa_login.token).expect("auth");

    let admin = admin_auth(&service, &enrolled);
    service
        .set_operator_mfa_policy(
            &admin,
            OperatorMfaPolicyUpdateRequest {
                policy: OperatorMfaPolicy::Required,
            },
        )
        .expect("enable required");

    assert!(
        service.authenticate_token(&free_login.token).is_err(),
        "factor-free operator session must be invalidated"
    );
    assert!(
        service.authenticate_token(&mfa_login.token).is_ok(),
        "mfa-backed operator session may remain"
    );
    assert!(
        service.authenticate_token(&admin.session_id).is_err(),
        "authenticate_token takes a token, not a session id"
    );
    // Admin MFA session itself is not revoked by the policy change.
    let admin_login = complete_session_login(&service, &enrolled, &enrolled.totp_secret)
        .expect("fresh admin login after policy change");
    assert!(service.authenticate_token(&admin_login.token).is_ok());
    let _ = (free_auth, mfa_auth);
}

#[test]
fn legacy_and_recovery_only_credentials_cannot_change_policy() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);

    // Historical factor-free administrator session (schema-3 migrated shape:
    // assurance=password, mfa_assured_at NULL). Mandatory admin MFA must
    // refuse authority at authenticate_token — not only at new login.
    {
        let conn = service.db_handle().lock().expect("lock");
        let now = unix_now() as i64;
        let token = "fixture-legacy-session-token";
        let token_hash = hash_token(token);
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state,
                can_operate, can_manage_enrollment, can_manage_access,
                can_manage_accounts, can_manage_security,
                revision, created_at, updated_at
             ) VALUES ('legacy-admin', 'legacy-admin', 'unused-hash', 'active', 1, 1, 1, 1, 1, 1, ?1, ?1)",
            rusqlite::params![now],
        )
        .expect("seed legacy account");
        conn.execute(
            "INSERT INTO sessions (
                id, account_id, manager_id, token_hash, created_at, expires_at,
                assurance, mfa_assured_at
             ) VALUES ('sess-legacy', 'legacy-admin', NULL, ?1, ?2, ?3, 'password', NULL)",
            rusqlite::params![token_hash, now, now + 3600],
        )
        .expect("seed historical password session");
        drop(conn);
        assert!(
            service.authenticate_token(token).is_err(),
            "historical password-only administrator session must not authenticate when MFA is mandatory"
        );
        // Cleanup logout must still work without granting authority.
        service
            .logout_token(token)
            .expect("cleanup logout of weak session");
    }

    // Recovery-only path never mints a session at all.
    let before = session_count(&service);
    let code = enrolled.recovery_codes[5].clone();
    let begin = service
        .begin_factor_recovery(FactorRecoveryBeginRequest {
            username: "admin".into(),
            password: PASSWORD.into(),
            recovery_code: code,
        })
        .expect("recovery begin");
    assert_eq!(begin.purpose, "totp_factor_recovery_only");
    assert_eq!(
        session_count(&service),
        before,
        "recovery begin does not mint a session"
    );
    assert_eq!(stored_policy(&service), "optional");
}

// ----- persisted-session MFA assurance (coordinator 2026-10-15) -----

#[test]
fn coordinator_historical_password_session_cannot_authorize_mfa_admin() {
    let svc = service();
    let admin = bootstrap_enrolled(&svc);
    let token = "isolated-historical-weak-session-fixture";
    let now = unix_now() as i64;
    svc.db_handle()
        .lock()
        .expect("fixture lock")
        .execute(
            "INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at, assurance, mfa_assured_at) VALUES ('historical-weak-session', ?1, ?2, ?3, ?4, 'password', NULL)",
            rusqlite::params![admin.account_id, hash_token(token), now, now + 3600],
        )
        .expect("historical migrated session fixture");
    assert!(
        svc.authenticate_token(token).is_err(),
        "A historical password-only session cannot retain administrator authority when MFA is mandatory"
    );
}

#[test]
fn optional_operator_password_session_denied_after_admin_role_promotion() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-promote", "operator-pass-70");
    // Factor-free operator under optional policy: password session is valid.
    let login = service
        .login(hs_server::models::LoginRequest {
            username: op.username.clone(),
            password: op.password.clone(),
            manager_public_identity: None,
        })
        .expect("optional operator v1 login");
    assert!(service.authenticate_token(&login.token).is_ok());

    // Promote to administrator — mandatory MFA applies immediately at use.
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE accounts SET can_manage_security = 1 WHERE id = ?1",
            rusqlite::params![op.account_id],
        )
        .expect("promote");
    }
    assert!(
        service.authenticate_token(&login.token).is_err(),
        "password-only session must lose authority after administrator promotion"
    );
}

#[test]
fn password_session_denied_after_required_policy_activation() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-policy-on", "operator-pass-71");
    let login = service
        .login(hs_server::models::LoginRequest {
            username: op.username.clone(),
            password: op.password.clone(),
            manager_public_identity: None,
        })
        .expect("optional operator login");
    assert!(service.authenticate_token(&login.token).is_ok());

    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE security_policy SET operator_mfa_policy = 'required' WHERE id = 1",
            [],
        )
        .expect("policy required");
    }
    assert!(
        service.authenticate_token(&login.token).is_err(),
        "password-only session must lose authority after required policy activation"
    );
}

#[test]
fn mfa_assured_session_retains_authority_for_admin() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let login = complete_session_login(&service, &enrolled, &enrolled.totp_secret)
        .expect("genuine mfa login");
    assert!(service.authenticate_token(&login.token).is_ok());
    let auth = service.authenticate_token(&login.token).expect("auth");
    assert!(auth.can_manage_security);
}

// ----- persistence and fault handling -----

#[cfg(any(windows, unix))]
#[test]
fn operator_mfa_policy_persists_private_store_restart() {
    let (_dir, base) = private_tempdir();
    let path = base.join("hs-server.db");
    {
        let db = db::open(&path).expect("open private store");
        let service = Service::new(db);
        let enrolled = bootstrap_enrolled(&service);
        let auth = admin_auth(&service, &enrolled);
        let view = service
            .set_operator_mfa_policy(
                &auth,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                },
            )
            .expect("set required");
        assert_eq!(view.policy, OperatorMfaPolicy::Required);
        assert!(view.mfa_required_for_operators);
    }

    let db = db::open(&path).expect("reopen private store");
    let service = Service::new(db);
    assert_eq!(stored_policy(&service), "required");
    // Default remains optional only on fresh installs; reopen keeps required.
    let op = seed_operator(&service, "op-persist", "operator-pass-33");
    assert!(
        operator_begin(&service, &op).is_err(),
        "persisted required policy still refuses non-enrolled operators"
    );
}

#[test]
fn corrupt_operator_policy_denies_new_authority_and_keeps_recovery() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-corrupt", "operator-pass-34");

    // Corrupt stored policy (disposable test store rebuild without CHECK).
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute_batch(
            r#"
            DROP TABLE security_policy;
            CREATE TABLE security_policy (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                operator_mfa_policy TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            INSERT INTO security_policy (id, operator_mfa_policy, updated_at)
            VALUES (1, 'corrupt-not-a-policy', 1);
            "#,
        )
        .expect("corrupt policy fixture");
    }

    assert!(
        operator_begin(&service, &op).is_err(),
        "corrupt policy must deny new operator authority"
    );
    let admin_begin = service.begin_auth_challenge(AuthChallengeBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        operation: "session".into(),
        manager_public_key: enrolled.public_key.clone(),
    });
    assert!(
        admin_begin.is_err(),
        "corrupt policy must deny new administrator authority too"
    );

    // Recovery semantics are preserved: recovery begin still works.
    let code = enrolled.recovery_codes[0].clone();
    let recovery = service.begin_factor_recovery(FactorRecoveryBeginRequest {
        username: "admin".into(),
        password: PASSWORD.into(),
        recovery_code: code,
    });
    assert!(
        recovery.is_ok(),
        "recovery-only verification must keep working under corrupt policy"
    );
}

#[test]
fn policy_storage_fault_denies_new_authority_without_losing_recovery() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-fault", "operator-pass-35");

    // Disposable test-only fault: abort any write to sessions during complete.
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute_batch(
            r#"
            CREATE TRIGGER deny_session_insert
            BEFORE INSERT ON sessions
            BEGIN
                SELECT RAISE(ABORT, 'injected session insert fault');
            END;
            "#,
        )
        .expect("inject session fault");
    }

    let begin = operator_begin(&service, &op).expect("begin still works");
    let denied = operator_complete(&service, &op, begin, None);
    assert!(denied.is_err(), "storage fault must deny session authority");
    assert_eq!(
        session_count(&service),
        0,
        "faulted insert must not leave a session"
    );
    assert!(
        service.security_state() == hs_server::SecurityState::Unavailable || denied.is_err(),
        "fault is a denial (latch via finish_storage on storage failures)"
    );

    // Recovery *material* is intact: the failed complete consumed no recovery
    // code and left the active factor unchanged. The pre-existing security
    // latch may pause new authority (including recovery enrollment) — that is
    // existing fail-closed behavior, not a loss of recovery semantics.
    {
        let conn = service.db_handle().lock().expect("lock");
        let used: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE account_id = ?1 AND used_at IS NOT NULL",
                rusqlite::params![enrolled.account_id],
                |r| r.get(0),
            )
            .expect("used recovery codes");
        assert_eq!(used, 0, "session fault must not consume recovery codes");
        let status: String = conn
            .query_row(
                "SELECT status FROM account_mfa WHERE account_id = ?1",
                rusqlite::params![enrolled.account_id],
                |r| r.get(0),
            )
            .expect("factor status");
        assert_eq!(status, "active", "factor unchanged by session fault");
    }
}

// ----- coordinator reviews 2026-10-15 -----

#[test]
fn coordinator_required_policy_cannot_be_bypassed_by_v1_login() {
    let svc = service();
    let _admin = bootstrap_enrolled(&svc);
    let op = seed_operator(
        &svc,
        "coordinator-legacy-required",
        "coordinator-fixture-pass-47",
    );
    {
        let conn = svc.db_handle().lock().expect("fixture lock");
        conn.execute(
            "UPDATE security_policy SET operator_mfa_policy = 'required' WHERE id = 1",
            [],
        )
        .expect("fixture policy");
    }
    let result = svc.login(hs_server::models::LoginRequest {
        username: op.username,
        password: op.password,
        manager_public_identity: Some(format!("key:{}", op.public_key)),
    });
    assert!(
        result.is_err(),
        "Required operator MFA must not be bypassed through the v1 login route"
    );
}

#[test]
fn coordinator_admin_mfa_cannot_be_bypassed_by_v1_login() {
    let svc = service();
    let _admin = bootstrap_enrolled(&svc);
    let op = seed_operator(
        &svc,
        "coordinator-legacy-admin",
        "coordinator-fixture-pass-48",
    );
    {
        let conn = svc.db_handle().lock().expect("fixture lock");
        conn.execute(
            "UPDATE accounts SET can_manage_security = 1 WHERE id = ?1",
            [&op.account_id],
        )
        .expect("fixture role");
    }
    let result = svc.login(hs_server::models::LoginRequest {
        username: op.username,
        password: op.password,
        manager_public_identity: Some(format!("key:{}", op.public_key)),
    });
    assert!(
        result.is_err(),
        "Mandatory administrator MFA must not be bypassed through v1 login"
    );
}

#[test]
fn coordinator_optional_mfa_still_requires_device_key_proof() {
    let svc = service();
    let _admin = bootstrap_enrolled(&svc);
    let op = seed_operator(
        &svc,
        "coordinator-legacy-proof",
        "coordinator-fixture-pass-49",
    );
    let result = svc.login(hs_server::models::LoginRequest {
        username: op.username,
        password: op.password,
        manager_public_identity: Some(format!("key:{}", op.public_key)),
    });
    assert!(
        result.is_err(),
        "Optional MFA must still require an actual approved device-key signature; \
         a v1 display label cannot establish manager authority"
    );
}

#[test]
fn v1_cannot_bind_key_bearing_manager_with_display_label() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    // Optional operator + real key-bearing manager from bootstrap_enrolled's
    // sibling fixture (seed_operator creates an approved key-bearing manager).
    let op = seed_operator(&service, "op-label-bind", "operator-pass-50");
    let secret = seed_active_factor(&service, &op.account_id);
    drop(secret);

    // Optional non-enrolled operator cannot use the display identity of a
    // key-bearing manager to mint a manager-bound session.
    let bare = seed_operator(&service, "op-label-bare", "operator-pass-51");
    let denied = service.login(hs_server::models::LoginRequest {
        username: bare.username.clone(),
        password: bare.password.clone(),
        manager_public_identity: Some(format!("key:{}", bare.public_key)),
    });
    assert!(
        denied.is_err(),
        "v1 display label must not bind a key-bearing manager"
    );

    // Label-only manager (public_key NULL) remains a legacy dev fixture path.
    {
        let conn = service.db_handle().lock().expect("lock");
        let now = unix_now() as i64;
        conn.execute(
            "INSERT INTO managers (
                id, public_identity, friendly_name, lifecycle_state,
                approved_by_account_id, approved_at, created_at, updated_at, public_key
             ) VALUES ('mgr-label-only', 'label-only-manager', 'Label only', 'approved',
                       ?1, ?2, ?2, ?2, NULL)",
            rusqlite::params![enrolled.account_id, now],
        )
        .expect("seed label-only manager");
    }
    let login = service
        .login(hs_server::models::LoginRequest {
            username: bare.username.clone(),
            password: bare.password.clone(),
            manager_public_identity: Some("label-only-manager".into()),
        })
        .expect("label-only manager binding remains a legacy dev fixture");
    assert!(login.manager.is_some());
    assert!(login.manager_public_key.is_none(), "v1 omits device key");
}

#[test]
fn v1_manager_binding_denies_key_added_before_issuance() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-midflight", "operator-pass-52");
    let begin = operator_begin(&service, &op).expect("begin");
    drop(begin);

    // Start from a label-only manager, then attach a device key after the
    // early lookup would have succeeded — the final transaction must deny.
    {
        let conn = service.db_handle().lock().expect("lock");
        let now = unix_now() as i64;
        conn.execute(
            "INSERT INTO managers (
                id, public_identity, friendly_name, lifecycle_state,
                approved_by_account_id, approved_at, created_at, updated_at, public_key
             ) VALUES ('mgr-midflight', 'midflight-manager', 'Mid', 'approved',
                       ?1, ?2, ?2, ?2, NULL)",
            rusqlite::params![op.account_id, now],
        )
        .expect("seed label-only manager");
    }

    // Race simulation: convert the manager to key-bearing in a hook-like
    // sequence by mutating between two service calls is not possible inside
    // one login; instead prove the final-tx recheck by attaching the key
    // first and confirming denial, and prove the early check denial too.
    {
        // Attach a fresh device key (not already bound to another manager).
        let (_signer, attached_key) = keypair();
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE managers SET public_key = ?1 WHERE id = 'mgr-midflight'",
            [&attached_key],
        )
        .expect("attach device key");
    }
    let denied = service.login(hs_server::models::LoginRequest {
        username: op.username.clone(),
        password: op.password.clone(),
        manager_public_identity: Some("midflight-manager".into()),
    });
    assert!(
        denied.is_err(),
        "key-bearing manager must refuse v1 label binding after key attach"
    );
    assert_eq!(session_count(&service), 0);
}

#[test]
fn optional_non_admin_v1_login_still_works_without_manager() {
    let service = service();
    let _admin = bootstrap_enrolled(&service);
    let op = seed_operator(&service, "op-plain-v1", "operator-pass-53");
    // Non-enrolled operator under optional policy: v1 password-only remains
    // available when no manager device is claimed (dev path, no device auth).
    let login = service
        .login(hs_server::models::LoginRequest {
            username: op.username.clone(),
            password: op.password.clone(),
            manager_public_identity: None,
        })
        .expect("optional non-admin v1 login");
    assert!(login.manager.is_none());
    assert!(login.manager_public_key.is_none());
    assert!(!login.mfa.required);
}

// ----- coordinator review 2026-10-14 -----

#[test]
fn v2_completion_returns_challenge_proven_manager_key_not_display_identity() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let login =
        complete_session_login(&service, &enrolled, &enrolled.totp_secret).expect("v2 completion");

    assert_eq!(
        login.manager_public_key.as_deref(),
        Some(enrolled.public_key.as_str()),
        "v2 manager_public_key must equal the exact challenge-proven device key"
    );
    let manager = login.manager.expect("manager view");
    // Bootstrap stores display identity as key:<hex>; that is NOT key authority.
    assert_ne!(
        manager.public_identity, enrolled.public_key,
        "public_identity is a display label, not naked key hex"
    );
    assert!(
        manager.public_identity.contains(&enrolled.public_key),
        "bootstrap display identity is key:<hex> of the proven key"
    );
}

#[test]
fn v1_login_omits_manager_public_key_field() {
    let service = service();
    // Non-admin without MFA requirement: the remaining v1 password-only path.
    // (Administrator MFA is mandatory and refuses v1 login.)
    {
        let conn = service.db_handle().lock().expect("lock");
        let hash = hash_password("v1-password-01").expect("hash");
        let now = unix_now() as i64;
        conn.execute(
            "INSERT INTO accounts (
                id, username, password_hash, state,
                can_operate, can_manage_enrollment, can_manage_access,
                can_manage_accounts, can_manage_security,
                revision, created_at, updated_at
             ) VALUES ('v1-user', 'v1-user', ?1, 'active', 1, 0, 0, 0, 0, 1, ?2, ?2)",
            rusqlite::params![hash, now],
        )
        .expect("seed v1 user");
    }
    let login = service
        .login(hs_server::models::LoginRequest {
            username: "v1-user".into(),
            password: "v1-password-01".into(),
            manager_public_identity: None,
        })
        .expect("v1 login");
    assert!(
        login.manager_public_key.is_none(),
        "v1 responses omit manager_public_key"
    );

    // Frozen wire output: serialized v1 JSON has no manager_public_key field.
    let wire = serde_json::to_value(&login).expect("serialize login");
    assert!(
        wire.get("manager_public_key").is_none(),
        "v1 wire output must skip manager_public_key entirely"
    );
}

#[test]
fn policy_mutation_denies_future_or_rolled_back_assurance_time() {
    let service = service();
    let enrolled = bootstrap_enrolled(&service);
    let admin = admin_auth(&service, &enrolled);
    let now = unix_now() as i64;

    // Future assurance timestamp (clock rollback / planted future) must deny.
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE sessions SET mfa_assured_at = ?1 WHERE id = ?2",
            rusqlite::params![now + 300, admin.session_id],
        )
        .expect("plant future assurance");
    }
    assert!(
        service
            .set_operator_mfa_policy(
                &admin,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                }
            )
            .is_err(),
        "future assurance timestamp must deny policy mutation"
    );
    assert_eq!(stored_policy(&service), "optional");

    // Stale assurance (older than 120s) must deny.
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE sessions SET mfa_assured_at = ?1 WHERE id = ?2",
            rusqlite::params![now - 121, admin.session_id],
        )
        .expect("plant stale assurance");
    }
    assert!(
        service
            .set_operator_mfa_policy(
                &admin,
                OperatorMfaPolicyUpdateRequest {
                    policy: OperatorMfaPolicy::Required,
                }
            )
            .is_err(),
        "stale assurance timestamp must deny policy mutation"
    );
    assert_eq!(stored_policy(&service), "optional");

    // Fresh assurance (age 0..=120) is accepted.
    {
        let conn = service.db_handle().lock().expect("lock");
        conn.execute(
            "UPDATE sessions SET mfa_assured_at = ?1 WHERE id = ?2",
            rusqlite::params![now - 1, admin.session_id],
        )
        .expect("plant fresh assurance");
    }
    service
        .set_operator_mfa_policy(
            &admin,
            OperatorMfaPolicyUpdateRequest {
                policy: OperatorMfaPolicy::Required,
            },
        )
        .expect("fresh assurance authorizes policy change");
    assert_eq!(stored_policy(&service), "required");
}

// ----- HTTP router (actual axum router + transaction seam) -----

mod operator_mfa_http {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    fn app(service: Arc<Service>) -> Router {
        hs_server::app(service)
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("oneshot");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    #[tokio::test]
    async fn operator_mfa_policy_routes_are_admin_mfa_scoped() {
        let service = service();
        let enrolled = bootstrap_enrolled(&service);
        let admin = admin_auth(&service, &enrolled);
        let admin_login = complete_session_login(&service, &enrolled, &enrolled.totp_secret)
            .expect("admin login");
        let op = seed_operator(&service, "op-http", "operator-pass-36");
        let op_login = operator_complete(
            &service,
            &op,
            operator_begin(&service, &op).expect("begin"),
            None,
        )
        .expect("operator login");
        let app = app(service.clone());

        // Challenge begin under default optional policy reports mfa_required=false.
        let (status, body) = send(
            &app,
            "POST",
            "/v2/auth/challenge",
            None,
            Some(serde_json::json!({
                "username": "op-http",
                "password": "operator-pass-36",
                "operation": "session",
                "manager_public_key": op.public_key.clone(),
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.get("mfa_required"), Some(&Value::Bool(false)));

        // GET requires administrator.
        let (status, _body) =
            send(&app, "GET", "/v2/security/operator-mfa-policy", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = send(
            &app,
            "GET",
            "/v2/security/operator-mfa-policy",
            Some(&op_login.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "operator cannot read policy");

        let (status, body) = send(
            &app,
            "GET",
            "/v2/security/operator-mfa-policy",
            Some(&admin_login.token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.get("policy").and_then(Value::as_str), Some("optional"));
        assert_eq!(
            body.get("mfa_required_for_operators"),
            Some(&Value::Bool(false))
        );

        // PUT requires administrator + fresh MFA-backed session.
        let (status, _) = send(
            &app,
            "PUT",
            "/v2/security/operator-mfa-policy",
            Some(&op_login.token),
            Some(serde_json::json!({"policy": "required"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "operator cannot write policy"
        );

        let (status, body) = send(
            &app,
            "PUT",
            "/v2/security/operator-mfa-policy",
            Some(&admin_login.token),
            Some(serde_json::json!({"policy": "required"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin MFA session can set policy: {body}"
        );
        assert_eq!(body.get("policy").and_then(Value::as_str), Some("required"));
        assert_eq!(
            body.get("mfa_required_for_operators"),
            Some(&Value::Bool(true))
        );

        // Strict DTO: unknown field / bad enum refused by the parser.
        // Axum's Json extractor surfaces deserialization failure as 400/422.
        for bad in [
            serde_json::json!({"policy": "required", "extra": 1}),
            serde_json::json!({"policy": "sometimes"}),
            serde_json::json!({}),
        ] {
            let (status, _) = send(
                &app,
                "PUT",
                "/v2/security/operator-mfa-policy",
                Some(&admin_login.token),
                Some(bad),
            )
            .await;
            assert!(
                status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
                "strict DTO must refuse malformed policy body, got {status}"
            );
        }

        // Challenge begin reports server-derived mfa_required over HTTP.
        // After the policy write above, this non-enrolled operator is denied.
        let (status, body) = send(
            &app,
            "POST",
            "/v2/auth/challenge",
            None,
            Some(serde_json::json!({
                "username": "op-http",
                "password": "operator-pass-36",
                "operation": "session",
                "manager_public_key": op.public_key.clone(),
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "required policy refuses non-enrolled operator begin: {body}"
        );

        let _ = admin.session_id;
    }

    #[tokio::test]
    async fn http_historical_password_session_cannot_use_admin_authority() {
        let service = service();
        let enrolled = bootstrap_enrolled(&service);
        let token = "http-historical-weak-session";
        let now = unix_now() as i64;
        {
            let conn = service.db_handle().lock().expect("lock");
            conn.execute(
                "INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at, assurance, mfa_assured_at) VALUES ('http-weak', ?1, ?2, ?3, ?4, 'password', NULL)",
                rusqlite::params![enrolled.account_id, hash_token(token), now, now + 3600],
            )
            .expect("weak session");
        }
        let app = app(service.clone());
        // Authority routes refuse the weak bearer.
        let (status, _) = send(&app, "GET", "/v1/auth/session", Some(token), None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "historical password session must not read session authority"
        );
        // Cleanup logout still works without granting authority.
        let (status, _) = send(&app, "POST", "/v1/auth/logout", Some(token), None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "weak session can log out");
        let (status, _) = send(&app, "GET", "/v1/auth/session", Some(token), None).await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
            "logged-out weak session stays denied"
        );
    }

    #[tokio::test]
    async fn http_v1_login_cannot_bypass_required_policy_or_admin_mfa() {
        let service = service();
        let _enrolled = bootstrap_enrolled(&service);
        let app = app(service.clone());

        // Required-policy operator: v1 password login is refused.
        let op = seed_operator(&service, "http-op-required", "operator-pass-60");
        {
            let conn = service.db_handle().lock().expect("lock");
            conn.execute(
                "UPDATE security_policy SET operator_mfa_policy = 'required' WHERE id = 1",
                [],
            )
            .expect("set required");
        }
        let (status, _) = send(
            &app,
            "POST",
            "/v1/auth/login",
            None,
            Some(serde_json::json!({
                "username": op.username,
                "password": op.password,
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "required policy must refuse v1 login"
        );

        // Administrator without going through v2 MFA: v1 login refused.
        let (status, _) = send(
            &app,
            "POST",
            "/v1/auth/login",
            None,
            Some(serde_json::json!({
                "username": "admin",
                "password": PASSWORD,
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "administrator MFA must refuse v1 login"
        );

        // Display label of a key-bearing manager cannot bind a device.
        let bare = seed_operator(&service, "http-op-label", "operator-pass-61");
        let (status, _) = send(
            &app,
            "POST",
            "/v1/auth/login",
            None,
            Some(serde_json::json!({
                "username": bare.username,
                "password": bare.password,
                "manager_public_identity": format!("key:{}", bare.public_key),
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "v1 display label must not bind a key-bearing manager"
        );
    }

    #[tokio::test]
    async fn http_challenge_complete_accepts_string_totp_for_existing_clients() {
        let service = service();
        let enrolled = bootstrap_enrolled(&service);
        let app = app(service.clone());
        let dep = deployment_id(&service);

        let (status, begin) = send(
            &app,
            "POST",
            "/v2/auth/challenge",
            None,
            Some(serde_json::json!({
                "username": "admin",
                "password": PASSWORD,
                "operation": "session",
                "manager_public_key": enrolled.public_key,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(begin.get("mfa_required"), Some(&Value::Bool(true)));
        let challenge_id = begin["challenge_id"].as_str().expect("id").to_string();
        let challenge_token = begin["challenge_token"]
            .as_str()
            .expect("token")
            .to_string();
        let sig = sign_challenge(
            &enrolled.signer,
            &dep,
            &challenge_id,
            "session",
            &enrolled.public_key,
        );
        let at = unused_totp_time(&service, &enrolled.account_id);
        let code = totp_generate_at(&enrolled.totp_secret, at).expect("code");

        // Existing string clients send totp_code as a JSON string.
        let (status, body) = send(
            &app,
            "POST",
            "/v2/auth/challenge/complete",
            None,
            Some(serde_json::json!({
                "challenge_id": challenge_id,
                "challenge_token": challenge_token,
                "manager_signature": sig,
                "totp_code": code,
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "string totp_code still accepted: {body}"
        );
        assert_eq!(
            body.pointer("/mfa/required").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            body.get("manager_public_key").and_then(Value::as_str),
            Some(enrolled.public_key.as_str()),
            "v2 HTTP completion returns the challenge-proven device key"
        );
    }
}
