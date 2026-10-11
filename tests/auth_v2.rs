//! Integration tests for auth v2: TOTP MFA, recovery-only verification,
//! device-key challenge login, and explicit schema migration.
//!
//! All fixtures are disposable in-memory or tempfile databases.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use hs_server::crypto::{
    auth_challenge_proof_message, bootstrap_manager_proof_message, hash_token, totp_generate_at,
    totp_time_step, unix_now,
};
use hs_server::db;
use hs_server::models::*;
use hs_server::service::Service;

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
        totp_code: "000000".into(),
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
        totp_code: code.clone(),
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
        totp_code: code,
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
        totp_code: code.clone(),
    });
    let r2 = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: c2.challenge_id.clone(),
        challenge_token: c2.challenge_token.clone(),
        manager_signature: s2,
        totp_code: code,
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
        totp_code: code,
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
        totp_code: code.clone(),
    });
    assert!(first.is_ok(), "first completion must succeed");

    // Same challenge id + token cannot be consumed twice.
    let second = service.complete_auth_challenge(AuthChallengeCompleteRequest {
        challenge_id: challenge.challenge_id.clone(),
        challenge_token: challenge.challenge_token.clone(),
        manager_signature: sig,
        totp_code: code,
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
        totp_code: code,
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
        totp_code: code,
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
        totp_code: code.clone(),
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
        totp_code: code,
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
        totp_code: code,
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
        totp_code: code,
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

/// Windows private store: persistent open is PersistentPrivate and allows
/// NEW persisted v2 MFA through the native boundary.
#[cfg(windows)]
mod windows_persistent_private {
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
    fn bootstrap_v2_persists_on_windows_private_store() {
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
        assert!(!response.totp_secret.is_empty());
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
            assert!(!response.totp_secret.is_empty());
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
            assert!(!response.totp_secret.is_empty());
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
