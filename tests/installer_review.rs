//! Coordinator checks for the exact review/apply and real CLI boundary.
use ed25519_dalek::{Signer, SigningKey};
use hs_server::installer::adapter::{CommandAdapter, TestAdapter};
use hs_server::installer::{machine, manifest, models::*};
use std::path::{Path, PathBuf};

const PACKAGE_DIR: &str = "/tmp/hs-coordinator-package";

fn reviewed_package() -> (TestAdapter, InstallPlan, PreflightResult, SigningKey) {
    let adapter = TestAdapter::new();
    let package = PathBuf::from(PACKAGE_DIR);
    let signer = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let entries = [
        ("artifacts/hs-server", b"test-binary".as_slice()),
        ("artifacts/hs-server.service", b"test-unit".as_slice()),
    ];
    let package_manifest = PackageManifest {
        format_version: 1,
        product: "hs-server".into(),
        version: "0.1.0".into(),
        platform: "linux-x86_64".into(),
        min_schema_version: 1,
        min_installer_version: "0.1.0".into(),
        artifacts: entries
            .iter()
            .map(|(name, bytes)| ArtifactEntry {
                path: (*name).into(),
                sha256: manifest::sha256_hex(bytes),
                size_bytes: bytes.len() as u64,
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&package_manifest).unwrap();
    {
        let mut fs = adapter.fs.lock().unwrap();
        fs.insert(package.join("manifest.json"), bytes.clone());
        fs.insert(
            package.join("manifest.sig"),
            signer.sign(&bytes).to_bytes().to_vec(),
        );
        for (name, contents) in entries {
            fs.insert(package.join(name), contents.to_vec());
        }
    }
    let preflight = machine::preflight(
        &adapter,
        &PreflightInput {
            contract_version: 1,
            target: PreflightTarget {
                host: "review-fixture".into(),
                port: 22,
            },
        },
    )
    .unwrap();
    let plan = machine::plan(
        &adapter,
        &PlanInput {
            contract_version: 1,
            preflight: preflight.clone(),
            package_dir: package.display().to_string(),
        },
        Some(&signer.verifying_key().to_bytes()),
    )
    .unwrap()
    .plan
    .unwrap();
    (adapter, plan, preflight, signer)
}

fn verify_key_hex(signer: &SigningKey) -> String {
    hex::encode(signer.verifying_key().to_bytes())
}

#[test]
fn reviewed_digest_cannot_authorize_changed_destination() {
    let (adapter, mut plan, preflight, signer) = reviewed_package();
    plan.files[0].destination = "/etc/ssh/sshd_config".into();
    // A caller-controlled digest cannot authorize arbitrary privileged resources.
    plan.review_digest = machine::compute_plan_digest(&plan);
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "a product/version digest does not authorize modified install resources"
    );
    assert!(!adapter
        .fs
        .lock()
        .unwrap()
        .contains_key(Path::new("/etc/ssh/sshd_config")));
}

#[test]
fn missing_package_verification_key_never_allows_apply() {
    let (adapter, plan, preflight, _) = reviewed_package();
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: None,
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "verification cannot be optional on the apply path"
    );
    assert!(
        adapter.commands.lock().unwrap().is_empty(),
        "missing verification anchor must precede mutation"
    );
}

#[test]
fn failed_service_query_cannot_report_host_compatible() {
    let adapter = TestAdapter::new();
    adapter.force_failures.lock().unwrap().insert(
        "query_unit_exists".into(),
        "service query unavailable".into(),
    );
    let result = machine::preflight(
        &adapter,
        &PreflightInput {
            contract_version: 1,
            target: PreflightTarget {
                host: "review-fixture".into(),
                port: 22,
            },
        },
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "unknown service ownership cannot mean no existing service"
    );
}

#[test]
fn unavailable_port_query_never_passes_apply() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    adapter.force_failures.lock().unwrap().insert(
        "query_port_listener".into(),
        "listener query unavailable".into(),
    );
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "failed required listener query cannot mean free ports"
    );
    assert!(
        adapter.commands.lock().unwrap().is_empty(),
        "required preflight failure must precede all mutations"
    );
}

#[test]
fn changed_package_after_review_is_not_executed() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    adapter.fs.lock().unwrap().insert(
        PathBuf::from("/tmp/hs-coordinator-package/artifacts/hs-server"),
        b"tampered-after-review".to_vec(),
    );
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "apply must independently reverify the exact signed package after review"
    );
    assert!(adapter.commands.lock().unwrap().is_empty());
}

#[test]
#[cfg(not(target_os = "linux"))]
fn normal_cli_cannot_report_fixture_linux_host_facts() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut process = Command::new(env!("CARGO_BIN_EXE_hs-server"))
        .args(["installer", "preflight"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"contract_version":1,"target":{"host":"local-review","port":22}}"#)
        .unwrap();
    let output = process.wait_with_output().unwrap();
    assert!(!output.status.success(), "normal installer CLI must refuse unsupported host rather than emit in-memory Ubuntu fixture facts: {}", String::from_utf8_lossy(&output.stdout));
}

// ---------------------------------------------------------------------------
// Journal write-ahead ordering and truthful failure reporting
// ---------------------------------------------------------------------------

#[test]
fn journal_intent_write_failure_precedes_all_mutation() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    // Fail the journal write that must precede the first mutation.
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("write_file".into(), "journal disk full".into());
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "an unwritable journal must fail the apply"
    );
    assert!(
        adapter.commands.lock().unwrap().is_empty(),
        "journal write-ahead failure must precede every mutating command"
    );
}

#[test]
fn journal_resource_intent_precedes_recorded_commands() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    )
    .unwrap();
    assert!(result.ok, "apply must succeed: {:?}", result.errors);

    let journal_bytes = adapter
        .read_file(Path::new("/tmp/hs-review-state/journal.json"))
        .unwrap();
    let journal: Journal = serde_json::from_slice(&journal_bytes).unwrap();

    // Every created resource has a write-ahead resource entry that reached Completed.
    let completed = |ty: &str, id: &str| {
        journal.resources.iter().any(|r| {
            r.resource_type == ty && r.identity == id && r.status == ResourceStatus::Completed
        })
    };
    for user in &journal.resources_created.service_users {
        assert!(
            completed("service_user", user),
            "missing completed entry for user {user}"
        );
    }
    for dir in &journal.resources_created.directories {
        assert!(
            completed("directory", dir),
            "missing completed entry for dir {dir}"
        );
    }
    for file in &journal.resources_created.files {
        assert!(
            completed("file", file),
            "missing completed entry for file {file}"
        );
    }
    for unit in &journal.resources_created.units {
        assert!(
            completed("unit", unit),
            "missing completed entry for unit {unit}"
        );
    }
    for rule in &journal.resources_created.firewall_rules {
        assert!(
            completed("firewall_rule", rule),
            "missing completed entry for rule {rule}"
        );
    }

    // No dangling Intent left behind after a successful apply.
    assert!(
        !journal
            .resources
            .iter()
            .any(|r| r.status == ResourceStatus::Intent),
        "successful apply must not leave intent entries unresolved: {:?}",
        journal.resources
    );
}

// ---------------------------------------------------------------------------
// User/path query failures must precede mutation
// ---------------------------------------------------------------------------

#[test]
fn failed_user_query_never_creates_service_user() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("query_user_exists".into(), "passwd unreadable".into());
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "unknown service-user ownership cannot mean 'create anyway'"
    );
    assert!(
        adapter.commands.lock().unwrap().is_empty(),
        "failed ownership query must precede all mutations"
    );
}

#[test]
fn symlinked_destination_parent_is_rejected() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    // /opt/helicoid is a symlink redirecting writes outside the product namespace.
    adapter
        .symlinks
        .lock()
        .unwrap()
        .insert(PathBuf::from("/opt/helicoid"));
    let result = machine::apply(
        &adapter,
        &ApplyInput {
            contract_version: 1,
            plan,
            preflight,
            confirm: true,
            package_dir: Some(PACKAGE_DIR.into()),
            verify_key: Some(verify_key_hex(&signer)),
        },
        Path::new("/tmp/hs-review-state"),
    );
    assert!(
        result.is_err() || !result.unwrap().ok,
        "a symlinked product parent must block writes"
    );
    assert!(
        !adapter
            .fs
            .lock()
            .unwrap()
            .contains_key(Path::new("/opt/helicoid/bin/hs-server")),
        "no file may be written through a symlinked parent"
    );
}

// ---------------------------------------------------------------------------
// Remove acts only on product resources
// ---------------------------------------------------------------------------

#[test]
fn tampered_journal_cannot_redirect_remove_to_foreign_paths() {
    let (adapter, _plan, _preflight, _signer) = reviewed_package();
    let state_dir = Path::new("/tmp/hs-review-state");
    // Journal claims we created an unrelated privileged file and a foreign user.
    let journal = Journal {
        contract_version: 1,
        plan_digest: machine::compute_plan_digest(&machine::generate_canonical_plan(
            "hs-server",
            "0.1.0",
        )),
        started_at: "2026-01-15T10:30:00Z".into(),
        updated_at: "2026-01-15T10:30:00Z".into(),
        current_phase: "completed".into(),
        phases: std::collections::BTreeMap::new(),
        resources_created: ResourcesCreated {
            service_users: vec!["root".into()],
            directories: vec!["/etc".into()],
            files: vec!["/etc/passwd".into(), "/etc/ssh/sshd_config".into()],
            units: vec!["../../etc/cron.d/evil".into()],
            firewall_rules: vec!["22:tcp:allow".into()],
        },
        resources: vec![],
    };
    adapter.fs.lock().unwrap().insert(
        state_dir.join("journal.json"),
        serde_json::to_vec_pretty(&journal).unwrap(),
    );
    adapter
        .fs
        .lock()
        .unwrap()
        .insert(PathBuf::from("/etc/passwd"), b"precious".to_vec());

    let result = machine::remove(
        &adapter,
        &RemoveInput {
            contract_version: 1,
            state_dir: state_dir.display().to_string(),
            delete_data: false,
            confirm: true,
        },
    )
    .unwrap();

    assert!(
        adapter
            .fs
            .lock()
            .unwrap()
            .contains_key(Path::new("/etc/passwd")),
        "remove must never delete foreign files listed in a tampered journal"
    );
    assert!(
        !result.ok,
        "refused removals must be reported as errors: {:?}",
        result.errors
    );
    assert!(
        result.errors.iter().any(|e| e.contains("non-product file")),
        "foreign file refusal must be named: {:?}",
        result.errors
    );
    assert!(
        result.errors.iter().any(|e| e.contains("non-product unit")),
        "path-traversal unit refusal must be named: {:?}",
        result.errors
    );
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("non-product service user")),
        "foreign user refusal must be named: {:?}",
        result.errors
    );
    let commands = adapter.commands.lock().unwrap();
    assert!(
        !commands.iter().any(|c| c.command == "userdel"),
        "foreign users must never be deleted"
    );
    assert!(
        !commands.iter().any(|c| c.command == "remove_unit"),
        "path-traversal unit names must never be deleted"
    );
}

// ---------------------------------------------------------------------------
// Restart after partial apply stays inside the product resource set
// ---------------------------------------------------------------------------

#[test]
fn restart_after_partial_apply_never_touches_foreign_resources() {
    let (adapter, plan, preflight, signer) = reviewed_package();
    // Fail late so earlier product resources already exist.
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("firewall_allow".into(), "ufw unavailable".into());
    let state_dir = Path::new("/tmp/hs-review-state");
    let input = ApplyInput {
        contract_version: 1,
        plan: plan.clone(),
        preflight: preflight.clone(),
        confirm: true,
        package_dir: Some(PACKAGE_DIR.into()),
        verify_key: Some(verify_key_hex(&signer)),
    };
    let first = machine::apply(&adapter, &input, state_dir).unwrap();
    assert!(!first.ok);

    // Plant an unrelated service and file that must survive restart + remove.
    adapter
        .existing_units
        .lock()
        .unwrap()
        .insert("unrelated.service".into());
    adapter.fs.lock().unwrap().insert(
        PathBuf::from("/var/lib/unrelated/data.bin"),
        b"keep-me".to_vec(),
    );

    adapter.force_failures.lock().unwrap().clear();
    let second = machine::apply(&adapter, &input, state_dir).unwrap();
    assert!(second.ok, "restart must complete: {:?}", second.errors);

    let remove_result = machine::remove(
        &adapter,
        &RemoveInput {
            contract_version: 1,
            state_dir: state_dir.display().to_string(),
            delete_data: false,
            confirm: true,
        },
    )
    .unwrap();
    assert!(
        remove_result.ok,
        "remove errors: {:?}",
        remove_result.errors
    );

    assert!(
        adapter
            .existing_units
            .lock()
            .unwrap()
            .contains("unrelated.service"),
        "unrelated service must be preserved"
    );
    assert!(
        adapter
            .fs
            .lock()
            .unwrap()
            .contains_key(Path::new("/var/lib/unrelated/data.bin")),
        "unrelated data must be preserved"
    );
}
