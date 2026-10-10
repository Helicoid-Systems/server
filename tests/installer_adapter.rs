//! Isolated real-filesystem and parser tests for the installer adapter.
//!
//! Covers fail-closed `/proc` and `systemctl show` parsing, exclusive
//! private temp writes, malicious tmp symlink preservation, atomic
//! old-file preservation, and injected query failures. Does not touch
//! auth, main, or contracts.

use hs_server::installer::adapter::{
    parse_proc_net_table, parse_systemctl_show_presence, read_file_capped, write_file_atomic,
    CommandAdapter, TestAdapter, MAX_PROC_NET_BYTES,
};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Private tempdir plus its canonical path. On macOS `/var` →
/// `/private/var`; the production nofollow walk refuses symlink
/// components, so tests must use a fully real path. Linux product
/// paths (`/opt`, `/var/lib`, `/etc`) are real directories and are
/// walked strictly from `/`.
fn real_tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

// ---------------------------------------------------------------------------
// Strict bounded proc-net parser
// ---------------------------------------------------------------------------

const TCP_HEADER: &str =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

#[test]
fn proc_net_tcp_listen_on_port_is_detected() {
    let content = format!(
        "{TCP_HEADER}\n   0: 0100007F:22E0 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
    );
    let hit = parse_proc_net_table(&content, 8928, true).unwrap();
    assert!(hit.is_some(), "LISTEN on 0x22E0=8928 must be reported");
}

#[test]
fn proc_net_tcp_non_listen_state_is_not_a_listener() {
    let content = format!(
        "{TCP_HEADER}\n   0: 0100007F:22E0 0100007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 20 4 30 10 -1\n"
    );
    let hit = parse_proc_net_table(&content, 8928, true).unwrap();
    assert_eq!(
        hit, None,
        "TCP state 01 (ESTABLISHED) is not a bind listener"
    );
}

#[test]
fn proc_net_udp_entry_on_port_is_detected() {
    let content = format!(
        "{TCP_HEADER}\n   0: 0100007F:527C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 99 2 0000000000000000 0\n"
    );
    let hit = parse_proc_net_table(&content, 21116, false).unwrap();
    assert!(hit.is_some(), "UDP bind on 0x527C=21116 must be reported");
}

#[test]
fn proc_net_missing_header_fails_closed() {
    let err = parse_proc_net_table("garbage line\n", 80, true).unwrap_err();
    assert!(
        err.contains("header"),
        "uninspectable table must not mean free: {err}"
    );
}

#[test]
fn proc_net_empty_table_fails_closed() {
    let err = parse_proc_net_table("", 80, true).unwrap_err();
    assert!(
        err.contains("empty"),
        "empty table must not mean free: {err}"
    );
}

#[test]
fn proc_net_malformed_record_fails_closed() {
    let content = format!("{TCP_HEADER}\n   0: NOT_A_RECORD\n");
    let err = parse_proc_net_table(&content, 80, true).unwrap_err();
    assert!(
        err.contains("malformed"),
        "malformed record must not mean free: {err}"
    );
}

#[test]
fn proc_net_malformed_port_field_fails_closed() {
    let content =
        format!("{TCP_HEADER}\n   0: 0100007F:ZZZZ 00000000:0000 0A 00:00 00:00 00 0 0 1\n");
    let err = parse_proc_net_table(&content, 80, true).unwrap_err();
    assert!(err.contains("malformed"), "bad port hex must fail: {err}");
}

#[test]
fn read_file_capped_rejects_oversize() {
    let (_dir, base) = real_tempdir();
    let path = base.join("big");
    std::fs::write(&path, vec![b'x'; 4096]).unwrap();
    let err = read_file_capped(path.to_str().unwrap(), 1024).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        read_file_capped(path.to_str().unwrap(), MAX_PROC_NET_BYTES)
            .unwrap()
            .len(),
        4096
    );
}

#[test]
fn read_file_capped_missing_file_is_an_error() {
    let err = read_file_capped("/no/such/proc/net/table", MAX_PROC_NET_BYTES).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

// ---------------------------------------------------------------------------
// systemctl show presence parser
// ---------------------------------------------------------------------------

#[test]
fn systemctl_show_loaded_is_present() {
    let out = "Id=hs-server.service\nLoadState=loaded\nFragmentPath=/etc/systemd/system/hs-server.service\nUnitFileState=enabled\n";
    assert!(
        parse_systemctl_show_presence(out).unwrap(),
        "loaded means present"
    );
}

#[test]
fn systemctl_show_not_found_is_absent() {
    let out = "Id=hs-server.service\nLoadState=not-found\nFragmentPath=\nUnitFileState=\n";
    assert!(
        !parse_systemctl_show_presence(out).unwrap(),
        "not-found means absent"
    );
}

#[test]
fn systemctl_show_masked_is_present() {
    let out = "Id=hs-server.service\nLoadState=masked\n";
    assert!(
        parse_systemctl_show_presence(out).unwrap(),
        "masked means present"
    );
}

#[test]
fn systemctl_show_unknown_load_state_blocks() {
    let err = parse_systemctl_show_presence("LoadState=whatever-new\n").unwrap_err();
    assert!(
        err.contains("unknown LoadState"),
        "unknown state must block: {err}"
    );
}

#[test]
fn systemctl_show_missing_load_state_blocks() {
    let err = parse_systemctl_show_presence("Id=hs-server.service\n").unwrap_err();
    assert!(err.contains("LoadState"), "missing state must block: {err}");
}

#[test]
fn systemctl_show_empty_load_state_blocks() {
    let err = parse_systemctl_show_presence("LoadState=\n").unwrap_err();
    assert!(err.contains("empty"), "empty state must block: {err}");
}

// ---------------------------------------------------------------------------
// Real filesystem: atomic write
// ---------------------------------------------------------------------------

#[test]
fn write_file_atomic_creates_new_file() {
    let (_dir, base) = real_tempdir();
    let dest = base.join("product.bin");
    write_file_atomic(&dest, b"hello").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
}

#[test]
fn write_file_atomic_creates_missing_parents() {
    let (_dir, base) = real_tempdir();
    let dest = base.join("a/b/c/file.txt");
    write_file_atomic(&dest, b"nested").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"nested");
}

#[test]
fn write_file_atomic_replaces_old_file_atomically() {
    let (_dir, base) = real_tempdir();
    let dest = base.join("product.bin");
    std::fs::write(&dest, b"old-contents").unwrap();
    write_file_atomic(&dest, b"new-contents").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"new-contents");
    let leftovers: Vec<_> = std::fs::read_dir(&base)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files must not survive: {leftovers:?}"
    );
}

#[test]
fn write_file_atomic_preserves_old_file_when_destination_is_symlink() {
    let (_dir, base) = real_tempdir();
    let foreign = base.join("foreign");
    std::fs::write(&foreign, b"precious").unwrap();
    let dest = base.join("product.bin");
    symlink(&foreign, &dest).unwrap();

    let err = write_file_atomic(&dest, b"new").unwrap_err();
    assert!(
        err.contains("symlink"),
        "destination symlink must be refused: {err}"
    );
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"precious",
        "foreign target must never be truncated"
    );
}

#[test]
fn write_file_atomic_preserves_foreign_target_via_malicious_tmp_symlink() {
    let (_dir, base) = real_tempdir();
    let foreign = base.join("foreign");
    std::fs::write(&foreign, b"precious").unwrap();
    let dest = base.join("product.bin");

    // Plant symlinks at the old predictable tmp.PID pattern and nearby
    // names File::create might have followed.
    let old_tmp = dest.with_extension(format!("tmp.{}", std::process::id()));
    symlink(&foreign, &old_tmp).unwrap();
    for i in 0..16u32 {
        let name = format!("product.tmp.{}.{}", std::process::id(), i);
        let _ = symlink(&foreign, base.join(name));
        let name = format!("product.bin.tmp.{}.{}", std::process::id(), i);
        let _ = symlink(&foreign, base.join(name));
    }

    write_file_atomic(&dest, b"new").unwrap();
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"precious",
        "precreated tmp symlink must never truncate its target"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"new");
}

#[test]
fn exclusive_create_refuses_existing_symlink_without_truncation() {
    use std::os::unix::fs::OpenOptionsExt;
    let (_dir, base) = real_tempdir();
    let foreign = base.join("foreign");
    std::fs::write(&foreign, b"precious").unwrap();
    let link = base.join("x.tmp.1");
    symlink(&foreign, &link).unwrap();

    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&link);
    assert!(result.is_err(), "O_EXCL must refuse an existing name");
    assert_eq!(std::fs::read(&foreign).unwrap(), b"precious");
}

#[test]
fn write_file_atomic_refuses_symlink_parent_and_preserves_old_file() {
    let (_dir, base) = real_tempdir();
    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("f"), b"old").unwrap();
    let link_parent = base.join("linkparent");
    symlink(&real, &link_parent).unwrap();

    let err = write_file_atomic(&link_parent.join("f"), b"new").unwrap_err();
    assert!(
        err.contains("symlink") || err.contains("openat"),
        "symlinked parent must be refused: {err}"
    );
    assert_eq!(
        std::fs::read(real.join("f")).unwrap(),
        b"old",
        "old file under the real parent must survive"
    );
}

#[test]
fn write_file_atomic_refuses_world_writable_parent_and_leaves_no_temp() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, base) = real_tempdir();
    let wd = base.join("wd");
    std::fs::create_dir(&wd).unwrap();
    let mut perms = std::fs::metadata(&wd).unwrap().permissions();
    perms.set_mode(0o777);
    std::fs::set_permissions(&wd, perms).unwrap();

    let err = write_file_atomic(&wd.join("f"), b"x").unwrap_err();
    assert!(
        err.contains("world-writable"),
        "attacker-writable parent must be refused: {err}"
    );
    let entries: Vec<_> = std::fs::read_dir(&wd)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(entries.is_empty(), "no temp may remain: {entries:?}");
}

#[test]
fn write_file_atomic_private_mode_on_temp_then_contents() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, base) = real_tempdir();
    let dest = base.join("secret");
    write_file_atomic(&dest, b"data").unwrap();
    let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "temp must be created private (0o600)");
}

#[test]
fn write_file_atomic_survives_preplanted_temp_names() {
    // Plant names in the exclusive-create namespace; the write must
    // still succeed without touching planted symlink targets.
    let (_dir, base) = real_tempdir();
    let foreign = base.join("foreign");
    std::fs::write(&foreign, b"precious").unwrap();
    let dest = base.join("cfg.json");

    let mut planted = 0;
    let pid = std::process::id();
    for b in 0..256u32 {
        let name = format!(".cfg.json.tmp.{pid}.{b:08x}");
        if symlink(&foreign, base.join(name)).is_ok() {
            planted += 1;
        }
    }
    let old = dest.with_extension(format!("tmp.{pid}"));
    let _ = symlink(&foreign, &old);
    assert!(planted > 0);

    write_file_atomic(&dest, b"{}").unwrap();
    assert_eq!(std::fs::read(&foreign).unwrap(), b"precious");
    assert_eq!(std::fs::read(&dest).unwrap(), b"{}");
}

// ---------------------------------------------------------------------------
// Injected query failures must never mean free / absent
// ---------------------------------------------------------------------------

#[test]
fn injected_port_query_failure_is_not_free() {
    let adapter = TestAdapter::new();
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("query_port_listener".into(), "proc unreadable".into());
    let result = adapter.query_port_listener(8920, "tcp");
    assert!(result.is_err(), "query failure must not report free");
}

#[test]
fn injected_unit_query_failure_is_not_absent() {
    let adapter = TestAdapter::new();
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("query_unit_exists".into(), "systemctl unavailable".into());
    let result = adapter.query_unit_exists("hs-server.service");
    assert!(result.is_err(), "query failure must not report absent");
}

#[test]
fn injected_user_query_failure_is_not_absent() {
    let adapter = TestAdapter::new();
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("query_user_exists".into(), "passwd unreadable".into());
    let result = adapter.query_user_exists("hs-server");
    assert!(result.is_err(), "query failure must not report absent");
}

#[test]
fn injected_write_failure_is_reported() {
    let adapter = TestAdapter::new();
    adapter
        .force_failures
        .lock()
        .unwrap()
        .insert("write_file".into(), "disk full".into());
    let result = adapter.write_file(Path::new("/opt/helicoid/x"), b"y");
    assert!(result.is_err());
}
