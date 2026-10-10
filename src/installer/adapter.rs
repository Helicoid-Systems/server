//! Command and filesystem adapter for the installer.
//!
//! Production uses Linux-specific commands (useradd, systemctl, ufw, etc.)
//! with fixed argv, timeouts, capped output, no shell concatenation.
//! Tests inject `TestAdapter` with in-memory filesystem and recorded commands.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use crate::error::{AppError, AppResult};

// ---------------------------------------------------------------------------
// File metadata (lightweight, cross-platform)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub len: u64,
    pub is_symlink: bool,
    pub is_dir: bool,
}

// ---------------------------------------------------------------------------
// Adapter trait
// ---------------------------------------------------------------------------

/// Abstraction over OS commands and filesystem for the installer.
/// Production adapter is only available on the Linux target.
/// Tests use `TestAdapter` with in-memory fixtures.
pub trait CommandAdapter: Send + Sync {
    /// Read entire file contents.
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, String>;

    /// Write file contents (creates parent dirs if needed).
    fn write_file(&self, path: &Path, contents: &[u8]) -> Result<(), String>;

    /// Create a directory (and parents).
    fn create_dir_all(&self, path: &Path) -> Result<(), String>;

    /// Remove a file.
    fn remove_file(&self, path: &Path) -> Result<(), String>;

    /// Remove a directory (must be empty).
    fn remove_dir(&self, path: &Path) -> Result<(), String>;

    /// Remove a directory and all contents.
    fn remove_dir_all(&self, path: &Path) -> Result<(), String>;

    /// Check if path exists.
    fn path_exists(&self, path: &Path) -> bool;

    /// Get file metadata (follows symlinks).
    fn metadata(&self, path: &Path) -> Result<FileMetadata, String>;

    /// Get file metadata (does NOT follow symlinks).
    fn symlink_metadata(&self, path: &Path) -> Result<FileMetadata, String>;

    /// List directory entries (filenames only, non-recursive).
    fn list_dir(&self, path: &Path) -> Result<Vec<String>, String>;

    /// Copy a file from src to dst.
    fn copy_file(&self, src: &Path, dst: &Path) -> Result<(), String>;

    /// Set file permissions (unix mode, e.g. 0o755).
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), String>;

    // --- System queries (preflight) ---

    /// Get OS information (name, version).
    fn query_os(&self) -> Result<(String, String), String>;

    /// Get architecture string (e.g. "x86_64").
    fn query_arch(&self) -> Result<String, String>;

    /// Check if running as root.
    fn query_is_root(&self) -> Result<bool, String>;

    /// Get storage info for a path: (total_bytes, available_bytes).
    fn query_storage(&self, path: &Path) -> Result<(u64, u64), String>;

    /// Check if a TCP/UDP port has a listener. Returns process name if found.
    fn query_port_listener(&self, port: u16, protocol: &str) -> Result<Option<String>, String>;

    /// Check if a systemd unit exists.
    fn query_unit_exists(&self, unit_name: &str) -> Result<bool, String>;

    /// Check if a system user exists.
    fn query_user_exists(&self, username: &str) -> Result<bool, String>;

    // --- System commands (apply/remove) ---

    /// Create a system user (useradd --system).
    fn create_system_user(&self, username: &str, home_dir: &Path) -> Result<(), String>;

    /// Remove a system user.
    fn remove_system_user(&self, username: &str) -> Result<(), String>;

    /// Install a systemd unit file.
    fn install_unit(&self, name: &str, content: &[u8]) -> Result<(), String>;

    /// Remove a systemd unit file.
    fn remove_unit(&self, name: &str) -> Result<(), String>;

    /// Reload systemd daemon.
    fn systemd_daemon_reload(&self) -> Result<(), String>;

    /// Enable a systemd unit.
    fn enable_unit(&self, name: &str) -> Result<(), String>;

    /// Disable a systemd unit.
    fn disable_unit(&self, name: &str) -> Result<(), String>;

    /// Stop a systemd unit.
    fn stop_unit(&self, name: &str) -> Result<(), String>;

    /// Add a firewall rule (ufw allow).
    fn firewall_allow(&self, port: u16, protocol: &str, comment: &str) -> Result<(), String>;

    /// Remove a firewall rule.
    fn firewall_deny(&self, port: u16, protocol: &str) -> Result<(), String>;

    /// Remove an exact firewall rule by port, protocol, and comment.
    fn firewall_deny_exact(&self, port: u16, protocol: &str, comment: &str) -> Result<(), String>;

    /// Get the current timestamp as ISO 8601.
    fn now_iso8601(&self) -> String;
}

// ---------------------------------------------------------------------------
// Test adapter: in-memory filesystem + recorded commands
// ---------------------------------------------------------------------------

/// Recorded command for test assertions.
#[derive(Debug, Clone)]
pub struct RecordedCommand {
    pub command: String,
    pub args: Vec<String>,
}

/// In-memory test adapter with controllable behavior.
pub struct TestAdapter {
    /// In-memory filesystem: path -> contents.
    pub fs: Arc<Mutex<HashMap<PathBuf, Vec<u8>>>>,
    /// Recorded commands.
    pub commands: Arc<Mutex<Vec<RecordedCommand>>>,
    /// Pre-configured port listeners.
    pub port_listeners: Arc<Mutex<HashMap<(u16, String), String>>>,
    /// Pre-configured existing users.
    pub existing_users: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Pre-configured existing units.
    pub existing_units: Arc<Mutex<std::collections::HashSet<String>>>,
    /// OS info: (name, version).
    pub os_info: (String, String),
    /// Architecture.
    pub arch: String,
    /// Is root.
    pub is_root: bool,
    /// Storage: (total, available).
    pub storage: (u64, u64),
    /// Force command failures (command name -> error message).
    pub force_failures: Arc<Mutex<HashMap<String, String>>>,
    /// Paths that report as symlinks via `symlink_metadata`.
    pub symlinks: Arc<Mutex<std::collections::HashSet<PathBuf>>>,
}

impl TestAdapter {
    pub fn new() -> Self {
        TestAdapter {
            fs: Arc::new(Mutex::new(HashMap::new())),
            commands: Arc::new(Mutex::new(Vec::new())),
            port_listeners: Arc::new(Mutex::new(HashMap::new())),
            existing_users: Arc::new(Mutex::new(std::collections::HashSet::new())),
            existing_units: Arc::new(Mutex::new(std::collections::HashSet::new())),
            os_info: ("ubuntu".into(), "26.04".into()),
            arch: "x86_64".into(),
            is_root: true,
            storage: (100 * 1024 * 1024 * 1024, 50 * 1024 * 1024 * 1024),
            force_failures: Arc::new(Mutex::new(HashMap::new())),
            symlinks: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    fn record(&self, command: &str, args: &[&str]) {
        self.commands.lock().unwrap().push(RecordedCommand {
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });
    }

    fn check_failure(&self, command: &str) -> Result<(), String> {
        let failures = self.force_failures.lock().unwrap();
        if let Some(msg) = failures.get(command) {
            Err(msg.clone())
        } else {
            Ok(())
        }
    }
}

impl Default for TestAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandAdapter for TestAdapter {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, String> {
        let fs = self.fs.lock().unwrap();
        fs.get(path)
            .cloned()
            .ok_or_else(|| format!("file not found: {}", path.display()))
    }

    fn write_file(&self, path: &Path, contents: &[u8]) -> Result<(), String> {
        self.check_failure("write_file")?;
        let mut fs = self.fs.lock().unwrap();
        // Auto-create parent dirs.
        if let Some(parent) = path.parent() {
            fs.entry(parent.to_path_buf()).or_default();
        }
        fs.insert(path.to_path_buf(), contents.to_vec());
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), String> {
        self.check_failure("create_dir_all")?;
        let mut fs = self.fs.lock().unwrap();
        fs.entry(path.to_path_buf()).or_default();
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), String> {
        self.check_failure("remove_file")?;
        let mut fs = self.fs.lock().unwrap();
        fs.remove(path);
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> Result<(), String> {
        self.check_failure("remove_dir")?;
        let mut fs = self.fs.lock().unwrap();
        fs.remove(path);
        Ok(())
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), String> {
        self.check_failure("remove_dir_all")?;
        let mut fs = self.fs.lock().unwrap();
        let prefix = path.to_path_buf();
        fs.retain(|k, _| !k.starts_with(&prefix) && k != &prefix);
        Ok(())
    }

    fn path_exists(&self, path: &Path) -> bool {
        let fs = self.fs.lock().unwrap();
        if fs.contains_key(path) {
            return true;
        }
        // Also check if any key starts with this path (directory exists).
        fs.keys().any(|k| k.starts_with(path))
    }

    fn metadata(&self, path: &Path) -> Result<FileMetadata, String> {
        // Follows symlinks: reports the target entry, never is_symlink.
        let fs = self.fs.lock().unwrap();
        if let Some(data) = fs.get(path) {
            return Ok(FileMetadata {
                len: data.len() as u64,
                is_symlink: false,
                is_dir: false,
            });
        }
        // Directory implied by a descendant entry (matches path_exists).
        if fs.keys().any(|k| k.starts_with(path) && k != path) {
            return Ok(FileMetadata {
                len: 0,
                is_symlink: false,
                is_dir: true,
            });
        }
        Err(format!("path not found: {}", path.display()))
    }

    fn symlink_metadata(&self, path: &Path) -> Result<FileMetadata, String> {
        if self.symlinks.lock().unwrap().contains(path) {
            return Ok(FileMetadata {
                len: 0,
                is_symlink: true,
                is_dir: false,
            });
        }
        self.metadata(path)
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<String>, String> {
        let fs = self.fs.lock().unwrap();
        let prefix = path.to_path_buf();
        let mut entries = Vec::new();
        for key in fs.keys() {
            if key.starts_with(&prefix) && key != &prefix {
                if let Ok(relative) = key.strip_prefix(&prefix) {
                    if let Some(name) = relative.components().next() {
                        let name_str = name.as_os_str().to_string_lossy().to_string();
                        if !entries.contains(&name_str) {
                            entries.push(name_str);
                        }
                    }
                }
            }
        }
        Ok(entries)
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<(), String> {
        self.check_failure("copy_file")?;
        let data = {
            let fs = self.fs.lock().unwrap();
            fs.get(src)
                .cloned()
                .ok_or_else(|| format!("source not found: {}", src.display()))?
        };
        let mut fs = self.fs.lock().unwrap();
        fs.insert(dst.to_path_buf(), data);
        Ok(())
    }

    fn set_permissions(&self, _path: &Path, _mode: u32) -> Result<(), String> {
        self.check_failure("set_permissions")?;
        Ok(())
    }

    fn query_os(&self) -> Result<(String, String), String> {
        self.check_failure("query_os")?;
        Ok(self.os_info.clone())
    }

    fn query_arch(&self) -> Result<String, String> {
        self.check_failure("query_arch")?;
        Ok(self.arch.clone())
    }

    fn query_is_root(&self) -> Result<bool, String> {
        self.check_failure("query_is_root")?;
        Ok(self.is_root)
    }

    fn query_storage(&self, _path: &Path) -> Result<(u64, u64), String> {
        self.check_failure("query_storage")?;
        Ok(self.storage)
    }

    fn query_port_listener(&self, port: u16, protocol: &str) -> Result<Option<String>, String> {
        self.check_failure("query_port_listener")?;
        let listeners = self.port_listeners.lock().unwrap();
        Ok(listeners.get(&(port, protocol.to_string())).cloned())
    }

    fn query_unit_exists(&self, unit_name: &str) -> Result<bool, String> {
        self.check_failure("query_unit_exists")?;
        let units = self.existing_units.lock().unwrap();
        Ok(units.contains(unit_name))
    }

    fn query_user_exists(&self, username: &str) -> Result<bool, String> {
        self.check_failure("query_user_exists")?;
        let users = self.existing_users.lock().unwrap();
        Ok(users.contains(username))
    }

    fn create_system_user(&self, username: &str, _home_dir: &Path) -> Result<(), String> {
        self.check_failure("create_system_user")?;
        self.record("useradd", &["--system", "--home-dir", "<path>", username]);
        let mut users = self.existing_users.lock().unwrap();
        users.insert(username.to_string());
        Ok(())
    }

    fn remove_system_user(&self, username: &str) -> Result<(), String> {
        self.check_failure("remove_system_user")?;
        self.record("userdel", &[username]);
        let mut users = self.existing_users.lock().unwrap();
        users.remove(username);
        Ok(())
    }

    fn install_unit(&self, name: &str, _content: &[u8]) -> Result<(), String> {
        self.check_failure("install_unit")?;
        self.record("install_unit", &[name]);
        let mut units = self.existing_units.lock().unwrap();
        units.insert(name.to_string());
        Ok(())
    }

    fn remove_unit(&self, name: &str) -> Result<(), String> {
        self.check_failure("remove_unit")?;
        self.record("remove_unit", &[name]);
        let mut units = self.existing_units.lock().unwrap();
        units.remove(name);
        Ok(())
    }

    fn systemd_daemon_reload(&self) -> Result<(), String> {
        self.check_failure("systemd_daemon_reload")?;
        self.record("systemctl", &["daemon-reload"]);
        Ok(())
    }

    fn enable_unit(&self, name: &str) -> Result<(), String> {
        self.check_failure("enable_unit")?;
        self.record("systemctl", &["enable", name]);
        Ok(())
    }

    fn disable_unit(&self, name: &str) -> Result<(), String> {
        self.check_failure("disable_unit")?;
        self.record("systemctl", &["disable", name]);
        Ok(())
    }

    fn stop_unit(&self, name: &str) -> Result<(), String> {
        self.check_failure("stop_unit")?;
        self.record("systemctl", &["stop", name]);
        Ok(())
    }

    fn firewall_allow(&self, port: u16, protocol: &str, comment: &str) -> Result<(), String> {
        self.check_failure("firewall_allow")?;
        self.record(
            "ufw",
            &["allow", &port.to_string(), &format!("/{protocol}"), comment],
        );
        Ok(())
    }

    fn firewall_deny(&self, port: u16, protocol: &str) -> Result<(), String> {
        self.check_failure("firewall_deny")?;
        self.record(
            "ufw",
            &[
                "delete",
                "allow",
                &port.to_string(),
                &format!("/{protocol}"),
            ],
        );
        Ok(())
    }

    fn firewall_deny_exact(&self, port: u16, protocol: &str, comment: &str) -> Result<(), String> {
        self.check_failure("firewall_deny")?;
        self.record(
            "ufw",
            &[
                "delete",
                "allow",
                &port.to_string(),
                &format!("/{protocol}"),
                "comment",
                comment,
            ],
        );
        Ok(())
    }

    fn now_iso8601(&self) -> String {
        "2026-01-15T10:30:00Z".to_string()
    }
}

// ---------------------------------------------------------------------------
// Shared unix helpers (LinuxAdapter + real filesystem tests)
// ---------------------------------------------------------------------------
//
// TOCTOU note: `write_file_atomic` uses descriptor-relative nofollow
// operations (openat/renameat/unlinkat/fsync on a held directory fd).
// That closes the parent-symlink and predictable-tmp races that a
// path-string lstat check cannot. It does not claim to close every
// race (mount-point swaps, exotic /proc fd tricks). World-writable
// non-sticky directories are refused as a remaining race gate.

/// Bound on `/proc/net/*` table reads.
pub const MAX_PROC_NET_BYTES: usize = 8 * 1024 * 1024;

/// Bound on `systemctl show` stdout.
pub const MAX_SYSTEMCTL_SHOW_BYTES: usize = 64 * 1024;

/// Parse a `/proc/net/{tcp,tcp6,udp,udp6}` table for a local port.
///
/// Fails closed on a missing header or any malformed record: an
/// uninspectable table must not be reported as "port free".
/// Returns `Ok(Some(process))` when a matching listener exists.
pub fn parse_proc_net_table(content: &str, port: u16, tcp: bool) -> Result<Option<String>, String> {
    let hex_port = format!("{port:04X}");
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| "proc net table is empty".to_string())?;
    if !header.contains("local_address") {
        return Err("proc net table missing local_address header".into());
    }

    let mut found = false;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return Err(format!("malformed proc net record: {line}"));
        }
        let local_addr = fields[1];
        let state = fields[3];
        let (_, addr_port) = local_addr
            .rsplit_once(':')
            .ok_or_else(|| format!("malformed local_address: {local_addr}"))?;
        if addr_port.len() != 4 || !addr_port.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("malformed port field: {addr_port}"));
        }
        let ip_hex = &local_addr[..local_addr.len() - addr_port.len() - 1];
        if ip_hex.is_empty() || !ip_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("malformed address field: {ip_hex}"));
        }
        if state.len() != 2 || !state.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("malformed state field: {state}"));
        }
        if !addr_port.eq_ignore_ascii_case(&hex_port) {
            continue;
        }
        // TCP: only LISTEN (0A) occupies a bind port. UDP: any entry binds.
        if tcp && state != "0A" {
            continue;
        }
        found = true;
    }

    Ok(if found {
        Some(format!("process on port {port}"))
    } else {
        None
    })
}

/// Parse `systemctl show --property=LoadState,...` output.
///
/// `Ok(true)` when the unit is known to systemd (loaded/masked/…),
/// `Ok(false)` only for `LoadState=not-found`. Unknown or missing
/// state is an error: unknown must block, never mean "absent".
pub fn parse_systemctl_show_presence(content: &str) -> Result<bool, String> {
    let mut load_state: Option<String> = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("LoadState=") {
            load_state = Some(v.trim().to_string());
        }
    }
    let load_state = load_state.ok_or_else(|| "systemctl show missing LoadState".to_string())?;
    match load_state.as_str() {
        "not-found" => Ok(false),
        "loaded" | "masked" | "error" | "bad-setting" | "stub" | "merged" => Ok(true),
        "" => Err("systemctl show returned empty LoadState".into()),
        other => Err(format!("unknown LoadState: {other}")),
    }
}

/// Read a file with a hard byte cap.
pub fn read_file_capped(path: &str, max: usize) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len().saturating_add(n) > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{path} exceeds {max} byte bound"),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{path} not UTF-8"))
    })
}

/// Open `path` as a directory without following any symlink component.
/// Creates missing directories (`mode 0o755`) when `create` is set.
/// Refuses world-writable non-sticky directories.
#[cfg(unix)]
fn open_dir_nofollow(path: &Path, create: bool) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: open/close are paired; fd is wrapped in OwnedFd on success.
    let mut fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!("open /: {}", std::io::Error::last_os_error()));
    }

    for comp in path.components() {
        let name = match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(n) => n,
            std::path::Component::ParentDir => {
                // SAFETY: fd owned locally until this return.
                unsafe { libc::close(fd) };
                return Err("parent-directory component refused".into());
            }
            std::path::Component::Prefix(_) => {
                unsafe { libc::close(fd) };
                return Err("windows path prefix unsupported".into());
            }
        };
        let cname = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| "path component contains NUL".to_string())?;
        // SAFETY: cname is a valid CString; fd is an open directory.
        let new_fd = unsafe {
            libc::openat(
                fd,
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if new_fd < 0 {
            let err = std::io::Error::last_os_error();
            if create && err.raw_os_error() == Some(libc::ENOENT) {
                // SAFETY: mkdirat on the held parent fd; name is one component.
                if unsafe { libc::mkdirat(fd, cname.as_ptr(), 0o755) } < 0 {
                    let e = std::io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(format!("mkdirat '{}': {e}", name.display()));
                }
                let new_fd = unsafe {
                    libc::openat(
                        fd,
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if new_fd < 0 {
                    let e = std::io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(format!("openat '{}': {e}", name.display()));
                }
                unsafe { libc::close(fd) };
                fd = new_fd;
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(format!(
                "openat '{}': {err} (symlink components are refused)",
                name.display()
            ));
        }
        unsafe { libc::close(fd) };
        fd = new_fd;
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("fstat dir: {e}"));
    }
    // Sticky world-writable (e.g. /tmp) is tolerated because the write
    // below is descriptor-relative and exclusive-create; non-sticky
    // world-writable parents are an attacker-writable race gate.
    if st.st_mode & libc::S_IWOTH != 0 && st.st_mode & libc::S_ISVTX == 0 {
        unsafe { libc::close(fd) };
        return Err("directory is world-writable; refusing write".into());
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Atomic write: unique exclusive private temp in the destination
/// directory, fsync, renameat, fsync parent. The temp is removed on
/// failure. Destination and parents never follow symlinks. The previous
/// destination file is preserved until the rename replaces it.
#[cfg(unix)]
pub fn write_file_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("/"),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("destination '{}' has no file name", path.display()))?;

    let dir_fd = open_dir_nofollow(parent, true)?;

    // Never open a destination that is already a symlink; rename would
    // replace the name, but an earlier write-open would have followed it.
    let c_dest = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| "destination name contains NUL".to_string())?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: dir_fd held; c_dest is one component; AT_SYMLINK_NOFOLLOW.
    let rc = unsafe {
        libc::fstatat(
            dir_fd.as_raw_fd(),
            c_dest.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
        return Err(format!(
            "destination '{}' is a symlink; refusing write",
            path.display()
        ));
    }
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOENT) {
            return Err(format!("lstat destination '{}': {e}", path.display()));
        }
    }

    // Unique private temp: O_CREAT|O_EXCL|O_NOFOLLOW, mode 0o600.
    // A precreated symlink at the name is EEXIST, never truncated.
    let mut tmp_name: Option<std::ffi::CString> = None;
    let mut tmp_fd: i32 = -1;
    for _ in 0..32 {
        let name = format!(
            ".{}.tmp.{}.{:08x}",
            file_name.to_string_lossy(),
            std::process::id(),
            rand::random::<u32>()
        );
        let cname = std::ffi::CString::new(name.as_str())
            .map_err(|_| "temp name contains NUL".to_string())?;
        // SAFETY: exclusive create in the held directory fd.
        let fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                cname.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            tmp_name = Some(cname);
            tmp_fd = fd;
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(format!(
                "create exclusive temp for '{}': {e}",
                path.display()
            ));
        }
    }
    let tmp_name = tmp_name.ok_or_else(|| {
        format!(
            "could not create exclusive temporary file for '{}'",
            path.display()
        )
    })?;

    // Write + fsync + rename + parent fsync; unlink temp on any failure.
    let result = (|| -> Result<(), String> {
        // SAFETY: tmp_fd is an exclusively created regular file.
        let mut file = unsafe { std::fs::File::from_raw_fd(tmp_fd) };
        // File owns tmp_fd now; do not double-close on the way out.
        tmp_fd = -1;
        file.write_all(contents)
            .map_err(|e| format!("write temp for '{}': {e}", path.display()))?;
        file.sync_all()
            .map_err(|e| format!("fsync temp for '{}': {e}", path.display()))?;
        drop(file);

        // SAFETY: renameat within the held directory; replaces the name.
        if unsafe {
            libc::renameat(
                dir_fd.as_raw_fd(),
                tmp_name.as_ptr(),
                dir_fd.as_raw_fd(),
                c_dest.as_ptr(),
            )
        } < 0
        {
            let e = std::io::Error::last_os_error();
            return Err(format!("renameat '{}': {e}", path.display()));
        }
        if unsafe { libc::fsync(dir_fd.as_raw_fd()) } < 0 {
            let e = std::io::Error::last_os_error();
            return Err(format!("fsync dir for '{}': {e}", path.display()));
        }
        Ok(())
    })();

    if result.is_err() {
        if tmp_fd >= 0 {
            unsafe { libc::close(tmp_fd) };
        }
        // SAFETY: tmp_name is a single component under dir_fd.
        unsafe {
            libc::unlinkat(dir_fd.as_raw_fd(), tmp_name.as_ptr(), 0);
        };
    }
    result
}

// ---------------------------------------------------------------------------
// Linux adapter: real OS commands and filesystem queries
// ---------------------------------------------------------------------------

/// Production adapter that queries the actual Linux host.
/// Only available on `target_os = "linux"`.
///
/// All command paths are absolute to avoid PATH injection.
#[cfg(target_os = "linux")]
pub struct LinuxAdapter;

/// Absolute paths for system commands used by LinuxAdapter.
#[cfg(target_os = "linux")]
const CMD_USERADD: &str = "/usr/sbin/useradd";
#[cfg(target_os = "linux")]
const CMD_USERDEL: &str = "/usr/sbin/userdel";
#[cfg(target_os = "linux")]
const CMD_SYSTEMCTL: &str = "/usr/bin/systemctl";
#[cfg(target_os = "linux")]
const CMD_UFW: &str = "/usr/sbin/ufw";
#[cfg(target_os = "linux")]
const CMD_UNAME: &str = "/usr/bin/uname";

#[cfg(target_os = "linux")]
impl LinuxAdapter {
    /// Run a command with fixed argv, bounded wait, and capped output.
    /// Returns (stdout, stderr, exit_code). stdout/stderr are truncated
    /// at 256 KiB; callers that need a hard fail on oversize must check.
    fn run_command(argv: &[&str], timeout_secs: u64) -> AppResult<(Vec<u8>, Vec<u8>, i32)> {
        use std::io::Read;
        use std::process::{Command, Stdio};

        const MAX_CMD_OUTPUT: usize = 256 * 1024;

        if argv.is_empty() {
            return Err(AppError::internal("empty command argv"));
        }

        let mut cmd = Command::new(argv[0]);
        if argv.len() > 1 {
            cmd.args(&argv[1..]);
        }
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| AppError::internal(format!("spawn '{}': {e}", argv[0])))?;

        // Drain stdout/stderr on helper threads so the child cannot
        // deadlock on a full pipe while we poll for exit.
        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();
        let out_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(ref mut pipe) = stdout_pipe {
                let mut chunk = [0u8; 8192];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if buf.len() >= MAX_CMD_OUTPUT {
                                // Keep reading to drain, but do not grow.
                                continue;
                            }
                            let room = MAX_CMD_OUTPUT - buf.len();
                            buf.extend_from_slice(&chunk[..n.min(room)]);
                        }
                        Err(_) => break,
                    }
                }
            }
            buf
        });
        let err_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(ref mut pipe) = stderr_pipe {
                let mut chunk = [0u8; 8192];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if buf.len() >= MAX_CMD_OUTPUT {
                                continue;
                            }
                            let room = MAX_CMD_OUTPUT - buf.len();
                            buf.extend_from_slice(&chunk[..n.min(room)]);
                        }
                        Err(_) => break,
                    }
                }
            }
            buf
        });

        // Bounded wait.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(AppError::internal(format!(
                            "command '{}' timed out after {timeout_secs}s",
                            argv[0]
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(AppError::internal(format!("try_wait: {e}")));
                }
            }
        };

        let stdout = out_handle.join().unwrap_or_default();
        let stderr = err_handle.join().unwrap_or_default();
        Ok((stdout, stderr, status.code().unwrap_or(-1)))
    }

    /// Read /etc/os-release and parse key=value pairs.
    fn parse_os_release() -> AppResult<(String, String)> {
        let content = std::fs::read_to_string("/etc/os-release")
            .map_err(|e| AppError::internal(format!("read /etc/os-release: {e}")))?;

        let mut id = String::new();
        let mut version = String::new();

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("ID=") {
                id = val.trim_matches('"').to_string();
            } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
                version = val.trim_matches('"').to_string();
            }
        }

        if id.is_empty() || version.is_empty() {
            return Err(AppError::internal(
                "cannot determine OS from /etc/os-release",
            ));
        }

        Ok((id, version))
    }
}

#[cfg(target_os = "linux")]
impl CommandAdapter for LinuxAdapter {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| format!("read '{}': {e}", path.display()))
    }

    fn write_file(&self, path: &Path, contents: &[u8]) -> Result<(), String> {
        write_file_atomic(path, contents)
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|e| format!("mkdir '{}': {e}", path.display()))
    }

    fn remove_file(&self, path: &Path) -> Result<(), String> {
        std::fs::remove_file(path).map_err(|e| format!("rm '{}': {e}", path.display()))
    }

    fn remove_dir(&self, path: &Path) -> Result<(), String> {
        std::fs::remove_dir(path).map_err(|e| format!("rmdir '{}': {e}", path.display()))
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), String> {
        std::fs::remove_dir_all(path).map_err(|e| format!("rm -rf '{}': {e}", path.display()))
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn metadata(&self, path: &Path) -> Result<FileMetadata, String> {
        let m = path
            .metadata()
            .map_err(|e| format!("metadata '{}': {e}", path.display()))?;
        Ok(FileMetadata {
            len: m.len(),
            is_symlink: false, // metadata() follows symlinks
            is_dir: m.is_dir(),
        })
    }

    fn symlink_metadata(&self, path: &Path) -> Result<FileMetadata, String> {
        let m = path
            .symlink_metadata()
            .map_err(|e| format!("lstat '{}': {e}", path.display()))?;
        Ok(FileMetadata {
            len: m.len(),
            is_symlink: m.file_type().is_symlink(),
            is_dir: m.is_dir(),
        })
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<String>, String> {
        let entries = path
            .read_dir()
            .map_err(|e| format!("readdir '{}': {e}", path.display()))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("readdir entry: {e}"))?;
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        Ok(names)
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<(), String> {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir '{}': {e}", parent.display()))?;
        }
        std::fs::copy(src, dst)
            .map_err(|e| format!("cp '{}' '{}': {e}", src.display(), dst.display()))?;
        Ok(())
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)
            .map_err(|e| format!("chmod '{}': {e}", path.display()))
    }

    fn query_os(&self) -> Result<(String, String), String> {
        Self::parse_os_release().map_err(|e| e.to_string())
    }

    fn query_arch(&self) -> Result<String, String> {
        let (stdout, _, code) =
            Self::run_command(&[CMD_UNAME, "-m"], 5).map_err(|e| e.to_string())?;
        if code != 0 {
            return Err("uname -m failed".into());
        }
        Ok(String::from_utf8_lossy(&stdout).trim().to_string())
    }

    fn query_is_root(&self) -> Result<bool, String> {
        // SAFETY: getuid is always safe and never fails.
        Ok(unsafe { libc::getuid() } == 0)
    }

    fn query_storage(&self, path: &Path) -> Result<(u64, u64), String> {
        let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| format!("invalid path: {}", path.display()))?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: statvfs writes to stat; c_path is valid CString.
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if rc != 0 {
            return Err(format!("statvfs failed for '{}': {}", path.display(), rc));
        }
        let block_size = if stat.f_frsize > 0 {
            stat.f_frsize as u64
        } else {
            stat.f_bsize as u64
        };
        let f_blocks = stat.f_blocks as u128;
        let f_bavail = stat.f_bavail as u128;
        let bs = block_size as u128;
        let total = bs * f_blocks;
        let available = bs * f_bavail;
        // Guard against overflow: cap at u64::MAX.
        let total_capped = total.min(u64::MAX as u128) as u64;
        let available_capped = available.min(u64::MAX as u128) as u64;
        Ok((total_capped, available_capped))
    }

    fn query_port_listener(&self, port: u16, protocol: &str) -> Result<Option<String>, String> {
        // Required tables must be readable and strictly parseable.
        // Optional IPv6 tables may be absent (ENOENT) when IPv6 is off;
        // any other read/parse failure fails closed — never report free.
        let (required, optional): (&[&str], &[&str]) = match protocol {
            "tcp" => (&["/proc/net/tcp"], &["/proc/net/tcp6"]),
            "udp" => (&["/proc/net/udp"], &["/proc/net/udp6"]),
            _ => return Err(format!("unsupported protocol: {protocol}")),
        };

        let mut hit = None;
        for proc_file in required.iter().chain(optional.iter()) {
            let content = match read_file_capped(proc_file, MAX_PROC_NET_BYTES) {
                Ok(c) => c,
                Err(e) => {
                    let missing = e.kind() == std::io::ErrorKind::NotFound;
                    if missing && optional.contains(proc_file) {
                        continue;
                    }
                    return Err(format!("read {proc_file}: {e}"));
                }
            };
            if let Some(process) = parse_proc_net_table(&content, port, protocol == "tcp")? {
                hit = Some(process);
            }
        }
        Ok(hit)
    }

    fn query_unit_exists(&self, unit_name: &str) -> Result<bool, String> {
        if unit_name.is_empty()
            || unit_name.contains('/')
            || unit_name.contains('\0')
            || unit_name.contains("..")
        {
            return Err(format!("invalid unit name: {unit_name}"));
        }

        // lstat fragment paths: a dangling symlink is still a conflict
        // (Path::exists would follow it and report absent).
        let paths = [
            format!("/etc/systemd/system/{unit_name}"),
            format!("/lib/systemd/system/{unit_name}"),
            format!("/usr/lib/systemd/system/{unit_name}"),
            format!("/run/systemd/system/{unit_name}"),
        ];
        for p in &paths {
            match std::fs::symlink_metadata(p) {
                Ok(_) => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("lstat '{p}': {e}")),
            }
        }

        // Loaded/transient units have no fragment on disk. Bounded
        // fixed-argv systemctl show; unknown state blocks via Err.
        let (stdout, stderr, code) = Self::run_command(
            &[
                CMD_SYSTEMCTL,
                "show",
                unit_name,
                "--property=LoadState,Id,FragmentPath,UnitFileState",
                "--no-pager",
            ],
            10,
        )
        .map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!(
                "systemctl show {unit_name} exited {code}: {}",
                String::from_utf8_lossy(&stderr)
            ));
        }
        if stdout.len() > MAX_SYSTEMCTL_SHOW_BYTES {
            return Err(format!(
                "systemctl show {unit_name} exceeded {MAX_SYSTEMCTL_SHOW_BYTES} byte bound"
            ));
        }
        parse_systemctl_show_presence(&String::from_utf8_lossy(&stdout))
    }

    fn query_user_exists(&self, username: &str) -> Result<bool, String> {
        let content =
            std::fs::read_to_string("/etc/passwd").map_err(|e| format!("read /etc/passwd: {e}"))?;
        for line in content.lines() {
            if let Some(name) = line.split(':').next() {
                if name == username {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn create_system_user(&self, username: &str, home_dir: &Path) -> Result<(), String> {
        let (_, _, code) = Self::run_command(
            &[
                CMD_USERADD,
                "--system",
                "--home-dir",
                &home_dir.to_string_lossy(),
                "--no-create-home",
                username,
            ],
            30,
        )
        .map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("useradd exited with code {code}"));
        }
        Ok(())
    }

    fn remove_system_user(&self, username: &str) -> Result<(), String> {
        let (_, _, code) =
            Self::run_command(&[CMD_USERDEL, username], 30).map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("userdel exited with code {code}"));
        }
        Ok(())
    }

    fn install_unit(&self, name: &str, content: &[u8]) -> Result<(), String> {
        let path = PathBuf::from(format!("/etc/systemd/system/{name}"));
        self.write_file(&path, content)
    }

    fn remove_unit(&self, name: &str) -> Result<(), String> {
        let path = PathBuf::from(format!("/etc/systemd/system/{name}"));
        self.remove_file(&path)
    }

    fn systemd_daemon_reload(&self) -> Result<(), String> {
        let (_, _, code) =
            Self::run_command(&[CMD_SYSTEMCTL, "daemon-reload"], 30).map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("daemon-reload exited with code {code}"));
        }
        Ok(())
    }

    fn enable_unit(&self, name: &str) -> Result<(), String> {
        let (_, _, code) =
            Self::run_command(&[CMD_SYSTEMCTL, "enable", name], 30).map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("enable {name} exited with code {code}"));
        }
        Ok(())
    }

    fn disable_unit(&self, name: &str) -> Result<(), String> {
        let (_, _, code) =
            Self::run_command(&[CMD_SYSTEMCTL, "disable", name], 30).map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("disable {name} exited with code {code}"));
        }
        Ok(())
    }

    fn stop_unit(&self, name: &str) -> Result<(), String> {
        let (_, _, code) =
            Self::run_command(&[CMD_SYSTEMCTL, "stop", name], 30).map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("stop {name} exited with code {code}"));
        }
        Ok(())
    }

    fn firewall_allow(&self, port: u16, protocol: &str, comment: &str) -> Result<(), String> {
        let port_proto = format!("{port}/{protocol}");
        let (_, _, code) =
            Self::run_command(&[CMD_UFW, "allow", &port_proto, "comment", comment], 30)
                .map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!("ufw allow {port_proto} exited with code {code}"));
        }
        Ok(())
    }

    fn firewall_deny(&self, port: u16, protocol: &str) -> Result<(), String> {
        let port_proto = format!("{port}/{protocol}");
        let (_, _, code) = Self::run_command(&[CMD_UFW, "delete", "allow", &port_proto], 30)
            .map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!(
                "ufw delete allow {port_proto} exited with code {code}"
            ));
        }
        Ok(())
    }

    fn firewall_deny_exact(&self, port: u16, protocol: &str, comment: &str) -> Result<(), String> {
        let port_proto = format!("{port}/{protocol}");
        let (_, _, code) = Self::run_command(
            &[CMD_UFW, "delete", "allow", &port_proto, "comment", comment],
            30,
        )
        .map_err(|e| e.to_string())?;
        if code != 0 {
            return Err(format!(
                "ufw delete allow {port_proto} comment {comment} exited with code {code}"
            ));
        }
        Ok(())
    }

    fn now_iso8601(&self) -> String {
        // Use UTC timestamp formatted without external crate.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        // Convert to broken-down time (UTC).
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        // Days since epoch to Y-M-D (simplified leap year calculation).
        let (year, month, day) = days_to_ymd(days);

        format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
    }
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
#[cfg(target_os = "linux")]
fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Simplified leap year calculation using the 400-year cycle.
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = is_leap(year);
    let month_lengths: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &ml in &month_lengths {
        if days < ml {
            break;
        }
        days -= ml;
        month += 1;
    }
    (year, month, days + 1)
}

#[cfg(target_os = "linux")]
const fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}
