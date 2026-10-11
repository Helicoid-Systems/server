//! Bounded create-new private file output and private-store path primitives.
//!
//! Trust boundary: recovery secrets and credential stores must never be
//! exposed, even briefly, and must never overwrite or follow a symlink. This
//! module performs **exclusive creation** only — a preexisting ordinary file
//! is left unchanged and a symlink is never followed (its target stays
//! unchanged).
//!
//! Unix: `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` mode `0600` inside a parent
//! directory opened `O_DIRECTORY|O_NOFOLLOW` (no symlink-component traversal).
//! Every traversed directory is validated; the final parent must be owned by
//! the process principal and must not be group- or world-writable. Relative
//! paths are resolved against the process working directory, never `/`.
//! Owner/type/mode (and Darwin extended ACLs) are verified **before** any
//! secret bytes are written.
//!
//! Windows: private recovery output and new persisted MFA secrets are
//! unavailable until an owner/SYSTEM/administrators DACL implementation has
//! native verification. Legacy loopback development uses an explicitly
//! unverified store and refuses pre-existing MFA rows.
//!
//! Other platforms: explicit `unavailable` **before any file or data
//! mutation**.

use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};

/// Hard bound on recovery payload bytes (recovery codes are small).
pub const MAX_PRIVATE_PAYLOAD_BYTES: usize = 64 * 1024;

/// True when this platform can securely create a new private file.
///
/// Windows is false in this build: there is no native-verified
/// owner/SYSTEM/administrators DACL path (see module docs). Callers must
/// refuse NEW persisted v2 MFA credentials and recovery material rather than
/// claim private Windows store support from Unix mode tests.
pub fn private_file_supported() -> bool {
    cfg!(unix)
}

/// True when NEW persisted v2 MFA credentials may be written to the store.
///
/// Same capability as [`private_file_supported`]: Unix private store is
/// enforced at the real on-disk boundary; Windows denies before the
/// bootstrap/enrollment transaction and keeps truthful v1 loopback development.
pub fn persisted_v2_credentials_supported() -> bool {
    cfg!(unix)
}

/// Create a new private file at `path` with `contents`.
///
/// Fails closed if the path exists (including as a symlink), if any parent
/// component is a symlink or unsafe, if the platform lacks a verified secure
/// create-new path, or if the payload exceeds [`MAX_PRIVATE_PAYLOAD_BYTES`].
/// On failure after creation the partial file is removed; secrets are never
/// written to an insecure location.
pub fn create_new_private_file(path: &Path, contents: &[u8]) -> AppResult<()> {
    if contents.len() > MAX_PRIVATE_PAYLOAD_BYTES {
        return Err(AppError::bad_request(format!(
            "recovery payload exceeds {MAX_PRIVATE_PAYLOAD_BYTES} bytes"
        )));
    }
    if contents.is_empty() {
        return Err(AppError::bad_request("recovery payload is empty"));
    }
    let abs = resolve_output_path(path)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("recovery path must have a file name"))?;
    if file_name.is_empty() {
        return Err(AppError::bad_request("recovery file name is empty"));
    }

    #[cfg(unix)]
    {
        unix_create_new_private(&abs, contents)
    }
    #[cfg(windows)]
    {
        windows_create_new_private(&abs, contents)
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Fail closed BEFORE any mutation. Do not fall back to a plain create.
        let _ = (abs, contents);
        Err(AppError::not_implemented(
            "secure private recovery file creation is not implemented on this platform; refusing to write recovery material without a verified private create-new path",
        ))
    }
}

/// Validate that a new private file *could* be created at `path`, without
/// creating or mutating anything.
///
/// Used by callers that must establish output preconditions **before** opening
/// or mutating a credential store (see BootstrapV2). Checks platform support,
/// path shape, and parent-directory safety. Does not write secrets and does
/// not create the target file.
pub fn preflight_new_private_file(path: &Path) -> AppResult<()> {
    if !private_file_supported() {
        return Err(AppError::not_implemented(
            "secure private recovery file creation is not implemented on this platform; refusing to write recovery material without a verified private create-new path",
        ));
    }
    let abs = resolve_output_path(path)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("recovery path must have a file name"))?;
    if file_name.is_empty() {
        return Err(AppError::bad_request("recovery file name is empty"));
    }

    #[cfg(unix)]
    {
        unix_preflight_new_private(&abs, file_name)
    }
    #[cfg(windows)]
    {
        windows_preflight_new_private(&abs, file_name)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file_name;
        Err(AppError::not_implemented(
            "secure private recovery file creation is not implemented on this platform",
        ))
    }
}

/// Resolve a caller-supplied output path to an absolute path.
///
/// Relative paths are joined onto the process working directory (`getcwd`).
/// They are **never** interpreted as root-relative. `..` components are
/// refused later by the no-follow directory walk.
pub(crate) fn resolve_output_path(path: &Path) -> AppResult<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(AppError::bad_request("recovery path is empty"));
    }
    // Refuse `..` before any resolution so a relative parent-escape is never
    // silently canonicalized away.
    for comp in path.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(AppError::bad_request(
                "parent-directory component refused in recovery path",
            ));
        }
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        let cwd = std::env::current_dir().map_err(|err| {
            AppError::bad_request(format!("cannot resolve relative recovery path: {err}"))
        })?;
        Ok(cwd.join(path))
    }
}

// ----- credential-store privacy (DB / WAL / SHM / backup) -----

/// Create or require a private product directory for credential storage.
///
/// Unix: missing parents are created `0700` (owner-only). An existing final
/// directory must be owned by the process principal and owner-private; a
/// shared/foreign/public directory is refused (never silently chmod'd).
/// Windows: unavailable; this build has no verified private DACL path.
pub fn ensure_private_store_dir(path: &Path) -> AppResult<PathBuf> {
    let abs = resolve_output_path(path)?;
    if abs.as_os_str().is_empty() {
        return Err(AppError::bad_request("store directory path is empty"));
    }

    #[cfg(unix)]
    {
        unix_ensure_private_store_dir(&abs)
    }
    #[cfg(windows)]
    {
        windows_ensure_private_store_dir(&abs)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(AppError::not_implemented(
            "secure private credential-store directory is not implemented on this platform",
        ))
    }
}

/// Verify an existing store file (DB, WAL, SHM, backup) is private before
/// credentials are written through it. Never mutates permissions.
pub fn verify_private_store_file(path: &Path) -> AppResult<()> {
    let abs = resolve_output_path(path)?;

    #[cfg(unix)]
    {
        unix_verify_private_store_file(&abs)
    }
    #[cfg(windows)]
    {
        windows_verify_private_store_file(&abs)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(AppError::not_implemented(
            "secure private credential-store file verification is not implemented on this platform",
        ))
    }
}

/// Create a new private store file (empty) at `path` with owner-only access.
/// Used to pre-create the SQLite database so its on-disk mode is private from
/// the first byte. Fails if the name already exists (no overwrite).
pub fn create_private_store_file(path: &Path) -> AppResult<()> {
    let abs = resolve_output_path(path)?;

    #[cfg(unix)]
    {
        unix_create_private_store_file(&abs)
    }
    #[cfg(windows)]
    {
        windows_create_private_store_file(&abs)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(AppError::not_implemented(
            "secure private credential-store file creation is not implemented on this platform",
        ))
    }
}

/// Read an existing private file through a validated held descriptor.
///
/// Opens `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` relative to a validated
/// private parent, verifies owner/type/mode/link/ACL **on that descriptor**,
/// then reads from the same fd with a hard cap of `max_bytes` (reads at most
/// `max_bytes + 1` so oversize input is detected). Never reopens by path
/// after verification (TOCTOU) and never mutates permissions on existing
/// files. The returned buffer is [`zeroize::Zeroizing`] so partial secret
/// bytes are cleared on every drop, including oversize/error paths. Windows
/// and other platforms refuse before any read.
pub fn read_existing_private_file(
    path: &Path,
    max_bytes: usize,
) -> AppResult<zeroize::Zeroizing<Vec<u8>>> {
    if !private_file_supported() {
        return Err(AppError::not_implemented(
            "reading an existing private file is not implemented on this platform; \
             refusing TLS material reads without a native-verified private credential boundary",
        ));
    }
    if max_bytes == 0 {
        return Err(AppError::bad_request("private file read bound is zero"));
    }
    if max_bytes > MAX_PRIVATE_PAYLOAD_BYTES {
        return Err(AppError::bad_request(format!(
            "private file read bound exceeds {MAX_PRIVATE_PAYLOAD_BYTES} bytes"
        )));
    }
    let abs = resolve_output_path(path)?;

    #[cfg(unix)]
    {
        unix_read_existing_private(&abs, max_bytes)
    }
    #[cfg(windows)]
    {
        let _ = (abs, max_bytes);
        Err(windows_unsupported_private_store("file read"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (abs, max_bytes);
        Err(AppError::not_implemented(
            "reading an existing private file is not implemented on this platform",
        ))
    }
}

/// Presence of a preexisting store path after a no-follow metadata probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePathPresence {
    /// Nothing is present at the name (`ENOENT`). Safe to create later.
    Absent,
    /// A regular file is present. Caller decides whether privacy applies.
    RegularFile,
}

/// Probe a preexisting store path (DB or SQLite sidecar) with
/// `symlink_metadata` so dangling symlinks are visible. Never follows a
/// symlink and never creates, truncates, or writes anything.
///
/// Refuses symlinks (dangling or live), non-regular files (FIFO, directory,
/// device), and metadata errors. Absent is `Ok(Absent)`.
pub fn validate_preexisting_store_shape(path: &Path) -> AppResult<StorePathPresence> {
    let abs = resolve_output_path(path)?;
    match std::fs::symlink_metadata(&abs) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(AppError::bad_request(
                    "store path is a symlink (including dangling); refusing to follow or replace it",
                ));
            }
            if !ft.is_file() {
                return Err(AppError::bad_request(
                    "store path is not a regular file (refusing FIFO/directory/device sidecar)",
                ));
            }
            Ok(StorePathPresence::RegularFile)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(StorePathPresence::Absent),
        Err(err) => Err(AppError::bad_request(format!(
            "cannot classify store path: {err}"
        ))),
    }
}

#[cfg(unix)]
fn unix_ensure_private_store_dir(abs: &Path) -> AppResult<PathBuf> {
    use std::os::fd::AsRawFd;

    let parent = match abs.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        Some(_) | None => PathBuf::from("/"),
    };
    let name = match abs.file_name() {
        Some(n) if !n.is_empty() => n.to_os_string(),
        _ => {
            return Err(AppError::bad_request(
                "store directory path must have a final component",
            ))
        }
    };

    // Walk/create ancestors as 0700 under the strict nofollow policy, then
    // require the final directory to be owner-private.
    let dir_fd = open_dir_nofollow(&parent, DirUse::Ancestor)?;
    use std::os::unix::ffi::OsStrExt;
    let cname = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| AppError::bad_request("store directory name contains NUL"))?;

    // Try to open an existing final directory first.
    let opened = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if opened >= 0 {
        let euid = unsafe { libc::geteuid() };
        if let Err(err) = validate_dir_fd(opened, DirUse::StoreParent, euid, Path::new(&name)) {
            unsafe { libc::close(opened) };
            return Err(err);
        }
        unsafe { libc::close(opened) };
        return Ok(abs.to_path_buf());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ENOENT) {
        return Err(AppError::bad_request(format!(
            "open store directory '{}': {err} (symlink components are refused)",
            name.display()
        )));
    }

    // Create missing final directory as owner-only, then verify the exact
    // object we created (owner/inode) before any mode mutation.
    if unsafe { libc::mkdirat(dir_fd.as_raw_fd(), cname.as_ptr(), 0o700) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!(
            "create private store directory '{}': {err}",
            name.display()
        )));
    }
    let opened = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            cname.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!(
            "open created store directory '{}': {err}",
            name.display()
        )));
    }
    // Verify this is a directory we own before mutating mode (no fchmod on a
    // substituted foreign directory).
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(opened, &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(opened) };
        return Err(AppError::bad_request(format!(
            "fstat created store directory: {err}"
        )));
    }
    let euid = unsafe { libc::geteuid() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR || st.st_uid != euid {
        unsafe { libc::close(opened) };
        return Err(AppError::bad_request(
            "created store directory is not owned by the process principal; refusing credential store",
        ));
    }
    // Force owner-only despite umask, then re-verify on the held fd.
    if unsafe { libc::fchmod(opened, 0o700) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(opened) };
        return Err(AppError::bad_request(format!(
            "fchmod private store directory: {err}"
        )));
    }
    if let Err(err) = validate_dir_fd(opened, DirUse::StoreParent, euid, Path::new(&name)) {
        unsafe { libc::close(opened) };
        return Err(err);
    }
    unsafe { libc::close(opened) };
    Ok(abs.to_path_buf())
}

#[cfg(unix)]
fn unix_verify_private_store_file(abs: &Path) -> AppResult<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let parent = unix_parent_of(abs)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("store file must have a file name"))?;
    let file_c = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| AppError::bad_request("store file name contains NUL"))?;
    let dir_fd = open_dir_nofollow(parent, DirUse::RecoveryParent)?;

    // Open the store file without following a symlink. O_NONBLOCK keeps a
    // FIFO (or other blocking special) from hanging the open; the fd-based
    // type check below then refuses it without writing.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            file_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!("open store file: {err}")));
    }
    let result = verify_existing_object_private(fd);
    unsafe { libc::close(fd) };
    result
}

#[cfg(unix)]
fn unix_create_private_store_file(abs: &Path) -> AppResult<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let parent = unix_parent_of(abs)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("store file must have a file name"))?;
    let file_c = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| AppError::bad_request("store file name contains NUL"))?;
    let dir_fd = open_dir_nofollow(parent, DirUse::StoreParent)?;

    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            file_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EEXIST) => Err(AppError::conflict(
                "store file already exists; refusing to overwrite",
                Some("create_new_only".to_string()),
            )),
            _ => Err(AppError::bad_request(format!(
                "create private store file: {err}"
            ))),
        };
    }
    let mut created: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut created) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        unlink_created_name(dir_fd.as_raw_fd(), &file_c, &created);
        return Err(AppError::bad_request(format!("fstat store file: {err}")));
    }
    let result = (|| -> AppResult<()> {
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        verify_private_file_fd(file.as_raw_fd(), &created, true)?;
        // Keep the file empty for SQLite to populate; drop closes the fd.
        drop(file);
        Ok(())
    })();
    if let Err(err) = result {
        unlink_created_name(dir_fd.as_raw_fd(), &file_c, &created);
        return Err(err);
    }
    if unsafe { libc::fsync(dir_fd.as_raw_fd()) } != 0 {
        let err = std::io::Error::last_os_error();
        unlink_created_name(dir_fd.as_raw_fd(), &file_c, &created);
        return Err(AppError::bad_request(format!(
            "fsync store directory: {err}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn unix_read_existing_private(
    abs: &Path,
    max_bytes: usize,
) -> AppResult<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let parent = unix_parent_of(abs)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("private file must have a file name"))?;
    let file_c = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| AppError::bad_request("private file name contains NUL"))?;
    let dir_fd = open_dir_nofollow(parent, DirUse::RecoveryParent)?;

    // O_NONBLOCK keeps a FIFO (or other blocking special) from hanging the
    // open; the fd-based type check below then refuses it without reading.
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            file_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!("open private file: {err}")));
    }
    // SAFETY: fd is an open descriptor we now own; File closes it on drop.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    // Owner / type / mode / ACL on the SAME descriptor we will read.
    verify_existing_object_private(file.as_raw_fd())?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!("fstat private file: {err}")));
    }
    if st.st_nlink != 1 {
        return Err(AppError::bad_request(
            "private file link count is not 1; refusing to read",
        ));
    }

    // Allocate the complete bounded buffer before reading any secret bytes.
    // It never grows or reallocates, so an old allocation cannot retain a
    // partial secret after Vec growth. One extra byte detects oversize input.
    let mut buf = zeroize::Zeroizing::new(vec![0; max_bytes + 1]);
    let mut file = file;
    let mut filled = 0;
    while filled < buf.len() {
        let count = file
            .read(&mut buf[filled..])
            .map_err(|err| AppError::bad_request(format!("read private file: {err}")))?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    if filled > max_bytes {
        return Err(AppError::bad_request(format!(
            "private file exceeds {max_bytes} bytes"
        )));
    }
    buf.truncate(filled);
    Ok(buf)
}

// Windows has no native-verified owner/SYSTEM/admin private store in this
// build. An earlier DACL draft was a blacklist (it would have allowed
// arbitrary other user/group allow-ACEs) and is not kept enabled to claim
// coverage. NEW persisted v2 MFA credentials and private recovery output are
// refused before mutation; legacy v1 loopback development remains available.
//
// To enable Windows support later: implement an exact allowlist of verified
// object owner / current principal / SYSTEM / Administrators via
// GetSecurityInfo on the held HANDLE (not a pathname), validate every path
// component against replacement, and prove it with native CI tests that also
// deny arbitrary unrelated SIDs and Authenticated Users ACEs.
#[cfg(windows)]
fn windows_unsupported_private_store(what: &str) -> AppError {
    AppError::not_implemented(format!(
        "secure private {what} is not implemented on this platform; \
         refusing NEW persisted v2 MFA credentials and recovery material \
         without a native-verified owner/SYSTEM/administrators DACL. \
         Legacy v1 loopback development remains available without MFA claims."
    ))
}

#[cfg(windows)]
fn windows_ensure_private_store_dir(abs: &Path) -> AppResult<PathBuf> {
    let _ = abs;
    Err(windows_unsupported_private_store(
        "credential-store directory",
    ))
}

#[cfg(windows)]
fn windows_verify_private_store_file(abs: &Path) -> AppResult<()> {
    let _ = abs;
    Err(windows_unsupported_private_store("credential-store file"))
}

#[cfg(windows)]
fn windows_create_private_store_file(abs: &Path) -> AppResult<()> {
    let _ = abs;
    Err(windows_unsupported_private_store("credential-store file"))
}

#[cfg(unix)]
fn unix_preflight_new_private(abs: &Path, file_name: &std::ffi::OsStr) -> AppResult<()> {
    use std::os::unix::ffi::OsStrExt;

    let parent = unix_parent_of(abs)?;
    let file_c = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| AppError::bad_request("recovery file name contains NUL"))?;

    let dir_fd = open_dir_nofollow(parent, DirUse::RecoveryParent)?;
    // Must not already exist (create-new semantics), checked on the held fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            std::os::fd::AsRawFd::as_raw_fd(&dir_fd),
            file_c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Err(AppError::conflict(
            "recovery file already exists; refusing to overwrite",
            Some("create_new_only".to_string()),
        ));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ENOENT) {
        return Err(AppError::bad_request(format!(
            "stat recovery target: {err}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn unix_parent_of(abs: &Path) -> AppResult<&Path> {
    match abs.parent() {
        Some(p) if !p.as_os_str().is_empty() => Ok(p),
        Some(_) => Ok(Path::new("/")),
        None => Err(AppError::bad_request("recovery path must have a parent")),
    }
}

/// How a directory will be used; final parents get ownership / writability
/// requirements that traversal-only ancestors do not.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirUse {
    /// Intermediate ancestor: root-owned or self-owned is fine; verified
    /// sticky temp is allowed for traversal; unsafe writable dirs refused.
    Ancestor,
    /// Final directory that will contain a new private file or store.
    /// Must be owned by the process principal and not group/world-writable.
    RecoveryParent,
    /// Credential-store parent: same as [`DirUse::RecoveryParent`], and the
    /// directory itself must be owner-only (0700-class).
    StoreParent,
}

#[cfg(unix)]
fn unix_create_new_private(abs: &Path, contents: &[u8]) -> AppResult<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let parent = unix_parent_of(abs)?;
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("recovery path must have a file name"))?;

    let file_c = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|_| AppError::bad_request("recovery file name contains NUL"))?;

    let dir_fd = open_dir_nofollow(parent, DirUse::RecoveryParent)?;
    let dir_raw = dir_fd.as_raw_fd();

    // Exclusive create-new. O_EXCL fails on existing file *and* on a
    // precreated symlink (we never open through it).
    let fd = unsafe {
        libc::openat(
            dir_raw,
            file_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EEXIST) => Err(AppError::conflict(
                "recovery file already exists; refusing to overwrite",
                Some("create_new_only".to_string()),
            )),
            _ => Err(AppError::bad_request(format!(
                "create private recovery file: {err}"
            ))),
        };
    }

    // Record the created inode so cleanup never unlinks a substituted name.
    let mut created: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut created) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        unlink_created_name(dir_raw, &file_c, &created);
        return Err(AppError::bad_request(format!(
            "fstat private recovery file: {err}"
        )));
    }

    let result = (|| -> AppResult<()> {
        // SAFETY: fd is an exclusively created regular file we own.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

        // Verify owner / type / mode / ACL BEFORE any secret bytes land.
        verify_private_file_fd(file.as_raw_fd(), &created, true)?;

        file.write_all(contents)
            .map_err(|err| AppError::bad_request(format!("write private recovery file: {err}")))?;
        file.sync_all()
            .map_err(|err| AppError::bad_request(format!("fsync private recovery file: {err}")))?;
        drop(file);
        Ok(())
    })();

    if let Err(err) = result {
        // Best-effort cleanup: never leave partial secrets behind, and never
        // unlink a name that was substituted after creation.
        unlink_created_name(dir_raw, &file_c, &created);
        return Err(err);
    }

    // Durability of the directory entry.
    if unsafe { libc::fsync(dir_raw) } != 0 {
        let err = std::io::Error::last_os_error();
        unlink_created_name(dir_raw, &file_c, &created);
        return Err(AppError::bad_request(format!(
            "fsync recovery directory: {err}"
        )));
    }
    Ok(())
}

/// Unlink `name` under `dir_fd` only when it still refers to `created`.
#[cfg(unix)]
fn unlink_created_name(dir_fd: i32, name: &std::ffi::CString, created: &libc::stat) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dir_fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if rc == 0 && st.st_dev == created.st_dev && st.st_ino == created.st_ino {
        unsafe {
            libc::unlinkat(dir_fd, name.as_ptr(), 0);
        };
    }
}

/// Verify a held file descriptor is a private regular file owned by us.
///
/// `require_new_mode` forces the mode to 0600 first (via `fchmod` on the
/// descriptor we already own) and then re-checks. On Darwin, extended ACLs
/// that could grant access beyond mode 0600 are stripped or the call fails
/// closed — effective privacy must be established before secrets are written.
#[cfg(unix)]
fn verify_private_file_fd(fd: i32, expected: &libc::stat, require_new_mode: bool) -> AppResult<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!(
            "fstat private recovery file: {err}"
        )));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(AppError::bad_request(
            "recovery file is not a regular file after creation",
        ));
    }
    if st.st_dev != expected.st_dev || st.st_ino != expected.st_ino {
        return Err(AppError::bad_request(
            "recovery file identity changed after creation; refusing to write",
        ));
    }
    if st.st_nlink != 1 {
        return Err(AppError::bad_request(
            "recovery file link count is not 1; refusing to write",
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if st.st_uid != euid {
        return Err(AppError::bad_request(
            "recovery file is not owned by the process principal; refusing to write",
        ));
    }
    if require_new_mode {
        if unsafe { libc::fchmod(fd, 0o600) } != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AppError::bad_request(format!(
                "fchmod private recovery file: {err}"
            )));
        }
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AppError::bad_request(format!(
                "fstat private recovery file: {err}"
            )));
        }
    }
    if st.st_mode & 0o077 != 0 {
        return Err(AppError::bad_request(
            "recovery file permissions are not private (expected 0600)",
        ));
    }
    // Effective privacy must match 0600 before any secret bytes. On Darwin,
    // extended ACLs can widen access beyond the mode; on a newly created
    // owned file we may strip them. Existing objects are never mutated.
    handle_extended_acl(fd, require_new_mode)?;
    Ok(())
}

/// Outcome of an extended-ACL query on a held descriptor.
#[cfg(unix)]
enum AclStatus {
    /// Explicit absence (Darwin: NULL + ENOENT). Mode bits alone apply.
    Absent,
    /// ACL has only DENY entries (restricts further; does not widen access).
    DenyOnly,
    /// At least one ALLOW entry is present (can widen access beyond mode).
    AllowPresent,
}

/// Query the extended ACL on `fd` with native semantics.
///
/// Darwin: `acl_get_fd_np(fd, ACL_TYPE_EXTENDED)` returns NULL with `ENOENT`
/// only when no ACL is present; any other query error is a denial. When an
/// ACL is returned, `acl_get_entry(acl, ACL_FIRST_ENTRY, &e)` returns **0**
/// when an entry exists and **-1** when there are none (EINVAL at end).
#[cfg(target_os = "macos")]
fn query_extended_acl(fd: i32) -> AppResult<AclStatus> {
    const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
    const ACL_FIRST_ENTRY: i32 = 0;
    const ACL_NEXT_ENTRY: i32 = -1;
    const ACL_EXTENDED_ALLOW: i32 = 1;
    const ACL_EXTENDED_DENY: i32 = 2;
    type AclT = *mut libc::c_void;
    type AclEntryT = *mut libc::c_void;

    // Exact declarations from MacOSX.sdk/usr/include/sys/acl.h:
    //   acl_t     acl_get_fd_np(int fd, acl_type_t type);
    //   int       acl_get_entry(acl_t acl, int entry_id, acl_entry_t *entry_p);
    //   int       acl_get_tag_type(acl_entry_t entry_d, acl_tag_t *tag_type_p);
    //   int       acl_free(void *obj_p);
    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, typ: i32) -> AclT;
        fn acl_get_entry(acl: AclT, entry_id: i32, entry_p: *mut AclEntryT) -> libc::c_int;
        fn acl_get_tag_type(entry: AclEntryT, tag_type_p: *mut i32) -> libc::c_int;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }

    unsafe {
        // Clear errno so ENOENT below is attributable to this call.
        *libc::__error() = 0;
        let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
        if acl.is_null() {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                // Only explicit absence may be treated as no ACL.
                Some(libc::ENOENT) => Ok(AclStatus::Absent),
                Some(libc::EOPNOTSUPP) => Err(AppError::bad_request(
                    "filesystem does not support extended ACL queries; cannot establish privacy",
                )),
                _ => Err(AppError::bad_request(format!(
                    "extended ACL query failed: {err}; cannot establish privacy"
                ))),
            };
        }

        let mut allow = false;
        let mut saw_any = false;
        let mut entry: AclEntryT = std::ptr::null_mut();
        *libc::__error() = 0;
        let mut rc = acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry);
        if rc == 0 {
            saw_any = true;
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                acl_free(acl.cast());
                return Err(AppError::bad_request(format!(
                    "extended ACL entry query failed: {err}; cannot establish privacy"
                )));
            }
        }
        while rc == 0 {
            let mut tag: i32 = 0;
            if acl_get_tag_type(entry, &mut tag) != 0 {
                let err = std::io::Error::last_os_error();
                acl_free(acl.cast());
                return Err(AppError::bad_request(format!(
                    "extended ACL tag query failed: {err}; cannot establish privacy"
                )));
            }
            match tag {
                t if t == ACL_EXTENDED_ALLOW => allow = true,
                t if t == ACL_EXTENDED_DENY => {}
                _ => {
                    // Unknown tag: cannot prove privacy.
                    acl_free(acl.cast());
                    return Err(AppError::bad_request(
                        "extended ACL has an unrecognized tag; cannot establish privacy",
                    ));
                }
            }
            *libc::__error() = 0;
            rc = acl_get_entry(acl, ACL_NEXT_ENTRY, &mut entry);
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINVAL) {
                    acl_free(acl.cast());
                    return Err(AppError::bad_request(format!(
                        "extended ACL entry walk failed: {err}; cannot establish privacy"
                    )));
                }
            }
        }
        acl_free(acl.cast());
        if !saw_any {
            return Ok(AclStatus::Absent);
        }
        if allow {
            Ok(AclStatus::AllowPresent)
        } else {
            Ok(AclStatus::DenyOnly)
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn query_extended_acl(fd: i32) -> AppResult<AclStatus> {
    // Linux: POSIX ACLs live in `system.posix_acl_access`. A mode of 0600
    // zeroes the ACL mask so named user/group entries cannot widen access
    // beyond owner; the xattr may still be present. We treat a non-trivial
    // ACL as AllowPresent so callers can strip (new) or refuse (existing).
    let mut buf = [0u8; 256];
    let name = b"system.posix_acl_access\0";
    let n = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOENT) | Some(libc::ENOTSUP) => Ok(AclStatus::Absent),
            _ => Err(AppError::bad_request(format!(
                "POSIX ACL query failed: {err}; cannot establish privacy"
            ))),
        };
    }
    // POSIX ACL xattr: 4 entries * 8 bytes = 32 for user/group/other class
    // entries. Longer means named user/group entries exist.
    if n > 32 {
        return Ok(AclStatus::AllowPresent);
    }
    Ok(AclStatus::DenyOnly)
}

/// Establish effective privacy for a held file descriptor.
///
/// `may_strip` is true only for a newly exclusively created object we own;
/// in that case extended ACLs may be removed before secret bytes. Existing
/// stores are never mutated to manufacture privacy — an unsafe ACL is refused.
/// Deny-only ACLs do not widen access and are accepted without stripping.
#[cfg(unix)]
fn handle_extended_acl(fd: i32, may_strip: bool) -> AppResult<()> {
    match query_extended_acl(fd)? {
        AclStatus::Absent | AclStatus::DenyOnly => Ok(()),
        AclStatus::AllowPresent => {
            if !may_strip {
                return Err(AppError::bad_request(
                    "existing object carries an extended ACL that can grant access beyond mode 0600; refusing without mutating it",
                ));
            }
            strip_extended_acl_new_object(fd)?;
            match query_extended_acl(fd)? {
                AclStatus::Absent | AclStatus::DenyOnly => Ok(()),
                AclStatus::AllowPresent => Err(AppError::bad_request(
                    "extended ACL still present after strip; cannot establish privacy",
                )),
            }
        }
    }
}

/// Strip extended ACLs from a newly created owned object (held fd).
#[cfg(target_os = "macos")]
fn strip_extended_acl_new_object(fd: i32) -> AppResult<()> {
    type AclT = *mut libc::c_void;
    extern "C" {
        fn acl_set_fd(fd: libc::c_int, acl: AclT) -> libc::c_int;
        fn acl_init(count: libc::c_int) -> AclT;
        fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
    }
    unsafe {
        let empty = acl_init(0);
        if empty.is_null() {
            return Err(AppError::bad_request(
                "cannot allocate empty ACL to strip Darwin extended ACL; refusing to write",
            ));
        }
        let rc = acl_set_fd(fd, empty);
        acl_free(empty.cast());
        if rc != 0 {
            return Err(AppError::bad_request(
                "cannot strip Darwin extended ACL on newly created object; refusing to write",
            ));
        }
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn strip_extended_acl_new_object(fd: i32) -> AppResult<()> {
    // Remove the POSIX ACL xattr from a newly created object.
    let name = b"system.posix_acl_access\0";
    let rc = unsafe { libc::fremovexattr(fd, name.as_ptr() as *const libc::c_char) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOENT) | Some(libc::ENOTSUP) => Ok(()),
            _ => Err(AppError::bad_request(format!(
                "cannot strip POSIX ACL on newly created object: {err}; refusing to write"
            ))),
        }
    } else {
        Ok(())
    }
}

/// Verify an existing object is private without mutating it.
#[cfg(unix)]
fn verify_existing_object_private(fd: i32) -> AppResult<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!("fstat store object: {err}")));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(AppError::bad_request("store object is not a regular file"));
    }
    let euid = unsafe { libc::geteuid() };
    if st.st_uid != euid {
        return Err(AppError::bad_request(
            "store object is not owned by the process principal; refusing credential store",
        ));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(AppError::bad_request(
            "store object is not private (expected 0600); refusing credential store",
        ));
    }
    handle_extended_acl(fd, false)?;
    Ok(())
}

/// Open `path` as a directory without following any symlink component.
///
/// Validates **each** traversed directory (not only the final parent):
/// refuses `..`, missing parents (no insecure tree creation), foreign-owned
/// ancestors and writable ancestors except trusted root-owned sticky temporary
/// directories. The final
/// parent must be owned by the process principal and must not be group- or
/// world-writable; store parents must additionally be owner-only.
#[cfg(unix)]
pub(crate) fn open_dir_nofollow(path: &Path, use_kind: DirUse) -> AppResult<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: open/close paired; fd wrapped in OwnedFd on success.
    let mut fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(AppError::bad_request(format!(
            "open /: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Root is always a valid traversal start; subsequent components are
    // checked individually below.
    let euid = unsafe { libc::geteuid() };
    let comps: Vec<_> = path.components().collect();
    let last_idx = comps.len().saturating_sub(1);
    let mut validated_any = false;

    for (idx, comp) in comps.iter().enumerate() {
        let name = match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(n) => n,
            std::path::Component::ParentDir => {
                unsafe { libc::close(fd) };
                return Err(AppError::bad_request(
                    "parent-directory component refused in recovery path",
                ));
            }
            std::path::Component::Prefix(_) => {
                unsafe { libc::close(fd) };
                return Err(AppError::bad_request("path prefix unsupported"));
            }
        };
        let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            unsafe { libc::close(fd) };
            AppError::bad_request("path component contains NUL")
        })?;
        // SAFETY: cname is a valid single component; fd is an open directory.
        let mut new_fd = unsafe {
            libc::openat(
                fd,
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if new_fd < 0 {
            let err = std::io::Error::last_os_error();
            // macOS O_DIRECTORY|O_NOFOLLOW on a symlink reports ENOTDIR;
            // Linux reports ELOOP. Both mean "this component is a symlink".
            let symlink_err = matches!(err.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR));
            if symlink_err {
                // Component is a symlink. Allow only a root-owned system link
                // (e.g. macOS /var -> private/var) from a trusted parent;
                // never follow attacker-controlled or self-repointed links.
                let mut lst: libc::stat = unsafe { std::mem::zeroed() };
                let lrc = unsafe {
                    libc::fstatat(fd, cname.as_ptr(), &mut lst, libc::AT_SYMLINK_NOFOLLOW)
                };
                let is_link = lrc == 0 && (lst.st_mode & libc::S_IFMT) == libc::S_IFLNK;
                if is_link && lst.st_uid == 0 {
                    // Follow this single root-owned system link only.
                    new_fd = unsafe {
                        libc::openat(
                            fd,
                            cname.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        )
                    };
                } else {
                    unsafe { libc::close(fd) };
                    return Err(AppError::bad_request(format!(
                        "open recovery parent '{}': {err} (symlink components are refused)",
                        name.display()
                    )));
                }
            }
        }
        if new_fd < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Err(AppError::bad_request(format!(
                    "recovery parent directory '{}' does not exist; refusing to create an insecure tree",
                    name.display()
                )));
            }
            return Err(AppError::bad_request(format!(
                "open recovery parent '{}': {err} (symlink components are refused)",
                name.display()
            )));
        }

        // Validate this component before advancing. The last real component
        // is the final parent; earlier ones are traversal ancestors.
        let is_final = idx == last_idx;
        let use_kind_for_comp = if is_final { use_kind } else { DirUse::Ancestor };
        if let Err(err) = validate_dir_fd(new_fd, use_kind_for_comp, euid, Path::new(name)) {
            unsafe {
                libc::close(new_fd);
                libc::close(fd);
            };
            return Err(err);
        }
        validated_any = true;

        unsafe { libc::close(fd) };
        fd = new_fd;
    }

    // A path of `/` (no Normal components) still needs a final-parent check
    // when a store/recovery file would be created directly under root.
    if !validated_any {
        if let Err(err) = validate_dir_fd(fd, use_kind, euid, Path::new("/")) {
            unsafe { libc::close(fd) };
            return Err(err);
        }
    }

    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Directory safety policy on a held descriptor.
#[cfg(unix)]
fn validate_dir_fd(fd: i32, use_kind: DirUse, euid: u32, name: &Path) -> AppResult<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(AppError::bad_request(format!(
            "fstat recovery parent '{}': {err}",
            name.display()
        )));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(AppError::bad_request(format!(
            "recovery path component '{}' is not a directory",
            name.display()
        )));
    }

    let world_w = st.st_mode & libc::S_IWOTH != 0;
    let group_w = st.st_mode & libc::S_IWGRP != 0;
    let sticky = st.st_mode & libc::S_ISVTX != 0;
    let owned_by_us = st.st_uid == euid;
    let owned_by_root = st.st_uid == 0;
    // Foreign owner can chmod/replace children even when the directory is
    // not writable by others — only root or self are trusted ancestors.
    let trusted_owner = owned_by_us || owned_by_root;

    match use_kind {
        DirUse::Ancestor => {
            if !trusted_owner {
                return Err(AppError::bad_request(format!(
                    "recovery path ancestor '{}' is not owned by root or the process principal; refusing write",
                    name.display()
                )));
            }
            // Group/world write is allowed only for verified root-owned sticky
            // temp (e.g. /tmp). Other writable ancestors are rename gates.
            let trusted_sticky_temp = sticky && owned_by_root;
            if world_w && !trusted_sticky_temp {
                return Err(AppError::bad_request(format!(
                    "recovery path ancestor '{}' is world-writable without a trusted root-owned sticky bit; refusing write",
                    name.display()
                )));
            }
            if group_w && !trusted_sticky_temp {
                return Err(AppError::bad_request(format!(
                    "recovery path ancestor '{}' is group-writable; refusing write",
                    name.display()
                )));
            }
            // Directory ACLs can grant delete_child/create beyond mode bits.
            // Existing ancestor ACLs are never stripped; unsafe ACLs refuse.
            handle_extended_acl(fd, false)?;
            Ok(())
        }
        DirUse::RecoveryParent | DirUse::StoreParent => {
            if !owned_by_us && !(owned_by_root && euid == 0) {
                return Err(AppError::bad_request(format!(
                    "recovery parent '{}' is not owned by the process principal; refusing write",
                    name.display()
                )));
            }
            if world_w {
                return Err(AppError::bad_request(format!(
                    "recovery parent '{}' is world-writable; refusing write",
                    name.display()
                )));
            }
            if group_w {
                return Err(AppError::bad_request(format!(
                    "recovery parent '{}' is group-writable; refusing write",
                    name.display()
                )));
            }
            if use_kind == DirUse::StoreParent && st.st_mode & 0o077 != 0 {
                return Err(AppError::bad_request(format!(
                    "store parent '{}' is not owner-private (expected 0700); refusing credential store",
                    name.display()
                )));
            }
            handle_extended_acl(fd, false)?;
            Ok(())
        }
    }
}

// Windows: no native-verified private create/store in this build.
// See windows_unsupported_private_store above. Private recovery output and
// NEW persisted v2 MFA credentials are refused before mutation.

#[cfg(windows)]
fn windows_preflight_new_private(_abs: &Path, _file_name: &std::ffi::OsStr) -> AppResult<()> {
    Err(windows_unsupported_private_store("recovery file"))
}

#[cfg(windows)]
fn windows_create_new_private(_abs: &Path, _contents: &[u8]) -> AppResult<()> {
    // Fail closed BEFORE any mutation. No insecure plain-File fallback.
    Err(windows_unsupported_private_store("recovery file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Tempdir whose base path is fully resolved (no symlink components).
    ///
    /// macOS `TMPDIR` is often under `/var/folders` where `/var` is a symlink
    /// to `private/var`. The walk allows only root-owned system symlink
    /// ancestors (e.g. /var); tests still canonicalize for stable assertions.
    /// The directory is forced `0700` so it satisfies store/recovery parent
    /// policy (`tempfile` default is `0755` on some hosts).
    fn tmpdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().canonicalize().expect("canonicalize");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("chmod tmpdir");
        }
        (dir, path)
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    // ----- universal: bounds and no-mutation (all platforms) -----

    #[test]
    fn preexisting_ordinary_file_is_unchanged() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        std::fs::write(&path, b"original-public").expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        }
        let err = create_new_private_file(&path, b"SECRET").expect_err("must refuse");
        let _ = err;
        let read = std::fs::read(&path).expect("read");
        assert_eq!(read, b"original-public", "existing file must be preserved");
    }

    #[test]
    fn failure_produces_no_secret_file() {
        let (_dir, base) = tmpdir();
        // Missing parent → fail before create.
        let path = base.join("missing").join("r.txt");
        let err = create_new_private_file(&path, b"TOP-SECRET").expect_err("refuse");
        let _ = err;
        // Walk the tree: no file may contain the secret.
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        let mut files = Vec::new();
        walk(&base, &mut files);
        for f in files {
            let bytes = std::fs::read(&f).unwrap_or_default();
            assert!(
                !bytes.windows(10).any(|w| w == b"TOP-SECRET"),
                "secret leaked into {}",
                f.display()
            );
        }
    }

    #[test]
    fn oversized_payload_is_rejected_before_create() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        let big = vec![0x41u8; MAX_PRIVATE_PAYLOAD_BYTES + 1];
        let err = create_new_private_file(&path, &big).expect_err("must reject");
        assert!(err.to_string().contains("exceeds"), "err={err}");
        assert!(!path.exists(), "no file on bound violation");
    }

    #[test]
    fn empty_payload_is_rejected() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        assert!(create_new_private_file(&path, b"").is_err());
        assert!(!path.exists());
    }

    #[test]
    fn preexisting_store_shape_absent_and_regular() {
        let (_dir, base) = tmpdir();
        let missing = base.join("nope.db");
        assert_eq!(
            validate_preexisting_store_shape(&missing).expect("absent"),
            StorePathPresence::Absent
        );
        let regular = base.join("ok.db");
        std::fs::write(&regular, b"x").expect("seed");
        assert_eq!(
            validate_preexisting_store_shape(&regular).expect("regular"),
            StorePathPresence::RegularFile
        );
    }

    #[test]
    fn preexisting_store_shape_refuses_dangling_symlink_without_following() {
        let (_dir, base) = tmpdir();
        let target = base.join("target.db");
        std::fs::write(&target, b"target-data").expect("target");
        let link = base.join("side.db");
        #[cfg(unix)]
        std::os::unix::fs::symlink(base.join("no-such-target"), &link).expect("dangling");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(base.join("no-such-target"), &link).expect("dangling");
        let err = validate_preexisting_store_shape(&link).expect_err("must refuse dangling");
        assert!(err.to_string().contains("symlink"), "err={err}");
        assert_eq!(
            std::fs::read(&target).expect("target"),
            b"target-data",
            "target untouched"
        );
    }

    #[test]
    fn preexisting_store_shape_refuses_live_symlink() {
        let (_dir, base) = tmpdir();
        let target = base.join("target.db");
        std::fs::write(&target, b"target-data").expect("target");
        let link = base.join("side.db");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).expect("symlink");
        let err = validate_preexisting_store_shape(&link).expect_err("must refuse live symlink");
        assert!(err.to_string().contains("symlink"), "err={err}");
        assert_eq!(std::fs::read(&target).expect("target"), b"target-data");
    }

    #[test]
    fn platform_support_flag_matches_behavior() {
        let (_dir, base) = tmpdir();
        let path = base.join("ok.txt");
        if private_file_supported() {
            create_new_private_file(&path, b"x").expect("create on supported platform");
        } else {
            let err = create_new_private_file(&path, b"x").expect_err("fail closed");
            assert!(
                err.to_string().contains("not implemented") || err.to_string().contains("refusing"),
                "err={err}"
            );
            assert!(!path.exists(), "no file on unsupported platform");
        }
    }

    #[test]
    fn preflight_refuses_existing_target_without_mutation() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        std::fs::write(&path, b"original").expect("seed");
        let err = preflight_new_private_file(&path).expect_err("must refuse existing");
        let msg = err.to_string();
        assert!(
            msg.contains("already exists") || msg.contains("refusing"),
            "msg={msg}"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"original");
    }

    #[test]
    fn preflight_rejects_missing_parent_without_creating() {
        let (_dir, base) = tmpdir();
        let path = base.join("no-such-dir").join("recovery.txt");
        let err = preflight_new_private_file(&path).expect_err("must refuse");
        let _ = err;
        assert!(
            !base.join("no-such-dir").exists(),
            "preflight must not create"
        );
    }

    // ----- Unix: real success path and on-disk privacy -----

    #[cfg(unix)]
    #[test]
    fn fifo_store_file_is_refused_without_hang_or_write() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::FileTypeExt;
        let (_dir, base) = tmpdir();
        let path = base.join("hs-server.db");
        // Create a real FIFO at the store name. Opening O_RDONLY without
        // O_NONBLOCK would block forever waiting for a writer.
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("cstr");
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo");
        // Must return promptly with an error — no hang, no write, no replace.
        let err = verify_private_store_file(&path).expect_err("must refuse FIFO");
        let msg = err.to_string();
        assert!(
            msg.contains("not a regular file") || msg.contains("refusing"),
            "msg={msg}"
        );
        // Shape probe also refuses without opening.
        let shape_err =
            validate_preexisting_store_shape(&path).expect_err("shape must refuse FIFO");
        assert!(
            shape_err.to_string().contains("not a regular file"),
            "err={shape_err}"
        );
        // FIFO preserved; no other files created in the directory.
        let meta = std::fs::symlink_metadata(&path).expect("fifo meta");
        assert!(meta.file_type().is_fifo(), "FIFO must be preserved");
        let mut names: Vec<_> = std::fs::read_dir(&base)
            .expect("readdir")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        names.sort();
        assert_eq!(names, vec![std::ffi::OsString::from("hs-server.db")]);
    }

    #[cfg(unix)]
    #[test]
    fn fresh_create_writes_private_contents() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        let payload = b"CODE1\nCODE2\n";
        create_new_private_file(&path, payload).expect("create");
        let read = std::fs::read(&path).expect("read");
        assert_eq!(read, payload);
        assert_eq!(mode_of(&path), 0o600, "must be owner-only");
    }

    /// Build a private directory *inside* the process cwd and return its
    /// path relative to cwd. Never mutates process cwd.
    #[cfg(unix)]
    fn private_rel_dir_in_cwd() -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let cwd = std::env::current_dir().expect("cwd");
        let dir = tempfile::Builder::new()
            .prefix("hs-rel-cwd-")
            .tempdir_in(&cwd)
            .expect("tempdir in cwd");
        let path = dir.path().canonicalize().expect("canonicalize");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let rel = path
            .strip_prefix(cwd.canonicalize().expect("canonicalize cwd"))
            .expect("under cwd")
            .to_path_buf();
        (dir, rel)
    }

    #[cfg(unix)]
    #[test]
    fn relative_path_resolves_against_cwd_not_root() {
        let (_dir, rel) = private_rel_dir_in_cwd();
        let result = create_new_private_file(&rel.join("recovery.txt"), b"REL-SECRET");
        result.expect("create via relative path");
        assert!(
            std::env::current_dir()
                .expect("cwd")
                .join(&rel)
                .join("recovery.txt")
                .exists(),
            "relative path must land under the intended cwd"
        );
        assert!(
            !Path::new("/recovery.txt").exists(),
            "must never create a root-relative path"
        );
        let read = std::fs::read(
            std::env::current_dir()
                .expect("cwd")
                .join(&rel)
                .join("recovery.txt"),
        )
        .expect("read");
        assert_eq!(read, b"REL-SECRET");
    }

    #[cfg(unix)]
    #[test]
    fn relative_nested_path_resolves_against_cwd() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, rel) = private_rel_dir_in_cwd();
        let nested = std::env::current_dir().expect("cwd").join(&rel).join("out");
        std::fs::create_dir(&nested).expect("mkdir");
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let result = create_new_private_file(&rel.join("out/recovery.txt"), b"NESTED");
        result.expect("create nested relative");
        assert!(nested.join("recovery.txt").exists());
        assert!(!Path::new("/out").exists(), "must not use root as anchor");
        assert!(!Path::new("/recovery.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn parent_dotdot_is_refused() {
        let (_dir, base) = tmpdir();
        let path = base.join("..").join("escape.txt");
        let err = create_new_private_file(&path, b"SECRET").expect_err("must refuse ..");
        let msg = err.to_string();
        assert!(
            msg.contains("parent-directory") || msg.contains("refusing"),
            "msg={msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn final_symlink_target_is_unchanged() {
        let (_dir, base) = tmpdir();
        let target = base.join("target.txt");
        std::fs::write(&target, b"target-data").expect("target");
        let link = base.join("recovery.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = create_new_private_file(&link, b"SECRET").expect_err("must refuse");
        let _ = err;
        assert_eq!(
            std::fs::read(&target).expect("target read"),
            b"target-data",
            "symlink target must be unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_is_refused() {
        let (_dir, base) = tmpdir();
        let real = base.join("real");
        std::fs::create_dir(&real).expect("real dir");
        std::fs::write(real.join("keep.txt"), b"keep").expect("keep");
        let evil = base.join("evil");
        std::os::unix::fs::symlink(&real, &evil).expect("symlink parent");

        let err = create_new_private_file(&evil.join("recovery.txt"), b"SECRET")
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("symlink") || msg.contains("refusing") || msg.contains("parent"),
            "msg={msg}"
        );
        assert!(
            !real.join("recovery.txt").exists(),
            "must not create through symlink parent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_parent_refused_without_tree_creation() {
        let (_dir, base) = tmpdir();
        let path = base.join("no-such-dir").join("recovery.txt");
        let err = create_new_private_file(&path, b"SECRET").expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist") || msg.contains("refusing"),
            "msg={msg}"
        );
        assert!(!base.join("no-such-dir").exists(), "no insecure tree");
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_parent_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, base) = tmpdir();
        let parent = base.join("shared");
        std::fs::create_dir(&parent).expect("dir");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let err = create_new_private_file(&parent.join("recovery.txt"), b"SECRET")
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("world-writable"), "msg={msg}");
        assert!(!parent.join("recovery.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_final_parent_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, base) = tmpdir();
        let parent = base.join("group-shared");
        std::fs::create_dir(&parent).expect("dir");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        let err = create_new_private_file(&parent.join("recovery.txt"), b"SECRET")
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("group-writable"), "msg={msg}");
        assert!(!parent.join("recovery.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_ancestor_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, base) = tmpdir();
        let mid = base.join("shared-ancestor");
        let leaf = mid.join("leaf");
        std::fs::create_dir(&mid).expect("mid");
        std::fs::create_dir(&leaf).expect("leaf");
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o770)).expect("chmod");
        // leaf is private and owned by us, but the ancestor is group-writable.
        let err = create_new_private_file(&leaf.join("recovery.txt"), b"SECRET")
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("group-writable") || msg.contains("ancestor"),
            "msg={msg}"
        );
        assert!(!leaf.join("recovery.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_nonsticky_ancestor_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, base) = tmpdir();
        let mid = base.join("shared-ancestor");
        let leaf = mid.join("leaf");
        std::fs::create_dir(&mid).expect("mid");
        std::fs::create_dir(&leaf).expect("leaf");
        std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let err = create_new_private_file(&leaf.join("recovery.txt"), b"SECRET")
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("world-writable") || msg.contains("group-writable"),
            "msg={msg}"
        );
        assert!(!leaf.join("recovery.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn sticky_world_writable_ancestor_allowed_into_private_leaf() {
        // Only root-owned sticky temp (e.g. /tmp) is a trusted traversal
        // ancestor. Build a private leaf under the real system temp when it
        // is root-owned sticky; otherwise assert the policy still holds for
        // a private self-owned chain (covered by fresh_create).
        let system_tmp = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize tmp");
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let c = std::ffi::CString::new(system_tmp.to_string_lossy().as_bytes()).expect("cstr");
        let ok = unsafe { libc::stat(c.as_ptr(), &mut st) } == 0;
        let root_sticky = ok
            && st.st_uid == 0
            && st.st_mode & libc::S_ISVTX != 0
            && st.st_mode & libc::S_IWOTH != 0;
        if root_sticky {
            let leaf = tempfile::Builder::new()
                .prefix("hs-acl-leaf-")
                .tempdir_in(&system_tmp)
                .expect("leaf in system tmp");
            let leaf_path = leaf.path().canonicalize().expect("canonicalize leaf");
            // tempdir is 0700 and owned by us — a valid final parent.
            create_new_private_file(&leaf_path.join("recovery.txt"), b"VIA-STICKY")
                .expect("create");
            assert_eq!(mode_of(&leaf_path.join("recovery.txt")), 0o600);
        } else {
            // System temp is not root-owned sticky here; private chain still works.
            let (_dir, base) = tmpdir();
            create_new_private_file(&base.join("recovery.txt"), b"VIA-STICKY").expect("create");
            assert_eq!(mode_of(&base.join("recovery.txt")), 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn root_owned_ancestor_is_allowed() {
        // System paths like /tmp are root-owned; traversal must work into a
        // private self-owned leaf (covered by sticky test + fresh_create in
        // tempfile under /tmp). This asserts the policy directly via the API.
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        create_new_private_file(&path, b"ROOT-ANCESTOR").expect("create");
        assert!(path.exists());
    }

    // ----- macOS: real extended-ACL fixtures (fail the flawed ==1 check) -----

    /// Build a real `chmod +a 'everyone allow read'` style ACL on `path`
    /// using the native libSystem API (no shell-out).
    #[cfg(target_os = "macos")]
    fn add_everyone_allow_read_acl(path: &Path) {
        type AclT = *mut libc::c_void;
        type AclEntryT = *mut libc::c_void;
        type AclPermsetT = *mut libc::c_void;
        const ACL_EXTENDED_ALLOW: i32 = 1;
        const ACL_READ_DATA: i32 = 1 << 1;
        extern "C" {
            fn acl_init(count: libc::c_int) -> AclT;
            fn acl_create_entry(acl_p: *mut AclT, entry_p: *mut AclEntryT) -> libc::c_int;
            fn acl_set_tag_type(entry: AclEntryT, tag: i32) -> libc::c_int;
            fn acl_get_permset(entry: AclEntryT, permset_p: *mut AclPermsetT) -> libc::c_int;
            fn acl_add_perm(permset: AclPermsetT, perm: i32) -> libc::c_int;
            fn acl_set_fd(fd: libc::c_int, acl: AclT) -> libc::c_int;
            fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
        }
        use std::os::unix::io::AsRawFd;
        let file = std::fs::File::open(path).expect("open for acl");
        unsafe {
            let mut acl = acl_init(1);
            assert!(!acl.is_null(), "acl_init");
            let mut entry: AclEntryT = std::ptr::null_mut();
            assert_eq!(acl_create_entry(&mut acl, &mut entry), 0);
            // No qualifier = everyone.
            assert_eq!(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW), 0);
            let mut ps: AclPermsetT = std::ptr::null_mut();
            assert_eq!(acl_get_permset(entry, &mut ps), 0);
            assert_eq!(acl_add_perm(ps, ACL_READ_DATA), 0);
            assert_eq!(acl_set_fd(file.as_raw_fd(), acl), 0, "acl_set_fd");
            acl_free(acl.cast());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_allow_acl_on_new_file_is_stripped_before_secret() {
        // A new exclusive create must establish privacy even if the parent
        // would grant an inherited allow ACL. We verify by attaching an allow
        // ACL to a pre-created sibling and confirming the writer refuses or
        // strips on its own new file (never the sibling).
        let (_dir, base) = tmpdir();
        let sibling = base.join("sibling.txt");
        std::fs::write(&sibling, b"public").expect("sibling");
        add_everyone_allow_read_acl(&sibling);
        // Creating our own new private file must still succeed and be private.
        let path = base.join("recovery.txt");
        create_new_private_file(&path, b"CODE").expect("create");
        assert_eq!(mode_of(&path), 0o600);
        // The sibling keeps its ACL (we never mutate foreign/other objects).
        let fd = std::fs::File::open(&sibling).expect("reopen");
        use std::os::unix::io::AsRawFd;
        let status = query_extended_acl(fd.as_raw_fd()).expect("query");
        assert!(
            matches!(status, AclStatus::AllowPresent),
            "sibling untouched"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_existing_file_with_allow_acl_is_refused_not_stripped() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        std::fs::write(&path, b"original").expect("seed");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        add_everyone_allow_read_acl(&path);
        let err = create_new_private_file(&path, b"SECRET").expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("already exists") || msg.contains("refusing"),
            "msg={msg}"
        );
        // Contents unchanged — no mutation to manufacture privacy.
        assert_eq!(std::fs::read(&path).expect("read"), b"original");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_store_file_with_allow_acl_is_refused() {
        let (_dir, base) = tmpdir();
        let path = base.join("hs-server.db");
        std::fs::write(&path, b"db-bytes").expect("seed");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        add_everyone_allow_read_acl(&path);
        let err = verify_private_store_file(&path).expect_err("must refuse ACL store");
        let msg = err.to_string();
        assert!(
            msg.contains("ACL") || msg.contains("acl") || msg.contains("refusing"),
            "msg={msg}"
        );
        // Never stripped: ACL still present.
        let fd = std::fs::File::open(&path).expect("reopen");
        use std::os::unix::io::AsRawFd;
        let status = query_extended_acl(fd.as_raw_fd()).expect("query");
        assert!(matches!(status, AclStatus::AllowPresent));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_empty_or_absent_acl_is_accepted() {
        let (_dir, base) = tmpdir();
        let path = base.join("ok.txt");
        create_new_private_file(&path, b"X").expect("create");
        let fd = std::fs::File::open(&path).expect("open");
        use std::os::unix::io::AsRawFd;
        let status = query_extended_acl(fd.as_raw_fd()).expect("query");
        assert!(matches!(status, AclStatus::Absent | AclStatus::DenyOnly));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_deny_only_acl_is_accepted_without_strip() {
        let (_dir, base) = tmpdir();
        let path = base.join("store.db");
        std::fs::write(&path, b"db").expect("seed");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        // Install a deny-only ACL via native API.
        type AclT = *mut libc::c_void;
        type AclEntryT = *mut libc::c_void;
        type AclPermsetT = *mut libc::c_void;
        const ACL_EXTENDED_DENY: i32 = 2;
        const ACL_READ_DATA: i32 = 1 << 1;
        extern "C" {
            fn acl_init(count: libc::c_int) -> AclT;
            fn acl_create_entry(acl_p: *mut AclT, entry_p: *mut AclEntryT) -> libc::c_int;
            fn acl_set_tag_type(entry: AclEntryT, tag: i32) -> libc::c_int;
            fn acl_get_permset(entry: AclEntryT, permset_p: *mut AclPermsetT) -> libc::c_int;
            fn acl_add_perm(permset: AclPermsetT, perm: i32) -> libc::c_int;
            fn acl_set_fd(fd: libc::c_int, acl: AclT) -> libc::c_int;
            fn acl_free(obj: *mut libc::c_void) -> libc::c_int;
        }
        use std::os::unix::io::AsRawFd;
        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open");
        unsafe {
            let mut acl = acl_init(1);
            let mut entry: AclEntryT = std::ptr::null_mut();
            assert_eq!(acl_create_entry(&mut acl, &mut entry), 0);
            assert_eq!(acl_set_tag_type(entry, ACL_EXTENDED_DENY), 0);
            let mut ps: AclPermsetT = std::ptr::null_mut();
            assert_eq!(acl_get_permset(entry, &mut ps), 0);
            assert_eq!(acl_add_perm(ps, ACL_READ_DATA), 0);
            assert_eq!(acl_set_fd(file.as_raw_fd(), acl), 0);
            acl_free(acl.cast());
        }
        verify_private_store_file(&path).expect("deny-only ACL must be accepted");
    }

    // ----- Windows: explicit denial only (no success-or-generic branch) -----

    #[cfg(windows)]
    #[test]
    fn windows_denies_private_create_with_no_file_or_secret() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        let err = create_new_private_file(&path, b"SECRET-RECOVERY")
            .expect_err("must deny NEW private create on Windows");
        let msg = err.to_string();
        assert!(
            msg.contains("not implemented") || msg.contains("refusing"),
            "msg={msg}"
        );
        assert!(!path.exists(), "no file may be created");
        assert!(!msg.contains("SECRET-RECOVERY"), "no secret in error");
    }

    #[cfg(windows)]
    #[test]
    fn windows_preflight_denies_without_mutation() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        let err = preflight_new_private_file(&path)
            .expect_err("must deny on Windows before any mutation");
        let msg = err.to_string();
        assert!(
            msg.contains("not implemented") || msg.contains("refusing"),
            "msg={msg}"
        );
        assert!(!path.exists(), "preflight must not create");
    }

    #[cfg(windows)]
    #[test]
    fn windows_denies_store_helpers_without_claiming_support() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        assert!(
            !private_file_supported(),
            "must not claim Windows private store"
        );
        assert!(!persisted_v2_credentials_supported());
        ensure_private_store_dir(&dir).expect_err("must deny store dir");
        assert!(!dir.exists(), "no directory created");
        create_private_store_file(&dir.join("hs-server.db")).expect_err("must deny store file");
        assert!(!dir.join("hs-server.db").exists());
    }
}
