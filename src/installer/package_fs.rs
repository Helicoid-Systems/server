//! Pinned package-directory custody for read-only verification.
//!
//! A [`PinnedPackage`] is an already-open package root plus operations that are
//! resolved relative to that held handle. It never reopens the caller's path for
//! a file, ancestor, or directory read. The Unix implementation uses
//! `openat`/`fstatat` with `O_NOFOLLOW`, nonblocking regular-file opens, bounded
//! reads, and bounded directory enumeration. The package root and every opened
//! ancestor must be real directories and must not be group- or world-writable
//! (sticky ancestors are permitted). The root's mode is rechecked before
//! evidence is returned.
//!
//! This module is library-only evidence machinery. It does not authenticate a
//! package by itself, install a service, or authorize a macOS apply.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Maximum entries returned by one pinned directory listing.
pub const MAX_PINNED_DIR_ENTRIES: usize = 4096;
/// Maximum bytes in one directory-entry name.
pub const MAX_PINNED_NAME_BYTES: usize = 255;
/// Maximum bytes in a package-relative path supplied to a pinned operation.
pub const MAX_PINNED_RELATIVE_PATH_BYTES: usize = 4096;
/// Maximum slash-separated components in a package-relative path.
pub const MAX_PINNED_RELATIVE_SEGMENTS: usize = 32;

/// Semantic filesystem failure from a pinned package operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageFsError {
    InvalidPath(String),
    Missing(String),
    Uninspectable(String),
    Symlink(String),
    NotDirectory(String),
    NotRegular(String),
    TooLarge {
        path: String,
        max: usize,
    },
    SizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },
    Changed(String),
    Unsupported(String),
    Other(String),
}

impl fmt::Display for PackageFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(message) => write!(f, "invalid package path: {message}"),
            Self::Missing(path) => write!(f, "missing package path: {path}"),
            Self::Uninspectable(path) => write!(f, "cannot inspect package path: {path}"),
            Self::Symlink(path) => write!(f, "package path is a symlink: {path}"),
            Self::NotDirectory(path) => write!(f, "package path is not a directory: {path}"),
            Self::NotRegular(path) => write!(f, "package path is not a regular file: {path}"),
            Self::TooLarge { path, max } => write!(f, "package file exceeds {max} bytes: {path}"),
            Self::SizeMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "package file size mismatch for {path}: expected {expected}, got {actual}"
            ),
            Self::Changed(path) => write!(f, "package path changed during verification: {path}"),
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

pub type PackageFsResult<T> = Result<T, PackageFsError>;

/// A bounded read policy applied to one regular file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedReadPolicy {
    /// Read at most this many bytes; reject a larger file.
    Max(usize),
    /// Require this exact size before reading and reject a changed size.
    Exact(u64),
}

/// Bytes read from one regular file while the package handle was held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedFile {
    pub bytes: Vec<u8>,
    pub size: u64,
}

/// Kind of one direct directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// One direct directory entry, resolved without following a symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedEntry {
    pub name: String,
    pub kind: PinnedEntryKind,
    pub size: u64,
}

/// Read-only operations over a package directory handle.
///
/// Implementations must resolve every relative path from the held root and
/// must not reopen the caller's original path. A missing or uninspectable
/// entry is an error; callers must not treat it as an empty package.
pub trait PinnedPackage: Send + Sync + fmt::Debug {
    fn read_file(&self, relative: &str, policy: PinnedReadPolicy) -> PackageFsResult<PinnedFile>;
    fn list_dir(&self, relative: &str) -> PackageFsResult<Vec<PinnedEntry>>;
    /// Re-check the held root identity before the verification result escapes.
    fn verify_root(&self) -> PackageFsResult<()>;
}

/// Validate and split a package-relative path. Empty is allowed only for a
/// directory operation at the package root.
pub(crate) fn relative_segments(relative: &str, allow_empty: bool) -> PackageFsResult<Vec<&str>> {
    if relative.is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(PackageFsError::InvalidPath(
                "package-relative file path must not be empty".to_string(),
            ))
        };
    }
    if relative.len() > MAX_PINNED_RELATIVE_PATH_BYTES
        || relative.starts_with('/')
        || relative.as_bytes().contains(&0)
    {
        return Err(PackageFsError::InvalidPath(relative.to_string()));
    }
    let mut segments = Vec::new();
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PackageFsError::InvalidPath(relative.to_string()));
        }
        if segment.len() > MAX_PINNED_NAME_BYTES {
            return Err(PackageFsError::InvalidPath(relative.to_string()));
        }
        segments.push(segment);
        if segments.len() > MAX_PINNED_RELATIVE_SEGMENTS {
            return Err(PackageFsError::InvalidPath(relative.to_string()));
        }
    }
    Ok(segments)
}

fn normalize_root(root: &Path) -> PackageFsResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in root.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::Normal(name) => {
                if name.as_encoded_bytes().contains(&0) {
                    return Err(PackageFsError::InvalidPath(root.display().to_string()));
                }
                normalized.push(name);
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(PackageFsError::InvalidPath(root.display().to_string()));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(PackageFsError::InvalidPath(
            "package root must not be empty".to_string(),
        ));
    }
    Ok(normalized)
}

fn set_entry(
    entries: &mut BTreeMap<String, PinnedEntryKind>,
    name: String,
    kind: PinnedEntryKind,
    path: &Path,
) -> PackageFsResult<()> {
    if name.len() > MAX_PINNED_NAME_BYTES {
        return Err(PackageFsError::TooLarge {
            path: path.display().to_string(),
            max: MAX_PINNED_NAME_BYTES,
        });
    }
    if let Some(existing) = entries.get(&name) {
        if *existing != kind {
            return Err(PackageFsError::Uninspectable(path.display().to_string()));
        }
    } else {
        entries.insert(name, kind);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-memory package snapshot (TestAdapter)
// ---------------------------------------------------------------------------

/// A snapshot of an in-memory fixture opened through `TestAdapter`.
///
/// The snapshot is deliberately immutable: once opened, verification cannot
/// observe a later mutation of the adapter's maps through this handle.
#[derive(Debug, Clone)]
pub(crate) struct InMemoryPinnedPackage {
    root: PathBuf,
    files: HashMap<PathBuf, Vec<u8>>,
    directories: HashSet<PathBuf>,
    symlinks: HashSet<PathBuf>,
}

impl InMemoryPinnedPackage {
    pub(crate) fn new(
        root: &Path,
        files: HashMap<PathBuf, Vec<u8>>,
        directories: HashSet<PathBuf>,
        symlinks: HashSet<PathBuf>,
    ) -> PackageFsResult<Self> {
        let root = normalize_root(root)?;
        if symlinks.contains(&root) {
            return Err(PackageFsError::Symlink(root.display().to_string()));
        }
        let has_child = files
            .keys()
            .chain(directories.iter())
            .chain(symlinks.iter())
            .any(|path| path != &root && path.starts_with(&root));
        if files.contains_key(&root) && !has_child && !directories.contains(&root) {
            return Err(PackageFsError::NotDirectory(root.display().to_string()));
        }
        if !directories.contains(&root) && !has_child {
            return Err(PackageFsError::Missing(root.display().to_string()));
        }

        let mut directories = directories;
        directories.insert(root.clone());
        let known_paths: Vec<PathBuf> = files
            .keys()
            .chain(symlinks.iter())
            .chain(directories.iter())
            .cloned()
            .collect();
        for path in known_paths {
            let mut parent = path.parent();
            while let Some(directory) = parent {
                if directory == root {
                    break;
                }
                if directory.starts_with(&root) {
                    directories.insert(directory.to_path_buf());
                }
                parent = directory.parent();
            }
        }

        Ok(Self {
            root,
            files,
            directories,
            symlinks,
        })
    }

    fn full_path(&self, relative: &str, allow_empty: bool) -> PackageFsResult<PathBuf> {
        let segments = relative_segments(relative, allow_empty)?;
        let mut current = self.root.clone();
        for segment in segments {
            current.push(segment);
            if self.symlinks.contains(&current) {
                return Err(PackageFsError::Symlink(current.display().to_string()));
            }
        }
        Ok(current)
    }

    fn has_children(&self, path: &Path) -> bool {
        self.files
            .keys()
            .chain(self.directories.iter())
            .chain(self.symlinks.iter())
            .any(|entry| entry != path && entry.starts_with(path))
    }
}

impl PinnedPackage for InMemoryPinnedPackage {
    fn read_file(&self, relative: &str, policy: PinnedReadPolicy) -> PackageFsResult<PinnedFile> {
        let path = self.full_path(relative, false)?;
        let Some(bytes) = self.files.get(&path) else {
            if self.directories.contains(&path) || self.has_children(&path) {
                return Err(PackageFsError::NotRegular(path.display().to_string()));
            }
            return Err(PackageFsError::Missing(path.display().to_string()));
        };
        let size = bytes.len() as u64;
        match policy {
            PinnedReadPolicy::Max(max) if bytes.len() > max => {
                return Err(PackageFsError::TooLarge {
                    path: path.display().to_string(),
                    max,
                });
            }
            PinnedReadPolicy::Exact(expected) if size != expected => {
                return Err(PackageFsError::SizeMismatch {
                    path: path.display().to_string(),
                    expected,
                    actual: size,
                });
            }
            _ => {}
        }
        Ok(PinnedFile {
            bytes: bytes.clone(),
            size,
        })
    }

    fn list_dir(&self, relative: &str) -> PackageFsResult<Vec<PinnedEntry>> {
        let path = self.full_path(relative, true)?;
        if self.files.contains_key(&path) {
            return Err(PackageFsError::NotDirectory(path.display().to_string()));
        }
        if !self.directories.contains(&path) && !self.has_children(&path) {
            return Err(PackageFsError::Missing(path.display().to_string()));
        }

        let mut entries = BTreeMap::new();
        for candidate in self
            .files
            .keys()
            .chain(self.directories.iter())
            .chain(self.symlinks.iter())
        {
            let Ok(relative_path) = candidate.strip_prefix(&path) else {
                continue;
            };
            if relative_path.as_os_str().is_empty() {
                continue;
            }
            let Some(first) = relative_path.components().next() else {
                continue;
            };
            let Component::Normal(name) = first else {
                continue;
            };
            let Some(name) = name.to_str() else {
                return Err(PackageFsError::Uninspectable(path.display().to_string()));
            };
            let child = path.join(first);
            let kind = if self.symlinks.contains(&child) {
                PinnedEntryKind::Symlink
            } else if self.files.contains_key(&child) {
                PinnedEntryKind::File
            } else if self.directories.contains(&child) {
                PinnedEntryKind::Directory
            } else {
                PinnedEntryKind::Other
            };
            set_entry(&mut entries, name.to_string(), kind, &path)?;
        }
        if entries.len() > MAX_PINNED_DIR_ENTRIES {
            return Err(PackageFsError::TooLarge {
                path: path.display().to_string(),
                max: MAX_PINNED_DIR_ENTRIES,
            });
        }
        Ok(entries
            .into_iter()
            .map(|(name, kind)| PinnedEntry {
                name,
                kind,
                size: 0,
            })
            .collect())
    }

    fn verify_root(&self) -> PackageFsResult<()> {
        if self.symlinks.contains(&self.root) || self.files.contains_key(&self.root) {
            return Err(PackageFsError::Changed(self.root.display().to_string()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unix descriptor-relative implementation
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    /// A package root held by an open directory descriptor.
    pub struct UnixPinnedPackage {
        root: OwnedFd,
        root_device: u64,
        root_inode: u64,
        /// Diagnostics only. Never reopen this path for package operations.
        path: PathBuf,
    }

    impl fmt::Debug for UnixPinnedPackage {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("UnixPinnedPackage")
                .field("path", &self.path)
                .field("device", &self.root_device)
                .field("inode", &self.root_inode)
                .finish_non_exhaustive()
        }
    }

    impl UnixPinnedPackage {
        /// Open and pin a package directory without following any symlink.
        pub fn open(path: &Path) -> PackageFsResult<Self> {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|error| PackageFsError::Uninspectable(error.to_string()))?
                    .join(path)
            };
            let mut normalized = PathBuf::new();
            for component in absolute.components() {
                match component {
                    Component::RootDir => normalized.push(Path::new("/")),
                    Component::CurDir => {}
                    Component::Normal(name) => normalized.push(name),
                    Component::ParentDir | Component::Prefix(_) => {
                        return Err(PackageFsError::InvalidPath(path.display().to_string()));
                    }
                }
            }
            if normalized.as_os_str().is_empty() {
                return Err(PackageFsError::InvalidPath(
                    "package root must not be empty".to_string(),
                ));
            }

            let mut directory = open_root_directory()?;
            for component in normalized.components() {
                let Component::Normal(name) = component else {
                    continue;
                };
                directory =
                    open_directory_at(&directory, name, normalized.display().to_string().as_str())?;
            }
            let metadata = stat_fd(directory.as_raw_fd(), &normalized.display().to_string())?;
            if !is_directory(&metadata) {
                return Err(PackageFsError::NotDirectory(
                    normalized.display().to_string(),
                ));
            }
            if (metadata.st_mode & (libc::S_IWGRP | libc::S_IWOTH)) != 0 {
                return Err(PackageFsError::Uninspectable(format!(
                    "{} is group- or world-writable",
                    normalized.display()
                )));
            }
            Ok(Self {
                root: directory,
                root_device: metadata.st_dev as u64,
                root_inode: metadata.st_ino as u64,
                path: normalized,
            })
        }

        fn duplicate(&self) -> PackageFsResult<OwnedFd> {
            duplicate_fd(&self.root, &self.path.display().to_string())
        }

        fn open_directory(&self, relative: &str) -> PackageFsResult<OwnedFd> {
            let segments = relative_segments(relative, true)?;
            let mut current = self.duplicate()?;
            for segment in segments {
                current = open_directory_at(&current, OsStr::new(segment), relative)?;
            }
            Ok(current)
        }

        fn open_file(&self, relative: &str) -> PackageFsResult<(File, libc::stat)> {
            let segments = relative_segments(relative, false)?;
            let Some((file_name, parents)) = segments.split_last() else {
                return Err(PackageFsError::InvalidPath(relative.to_string()));
            };
            let mut directory = self.duplicate()?;
            for parent in parents {
                directory = open_directory_at(&directory, OsStr::new(parent), relative)?;
            }
            open_file_at(&directory, OsStr::new(file_name), relative)
        }

        #[cfg(test)]
        pub(super) fn read_file_with_hook<F: FnOnce()>(
            &self,
            relative: &str,
            policy: PinnedReadPolicy,
            hook: F,
        ) -> PackageFsResult<PinnedFile> {
            self.read_file_inner(relative, policy, hook)
        }

        fn read_file_inner<F: FnOnce()>(
            &self,
            relative: &str,
            policy: PinnedReadPolicy,
            hook: F,
        ) -> PackageFsResult<PinnedFile> {
            let (mut file, before) = self.open_file(relative)?;
            let limit = match policy {
                PinnedReadPolicy::Max(max) => {
                    if before.st_size < 0 || before.st_size as u64 > max as u64 {
                        return Err(PackageFsError::TooLarge {
                            path: relative.to_string(),
                            max,
                        });
                    }
                    max as u64
                }
                PinnedReadPolicy::Exact(expected) => {
                    if before.st_size < 0 || before.st_size as u64 != expected {
                        return Err(PackageFsError::SizeMismatch {
                            path: relative.to_string(),
                            expected,
                            actual: before.st_size.max(0) as u64,
                        });
                    }
                    expected
                }
            };
            let limit_usize = usize::try_from(limit).map_err(|_| PackageFsError::TooLarge {
                path: relative.to_string(),
                max: usize::MAX,
            })?;
            let read_limit = limit
                .checked_add(1)
                .ok_or_else(|| PackageFsError::TooLarge {
                    path: relative.to_string(),
                    max: usize::MAX,
                })?;
            hook();
            let mut bytes = Vec::new();
            {
                let mut bounded = (&mut file).take(read_limit);
                bounded.read_to_end(&mut bytes).map_err(|error| {
                    PackageFsError::Uninspectable(format!("{relative}: {error}"))
                })?;
            }
            if bytes.len() > limit_usize {
                return Err(match policy {
                    PinnedReadPolicy::Max(max) => PackageFsError::TooLarge {
                        path: relative.to_string(),
                        max,
                    },
                    PinnedReadPolicy::Exact(expected) => PackageFsError::SizeMismatch {
                        path: relative.to_string(),
                        expected,
                        actual: bytes.len() as u64,
                    },
                });
            }
            let after = stat_fd(file.as_raw_fd(), relative)?;
            if !is_regular(&after)
                || after.st_dev != before.st_dev
                || after.st_ino != before.st_ino
                || after.st_size != before.st_size
                || bytes.len() as u64 != before.st_size as u64
            {
                return Err(PackageFsError::Changed(relative.to_string()));
            }
            Ok(PinnedFile {
                bytes,
                size: before.st_size as u64,
            })
        }
    }

    impl PinnedPackage for UnixPinnedPackage {
        fn read_file(
            &self,
            relative: &str,
            policy: PinnedReadPolicy,
        ) -> PackageFsResult<PinnedFile> {
            self.read_file_inner(relative, policy, || {})
        }

        fn list_dir(&self, relative: &str) -> PackageFsResult<Vec<PinnedEntry>> {
            let directory = self.open_directory(relative)?;
            let before = stat_fd(directory.as_raw_fd(), relative)?;
            if !is_directory(&before) {
                return Err(PackageFsError::NotDirectory(relative.to_string()));
            }
            let listing_fd = duplicate_fd(&directory, relative)?;
            let raw = listing_fd.into_raw_fd();
            let stream = unsafe { libc::fdopendir(raw) };
            if stream.is_null() {
                unsafe { libc::close(raw) };
                return Err(PackageFsError::Uninspectable(relative.to_string()));
            }

            let mut entries = Vec::new();
            loop {
                clear_errno();
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let errno = last_errno();
                    if errno != 0 {
                        unsafe { libc::closedir(stream) };
                        return Err(PackageFsError::Uninspectable(format!(
                            "{relative}: readdir errno {errno}"
                        )));
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
                let Ok(name) = name.to_str() else {
                    unsafe { libc::closedir(stream) };
                    return Err(PackageFsError::Uninspectable(relative.to_string()));
                };
                if name == "." || name == ".." {
                    continue;
                }
                if name.len() > MAX_PINNED_NAME_BYTES {
                    unsafe { libc::closedir(stream) };
                    return Err(PackageFsError::TooLarge {
                        path: relative.to_string(),
                        max: MAX_PINNED_NAME_BYTES,
                    });
                }
                if entries.len() >= MAX_PINNED_DIR_ENTRIES {
                    unsafe { libc::closedir(stream) };
                    return Err(PackageFsError::TooLarge {
                        path: relative.to_string(),
                        max: MAX_PINNED_DIR_ENTRIES,
                    });
                }
                let c_name = match CString::new(name.as_bytes()) {
                    Ok(name) => name,
                    Err(_) => {
                        unsafe { libc::closedir(stream) };
                        return Err(PackageFsError::InvalidPath(relative.to_string()));
                    }
                };
                let mut status: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::fstatat(
                        directory.as_raw_fd(),
                        c_name.as_ptr(),
                        &mut status,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                {
                    let error = std::io::Error::last_os_error();
                    unsafe { libc::closedir(stream) };
                    return Err(map_io(relative, error));
                }
                let kind = if is_symlink(&status) {
                    PinnedEntryKind::Symlink
                } else if is_directory(&status) {
                    PinnedEntryKind::Directory
                } else if is_regular(&status) {
                    PinnedEntryKind::File
                } else {
                    PinnedEntryKind::Other
                };
                entries.push(PinnedEntry {
                    name: name.to_string(),
                    kind,
                    size: status.st_size.max(0) as u64,
                });
            }
            unsafe { libc::closedir(stream) };
            entries.sort_by(|a, b| a.name.cmp(&b.name));

            let after = stat_fd(directory.as_raw_fd(), relative)?;
            if after.st_dev != before.st_dev
                || after.st_ino != before.st_ino
                || !is_directory(&after)
            {
                return Err(PackageFsError::Changed(relative.to_string()));
            }
            Ok(entries)
        }

        fn verify_root(&self) -> PackageFsResult<()> {
            let metadata = stat_fd(self.root.as_raw_fd(), &self.path.display().to_string())?;
            if metadata.st_dev as u64 != self.root_device
                || metadata.st_ino as u64 != self.root_inode
                || !is_directory(&metadata)
            {
                return Err(PackageFsError::Changed(self.path.display().to_string()));
            }
            if (metadata.st_mode & (libc::S_IWGRP | libc::S_IWOTH)) != 0 {
                return Err(PackageFsError::Uninspectable(format!(
                    "{} became group- or world-writable",
                    self.path.display()
                )));
            }
            Ok(())
        }
    }

    fn open_root_directory() -> PackageFsResult<OwnedFd> {
        let raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(map_io("/", std::io::Error::last_os_error()));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    fn open_directory_at(
        parent: &OwnedFd,
        name: &OsStr,
        display: &str,
    ) -> PackageFsResult<OwnedFd> {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| PackageFsError::InvalidPath(display.to_string()))?;
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(map_io(display, std::io::Error::last_os_error()));
        }
        if is_symlink(&status) {
            return Err(PackageFsError::Symlink(display.to_string()));
        }
        if !is_directory(&status) {
            return Err(PackageFsError::NotDirectory(display.to_string()));
        }
        if is_unsafe_writable_directory(&status) {
            return Err(PackageFsError::Uninspectable(format!(
                "{display} is group- or world-writable without the sticky bit"
            )));
        }
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(map_io(display, std::io::Error::last_os_error()));
        }
        let opened = unsafe { OwnedFd::from_raw_fd(raw) };
        let opened_status = stat_fd(opened.as_raw_fd(), display)?;
        if !is_directory(&opened_status)
            || opened_status.st_dev != status.st_dev
            || opened_status.st_ino != status.st_ino
        {
            return Err(PackageFsError::Changed(display.to_string()));
        }
        Ok(opened)
    }

    fn open_file_at(
        parent: &OwnedFd,
        name: &OsStr,
        display: &str,
    ) -> PackageFsResult<(File, libc::stat)> {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| PackageFsError::InvalidPath(display.to_string()))?;
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(map_io(display, std::io::Error::last_os_error()));
        }
        if is_symlink(&status) {
            return Err(PackageFsError::Symlink(display.to_string()));
        }
        if !is_regular(&status) {
            return Err(PackageFsError::NotRegular(display.to_string()));
        }
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(map_io(display, std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let opened = stat_fd(file.as_raw_fd(), display)?;
        if !is_regular(&opened) {
            return Err(PackageFsError::NotRegular(display.to_string()));
        }
        // The no-follow open is authoritative; reject an inode swap between
        // lstat and open rather than verifying a different file.
        if opened.st_dev != status.st_dev || opened.st_ino != status.st_ino {
            return Err(PackageFsError::Changed(display.to_string()));
        }
        Ok((file, opened))
    }

    fn duplicate_fd(fd: &OwnedFd, display: &str) -> PackageFsResult<OwnedFd> {
        let raw = unsafe { libc::dup(fd.as_raw_fd()) };
        if raw < 0 {
            return Err(map_io(display, std::io::Error::last_os_error()));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    fn stat_fd(fd: RawFd, display: &str) -> PackageFsResult<libc::stat> {
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut status) } != 0 {
            return Err(map_io(display, std::io::Error::last_os_error()));
        }
        Ok(status)
    }

    fn map_io(display: &str, error: std::io::Error) -> PackageFsError {
        match error.raw_os_error() {
            Some(libc::ENOENT) => PackageFsError::Missing(display.to_string()),
            Some(libc::EACCES) | Some(libc::EPERM) => {
                PackageFsError::Uninspectable(display.to_string())
            }
            Some(libc::ELOOP) => PackageFsError::Symlink(display.to_string()),
            Some(libc::ENOTDIR) => PackageFsError::NotDirectory(display.to_string()),
            Some(libc::ENAMETOOLONG) => PackageFsError::InvalidPath(display.to_string()),
            _ => PackageFsError::Other(format!("{display}: {error}")),
        }
    }

    fn is_directory(status: &libc::stat) -> bool {
        (status.st_mode & libc::S_IFMT) == libc::S_IFDIR
    }

    fn is_regular(status: &libc::stat) -> bool {
        (status.st_mode & libc::S_IFMT) == libc::S_IFREG
    }

    fn is_symlink(status: &libc::stat) -> bool {
        (status.st_mode & libc::S_IFMT) == libc::S_IFLNK
    }

    fn is_unsafe_writable_directory(status: &libc::stat) -> bool {
        (status.st_mode & (libc::S_IWGRP | libc::S_IWOTH)) != 0
            && (status.st_mode & libc::S_ISVTX) == 0
    }

    #[cfg(target_os = "linux")]
    fn clear_errno() {
        unsafe {
            *libc::__errno_location() = 0;
        }
    }

    #[cfg(target_os = "macos")]
    fn clear_errno() {
        unsafe {
            *libc::__error() = 0;
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn clear_errno() {}

    fn last_errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }
}

#[cfg(unix)]
pub use unix::UnixPinnedPackage;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn pinned_reader_detects_growth_after_size_check() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical tempdir");
        let file = root.join("file");
        std::fs::write(&file, b"four").expect("initial file");
        let package = UnixPinnedPackage::open(&root).expect("pinned package");

        let error = package
            .read_file_with_hook("file", PinnedReadPolicy::Exact(4), || {
                let mut appended = OpenOptions::new()
                    .append(true)
                    .open(&file)
                    .expect("open for append");
                appended.write_all(b"!").expect("append");
            })
            .expect_err("growth after size check must refuse");
        assert!(
            matches!(error, PackageFsError::SizeMismatch { .. }),
            "error={error:?}"
        );
    }
}
