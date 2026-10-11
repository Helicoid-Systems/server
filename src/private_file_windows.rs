//! Windows-native private file/store boundary.
//!
//! Two distinct policies on held handles:
//!
//! 1. **Ancestor namespace integrity** (traversed directories): owner is
//!    current user / SYSTEM / Administrators, or the exact maintained
//!    Windows TrustedInstaller service SID (`S-1-5-80-956008885-…`) —
//!    **ancestor owner only**, never a product owner and never a product
//!    DACL principal. Unknown principals may hold existing read/traverse
//!    plus **FILE_ADD_SUBDIRECTORY only** (create-new subdirectory name;
//!    not a replacement of an existing name). File-add / write-data
//!    (bit `0x2`), delete, delete-child, write-DACL, write-owner,
//!    generic-write/ALL, write attributes/EA remain refused. INHERIT_ONLY
//!    ACEs grant nothing on the ancestor itself: after validating supported
//!    ACE type/flags the current-directory mask is ignored (children are
//!    opened relative a retained parent handle no-follow and independently
//!    verified; created product SDs are protected so ancestor ACEs never
//!    propagate into product). Object/callback/unknown ACE types, unknown
//!    ACE flags, NULL DACL, and reparse fail closed.
//! 2. **Final product object** (store dirs, recovery files, DB/sidecars):
//!    owner is the current process user (TrustedInstaller is **not**
//!    accepted); every ACCESS_ALLOWED ACE SID (including INHERITED and
//!    INHERIT_ONLY) is exactly current user / SYSTEM / Administrators.
//!    **Create-new** of our own files/dirs uses an explicit **protected**
//!    DACL. **SQLite-created children** (WAL/SHM/journal) carry
//!    **inherited trusted ACEs** from a product directory with a protected
//!    DACL and trusted OBJECT_INHERIT ACEs — they are not given their own
//!    protected DACL; verification accepts validated inherited trusted
//!    ACEs. TokenDefaultDacl is never assumed. Product dirs must prove a
//!    trusted OBJECT_INHERIT ACE exists; unknown SID / NULL DACL / foreign
//!    owner fail closed. Existing product dirs keep the strict all-unknown
//!    refusal (including INHERIT_ONLY) because SQLite children inherit.
//!
//! Create-new supplies the protected DACL atomically via
//! `OBJECT_ATTRIBUTES.SecurityDescriptor` — no brief public window and no
//! post-write chmod. Existing objects are never re-ACL'd. Cleanup deletes
//! only the created object identity. NTSTATUS is matched by value (never by
//! error Display text).
//!
//! Held-handle / no-overwrite safety (the proof seam for ancestor
//! FILE_ADD_SUBDIRECTORY and for rename survival):
//! - Each component is opened relative a **retained** `NtCreateFile`
//!   `RootDirectory` handle with `FILE_OPEN_REPARSE_POINT` (no-follow).
//!   Ancestor renames after a child handle is held do not retarget the walk.
//! - Final product create uses `FILE_CREATE` (exclusive) with the protected
//!   SD; a preexisting name is never overwritten or re-ACL'd, and no secret
//!   is written on refusal.
//! - The new product object is verified on the held handle before any
//!   payload write.
//!
//! Path safety: refuse UNC, device namespaces, ADS, `..`, reserved device
//! names. Minimum rights are used for traversed directories so unprivileged
//! preflight/read still work. SQLite path-based open is pinned by the
//! ancestor namespace policy (unknown principals cannot replace the name)
//! plus the product-dir child-inheritance boundary and private sidecar
//! checks in `db`. Remaining installed-service / recovery-path review is
//! unchanged by this ancestor-role distinction.

use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, GENERIC_EXECUTE, GENERIC_READ, HANDLE,
    INVALID_HANDLE_VALUE, NTSTATUS, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AddAccessAllowedAceEx, CopySid, CreateWellKnownSid, EqualSid, GetAce, GetLengthSid,
    GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_FLAGS, ACE_HEADER, ACL_REVISION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE, INHERIT_ONLY_ACE,
    NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileDispositionInfo, GetFileInformationByHandle, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_DISPOSITION_INFO, FILE_EXECUTE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_TRAVERSE,
    FILE_WRITE_DATA, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::error::{AppError, AppResult};
use crate::private_file::{StorePathPresence, MAX_PRIVATE_PAYLOAD_BYTES};

const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

/// Exact maintained Windows TrustedInstaller service SID.
///
/// Parsed only via native `ConvertStringSidToSidW` into an owned buffer —
/// never LookupAccountName, network/account-name trust, or arbitrary
/// service SIDs. Accepted solely as trusted **ancestor owner**; never as
/// product owner and never as a product DACL allowlist principal.
const TRUSTED_INSTALLER_SERVICE_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Access bits allowed to unknown principals on a non-INHERIT_ONLY ancestor
/// ACE: existing read/traverse plus FILE_ADD_SUBDIRECTORY only.
///
/// FILE_ADD_SUBDIRECTORY (`0x4`) is create-new-subdirectory name — it cannot
/// replace an existing name. Held-handle safety (module docs): every child is
/// opened relative a retained parent handle no-follow and independently
/// verified; final product create is `FILE_CREATE` + protected DACL (no
/// overwrite; ancestor ACEs do not propagate into product).
///
/// FILE_ADD_FILE / FILE_WRITE_DATA (bit `0x2`) stay forbidden: writable
/// file / reparse risks differ from create-subdir. DELETE / DELETE_CHILD /
/// WRITE_DAC / WRITE_OWNER / GENERIC_WRITE / GENERIC_ALL / write
/// attributes/EA and every other bit are refused (allow-list, not deny-list).
const ANCESTOR_UNKNOWN_ALLOWED_RIGHTS: u32 = FILE_LIST_DIRECTORY
    | FILE_READ_DATA
    | FILE_READ_EA
    | FILE_READ_ATTRIBUTES
    | FILE_TRAVERSE
    | FILE_EXECUTE
    | READ_CONTROL
    | SYNCHRONIZE
    | GENERIC_READ
    | GENERIC_EXECUTE
    | FILE_ADD_SUBDIRECTORY;

/// Flags allowed on ancestor ALLOW ACEs. Unknown object/callback flag bits
/// fail closed; INHERIT_ONLY is validated then ignored for current-directory
/// mutation (grants nothing on this object).
const ANCESTOR_ALLOWED_ACE_FLAGS: ACE_FLAGS = CONTAINER_INHERIT_ACE
    | OBJECT_INHERIT_ACE
    | INHERIT_ONLY_ACE
    | NO_PROPAGATE_INHERIT_ACE
    | INHERITED_ACE;

// ----- handle / allocator wrappers -----

/// HANDLE is `*mut c_void` in windows-sys 0.61 — never an integer 0.
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn from_raw(h: HANDLE) -> AppResult<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return Err(AppError::internal("windows handle is invalid"));
        }
        Ok(Self(h))
    }
    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Owned `LocalFree` allocation (`HLOCAL` = `*mut c_void`).
struct LocalFreePtr(windows_sys::Win32::Foundation::HLOCAL);

impl Drop for LocalFreePtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn last_err(context: &str) -> AppError {
    let code = unsafe { GetLastError() };
    AppError::bad_request(format!("{context}: win32 error {code}"))
}

fn nt_err(context: &str, status: NTSTATUS) -> AppError {
    AppError::bad_request(format!("{context}: ntstatus 0x{:08X}", status as u32))
}

/// Typed NT open failure. Callers branch on the status, never Display text.
#[derive(Debug)]
enum OpenError {
    NotFound,
    AlreadyExists,
    Failed(AppError),
}

impl OpenError {
    fn is_not_found(&self) -> bool {
        matches!(self, OpenError::NotFound)
    }
    fn is_already_exists(&self) -> bool {
        matches!(self, OpenError::AlreadyExists)
    }
    fn into_app_error(self, fallback: &str) -> AppError {
        match self {
            OpenError::NotFound => AppError::bad_request(format!("{fallback}: not found")),
            OpenError::AlreadyExists => AppError::conflict(
                "target already exists; refusing to overwrite",
                Some("create_new_only".to_string()),
            ),
            OpenError::Failed(err) => err,
        }
    }
}

fn ntstatus_to_open_error(context: &str, status: NTSTATUS) -> OpenError {
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        return OpenError::NotFound;
    }
    if status == STATUS_OBJECT_NAME_COLLISION {
        return OpenError::AlreadyExists;
    }
    OpenError::Failed(nt_err(context, status))
}

// ----- path safety -----

/// Refuse UNC, device namespaces, ADS, reserved device names, and empty names.
pub(crate) fn reject_unsafe_windows_path(abs: &Path) -> AppResult<()> {
    if !abs.is_absolute() {
        return Err(AppError::bad_request(
            "private stores require an absolute drive path",
        ));
    }
    let raw = abs.as_os_str();
    if raw.is_empty() {
        return Err(AppError::bad_request("recovery path is empty"));
    }
    let s = raw.to_string_lossy();
    if s.starts_with(r"\\") {
        return Err(AppError::bad_request(
            "UNC/device path forms are refused for private stores",
        ));
    }
    if s.contains(r"\\\\") {
        return Err(AppError::bad_request(
            "repeated separator path form is refused for private stores",
        ));
    }
    let bytes = raw.as_encoded_bytes();
    if bytes.contains(&0) {
        return Err(AppError::bad_request("path contains NUL"));
    }

    let mut seen_normal = false;
    for comp in abs.components() {
        match comp {
            Component::Prefix(p) => {
                use std::path::Prefix;
                match p.kind() {
                    Prefix::Disk(_) => {}
                    Prefix::VerbatimDisk(_) | Prefix::Verbatim(_) | Prefix::VerbatimUNC(..) => {
                        return Err(AppError::bad_request(
                            "verbatim/device path prefix is refused for private stores",
                        ));
                    }
                    Prefix::UNC(..) => {
                        return Err(AppError::bad_request(
                            "UNC path prefix is refused for private stores",
                        ));
                    }
                    _ => {
                        return Err(AppError::bad_request(
                            "unsupported path prefix for private stores",
                        ));
                    }
                }
            }
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(AppError::bad_request(
                    "parent-directory component refused in recovery path",
                ));
            }
            Component::Normal(name) => {
                seen_normal = true;
                let n = name.to_string_lossy();
                if n.is_empty() {
                    return Err(AppError::bad_request("empty path component refused"));
                }
                if n.contains(':') {
                    return Err(AppError::bad_request(
                        "alternate data stream / colon path component is refused",
                    ));
                }
                if n.contains('\0') {
                    return Err(AppError::bad_request("path component contains NUL"));
                }
                // NT-relative opens preserve trailing dots/spaces while SQLite's
                // Win32 path open can normalize them to another name.
                if n.ends_with('.') || n.ends_with(' ') {
                    return Err(AppError::bad_request(
                        "trailing dot/space path component is refused",
                    ));
                }
                let stem = n.split('.').next().unwrap_or("").to_ascii_uppercase();
                const RESERVED: [&str; 25] = [
                    "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$", "COM1", "COM2",
                    "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3",
                    "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
                ];
                if RESERVED.contains(&stem.as_str()) {
                    return Err(AppError::bad_request(
                        "reserved device name path component is refused",
                    ));
                }
            }
        }
    }
    if !seen_normal {
        return Err(AppError::bad_request("recovery path must have a file name"));
    }
    Ok(())
}

// ----- SIDs -----

/// Owned SID bytes in pointer-aligned storage.
///
/// SIDs are self-relative byte structures, but Windows SID and
/// `TOKEN_USER` / `SECURITY_DESCRIPTOR` APIs assume at least pointer
/// alignment. Every SID backing (current user / well-known / TrustedInstaller)
/// uses this allocation so `as_psid()` is always aligned and owned — no
/// borrowed pointer escapes, no unaligned `Vec<u8>` casts. API byte lengths
/// passed to `CopySid` / `CreateWellKnownSid` / `GetTokenInformation` stay
/// exact and bounded.
struct SidBuf {
    /// Pointer-aligned backing store (`u64` words).
    storage: Vec<u64>,
}

impl SidBuf {
    /// Aligned storage able to hold `bytes` (rounded up to `u64` words).
    fn alloc_bytes(bytes: usize) -> Self {
        let words = bytes.div_ceil(std::mem::size_of::<u64>());
        Self {
            storage: vec![0u64; words],
        }
    }

    fn as_psid(&self) -> PSID {
        self.storage.as_ptr() as PSID
    }

    fn as_mut_psid(&mut self) -> PSID {
        self.storage.as_mut_ptr() as PSID
    }
}

/// Exact `CopySid` into a fresh pointer-aligned owned buffer.
fn copy_sid_owned(src: PSID) -> AppResult<SidBuf> {
    if src.is_null() {
        return Err(AppError::internal("CopySid source SID is null"));
    }
    let len = unsafe { GetLengthSid(src) } as usize;
    if len == 0 || len > 68 {
        return Err(AppError::internal("SID length invalid"));
    }
    let mut out = SidBuf::alloc_bytes(len);
    let ok = unsafe { CopySid(len as u32, out.as_mut_psid(), src) };
    if ok == 0 {
        return Err(last_err("CopySid"));
    }
    Ok(out)
}

fn current_user_sid() -> AppResult<SidBuf> {
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(last_err("OpenProcessToken"));
    }
    let token = OwnedHandle::from_raw(token)?;
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token.get(), TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(last_err("GetTokenInformation(TokenUser) size"));
    }
    // TOKEN_USER contains a PSID — the query buffer must be pointer-aligned.
    let mut buf = SidBuf::alloc_bytes(needed as usize);
    let ok = unsafe {
        GetTokenInformation(
            token.get(),
            TokenUser,
            buf.as_mut_psid() as _,
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_err("GetTokenInformation(TokenUser)"));
    }
    if (needed as usize) > buf.storage.len() * std::mem::size_of::<u64>() {
        return Err(AppError::internal(
            "GetTokenInformation(TokenUser) exceeded aligned allocation",
        ));
    }
    let user = buf.as_psid() as *const TOKEN_USER;
    let sid = unsafe { (*user).User.Sid };
    if sid.is_null() {
        return Err(AppError::internal("token user SID is null"));
    }
    copy_sid_owned(sid)
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> AppResult<SidBuf> {
    // 68 is the documented CreateWellKnownSid maximum; exact `size` is
    // checked and the aligned allocation is retained as the owned backing.
    const MAX_SID_BYTES: usize = 68;
    let mut buf = SidBuf::alloc_bytes(MAX_SID_BYTES);
    let mut size = MAX_SID_BYTES as u32;
    let ok =
        unsafe { CreateWellKnownSid(kind, std::ptr::null_mut(), buf.as_mut_psid(), &mut size) };
    if ok == 0 {
        return Err(last_err("CreateWellKnownSid"));
    }
    if size == 0 || size as usize > MAX_SID_BYTES {
        return Err(AppError::internal("CreateWellKnownSid length invalid"));
    }
    Ok(buf)
}

fn sid_eq(a: PSID, b: PSID) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    unsafe { EqualSid(a, b) != 0 }
}

/// Exact TrustedInstaller service SID from the maintained literal string.
///
/// Native parse + owned pointer-aligned copy (`ConvertStringSidToSidW` →
/// `CopySid`). The temporary LocalAlloc SID is freed immediately; the
/// returned `SidBuf` is the only backing store callers hold.
fn trusted_installer_sid() -> AppResult<SidBuf> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    // PCWSTR — no mutation required.
    let wide: Vec<u16> = TRUSTED_INSTALLER_SERVICE_SID
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut raw: PSID = std::ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw) };
    if ok == 0 {
        return Err(last_err("ConvertStringSidToSidW(TrustedInstaller)"));
    }
    if raw.is_null() {
        return Err(AppError::internal(
            "ConvertStringSidToSidW(TrustedInstaller) returned null SID",
        ));
    }
    let raw = LocalFreePtr(raw as windows_sys::Win32::Foundation::HLOCAL);
    copy_sid_owned(raw.0 as PSID)
}

/// Current user / SYSTEM / Administrators (+ TrustedInstaller for ancestor
/// **owner** only).
struct AllowSids {
    user: SidBuf,
    system: SidBuf,
    admins: SidBuf,
    /// Ancestor owner only — never product owner, never product DACL ACE.
    trusted_installer: SidBuf,
}

impl AllowSids {
    fn current() -> AppResult<Self> {
        Ok(Self {
            user: current_user_sid()?,
            system: well_known_sid(WinLocalSystemSid)?,
            admins: well_known_sid(WinBuiltinAdministratorsSid)?,
            trusted_installer: trusted_installer_sid()?,
        })
    }

    /// Product DACL / product owner allowlist. TrustedInstaller is absent.
    fn contains(&self, sid: PSID) -> bool {
        sid_eq(sid, self.user.as_psid())
            || sid_eq(sid, self.system.as_psid())
            || sid_eq(sid, self.admins.as_psid())
    }

    fn is_user(&self, sid: PSID) -> bool {
        sid_eq(sid, self.user.as_psid())
    }

    /// Ancestor owner set: trusted principals plus exact TrustedInstaller.
    fn is_trusted_ancestor_owner(&self, sid: PSID) -> bool {
        self.contains(sid) || sid_eq(sid, self.trusted_installer.as_psid())
    }
}

// ----- protected private DACL -----

/// Owned absolute `SECURITY_DESCRIPTOR` + ACL storage.
///
/// `storage` is `Vec<u64>` so the descriptor is pointer-aligned (a `Vec<u8>`
/// is only byte-aligned). `owner_sid` is **required**: `SetSecurityDescriptorOwner`
/// stores a raw `PSID` and does **not** copy the SID (unlike
/// `AddAccessAllowedAceEx`, which copies into the ACL). The owner backing
/// allocation must outlive every kernel use of `as_ptr()`.
struct OwnedSecurityDescriptor {
    /// Aligned bytes: `SECURITY_DESCRIPTOR` then ACL.
    storage: Vec<u64>,
    /// Backing allocation for `Owner` (kept alive on purpose).
    _owner_sid: SidBuf,
}

impl OwnedSecurityDescriptor {
    fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        // SAFETY: storage is large enough and 8-byte aligned (Vec<u64>).
        self.storage.as_ptr() as *const SECURITY_DESCRIPTOR
    }

    /// Owner PSID installed in the descriptor (stable heap address).
    #[cfg(test)]
    fn owner_sid(&self) -> PSID {
        self._owner_sid.as_psid()
    }
}

/// Build a protected private security descriptor.
///
/// `inheritable` adds `CONTAINER_INHERIT|OBJECT_INHERIT` on the trusted ACEs so
/// SQLite-created children (WAL/SHM/journal, including delete+recreate) inherit
/// a private DACL at create time — no TokenDefaultDacl assumption. Product
/// directories use `inheritable = true`; leaf files use `false`.
fn build_private_security_descriptor(inheritable: bool) -> AppResult<OwnedSecurityDescriptor> {
    let allow = AllowSids::current()?;
    let user_len = unsafe { GetLengthSid(allow.user.as_psid()) } as usize;
    let sys_len = unsafe { GetLengthSid(allow.system.as_psid()) } as usize;
    let adm_len = unsafe { GetLengthSid(allow.admins.as_psid()) } as usize;
    let ace = |sid_len: usize| 8 + sid_len;
    let acl_len = std::mem::size_of::<windows_sys::Win32::Security::ACL>()
        + ace(user_len)
        + ace(sys_len)
        + ace(adm_len);
    let acl_len = (acl_len + 3) & !3;

    let sd_size = std::mem::size_of::<SECURITY_DESCRIPTOR>();
    let total = sd_size + acl_len;
    // 8-byte aligned storage for the absolute SECURITY_DESCRIPTOR.
    let words = total.div_ceil(std::mem::size_of::<u64>());
    let mut storage = vec![0u64; words];
    let sd_ptr = storage.as_mut_ptr() as *mut SECURITY_DESCRIPTOR;
    let sd_ps: PSECURITY_DESCRIPTOR = sd_ptr as PSECURITY_DESCRIPTOR;
    let acl_ptr =
        unsafe { (sd_ptr as *mut u8).add(sd_size) } as *mut windows_sys::Win32::Security::ACL;

    unsafe {
        if InitializeSecurityDescriptor(sd_ps, 1) == 0 {
            return Err(last_err("InitializeSecurityDescriptor"));
        }
        if InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) == 0 {
            return Err(last_err("InitializeAcl"));
        }
        let flags: ACE_FLAGS = if inheritable {
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
        } else {
            0
        };
        for sid in [
            allow.user.as_psid(),
            allow.system.as_psid(),
            allow.admins.as_psid(),
        ] {
            if AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, flags, 0x001F_01FF, sid) == 0 {
                return Err(last_err("AddAccessAllowedAceEx"));
            }
        }
        if SetSecurityDescriptorDacl(sd_ps, 1, acl_ptr, 0) == 0 {
            return Err(last_err("SetSecurityDescriptorDacl"));
        }
        // Owner is a raw pointer — do NOT let `allow.user` drop. Move it into
        // OwnedSecurityDescriptor so the SID heap stays alive with the SD.
        if SetSecurityDescriptorOwner(sd_ps, allow.user.as_psid(), 0) == 0 {
            return Err(last_err("SetSecurityDescriptorOwner"));
        }
        if SetSecurityDescriptorControl(sd_ps, SE_DACL_PROTECTED, SE_DACL_PROTECTED) == 0 {
            return Err(last_err("SetSecurityDescriptorControl"));
        }
    }
    Ok(OwnedSecurityDescriptor {
        storage,
        _owner_sid: allow.user,
    })
}

// ----- DACL verification -----

fn fetch_owner_and_dacl(
    handle: HANDLE,
) -> AppResult<(PSID, *mut windows_sys::Win32::Security::ACL, LocalFreePtr)> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut group: PSID = std::ptr::null_mut();
    let mut dacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let mut sacl: *mut windows_sys::Win32::Security::ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut sd,
        )
    };
    if status != 0 {
        return Err(AppError::bad_request(format!(
            "GetSecurityInfo failed: win32 error {status}"
        )));
    }
    Ok((owner, dacl, LocalFreePtr(sd)))
}

fn ace_sid(ace_ptr: *mut core::ffi::c_void) -> PSID {
    let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
    (&ace.SidStart) as *const u32 as PSID
}

fn reject_unsupported_ace_type(ace_type: u8) -> AppResult<()> {
    // ACE type constants are u32; ACE_HEADER.AceType is u8.
    if ace_type as u32 == ACCESS_ALLOWED_ACE_TYPE || ace_type as u32 == ACCESS_DENIED_ACE_TYPE {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "unsupported or object/callback ACE type; refusing credential store",
        ))
    }
}

/// Flags allowed on product-object ALLOW ACEs. `INHERITED_ACE` is allowed only
/// as part of the supported trusted-allowlist inheritance policy (product
/// parent inheritable ACEs); the SID check still applies to every ACE.
const PRODUCT_ALLOWED_ACE_FLAGS: ACE_FLAGS = CONTAINER_INHERIT_ACE
    | OBJECT_INHERIT_ACE
    | INHERIT_ONLY_ACE
    | NO_PROPAGATE_INHERIT_ACE
    | INHERITED_ACE;

/// Walk every ALLOW ACE (including INHERITED and INHERIT_ONLY) and require the
/// SID to be in the trusted allowlist. INHERIT_ONLY still propagates to
/// children — an unknown INHERIT_ONLY SID is not private. Returns whether at
/// least one trusted inheritable ALLOW ACE exists (needed so SQLite-created
/// children do not fall back to TokenDefaultDacl).
fn check_product_allow_aces(
    dacl: *mut windows_sys::Win32::Security::ACL,
    allow: &AllowSids,
) -> AppResult<bool> {
    let acl = unsafe { &*dacl };
    // File children need OBJECT_INHERIT (CONTAINER alone does not grant ACL
    // inheritance onto files). Require a trusted OBJECT_INHERIT ALLOW ACE.
    let mut has_trusted_object_inherit = false;
    for i in 0..acl.AceCount {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i as u32, &mut ace_ptr) } == 0 {
            return Err(last_err("GetAce"));
        }
        if ace_ptr.is_null() {
            return Err(AppError::bad_request("ACE pointer is null; refusing"));
        }
        let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        reject_unsupported_ace_type(header.AceType)?;
        // AceFlags is u8; ACE_FLAGS constants are u32.
        let ace_flags: ACE_FLAGS = header.AceFlags as ACE_FLAGS;
        if header.AceType as u32 == ACCESS_DENIED_ACE_TYPE {
            // restrictive only
        } else if header.AceType as u32 == ACCESS_ALLOWED_ACE_TYPE {
            if ace_flags & !PRODUCT_ALLOWED_ACE_FLAGS != 0 {
                return Err(AppError::bad_request(
                    "ACCESS_ALLOWED ACE has unsupported flags; refusing credential store",
                ));
            }
            // Always check the principal — including INHERIT_ONLY and
            // INHERITED. Inherit-only unknown SIDs propagate to children.
            if !allow.contains(ace_sid(ace_ptr)) {
                return Err(AppError::bad_request(
                    "ACCESS_ALLOWED ACE names a principal outside the \
                     process-owner/SYSTEM/Administrators allowlist; refusing credential store",
                ));
            }
            // OBJECT_INHERIT is required so SQLite FILE children inherit.
            // CONTAINER_INHERIT alone is not a file-child policy.
            if ace_flags & OBJECT_INHERIT_ACE != 0 {
                has_trusted_object_inherit = true;
            }
        }
    }
    Ok(has_trusted_object_inherit)
}

fn dacl_is_protected(sd: PSECURITY_DESCRIPTOR) -> AppResult<bool> {
    use windows_sys::Win32::Security::GetSecurityDescriptorControl;
    if sd.is_null() {
        return Err(AppError::bad_request(
            "security descriptor is null; refusing",
        ));
    }
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0 {
        return Err(last_err("GetSecurityDescriptorControl"));
    }
    Ok(control & SE_DACL_PROTECTED != 0)
}

/// Final product object (file or leaf): owner is current user; every ALLOW ACE
/// (including inherited / inherit-only) is a trusted SID. Supported
/// inheritance: inherited allow ACEs from a trusted product parent pass the
/// SID check; unknown SID fails closed. Never mutates the object.
pub(crate) fn verify_private_object_on_handle(handle: HANDLE) -> AppResult<()> {
    let allow = AllowSids::current()?;
    let (owner, dacl, _sd) = fetch_owner_and_dacl(handle)?;
    if owner.is_null() || !allow.is_user(owner) {
        return Err(AppError::bad_request(
            "object is not owned by the current process principal; refusing credential store",
        ));
    }
    if dacl.is_null() {
        return Err(AppError::bad_request(
            "object has a NULL DACL; refusing credential store",
        ));
    }
    let _ = check_product_allow_aces(dacl, &allow)?;
    Ok(())
}

/// Product directory used as a SQLite/credential store parent.
///
/// Same trusted-allowlist check as [`verify_private_object_on_handle`], plus:
/// - DACL must be `SE_DACL_PROTECTED` (no outside inheritable ACEs)
/// - at least one trusted inheritable ALLOW ACE must exist so SQLite-created
///   children (WAL/SHM/journal, including delete+recreate) inherit a private
///   DACL at create time. TokenDefaultDacl is never assumed.
pub(crate) fn verify_product_dir_on_handle(handle: HANDLE) -> AppResult<()> {
    if !handle_is_directory(handle)? {
        return Err(AppError::bad_request(
            "store path is not a directory; refusing credential store",
        ));
    }
    let allow = AllowSids::current()?;
    let (owner, dacl, sd) = fetch_owner_and_dacl(handle)?;
    if owner.is_null() || !allow.is_user(owner) {
        return Err(AppError::bad_request(
            "object is not owned by the current process principal; refusing credential store",
        ));
    }
    if dacl.is_null() {
        return Err(AppError::bad_request(
            "object has a NULL DACL; refusing credential store",
        ));
    }
    if !dacl_is_protected(sd.0)? {
        return Err(AppError::bad_request(
            "product directory DACL is not protected; refusing credential store \
             (outside inheritable ACEs would reach SQLite children)",
        ));
    }
    let has_trusted_object_inherit = check_product_allow_aces(dacl, &allow)?;
    if !has_trusted_object_inherit {
        return Err(AppError::bad_request(
            "product directory lacks trusted OBJECT_INHERIT ALLOW ACEs; refusing credential store \
             (SQLite FILE children would fall back to the process default DACL)",
        ));
    }
    Ok(())
}

/// Ancestor namespace-integrity policy on a held directory handle.
///
/// Owner must be current user / SYSTEM / Administrators / exact
/// TrustedInstaller service SID (ancestor owner only). Unknown principals
/// may hold existing read/traverse plus FILE_ADD_SUBDIRECTORY (create-new
/// subdirectory) — never file-add/write-data, delete-child, write-DACL,
/// write-owner, or delete. INHERIT_ONLY ACEs grant nothing on this object:
/// type/flags are validated, then the current-directory mask is ignored
/// (children are independently verified; product creates use a protected SD).
/// Object/callback/unknown ACE types, unknown ACE flags, and NULL DACL fail
/// closed. Inherited ACEs are allowed when their SID/mask still satisfy this
/// policy (inheritance is not a trust root; every ACE is checked).
pub(crate) fn verify_ancestor_namespace_integrity(handle: HANDLE) -> AppResult<()> {
    let allow = AllowSids::current()?;
    let (owner, dacl, _sd) = fetch_owner_and_dacl(handle)?;
    if owner.is_null() || !allow.is_trusted_ancestor_owner(owner) {
        return Err(AppError::bad_request(
            "path ancestor is not owned by the current principal/SYSTEM/Administrators/TrustedInstaller; \
             refusing private store",
        ));
    }
    if dacl.is_null() {
        return Err(AppError::bad_request(
            "path ancestor has a NULL DACL; refusing private store",
        ));
    }

    let acl = unsafe { &*dacl };
    for i in 0..acl.AceCount {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i as u32, &mut ace_ptr) } == 0 {
            return Err(last_err("GetAce"));
        }
        if ace_ptr.is_null() {
            return Err(AppError::bad_request("ACE pointer is null; refusing"));
        }
        let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        reject_unsupported_ace_type(header.AceType)?;
        let ace_flags: ACE_FLAGS = header.AceFlags as ACE_FLAGS;
        if ace_flags & !ANCESTOR_ALLOWED_ACE_FLAGS != 0 {
            return Err(AppError::bad_request(
                "path ancestor ACCESS_ALLOWED ACE has unsupported flags; refusing private store",
            ));
        }
        if header.AceType as u32 == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        // INHERIT_ONLY grants nothing on this directory. Children are opened
        // relative a retained parent handle no-follow and independently
        // verified; created product SDs are protected so this ACE never
        // propagates into product. Ignore the current-directory mask.
        if ace_flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let sid = ace_sid(ace_ptr);
        if allow.contains(sid) {
            continue;
        }
        let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
        if ace.Mask & !ANCESTOR_UNKNOWN_ALLOWED_RIGHTS != 0 {
            return Err(AppError::bad_request(
                "path ancestor grants name-mutation/delete-child/write-DACL/write-owner \
                 or file-add/write-data to a principal outside the trusted owner/SYSTEM/Administrators set; \
                 refusing private store",
            ));
        }
    }
    Ok(())
}

// ----- held-handle path walk -----

/// Desired access for a held open (minimum required).
#[derive(Clone, Copy)]
enum OpenRights {
    /// Traverse-only ancestor: list/attributes/read-control/synchronize.
    Traverse,
    /// Parent directory used to create or delete children.
    ParentCreate,
    /// Regular file open for read + security query + possible delete.
    FileRead,
    /// Regular file create/write + security query + delete on cleanup.
    FileCreate,
}

impl OpenRights {
    fn mask(self) -> u32 {
        match self {
            OpenRights::Traverse => {
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            }
            OpenRights::ParentCreate => {
                FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_DELETE_CHILD
                    | FILE_LIST_DIRECTORY
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | DELETE
                    | SYNCHRONIZE
            }
            OpenRights::FileRead => {
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
            }
            OpenRights::FileCreate => {
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | DELETE
                    | SYNCHRONIZE
            }
        }
    }
}

/// Open `name` relative a retained parent handle (NT `RootDirectory`).
///
/// The parent handle keeps its object identity across ancestor renames; the
/// walk never re-resolves from a path string after a child is held. Create is
/// `FILE_CREATE` (exclusive, no overwrite); existing opens are `FILE_OPEN`.
/// `FILE_OPEN_REPARSE_POINT` is always set so junction/symlink components are
/// opened as the reparse object and then refused.
fn open_relative(
    parent: HANDLE,
    name: &std::ffi::OsStr,
    directory: bool,
    create: bool,
    sd: Option<*const SECURITY_DESCRIPTOR>,
    rights: OpenRights,
) -> Result<OwnedHandle, OpenError> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    wide.push(0);
    let byte_len = (wide.len() - 1) * 2;
    if byte_len > u16::MAX as usize {
        return Err(OpenError::Failed(AppError::bad_request(
            "path component too long",
        )));
    }
    let us = UNICODE_STRING {
        Length: byte_len as u16,
        MaximumLength: byte_len as u16,
        Buffer: wide.as_mut_ptr(),
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: sd.unwrap_or(std::ptr::null()),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut iosb = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = std::ptr::null_mut();
    let create_options = if directory {
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    } else {
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    };
    let disposition = if create { FILE_CREATE } else { FILE_OPEN };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            rights.mask(),
            &oa,
            &mut iosb,
            std::ptr::null(),
            0,
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
            disposition,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(ntstatus_to_open_error("NtCreateFile", status));
    }
    match OwnedHandle::from_raw(handle) {
        Ok(owned) => {
            if let Err(err) = reject_reparse_on_handle(owned.get()) {
                return Err(OpenError::Failed(err));
            }
            Ok(owned)
        }
        Err(err) => Err(OpenError::Failed(err)),
    }
}

fn reject_reparse_on_handle(handle: HANDLE) -> AppResult<()> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(last_err("GetFileInformationByHandle"));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AppError::bad_request(
            "path component is a reparse point (symlink/junction); refusing to follow",
        ));
    }
    Ok(())
}

fn handle_is_directory(handle: HANDLE) -> AppResult<bool> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(last_err("GetFileInformationByHandle"));
    }
    Ok(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0)
}

fn handle_link_count(handle: HANDLE) -> AppResult<u32> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(last_err("GetFileInformationByHandle"));
    }
    Ok(info.nNumberOfLinks)
}

struct FileIdentity {
    volume: u32,
    index_high: u32,
    index_low: u32,
}

fn handle_identity(handle: HANDLE) -> AppResult<FileIdentity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(last_err("GetFileInformationByHandle"));
    }
    Ok(FileIdentity {
        volume: info.dwVolumeSerialNumber,
        index_high: info.nFileIndexHigh,
        index_low: info.nFileIndexLow,
    })
}

fn identities_equal(a: &FileIdentity, b: &FileIdentity) -> bool {
    a.volume == b.volume && a.index_high == b.index_high && a.index_low == b.index_low
}

/// How a directory is validated while walking.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DirRole {
    /// Intermediate ancestor: namespace integrity only.
    Ancestor,
    /// Immediate parent of a product object: namespace integrity is enough
    /// because the created/verified product object itself is strict private.
    ObjectParent,
    /// A product directory (store dir): strict private DACL.
    ProductDir,
}

fn verify_dir_on_handle(handle: HANDLE, role: DirRole) -> AppResult<()> {
    if !handle_is_directory(handle)? {
        return Err(AppError::bad_request(
            "path component is not a directory; refusing private store",
        ));
    }
    match role {
        DirRole::Ancestor | DirRole::ObjectParent => verify_ancestor_namespace_integrity(handle),
        DirRole::ProductDir => verify_product_dir_on_handle(handle),
    }
}

/// Walk to the parent directory of `abs` with no-follow semantics.
///
/// Intermediate components use ancestor namespace integrity. The immediate
/// parent uses `parent_role`. Drive root is opened with traverse-only rights.
fn open_parent_nofollow(
    abs: &Path,
    parent_role: DirRole,
) -> AppResult<(OwnedHandle, std::ffi::OsString)> {
    let file_name = abs
        .file_name()
        .ok_or_else(|| AppError::bad_request("recovery path must have a file name"))?;
    if file_name.is_empty() {
        return Err(AppError::bad_request("recovery file name is empty"));
    }
    let parent = match abs.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => {
            return Err(AppError::bad_request(
                "recovery path must include a parent directory",
            ))
        }
    };

    let mut comps = parent.components();
    let root = comps
        .next()
        .ok_or_else(|| AppError::bad_request("recovery path must have a parent directory"))?;
    let root_name = match root {
        Component::Prefix(p) => std::ffi::OsString::from(p.as_os_str()),
        _ => {
            return Err(AppError::bad_request(
                "private store requires an absolute drive path",
            ))
        }
    };
    let mut current = open_drive_root(&root_name)?;
    // Root is an ancestor (SYSTEM-owned on Windows).
    verify_dir_on_handle(current.get(), DirRole::Ancestor)?;

    let mut names = Vec::new();
    for comp in comps {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(AppError::bad_request(
                    "parent-directory component refused in recovery path",
                ))
            }
            Component::Normal(n) => names.push(n.to_os_string()),
        }
    }

    let last = names.len().saturating_sub(1);
    for (idx, name) in names.iter().enumerate() {
        let role = if idx == last {
            parent_role
        } else {
            DirRole::Ancestor
        };
        let next = open_relative(current.get(), name, true, false, None, OpenRights::Traverse)
            .map_err(|e| e.into_app_error("open path component"))?;
        verify_dir_on_handle(next.get(), role)?;
        current = next;
    }
    if names.is_empty() {
        // File sits directly under the drive root; apply the requested role
        // to the root handle we already hold.
        verify_dir_on_handle(current.get(), parent_role)?;
    }
    Ok((current, file_name.to_os_string()))
}

fn open_drive_root(prefix: &std::ffi::OsStr) -> AppResult<OwnedHandle> {
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
    let mut wide: Vec<u16> = prefix.encode_wide().collect();
    wide.extend([b'\\' as u16, 0u16]);
    // Minimum rights: traverse/read-control only. FILE_ALL_ACCESS is not
    // required and fails for unprivileged preflight/read.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            OpenRights::Traverse.mask(),
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let owned = OwnedHandle::from_raw(handle)?;
    reject_reparse_on_handle(owned.get())?;
    if !handle_is_directory(owned.get())? {
        return Err(AppError::bad_request("drive root is not a directory"));
    }
    Ok(owned)
}

// ----- public operations -----

pub(crate) fn windows_preflight_new_private(
    abs: &Path,
    _file_name: &std::ffi::OsStr,
) -> AppResult<()> {
    reject_unsafe_windows_path(abs)?;
    let (parent, name) = open_parent_nofollow(abs, DirRole::ObjectParent)?;
    // Parent already verified during walk.
    match open_relative(
        parent.get(),
        &name,
        false,
        false,
        None,
        OpenRights::FileRead,
    ) {
        Err(OpenError::NotFound) => Ok(()),
        Err(OpenError::AlreadyExists) => Err(AppError::conflict(
            "recovery file already exists; refusing to overwrite",
            Some("create_new_only".to_string()),
        )),
        Err(OpenError::Failed(err)) => Err(err),
        Ok(_) => Err(AppError::conflict(
            "recovery file already exists; refusing to overwrite",
            Some("create_new_only".to_string()),
        )),
    }
}

pub(crate) fn windows_create_new_private(abs: &Path, contents: &[u8]) -> AppResult<()> {
    if contents.len() > MAX_PRIVATE_PAYLOAD_BYTES {
        return Err(AppError::bad_request(format!(
            "recovery payload exceeds {MAX_PRIVATE_PAYLOAD_BYTES} bytes"
        )));
    }
    if contents.is_empty() {
        return Err(AppError::bad_request("recovery payload is empty"));
    }
    reject_unsafe_windows_path(abs)?;
    let (parent, name) = open_parent_nofollow(abs, DirRole::ObjectParent)?;

    let sd = build_private_security_descriptor(false)?;
    let created = open_relative(
        parent.get(),
        &name,
        false,
        true,
        Some(sd.as_ptr()),
        OpenRights::FileCreate,
    )
    .map_err(|e| e.into_app_error("create private recovery file"))?;
    let identity = handle_identity(created.get())?;

    let result = (|| -> AppResult<()> {
        if handle_is_directory(created.get())? {
            return Err(AppError::bad_request(
                "recovery file is not a regular file after creation",
            ));
        }
        if handle_link_count(created.get())? != 1 {
            return Err(AppError::bad_request(
                "recovery file link count is not 1; refusing to write",
            ));
        }
        verify_private_object_on_handle(created.get())?;
        write_all_handle(created.get(), contents)
    })();

    if let Err(err) = result {
        delete_created_object(created.get(), &identity);
        return Err(err);
    }
    Ok(())
}

fn write_all_handle(handle: HANDLE, contents: &[u8]) -> AppResult<()> {
    use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, WriteFile};
    let mut written: u32 = 0;
    let ok = unsafe {
        WriteFile(
            handle,
            contents.as_ptr() as _,
            contents.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || written as usize != contents.len() {
        return Err(last_err("WriteFile private recovery file"));
    }
    if unsafe { FlushFileBuffers(handle) } == 0 {
        return Err(last_err("FlushFileBuffers private recovery file"));
    }
    Ok(())
}

/// Delete only the created object identity (never a swapped path).
fn delete_created_object(handle: HANDLE, expected: &FileIdentity) {
    if let Ok(cur) = handle_identity(handle) {
        if !identities_equal(&cur, expected) {
            return;
        }
    }
    let mut info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        let _ = SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &mut info as *mut FILE_DISPOSITION_INFO as _,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        );
    }
}

pub(crate) fn windows_ensure_private_store_dir(abs: &Path) -> AppResult<PathBuf> {
    reject_unsafe_windows_path(abs)?;
    let (parent, name) = open_parent_nofollow(abs, DirRole::ObjectParent)?;
    match open_relative(parent.get(), &name, true, false, None, OpenRights::Traverse) {
        Ok(dir) => {
            // Product directory must satisfy the strict private policy and
            // proven trusted child-inheritance boundary.
            verify_product_dir_on_handle(dir.get())?;
            Ok(abs.to_path_buf())
        }
        Err(err) if err.is_not_found() => {
            // Protected DACL + inheritable trusted ACEs so SQLite children
            // (WAL/SHM/journal, including delete+recreate) are private at
            // create time — no TokenDefaultDacl assumption.
            let sd = build_private_security_descriptor(true)?;
            let dir = open_relative(
                parent.get(),
                &name,
                true,
                true,
                Some(sd.as_ptr()),
                OpenRights::ParentCreate,
            )
            .map_err(|e| e.into_app_error("create private store directory"))?;
            verify_product_dir_on_handle(dir.get())?;
            Ok(abs.to_path_buf())
        }
        Err(err) => Err(err.into_app_error("open private store directory")),
    }
}

pub(crate) fn windows_create_private_store_file(abs: &Path) -> AppResult<()> {
    reject_unsafe_windows_path(abs)?;
    let (parent, name) = open_parent_nofollow(abs, DirRole::ProductDir)?;
    let sd = build_private_security_descriptor(false)?;
    let created = open_relative(
        parent.get(),
        &name,
        false,
        true,
        Some(sd.as_ptr()),
        OpenRights::FileCreate,
    )
    .map_err(|e| e.into_app_error("create private store file"))?;
    let identity = handle_identity(created.get())?;
    let result = (|| -> AppResult<()> {
        if handle_link_count(created.get())? != 1 {
            return Err(AppError::bad_request(
                "store file link count is not 1; refusing credential store",
            ));
        }
        verify_private_object_on_handle(created.get())?;
        Ok(())
    })();
    if let Err(err) = result {
        delete_created_object(created.get(), &identity);
        return Err(err);
    }
    // Pre-create sibling -wal / -shm with the same protected DACL so SQLite
    // reuses objects that already carry our private descriptor (no inherited
    // allow ACEs, no brief public sidecars).
    for suffix in ["-wal", "-shm"] {
        let mut side_name = name.clone();
        side_name.push(suffix);
        match open_relative(
            parent.get(),
            &side_name,
            false,
            true,
            Some(sd.as_ptr()),
            OpenRights::FileCreate,
        ) {
            Ok(_side) => {}
            Err(err) if err.is_already_exists() => {}
            Err(err) => return Err(err.into_app_error("create private store sidecar")),
        }
    }
    Ok(())
}

pub(crate) fn windows_verify_private_store_file(abs: &Path) -> AppResult<()> {
    reject_unsafe_windows_path(abs)?;
    let (parent, name) = open_parent_nofollow(abs, DirRole::ProductDir)?;
    let file = open_relative(
        parent.get(),
        &name,
        false,
        false,
        None,
        OpenRights::FileRead,
    )
    .map_err(|e| e.into_app_error("open private store file"))?;
    if handle_is_directory(file.get())? {
        return Err(AppError::bad_request("store object is not a regular file"));
    }
    if handle_link_count(file.get())? != 1 {
        return Err(AppError::bad_request(
            "store object link count is not 1; refusing credential store",
        ));
    }
    verify_private_object_on_handle(file.get())
}

pub(crate) fn windows_read_existing_private(
    abs: &Path,
    max_bytes: usize,
) -> AppResult<zeroize::Zeroizing<Vec<u8>>> {
    reject_unsafe_windows_path(abs)?;
    let (parent, name) = open_parent_nofollow(abs, DirRole::ObjectParent)?;
    let file = open_relative(
        parent.get(),
        &name,
        false,
        false,
        None,
        OpenRights::FileRead,
    )
    .map_err(|e| e.into_app_error("open private file"))?;
    if handle_is_directory(file.get())? {
        return Err(AppError::bad_request("private file is not a regular file"));
    }
    if handle_link_count(file.get())? != 1 {
        return Err(AppError::bad_request(
            "private file link count is not 1; refusing to read",
        ));
    }
    verify_private_object_on_handle(file.get())?;

    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let mut buf = zeroize::Zeroizing::new(vec![0u8; max_bytes + 1]);
    let mut filled = 0usize;
    while filled < buf.len() {
        let mut read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                file.get(),
                buf[filled..].as_mut_ptr() as _,
                (buf.len() - filled) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_err("ReadFile private file"));
        }
        if read == 0 {
            break;
        }
        filled += read as usize;
    }
    if filled > max_bytes {
        return Err(AppError::bad_request(format!(
            "private file exceeds {max_bytes} bytes"
        )));
    }
    buf.truncate(filled);
    Ok(buf)
}

pub(crate) fn windows_validate_preexisting_shape(abs: &Path) -> AppResult<StorePathPresence> {
    reject_unsafe_windows_path(abs)?;
    match std::fs::symlink_metadata(abs) {
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
            let (parent, name) = open_parent_nofollow(abs, DirRole::ObjectParent)?;
            let file = open_relative(
                parent.get(),
                &name,
                false,
                false,
                None,
                OpenRights::FileRead,
            )
            .map_err(|e| e.into_app_error("open store path"))?;
            reject_reparse_on_handle(file.get())?;
            Ok(StorePathPresence::RegularFile)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(StorePathPresence::Absent),
        Err(err) => Err(AppError::bad_request(format!(
            "cannot classify store path: {err}"
        ))),
    }
}

// ----- native regression tests (Windows only) -----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_file::{
        create_new_private_file, create_private_store_file, ensure_private_store_dir,
        preflight_new_private_file, read_existing_private_file, verify_private_store_file,
    };
    use windows_sys::Win32::Security::{
        WinBuiltinUsersSid, WinWorldSid, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };

    #[test]
    fn nt_and_win32_path_aliases_are_refused_before_io() {
        for raw in [
            r"C:store\secret",
            r"C:\store.\secret",
            r"C:\store\secret ",
            r"C:\store\LPT9",
        ] {
            assert!(
                reject_unsafe_windows_path(Path::new(raw)).is_err(),
                "unsafe path accepted: {raw}"
            );
        }
    }

    fn tmpdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        // Do NOT rewrite system or user temp ancestry. The directory we just
        // created is a normal user temp leaf under standard ancestry.
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    /// Aligned SD + ACL scratch for `SetNamedSecurityInfoW` test helpers.
    ///
    /// Absolute `SECURITY_DESCRIPTOR` requires pointer alignment; a `Vec<u8>`
    /// is only byte-aligned. Returns (storage, sd_ptr, acl_ptr).
    fn aligned_sd_acl(
        acl_len: usize,
    ) -> (
        Vec<u64>,
        *mut SECURITY_DESCRIPTOR,
        *mut windows_sys::Win32::Security::ACL,
    ) {
        let sd_size = std::mem::size_of::<SECURITY_DESCRIPTOR>();
        let total = sd_size + acl_len;
        let words = total.div_ceil(std::mem::size_of::<u64>());
        let mut storage = vec![0u64; words];
        let sd_ptr = storage.as_mut_ptr() as *mut SECURITY_DESCRIPTOR;
        let acl_ptr =
            unsafe { (sd_ptr as *mut u8).add(sd_size) } as *mut windows_sys::Win32::Security::ACL;
        (storage, sd_ptr, acl_ptr)
    }

    /// Build a DACL on `dir` that grants `everyone` the given mask (plus a
    /// user full-control ACE so the test can still create children).
    fn grant_everyone(dir: &Path, mask: u32) {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        let everyone = well_known_sid(WinWorldSid).expect("world sid");
        let user = current_user_sid().expect("user sid");
        let sys = well_known_sid(WinLocalSystemSid).expect("system sid");
        let adm = well_known_sid(WinBuiltinAdministratorsSid).expect("admins sid");

        let acl_len = 256usize;
        let (_storage, sd_ptr, acl_ptr) = aligned_sd_acl(acl_len);
        let sd_ps: PSECURITY_DESCRIPTOR = sd_ptr as PSECURITY_DESCRIPTOR;
        unsafe {
            assert!(InitializeSecurityDescriptor(sd_ps, 1) != 0);
            assert!(InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) != 0);
            for sid in [user.as_psid(), sys.as_psid(), adm.as_psid()] {
                assert!(
                    AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, 0, 0x001F_01FF, sid) != 0,
                    "AddAccessAllowedAceEx trusted"
                );
            }
            assert!(
                AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, 0, mask, everyone.as_psid()) != 0,
                "AddAccessAllowedAceEx everyone"
            );
            assert!(SetSecurityDescriptorDacl(sd_ps, 1, acl_ptr, 0) != 0);
            assert!(SetSecurityDescriptorControl(sd_ps, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0);
            let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
            wide.push(0);
            let rc = SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl_ptr,
                std::ptr::null_mut(),
            );
            assert_eq!(rc, 0, "SetNamedSecurityInfoW rc={rc}");
        }
    }

    /// Normal user temp ancestry + private final object (no ancestor rewrite).
    #[test]
    fn normal_user_temp_ancestry_allows_private_final_object() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        create_new_private_file(&path, b"CODE1\nCODE2\n").expect("create under normal temp");
        assert!(path.exists());
        let got = read_existing_private_file(&path, 1024).expect("read");
        assert_eq!(got.as_slice(), b"CODE1\nCODE2\n");
        // Preflight of a fresh name succeeds without creating.
        preflight_new_private_file(&base.join("other.txt")).expect("preflight");
        assert!(!base.join("other.txt").exists());
    }

    /// Store dir + DB file under normal temp ancestry.
    #[test]
    fn normal_user_temp_ancestry_allows_private_store() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db = dir.join("hs-server.db");
        create_private_store_file(&db).expect("store file");
        verify_private_store_file(&db).expect("verify store file");
    }

    /// Ancestor with unknown-principal name-mutation/delete-child is refused.
    #[test]
    fn foreign_sid_name_mutation_on_ancestor_is_denied() {
        let (_dir, base) = tmpdir();
        let hostile = base.join("hostile");
        std::fs::create_dir(&hostile).expect("hostile dir");
        // Everyone: FILE_ADD_FILE | FILE_DELETE_CHILD (name mutation).
        grant_everyone(&hostile, FILE_ADD_FILE | FILE_DELETE_CHILD);

        let target = hostile.join("recovery.txt");
        let err = create_new_private_file(&target, b"SECRET")
            .expect_err("must refuse ancestor with unknown name-mutation grant");
        let msg = err.to_string();
        assert!(
            msg.contains("name-mutation")
                || msg.contains("delete-child")
                || msg.contains("refusing private store")
                || msg.contains("path ancestor"),
            "msg={msg}"
        );
        assert!(!target.exists(), "no insecure fallback create");
        assert!(!msg.contains("SECRET"), "no secret in error");
    }

    /// Unknown-principal WRITE_DAC on an ancestor is refused.
    #[test]
    fn foreign_sid_write_dac_on_ancestor_is_denied() {
        let (_dir, base) = tmpdir();
        let hostile = base.join("hostile");
        std::fs::create_dir(&hostile).expect("hostile dir");
        grant_everyone(&hostile, WRITE_DAC | FILE_LIST_DIRECTORY | FILE_TRAVERSE);
        let err = create_new_private_file(&hostile.join("r.txt"), b"SECRET")
            .expect_err("must refuse ancestor with unknown write-DACL grant");
        assert!(
            err.to_string().contains("write-DACL")
                || err.to_string().contains("path ancestor")
                || err.to_string().contains("refusing"),
            "err={err}"
        );
        assert!(!hostile.join("r.txt").exists());
    }

    /// Read/traverse-only unknown grant on an ancestor is allowed (legitimate).
    #[test]
    fn foreign_sid_read_traverse_on_ancestor_is_allowed() {
        let (_dir, base) = tmpdir();
        let ok_dir = base.join("listed");
        std::fs::create_dir(&ok_dir).expect("listed dir");
        grant_everyone(
            &ok_dir,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        );
        create_new_private_file(&ok_dir.join("recovery.txt"), b"OK")
            .expect("read/traverse-only ancestor must allow private create");
        assert!(ok_dir.join("recovery.txt").exists());
    }

    /// Secure create is exclusive: no overwrite, no fallback write.
    #[test]
    fn secure_create_no_overwrite_and_no_fallback() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        create_new_private_file(&path, b"FIRST").expect("create");
        let err = create_new_private_file(&path, b"SECOND").expect_err("no overwrite");
        assert!(
            err.to_string().contains("already exists")
                || err.to_string().contains("create_new_only"),
            "err={err}"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"FIRST");
    }

    /// Owner PSID backing must outlive the descriptor through kernel use.
    /// Allocation churn would expose a dangling `Owner` pointer; then create
    /// a real file and verify the on-disk owner is the current user.
    #[test]
    fn owner_sid_lives_through_churn_and_create() {
        use windows_sys::Win32::Security::GetSecurityDescriptorOwner;
        let sd = build_private_security_descriptor(false).expect("build sd");
        // Alignment: absolute SECURITY_DESCRIPTOR requires pointer alignment.
        assert_eq!(
            sd.as_ptr() as usize % std::mem::align_of::<*mut core::ffi::c_void>(),
            0,
            "SECURITY_DESCRIPTOR storage must be pointer-aligned"
        );

        // Allocation churn: reuse/free heap so a dangling Owner is likely wrong.
        for _ in 0..256 {
            let junk: Vec<u64> = vec![0xDEAD_BEEF_u64; 4096];
            drop(junk);
            let more: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; 2048]).collect();
            drop(more);
        }

        let user = current_user_sid().expect("user sid");
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted: windows_sys::core::BOOL = 0;
        let ok = unsafe {
            GetSecurityDescriptorOwner(
                sd.as_ptr() as PSECURITY_DESCRIPTOR,
                &mut owner,
                &mut defaulted,
            )
        };
        assert!(ok != 0, "GetSecurityDescriptorOwner");
        assert!(
            sid_eq(owner, user.as_psid()),
            "descriptor Owner must be current user after allocation churn"
        );
        assert!(
            sid_eq(sd.owner_sid(), user.as_psid()),
            "owned field must match current user"
        );

        // Actual create + on-disk owner verification (not a generic error).
        let (_dir, base) = tmpdir();
        let path = base.join("owner-check.txt");
        create_new_private_file(&path, b"OWNER").expect("create");
        let (parent, name) = open_parent_nofollow(&path, DirRole::ObjectParent).expect("parent");
        let file = open_relative(
            parent.get(),
            &name,
            false,
            false,
            None,
            OpenRights::FileRead,
        )
        .expect("open created");
        verify_private_object_on_handle(file.get()).expect("on-disk owner must be current user");
    }

    /// Install an ACE on `path` with arbitrary flags/mask/sid (test helper).
    fn add_ace(path: &Path, sid: PSID, mask: u32, ace_flags: ACE_FLAGS) {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        let acl_len = 256usize;
        let (_storage, sd_ptr, acl_ptr) = aligned_sd_acl(acl_len);
        let sd_ps: PSECURITY_DESCRIPTOR = sd_ptr as PSECURITY_DESCRIPTOR;
        unsafe {
            assert!(InitializeSecurityDescriptor(sd_ps, 1) != 0);
            assert!(InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) != 0);
            let user = current_user_sid().expect("user");
            let sys = well_known_sid(WinLocalSystemSid).expect("sys");
            let adm = well_known_sid(WinBuiltinAdministratorsSid).expect("adm");
            for s in [user.as_psid(), sys.as_psid(), adm.as_psid()] {
                assert!(
                    AddAccessAllowedAceEx(
                        acl_ptr,
                        ACL_REVISION,
                        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                        0x001F_01FF,
                        s
                    ) != 0
                );
            }
            assert!(AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, ace_flags, mask, sid) != 0);
            assert!(SetSecurityDescriptorDacl(sd_ps, 1, acl_ptr, 0) != 0);
            assert!(SetSecurityDescriptorControl(sd_ps, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0);
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            wide.push(0);
            let rc = SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl_ptr,
                std::ptr::null_mut(),
            );
            assert_eq!(rc, 0, "SetNamedSecurityInfoW rc={rc}");
        }
    }

    fn set_null_dacl(path: &Path) {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        unsafe {
            let rc = SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
            );
            assert_eq!(rc, 0, "SetNamedSecurityInfoW null DACL rc={rc}");
        }
    }

    /// Sidecar path helper.
    fn sidecar(db_path: &Path, suffix: &str) -> PathBuf {
        let mut os = db_path.as_os_str().to_os_string();
        os.push(suffix);
        PathBuf::from(os)
    }

    /// Bounded native owner classification label. Never prints SIDs,
    /// account names, or paths — only the declared role bucket.
    fn classify_owner_label(allow: &AllowSids, sid: PSID) -> &'static str {
        if sid.is_null() {
            return "null";
        }
        if allow.is_user(sid) {
            return "currentUser";
        }
        if sid_eq(sid, allow.system.as_psid()) {
            return "SYSTEM";
        }
        if sid_eq(sid, allow.admins.as_psid()) {
            return "Administrators";
        }
        if sid_eq(sid, allow.trusted_installer.as_psid()) {
            return "TrustedInstaller";
        }
        "other"
    }

    /// Process TokenOwner classification (may differ from TokenUser on
    /// elevated tokens). Bounded: classification only.
    fn process_token_owner_label(allow: &AllowSids) -> &'static str {
        use windows_sys::Win32::Security::{TokenOwner, TOKEN_OWNER};
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return "token-query-failed";
        }
        let token = match OwnedHandle::from_raw(token) {
            Ok(t) => t,
            Err(_) => return "token-handle-failed",
        };
        let mut needed: u32 = 0;
        unsafe {
            GetTokenInformation(
                token.get(),
                TokenOwner,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed == 0 || needed > 4096 {
            return "token-owner-size-failed";
        }
        let mut buf = SidBuf::alloc_bytes(needed as usize);
        if unsafe {
            GetTokenInformation(
                token.get(),
                TokenOwner,
                buf.as_mut_psid() as _,
                needed,
                &mut needed,
            )
        } == 0
        {
            return "token-owner-query-failed";
        }
        if (needed as usize) > buf.storage.len() * std::mem::size_of::<u64>() {
            return "token-owner-overflow";
        }
        let owner = buf.as_psid() as *const TOKEN_OWNER;
        let sid = unsafe { (*owner).Owner };
        classify_owner_label(allow, sid)
    }

    /// Diagnostic line: role + owner classification + TokenOwner class.
    /// Printed only from test failure seams / the dedicated diagnostic test.
    fn owner_diagnostic_line(role: &str, handle: HANDLE) -> String {
        let allow = match AllowSids::current() {
            Ok(a) => a,
            Err(_) => return format!("diag role={role} allow-sids-unavailable"),
        };
        let owner_label = match fetch_owner_and_dacl(handle) {
            Ok((owner, _dacl, _sd)) => classify_owner_label(&allow, owner),
            Err(_) => {
                return format!(
                    "diag role={role} object-owner=fetch-failed token-owner={}",
                    process_token_owner_label(&allow)
                )
            }
        };
        let token_owner = process_token_owner_label(&allow);
        let token_user = classify_owner_label(&allow, allow.user.as_psid());
        format!(
            "diag role={role} object-owner={owner_label} token-user={token_user} token-owner={token_owner}"
        )
    }

    /// Path wrapper for [`owner_diagnostic_line`] (opens read-only, no-follow).
    fn owner_diagnostic_path(role: &str, path: &Path) -> String {
        match open_parent_nofollow(path, DirRole::ObjectParent) {
            Ok((parent, name)) => {
                match open_relative(
                    parent.get(),
                    &name,
                    false,
                    false,
                    None,
                    OpenRights::FileRead,
                ) {
                    Ok(file) => owner_diagnostic_line(role, file.get()),
                    Err(_) => format!("diag role={role} open-failed"),
                }
            }
            Err(_) => format!("diag role={role} parent-open-failed"),
        }
    }

    /// Require a live sidecar (present now) and verify it is private.
    /// On refusal, panic includes bounded owner metadata (classification only).
    fn require_live_private(db_path: &Path, suffix: &str) {
        let p = sidecar(db_path, suffix);
        assert!(
            p.exists(),
            "sidecar {suffix} must exist while SQLite holds the connection after write"
        );
        if let Err(e) = verify_private_store_file(&p) {
            let diag = owner_diagnostic_path("sqlite-sidecar", &p);
            panic!("live sidecar {suffix} must be private: {e}\n{diag}");
        }
    }

    /// SQLite lifecycle: WAL/SHM private **while the connection is live after
    /// an actual write** (not after close, when SQLite deletes them). Rollback
    /// journal private **inside an uncommitted transaction**. Close/reopen and
    /// repeat live checks to prove create/recreate.
    #[test]
    fn sqlite_lifecycle_live_wal_shm_journal_stay_private() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db_path = dir.join("hs-server.db");
        create_private_store_file(&db_path).expect("create db");

        // --- Phase 1: first open, WAL mode, committed write, live check ---
        {
            let conn = rusqlite::Connection::open(&db_path).expect("open sqlite");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("wal");
            conn.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES ('SECRET');")
                .expect("write");
            verify_private_store_file(&db_path).expect("db private while live");
            require_live_private(&db_path, "-wal");
            require_live_private(&db_path, "-shm");
            conn.close().expect("close");
        }
        verify_private_store_file(&db_path).expect("db private after close");

        // --- Phase 2: reopen (recreates WAL/SHM), live check after write ---
        {
            let conn = rusqlite::Connection::open(&db_path).expect("reopen");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("wal");
            conn.execute("INSERT INTO t VALUES ('MORE')", [])
                .expect("more");
            verify_private_store_file(&db_path).expect("db private on reopen live");
            require_live_private(&db_path, "-wal");
            require_live_private(&db_path, "-shm");
            conn.close().expect("close2");
        }

        // --- Phase 3: rollback journal inside an uncommitted transaction ---
        {
            let conn = rusqlite::Connection::open(&db_path).expect("reopen3");
            conn.pragma_update(None, "journal_mode", "DELETE")
                .expect("delete journal");
            let tx = conn.unchecked_transaction().expect("begin uncommitted tx");
            tx.execute("INSERT INTO t VALUES ('J')", [])
                .expect("j write");
            // Journal must exist and be private while the write is uncommitted.
            require_live_private(&db_path, "-journal");
            verify_private_store_file(&db_path).expect("db private during tx");
            tx.rollback().expect("rollback");
            conn.close().expect("close3");
        }

        // --- Phase 4: reopen again, WAL live check proves recreation ---
        {
            let conn = rusqlite::Connection::open(&db_path).expect("reopen4");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("wal");
            conn.execute("INSERT INTO t VALUES ('AGAIN')", [])
                .expect("again");
            require_live_private(&db_path, "-wal");
            require_live_private(&db_path, "-shm");
            conn.close().expect("close4");
        }
        verify_private_store_file(&db_path).expect("db private final");
    }

    /// Product dir with only CONTAINER_INHERIT (no OBJECT_INHERIT) cannot
    /// guarantee ACL on SQLite FILE children — refuse without re-ACL.
    #[test]
    fn container_only_inheritable_product_dir_is_refused() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        verify_product_dir_on_handle_via_ensure(&dir);
        grant_container_only_trusted(&dir);
        let err = ensure_private_store_dir(&dir).expect_err(
            "must refuse product dir lacking OBJECT_INHERIT (container-only cannot ACL file children)",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("OBJECT_INHERIT")
                || msg.contains("default DACL")
                || msg.contains("refusing"),
            "msg={msg}"
        );
        // Original ACL preserved (no silent re-ACL of existing dirs).
        let err2 = ensure_private_store_dir(&dir).expect_err("still refused after non-mutation");
        assert!(
            err2.to_string().contains("OBJECT_INHERIT")
                || err2.to_string().contains("default DACL")
                || err2.to_string().contains("refusing"),
            "err2={err2}"
        );
    }

    /// Rebuild `dir` DACL: trusted SIDs with CONTAINER_INHERIT only (no OBJECT_INHERIT).
    fn grant_container_only_trusted(dir: &Path) {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        let user = current_user_sid().expect("user");
        let sys = well_known_sid(WinLocalSystemSid).expect("sys");
        let adm = well_known_sid(WinBuiltinAdministratorsSid).expect("adm");
        let acl_len = 256usize;
        let (_storage, sd_ptr, acl_ptr) = aligned_sd_acl(acl_len);
        let sd_ps: PSECURITY_DESCRIPTOR = sd_ptr as PSECURITY_DESCRIPTOR;
        unsafe {
            assert!(InitializeSecurityDescriptor(sd_ps, 1) != 0);
            assert!(InitializeAcl(acl_ptr, acl_len as u32, ACL_REVISION) != 0);
            for s in [user.as_psid(), sys.as_psid(), adm.as_psid()] {
                assert!(
                    AddAccessAllowedAceEx(
                        acl_ptr,
                        ACL_REVISION,
                        CONTAINER_INHERIT_ACE,
                        0x001F_01FF,
                        s
                    ) != 0
                );
            }
            assert!(SetSecurityDescriptorDacl(sd_ps, 1, acl_ptr, 0) != 0);
            assert!(SetSecurityDescriptorControl(sd_ps, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0);
            let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
            wide.push(0);
            let rc = SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl_ptr,
                std::ptr::null_mut(),
            );
            assert_eq!(rc, 0, "SetNamedSecurityInfoW container-only rc={rc}");
        }
    }

    fn verify_product_dir_on_handle_via_ensure(dir: &Path) {
        ensure_private_store_dir(dir).expect("product dir valid before mutation");
    }

    /// Unknown SID INHERIT_ONLY on a product directory must fail closed —
    /// it would propagate read/write into SQLite-created children.
    #[test]
    fn unknown_sid_inherit_only_on_product_dir_is_refused() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let everyone = well_known_sid(WinWorldSid).expect("world");
        add_ace(
            &dir,
            everyone.as_psid(),
            0x001F_01FF,
            INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE,
        );
        // ensure_private_store_dir re-verifies the product directory.
        let err = ensure_private_store_dir(&dir)
            .expect_err("must refuse product dir with unknown INHERIT_ONLY child grant");
        let msg = err.to_string();
        assert!(
            msg.contains("allowlist") || msg.contains("refusing"),
            "msg={msg}"
        );
    }

    /// NULL DACL is never private.
    #[test]
    fn null_dacl_on_store_file_is_refused() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db = dir.join("hs-server.db");
        create_private_store_file(&db).expect("create");
        set_null_dacl(&db);
        let err = verify_private_store_file(&db).expect_err("NULL DACL must refuse");
        assert!(
            err.to_string().contains("NULL DACL") || err.to_string().contains("refusing"),
            "err={err}"
        );
    }

    /// Unknown non-Everyone SID with full control on a product file is refused.
    #[test]
    fn unknown_users_sid_on_product_file_is_refused() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db = dir.join("hs-server.db");
        create_private_store_file(&db).expect("create");
        let users = well_known_sid(WinBuiltinUsersSid).expect("users");
        add_ace(&db, users.as_psid(), 0x001F_01FF, 0);
        let err = verify_private_store_file(&db).expect_err("unknown users SID must refuse");
        assert!(
            err.to_string().contains("allowlist") || err.to_string().contains("refusing"),
            "err={err}"
        );
    }

    /// Hard-linked store file is refused (nlink != 1).
    #[test]
    fn hardlink_store_file_is_refused() {
        use windows_sys::Win32::Storage::FileSystem::CreateHardLinkW;
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db = dir.join("hs-server.db");
        create_private_store_file(&db).expect("create");
        let mut src: Vec<u16> = db.as_os_str().encode_wide().collect();
        src.push(0);
        let link = dir.join("hs-server-link.db");
        let mut dst: Vec<u16> = link.as_os_str().encode_wide().collect();
        dst.push(0);
        let ok = unsafe { CreateHardLinkW(dst.as_ptr(), src.as_ptr(), std::ptr::null()) };
        assert!(ok != 0, "CreateHardLinkW");
        let err = verify_private_store_file(&db).expect_err("hardlink must refuse");
        assert!(
            err.to_string().contains("link count") || err.to_string().contains("refusing"),
            "err={err}"
        );
    }

    /// Reparse/junction store file is refused without following.
    #[test]
    fn reparse_store_file_is_refused() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let target = dir.join("target.db");
        create_private_store_file(&target).expect("target");
        let link = dir.join("hs-server.db");
        std::os::windows::fs::symlink_file(&target, &link).expect("symlink");
        let err = crate::private_file::validate_preexisting_store_shape(&link)
            .expect_err("reparse must refuse");
        assert!(
            err.to_string().contains("symlink") || err.to_string().contains("reparse"),
            "err={err}"
        );
    }

    // Only owned fixtures need foreign-owner assignment. Use a thread token;
    // never enable SeRestorePrivilege on the process shared by parallel tests.
    struct RestorePrivilegeScope {
        previous: Option<OwnedHandle>,
        _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    impl Drop for RestorePrivilegeScope {
        fn drop(&mut self) {
            use windows_sys::Win32::Security::RevertToSelf;
            use windows_sys::Win32::System::Threading::SetThreadToken;
            let ok = unsafe {
                match &self.previous {
                    Some(token) => SetThreadToken(std::ptr::null(), token.get()),
                    None => RevertToSelf(),
                }
            };
            // Test-only fatal cleanup failure: continuing would leak elevated
            // thread context into a later test, including during unwinding.
            if ok == 0 {
                std::process::abort();
            }
        }
    }

    fn enable_restore_privilege() -> RestorePrivilegeScope {
        use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, ERROR_SUCCESS};
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, ImpersonateSelf, LookupPrivilegeValueW, SecurityImpersonation,
            LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_IMPERSONATE,
            TOKEN_PRIVILEGES,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
        let mut previous: HANDLE = std::ptr::null_mut();
        let opened = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut previous,
            )
        };
        let previous = if opened != 0 {
            Some(OwnedHandle::from_raw(previous).expect("previous thread token"))
        } else {
            assert_eq!(
                unsafe { GetLastError() },
                ERROR_NO_TOKEN,
                "query previous thread token"
            );
            None
        };
        assert!(
            unsafe { ImpersonateSelf(SecurityImpersonation) } != 0,
            "ImpersonateSelf"
        );
        // Construct immediately: all subsequent assertion failures unwind back
        // to the exact previous thread context.
        let scope = RestorePrivilegeScope {
            previous,
            _same_thread: std::marker::PhantomData,
        };
        let mut token: HANDLE = std::ptr::null_mut();
        assert!(
            unsafe {
                OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    1,
                    &mut token,
                )
            } != 0,
            "OpenThreadToken for SeRestorePrivilege"
        );
        let token = OwnedHandle::from_raw(token).expect("thread token handle");
        let mut luid = unsafe { std::mem::zeroed::<windows_sys::Win32::Foundation::LUID>() };
        let name: Vec<u16> = "SeRestorePrivilege"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        assert!(
            unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) } != 0,
            "LookupPrivilegeValueW SeRestorePrivilege"
        );
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = unsafe {
            AdjustTokenPrivileges(
                token.get(),
                0,
                &tp,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let error = unsafe { GetLastError() };
        assert!(ok != 0, "AdjustTokenPrivileges SeRestorePrivilege");
        assert_eq!(
            error, ERROR_SUCCESS,
            "SeRestorePrivilege must actually be assigned"
        );
        scope
    }

    #[test]
    fn restore_fixture_privilege_does_not_escape_unwind() {
        use windows_sys::Win32::Foundation::ERROR_NO_TOKEN;
        use windows_sys::Win32::Security::{
            TokenPrivileges, TokenStatistics, TOKEN_INFORMATION_CLASS,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

        fn token_bytes(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Vec<u8> {
            let mut needed = 0;
            unsafe {
                GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed);
            }
            assert!(needed > 0 && needed <= 65_536, "bounded token metadata");
            let mut storage = vec![0u64; (needed as usize).div_ceil(8)];
            assert!(
                unsafe {
                    GetTokenInformation(
                        token,
                        class,
                        storage.as_mut_ptr().cast(),
                        needed,
                        &mut needed,
                    )
                } != 0,
                "query token metadata"
            );
            assert!(needed as usize <= storage.len() * 8);
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize) }
                .to_vec()
        }

        fn thread_metadata() -> Option<Vec<u8>> {
            let mut handle = std::ptr::null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut handle) } == 0 {
                assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
                None
            } else {
                let token = OwnedHandle::from_raw(handle).expect("thread token");
                Some(token_bytes(token.get(), TokenStatistics))
            }
        }

        let mut handle = std::ptr::null_mut();
        assert!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } != 0);
        let process = OwnedHandle::from_raw(handle).expect("process token");
        let before_process = token_bytes(process.get(), TokenPrivileges);
        let before_thread = thread_metadata();
        let result = std::panic::catch_unwind(|| {
            let _scope = enable_restore_privilege();
            assert!(
                thread_metadata().is_some(),
                "fixture must impersonate on this thread"
            );
            panic!("deliberate fixture unwind");
        });
        assert!(result.is_err());
        assert_eq!(
            thread_metadata(),
            before_thread,
            "restore the previous thread context"
        );
        assert_eq!(
            token_bytes(process.get(), TokenPrivileges),
            before_process,
            "parallel tests must retain unchanged process privileges"
        );
    }

    /// Set the object owner to `sid` (SeRestorePrivilege for non-self owners).
    fn set_owner(path: &Path, sid: PSID) {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                sid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "SetNamedSecurityInfoW owner rc={rc}");
    }

    /// Exact TrustedInstaller SID parses and is accepted as ancestor owner.
    #[test]
    fn trusted_installer_owner_on_ancestor_is_allowed() {
        let _privilege = enable_restore_privilege();
        let ti = trusted_installer_sid().expect("trusted installer sid");
        assert!(!ti.as_psid().is_null());
        let (_dir, base) = tmpdir();
        let mid = base.join("ti-ancestor");
        std::fs::create_dir(&mid).expect("ti-ancestor dir");
        set_owner(&mid, ti.as_psid());
        create_new_private_file(&mid.join("recovery.txt"), b"OK")
            .expect("TrustedInstaller ancestor owner must allow private create");
        assert!(mid.join("recovery.txt").exists());
    }

    /// TrustedInstaller is not a product-dir owner (final store stays
    /// current-principal owned).
    #[test]
    fn trusted_installer_owner_on_product_dir_is_refused() {
        let _privilege = enable_restore_privilege();
        let ti = trusted_installer_sid().expect("trusted installer sid");
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        set_owner(&dir, ti.as_psid());
        let err = ensure_private_store_dir(&dir)
            .expect_err("product dir owner must remain current principal");
        let msg = err.to_string();
        assert!(
            msg.contains("owned by the current process principal")
                || msg.contains("refusing credential store"),
            "msg={msg}"
        );
    }

    /// TrustedInstaller is never a product DACL allowlist principal.
    #[test]
    fn trusted_installer_dac_on_product_file_is_refused() {
        let ti = trusted_installer_sid().expect("trusted installer sid");
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db = dir.join("hs-server.db");
        create_private_store_file(&db).expect("create");
        add_ace(&db, ti.as_psid(), 0x001F_01FF, 0);
        let err = verify_private_store_file(&db)
            .expect_err("TrustedInstaller product DACL ACE must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("allowlist") || msg.contains("refusing"),
            "msg={msg}"
        );
    }

    /// Unknown read/traverse + FILE_ADD_SUBDIRECTORY on an ancestor is allowed
    /// (create-new subdirectory only; observed normal Temp root grant).
    #[test]
    fn foreign_sid_add_subdirectory_on_ancestor_is_allowed() {
        let (_dir, base) = tmpdir();
        let ok_dir = base.join("listed");
        std::fs::create_dir(&ok_dir).expect("listed dir");
        grant_everyone(
            &ok_dir,
            FILE_ADD_SUBDIRECTORY
                | FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE,
        );
        create_new_private_file(&ok_dir.join("recovery.txt"), b"OK")
            .expect("FILE_ADD_SUBDIRECTORY ancestor must allow private create");
        assert!(ok_dir.join("recovery.txt").exists());
    }

    /// FILE_ADD_FILE / FILE_WRITE_DATA (bit 0x2) on an ancestor is refused.
    #[test]
    fn foreign_sid_add_file_on_ancestor_is_denied() {
        let (_dir, base) = tmpdir();
        let hostile = base.join("hostile");
        std::fs::create_dir(&hostile).expect("hostile dir");
        grant_everyone(
            &hostile,
            FILE_ADD_FILE | FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        );
        let target = hostile.join("recovery.txt");
        let err = create_new_private_file(&target, b"SECRET")
            .expect_err("FILE_ADD_FILE on ancestor must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("file-add/write-data")
                || msg.contains("name-mutation")
                || msg.contains("refusing private store")
                || msg.contains("path ancestor"),
            "msg={msg}"
        );
        assert!(!target.exists(), "no insecure fallback create");
        assert!(!msg.contains("SECRET"), "no secret in error");
    }

    /// FILE_WRITE_DATA (same bit 0x2 as FILE_ADD_FILE) on an ancestor is refused.
    #[test]
    fn foreign_sid_write_data_on_ancestor_is_denied() {
        let (_dir, base) = tmpdir();
        let hostile = base.join("hostile");
        std::fs::create_dir(&hostile).expect("hostile dir");
        grant_everyone(
            &hostile,
            FILE_WRITE_DATA | FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        );
        let err = create_new_private_file(&hostile.join("r.txt"), b"SECRET")
            .expect_err("FILE_WRITE_DATA on ancestor must refuse");
        assert!(
            err.to_string().contains("file-add/write-data")
                || err.to_string().contains("refusing private store")
                || err.to_string().contains("path ancestor"),
            "err={err}"
        );
        assert!(!hostile.join("r.txt").exists());
    }

    /// GENERIC_WRITE on an ancestor is refused.
    #[test]
    fn foreign_sid_generic_write_on_ancestor_is_denied() {
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        let (_dir, base) = tmpdir();
        let hostile = base.join("hostile");
        std::fs::create_dir(&hostile).expect("hostile dir");
        grant_everyone(
            &hostile,
            GENERIC_WRITE | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
        );
        let err = create_new_private_file(&hostile.join("r.txt"), b"SECRET")
            .expect_err("GENERIC_WRITE on ancestor must refuse");
        assert!(
            err.to_string().contains("file-add/write-data")
                || err.to_string().contains("refusing private store")
                || err.to_string().contains("path ancestor"),
            "err={err}"
        );
        assert!(!hostile.join("r.txt").exists());
    }

    /// WRITE_OWNER / write-attributes / write-EA on an ancestor are refused.
    #[test]
    fn foreign_sid_write_owner_attrs_ea_on_ancestor_is_denied() {
        for mask in [
            WRITE_OWNER | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
            FILE_WRITE_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
            FILE_WRITE_EA | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
        ] {
            let (_dir, base) = tmpdir();
            let hostile = base.join("hostile");
            std::fs::create_dir(&hostile).expect("hostile dir");
            grant_everyone(&hostile, mask);
            let err = create_new_private_file(&hostile.join("r.txt"), b"SECRET")
                .expect_err("write-owner/attrs/EA on ancestor must refuse");
            let msg = err.to_string();
            assert!(
                msg.contains("file-add/write-data")
                    || msg.contains("refusing private store")
                    || msg.contains("path ancestor"),
                "mask=0x{mask:08X} msg={msg}"
            );
            assert!(!hostile.join("r.txt").exists());
        }
    }

    /// INHERIT_ONLY on an ancestor grants nothing on that object: unknown
    /// current-write-looking masks are ignored after type/flags validation.
    #[test]
    fn ancestor_inherit_only_unknown_mutation_is_ignored() {
        use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE};
        let (_dir, base) = tmpdir();
        let ok_dir = base.join("listed");
        std::fs::create_dir(&ok_dir).expect("listed dir");
        let everyone = well_known_sid(WinWorldSid).expect("world");
        add_ace(
            &ok_dir,
            everyone.as_psid(),
            GENERIC_ALL | GENERIC_WRITE | FILE_ADD_FILE | FILE_WRITE_DATA | FILE_DELETE_CHILD,
            INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        );
        create_new_private_file(&ok_dir.join("recovery.txt"), b"OK")
            .expect("ancestor INHERIT_ONLY must not grant current-directory mutation");
        assert!(ok_dir.join("recovery.txt").exists());
    }

    /// Same unknown INHERIT_ONLY on a product directory is still refused
    /// (SQLite children would inherit).
    #[test]
    fn product_dir_inherit_only_unknown_still_denied() {
        use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE};
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let everyone = well_known_sid(WinWorldSid).expect("world");
        add_ace(
            &dir,
            everyone.as_psid(),
            GENERIC_ALL | GENERIC_WRITE | FILE_ADD_FILE | FILE_WRITE_DATA,
            INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        );
        let err = ensure_private_store_dir(&dir)
            .expect_err("product dir unknown INHERIT_ONLY must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("allowlist") || msg.contains("refusing"),
            "msg={msg}"
        );
    }

    /// Unknown preexisting final name cannot be overwritten, re-ACL'd, or
    /// receive a secret write.
    #[test]
    fn unknown_preexisting_final_is_not_overwritten_or_reacled() {
        let (_dir, base) = tmpdir();
        let path = base.join("recovery.txt");
        std::fs::write(&path, b"PREEXISTING").expect("seed preexisting");
        let users = well_known_sid(WinBuiltinUsersSid).expect("users");
        add_ace(&path, users.as_psid(), 0x001F_01FF, 0);
        let err = create_new_private_file(&path, b"SECRET")
            .expect_err("preexisting final name must not be overwritten");
        let msg = err.to_string();
        assert!(
            msg.contains("already exists") || msg.contains("create_new_only"),
            "msg={msg}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read unchanged"),
            b"PREEXISTING",
            "no secret write over preexisting final"
        );
        assert!(!msg.contains("SECRET"), "no secret in error");
    }

    /// Bounded native metadata diagnostic for SQLite-created sidecars vs
    /// explicit create. Panics with role + owner classification (and process
    /// TokenOwner class) when a SQLite-recreated sidecar is refused by the
    /// product owner gate — the observed owner-policy boundary under
    /// diagnosis. No SIDs, account names, or paths in the message.
    #[test]
    fn sqlite_recreated_sidecar_owner_class_diagnostic() {
        let (_dir, base) = tmpdir();
        let dir = base.join("store");
        ensure_private_store_dir(&dir).expect("store dir");
        let db_path = dir.join("hs-server.db");
        create_private_store_file(&db_path).expect("create db");
        {
            let conn = rusqlite::Connection::open(&db_path).expect("open sqlite");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("wal");
            conn.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES ('X');")
                .expect("write");
            conn.close().expect("close");
        }
        // Close checkpoints and deletes WAL/SHM; reopen recreates them with
        // the process default owner (hypothesis: TokenOwner, not TokenUser).
        {
            let conn = rusqlite::Connection::open(&db_path).expect("reopen");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("wal");
            conn.execute("INSERT INTO t VALUES ('Y')", [])
                .expect("more");
            // Collect both live objects before closing SQLite or reporting
            // a refusal. Closing may remove the objects being diagnosed.
            let mut diagnostics = Vec::new();
            let mut refused = false;
            for suffix in ["-wal", "-shm"] {
                let p = sidecar(&db_path, suffix);
                let role = format!("sqlite-recreated-{suffix}");
                diagnostics.push(owner_diagnostic_path(&role, &p));
                refused |= verify_private_store_file(&p).is_err();
            }
            conn.close().expect("close2");
            assert!(!refused, "{}", diagnostics.join("\n"));
        }
    }
}
