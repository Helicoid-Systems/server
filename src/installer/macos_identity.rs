//! Read-only observation of the fixed macOS service identity.
//!
//! The product identity is `_helicoid`. This module answers one question:
//! what does the local Directory Services node say about that exact account,
//! and may an installer adopt it? It does not create the account, choose a UID
//! or GID, write a plist, load a service, plan, apply, or claim readiness.
//!
//! # Policy
//!
//! - An existing account is never adopted from its name alone. This revision
//!   defines no independent product-ownership evidence (install receipt,
//!   signature, or recorded identity), so every existing account is refused
//!   with [`IdentityRefusal::OwnershipNotVerified`]. Product policy permits an
//!   existing account only with an independently verified Helicoid-owned
//!   receipt; that verifier does not exist yet.
//! - An absent record is [`ServiceIdentityDecision::AccountAbsentObservation`]
//!   only when the fixed service group is also absent. That is an observation,
//!   not proof the names are free and not authorization to create them. If the
//!   user is absent but the group already exists, the result is
//!   [`ServiceIdentityDecision::AccountAbsentGroupPresentObservation`] and a
//!   fresh-install plan is refused. The read-only macOS plan may use the fully
//!   absent observation to review a fresh install. A future reviewed creation
//!   must use collision-safe create semantics and re-observe the exact
//!   identity. This module chooses no UID/GID and performs no creation.
//! - Unreadable, malformed, oversized, or ambiguous observations become
//!   [`ServiceIdentityDecision::Unavailable`]; they are never absence and never
//!   a clean identity.
//!
//! # Observation
//!
//! All observations use `/usr/bin/dscl` with fixed, absolute argv and no shell.
//! Numeric UID/GID arguments are typed `u32`, so they cannot carry shell text.
//! Output is bounded by bytes, lines, attributes, and records. The commands are
//! read-only `-read`, `-search`, and `-list` operations against the local
//! directory node (`.`), with `LC_ALL=C`.
//!
//! # Validation
//!
//! A present account is checked for:
//!
//! - the user record type and exactly one `RecordName` equal to `_helicoid`
//!   under ASCII case folding (aliases are refused);
//! - a UID other than 0 and the conservative `1..=99` system range used by
//!   this check. System accounts also exist above that range; this is not a
//!   complete allocation policy and it selects no UID;
//! - a positive GID whose group name equals `_helicoid` under ASCII case
//!   folding;
//! - Directory Services searches that resolve the UID and primary group only
//!   to the fixed account under ASCII case folding; multiple results refuse;
//! - no supplemental group memberships outside the fixed service group under
//!   ASCII case folding;
//! - a non-login shell from [`NON_LOGIN_SHELLS`];
//! - the locked password marker `*` and no authentication authority.
//!
//! These checks are necessary, not sufficient: the ownership-evidence refusal
//! above still applies.
//!
//! # Limits
//!
//! Only the local Directory Services node is observed. Direct
//! `GroupMembership` names are checked; `GroupMembers` GUID lists, nested group
//! expansion, and effective-group resolution are not evaluated. Account-
//! creation metadata, audit records, and install receipts are not available
//! here. The parser accepts the stable text shape emitted by `/usr/bin/dscl`;
//! a different shape fails closed. Because this revision never accepts an
//! existing account without ownership evidence, these gaps cannot admit an
//! account by themselves; they must be closed before any future acceptance
//! path is enabled. Caller privilege is not checked here; the launchd preflight
//! independently requires euid 0 before installation.

use std::collections::BTreeMap;
use std::fmt;

/// The fixed service-account name. No caller supplies or selects this value.
/// Directory Services name comparisons use ASCII case folding for this fixed
/// ASCII name.
pub const PRODUCT_SERVICE_ACCOUNT: &str = "_helicoid";
/// The fixed service-group name required for the account's primary group,
/// compared under ASCII case folding.
pub const PRODUCT_SERVICE_GROUP: &str = "_helicoid";
/// Non-login shells present on macOS and accepted for the service account.
pub const NON_LOGIN_SHELLS: &[&str] = &["/usr/bin/false", "/sbin/nologin"];
/// Conservative fail-closed ceiling for UIDs treated as system-reserved by
/// this check. This is not a complete model of Apple's UID allocation: system
/// accounts also exist above this range. The module selects no UID.
pub const RESERVED_SYSTEM_UID_CEILING: i64 = 99;

const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
const MAX_OBSERVATION_LINES: usize = 1024;
const MAX_ATTRIBUTES: usize = 256;
const MAX_ATTRIBUTE_VALUES: usize = 64;
const MAX_ATTRIBUTE_LINE_BYTES: usize = 4096;
const MAX_RECORD_NAMES: usize = 16;
const MAX_SEARCH_RECORDS: usize = 4096;
const MAX_GROUP_MEMBERSHIPS: usize = 4096;
const MAX_MEMBERS_PER_GROUP: usize = 4096;

/// Closed set of read-only Directory Services observations. Each maps to one
/// fixed absolute argv. The only variable arguments are numeric IDs taken from
/// a `u32`, never caller-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityQuery {
    AccountRecord,
    GroupRecord,
    UsersWithUniqueId { unique_id: u32 },
    UsersWithPrimaryGroupId { primary_group_id: u32 },
    GroupsWithPrimaryGroupId { primary_group_id: u32 },
    GroupMembershipList,
}

impl IdentityQuery {
    pub fn name(self) -> String {
        match self {
            IdentityQuery::AccountRecord => "account_record".to_string(),
            IdentityQuery::GroupRecord => "group_record".to_string(),
            IdentityQuery::UsersWithUniqueId { unique_id } => {
                format!("users_with_unique_id:{unique_id}")
            }
            IdentityQuery::UsersWithPrimaryGroupId { primary_group_id } => {
                format!("users_with_primary_group_id:{primary_group_id}")
            }
            IdentityQuery::GroupsWithPrimaryGroupId { primary_group_id } => {
                format!("groups_with_primary_group_id:{primary_group_id}")
            }
            IdentityQuery::GroupMembershipList => "group_membership_list".to_string(),
        }
    }

    /// Fixed argv for this observation. The first element is absolute; the
    /// remainder are fixed literals plus a validated numeric ID.
    pub fn reviewed_argv(self) -> Vec<String> {
        match self {
            IdentityQuery::AccountRecord => vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-read".to_string(),
                format!("/Users/{PRODUCT_SERVICE_ACCOUNT}"),
            ],
            IdentityQuery::GroupRecord => vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-read".to_string(),
                format!("/Groups/{PRODUCT_SERVICE_GROUP}"),
            ],
            IdentityQuery::UsersWithUniqueId { unique_id } => vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-search".to_string(),
                "/Users".to_string(),
                "UniqueID".to_string(),
                unique_id.to_string(),
            ],
            IdentityQuery::UsersWithPrimaryGroupId { primary_group_id } => vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-search".to_string(),
                "/Users".to_string(),
                "PrimaryGroupID".to_string(),
                primary_group_id.to_string(),
            ],
            IdentityQuery::GroupsWithPrimaryGroupId { primary_group_id } => vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-search".to_string(),
                "/Groups".to_string(),
                "PrimaryGroupID".to_string(),
                primary_group_id.to_string(),
            ],
            IdentityQuery::GroupMembershipList => vec![
                "/usr/bin/dscl".to_string(),
                ".".to_string(),
                "-list".to_string(),
                "/Groups".to_string(),
                "GroupMembership".to_string(),
            ],
        }
    }
}

/// Captured stdout, stderr, and exit status of one bounded observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityObservation {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl IdentityObservation {
    pub fn success(stdout: impl Into<String>) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn failure(exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// Injectable read-only host seam. Production uses
/// [`MacosSystemIdentityObserver`] on macOS; tests use in-memory fixtures.
pub trait MacosIdentityObserver: Send + Sync {
    fn observe(&self, query: IdentityQuery) -> Result<IdentityObservation, String>;
}

/// Required facts parsed from one local user record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecordFacts {
    pub record_names: Vec<String>,
    pub record_type: String,
    pub unique_id: i64,
    pub primary_group_id: i64,
    pub user_shell: String,
    pub password: String,
    pub authentication_authority: Vec<String>,
}

/// Why a present account cannot be adopted. Every present-account decision
/// includes [`IdentityRefusal::OwnershipNotVerified`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityRefusal {
    /// No independent ownership evidence source exists in this revision.
    OwnershipNotVerified,
    RecordType {
        observed: String,
    },
    RecordName {
        observed: Vec<String>,
    },
    RootUniqueId,
    ReservedSystemUniqueId {
        observed: i64,
    },
    InvalidUniqueId {
        observed: i64,
    },
    NonExclusiveUniqueId {
        records: Vec<String>,
    },
    InvalidPrimaryGroupId {
        observed: i64,
    },
    NonExclusivePrimaryGroup {
        groups: Vec<String>,
    },
    PrimaryGroupMembers {
        records: Vec<String>,
    },
    InteractiveShell {
        observed: String,
    },
    /// The password field was not the locked `*` marker. The field value is
    /// intentionally not echoed because it may contain a credential hash.
    PasswordCapable,
    /// An authentication authority other than the disabled marker was present.
    /// The value is intentionally not echoed because it may contain tokens.
    AuthenticationAuthority,
    SharedServiceGroup {
        members: Vec<String>,
    },
    /// Multiple group records differ only by case from the fixed service group.
    AmbiguousServiceGroupCase {
        groups: Vec<String>,
    },
    SupplementalGroupMembership {
        groups: Vec<String>,
    },
}

impl fmt::Display for IdentityRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityRefusal::OwnershipNotVerified => write!(
                formatter,
                "no independently verifiable product ownership evidence exists for an existing account"
            ),
            IdentityRefusal::RecordType { observed } => {
                write!(formatter, "record type is '{observed}', not a user record")
            }
            IdentityRefusal::RecordName { observed } => {
                write!(
                    formatter,
                    "record names do not resolve to exactly one name equal to '{PRODUCT_SERVICE_ACCOUNT}' under ASCII case folding: {observed:?}"
                )
            }
            IdentityRefusal::RootUniqueId => write!(formatter, "UID is 0 (root)"),
            IdentityRefusal::ReservedSystemUniqueId { observed } => {
                write!(
                    formatter,
                    "UID {observed} is in the conservative system range used by this check"
                )
            }
            IdentityRefusal::InvalidUniqueId { observed } => {
                write!(formatter, "UID {observed} is not a valid non-negative 32-bit ID")
            }
            IdentityRefusal::NonExclusiveUniqueId { records } => {
                write!(
                    formatter,
                    "UID does not resolve only to '{PRODUCT_SERVICE_ACCOUNT}' under ASCII case folding: {records:?}"
                )
            }
            IdentityRefusal::InvalidPrimaryGroupId { observed } => {
                write!(formatter, "GID {observed} is not a valid positive 32-bit ID")
            }
            IdentityRefusal::NonExclusivePrimaryGroup { groups } => {
                write!(
                    formatter,
                    "primary group does not resolve only to '{PRODUCT_SERVICE_GROUP}' under ASCII case folding: {groups:?}"
                )
            }
            IdentityRefusal::PrimaryGroupMembers { records } => {
                write!(
                    formatter,
                    "primary group resolves to records other than '{PRODUCT_SERVICE_ACCOUNT}' under ASCII case folding: {records:?}"
                )
            }
            IdentityRefusal::InteractiveShell { observed } => {
                write!(formatter, "shell '{observed}' is not an accepted non-login shell")
            }
            IdentityRefusal::PasswordCapable => {
                write!(formatter, "password field is not the locked '*' marker")
            }
            IdentityRefusal::AuthenticationAuthority => {
                write!(formatter, "account carries an authentication authority")
            }
            IdentityRefusal::SharedServiceGroup { members } => {
                write!(formatter, "service group contains other members: {members:?}")
            }
            IdentityRefusal::AmbiguousServiceGroupCase { groups } => {
                write!(
                    formatter,
                    "multiple group records differ only by case from '{PRODUCT_SERVICE_GROUP}': {groups:?}"
                )
            }
            IdentityRefusal::SupplementalGroupMembership { groups } => {
                write!(formatter, "account is a member of supplemental groups: {groups:?}")
            }
        }
    }
}

/// The complete result of the read-only identity observation. No variant
/// authorizes installation, apply, creation, readiness, or service mutation.
/// `AccountAbsentObservation` may support a read-only fresh-install review plan
/// only when both the account and group are absent; it is not proof either name
/// is free or authorization to create them. Every existing account remains
/// unverified without an independent Helicoid-owned receipt, and an absent
/// account with an existing group is refused as not fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceIdentityDecision {
    /// Directory Services reported the fixed record absent **and** the fixed
    /// service group absent. This is an observation, not proof that either name
    /// is free and not authorization to create anything. A future reviewed
    /// creation must use collision-safe create semantics and re-observe the
    /// exact identity. No UID/GID was selected and no creation happened.
    AccountAbsentObservation,
    /// The fixed user record was absent but the fixed service group already
    /// exists. This is not a fresh service identity and must not be planned as
    /// a fresh install. No creation or adoption is authorized.
    AccountAbsentGroupPresentObservation,
    /// The account exists and must not be adopted. The reasons always include
    /// [`IdentityRefusal::OwnershipNotVerified`].
    ExistingAccountRefused { reasons: Vec<IdentityRefusal> },
    /// Facts could not be established safely. This is a blocker, not absence.
    Unavailable { reason: String },
}

impl fmt::Display for ServiceIdentityDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceIdentityDecision::AccountAbsentObservation => write!(
                formatter,
                "service account '{PRODUCT_SERVICE_ACCOUNT}' and group '{PRODUCT_SERVICE_GROUP}' were observed absent; this is not proof either name is free. Future reviewed creation requires collision-safe create semantics and a recheck of the exact identity. No UID/GID was chosen"
            ),
            ServiceIdentityDecision::AccountAbsentGroupPresentObservation => write!(
                formatter,
                "service account '{PRODUCT_SERVICE_ACCOUNT}' was observed absent, but the fixed service group '{PRODUCT_SERVICE_GROUP}' already exists; this is not a fresh service identity and must not be adopted or planned as a fresh install"
            ),
            ServiceIdentityDecision::ExistingAccountRefused { reasons } => {
                let described: Vec<String> = reasons.iter().map(ToString::to_string).collect();
                write!(
                    formatter,
                    "service account '{PRODUCT_SERVICE_ACCOUNT}' exists and is refused: {}",
                    described.join("; ")
                )
            }
            ServiceIdentityDecision::Unavailable { reason } => {
                write!(formatter, "service identity facts are unavailable: {reason}")
            }
        }
    }
}

fn validate_observation(observation: &IdentityObservation) -> Result<(), String> {
    for (stream, value) in [
        ("stdout", &observation.stdout),
        ("stderr", &observation.stderr),
    ] {
        if value.len() > MAX_OBSERVATION_BYTES {
            return Err(format!(
                "{stream} exceeds the {MAX_OBSERVATION_BYTES}-byte observation bound"
            ));
        }
        if value.lines().count() > MAX_OBSERVATION_LINES {
            return Err(format!(
                "{stream} exceeds the {MAX_OBSERVATION_LINES}-line observation bound"
            ));
        }
        if value.as_bytes().contains(&0) {
            return Err(format!("{stream} contains a NUL byte"));
        }
    }
    Ok(())
}

fn first_line(value: &str) -> String {
    value
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect()
}

fn require_success(observation: &IdentityObservation, field: &str) -> Result<(), String> {
    validate_observation(observation)?;
    if observation.exit_code != 0 {
        return Err(format!(
            "{field} observation failed with exit {}: {}",
            observation.exit_code,
            first_line(&observation.stderr)
        ));
    }
    if !observation.stderr.trim().is_empty() {
        return Err(format!(
            "{field} observation succeeded with unexpected stderr: {}",
            first_line(&observation.stderr)
        ));
    }
    Ok(())
}

fn record_not_found(observation: &IdentityObservation) -> bool {
    // Require the explicit diagnostic on stderr and an empty stdout. A
    // diagnostic mixed with record output is ambiguous and stays unavailable.
    // Absence is an observation only; the decision layer labels it as requiring
    // collision-safe creation and a recheck, not as authorization to create.
    observation.exit_code != 0
        && observation.stdout.trim().is_empty()
        && observation.stderr.contains("eDSRecordNotFound")
}

/// Directory Services name resolution is treated as case-insensitive for this
/// fixed ASCII identity. ASCII folding is sufficient here and avoids locale-
/// dependent behavior.
fn is_service_account_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(PRODUCT_SERVICE_ACCOUNT)
}

fn is_service_group_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(PRODUCT_SERVICE_GROUP)
}

fn valid_attribute_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 128 {
        return false;
    }
    let mut characters = key.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    characters.all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
    })
}

fn split_attribute_line(line: &str) -> Option<(String, String)> {
    let (key, value) = if let Some(index) = line.find(": ") {
        (&line[..index], &line[index + 2..])
    } else {
        (line.strip_suffix(':')?, "")
    };
    if !valid_attribute_key(key) {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

/// Parse the text record emitted by `dscl . -read`. Continuation lines belong
/// to the preceding attribute; attribute names may contain a colon (for
/// example `dsAttrTypeNative:IsHidden`). Malformed shapes fail closed.
fn parse_dscl_attributes(stdout: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for raw in stdout.lines() {
        let line = raw.trim_end_matches('\r');
        if line.len() > MAX_ATTRIBUTE_LINE_BYTES {
            return Err(format!(
                "record line exceeds the {MAX_ATTRIBUTE_LINE_BYTES}-byte bound"
            ));
        }
        if let Some((key, value)) = split_attribute_line(line) {
            if !attributes.contains_key(&key) && attributes.len() >= MAX_ATTRIBUTES {
                return Err(format!("record has more than {MAX_ATTRIBUTES} attributes"));
            }
            let values = attributes.entry(key.clone()).or_default();
            if values.len() >= MAX_ATTRIBUTE_VALUES {
                return Err(format!(
                    "attribute '{key}' has more than {MAX_ATTRIBUTE_VALUES} values"
                ));
            }
            if !value.is_empty() {
                values.push(value);
            }
            current = Some(key);
        } else if let Some(key) = current.as_deref() {
            let values = attributes
                .get_mut(key)
                .ok_or_else(|| format!("internal parser state lost attribute '{key}'"))?;
            if values.len() >= MAX_ATTRIBUTE_VALUES {
                return Err(format!(
                    "attribute '{key}' has more than {MAX_ATTRIBUTE_VALUES} values"
                ));
            }
            values.push(line.trim_start().to_string());
        } else {
            return Err(format!(
                "record starts with an unexpected line: '{}'",
                first_line(line)
            ));
        }
    }

    if attributes.is_empty() {
        return Err("record was empty".to_string());
    }
    Ok(attributes)
}

fn single_trimmed(attributes: &BTreeMap<String, Vec<String>>, key: &str) -> Result<String, String> {
    let values = attributes
        .get(key)
        .ok_or_else(|| format!("record is missing {key}"))?;
    if values.len() != 1 {
        return Err(format!(
            "record has {} values for {key}; expected exactly one",
            values.len()
        ));
    }
    let value = values[0].trim();
    if value.is_empty() {
        return Err(format!("record has an empty {key}"));
    }
    Ok(value.to_string())
}

fn parse_integer(value: &str, field: &str) -> Result<i64, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 12 {
        return Err(format!("{field} was not a bounded decimal integer"));
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(format!("{field} was not a canonical decimal integer"));
    }
    value
        .parse::<i64>()
        .map_err(|_| format!("{field} was outside the i64 range"))
}

fn parse_record_names(attributes: &BTreeMap<String, Vec<String>>) -> Result<Vec<String>, String> {
    let values = attributes
        .get("RecordName")
        .ok_or_else(|| "record is missing RecordName".to_string())?;
    let mut names = Vec::new();
    for value in values {
        for name in value.split_ascii_whitespace() {
            if name.len() > 256 || name.chars().any(char::is_control) {
                return Err("record name was malformed".to_string());
            }
            names.push(name.to_string());
            if names.len() > MAX_RECORD_NAMES {
                return Err(format!("record has more than {MAX_RECORD_NAMES} names"));
            }
        }
    }
    if names.is_empty() {
        return Err("record has no names".to_string());
    }
    Ok(names)
}

/// Parse one local user record. `Ok(None)` means Directory Services returned
/// the explicit record-not-found diagnostic. That is an observation only; it
/// does not prove the name is free. Every other failure is `Err` and must
/// become [`ServiceIdentityDecision::Unavailable`].
pub fn parse_user_record(
    observation: &IdentityObservation,
) -> Result<Option<UserRecordFacts>, String> {
    validate_observation(observation)?;
    if record_not_found(observation) {
        return Ok(None);
    }
    require_success(observation, "account record")?;
    let attributes = parse_dscl_attributes(&observation.stdout)?;

    let record_type = single_trimmed(&attributes, "RecordType")?;
    let unique_id = parse_integer(&single_trimmed(&attributes, "UniqueID")?, "UniqueID")?;
    let primary_group_id = parse_integer(
        &single_trimmed(&attributes, "PrimaryGroupID")?,
        "PrimaryGroupID",
    )?;
    let user_shell = single_trimmed(&attributes, "UserShell")?;
    let password = single_trimmed(&attributes, "Password")?;
    let record_names = parse_record_names(&attributes)?;
    let authentication_authority = attributes
        .get("AuthenticationAuthority")
        .map(|values| {
            values
                .iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(UserRecordFacts {
        record_names,
        record_type,
        unique_id,
        primary_group_id,
        user_shell,
        password,
        authentication_authority,
    }))
}

/// Parse the fixed service-group record observation. `Ok(false)` means the
/// explicit record-not-found diagnostic; `Ok(true)` means a group record is
/// present. Empty successful output is ambiguous and fails closed.
pub fn parse_group_record_presence(observation: &IdentityObservation) -> Result<bool, String> {
    validate_observation(observation)?;
    if record_not_found(observation) {
        return Ok(false);
    }
    require_success(observation, "group record")?;
    if observation.stdout.trim().is_empty() {
        return Err("group record was empty".to_string());
    }
    Ok(true)
}

/// Parse the shaped output of `dscl . -search <node> <attribute> <value>`.
/// The returned names are the matching record names; an empty vector means the
/// search found no records, which is not proof of a clean identity.
pub fn parse_identity_search(
    observation: &IdentityObservation,
    expected_attribute: &str,
    expected_value: u32,
) -> Result<Vec<String>, String> {
    require_success(observation, "identity search")?;
    let expected_value = expected_value.to_string();
    let mut records = Vec::new();
    let mut pending: Option<(String, Vec<String>)> = None;

    for raw in observation.stdout.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if line.chars().next().is_some_and(char::is_whitespace) {
            let Some((_, values)) = pending.as_mut() else {
                return Err("search value appeared before a record header".to_string());
            };
            if values.len() >= MAX_ATTRIBUTE_VALUES {
                return Err("search record has too many values".to_string());
            }
            if line.trim() != expected_value {
                return Err("search returned a value different from the query".to_string());
            }
            values.push(line.trim().to_string());
            continue;
        }
        if line.trim() == ")" {
            let Some((name, values)) = pending.take() else {
                return Err("search terminator appeared before a record header".to_string());
            };
            if values.is_empty() {
                return Err(format!("search result for '{name}' had no value"));
            }
            if records.len() >= MAX_SEARCH_RECORDS {
                return Err(format!(
                    "search returned more than {MAX_SEARCH_RECORDS} records"
                ));
            }
            records.push(name);
            continue;
        }

        if pending.is_some() {
            return Err("search record started before the previous record closed".to_string());
        }
        let marker = " = (";
        let Some(index) = line.find(marker) else {
            return Err(format!("unexpected search line: '{}'", first_line(line)));
        };
        let header = &line[..index];
        let mut parts = header.split_ascii_whitespace();
        let Some(name) = parts.next() else {
            return Err("search record header was empty".to_string());
        };
        let attribute = parts.collect::<Vec<_>>().join(" ");
        if attribute != expected_attribute {
            return Err(format!(
                "search returned attribute '{attribute}', expected '{expected_attribute}'"
            ));
        }
        if name.len() > 256 || name.chars().any(char::is_control) {
            return Err("search record name was malformed".to_string());
        }
        pending = Some((name.to_string(), Vec::new()));
    }

    if pending.is_some() {
        return Err("search output ended before a record closed".to_string());
    }
    Ok(records)
}

fn valid_record_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 256 && !token.chars().any(char::is_control)
}

/// Parse `dscl . -list /Groups GroupMembership`. Each line is a group name
/// followed by its direct member names. Duplicate group lines fail closed.
pub fn parse_group_membership_list(
    observation: &IdentityObservation,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    require_success(observation, "group membership list")?;
    if observation.stdout.trim().is_empty() {
        // Empty successful output is not treated as proof that the account has
        // no supplemental memberships.
        return Err("group membership list was empty".to_string());
    }
    let mut groups = BTreeMap::new();

    for raw in observation.stdout.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_ATTRIBUTE_LINE_BYTES {
            return Err(format!(
                "group membership line exceeds the {MAX_ATTRIBUTE_LINE_BYTES}-byte bound"
            ));
        }
        if line.chars().next().is_some_and(char::is_whitespace) {
            return Err("group membership list was indented unexpectedly".to_string());
        }
        let mut parts = line.split_ascii_whitespace();
        let Some(group) = parts.next() else {
            continue;
        };
        if !valid_record_token(group) {
            return Err("group name was malformed".to_string());
        }
        let members: Vec<String> = parts
            .map(|member| {
                if valid_record_token(member) {
                    Ok(member.to_string())
                } else {
                    Err("group member name was malformed".to_string())
                }
            })
            .collect::<Result<_, _>>()?;
        if members.len() > MAX_MEMBERS_PER_GROUP {
            return Err(format!(
                "group '{group}' has more than {MAX_MEMBERS_PER_GROUP} members"
            ));
        }
        if !groups.contains_key(group) && groups.len() >= MAX_GROUP_MEMBERSHIPS {
            return Err(format!(
                "group membership list exceeds {MAX_GROUP_MEMBERSHIPS} groups"
            ));
        }
        if groups.insert(group.to_string(), members).is_some() {
            return Err(format!("group '{group}' appeared more than once"));
        }
    }

    Ok(groups)
}

fn validate_record(record: &UserRecordFacts) -> Vec<IdentityRefusal> {
    let mut reasons = Vec::new();

    if record.record_type != "dsRecTypeStandard:Users" {
        reasons.push(IdentityRefusal::RecordType {
            observed: record.record_type.clone(),
        });
    }
    if !matches!(
        record.record_names.as_slice(),
        [name] if is_service_account_name(name)
    ) {
        reasons.push(IdentityRefusal::RecordName {
            observed: record.record_names.clone(),
        });
    }

    match record.unique_id {
        0 => reasons.push(IdentityRefusal::RootUniqueId),
        unique_id if (1..=RESERVED_SYSTEM_UID_CEILING).contains(&unique_id) => {
            reasons.push(IdentityRefusal::ReservedSystemUniqueId {
                observed: unique_id,
            });
        }
        unique_id if unique_id < 0 || u32::try_from(unique_id).is_err() => {
            reasons.push(IdentityRefusal::InvalidUniqueId {
                observed: unique_id,
            });
        }
        _ => {}
    }

    if record.primary_group_id < 0 || u32::try_from(record.primary_group_id).is_err() {
        reasons.push(IdentityRefusal::InvalidPrimaryGroupId {
            observed: record.primary_group_id,
        });
    }

    if !NON_LOGIN_SHELLS.contains(&record.user_shell.as_str()) {
        reasons.push(IdentityRefusal::InteractiveShell {
            observed: record.user_shell.clone(),
        });
    }

    if record.password != "*" {
        reasons.push(IdentityRefusal::PasswordCapable);
    }

    if !record.authentication_authority.is_empty()
        && !record
            .authentication_authority
            .iter()
            .all(|value| value == ";DisabledUser;")
    {
        reasons.push(IdentityRefusal::AuthenticationAuthority);
    }

    reasons
}

fn query_search(
    observer: &dyn MacosIdentityObserver,
    query: IdentityQuery,
    attribute: &str,
    value: u32,
) -> Result<Vec<String>, String> {
    let observation = observer
        .observe(query)
        .map_err(|error| format!("{} observation failed: {error}", query.name()))?;
    parse_identity_search(&observation, attribute, value)
        .map_err(|error| format!("{}: {error}", query.name()))
}

fn observe_directory_facts(
    observer: &dyn MacosIdentityObserver,
    record: &UserRecordFacts,
) -> Result<Vec<IdentityRefusal>, String> {
    let unique_id = u32::try_from(record.unique_id)
        .map_err(|_| "validated UniqueID did not fit u32".to_string())?;
    let primary_group_id = u32::try_from(record.primary_group_id)
        .map_err(|_| "validated PrimaryGroupID did not fit u32".to_string())?;
    let mut reasons = Vec::new();

    let users = query_search(
        observer,
        IdentityQuery::UsersWithUniqueId { unique_id },
        "UniqueID",
        unique_id,
    )?;
    if !matches!(
        users.as_slice(),
        [name] if is_service_account_name(name)
    ) {
        reasons.push(IdentityRefusal::NonExclusiveUniqueId { records: users });
    }

    let groups = query_search(
        observer,
        IdentityQuery::GroupsWithPrimaryGroupId { primary_group_id },
        "PrimaryGroupID",
        primary_group_id,
    )?;
    if !matches!(
        groups.as_slice(),
        [name] if is_service_group_name(name)
    ) {
        reasons.push(IdentityRefusal::NonExclusivePrimaryGroup { groups });
    }

    let members = query_search(
        observer,
        IdentityQuery::UsersWithPrimaryGroupId { primary_group_id },
        "PrimaryGroupID",
        primary_group_id,
    )?;
    if !matches!(
        members.as_slice(),
        [name] if is_service_account_name(name)
    ) {
        reasons.push(IdentityRefusal::PrimaryGroupMembers { records: members });
    }

    let memberships = observer
        .observe(IdentityQuery::GroupMembershipList)
        .map_err(|error| format!("group membership list observation failed: {error}"))?;
    let memberships = parse_group_membership_list(&memberships)
        .map_err(|error| format!("group membership list: {error}"))?;

    let mut supplemental_groups = Vec::new();
    let mut shared_service_group_members = Vec::new();
    let mut service_group_names = Vec::new();
    for (group, members) in &memberships {
        if is_service_group_name(group) {
            if !service_group_names.iter().any(|observed| observed == group) {
                service_group_names.push(group.clone());
            }
            let extras: Vec<String> = members
                .iter()
                .filter(|member| !is_service_account_name(member))
                .cloned()
                .collect();
            if !extras.is_empty() {
                shared_service_group_members.extend(extras);
            }
        } else if members.iter().any(|member| is_service_account_name(member)) {
            supplemental_groups.push(group.clone());
        }
    }
    if service_group_names.len() > 1 {
        reasons.push(IdentityRefusal::AmbiguousServiceGroupCase {
            groups: service_group_names,
        });
    }
    if !shared_service_group_members.is_empty() {
        reasons.push(IdentityRefusal::SharedServiceGroup {
            members: shared_service_group_members,
        });
    }
    if !supplemental_groups.is_empty() {
        reasons.push(IdentityRefusal::SupplementalGroupMembership {
            groups: supplemental_groups,
        });
    }

    Ok(reasons)
}

/// Observe and validate the fixed service identity. The result is a report, not
/// an authorization: no decision variant enables install, apply, creation,
/// readiness, or service mutation.
pub fn observe_service_identity(observer: &dyn MacosIdentityObserver) -> ServiceIdentityDecision {
    let record = match observer.observe(IdentityQuery::AccountRecord) {
        Ok(observation) => match parse_user_record(&observation) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return match observer.observe(IdentityQuery::GroupRecord) {
                    Ok(observation) => match parse_group_record_presence(&observation) {
                        Ok(false) => ServiceIdentityDecision::AccountAbsentObservation,
                        Ok(true) => ServiceIdentityDecision::AccountAbsentGroupPresentObservation,
                        Err(reason) => ServiceIdentityDecision::Unavailable {
                            reason: format!("group record: {reason}"),
                        },
                    },
                    Err(error) => ServiceIdentityDecision::Unavailable {
                        reason: format!("group record observation failed: {error}"),
                    },
                };
            }
            Err(reason) => {
                return ServiceIdentityDecision::Unavailable {
                    reason: format!("account record: {reason}"),
                }
            }
        },
        Err(error) => {
            return ServiceIdentityDecision::Unavailable {
                reason: format!("account record observation failed: {error}"),
            }
        }
    };

    let mut reasons = validate_record(&record);
    if !reasons.is_empty() {
        // The account is already refused. Do not widen the read-only query
        // set merely to enumerate additional reasons.
        reasons.push(IdentityRefusal::OwnershipNotVerified);
        return ServiceIdentityDecision::ExistingAccountRefused { reasons };
    }

    match observe_directory_facts(observer, &record) {
        Ok(mut reasons) => {
            reasons.push(IdentityRefusal::OwnershipNotVerified);
            ServiceIdentityDecision::ExistingAccountRefused { reasons }
        }
        Err(reason) => ServiceIdentityDecision::Unavailable { reason },
    }
}

// ---------------------------------------------------------------------------
// Production macOS observer (read-only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(target_os = "macos")]
const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;

#[cfg(target_os = "macos")]
fn read_pipe(mut pipe: impl std::io::Read) -> Result<(Vec<u8>, bool), String> {
    let mut captured = Vec::new();
    let mut total = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                total = total.saturating_add(read);
                if captured.len() < MAX_COMMAND_OUTPUT_BYTES {
                    let room = MAX_COMMAND_OUTPUT_BYTES - captured.len();
                    captured.extend_from_slice(&chunk[..read.min(room)]);
                }
            }
            Err(error) => return Err(format!("read command output: {error}")),
        }
    }
    Ok((captured, total > MAX_COMMAND_OUTPUT_BYTES))
}

#[cfg(target_os = "macos")]
fn run_bounded(argv: &[String]) -> Result<IdentityObservation, String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    if argv.is_empty() || argv.len() > 8 {
        return Err("reviewed command has an invalid argument count".to_string());
    }
    if !argv[0].starts_with('/')
        || argv
            .iter()
            .any(|argument| argument.contains('\0') || argument.contains('\n'))
    {
        return Err("reviewed command must use absolute, single-line arguments".to_string());
    }

    let mut command = Command::new(&argv[0]);
    if argv.len() > 1 {
        command.args(&argv[1..]);
    }
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", argv[0]))?;

    let stdout_pipe = match child.stdout.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("stdout pipe unavailable".to_string());
        }
    };
    let stderr_pipe = match child.stderr.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("stderr pipe unavailable".to_string());
        }
    };
    let stdout_thread = std::thread::spawn(move || read_pipe(stdout_pipe));
    let stderr_thread = std::thread::spawn(move || read_pipe(stderr_pipe));

    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "command '{}' timed out after {}s",
                        argv[0],
                        COMMAND_TIMEOUT.as_secs()
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wait for '{}': {error}", argv[0]));
            }
        }
    };

    let (stdout, stdout_overflow) = stdout_thread
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?
        .map_err(|error| format!("stdout reader failed: {error}"))?;
    let (stderr, stderr_overflow) = stderr_thread
        .join()
        .map_err(|_| "stderr reader panicked".to_string())?
        .map_err(|error| format!("stderr reader failed: {error}"))?;

    if stdout_overflow || stderr_overflow {
        return Err(format!(
            "command '{}' exceeded the {MAX_COMMAND_OUTPUT_BYTES}-byte output bound",
            argv[0]
        ));
    }

    let exit_code = status
        .code()
        .ok_or_else(|| format!("command '{}' ended without an exit code", argv[0]))?;
    let stdout = String::from_utf8(stdout)
        .map_err(|_| format!("command '{}' produced non-UTF-8 stdout", argv[0]))?;
    let stderr = String::from_utf8(stderr)
        .map_err(|_| format!("command '{}' produced non-UTF-8 stderr", argv[0]))?;

    Ok(IdentityObservation {
        exit_code,
        stdout,
        stderr,
    })
}

/// Production observer. It only runs the fixed read-only queries in
/// [`IdentityQuery`].
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct MacosSystemIdentityObserver;

#[cfg(target_os = "macos")]
impl MacosSystemIdentityObserver {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl MacosIdentityObserver for MacosSystemIdentityObserver {
    fn observe(&self, query: IdentityQuery) -> Result<IdentityObservation, String> {
        run_bounded(&query.reviewed_argv())
    }
}

/// Observe the real local service identity on this Mac. Read-only.
#[cfg(target_os = "macos")]
pub fn observe_local_service_identity() -> ServiceIdentityDecision {
    observe_service_identity(&MacosSystemIdentityObserver::new())
}
