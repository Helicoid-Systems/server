//! Focused fixture tests for the read-only macOS service-identity seam.
//!
//! These tests never create an account, call `dscl`, invoke `sudo`, mutate
//! launchd, or touch a user/system path. The fake observer supplies realistic
//! `dscl` output. One explicitly ignored macOS test performs a read-only live
//! observation and is not part of the default test run.

use std::collections::HashMap;
use std::sync::Mutex;

#[cfg(target_os = "macos")]
use hs_server::installer::macos_identity::observe_local_service_identity;
use hs_server::installer::macos_identity::{
    observe_service_identity, parse_group_membership_list, parse_group_record,
    parse_group_record_presence, parse_identity_search, parse_user_record, IdentityObservation,
    IdentityQuery, IdentityRefusal, MacosIdentityObserver, ServiceIdentityDecision,
    NON_LOGIN_SHELLS, PRODUCT_SERVICE_ACCOUNT, PRODUCT_SERVICE_GROUP,
};

const CLEAN_UID: u32 = 4242;
const CLEAN_GID: u32 = 4242;

const CLEAN_MEMBERSHIPS: &str = "\
admin                    root
wheel                    root
_helicoid                _helicoid
";

const CLEAN_RECORD: &str = "\
AppleMetaNodeLocation: /Local/Default
GeneratedUID: 11111111-2222-3333-4444-555555555555
NFSHomeDirectory: /var/empty
Password: *
PrimaryGroupID: 4242
RealName:
 Helicoid Service
RecordName: _helicoid
RecordType: dsRecTypeStandard:Users
UniqueID: 4242
UserShell: /usr/bin/false
";

const WWW_RECORD: &str = "\
AppleMetaNodeLocation: /Local/Default
GeneratedUID: FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000046
NFSHomeDirectory: /Library/WebServer
Password: *
PrimaryGroupID: 70
RealName:
 World Wide Web Server
RecordName: _www www
RecordType: dsRecTypeStandard:Users
UniqueID: 70
UserShell: /usr/bin/false
";

const SETUP_RECORD: &str = "\
dsAttrTypeNative:IsHidden: YES
AppleMetaNodeLocation: /Local/Default
GeneratedUID: FFFFEEEE-DDDD-CCCC-BBBB-AAAA000000F8
NFSHomeDirectory: /var/setup
Password: *
PrimaryGroupID: 248
RealName:
 Setup User
RecordName: _mbsetupuser
RecordType: dsRecTypeStandard:Users
UniqueID: 248
UserShell: /bin/bash
";

struct FakeObserver {
    observations: Mutex<HashMap<IdentityQuery, Result<IdentityObservation, String>>>,
    calls: Mutex<Vec<IdentityQuery>>,
}

impl FakeObserver {
    fn new() -> Self {
        Self {
            observations: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with(self, query: IdentityQuery, observation: Result<IdentityObservation, String>) -> Self {
        let mut observations = self.observations.lock().expect("observer lock");
        observations.insert(query, observation);
        drop(observations);
        self
    }

    fn with_success(self, query: IdentityQuery, stdout: impl Into<String>) -> Self {
        self.with(query, Ok(IdentityObservation::success(stdout)))
    }

    fn with_error(self, query: IdentityQuery, error: &str) -> Self {
        self.with(query, Err(error.to_string()))
    }

    fn calls(&self) -> Vec<IdentityQuery> {
        self.calls.lock().expect("calls lock").clone()
    }
}

impl MacosIdentityObserver for FakeObserver {
    fn observe(&self, query: IdentityQuery) -> Result<IdentityObservation, String> {
        self.calls.lock().expect("calls lock").push(query);
        self.observations
            .lock()
            .expect("observer lock")
            .get(&query)
            .cloned()
            .unwrap_or_else(|| Err(format!("unexpected query: {query:?}")))
    }
}

fn search_result(name: &str, attribute: &str, value: u32) -> String {
    format!("{name}\t\t{attribute} = (\n    {value}\n)\n")
}

fn search_results(records: &[(&str, &str, u32)]) -> String {
    records
        .iter()
        .map(|(name, attribute, value)| search_result(name, attribute, *value))
        .collect()
}

fn clean_observer() -> FakeObserver {
    FakeObserver::new()
        .with_success(IdentityQuery::AccountRecord, CLEAN_RECORD)
        .with_success(
            IdentityQuery::UsersWithUniqueId {
                unique_id: CLEAN_UID,
            },
            search_result(PRODUCT_SERVICE_ACCOUNT, "UniqueID", CLEAN_UID),
        )
        .with_success(
            IdentityQuery::GroupsWithPrimaryGroupId {
                primary_group_id: CLEAN_GID,
            },
            search_result(PRODUCT_SERVICE_GROUP, "PrimaryGroupID", CLEAN_GID),
        )
        .with_success(
            IdentityQuery::UsersWithPrimaryGroupId {
                primary_group_id: CLEAN_GID,
            },
            search_result(PRODUCT_SERVICE_ACCOUNT, "PrimaryGroupID", CLEAN_GID),
        )
        .with_success(IdentityQuery::GroupMembershipList, CLEAN_MEMBERSHIPS)
}

fn reasons(decision: ServiceIdentityDecision) -> Vec<IdentityRefusal> {
    match decision {
        ServiceIdentityDecision::ExistingAccountRefused { reasons } => reasons,
        other => panic!("expected an account refusal, got {other:?}"),
    }
}

fn unavailable_reason(decision: ServiceIdentityDecision) -> String {
    match decision {
        ServiceIdentityDecision::Unavailable { reason } => reason,
        other => panic!("expected unavailable facts, got {other:?}"),
    }
}

#[test]
fn macos_identity_real_www_record_fixture_parses() {
    let record = parse_user_record(&IdentityObservation::success(WWW_RECORD))
        .expect("realistic _www record must parse")
        .expect("_www record is present");
    assert_eq!(record.record_names, vec!["_www", "www"]);
    assert_eq!(record.record_type, "dsRecTypeStandard:Users");
    assert_eq!(record.unique_id, 70);
    assert_eq!(record.primary_group_id, 70);
    assert_eq!(record.user_shell, "/usr/bin/false");
    assert_eq!(record.password, "*");
    assert!(record.authentication_authority.is_empty());
}

#[test]
fn macos_identity_hidden_native_attribute_fixture_parses() {
    let record = parse_user_record(&IdentityObservation::success(SETUP_RECORD))
        .expect("hidden system record must parse")
        .expect("record is present");
    assert_eq!(record.record_names, vec!["_mbsetupuser"]);
    assert_eq!(record.unique_id, 248);
    assert_eq!(record.primary_group_id, 248);
    assert_eq!(record.user_shell, "/bin/bash");
}

#[test]
fn macos_identity_absent_record_is_observation_requiring_recheck() {
    let observer = FakeObserver::new()
        .with(
            IdentityQuery::AccountRecord,
            Ok(IdentityObservation::failure(
                56,
                "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n",
            )),
        )
        .with(
            IdentityQuery::GroupRecord,
            Ok(IdentityObservation::failure(
                56,
                "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n",
            )),
        );
    let decision = observe_service_identity(&observer);
    assert_eq!(decision, ServiceIdentityDecision::AccountAbsentObservation);
    assert_eq!(
        observer.calls(),
        vec![IdentityQuery::AccountRecord, IdentityQuery::GroupRecord]
    );
    let text = decision.to_string();
    assert!(
        text.contains("not proof either name is free"),
        "unexpected text: {text}"
    );
    assert!(text.contains("collision-safe"), "unexpected text: {text}");
    assert!(text.contains("No UID/GID"), "unexpected text: {text}");
}

#[test]
fn macos_identity_absent_user_with_existing_group_is_not_fresh() {
    let observer = FakeObserver::new()
        .with(
            IdentityQuery::AccountRecord,
            Ok(IdentityObservation::failure(
                56,
                "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n",
            )),
        )
        .with_success(
            IdentityQuery::GroupRecord,
            "RecordName: _helicoid\nRecordType: dsRecTypeStandard:Groups\n",
        );
    let decision = observe_service_identity(&observer);
    assert_eq!(
        decision,
        ServiceIdentityDecision::AccountAbsentGroupPresentObservation
    );
    assert_eq!(
        observer.calls(),
        vec![IdentityQuery::AccountRecord, IdentityQuery::GroupRecord]
    );
    assert!(decision
        .to_string()
        .contains("not a fresh service identity"));
}

#[test]
fn macos_identity_group_record_presence_fails_closed_on_ambiguity() {
    let absent =
        IdentityObservation::failure(56, "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n");
    assert_eq!(parse_group_record_presence(&absent), Ok(false));

    let present = IdentityObservation::success(
        "RecordName: _helicoid\nRecordType: dsRecTypeStandard:Groups\n",
    );
    assert_eq!(parse_group_record_presence(&present), Ok(true));

    let empty = IdentityObservation::success("");
    assert!(parse_group_record_presence(&empty).is_err());

    let mixed = IdentityObservation {
        exit_code: 56,
        stdout: "RecordName: _helicoid\n".to_string(),
        stderr: "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n".to_string(),
    };
    assert!(parse_group_record_presence(&mixed).is_err());
}

#[test]
fn macos_identity_group_observation_failure_is_unavailable() {
    let observer = FakeObserver::new()
        .with(
            IdentityQuery::AccountRecord,
            Ok(IdentityObservation::failure(
                56,
                "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n",
            )),
        )
        .with_error(IdentityQuery::GroupRecord, "group lookup denied");
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(
        reason.contains("group record observation failed"),
        "unexpected reason: {reason}"
    );
}

#[test]
fn macos_identity_record_not_found_requires_explicit_diagnostic() {
    let permission = IdentityObservation::failure(56, "Permission denied\n");
    assert!(parse_user_record(&permission).is_err());

    let absent =
        IdentityObservation::failure(56, "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n");
    assert_eq!(parse_user_record(&absent).expect("absent record"), None);

    let mixed = IdentityObservation {
        exit_code: 56,
        stdout: "UniqueID: 1\n".to_string(),
        stderr: "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n".to_string(),
    };
    assert!(parse_user_record(&mixed).is_err());
}

#[test]
fn macos_identity_clean_existing_account_is_still_refused() {
    let observer = clean_observer();
    let decision = observe_service_identity(&observer);
    assert_eq!(
        reasons(decision),
        vec![IdentityRefusal::OwnershipNotVerified]
    );
    assert_eq!(
        observer.calls(),
        vec![
            IdentityQuery::AccountRecord,
            IdentityQuery::UsersWithUniqueId {
                unique_id: CLEAN_UID
            },
            IdentityQuery::GroupsWithPrimaryGroupId {
                primary_group_id: CLEAN_GID
            },
            IdentityQuery::UsersWithPrimaryGroupId {
                primary_group_id: CLEAN_GID
            },
            IdentityQuery::GroupMembershipList,
        ]
    );
}

#[test]
fn macos_identity_root_uid_is_refused_without_directory_queries() {
    let record = CLEAN_RECORD
        .replace("UniqueID: 4242", "UniqueID: 0")
        .replace("PrimaryGroupID: 4242", "PrimaryGroupID: 0");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::RootUniqueId,
            IdentityRefusal::OwnershipNotVerified
        ]
    );
    assert_eq!(observer.calls(), vec![IdentityQuery::AccountRecord]);
}

#[test]
fn macos_identity_root_record_name_is_refused() {
    let record = CLEAN_RECORD
        .replace("RecordName: _helicoid", "RecordName: root")
        .replace("UniqueID: 4242", "UniqueID: 0")
        .replace("PrimaryGroupID: 4242", "PrimaryGroupID: 0");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::RecordName {
                observed: vec!["root".to_string()]
            },
            IdentityRefusal::RootUniqueId,
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_reserved_uid_is_refused() {
    let record = CLEAN_RECORD
        .replace("UniqueID: 4242", "UniqueID: 42")
        .replace("PrimaryGroupID: 4242", "PrimaryGroupID: 42");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::ReservedSystemUniqueId { observed: 42 },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_negative_uid_and_gid_are_invalid() {
    let record = CLEAN_RECORD
        .replace("UniqueID: 4242", "UniqueID: -2")
        .replace("PrimaryGroupID: 4242", "PrimaryGroupID: -2");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::InvalidUniqueId { observed: -2 },
            IdentityRefusal::InvalidPrimaryGroupId { observed: -2 },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_interactive_shell_is_refused() {
    let record = CLEAN_RECORD.replace("UserShell: /usr/bin/false", "UserShell: /bin/zsh");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::InteractiveShell {
                observed: "/bin/zsh".to_string()
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_password_marker_is_refused() {
    let record = CLEAN_RECORD.replace("Password: *", "Password: ********");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::PasswordCapable,
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_authentication_authority_is_refused() {
    let record = format!("{CLEAN_RECORD}AuthenticationAuthority: ;ShadowHash;\n");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::AuthenticationAuthority,
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_alias_record_name_is_refused() {
    let record = CLEAN_RECORD.replace("RecordName: _helicoid", "RecordName: _helicoid helicoid");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::RecordName {
                observed: vec!["_helicoid".to_string(), "helicoid".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_wrong_record_type_is_refused() {
    let record = CLEAN_RECORD.replace(
        "RecordType: dsRecTypeStandard:Users",
        "RecordType: dsRecTypeStandard:Groups",
    );
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::RecordType {
                observed: "dsRecTypeStandard:Groups".to_string()
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_missing_shell_is_unavailable() {
    let record = CLEAN_RECORD.replace("UserShell: /usr/bin/false\n", "");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("UserShell"), "unexpected: {reason}");
}

#[test]
fn macos_identity_success_with_stderr_is_ambiguous() {
    let observer = FakeObserver::new().with(
        IdentityQuery::AccountRecord,
        Ok(IdentityObservation {
            exit_code: 0,
            stdout: CLEAN_RECORD.to_string(),
            stderr: "warning: directory service cache\n".to_string(),
        }),
    );
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("unexpected stderr"), "unexpected: {reason}");
}

#[test]
fn macos_identity_privileged_primary_group_is_refused() {
    let record = CLEAN_RECORD.replace("PrimaryGroupID: 4242", "PrimaryGroupID: 80");
    let observer = FakeObserver::new()
        .with_success(IdentityQuery::AccountRecord, record)
        .with_success(
            IdentityQuery::UsersWithUniqueId {
                unique_id: CLEAN_UID,
            },
            search_result(PRODUCT_SERVICE_ACCOUNT, "UniqueID", CLEAN_UID),
        )
        .with_success(
            IdentityQuery::GroupsWithPrimaryGroupId {
                primary_group_id: 80,
            },
            search_result("admin", "PrimaryGroupID", 80),
        )
        .with_success(
            IdentityQuery::UsersWithPrimaryGroupId {
                primary_group_id: 80,
            },
            search_result(PRODUCT_SERVICE_ACCOUNT, "PrimaryGroupID", 80),
        )
        .with_success(IdentityQuery::GroupMembershipList, CLEAN_MEMBERSHIPS);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::NonExclusivePrimaryGroup {
                groups: vec!["admin".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_shared_uid_is_refused() {
    let observer = clean_observer().with_success(
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID,
        },
        search_results(&[
            ("_helicoid", "UniqueID", CLEAN_UID),
            ("alice", "UniqueID", CLEAN_UID),
        ]),
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::NonExclusiveUniqueId {
                records: vec!["_helicoid".to_string(), "alice".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_shared_primary_group_is_refused() {
    let observer = clean_observer()
        .with_success(
            IdentityQuery::GroupsWithPrimaryGroupId {
                primary_group_id: CLEAN_GID,
            },
            search_result("staff", "PrimaryGroupID", CLEAN_GID),
        )
        .with_success(
            IdentityQuery::UsersWithPrimaryGroupId {
                primary_group_id: CLEAN_GID,
            },
            search_results(&[
                ("_helicoid", "PrimaryGroupID", CLEAN_GID),
                ("alice", "PrimaryGroupID", CLEAN_GID),
            ]),
        );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::NonExclusivePrimaryGroup {
                groups: vec!["staff".to_string()]
            },
            IdentityRefusal::PrimaryGroupMembers {
                records: vec!["_helicoid".to_string(), "alice".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_supplemental_privileged_group_is_refused() {
    let observer = clean_observer().with_success(
        IdentityQuery::GroupMembershipList,
        "admin                    root barni _helicoid\n_helicoid                _helicoid\n",
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::SupplementalGroupMembership {
                groups: vec!["admin".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_shared_service_group_is_refused() {
    let observer = clean_observer().with_success(
        IdentityQuery::GroupMembershipList,
        "_helicoid                _helicoid alice\n",
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::SharedServiceGroup {
                members: vec!["alice".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_permission_error_is_unavailable() {
    let observer = FakeObserver::new().with(
        IdentityQuery::AccountRecord,
        Ok(IdentityObservation::failure(1, "Permission denied\n")),
    );
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("Permission denied"), "unexpected: {reason}");
}

#[test]
fn macos_identity_transport_error_is_unavailable() {
    let observer = FakeObserver::new().with_error(IdentityQuery::AccountRecord, "spawn denied");
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("spawn denied"), "unexpected: {reason}");
}

#[test]
fn macos_identity_search_permission_error_is_unavailable() {
    let observer = clean_observer().with(
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID,
        },
        Ok(IdentityObservation::failure(1, "Permission denied\n")),
    );
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("Permission denied"), "unexpected: {reason}");
}

#[test]
fn macos_identity_group_membership_permission_error_is_unavailable() {
    let observer = clean_observer().with(
        IdentityQuery::GroupMembershipList,
        Ok(IdentityObservation::failure(1, "Operation not permitted\n")),
    );
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(
        reason.contains("Operation not permitted"),
        "unexpected: {reason}"
    );
}

#[test]
fn macos_identity_duplicate_unique_id_attribute_is_ambiguous() {
    let record = format!("{CLEAN_RECORD}UniqueID: 4243\n");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("UniqueID"), "unexpected: {reason}");
}

#[test]
fn macos_identity_empty_success_record_is_unavailable() {
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, "");
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("empty"), "unexpected: {reason}");
}

#[test]
fn macos_identity_malformed_search_output_is_unavailable() {
    let observer = clean_observer().with_success(
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID,
        },
        "garbage\n",
    );
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(
        reason.contains("unexpected search line"),
        "unexpected: {reason}"
    );
}

#[test]
fn macos_identity_empty_group_list_is_unavailable() {
    let observer = clean_observer().with_success(IdentityQuery::GroupMembershipList, "");
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(
        reason.contains("group membership list was empty"),
        "unexpected: {reason}"
    );
}

#[test]
fn macos_identity_duplicate_group_line_is_unavailable() {
    let observer = clean_observer().with_success(
        IdentityQuery::GroupMembershipList,
        "admin                    root\nadmin                    alice\n",
    );
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("more than once"), "unexpected: {reason}");
}

#[test]
fn macos_identity_oversized_observation_is_unavailable() {
    let observer =
        FakeObserver::new().with_success(IdentityQuery::AccountRecord, "x".repeat(64 * 1024 + 1));
    let reason = unavailable_reason(observe_service_identity(&observer));
    assert!(reason.contains("exceeds"), "unexpected: {reason}");
}

#[test]
fn macos_identity_empty_uid_search_is_a_conflict_not_clean() {
    let observer = clean_observer().with_success(
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID,
        },
        "",
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::NonExclusiveUniqueId { records: vec![] },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_real_search_fixture_parses() {
    let observation = IdentityObservation::success(search_result("_www", "UniqueID", 70));
    assert_eq!(
        parse_identity_search(&observation, "UniqueID", 70).expect("search parse"),
        vec!["_www"]
    );
    assert!(parse_identity_search(&observation, "PrimaryGroupID", 70).is_err());
}

#[test]
fn macos_identity_group_membership_fixture_parses() {
    let observation = IdentityObservation::success(
        "admin                    root barni _mbsetupuser\n\
         wheel                    root\n\
         _www                     _devicemgr _teamsserver\n",
    );
    let groups = parse_group_membership_list(&observation).expect("membership parse");
    assert_eq!(groups["admin"], vec!["root", "barni", "_mbsetupuser"]);
    assert_eq!(groups["wheel"], vec!["root"]);
    assert_eq!(groups["_www"], vec!["_devicemgr", "_teamsserver"]);
    assert!(parse_group_membership_list(&IdentityObservation::success("")).is_err());
}

#[test]
fn macos_identity_case_variant_record_name_is_recognized_and_still_refused() {
    let record = CLEAN_RECORD.replace("RecordName: _helicoid", "RecordName: _Helicoid");
    let observer = FakeObserver::new()
        .with_success(IdentityQuery::AccountRecord, record)
        .with_success(
            IdentityQuery::UsersWithUniqueId {
                unique_id: CLEAN_UID,
            },
            search_result("_Helicoid", "UniqueID", CLEAN_UID),
        )
        .with_success(
            IdentityQuery::GroupsWithPrimaryGroupId {
                primary_group_id: CLEAN_GID,
            },
            search_result("_Helicoid", "PrimaryGroupID", CLEAN_GID),
        )
        .with_success(
            IdentityQuery::UsersWithPrimaryGroupId {
                primary_group_id: CLEAN_GID,
            },
            search_result("_Helicoid", "PrimaryGroupID", CLEAN_GID),
        )
        .with_success(
            IdentityQuery::GroupMembershipList,
            "_Helicoid                _Helicoid\nadmin                    root\n",
        );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![IdentityRefusal::OwnershipNotVerified]
    );
}

#[test]
fn macos_identity_case_variant_supplemental_group_is_refused() {
    let observer = clean_observer().with_success(
        IdentityQuery::GroupMembershipList,
        "admin                    root _Helicoid\n_helicoid                _helicoid\n",
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::SupplementalGroupMembership {
                groups: vec!["admin".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_ambiguous_service_group_case_is_refused() {
    let observer = clean_observer().with_success(
        IdentityQuery::GroupMembershipList,
        "_helicoid                _helicoid\n_Helicoid                _helicoid\n",
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::AmbiguousServiceGroupCase {
                groups: vec!["_Helicoid".to_string(), "_helicoid".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_ambiguous_unique_id_case_is_refused() {
    let observer = clean_observer().with_success(
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID,
        },
        search_results(&[
            ("_helicoid", "UniqueID", CLEAN_UID),
            ("_Helicoid", "UniqueID", CLEAN_UID),
        ]),
    );
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::NonExclusiveUniqueId {
                records: vec!["_helicoid".to_string(), "_Helicoid".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_case_variant_record_name_alias_is_refused() {
    let record = CLEAN_RECORD.replace("RecordName: _helicoid", "RecordName: _helicoid _Helicoid");
    let observer = FakeObserver::new().with_success(IdentityQuery::AccountRecord, record);
    assert_eq!(
        reasons(observe_service_identity(&observer)),
        vec![
            IdentityRefusal::RecordName {
                observed: vec!["_helicoid".to_string(), "_Helicoid".to_string()]
            },
            IdentityRefusal::OwnershipNotVerified
        ]
    );
}

#[test]
fn macos_identity_reviewed_commands_are_fixed_absolute_argv_without_shell() {
    let queries = [
        IdentityQuery::AccountRecord,
        IdentityQuery::GroupRecord,
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID,
        },
        IdentityQuery::UsersWithPrimaryGroupId {
            primary_group_id: CLEAN_GID,
        },
        IdentityQuery::GroupsWithPrimaryGroupId {
            primary_group_id: CLEAN_GID,
        },
        IdentityQuery::GroupMembershipList,
    ];

    for query in queries {
        let argv = query.reviewed_argv();
        assert!(!argv.is_empty());
        assert_eq!(argv[0], "/usr/bin/dscl");
        assert!(argv.len() <= 6);
        for argument in &argv {
            assert!(!argument.contains('\0'), "{query:?} contains NUL");
            assert!(!argument.contains('\n'), "{query:?} contains newline");
            for forbidden in ["/bin/sh", "/bin/bash", "-c", ";", "|", "$", "`"] {
                assert!(
                    !argument.contains(forbidden),
                    "{query:?} argument {argument:?} contains {forbidden}"
                );
            }
            for forbidden in [
                "-create",
                "-delete",
                "-append",
                "-passwd",
                "-modify",
                "-merge",
                "sudo",
                "launchctl",
            ] {
                assert!(
                    !argument.contains(forbidden),
                    "{query:?} argument {argument:?} contains {forbidden}"
                );
            }
        }
    }

    assert_eq!(
        IdentityQuery::AccountRecord.reviewed_argv(),
        vec![
            "/usr/bin/dscl".to_string(),
            ".".to_string(),
            "-read".to_string(),
            format!("/Users/{PRODUCT_SERVICE_ACCOUNT}"),
        ]
    );
    assert_eq!(
        IdentityQuery::GroupRecord.reviewed_argv(),
        vec![
            "/usr/bin/dscl".to_string(),
            ".".to_string(),
            "-read".to_string(),
            format!("/Groups/{PRODUCT_SERVICE_GROUP}"),
        ]
    );
    assert_eq!(
        IdentityQuery::UsersWithUniqueId {
            unique_id: CLEAN_UID
        }
        .reviewed_argv(),
        vec![
            "/usr/bin/dscl".to_string(),
            ".".to_string(),
            "-search".to_string(),
            "/Users".to_string(),
            "UniqueID".to_string(),
            CLEAN_UID.to_string(),
        ]
    );
    assert_eq!(
        IdentityQuery::GroupsWithPrimaryGroupId {
            primary_group_id: CLEAN_GID
        }
        .reviewed_argv(),
        vec![
            "/usr/bin/dscl".to_string(),
            ".".to_string(),
            "-search".to_string(),
            "/Groups".to_string(),
            "PrimaryGroupID".to_string(),
            CLEAN_GID.to_string(),
        ]
    );
    assert_eq!(PRODUCT_SERVICE_GROUP, "_helicoid");
    assert!(NON_LOGIN_SHELLS.contains(&"/usr/bin/false"));
    assert!(NON_LOGIN_SHELLS.contains(&"/sbin/nologin"));
    assert!(!NON_LOGIN_SHELLS.contains(&"/usr/sbin/nologin"));
    assert!(!NON_LOGIN_SHELLS.contains(&"/bin/zsh"));
}

#[test]
fn group_record_parser_reads_the_receipt_identity_fields() {
    let observation = IdentityObservation::success(
        "RecordName: _helicoid\nRecordType: dsRecTypeStandard:Groups\nPrimaryGroupID: 400\nGroupMembership: _helicoid\n",
    );
    let record = parse_group_record(&observation)
        .expect("group record")
        .expect("present group");
    assert_eq!(record.record_names, vec!["_helicoid".to_string()]);
    assert_eq!(record.record_type, "dsRecTypeStandard:Groups");
    assert_eq!(record.primary_group_id, 400);
    assert_eq!(record.group_membership, vec!["_helicoid".to_string()]);

    let absent = IdentityObservation::failure(100, "eDSRecordNotFound: record not found\n");
    assert_eq!(
        parse_group_record(&absent).expect("not-found is an observation"),
        None
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "read-only live Directory Services observation; run explicitly on macOS"]
fn macos_identity_live_observation_is_read_only_and_never_authorizes_install() {
    let decision = observe_local_service_identity();
    println!("live service identity: {decision}");
    match decision {
        ServiceIdentityDecision::AccountAbsentObservation => {}
        ServiceIdentityDecision::AccountAbsentGroupPresentObservation => {
            println!("live identity has an existing service group");
        }
        ServiceIdentityDecision::ExistingAccountRefused { reasons } => {
            assert!(reasons.contains(&IdentityRefusal::OwnershipNotVerified));
        }
        ServiceIdentityDecision::Unavailable { reason } => {
            println!("live identity facts unavailable: {reason}");
        }
    }
}
