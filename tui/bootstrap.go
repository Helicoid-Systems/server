package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	localAuthority = "127.0.0.1:8787"
	maxAPIResponse = 4 << 20
)

type deploymentInfo struct {
	DeploymentID string `json:"deployment_id"`
}

type bootstrapV2Input struct {
	BootstrapToken      string `json:"bootstrap_token"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	ManagerPublicKey    string `json:"manager_public_key"`
	ManagerProof        string `json:"manager_proof"`
	ManagerFriendlyName string `json:"manager_friendly_name"`
}

type bootstrapV2Output struct {
	AccountID        string   `json:"account_id"`
	Username         string   `json:"username"`
	MFAEnrollmentID  string   `json:"mfa_enrollment_id"`
	TOTPSecret       string   `json:"totp_secret_base32"`
	RecoveryCodes    []string `json:"recovery_codes"`
	ManagerPublicKey *string  `json:"manager_public_key"`
	AccountState     string   `json:"account_state"`
	ServerState      string   `json:"server_state"`
}

type mfaConfirmInput struct {
	MFAEnrollmentID        string `json:"mfa_enrollment_id"`
	TOTPCode               string `json:"totp_code"`
	RecoveryMaterialStored bool   `json:"recovery_material_stored"`
}

type mfaConfirmOutput struct {
	AccountID    string `json:"account_id"`
	MFAStatus    string `json:"mfa_status"`
	AccountState string `json:"account_state"`
}

type authChallengeBeginInput struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	Operation        string `json:"operation"`
	ManagerPublicKey string `json:"manager_public_key"`
}

type authChallengeBeginOutput struct {
	ChallengeID      string `json:"challenge_id"`
	ChallengeToken   string `json:"challenge_token"`
	Operation        string `json:"operation"`
	ManagerPublicKey string `json:"manager_public_key"`
	DeploymentID     string `json:"deployment_id"`
	MFARequired      bool   `json:"mfa_required"`
}

type authChallengeCompleteInput struct {
	ChallengeID      string `json:"challenge_id"`
	ChallengeToken   string `json:"challenge_token"`
	ManagerSignature string `json:"manager_signature"`
	TOTPCode         string `json:"totp_code"`
}

type authenticatedSession struct {
	Token            string      `json:"token"`
	ExpiresAtUnix    int64       `json:"expires_at_unix"`
	Account          accountView `json:"account"`
	ManagerPublicKey *string     `json:"manager_public_key"`
}

type accountView struct {
	ID                  string              `json:"id"`
	Username            string              `json:"username"`
	State               string              `json:"state"`
	RecoveryQuarantined bool                `json:"recovery_quarantined"`
	Capabilities        accountCapabilities `json:"capabilities"`
	Revision            int64               `json:"revision"`
}

type accountCapabilities struct {
	Operate          bool `json:"operate"`
	ManageEnrollment bool `json:"manage_enrollment"`
	ManageAccess     bool `json:"manage_access"`
	ManageAccounts   bool `json:"manage_accounts"`
	ManageSecurity   bool `json:"manage_security"`
}

type accountListOutput struct {
	Accounts []accountView `json:"accounts"`
}

type computerView struct {
	ID              string             `json:"id"`
	FriendlyName    string             `json:"friendly_name"`
	Platform        string             `json:"platform"`
	EnrollmentState string             `json:"enrollment_state"`
	EnrollmentEpoch int64              `json:"enrollment_epoch"`
	Groups          []computerGroupRef `json:"groups"`
}

type computerListOutput struct {
	Computers       []computerView `json:"computers"`
	ScopeIsExplicit bool           `json:"scope_is_explicit"`
	MaxPageSize     int            `json:"max_page_size"`
}

type managerView struct {
	ID             string `json:"id"`
	PublicIdentity string `json:"public_identity"`
	FriendlyName   string `json:"friendly_name"`
	LifecycleState string `json:"lifecycle_state"`
	ApprovedAtUnix *int64 `json:"approved_at_unix"`
}

type managerListOutput struct {
	Managers []managerView `json:"managers"`
}

type managerApproveInput struct {
	Confirm bool `json:"confirm"`
}

type managerRevokeInput struct {
	Confirm          bool   `json:"confirm"`
	ConfirmManagerID string `json:"confirm_manager_id"`
}

func runBootstrapCommand(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: helicoid-server bootstrap")
	}
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client := newLoopbackAPIClient()
	health, err := fetchLoopbackJSON[healthReport](ctx, client, http.MethodGet, "/health", nil)
	if err != nil {
		return err
	}
	if health.BootstrapCompleted {
		return errors.New("server bootstrap is already complete")
	}
	if health.Status != "ok" && health.Status != "degraded" {
		return errors.New("local Helicoid server health is not ready for bootstrap")
	}
	if !health.Features.MFA || !health.Features.ManagerEnrollment {
		return errors.New("local server does not advertise MFA and manager enrollment")
	}
	deployment, err := fetchLoopbackJSON[deploymentInfo](ctx, client, http.MethodGet, "/v2/deployment", nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(deployment.DeploymentID) == "" {
		return errors.New("server returned no deployment identity")
	}
	identity, err := loadOrCreateManagerIdentity(deployment.DeploymentID)
	if err != nil {
		return err
	}

	username, err := readPromptLine("Administrator username: ")
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("administrator username is required")
	}
	token, err := readSecret("One-time bootstrap token: ")
	if err != nil {
		return err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("bootstrap token is required")
	}
	password, err := readSecret("Administrator password: ")
	if err != nil {
		return err
	}
	confirmation, err := readSecret("Repeat administrator password: ")
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(confirmation)) != 1 {
		return errors.New("password entries did not match")
	}
	confirmation = ""

	proofMessage, err := bootstrapManagerProofMessage(deployment.DeploymentID, token, identity.publicKeyHex())
	if err != nil {
		return err
	}
	friendlyName, _ := os.Hostname()
	if strings.TrimSpace(friendlyName) == "" {
		friendlyName = "Linux server manager"
	}
	request := bootstrapV2Input{
		BootstrapToken:      token,
		Username:            username,
		Password:            password,
		ManagerPublicKey:    identity.publicKeyHex(),
		ManagerProof:        identity.sign(proofMessage),
		ManagerFriendlyName: friendlyName,
	}
	// Drop references as soon as the one-use request has been sent. The API
	// endpoint never echoes these fields and this command never prints them.
	token = ""
	password = ""
	proofMessage = nil
	response, err := fetchLoopbackJSON[bootstrapV2Output](ctx, client, http.MethodPost, "/v2/bootstrap", request)
	request.BootstrapToken = ""
	request.Password = ""
	request.ManagerProof = ""
	if err != nil {
		return err
	}
	if response.MFAEnrollmentID == "" || response.TOTPSecret == "" || len(response.RecoveryCodes) == 0 {
		return errors.New("server returned incomplete one-time MFA enrollment material")
	}
	if response.ManagerPublicKey == nil || !strings.EqualFold(*response.ManagerPublicKey, identity.publicKeyHex()) {
		return errors.New("server did not bind the initiating manager identity")
	}

	fmt.Fprintf(os.Stdout, "Administrator %q is pending MFA confirmation.\n", response.Username)
	fmt.Fprintln(os.Stdout, "Add this TOTP secret to your authenticator:")
	fmt.Fprintln(os.Stdout, response.TOTPSecret)
	fmt.Fprintln(os.Stdout, "Store these recovery codes somewhere independent of this server:")
	for index, code := range response.RecoveryCodes {
		fmt.Fprintln(os.Stdout, code)
		response.RecoveryCodes[index] = ""
	}
	response.TOTPSecret = ""
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Enrollment ID for confirmation retry: %s\n", response.MFAEnrollmentID)
	return confirmMFAEnrollment(ctx, client, response.MFAEnrollmentID)
}

func runMFACommand(args []string) error {
	if len(args) == 1 && args[0] == "recover" {
		return runFactorRecoveryCommand()
	}
	if len(args) != 2 || args[0] != "confirm" || args[1] == "" {
		return errors.New("usage: helicoid-server mfa confirm ENROLLMENT_ID | mfa recover")
	}
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return confirmMFAEnrollment(ctx, newLoopbackAPIClient(), args[1])
}

type factorRecoveryBeginInput struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	RecoveryCode string `json:"recovery_code"`
}

type factorRecoveryBeginOutput struct {
	MFAEnrollmentID string `json:"mfa_enrollment_id"`
	TOTPSecret      string `json:"totp_secret_base32"`
	AccountID       string `json:"account_id"`
	Purpose         string `json:"purpose"`
}

func runFactorRecoveryCommand() error {
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}
	username, err := readPromptLine("Account username: ")
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("account username is required")
	}
	password, err := readSecret("Account password: ")
	if err != nil {
		return err
	}
	recoveryCode, err := readSecret("Unused recovery code: ")
	if err != nil {
		password = ""
		return err
	}
	input := factorRecoveryBeginInput{Username: username, Password: password, RecoveryCode: strings.TrimSpace(recoveryCode)}
	password = ""
	recoveryCode = ""
	if input.RecoveryCode == "" {
		return errors.New("recovery code is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := newLoopbackAPIClient()
	output, err := fetchLoopbackJSON[factorRecoveryBeginOutput](ctx, client, http.MethodPost, "/v2/auth/recovery/begin", input)
	input.Password = ""
	input.RecoveryCode = ""
	if err != nil {
		return err
	}
	if !validUUID(output.AccountID) || !validUUID(output.MFAEnrollmentID) || output.Purpose != "totp_factor_recovery_only" || output.TOTPSecret == "" {
		output.TOTPSecret = ""
		return errors.New("server returned incomplete factor recovery material")
	}
	fmt.Fprintf(os.Stdout, "TOTP recovery is pending for account %s. Add this new secret to the authenticator:\n", output.AccountID)
	fmt.Fprintln(os.Stdout, output.TOTPSecret)
	output.TOTPSecret = ""
	fmt.Fprintln(os.Stdout, "The recovery code you used is consumed; other unused recovery codes remain available.")
	answer, err := readPromptLine("After saving the new TOTP secret and confirming other recovery codes are stored independently, type STORED: ")
	if err != nil {
		return err
	}
	if answer != "STORED" {
		return errors.New("factor recovery was not confirmed; enrollment remains pending")
	}
	code, err := readSecret("Current code from the new authenticator: ")
	if err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	if !validTOTPCode(code) {
		code = ""
		return errors.New("authenticator code must contain six digits")
	}
	confirmed, err := fetchLoopbackJSON[mfaConfirmOutput](ctx, client, http.MethodPost, "/v2/auth/recovery/complete", mfaConfirmInput{
		MFAEnrollmentID:        output.MFAEnrollmentID,
		TOTPCode:               code,
		RecoveryMaterialStored: true,
	})
	code = ""
	if err != nil {
		return err
	}
	if confirmed.AccountID != output.AccountID || confirmed.MFAStatus != "active" || confirmed.AccountState != "active" {
		return errors.New("server did not confirm active factor recovery")
	}
	fmt.Fprintf(os.Stdout, "TOTP factor recovery completed for account %s. No session was created.\n", confirmed.AccountID)
	return nil
}

func runComputersCommand(args []string) error {
	if len(args) != 1 || args[0] != "list" && args[0] != "enrollment-list" {
		return errors.New("usage: helicoid-server computers list|enrollment-list")
	}
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := newLoopbackAPIClient()
	deployment, session, err := authenticateLocalManager(ctx, client)
	if err != nil {
		return err
	}
	revoked := false
	defer func() {
		if !revoked {
			_ = revokeLoopbackSession(ctx, client, session.Token)
		}
		session.Token = ""
	}()
	path := "/v2/computers"
	if args[0] == "enrollment-list" {
		if !session.Account.Capabilities.ManageEnrollment {
			return errors.New("enrollment management permission is required to list enrollment metadata")
		}
		path = "/v2/enrollment/computers"
	}
	computers, err := fetchLoopbackJSONWithBearer[computerListOutput](ctx, client, http.MethodGet, path, nil, session.Token)
	if err != nil {
		return err
	}
	if err := finishLocalManagerSession(ctx, client, &session); err != nil {
		return err
	}
	revoked = true
	label := "Authorized inventory"
	scope := "all assigned computers"
	if args[0] == "enrollment-list" {
		label = "Enrollment metadata"
		if computers.MaxPageSize < 1 || computers.MaxPageSize > 100 {
			return errors.New("server returned an invalid enrollment inventory page limit")
		}
		scope = fmt.Sprintf("registered computers (up to %d per response; this does not grant observe access)", computers.MaxPageSize)
	} else if computers.ScopeIsExplicit {
		scope = "explicitly assigned computers"
	}
	fmt.Fprintf(os.Stdout, "%s on deployment %s (%s; viewed by %s):\n", label, deployment.DeploymentID, scope, session.Account.Username)
	for _, computer := range computers.Computers {
		groupNames := make([]string, 0, len(computer.Groups))
		for _, group := range computer.Groups {
			groupNames = append(groupNames, group.Name)
		}
		groups := "none"
		if len(groupNames) > 0 {
			groups = strings.Join(groupNames, ", ")
		}
		fmt.Fprintf(os.Stdout, "%s  %-26q platform=%-12s enrollment=%s epoch=%d groups=%q\n", computer.ID, computer.FriendlyName, computer.Platform, computer.EnrollmentState, computer.EnrollmentEpoch, groups)
	}
	if len(computers.Computers) == 0 {
		if args[0] == "enrollment-list" {
			fmt.Fprintln(os.Stdout, "No registered computers are available for enrollment administration.")
		} else {
			fmt.Fprintln(os.Stdout, "No computers are assigned to this account.")
		}
	}
	return nil
}

func runManagersCommand(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: helicoid-server managers list | managers approve|revoke [MANAGER_ID]")
	}
	if args[0] != "list" && args[0] != "approve" && args[0] != "revoke" ||
		args[0] == "list" && len(args) != 1 ||
		(args[0] == "approve" || args[0] == "revoke") && len(args) > 2 {
		return errors.New("usage: helicoid-server managers list | managers approve|revoke [MANAGER_ID]")
	}
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}
	managerID := ""
	if args[0] == "approve" || args[0] == "revoke" {
		if len(args) == 2 {
			managerID = args[1]
		} else {
			promptedID, promptErr := readPromptLine("Management device ID: ")
			if promptErr != nil {
				return promptErr
			}
			managerID = strings.TrimSpace(promptedID)
		}
		if !validUUID(managerID) {
			return errors.New("management device ID must be a UUID")
		}
		managerID = strings.ToLower(managerID)
		answer, err := readPromptLine(fmt.Sprintf("To %s manager %s, type %s %s: ", args[0], managerID, args[0], managerID))
		if err != nil {
			return err
		}
		if answer != args[0]+" "+managerID {
			return fmt.Errorf("manager %s was not confirmed", args[0])
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := newLoopbackAPIClient()
	deployment, session, err := authenticateLocalManager(ctx, client)
	if err != nil {
		return err
	}
	revoked := false
	defer func() {
		if !revoked {
			_ = revokeLoopbackSession(ctx, client, session.Token)
		}
		session.Token = ""
	}()
	if !session.Account.Capabilities.ManageEnrollment {
		return errors.New("enrollment management permission is required to manage devices")
	}
	if args[0] == "list" {
		managers, err := fetchLoopbackJSONWithBearer[managerListOutput](ctx, client, http.MethodGet, "/v2/managers", nil, session.Token)
		if err != nil {
			return err
		}
		if err := finishLocalManagerSession(ctx, client, &session); err != nil {
			return err
		}
		revoked = true
		fmt.Fprintf(os.Stdout, "Management devices on deployment %s:\n", deployment.DeploymentID)
		for _, manager := range managers.Managers {
			fmt.Fprintf(os.Stdout, "%s  %-12s  %q  %s\n", manager.ID, manager.LifecycleState, manager.FriendlyName, manager.PublicIdentity)
		}
		if len(managers.Managers) == 0 {
			fmt.Fprintln(os.Stdout, "No management devices are registered.")
		}
		return nil
	}
	if args[0] == "revoke" {
		if session.ManagerPublicKey == nil {
			return errors.New("authenticated session has no manager identity")
		}
		managers, err := fetchLoopbackJSONWithBearer[managerListOutput](ctx, client, http.MethodGet, "/v2/managers", nil, session.Token)
		if err != nil {
			return err
		}
		for _, manager := range managers.Managers {
			if manager.ID == managerID && strings.EqualFold(manager.PublicIdentity, "key:"+*session.ManagerPublicKey) {
				return errors.New("the current management device cannot revoke itself; sign in from another approved device")
			}
		}
	}
	path := "/v2/managers/" + managerID + "/approve"
	var input any = managerApproveInput{Confirm: true}
	if args[0] == "revoke" {
		path = "/v2/managers/" + managerID + "/revoke"
		input = managerRevokeInput{Confirm: true, ConfirmManagerID: managerID}
	}
	manager, err := fetchLoopbackJSONWithBearer[managerView](ctx, client, http.MethodPost, path, input, session.Token)
	if err != nil {
		return err
	}
	wantState := "approved"
	if args[0] == "revoke" {
		wantState = "revoked"
	}
	if manager.ID != managerID || manager.LifecycleState != wantState {
		return fmt.Errorf("server did not confirm the requested manager %s", args[0])
	}
	if err := finishLocalManagerSession(ctx, client, &session); err != nil {
		return err
	}
	revoked = true
	fmt.Fprintf(os.Stdout, "%s management device %q (%s) on deployment %s.\n", strings.ToUpper(args[0][:1])+args[0][1:], manager.FriendlyName, manager.ID, deployment.DeploymentID)
	return nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}

func authenticateLocalManager(ctx context.Context, client *http.Client) (deploymentInfo, authenticatedSession, error) {
	deployment, err := fetchLoopbackJSON[deploymentInfo](ctx, client, http.MethodGet, "/v2/deployment", nil)
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	if err := validateDeploymentID(deployment.DeploymentID); err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	identity, err := loadManagerIdentity(deployment.DeploymentID)
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	username, err := readPromptLine("Account username: ")
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return deploymentInfo{}, authenticatedSession{}, errors.New("account username is required")
	}
	password, err := readSecret("Account password: ")
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	challengeRequest := authChallengeBeginInput{
		Username:         username,
		Password:         password,
		Operation:        "session",
		ManagerPublicKey: identity.publicKeyHex(),
	}
	password = ""
	challenge, err := fetchLoopbackJSON[authChallengeBeginOutput](ctx, client, http.MethodPost, "/v2/auth/challenge", challengeRequest)
	challengeRequest.Password = ""
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	if challenge.ChallengeID == "" || challenge.ChallengeToken == "" || challenge.Operation != "session" ||
		challenge.DeploymentID != deployment.DeploymentID || !strings.EqualFold(challenge.ManagerPublicKey, identity.publicKeyHex()) || !challenge.MFARequired {
		return deploymentInfo{}, authenticatedSession{}, errors.New("server returned an invalid or factor-free administrator challenge")
	}
	proofMessage, err := authChallengeProofMessage(challenge.DeploymentID, challenge.ChallengeID, challenge.Operation, identity.publicKeyHex())
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	code, err := readSecret("Current authenticator code: ")
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	code = strings.TrimSpace(code)
	if !validTOTPCode(code) {
		return deploymentInfo{}, authenticatedSession{}, errors.New("authenticator code must contain six digits")
	}
	completion := authChallengeCompleteInput{
		ChallengeID:      challenge.ChallengeID,
		ChallengeToken:   challenge.ChallengeToken,
		ManagerSignature: identity.sign(proofMessage),
		TOTPCode:         code,
	}
	challenge.ChallengeToken = ""
	code = ""
	proofMessage = nil
	session, err := fetchLoopbackJSON[authenticatedSession](ctx, client, http.MethodPost, "/v2/auth/challenge/complete", completion)
	completion.ChallengeToken = ""
	completion.TOTPCode = ""
	if err != nil {
		return deploymentInfo{}, authenticatedSession{}, err
	}
	if session.Token == "" || session.Account.State != "active" || session.ManagerPublicKey == nil ||
		!strings.EqualFold(*session.ManagerPublicKey, identity.publicKeyHex()) {
		if session.Token != "" {
			_ = revokeLoopbackSession(ctx, client, session.Token)
			session.Token = ""
		}
		return deploymentInfo{}, authenticatedSession{}, errors.New("server returned an invalid authenticated manager session")
	}
	return deployment, session, nil
}

func validTOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func finishLocalManagerSession(ctx context.Context, client *http.Client, session *authenticatedSession) error {
	if session.Token == "" {
		return errors.New("authenticated manager session is missing")
	}
	if err := revokeLoopbackSession(ctx, client, session.Token); err != nil {
		return errors.New("the authorized operation succeeded, but its session could not be revoked; it will expire automatically")
	}
	session.Token = ""
	return nil
}

func formatAccountCapabilities(capabilities accountCapabilities) string {
	roles := make([]string, 0, 5)
	if capabilities.Operate {
		roles = append(roles, "operate")
	}
	if capabilities.ManageEnrollment {
		roles = append(roles, "enrollment")
	}
	if capabilities.ManageAccess {
		roles = append(roles, "access")
	}
	if capabilities.ManageAccounts {
		roles = append(roles, "accounts")
	}
	if capabilities.ManageSecurity {
		roles = append(roles, "security")
	}
	if len(roles) == 0 {
		return "none"
	}
	return strings.Join(roles, ",")
}

func confirmMFAEnrollment(ctx context.Context, client *http.Client, enrollmentID string) error {
	if err := attestRecoveryStorage(); err != nil {
		return err
	}
	code, err := readSecret("Current authenticator code: ")
	if err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return errors.New("authenticator code must contain six digits")
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return errors.New("authenticator code must contain six digits")
		}
	}
	output, err := fetchLoopbackJSON[mfaConfirmOutput](ctx, client, http.MethodPost, "/v2/mfa/enroll/confirm", mfaConfirmInput{
		MFAEnrollmentID:        enrollmentID,
		TOTPCode:               code,
		RecoveryMaterialStored: true,
	})
	code = ""
	if err != nil {
		return err
	}
	if output.AccountState != "active" || output.MFAStatus != "active" {
		return errors.New("server did not confirm an active administrator MFA state")
	}
	fmt.Fprintln(os.Stdout, "Administrator MFA confirmed. The account is active, and bootstrap is complete.")
	return nil
}

func attestRecoveryStorage() error {
	fmt.Fprintln(os.Stdout, "Before activation, save the recovery codes outside this server.")
	answer, err := readPromptLine("After saving them independently, type STORED: ")
	if err != nil {
		return err
	}
	if answer != "STORED" {
		return errors.New("recovery material was not confirmed; the administrator remains inactive")
	}
	return nil
}

func requireInteractiveTerminal() error {
	for _, stream := range []*os.File{os.Stdin, os.Stdout} {
		info, err := stream.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return errors.New("this operation requires an interactive terminal for authentication and confirmations")
		}
	}
	return nil
}

func newLoopbackAPIClient() *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != localAuthority {
				return nil, errors.New("request destination is outside the fixed loopback authority")
			}
			return dialer.DialContext(ctx, "tcp", localAuthority)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchLoopbackJSON[T any](ctx context.Context, client *http.Client, method, path string, input any) (T, error) {
	return fetchLoopbackJSONWithBearer[T](ctx, client, method, path, input, "")
}

func fetchLoopbackJSONWithBearer[T any](ctx context.Context, client *http.Client, method, path string, input any, bearer string) (T, error) {
	return fetchLoopbackJSONWithBearerQuery[T](ctx, client, method, path, nil, input, bearer)
}

func fetchLoopbackJSONWithBearerQuery[T any](ctx context.Context, client *http.Client, method, path string, query url.Values, input any, bearer string) (T, error) {
	var zero T
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") {
		return zero, errors.New("invalid local API path")
	}
	var body io.Reader
	var payload []byte
	if input != nil {
		var err error
		payload, err = json.Marshal(input)
		if err != nil {
			return zero, errors.New("encode local API request")
		}
		body = bytes.NewReader(payload)
	}
	endpoint := url.URL{Scheme: "http", Host: localAuthority, Path: path}
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		zeroBytes(payload)
		return zero, errors.New("create local API request")
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	zeroBytes(payload)
	if err != nil {
		return zero, errors.New("local Helicoid API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, fmt.Errorf("local Helicoid API returned HTTP %d", response.StatusCode)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxAPIResponse+1))
	if err != nil {
		return zero, errors.New("read local Helicoid API response")
	}
	defer zeroBytes(responseBody)
	if len(responseBody) > maxAPIResponse {
		return zero, errors.New("local Helicoid API response exceeded the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	var output T
	if err := decoder.Decode(&output); err != nil {
		return zero, errors.New("decode local Helicoid API response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, errors.New("local Helicoid API returned trailing data")
	}
	return output, nil
}

func revokeLoopbackSession(ctx context.Context, client *http.Client, token string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+localAuthority+"/v2/auth/logout", nil)
	if err != nil {
		return errors.New("create local session revocation request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return errors.New("revoke local administrator session")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("local session revocation returned HTTP %d", response.StatusCode)
	}
	return nil
}
