package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type createAccountV2Input struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	CanOperate          bool   `json:"can_operate"`
	CanManageEnrollment bool   `json:"can_manage_enrollment"`
	CanManageAccess     bool   `json:"can_manage_access"`
	CanManageAccounts   bool   `json:"can_manage_accounts"`
	CanManageSecurity   bool   `json:"can_manage_security"`
}

type accountProvisioningOutput struct {
	Account         accountView `json:"account"`
	MFAEnrollmentID string      `json:"mfa_enrollment_id"`
	TOTPSecret      string      `json:"totp_secret_base32"`
	RecoveryCodes   []string    `json:"recovery_codes"`
}

type updateAccountCapabilitiesInput struct {
	ExpectedRevision    int64 `json:"expected_revision"`
	CanOperate          bool  `json:"can_operate"`
	CanManageEnrollment bool  `json:"can_manage_enrollment"`
	CanManageAccess     bool  `json:"can_manage_access"`
	CanManageAccounts   bool  `json:"can_manage_accounts"`
	CanManageSecurity   bool  `json:"can_manage_security"`
}

type updateAccountStateInput struct {
	ExpectedRevision int64  `json:"expected_revision"`
	State            string `json:"state"`
}

type grantAccessInput struct {
	AccountID        string   `json:"account_id"`
	Capability       string   `json:"capability"`
	ComputerIDs      []string `json:"computer_ids"`
	ComputerScopeAll bool     `json:"computer_scope_all"`
}

type revokeAccessInput struct {
	ExpectedRevision int64 `json:"expected_revision"`
	Confirm          bool  `json:"confirm"`
}

type accessRevocationOutput struct {
	ID              string `json:"id"`
	AccountID       string `json:"account_id"`
	Capability      string `json:"capability"`
	State           string `json:"state"`
	RevokedRevision int64  `json:"revoked_revision"`
}

type accessAssignmentView struct {
	ID               string   `json:"id"`
	AccountID        string   `json:"account_id"`
	Capability       string   `json:"capability"`
	ComputerScopeAll bool     `json:"computer_scope_all"`
	ComputerIDs      []string `json:"computer_ids"`
	Revision         int64    `json:"revision"`
}

type accessAssignmentListOutput struct {
	Assignments []accessAssignmentView `json:"access_assignments"`
}

type mfaPolicyView struct {
	Policy                  string `json:"policy"`
	MFARequiredForOperators bool   `json:"mfa_required_for_operators"`
}

type mfaPolicyInput struct {
	Policy string `json:"policy"`
}

func runAccountsCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: helicoid-server accounts list|create|capabilities [ACCOUNT_ID]|state [ACCOUNT_ID active|disabled]|access list|grant|revoke [ASSIGNMENT_ID]|mfa-policy [optional|required]")
	}
	valid := false
	switch args[0] {
	case "list", "create":
		valid = len(args) == 1
	case "capabilities":
		valid = len(args) <= 2
	case "state":
		valid = len(args) == 1 || len(args) == 3
	case "access":
		valid = len(args) == 2 && (args[1] == "list" || args[1] == "grant" || args[1] == "revoke") ||
			len(args) == 3 && args[1] == "revoke" && validUUID(args[2])
	case "mfa-policy":
		valid = len(args) <= 2
	}
	if !valid {
		return errors.New("usage: helicoid-server accounts list|create|capabilities [ACCOUNT_ID]|state [ACCOUNT_ID active|disabled]|access list|grant|revoke [ASSIGNMENT_ID]|mfa-policy [optional|required]")
	}
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}

	accountID := ""
	state := ""
	if (args[0] == "capabilities" && len(args) == 2) || (args[0] == "state" && len(args) == 3) {
		accountID = args[1]
		if !validUUID(accountID) {
			return errors.New("account ID must be a UUID")
		}
	}
	if args[0] == "state" && len(args) == 3 {
		state = args[2]
		if state != "active" && state != "disabled" {
			return errors.New("account state must be active or disabled")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := newLoopbackAPIClient()
	return withAuthenticatedManager(ctx, client, func(deployment deploymentInfo, session *authenticatedSession) error {
		switch args[0] {
		case "list":
			if !session.Account.Capabilities.ManageAccounts {
				return errors.New("account management permission is required to list accounts")
			}
			accounts, err := fetchLoopbackJSONWithBearer[accountListOutput](ctx, client, http.MethodGet, "/v2/accounts", nil, session.Token)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Authorized accounts on deployment %s (%s):\n", deployment.DeploymentID, session.Account.Username)
			for _, account := range accounts.Accounts {
				state := account.State
				if account.RecoveryQuarantined {
					state += " (recovery quarantined)"
				}
				fmt.Fprintf(os.Stdout, "%s  %-26q state=%-34s revision=%d roles=%s\n", account.ID, account.Username, state, account.Revision, formatAccountCapabilities(account.Capabilities))
			}
			if len(accounts.Accounts) == 0 {
				fmt.Fprintln(os.Stdout, "No accounts are currently visible to this administrator.")
			}
			return nil
		case "create":
			if !session.Account.Capabilities.ManageAccounts {
				return errors.New("account management permission is required to create accounts")
			}
			return createAccountInteractively(ctx, client, deployment, session)
		case "capabilities":
			if !session.Account.Capabilities.ManageAccounts {
				return errors.New("account management permission is required to change capabilities")
			}
			return updateAccountCapabilitiesInteractively(ctx, client, deployment, session, accountID)
		case "state":
			if !session.Account.Capabilities.ManageAccounts {
				return errors.New("account management permission is required to change account state")
			}
			return updateAccountStateInteractively(ctx, client, deployment, session, accountID, state)
		case "access":
			if !session.Account.Capabilities.ManageAccess {
				return errors.New("access management permission is required to manage assignments")
			}
			assignmentID := ""
			if len(args) == 3 {
				assignmentID = args[2]
			}
			return runAccessAssignmentCommand(ctx, client, deployment, session, args[1], assignmentID)
		case "mfa-policy":
			if !session.Account.Capabilities.ManageSecurity {
				return errors.New("security administration permission is required to manage operator MFA policy")
			}
			policy := ""
			if len(args) == 2 {
				policy = args[1]
			}
			return runOperatorMFAPolicyCommand(ctx, client, deployment, session, policy)
		default:
			return errors.New("unsupported account operation")
		}
	})
}

func runAccessAssignmentCommand(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, action, assignmentID string) error {
	if action == "list" {
		output, err := fetchLoopbackJSONWithBearer[accessAssignmentListOutput](ctx, client, http.MethodGet, "/v2/access", nil, session.Token)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Computer access assignments on deployment %s:\n", deployment.DeploymentID)
		for _, assignment := range output.Assignments {
			scope := "all computers"
			if !assignment.ComputerScopeAll {
				scope = "computers " + strings.Join(assignment.ComputerIDs, ",")
			}
			fmt.Fprintf(os.Stdout, "%s  account=%s capability=%s scope=%s revision=%d\n", assignment.ID, assignment.AccountID, assignment.Capability, scope, assignment.Revision)
		}
		if len(output.Assignments) == 0 {
			fmt.Fprintln(os.Stdout, "No computer access assignments are configured.")
		}
		return nil
	}
	if action == "revoke" {
		if assignmentID == "" {
			promptedID, err := readPromptLine("Access assignment ID to revoke: ")
			if err != nil {
				return err
			}
			assignmentID = strings.TrimSpace(promptedID)
		}
		if !validUUID(assignmentID) {
			return errors.New("access assignment ID must be a UUID")
		}
		assignments, err := fetchLoopbackJSONWithBearer[accessAssignmentListOutput](ctx, client, http.MethodGet, "/v2/access", nil, session.Token)
		if err != nil {
			return err
		}
		var selected accessAssignmentView
		found := false
		for _, assignment := range assignments.Assignments {
			if assignment.ID == assignmentID {
				selected = assignment
				found = true
				break
			}
		}
		if !found || selected.Revision < 1 {
			return errors.New("access assignment is not visible to this administrator")
		}
		scope := "all computers"
		if !selected.ComputerScopeAll {
			scope = "computers " + strings.Join(selected.ComputerIDs, ",")
		}
		fmt.Fprintf(os.Stdout, "Revoke %s for account %s on %s (revision %d) from deployment %s.\n", selected.Capability, selected.AccountID, scope, selected.Revision, deployment.DeploymentID)
		confirmation := fmt.Sprintf("revoke access %s revision %d", assignmentID, selected.Revision)
		answer, err := readPromptLine("Type " + confirmation + " to continue: ")
		if err != nil {
			return err
		}
		if answer != confirmation {
			return errors.New("access assignment revocation was not confirmed")
		}
		output, err := fetchLoopbackJSONWithBearer[accessRevocationOutput](ctx, client, http.MethodDelete, "/v2/access/"+assignmentID, revokeAccessInput{
			ExpectedRevision: selected.Revision,
			Confirm:          true,
		}, session.Token)
		if err != nil {
			return err
		}
		if output.ID != assignmentID || output.AccountID != selected.AccountID || output.Capability != selected.Capability ||
			output.State != "revoked" || output.RevokedRevision != selected.Revision {
			return errors.New("server did not confirm the requested access revocation")
		}
		fmt.Fprintf(os.Stdout, "Revoked access assignment %s on deployment %s.\n", output.ID, deployment.DeploymentID)
		return nil
	}
	accountID, err := readPromptLine("Account ID to grant access: ")
	if err != nil {
		return err
	}
	accountID = strings.TrimSpace(accountID)
	if !validUUID(accountID) {
		return errors.New("account ID must be a UUID")
	}
	capability, err := readPromptLine("Capability (operate, observe, install_maintain): ")
	if err != nil {
		return err
	}
	capability = strings.TrimSpace(capability)
	if capability != "operate" && capability != "observe" && capability != "install_maintain" {
		return errors.New("capability must be operate, observe, or install_maintain")
	}
	scope, err := readPromptLine("Computer scope (all or selected): ")
	if err != nil {
		return err
	}
	scope = strings.TrimSpace(scope)
	input := grantAccessInput{AccountID: accountID, Capability: capability}
	switch scope {
	case "all":
		input.ComputerScopeAll = true
	case "selected":
		ids, err := readPromptLine("Comma-separated computer IDs: ")
		if err != nil {
			return err
		}
		seen := make(map[string]struct{})
		for _, id := range strings.Split(ids, ",") {
			id = strings.TrimSpace(id)
			if !validUUID(id) {
				return errors.New("every selected computer ID must be a UUID")
			}
			if _, exists := seen[id]; exists {
				return errors.New("selected computer IDs must be unique")
			}
			seen[id] = struct{}{}
			input.ComputerIDs = append(input.ComputerIDs, id)
		}
	default:
		return errors.New("computer scope must be all or selected")
	}
	scopeDescription := "all computers"
	if !input.ComputerScopeAll {
		scopeDescription = "computers " + strings.Join(input.ComputerIDs, ",")
	}
	fmt.Fprintf(os.Stdout, "Grant %s to account %s for %s on deployment %s.\n", input.Capability, input.AccountID, scopeDescription, deployment.DeploymentID)
	confirmation := "grant " + capability + " " + accountID + " " + scopeDescription
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("computer access grant was not confirmed")
	}
	assignment, err := fetchLoopbackJSONWithBearer[accessAssignmentView](ctx, client, http.MethodPost, "/v2/access", input, session.Token)
	if err != nil {
		return err
	}
	if assignment.AccountID != accountID || assignment.Capability != capability || assignment.ComputerScopeAll != input.ComputerScopeAll || assignment.Revision < 1 ||
		(!input.ComputerScopeAll && !sameIDs(assignment.ComputerIDs, input.ComputerIDs)) {
		return errors.New("server did not confirm the requested access assignment")
	}
	fmt.Fprintf(os.Stdout, "Granted %s to account %s for %s (assignment %s, revision %d) on deployment %s.\n", assignment.Capability, assignment.AccountID, scopeDescription, assignment.ID, assignment.Revision, deployment.DeploymentID)
	if assignment.Capability == "observe" {
		fmt.Fprintln(os.Stdout, "This records authorization only; screen observation remains unavailable in this server build.")
	}
	return nil
}

func sameIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	remaining := make(map[string]int, len(left))
	for _, id := range left {
		remaining[id]++
	}
	for _, id := range right {
		remaining[id]--
		if remaining[id] < 0 {
			return false
		}
	}
	return true
}

func runOperatorMFAPolicyCommand(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, requested string) error {
	current, err := fetchLoopbackJSONWithBearer[mfaPolicyView](ctx, client, http.MethodGet, "/v2/security/operator-mfa-policy", nil, session.Token)
	if err != nil {
		return err
	}
	if requested == "" {
		fmt.Fprintf(os.Stdout, "Current operator MFA policy on deployment %s: %s\n", deployment.DeploymentID, current.Policy)
		requested, err = readPromptLine("Set policy to optional or required: ")
		if err != nil {
			return err
		}
		requested = strings.TrimSpace(requested)
	}
	if requested != "optional" && requested != "required" {
		return errors.New("MFA policy must be optional or required")
	}
	if requested == current.Policy {
		fmt.Fprintf(os.Stdout, "Operator MFA policy is already %s; no update was sent.\n", requested)
		return nil
	}
	fmt.Fprintf(os.Stdout, "Change operator MFA policy from %s to %s on deployment %s.\n", current.Policy, requested, deployment.DeploymentID)
	answer, err := readPromptLine("Type mfa-policy " + requested + " to continue: ")
	if err != nil {
		return err
	}
	if answer != "mfa-policy "+requested {
		return errors.New("operator MFA policy change was not confirmed")
	}
	updated, err := fetchLoopbackJSONWithBearer[mfaPolicyView](ctx, client, http.MethodPut, "/v2/security/operator-mfa-policy", mfaPolicyInput{Policy: requested}, session.Token)
	if err != nil {
		return err
	}
	if updated.Policy != requested || updated.MFARequiredForOperators != (requested == "required") {
		return errors.New("server did not confirm the requested operator MFA policy")
	}
	fmt.Fprintf(os.Stdout, "Changed operator MFA policy to %s on deployment %s.\n", updated.Policy, deployment.DeploymentID)
	return nil
}

func withAuthenticatedManager(ctx context.Context, client *http.Client, operation func(deploymentInfo, *authenticatedSession) error) error {
	deployment, session, err := authenticateLocalManager(ctx, client)
	if err != nil {
		return err
	}
	revoked := false
	defer func() {
		if !revoked && session.Token != "" {
			_ = revokeLoopbackSession(ctx, client, session.Token)
		}
		session.Token = ""
	}()
	if err := operation(deployment, &session); err != nil {
		return err
	}
	if err := finishLocalManagerSession(ctx, client, &session); err != nil {
		return err
	}
	revoked = true
	return nil
}

func createAccountInteractively(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession) error {
	username, err := readPromptLine("New account username: ")
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("account username is required")
	}

	capabilities, err := promptAccountCapabilities(accountCapabilities{}, session.Account.Capabilities.ManageSecurity)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Create %q on deployment %s with roles: %s\n", username, deployment.DeploymentID, formatAccountCapabilities(capabilities))
	confirmation := "create account " + username + " roles " + formatAccountCapabilities(capabilities)
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("account creation was not confirmed")
	}

	password, err := readSecret("Initial account password: ")
	if err != nil {
		return err
	}
	passwordConfirmation, err := readSecret("Repeat initial account password: ")
	if err != nil {
		password = ""
		return err
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(passwordConfirmation)) != 1 {
		password = ""
		passwordConfirmation = ""
		return errors.New("password entries did not match")
	}
	passwordConfirmation = ""
	input := createAccountV2Input{
		Username:            username,
		Password:            password,
		CanOperate:          capabilities.Operate,
		CanManageEnrollment: capabilities.ManageEnrollment,
		CanManageAccess:     capabilities.ManageAccess,
		CanManageAccounts:   capabilities.ManageAccounts,
		CanManageSecurity:   capabilities.ManageSecurity,
	}
	output, err := fetchLoopbackJSONWithBearer[accountProvisioningOutput](ctx, client, http.MethodPost, "/v2/accounts", input, session.Token)
	input.Password = ""
	password = ""
	if err != nil {
		return err
	}
	if output.Account.Username != username || output.Account.State != "pending_mfa" || output.MFAEnrollmentID == "" || output.TOTPSecret == "" || len(output.RecoveryCodes) == 0 {
		output.TOTPSecret = ""
		for index := range output.RecoveryCodes {
			output.RecoveryCodes[index] = ""
		}
		return errors.New("server returned incomplete account provisioning material")
	}

	fmt.Fprintf(os.Stdout, "Account %q is pending MFA confirmation on deployment %s.\n", output.Account.Username, deployment.DeploymentID)
	fmt.Fprintln(os.Stdout, "Add this TOTP secret to the new account's authenticator:")
	fmt.Fprintln(os.Stdout, output.TOTPSecret)
	fmt.Fprintln(os.Stdout, "Store these recovery codes somewhere independent of this server:")
	for _, code := range output.RecoveryCodes {
		fmt.Fprintln(os.Stdout, code)
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Enrollment ID for confirmation retry: %s\n", output.MFAEnrollmentID)
	output.TOTPSecret = ""
	for index := range output.RecoveryCodes {
		output.RecoveryCodes[index] = ""
	}
	if err := confirmMFAEnrollment(ctx, client, output.MFAEnrollmentID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Account provisioned on deployment %s. Deliver the initial password to the account owner through your approved channel.\n", deployment.DeploymentID)
	return nil
}

func updateAccountCapabilitiesInteractively(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, accountID string) error {
	if accountID == "" {
		promptedID, err := readPromptLine("Account ID to edit: ")
		if err != nil {
			return err
		}
		accountID = strings.TrimSpace(promptedID)
	}
	if !validUUID(accountID) {
		return errors.New("account ID must be a UUID")
	}
	accounts, err := fetchLoopbackJSONWithBearer[accountListOutput](ctx, client, http.MethodGet, "/v2/accounts", nil, session.Token)
	if err != nil {
		return err
	}
	account, ok := findAccount(accounts.Accounts, accountID)
	if !ok {
		return errors.New("account is not visible to this administrator")
	}
	if account.State != "active" {
		return errors.New("only active accounts can have capabilities changed")
	}
	fmt.Fprintf(os.Stdout, "Current capabilities for %q: %s (revision %d)\n", account.Username, formatAccountCapabilities(account.Capabilities), account.Revision)
	capabilities, err := promptAccountCapabilities(account.Capabilities, session.Account.Capabilities.ManageSecurity)
	if err != nil {
		return err
	}
	if capabilities == account.Capabilities {
		fmt.Fprintln(os.Stdout, "Capabilities are unchanged; no update was sent.")
		return nil
	}
	fmt.Fprintf(os.Stdout, "Set capabilities for %q on deployment %s to: %s\n", account.Username, deployment.DeploymentID, formatAccountCapabilities(capabilities))
	confirmation := "capabilities " + accountID + " " + formatAccountCapabilities(capabilities)
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("capability update was not confirmed")
	}
	updated, err := fetchLoopbackJSONWithBearer[accountView](ctx, client, http.MethodPut, "/v2/accounts/"+accountID+"/capabilities", updateAccountCapabilitiesInput{
		ExpectedRevision:    account.Revision,
		CanOperate:          capabilities.Operate,
		CanManageEnrollment: capabilities.ManageEnrollment,
		CanManageAccess:     capabilities.ManageAccess,
		CanManageAccounts:   capabilities.ManageAccounts,
		CanManageSecurity:   capabilities.ManageSecurity,
	}, session.Token)
	if err != nil {
		return err
	}
	if updated.ID != accountID || updated.Revision != account.Revision+1 || updated.Capabilities != capabilities {
		return errors.New("server did not confirm the requested capability update")
	}
	fmt.Fprintf(os.Stdout, "Updated capabilities for %q on deployment %s.\n", updated.Username, deployment.DeploymentID)
	return nil
}

func updateAccountStateInteractively(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, accountID, state string) error {
	if accountID == "" {
		promptedID, err := readPromptLine("Account ID to change: ")
		if err != nil {
			return err
		}
		accountID = strings.TrimSpace(promptedID)
	}
	if !validUUID(accountID) {
		return errors.New("account ID must be a UUID")
	}
	if state == "" {
		promptedState, err := readPromptLine("Requested state (active or disabled): ")
		if err != nil {
			return err
		}
		state = strings.TrimSpace(promptedState)
	}
	if state != "active" && state != "disabled" {
		return errors.New("account state must be active or disabled")
	}
	accounts, err := fetchLoopbackJSONWithBearer[accountListOutput](ctx, client, http.MethodGet, "/v2/accounts", nil, session.Token)
	if err != nil {
		return err
	}
	account, ok := findAccount(accounts.Accounts, accountID)
	if !ok {
		return errors.New("account is not visible to this administrator")
	}
	if account.RecoveryQuarantined {
		return errors.New("restored account authority remains quarantined and cannot be reactivated")
	}
	if account.State != "active" && account.State != "disabled" {
		return errors.New("only active or disabled accounts can change state")
	}
	if account.ID == session.Account.ID && state == "disabled" {
		return errors.New("the current account cannot disable itself through this workflow")
	}
	if account.State == state {
		fmt.Fprintf(os.Stdout, "Account %q is already %s; no update was sent.\n", account.Username, state)
		return nil
	}
	fmt.Fprintf(os.Stdout, "Change %q from %s to %s on deployment %s (revision %d).\n", account.Username, account.State, state, deployment.DeploymentID, account.Revision)
	answer, err := readPromptLine("Type state " + accountID + " " + state + " to continue: ")
	if err != nil {
		return err
	}
	if answer != "state "+accountID+" "+state {
		return errors.New("account state change was not confirmed")
	}
	updated, err := fetchLoopbackJSONWithBearer[accountView](ctx, client, http.MethodPut, "/v2/accounts/"+accountID+"/state", updateAccountStateInput{
		ExpectedRevision: account.Revision,
		State:            state,
	}, session.Token)
	if err != nil {
		return err
	}
	if updated.ID != accountID || updated.Revision != account.Revision+1 || updated.State != state {
		return errors.New("server did not confirm the requested account state change")
	}
	fmt.Fprintf(os.Stdout, "Changed account %q to %s on deployment %s.\n", updated.Username, updated.State, deployment.DeploymentID)
	return nil
}

func promptAccountCapabilities(current accountCapabilities, allowSecurity bool) (accountCapabilities, error) {
	var next accountCapabilities
	var err error
	if next.Operate, err = promptBool("Can operate computers", current.Operate); err != nil {
		return next, err
	}
	if next.ManageEnrollment, err = promptBool("Can manage enrollment and managers", current.ManageEnrollment); err != nil {
		return next, err
	}
	if next.ManageAccess, err = promptBool("Can manage computer access", current.ManageAccess); err != nil {
		return next, err
	}
	if next.ManageAccounts, err = promptBool("Can create and manage accounts", current.ManageAccounts); err != nil {
		return next, err
	}
	if allowSecurity {
		if next.ManageSecurity, err = promptBool("Can manage security policy", current.ManageSecurity); err != nil {
			return next, err
		}
	} else if current.ManageSecurity {
		return next, errors.New("only a security administrator can change this account's security role")
	}
	return next, nil
}

func promptBool(label string, current bool) (bool, error) {
	defaultChoice := "no"
	if current {
		defaultChoice = "yes"
	}
	answer, err := readPromptLine(fmt.Sprintf("%s? [y/n; Enter keeps %s]: ", label, defaultChoice))
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "":
		return current, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, errors.New("answer with y or n")
	}
}

func findAccount(accounts []accountView, id string) (accountView, bool) {
	for _, account := range accounts {
		if account.ID == id {
			return account, true
		}
	}
	return accountView{}, false
}
