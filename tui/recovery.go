package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

type recoveryQuarantineStatus struct {
	DeploymentID             string `json:"deployment_id"`
	RecoveryQuarantined      bool   `json:"recovery_quarantined"`
	QuarantinedAccountCount  int64  `json:"quarantined_account_count"`
	RevokedManagerCount      int64  `json:"revoked_manager_count"`
	QuarantinedEndpointCount int64  `json:"quarantined_endpoint_count"`
}

type recoveryQuarantineReleaseInput struct {
	ExpectedDeploymentID                        string `json:"expected_deployment_id"`
	ExpectedQuarantinedAccountCount             int64  `json:"expected_quarantined_account_count"`
	ExpectedRevokedManagerCount                 int64  `json:"expected_revoked_manager_count"`
	ExpectedQuarantinedEndpointCount            int64  `json:"expected_quarantined_endpoint_count"`
	AcknowledgeMissingPostBackupHistory         bool   `json:"acknowledge_missing_post_backup_history"`
	AcknowledgeRestoredAuthoritiesRemainBlocked bool   `json:"acknowledge_restored_authorities_remain_quarantined"`
	ConfirmationPhrase                          string `json:"confirmation_phrase"`
}

func runRecoveryCommand(args []string) error {
	if len(args) != 1 || (args[0] != "status" && args[0] != "release-quarantine") {
		return errors.New("usage: helicoid-server recovery status|release-quarantine")
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
	return withAuthenticatedManager(ctx, client, func(deployment deploymentInfo, session *authenticatedSession) error {
		if !session.Account.Capabilities.ManageAccounts {
			return errors.New("account management permission is required to review recovery quarantine")
		}
		status, err := fetchLoopbackJSONWithBearer[recoveryQuarantineStatus](
			ctx, client, http.MethodGet, "/v2/recovery/quarantine", nil, session.Token)
		if err != nil {
			return err
		}
		if status.DeploymentID != deployment.DeploymentID {
			return errors.New("recovery status belongs to a different deployment")
		}
		printRecoveryQuarantineStatus(status)
		if args[0] == "status" || !status.RecoveryQuarantined {
			return nil
		}
		if !session.Account.Capabilities.ManageSecurity {
			return errors.New("a security administrator must release restore recovery quarantine")
		}

		fmt.Fprintln(os.Stdout, "\nThe backup does not contain later revocations, account changes, or endpoint replacements.")
		fmt.Fprintln(os.Stdout, "Restored accounts remain disabled, restored Manager approvals remain revoked, and endpoints remain quarantined after release.")
		phrase := "release restored deployment " + status.DeploymentID
		answer, err := readPromptLine("Type " + phrase + " to continue: ")
		if err != nil {
			return err
		}
		if answer != phrase {
			return errors.New("recovery quarantine release was not confirmed")
		}
		historyAnswer, err := readPromptLine("Type 'missing post-backup history acknowledged': ")
		if err != nil {
			return err
		}
		if historyAnswer != "missing post-backup history acknowledged" {
			return errors.New("missing-history acknowledgment did not match")
		}
		retainedAnswer, err := readPromptLine("Type 'restored authorities stay quarantined': ")
		if err != nil {
			return err
		}
		if retainedAnswer != "restored authorities stay quarantined" {
			return errors.New("retained-authority acknowledgment did not match")
		}

		updated, err := fetchLoopbackJSONWithBearer[recoveryQuarantineStatus](
			ctx, client, http.MethodPost, "/v2/recovery/quarantine/release",
			recoveryQuarantineReleaseInput{
				ExpectedDeploymentID:                        status.DeploymentID,
				ExpectedQuarantinedAccountCount:             status.QuarantinedAccountCount,
				ExpectedRevokedManagerCount:                 status.RevokedManagerCount,
				ExpectedQuarantinedEndpointCount:            status.QuarantinedEndpointCount,
				AcknowledgeMissingPostBackupHistory:         true,
				AcknowledgeRestoredAuthoritiesRemainBlocked: true,
				ConfirmationPhrase:                          phrase,
			},
			session.Token)
		if err != nil {
			return err
		}
		if updated.DeploymentID != status.DeploymentID || updated.RecoveryQuarantined ||
			updated.QuarantinedAccountCount != status.QuarantinedAccountCount ||
			updated.RevokedManagerCount != status.RevokedManagerCount ||
			updated.QuarantinedEndpointCount != status.QuarantinedEndpointCount {
			return errors.New("server did not confirm the reviewed recovery release")
		}
		fmt.Fprintln(os.Stdout, "Recovery quarantine released for new authority only. Restored accounts and endpoints remain blocked.")
		return nil
	})
}

func printRecoveryQuarantineStatus(status recoveryQuarantineStatus) {
	fmt.Fprintf(os.Stdout, "Recovery status for deployment %s\n", status.DeploymentID)
	fmt.Fprintf(os.Stdout, "Deployment quarantine: %t\n", status.RecoveryQuarantined)
	fmt.Fprintf(os.Stdout, "Quarantined restored accounts: %d\n", status.QuarantinedAccountCount)
	fmt.Fprintf(os.Stdout, "Revoked Manager identities: %d\n", status.RevokedManagerCount)
	fmt.Fprintf(os.Stdout, "Quarantined endpoints: %d\n", status.QuarantinedEndpointCount)
}
