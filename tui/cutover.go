package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type authorityCutoverStatus struct {
	AuthorityID            string                  `json:"authority_id"`
	AuthorityState         string                  `json:"authority_state"`
	AuthorityGeneration    int64                   `json:"authority_generation"`
	PredecessorAuthorityID *string                 `json:"predecessor_authority_id"`
	Cutover                *authorityCutoverRecord `json:"cutover"`
}

type authorityCutoverRecord struct {
	ID                       string  `json:"id"`
	PredecessorAuthorityID   string  `json:"predecessor_authority_id"`
	ReplacementAuthorityID   *string `json:"replacement_authority_id"`
	Generation               int64   `json:"generation"`
	State                    string  `json:"state"`
	InitiatedByAccountID     *string `json:"initiated_by_account_id"`
	ApprovedByAccountID      *string `json:"approved_by_account_id"`
	FencingMethod            *string `json:"fencing_method"`
	FencingEvidenceReference *string `json:"fencing_evidence_reference"`
	CreatedAt                int64   `json:"created_at"`
	ApprovedAt               *int64  `json:"approved_at"`
}

func runCutoverCommand(args []string) error {
	if len(args) != 1 || !oneOf(args[0], "status", "drain", "approve", "cancel") {
		return errors.New("usage: helicoid-server cutover status|drain|approve|cancel")
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
			return errors.New("account management permission is required to review authority cutover")
		}
		status, err := fetchLoopbackJSONWithBearer[authorityCutoverStatus](
			ctx, client, http.MethodGet, "/v2/authority/cutover", nil, session.Token)
		if err != nil {
			return err
		}
		if status.AuthorityID != deployment.DeploymentID {
			return errors.New("authority cutover status belongs to a different deployment")
		}
		printAuthorityCutoverStatus(status)
		if args[0] == "status" {
			return nil
		}
		if !session.Account.Capabilities.ManageSecurity {
			return errors.New("a security administrator is required for authority cutover")
		}
		switch args[0] {
		case "drain":
			if status.AuthorityState != "active" {
				return errors.New("only an Active authority can begin a drain")
			}
			fmt.Fprintln(os.Stdout, "Before draining, end every active interaction and settle or cancel pending observation grants and file jobs.")
			phrase := "drain authority " + status.AuthorityID
			answer, err := readPromptLine("This stops ordinary authority on this server. Type " + phrase + ": ")
			if err != nil {
				return err
			}
			if answer != phrase {
				return errors.New("authority drain was not confirmed")
			}
			updated, err := fetchLoopbackJSONWithBearer[authorityCutoverStatus](
				ctx, client, http.MethodPost, "/v2/authority/cutover/drain",
				map[string]string{"confirmation_phrase": phrase}, session.Token)
			if err != nil {
				return err
			}
			printAuthorityCutoverStatus(updated)
			fmt.Fprintln(os.Stdout, "Authority is Draining. Take the encrypted backup, stop or isolate this host, then restore it on the replacement host.")
			return nil
		case "approve":
			if status.AuthorityState != "awaiting_cutover" || status.Cutover == nil || status.Cutover.State != "awaiting_review" || status.PredecessorAuthorityID == nil {
				return errors.New("no restored authority is awaiting cutover review")
			}
			replacementID := status.AuthorityID
			predecessorID := *status.PredecessorAuthorityID
			fmt.Fprintln(os.Stdout, "Approval records your independent review; it cannot prove that an unreachable or cloned old host was fenced.")
			method, err := chooseFencingMethod()
			if err != nil {
				return err
			}
			evidence, err := readPromptLine("Evidence reference (for example, a change ticket or verified local procedure ID): ")
			if err != nil {
				return err
			}
			phrase := "approve authority cutover " + predecessorID + " to " + replacementID
			answer, err := readPromptLine("Type " + phrase + ": ")
			if err != nil {
				return err
			}
			if answer != phrase {
				return errors.New("authority cutover approval was not confirmed")
			}
			input := map[string]string{
				"cutover_id":                        status.Cutover.ID,
				"expected_predecessor_authority_id": predecessorID,
				"expected_replacement_authority_id": replacementID,
				"fencing_method":                    method,
				"fencing_evidence_reference":        strings.TrimSpace(evidence),
				"confirmation_phrase":               phrase,
			}
			updated, err := fetchLoopbackJSONWithBearer[authorityCutoverStatus](
				ctx, client, http.MethodPost, "/v2/authority/cutover/approve", input, session.Token)
			if err != nil {
				return err
			}
			printAuthorityCutoverStatus(updated)
			fmt.Fprintln(os.Stdout, "Cutover review approved. The restored deployment remains quarantined until its recovery review is released; peer trust still requires reconciliation.")
			return nil
		case "cancel":
			if status.AuthorityState != "draining" || status.Cutover == nil || status.Cutover.State != "draining" {
				return errors.New("only the still-running predecessor can cancel a draining cutover")
			}
			phrase := "cancel authority cutover " + status.Cutover.ID
			answer, err := readPromptLine("Type " + phrase + " to restore this predecessor to Active: ")
			if err != nil {
				return err
			}
			if answer != phrase {
				return errors.New("authority cutover cancellation was not confirmed")
			}
			updated, err := fetchLoopbackJSONWithBearer[authorityCutoverStatus](
				ctx, client, http.MethodPost, "/v2/authority/cutover/cancel",
				map[string]string{"cutover_id": status.Cutover.ID, "confirmation_phrase": phrase}, session.Token)
			if err != nil {
				return err
			}
			printAuthorityCutoverStatus(updated)
			return nil
		default:
			return errors.New("unsupported authority cutover action")
		}
	})
}

func chooseFencingMethod() (string, error) {
	fmt.Fprintln(os.Stdout, "Choose the reviewed predecessor-fencing procedure:")
	fmt.Fprintln(os.Stdout, "1. Host powered off")
	fmt.Fprintln(os.Stdout, "2. Service and routes isolated")
	fmt.Fprintln(os.Stdout, "3. Network isolated")
	fmt.Fprintln(os.Stdout, "4. Locally verified profile")
	answer, err := readPromptLine("Selection [1-4]: ")
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(answer) {
	case "1":
		return "host_powered_off", nil
	case "2":
		return "service_and_routes_isolated", nil
	case "3":
		return "network_isolated", nil
	case "4":
		return "locally_verified_profile", nil
	default:
		return "", errors.New("choose a fencing procedure from 1 to 4")
	}
}

func printAuthorityCutoverStatus(status authorityCutoverStatus) {
	fmt.Fprintf(os.Stdout, "Authority: %s\n", status.AuthorityID)
	fmt.Fprintf(os.Stdout, "State: %s\n", status.AuthorityState)
	fmt.Fprintf(os.Stdout, "Generation: %d\n", status.AuthorityGeneration)
	if status.PredecessorAuthorityID != nil {
		fmt.Fprintf(os.Stdout, "Predecessor: %s\n", *status.PredecessorAuthorityID)
	}
	if status.Cutover != nil {
		fmt.Fprintf(os.Stdout, "Cutover review: %s (%s)\n", status.Cutover.ID, status.Cutover.State)
		if status.Cutover.ReplacementAuthorityID != nil {
			fmt.Fprintf(os.Stdout, "Replacement: %s\n", *status.Cutover.ReplacementAuthorityID)
		}
		if status.Cutover.ApprovedByAccountID != nil {
			fmt.Fprintf(os.Stdout, "Approved by account: %s\n", *status.Cutover.ApprovedByAccountID)
		}
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
