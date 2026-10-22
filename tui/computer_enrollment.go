package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type endpointInvitationRequest struct {
	FriendlyName string `json:"friendly_name"`
	Platform     string `json:"platform"`
}

type oneTimeEnrollmentCode []byte

func (code *oneTimeEnrollmentCode) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("invalid enrollment code response")
	}
	for _, character := range data[1 : len(data)-1] {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-') {
			return errors.New("invalid enrollment code response")
		}
	}
	*code = append((*code)[:0], data[1:len(data)-1]...)
	return nil
}

func (code oneTimeEnrollmentCode) MarshalJSON() ([]byte, error) {
	for _, character := range code {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '_' || character == '-') {
			return nil, errors.New("invalid enrollment code")
		}
	}
	result := make([]byte, 0, len(code)+2)
	result = append(result, '"')
	result = append(result, code...)
	result = append(result, '"')
	return result, nil
}

type endpointInvitationIssued struct {
	ID             string                `json:"id"`
	DeploymentID   string                `json:"deployment_id"`
	FriendlyName   string                `json:"friendly_name"`
	Platform       string                `json:"platform"`
	EnrollmentCode oneTimeEnrollmentCode `json:"enrollment_code"`
	CreatedAt      int64                 `json:"created_at_unix"`
	ExpiresAt      int64                 `json:"expires_at_unix"`
}

type endpointInvitationView struct {
	ID           string `json:"id"`
	FriendlyName string `json:"friendly_name"`
	Platform     string `json:"platform"`
	State        string `json:"state"`
	CreatedAt    int64  `json:"created_at_unix"`
	ExpiresAt    int64  `json:"expires_at_unix"`
	ComputerID   string `json:"computer_id"`
}

type endpointInvitationList struct {
	Invitations []endpointInvitationView `json:"invitations"`
	MaxPageSize int                      `json:"max_page_size"`
}

type enrollmentDecisionInput struct {
	ExpectedEpoch int64  `json:"expected_enrollment_epoch"`
	ConfirmID     string `json:"confirm_computer_id"`
}

type invitationRevocationInput struct {
	ConfirmID string `json:"confirm_invitation_id"`
}

func runComputerEnrollmentCommand(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: helicoid-server enrollment invitations|invite|approve|revoke|revoke-invitation [ID]")
	}
	command := args[0]
	valid := command == "invitations" && len(args) == 1 || command == "invite" && len(args) == 1 ||
		(command == "approve" || command == "revoke" || command == "revoke-invitation") && len(args) <= 2
	if !valid {
		return errors.New("usage: helicoid-server enrollment invitations|invite|approve|revoke|revoke-invitation [ID]")
	}
	requestedID := ""
	if len(args) == 2 {
		requestedID = strings.ToLower(args[1])
		if !validUUID(requestedID) {
			return errors.New("enrollment ID must be a UUID")
		}
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
		if !session.Account.Capabilities.ManageEnrollment {
			return errors.New("enrollment management permission is required to manage endpoints")
		}
		switch command {
		case "invitations":
			return listEndpointInvitations(ctx, client, deployment, session)
		case "invite":
			return createEndpointInvitation(ctx, client, deployment, session)
		case "approve":
			return decideEndpointEnrollment(ctx, client, deployment, session, requestedID, true)
		case "revoke":
			return decideEndpointEnrollment(ctx, client, deployment, session, requestedID, false)
		case "revoke-invitation":
			return revokeEndpointInvitation(ctx, client, deployment, session, requestedID)
		default:
			return errors.New("unsupported endpoint enrollment operation")
		}
	})
}

func listEndpointInvitations(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession) error {
	output, err := fetchLoopbackJSONWithBearer[endpointInvitationList](ctx, client, http.MethodGet, "/v2/enrollment/invitations", nil, session.Token)
	if err != nil {
		return err
	}
	if output.MaxPageSize < 1 || output.MaxPageSize > 100 || len(output.Invitations) > output.MaxPageSize {
		return errors.New("server returned an invalid invitation page limit")
	}
	fmt.Fprintf(os.Stdout, "Endpoint invitations on deployment %s (up to %d records; codes are never listed):\n", deployment.DeploymentID, output.MaxPageSize)
	for _, invitation := range output.Invitations {
		computer := invitation.ComputerID
		if computer == "" {
			computer = "-"
		}
		fmt.Fprintf(os.Stdout, "%s  %-26q platform=%-12s state=%-9s expires=%d computer=%s\n", invitation.ID, invitation.FriendlyName, invitation.Platform, invitation.State, invitation.ExpiresAt, computer)
	}
	if len(output.Invitations) == 0 {
		fmt.Fprintln(os.Stdout, "No endpoint invitations are recorded.")
	}
	return nil
}

func createEndpointInvitation(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession) error {
	name, err := readPromptLine("Endpoint friendly name: ")
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("endpoint friendly name is required")
	}
	platform, err := readPromptLine("Platform (windows, macos, or linux): ")
	if err != nil {
		return err
	}
	platform = strings.ToLower(strings.TrimSpace(platform))
	if platform != "windows" && platform != "macos" && platform != "linux" {
		return errors.New("platform must be windows, macos, or linux")
	}
	confirmation := "create endpoint invitation"
	fmt.Fprintf(os.Stdout, "Create a 15-minute one-time enrollment invitation for %q (%s) on deployment %s.\n", name, platform, deployment.DeploymentID)
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("endpoint invitation confirmation did not match")
	}
	issued, err := fetchLoopbackJSONWithBearer[endpointInvitationIssued](ctx, client, http.MethodPost, "/v2/enrollment/invitations", endpointInvitationRequest{
		FriendlyName: name,
		Platform:     platform,
	}, session.Token)
	if err != nil {
		return err
	}
	defer zeroBytes(issued.EnrollmentCode)
	if !validUUID(issued.ID) || issued.DeploymentID != deployment.DeploymentID ||
		issued.FriendlyName != name || issued.Platform != platform || len(issued.EnrollmentCode) != 43 ||
		issued.CreatedAt <= 0 || issued.ExpiresAt-issued.CreatedAt != 15*60 {
		return errors.New("server returned invalid endpoint invitation material")
	}
	fmt.Fprintf(os.Stdout, "Invitation ID: %s\nDeployment: %s\nEndpoint: %q (%s)\nExpires at: %d\nOne-time enrollment code (displayed once): %s\n", issued.ID, issued.DeploymentID, issued.FriendlyName, issued.Platform, issued.ExpiresAt, issued.EnrollmentCode)
	return nil
}

func revokeEndpointInvitation(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, requestedID string) error {
	output, err := fetchLoopbackJSONWithBearer[endpointInvitationList](ctx, client, http.MethodGet, "/v2/enrollment/invitations", nil, session.Token)
	if err != nil {
		return err
	}
	invitation, err := selectEndpointInvitation(output.Invitations, requestedID, true)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Revoke unredeemed invitation %s for %q on deployment %s?\n", invitation.ID, invitation.FriendlyName, deployment.DeploymentID)
	answer, err := readPromptLine("Type the exact invitation ID to revoke: ")
	if err != nil {
		return err
	}
	if answer != invitation.ID {
		return errors.New("invitation ID confirmation did not match")
	}
	revoked, err := fetchLoopbackJSONWithBearer[endpointInvitationView](ctx, client, http.MethodPost, "/v2/enrollment/invitations/"+invitation.ID+"/revoke", invitationRevocationInput{ConfirmID: invitation.ID}, session.Token)
	if err != nil {
		return err
	}
	if revoked.ID != invitation.ID || revoked.State != "revoked" {
		return errors.New("server did not confirm invitation revocation")
	}
	fmt.Fprintf(os.Stdout, "Revoked invitation %s on deployment %s.\n", revoked.ID, deployment.DeploymentID)
	return nil
}

func selectEndpointInvitation(invitations []endpointInvitationView, requestedID string, pendingOnly bool) (endpointInvitationView, error) {
	if requestedID == "" {
		for _, invitation := range invitations {
			if !pendingOnly || invitation.State == "pending" {
				fmt.Fprintf(os.Stdout, "%s  %-26q platform=%-12s state=%s\n", invitation.ID, invitation.FriendlyName, invitation.Platform, invitation.State)
			}
		}
		value, err := readPromptLine("Invitation ID: ")
		if err != nil {
			return endpointInvitationView{}, err
		}
		requestedID = strings.ToLower(strings.TrimSpace(value))
	}
	if !validUUID(requestedID) {
		return endpointInvitationView{}, errors.New("invitation ID must be a UUID")
	}
	for _, invitation := range invitations {
		if invitation.ID == requestedID && (!pendingOnly || invitation.State == "pending") {
			return invitation, nil
		}
	}
	return endpointInvitationView{}, errors.New("pending invitation is not visible on this deployment")
}

func decideEndpointEnrollment(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, requestedID string, approve bool) error {
	output, err := fetchLoopbackJSONWithBearer[computerListOutput](ctx, client, http.MethodGet, "/v2/enrollment/computers", nil, session.Token)
	if err != nil {
		return err
	}
	if output.MaxPageSize < 1 || output.MaxPageSize > 100 || len(output.Computers) > output.MaxPageSize {
		return errors.New("server returned an invalid enrollment inventory page limit")
	}
	computer, err := selectEnrollmentComputer(output.Computers, requestedID, approve)
	if err != nil {
		return err
	}
	action := "Revoke"
	if approve {
		action = "Approve"
	}
	fmt.Fprintf(os.Stdout, "%s endpoint %q (%s, %s, epoch %d) on deployment %s?\n", action, computer.FriendlyName, computer.ID, computer.Platform, computer.EnrollmentEpoch, deployment.DeploymentID)
	confirmation := strings.ToLower(action) + " computer " + computer.ID
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("computer enrollment confirmation did not match")
	}
	pathAction := "revoke"
	expectedState := "revoked"
	if approve {
		pathAction = "approve"
		expectedState = "enrolled"
	}
	updated, err := fetchLoopbackJSONWithBearer[computerView](ctx, client, http.MethodPost, "/v2/enrollment/computers/"+computer.ID+"/"+pathAction, enrollmentDecisionInput{
		ExpectedEpoch: computer.EnrollmentEpoch,
		ConfirmID:     computer.ID,
	}, session.Token)
	if err != nil {
		return err
	}
	if updated.ID != computer.ID || updated.EnrollmentState != expectedState || updated.EnrollmentEpoch != computer.EnrollmentEpoch+1 {
		return errors.New("server did not confirm the computer enrollment decision")
	}
	fmt.Fprintf(os.Stdout, "Endpoint %s at epoch %d on deployment %s.\n", updated.EnrollmentState, updated.EnrollmentEpoch, deployment.DeploymentID)
	return nil
}

func selectEnrollmentComputer(computers []computerView, requestedID string, pendingOnly bool) (computerView, error) {
	if requestedID == "" {
		for _, computer := range computers {
			if !pendingOnly && computer.EnrollmentState != "revoked" || pendingOnly && computer.EnrollmentState == "pending" {
				fmt.Fprintf(os.Stdout, "%s  %-26q platform=%-12s state=%-10s epoch=%d\n", computer.ID, computer.FriendlyName, computer.Platform, computer.EnrollmentState, computer.EnrollmentEpoch)
			}
		}
		value, err := readPromptLine("Computer ID: ")
		if err != nil {
			return computerView{}, err
		}
		requestedID = strings.ToLower(strings.TrimSpace(value))
	}
	if !validUUID(requestedID) {
		return computerView{}, errors.New("computer ID must be a UUID")
	}
	for _, computer := range computers {
		eligible := computer.EnrollmentState != "revoked"
		if pendingOnly {
			eligible = computer.EnrollmentState == "pending"
		}
		if computer.ID == requestedID && eligible && computer.EnrollmentEpoch > 0 {
			return computer, nil
		}
	}
	return computerView{}, errors.New("computer is not eligible for this enrollment decision")
}

var _ json.Marshaler = oneTimeEnrollmentCode(nil)
