package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type computerGroupView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision int64  `json:"revision"`
}

type computerGroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type computerGroupListOutput struct {
	Groups []computerGroupView `json:"groups"`
}

type createComputerGroupInput struct {
	Name string `json:"name"`
}

type renameComputerGroupInput struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Name             string `json:"name"`
}

type setComputerGroupMembershipInput struct {
	ExpectedRevision int64 `json:"expected_revision"`
	Included         bool  `json:"included"`
}

type deleteComputerGroupInput struct {
	ExpectedRevision int64  `json:"expected_revision"`
	ConfirmGroupID   string `json:"confirm_group_id"`
}

type computerGroupCommand struct {
	action     string
	groupID    string
	computerID string
	desired    string
}

func parseComputerGroupCommand(args []string) (computerGroupCommand, error) {
	if len(args) == 0 {
		return computerGroupCommand{}, errors.New("usage: helicoid-server groups list|create|rename [GROUP_ID]|member [GROUP_ID COMPUTER_ID include|exclude]|delete [GROUP_ID]")
	}

	command := computerGroupCommand{action: args[0]}
	valid := false
	switch command.action {
	case "list", "create":
		valid = len(args) == 1
	case "rename", "delete":
		valid = len(args) == 1 || len(args) == 2 && validUUID(args[1])
		if len(args) == 2 {
			command.groupID = strings.ToLower(args[1])
		}
	case "member":
		valid = len(args) == 1 || len(args) == 4 && validUUID(args[1]) && validUUID(args[2]) && (args[3] == "include" || args[3] == "exclude")
		if len(args) == 4 {
			command.groupID = strings.ToLower(args[1])
			command.computerID = strings.ToLower(args[2])
			command.desired = args[3]
		}
	}
	if !valid {
		return computerGroupCommand{}, errors.New("usage: helicoid-server groups list|create|rename [GROUP_ID]|member [GROUP_ID COMPUTER_ID include|exclude]|delete [GROUP_ID]")
	}
	return command, nil
}

func runGroupsCommand(args []string) error {
	command, err := parseComputerGroupCommand(args)
	if err != nil {
		return err
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
			return errors.New("enrollment management permission is required to administer computer groups")
		}
		switch command.action {
		case "list":
			return listComputerGroups(ctx, client, deployment, session)
		case "create":
			return createComputerGroup(ctx, client, deployment, session)
		case "rename":
			return renameComputerGroup(ctx, client, deployment, session, command.groupID)
		case "member":
			return setComputerGroupMembership(ctx, client, deployment, session, command)
		case "delete":
			return deleteComputerGroup(ctx, client, deployment, session, command.groupID)
		default:
			return errors.New("unsupported computer group operation")
		}
	})
}

func listComputerGroups(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession) error {
	groups, err := fetchLoopbackJSONWithBearer[computerGroupListOutput](ctx, client, http.MethodGet, "/v2/groups", nil, session.Token)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Computer groups on deployment %s (membership never grants access):\n", deployment.DeploymentID)
	for _, group := range groups.Groups {
		fmt.Fprintf(os.Stdout, "%s  %-32q revision=%d\n", group.ID, group.Name, group.Revision)
	}
	if len(groups.Groups) == 0 {
		fmt.Fprintln(os.Stdout, "No computer groups are configured.")
	}
	return nil
}

func createComputerGroup(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession) error {
	name, err := readPromptLine("New group name: ")
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("computer group name is required")
	}
	fmt.Fprintf(os.Stdout, "Create group %q on deployment %s. Group membership does not grant computer access.\n", name, deployment.DeploymentID)
	answer, err := readPromptLine("Type create-group to continue: ")
	if err != nil {
		return err
	}
	if answer != "create-group" {
		return errors.New("group creation confirmation did not match")
	}
	created, err := fetchLoopbackJSONWithBearer[computerGroupView](ctx, client, http.MethodPost, "/v2/groups", createComputerGroupInput{Name: name}, session.Token)
	if err != nil {
		return err
	}
	if !validUUID(created.ID) || created.Name == "" || created.Revision != 1 {
		return errors.New("server did not confirm the new computer group")
	}
	fmt.Fprintf(os.Stdout, "Created group %q (%s), revision %d.\n", created.Name, created.ID, created.Revision)
	return nil
}

func renameComputerGroup(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, requestedID string) error {
	groups, err := loadComputerGroups(ctx, client, session)
	if err != nil {
		return err
	}
	group, err := selectComputerGroup(groups, requestedID)
	if err != nil {
		return err
	}
	name, err := readPromptLine("New group name: ")
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("computer group name is required")
	}
	fmt.Fprintf(os.Stdout, "Rename group %q (%s) to %q on deployment %s.\n", group.Name, group.ID, name, deployment.DeploymentID)
	confirmation := "rename-group " + group.ID
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("group rename confirmation did not match")
	}
	updated, err := fetchLoopbackJSONWithBearer[computerGroupView](ctx, client, http.MethodPut, "/v2/groups/"+group.ID, renameComputerGroupInput{
		ExpectedRevision: group.Revision,
		Name:             name,
	}, session.Token)
	if err != nil {
		return err
	}
	if updated.ID != group.ID || updated.Name != name || updated.Revision < group.Revision {
		return errors.New("server did not confirm the requested group rename")
	}
	fmt.Fprintf(os.Stdout, "Group renamed to %q on deployment %s at revision %d.\n", updated.Name, deployment.DeploymentID, updated.Revision)
	return nil
}

func setComputerGroupMembership(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, command computerGroupCommand) error {
	groups, err := loadComputerGroups(ctx, client, session)
	if err != nil {
		return err
	}
	group, err := selectComputerGroup(groups, command.groupID)
	if err != nil {
		return err
	}
	computers, err := fetchLoopbackJSONWithBearer[computerListOutput](ctx, client, http.MethodGet, "/v2/enrollment/computers", nil, session.Token)
	if err != nil {
		return err
	}
	if computers.MaxPageSize < 1 || computers.MaxPageSize > 100 {
		return errors.New("server returned an invalid enrollment inventory page limit")
	}
	fmt.Fprintf(os.Stdout, "Enrollment metadata on deployment %s (up to %d records; no observe access is implied):\n", deployment.DeploymentID, computers.MaxPageSize)
	for _, computer := range computers.Computers {
		fmt.Fprintf(os.Stdout, "%s  %-26q platform=%-12s enrollment=%s epoch=%d\n", computer.ID, computer.FriendlyName, computer.Platform, computer.EnrollmentState, computer.EnrollmentEpoch)
	}
	if len(computers.Computers) == 0 {
		fmt.Fprintln(os.Stdout, "No registered computers are available for enrollment administration.")
	}
	computerID := command.computerID
	if computerID == "" {
		value, err := readPromptLine("Computer ID: ")
		if err != nil {
			return err
		}
		computerID = strings.ToLower(strings.TrimSpace(value))
	}
	if !validUUID(computerID) {
		return errors.New("computer ID must be a UUID")
	}
	desired := command.desired
	if desired == "" {
		value, err := readPromptLine("Type include or exclude: ")
		if err != nil {
			return err
		}
		desired = strings.TrimSpace(value)
	}
	if desired != "include" && desired != "exclude" {
		return errors.New("membership action must be include or exclude")
	}
	included := desired == "include"
	action := "Remove"
	direction := "from"
	if included {
		action = "Add"
		direction = "to"
	}
	fmt.Fprintf(os.Stdout, "%s computer %s %s group %q on deployment %s. This changes a group label only; it does not grant access.\n", action, computerID, direction, group.Name, deployment.DeploymentID)
	confirmation := fmt.Sprintf("group-member %s %s %s", desired, group.ID, computerID)
	answer, err := readPromptLine("Type " + confirmation + " to continue: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("group membership confirmation did not match")
	}
	updated, err := fetchLoopbackJSONWithBearer[computerGroupView](ctx, client, http.MethodPut, "/v2/groups/"+group.ID+"/computers/"+computerID, setComputerGroupMembershipInput{
		ExpectedRevision: group.Revision,
		Included:         included,
	}, session.Token)
	if err != nil {
		return err
	}
	if updated.ID != group.ID || updated.Revision < group.Revision {
		return errors.New("server did not confirm the requested group membership change")
	}
	fmt.Fprintf(os.Stdout, "Group membership updated on deployment %s at revision %d. No access assignment was changed.\n", deployment.DeploymentID, updated.Revision)
	return nil
}

func deleteComputerGroup(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, requestedID string) error {
	groups, err := loadComputerGroups(ctx, client, session)
	if err != nil {
		return err
	}
	group, err := selectComputerGroup(groups, requestedID)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Delete group %q (%s, revision %d) from deployment %s and remove its labels?\n", group.Name, group.ID, group.Revision, deployment.DeploymentID)
	answer, err := readPromptLine("Type the exact group ID to delete: ")
	if err != nil {
		return err
	}
	if answer != group.ID {
		return errors.New("group ID confirmation did not match")
	}
	if err := sendLoopbackJSONWithBearer(ctx, client, http.MethodDelete, "/v2/groups/"+group.ID, deleteComputerGroupInput{
		ExpectedRevision: group.Revision,
		ConfirmGroupID:   group.ID,
	}, session.Token, http.StatusNoContent); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Deleted group %q on deployment %s. Computer records and access assignments were not changed.\n", group.Name, deployment.DeploymentID)
	return nil
}

func loadComputerGroups(ctx context.Context, client *http.Client, session *authenticatedSession) ([]computerGroupView, error) {
	groups, err := fetchLoopbackJSONWithBearer[computerGroupListOutput](ctx, client, http.MethodGet, "/v2/groups", nil, session.Token)
	if err != nil {
		return nil, err
	}
	return groups.Groups, nil
}

func selectComputerGroup(groups []computerGroupView, requestedID string) (computerGroupView, error) {
	if requestedID == "" {
		for _, group := range groups {
			fmt.Fprintf(os.Stdout, "%s  %-32q revision=%d\n", group.ID, group.Name, group.Revision)
		}
		if len(groups) == 0 {
			return computerGroupView{}, errors.New("no computer groups are configured")
		}
		value, err := readPromptLine("Group ID: ")
		if err != nil {
			return computerGroupView{}, err
		}
		requestedID = strings.ToLower(strings.TrimSpace(value))
	}
	if !validUUID(requestedID) {
		return computerGroupView{}, errors.New("group ID must be a UUID")
	}
	for _, group := range groups {
		if group.ID == requestedID && group.Revision > 0 {
			return group, nil
		}
	}
	return computerGroupView{}, errors.New("computer group is not visible on this deployment")
}

func sendLoopbackJSONWithBearer(ctx context.Context, client *http.Client, method, path string, input any, bearer string, expectedStatus int) error {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") {
		return errors.New("invalid local API path")
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return errors.New("encode local API request")
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+localAuthority+path, bytes.NewReader(payload))
	if err != nil {
		zeroBytes(payload)
		return errors.New("create local API request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := client.Do(request)
	zeroBytes(payload)
	if err != nil {
		return errors.New("local Helicoid API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("local Helicoid API returned HTTP %d", response.StatusCode)
	}
	read, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxAPIResponse+1))
	if err != nil {
		return errors.New("read local API response")
	}
	if read > maxAPIResponse {
		return errors.New("local Helicoid API response exceeded the size limit")
	}
	return nil
}
