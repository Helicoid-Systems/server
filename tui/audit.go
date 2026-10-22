package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type auditEventActor struct {
	AccountID string  `json:"account_id"`
	ManagerID *string `json:"manager_id"`
}

type auditEvent struct {
	ID        string          `json:"id"`
	Actor     auditEventActor `json:"actor"`
	Action    string          `json:"action"`
	TargetIDs []string        `json:"target_ids"`
	TimeUnix  int64           `json:"time_unix"`
	Result    string          `json:"result"`
	Reason    string          `json:"reason_code"`
}

type auditEventCursor struct {
	BeforeUnix int64  `json:"before_unix"`
	BeforeID   string `json:"before_id"`
}

type auditEventList struct {
	Events     []auditEvent      `json:"events"`
	NextCursor *auditEventCursor `json:"next_cursor"`
}

type auditRetentionResponse struct {
	RetentionDays int64 `json:"retention_days"`
	UpdatedAtUnix int64 `json:"updated_at_unix"`
}

type auditRetentionUpdate struct {
	RetentionDays int64 `json:"retention_days"`
}

func runAuditCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: helicoid-server audit recent [LIMIT] | page BEFORE_UNIX BEFORE_ID [LIMIT] | retention [set DAYS]")
	}
	if args[0] == "retention" {
		return runAuditRetentionCommand(args[1:])
	}
	limit := 50
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	switch args[0] {
	case "recent":
		if len(args) > 2 {
			return errors.New("usage: helicoid-server audit recent [LIMIT]")
		}
		if len(args) == 2 {
			parsed, err := strconv.Atoi(args[1])
			if err != nil || parsed < 1 || parsed > 100 {
				return errors.New("audit event limit must be between 1 and 100")
			}
			limit = parsed
		}
	case "page":
		if len(args) != 3 && len(args) != 4 {
			return errors.New("usage: helicoid-server audit page BEFORE_UNIX BEFORE_ID [LIMIT]")
		}
		beforeUnix, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return errors.New("audit cursor time must be a nonnegative Unix timestamp")
		}
		if beforeUnix < 0 || !validAuditIdentifier(args[2]) {
			return errors.New("audit continuation cursor is invalid")
		}
		query.Set("before_unix", strconv.FormatInt(beforeUnix, 10))
		query.Set("before_id", args[2])
		if len(args) == 4 {
			parsed, err := strconv.Atoi(args[3])
			if err != nil || parsed < 1 || parsed > 100 {
				return errors.New("audit event limit must be between 1 and 100")
			}
			limit = parsed
		}
	default:
		return errors.New("usage: helicoid-server audit recent [LIMIT] | page BEFORE_UNIX BEFORE_ID [LIMIT] | retention [set DAYS]")
	}
	query.Set("limit", strconv.Itoa(limit))
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
		if !session.Account.Capabilities.ManageSecurity {
			return errors.New("security administration permission is required to read audit events")
		}
		output, err := fetchLoopbackJSONWithBearerQuery[auditEventList](ctx, client, http.MethodGet,
			"/v2/audit/events", query, nil, session.Token)
		if err != nil {
			return err
		}
		if err := validateAuditEventList(output, limit); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Recent security audit metadata on deployment %s (account %q):\n", deployment.DeploymentID, session.Account.Username)
		for _, event := range output.Events {
			managerID := "-"
			if event.Actor.ManagerID != nil {
				managerID = *event.Actor.ManagerID
			}
			targets := strings.Join(event.TargetIDs, ",")
			fmt.Fprintf(os.Stdout, "%s  action=%s result=%s reason=%s actor=%s manager=%s targets=%s event=%s\n",
				time.Unix(event.TimeUnix, 0).UTC().Format(time.RFC3339), event.Action, event.Result,
				event.Reason, event.Actor.AccountID, managerID, targets, event.ID)
		}
		if len(output.Events) == 0 {
			fmt.Fprintln(os.Stdout, "No retained audit events match this page.")
		}
		if output.NextCursor != nil {
			fmt.Fprintf(os.Stdout, "Older events are available. Continue with: helicoid-server audit page %d %s %d\n",
				output.NextCursor.BeforeUnix, output.NextCursor.BeforeID, limit)
		}
		return nil
	})
}

func runAuditRetentionCommand(args []string) error {
	if len(args) != 0 && (len(args) != 2 || args[0] != "set") {
		return errors.New("usage: helicoid-server audit retention [set DAYS]")
	}
	requestedDays := int64(0)
	if len(args) == 2 {
		parsed, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || parsed < 1 || parsed > 3650 {
			return errors.New("audit retention must be between 1 and 3650 days")
		}
		requestedDays = parsed
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
		if !session.Account.Capabilities.ManageSecurity {
			return errors.New("security administration permission is required to manage audit retention")
		}
		current, err := fetchLoopbackJSONWithBearer[auditRetentionResponse](ctx, client, http.MethodGet, "/v2/security/audit-retention", nil, session.Token)
		if err != nil {
			return err
		}
		if current.RetentionDays < 1 || current.RetentionDays > 3650 || current.UpdatedAtUnix < 0 {
			return errors.New("server returned an invalid audit-retention policy")
		}
		fmt.Fprintf(os.Stdout, "Audit retention on deployment %s: %d days (updated %s UTC).\n",
			deployment.DeploymentID, current.RetentionDays, time.Unix(current.UpdatedAtUnix, 0).UTC().Format(time.RFC3339))
		if requestedDays == 0 {
			input, err := readPromptLine("New retention days, or press Enter to keep the current policy: ")
			if err != nil {
				return err
			}
			input = strings.TrimSpace(input)
			if input == "" {
				return nil
			}
			requestedDays, err = strconv.ParseInt(input, 10, 64)
			if err != nil || requestedDays < 1 || requestedDays > 3650 {
				return errors.New("audit retention must be between 1 and 3650 days")
			}
		}
		if requestedDays == current.RetentionDays {
			fmt.Fprintln(os.Stdout, "Audit retention is unchanged.")
			return nil
		}
		confirmation := fmt.Sprintf("change audit retention to %d days", requestedDays)
		fmt.Fprintln(os.Stdout, "Shortening retention removes older events from the active audit table; backups or database free pages may retain prior bytes.")
		answer, err := readPromptLine("Type " + confirmation + " to continue: ")
		if err != nil {
			return err
		}
		if answer != confirmation {
			return errors.New("audit retention change was not confirmed")
		}
		updated, err := fetchLoopbackJSONWithBearer[auditRetentionResponse](ctx, client, http.MethodPut,
			"/v2/security/audit-retention", auditRetentionUpdate{RetentionDays: requestedDays}, session.Token)
		if err != nil {
			return err
		}
		if updated.RetentionDays != requestedDays || updated.UpdatedAtUnix < 0 {
			return errors.New("server did not confirm the requested audit-retention policy")
		}
		fmt.Fprintf(os.Stdout, "Audit retention is now %d days.\n", updated.RetentionDays)
		return nil
	})
}

func validateAuditEventList(output auditEventList, limit int) error {
	if len(output.Events) > limit {
		return errors.New("server returned more audit events than the requested page bound")
	}
	for _, event := range output.Events {
		if !validAuditIdentifier(event.ID) || !validAuditIdentifier(event.Actor.AccountID) ||
			(event.Actor.ManagerID != nil && !validAuditIdentifier(*event.Actor.ManagerID)) ||
			!validAuditCode(event.Action) || !validAuditCode(event.Reason) || event.TimeUnix < 0 ||
			(event.Result != "succeeded" && event.Result != "denied" && event.Result != "failed") ||
			len(event.TargetIDs) == 0 || len(event.TargetIDs) > 102 {
			return errors.New("server returned malformed audit metadata; refusing to display it")
		}
		for _, target := range event.TargetIDs {
			if !validAuditIdentifier(target) {
				return errors.New("server returned malformed audit target metadata; refusing to display it")
			}
		}
	}
	if output.NextCursor != nil && (output.NextCursor.BeforeUnix < 0 || !validAuditIdentifier(output.NextCursor.BeforeID)) {
		return errors.New("server returned an invalid audit continuation cursor")
	}
	return nil
}

func validAuditIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validAuditCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
