package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"charm.land/log/v2"
)

func main() {
	logger := log.New(os.Stderr)
	if err := run(os.Args[1:]); err != nil {
		logger.Error("helicoid-server failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return runTUI()
	}
	switch args[0] {
	case "status":
		return runStatus(args[1:])
	case "doctor":
		return runDoctorCommand(args[1:])
	case "bootstrap":
		return runBootstrapCommand(args[1:])
	case "recovery":
		return runRecoveryCommand(args[1:])
	case "cutover":
		return runCutoverCommand(args[1:])
	case "mfa":
		return runMFACommand(args[1:])
	case "accounts":
		return runAccountsCommand(args[1:])
	case "computers":
		return runComputersCommand(args[1:])
	case "enrollment":
		return runComputerEnrollmentCommand(args[1:])
	case "groups":
		return runGroupsCommand(args[1:])
	case "managers":
		return runManagersCommand(args[1:])
	case "files":
		return runFilesCommand(args[1:])
	case "support":
		return runSupportCommand(args[1:])
	case "logs":
		return runLogsCommand(args[1:])
	case "audit":
		return runAuditCommand(args[1:])
	case "installer":
		return runInstallerCommand(args[1:])
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q; use --help", args[0])
	}
}

func runStatus(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write the operation status as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*jsonOutput {
		return errors.New("usage: helicoid-server status --json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
	defer cancel()
	status, err := loadStatus(ctx)
	if err != nil {
		if writeErr := writeJSON(os.Stdout, map[string]any{"ok": false, "error": err.Error()}); writeErr != nil {
			return writeErr
		}
		return err
	}
	return writeJSON(os.Stdout, status)
}

func runDoctorCommand(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write capability and local preflight results as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*jsonOutput {
		return errors.New("usage: helicoid-server doctor --json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
	defer cancel()
	report := runDoctor(ctx)
	if err := writeJSON(os.Stdout, report); err != nil {
		return err
	}
	if !report.OK {
		return errors.New("doctor reported unavailable or failed checks")
	}
	return nil
}

func writeJSON(writer *os.File, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON response: %w", err)
	}
	return nil
}

func printUsage(writer *os.File) {
	fmt.Fprintln(writer, "Usage: helicoid-server [status --json | doctor --json | logs recent | audit recent [LIMIT] | audit page BEFORE_UNIX BEFORE_ID [LIMIT] | audit retention [set DAYS] | support export [--output NEW_FILE] | bootstrap | recovery status|release-quarantine | cutover status|drain|approve|cancel | mfa confirm ENROLLMENT_ID|recover | accounts COMMAND | computers list|enrollment-list | enrollment COMMAND | groups COMMAND | managers COMMAND | files storage|jobs | files cancel [JOB_ID] | files requests list|create|publish [REQUEST_ID]|close [REQUEST_ID]|submissions [REQUEST_ID]|download [REQUEST_ID]|delete-submission [REQUEST_ID] | installer install|plan|apply|resume|remove|database-path]")
	fmt.Fprintln(writer, "Accounts: list, create, capabilities [ACCOUNT_ID], state [ACCOUNT_ID active|disabled], access list|grant|revoke [ASSIGNMENT_ID], mfa-policy [optional|required]")
	fmt.Fprintln(writer, "Groups: list, create, rename [GROUP_ID], member [GROUP_ID COMPUTER_ID include|exclude], delete [GROUP_ID]")
	fmt.Fprintln(writer, "Enrollment: invitations, invite, approve [COMPUTER_ID], revoke [COMPUTER_ID], revoke-invitation [INVITATION_ID]")
	fmt.Fprintln(writer, "Managers: list, approve [MANAGER_ID], revoke [MANAGER_ID]")
	fmt.Fprintln(writer, "Files: jobs, cancel [JOB_ID], requests list, create, publish [REQUEST_ID], close [REQUEST_ID], submissions [REQUEST_ID], download [REQUEST_ID], delete-submission [REQUEST_ID]")
	fmt.Fprintln(writer, "Installer commands: install, plan [--data-dir DIR --backup-dir DIR], apply, resume, remove [--data-dir DIR --backup-dir DIR], database-path.")
	fmt.Fprintln(writer, "With no command, open the interactive server management TUI.")
}
