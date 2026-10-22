package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxReviewedPlanBytes = 8 << 20

type planV2Input struct {
	ContractVersion uint32                  `json:"contract_version"`
	Configuration   deploymentConfiguration `json:"configuration"`
	Preflight       preflightResult         `json:"preflight"`
	PackageDir      string                  `json:"package_dir"`
}

type planV2Response struct {
	ContractVersion    uint32                  `json:"contract_version"`
	OK                 bool                    `json:"ok"`
	Configuration      deploymentConfiguration `json:"configuration"`
	Plan               json.RawMessage         `json:"plan"`
	ReviewedPlanDigest string                  `json:"reviewed_plan_digest"`
	Warnings           []string                `json:"warnings"`
	Error              string                  `json:"error"`
}

type reviewedInstallRequest struct {
	ContractVersion    uint32                  `json:"contract_version"`
	Configuration      deploymentConfiguration `json:"configuration"`
	Preflight          preflightResult         `json:"preflight"`
	Plan               json.RawMessage         `json:"plan"`
	ReviewedPlanDigest string                  `json:"reviewed_plan_digest"`
	Confirm            bool                    `json:"confirm"`
	PackageDir         string                  `json:"package_dir"`
	VerifyKey          string                  `json:"verify_key"`
}

func runInstallerCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: helicoid-server installer install|plan|apply|resume|cancel|remove|database-path")
	}
	switch args[0] {
	case "install":
		return runInstallerInstall(args[1:])
	case "plan":
		return runInstallerPlan(args[1:])
	case "apply":
		return runInstallerApply(args[1:])
	case "resume":
		return runInstallerResume(args[1:])
	case "cancel":
		return runInstallerCancel(args[1:])
	case "remove":
		return runInstallerRemove(args[1:])
	case "database-path":
		return runInstallerDatabasePath(args[1:])
	default:
		return fmt.Errorf("unknown installer command %q; use install, plan, apply, resume, cancel, remove, or database-path", args[0])
	}
}

func runInstallerCancel(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: helicoid-server installer cancel")
	}
	if os.Geteuid() != 0 {
		return errors.New("cancelling installation changes the local host; run this workflow from a root terminal")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
	defer cancel()
	configuration, err := loadStoredConfiguration(ctx)
	if err != nil {
		return err
	}
	var status operationStatus
	if err := callBackend(ctx, "status-v2", statusInput{
		ContractVersion: 2,
		Configuration:   configuration,
	}, &status); err != nil {
		return err
	}
	if status.OperationID == nil || !status.CancellationAvailable {
		return errors.New("the current installer operation is not cancellable")
	}
	phrase := "cancel installer operation " + *status.OperationID
	answer, err := readPromptLine("Type " + phrase + " to remove the journal-owned service resources; data and backups will be preserved: ")
	if err != nil {
		return fmt.Errorf("read cancellation confirmation: %w", err)
	}
	if answer != phrase {
		return errors.New("cancellation was not confirmed; no host changes were made")
	}
	input := struct {
		ContractVersion uint32                  `json:"contract_version"`
		Configuration   deploymentConfiguration `json:"configuration"`
		OperationID     string                  `json:"operation_id"`
		Confirm         bool                    `json:"confirm"`
	}{
		ContractVersion: 2,
		Configuration:   configuration,
		OperationID:     *status.OperationID,
		Confirm:         true,
	}
	var result operationStatus
	if err := callBackendArgs(ctx, []string{"cancel-v2", "--state-dir", "/opt/helicoid/.installer"}, input, &result); err != nil {
		return err
	}
	if err := writeJSON(os.Stdout, result); err != nil {
		return err
	}
	if result.State != "cancelled" && result.Result.Code != "cancellation_requested" {
		return fmt.Errorf("installer cancellation needs attention: %s", result.Result.Summary)
	}
	return nil
}

func runInstallerInstall(args []string) (result error) {
	if len(args) != 0 {
		return errors.New("usage: helicoid-server installer install")
	}
	if os.Geteuid() != 0 {
		return errors.New("installation changes the local host; run this workflow from a root terminal")
	}
	inputInfo, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("inspect terminal input: %w", err)
	}
	if inputInfo.Mode()&os.ModeCharDevice == 0 {
		return errors.New("interactive installation requires a terminal")
	}

	packageInput, err := readPromptLine("Path to extracted signed Linux package: ")
	if err != nil {
		return fmt.Errorf("read package path: %w", err)
	}
	packageInput = strings.TrimSpace(packageInput)
	if packageInput == "" {
		return errors.New("package path is required")
	}
	packageDir, err := filepath.Abs(packageInput)
	if err != nil {
		return fmt.Errorf("resolve package path: %w", err)
	}
	packageInfo, err := os.Stat(packageDir)
	if err != nil {
		return fmt.Errorf("inspect package directory: %w", err)
	}
	if !packageInfo.IsDir() {
		return errors.New("package path must identify an extracted package directory")
	}

	verifyKey, err := readPromptLine("Trusted release verification key (64 hex characters): ")
	if err != nil {
		return fmt.Errorf("read package verification key: %w", err)
	}
	verifyKey = strings.TrimSpace(verifyKey)
	if err := validateVerifyKey(verifyKey); err != nil {
		return err
	}

	configuration := defaultInstallConfiguration()
	deploymentKind, err := readPromptLine("Deployment kind [linux_systemd/linux_compose] (default linux_systemd): ")
	if err != nil {
		return fmt.Errorf("read deployment kind: %w", err)
	}
	if strings.TrimSpace(deploymentKind) != "" {
		configuration.DeploymentKind = strings.TrimSpace(deploymentKind)
	}
	if configuration.DeploymentKind != "linux_systemd" && configuration.DeploymentKind != "linux_compose" {
		return errors.New("deployment kind must be linux_systemd or linux_compose")
	}
	scope, err := readPromptLine("Network scope [lan/private_dns/loopback_development] (default lan): ")
	if err != nil {
		return fmt.Errorf("read network scope: %w", err)
	}
	if strings.TrimSpace(scope) != "" {
		configuration.Network.Scope = strings.TrimSpace(scope)
	}
	switch configuration.Network.Scope {
	case "lan", "private_dns":
		bindAddress, promptErr := readPromptLine("Private LAN IP assigned to this host: ")
		if promptErr != nil {
			return fmt.Errorf("read LAN bind address: %w", promptErr)
		}
		configuration.Network.BindAddress = strings.TrimSpace(bindAddress)
		hostnamePrompt := "Manager DNS hostname (optional): "
		if configuration.Network.Scope == "private_dns" {
			hostnamePrompt = "Required private DNS hostname used by Managers: "
		}
		clientHostname, promptErr := readPromptLine(hostnamePrompt)
		if promptErr != nil {
			return fmt.Errorf("read Manager DNS hostname: %w", promptErr)
		}
		configuration.Network.ClientHostname = strings.TrimSpace(clientHostname)
		fmt.Fprintln(os.Stdout, "Provide a root-owned certificate chain and matching private key before continuing:")
		fmt.Fprintln(os.Stdout, "  /etc/ssl/helicoid/fullchain.pem")
		fmt.Fprintln(os.Stdout, "  /etc/ssl/helicoid/private-key.pem")
		fmt.Fprintln(os.Stdout, "Keep /etc/ssl/helicoid root-owned mode 0700 and both files root-owned mode 0600.")
		if configuration.Network.ClientHostname != "" {
			fmt.Fprintf(os.Stdout, "Create private DNS for %s pointing to %s and include that name in the certificate DNS SAN; preflight checks the name.\n", configuration.Network.ClientHostname, configuration.Network.BindAddress)
			if configuration.Network.Scope == "private_dns" {
				fmt.Fprintf(os.Stdout, "If using a proxy, forward HTTPS for %s to %s:%d with certificate validation and the hostname preserved.\n", configuration.Network.ClientHostname, configuration.Network.BindAddress, configuration.Network.AuthorityPort)
			}
		} else {
			fmt.Fprintf(os.Stdout, "Include the bind IP %s in the certificate IP SAN; preflight checks the name.\n", configuration.Network.BindAddress)
		}
		fmt.Fprintln(os.Stdout, "Manager clients must trust the certificate's issuing CA; preflight does not check client trust.")
		fmt.Fprintf(os.Stdout, "Allow TCP %d only from trusted Manager client networks; no UDP listener is required.\n", configuration.Network.AuthorityPort)
		fmt.Fprintln(os.Stdout, "The installer will not change DNS, firewall, proxy, certificate renewal, or existing service configuration.")
	case "loopback_development":
		configuration.Network = networkConfiguration{Scope: "loopback_development", AuthorityPort: 8787}
	default:
		return errors.New("network scope must be lan, private_dns, or loopback_development")
	}
	dataDirectory, err := readPromptLine(fmt.Sprintf("Data directory [%s]: ", configuration.Storage.DataDirectory))
	if err != nil {
		return fmt.Errorf("read data directory: %w", err)
	}
	if strings.TrimSpace(dataDirectory) != "" {
		configuration.Storage.DataDirectory = strings.TrimSpace(dataDirectory)
	}
	backupDirectory, err := readPromptLine(fmt.Sprintf("Backup directory [%s]: ", configuration.Storage.BackupDirectory))
	if err != nil {
		return fmt.Errorf("read backup directory: %w", err)
	}
	if strings.TrimSpace(backupDirectory) != "" {
		configuration.Storage.BackupDirectory = strings.TrimSpace(backupDirectory)
	}
	if err := validateDeploymentConfiguration(configuration); err != nil {
		return fmt.Errorf("invalid deployment configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
	var preflight preflightResult
	err = callBackend(ctx, "preflight-v2", preflightInput{
		ContractVersion: 2,
		Configuration:   configuration,
	}, &preflight)
	cancel()
	if err != nil {
		return fmt.Errorf("run local host preflight: %w", err)
	}
	if preflight.ContractVersion != 2 || preflight.Configuration != configuration {
		return errors.New("installer backend returned a mismatched preflight contract")
	}
	if !preflight.OK {
		var checks bytes.Buffer
		if err := json.Indent(&checks, preflight.HostChecks, "", "  "); err != nil {
			return fmt.Errorf("host preflight failed and its checks could not be displayed: %w", err)
		}
		fmt.Fprintln(os.Stdout, "Host preflight did not pass; no changes were made.")
		fmt.Fprintln(os.Stdout, checks.String())
		for _, item := range []struct {
			label string
			raw   json.RawMessage
		}{
			{"Docker Compose runtime", preflight.DockerComposeRuntime},
			{"Lifecycle capabilities", preflight.Capabilities},
		} {
			if len(item.raw) == 0 {
				continue
			}
			var details bytes.Buffer
			if err := json.Indent(&details, item.raw, "", "  "); err == nil {
				fmt.Fprintf(os.Stdout, "%s:\n%s\n", item.label, details.String())
			}
		}
		return errors.New("resolve the reported host checks, then run installer install again")
	}

	ctx, cancel = context.WithTimeout(context.Background(), backendTimeout*2)
	var plan planV2Response
	err = callBackendArgs(ctx, []string{
		"plan-v2", "--package-dir", packageDir, "--verify-key", verifyKey,
	}, planV2Input{
		ContractVersion: 2,
		Configuration:   configuration,
		Preflight:       preflight,
		PackageDir:      packageDir,
	}, &plan)
	cancel()
	if err != nil {
		return fmt.Errorf("verify package and create reviewed plan: %w", err)
	}
	if plan.ContractVersion != 2 || plan.Configuration != configuration {
		return errors.New("installer backend returned a mismatched plan contract")
	}
	if !plan.OK || len(plan.Plan) == 0 || plan.ReviewedPlanDigest == "" {
		if plan.Error != "" {
			return fmt.Errorf("installer backend refused the plan: %s", plan.Error)
		}
		return errors.New("installer backend returned no applicable reviewed plan")
	}

	request := reviewedInstallRequest{
		ContractVersion:    2,
		Configuration:      configuration,
		Preflight:          preflight,
		Plan:               plan.Plan,
		ReviewedPlanDigest: plan.ReviewedPlanDigest,
		PackageDir:         packageDir,
		VerifyKey:          verifyKey,
	}
	if err := validateReviewedRequest(request); err != nil {
		return fmt.Errorf("validate reviewed installer request: %w", err)
	}
	encoded, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("encode reviewed installer request: %w", err)
	}
	reviewPath, err := writePersistentReview(encoded)
	if err != nil {
		return err
	}
	keepReview := false
	defer func() {
		if !keepReview {
			if removeErr := os.Remove(reviewPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("remove unconfirmed reviewed request: %w", removeErr))
			}
		}
	}()

	var reviewedPlan bytes.Buffer
	if err := json.Indent(&reviewedPlan, plan.Plan, "", "  "); err != nil {
		return fmt.Errorf("format reviewed plan: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Signed package verified. Review the proposed %s installation:\n", configuration.DeploymentKind)
	fmt.Fprintln(os.Stdout, reviewedPlan.String())
	fmt.Fprintf(os.Stdout, "Reviewed plan digest: %s\n", plan.ReviewedPlanDigest)
	fmt.Fprintf(os.Stdout, "Data: %s\nBackups: %s\n", configuration.Storage.DataDirectory, configuration.Storage.BackupDirectory)
	for _, warning := range plan.Warnings {
		fmt.Fprintf(os.Stdout, "Warning: %s\n", warning)
	}
	confirmation, err := readPromptLine("Type install helicoid server to apply this plan: ")
	if err != nil {
		return fmt.Errorf("read installation confirmation: %w", err)
	}
	if confirmation != "install helicoid server" {
		return errors.New("installation was not confirmed; no host changes were made")
	}

	request.Confirm = true
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Minute)
	var status operationStatus
	err = callBackendArgs(ctx, []string{
		"apply-v2", "--state-dir", "/opt/helicoid/.installer",
	}, request, &status)
	cancel()
	if err != nil {
		keepReview = true
		fmt.Fprintf(os.Stderr, "The reviewed request is retained at %s for inspection or resume.\n", reviewPath)
		return fmt.Errorf("apply reviewed installation: %w", err)
	}
	if err := writeJSON(os.Stdout, status); err != nil {
		keepReview = true
		return fmt.Errorf("write installation result; reviewed request retained at %s: %w", reviewPath, err)
	}
	if status.State != "completed" {
		keepReview = true
		fmt.Fprintf(os.Stderr, "The reviewed request is retained at %s. Resume with: sudo helicoid-server installer resume --request %s --confirm\n", reviewPath, reviewPath)
		return fmt.Errorf("installer operation %s ended in state %s", optionalText(status.OperationID), status.State)
	}
	return nil
}

func writePersistentReview(content []byte) (path string, result error) {
	return writePrivateReviewInDir("/var/tmp", content)
}

func writePrivateReviewInDir(directory string, content []byte) (path string, result error) {
	file, err := os.CreateTemp(directory, "helicoid-reviewed-*.json")
	if err != nil {
		return "", fmt.Errorf("create private reviewed request: %w", err)
	}
	path = file.Name()
	keep := false
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); closeErr != nil {
				result = errors.Join(result, fmt.Errorf("close reviewed request: %w", closeErr))
			}
		}
		if !keep {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("remove incomplete reviewed request: %w", removeErr))
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("restrict reviewed request permissions: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		return "", fmt.Errorf("write reviewed request: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync reviewed request: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close reviewed request: %w", err)
	}
	closed = true
	keep = true
	return path, nil
}

func runInstallerDatabasePath(args []string) error {
	flags := flag.NewFlagSet("installer database-path", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: helicoid-server installer database-path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
	defer cancel()
	var configuration *deploymentConfiguration
	if err := callBackendArgs(ctx, []string{
		"configuration-v2", "--state-dir", "/opt/helicoid/.installer",
	}, nil, &configuration); err != nil {
		return err
	}
	if configuration == nil {
		return errors.New("no durable v2 deployment configuration is recorded")
	}
	if err := validateDeploymentConfiguration(*configuration); err != nil {
		return fmt.Errorf("stored installer configuration: %w", err)
	}
	if _, err := fmt.Fprintln(os.Stdout, filepath.Join(configuration.Storage.DataDirectory, "hs-server.db")); err != nil {
		return fmt.Errorf("write database path: %w", err)
	}
	return nil
}

func runInstallerRemove(args []string) error {
	flags := flag.NewFlagSet("installer remove", flag.ContinueOnError)
	confirm := flags.Bool("confirm", false, "confirm removing the journaled Helicoid service resources")
	deleteData := flags.Bool("delete-data", false, "also remove the configured data and backup directories")
	confirmDeleteData := flags.Bool("confirm-delete-data", false, "confirm permanent deletion of server data and backups")
	dataDirectory := flags.String("data-dir", "", "override the recorded Helicoid data directory")
	backupDirectory := flags.String("backup-dir", "", "override the recorded Helicoid backup directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*confirm {
		return errors.New("usage: helicoid-server installer remove --confirm [--data-dir DIR] [--backup-dir DIR] [--delete-data --confirm-delete-data]")
	}
	if *deleteData && !*confirmDeleteData {
		return errors.New("--delete-data also requires --confirm-delete-data; data and backups are preserved by default")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	configuration, err := loadStoredConfiguration(ctx)
	if err != nil {
		return err
	}
	if *dataDirectory != "" {
		configuration.Storage.DataDirectory = *dataDirectory
	}
	if *backupDirectory != "" {
		configuration.Storage.BackupDirectory = *backupDirectory
	}
	configuration.Storage.PreserveDataOnRemoval = !*deleteData
	if err := validateDeploymentConfiguration(configuration); err != nil {
		return err
	}
	request := removeV2Input{ContractVersion: 2, Configuration: configuration, Confirm: true}
	var result operationStatus
	if err := callBackendArgs(ctx, []string{
		"remove-v2", "--state-dir", "/opt/helicoid/.installer",
	}, request, &result); err != nil {
		return err
	}
	if err := writeJSON(os.Stdout, result); err != nil {
		return err
	}
	if result.State != "completed" && result.State != "not_installed" {
		return fmt.Errorf("removal operation %s ended in state %s", optionalText(result.OperationID), result.State)
	}
	return nil
}

func runInstallerPlan(args []string) error {
	flags := flag.NewFlagSet("installer plan", flag.ContinueOnError)
	packageDir := flags.String("package-dir", "", "path to the extracted signed server package")
	verifyKey := flags.String("verify-key", "", "trusted Ed25519 package verification key in hex")
	outputPath := flags.String("output", "", "new file to write the reviewed apply request")
	deploymentKind := flags.String("deployment-kind", "linux_systemd", "deployment kind: linux_systemd or linux_compose")
	dataDirectory := flags.String("data-dir", defaultConfiguration().Storage.DataDirectory, "Helicoid data directory")
	backupDirectory := flags.String("backup-dir", defaultConfiguration().Storage.BackupDirectory, "Helicoid backup directory")
	scope := flags.String("scope", "lan", "network scope: lan, private_dns, or loopback_development")
	bindAddress := flags.String("bind-address", "", "private IP assigned to this host (required for lan and private_dns)")
	clientHostname := flags.String("client-hostname", "", "private DNS hostname used by Manager clients (required for private_dns)")
	authorityPort := flags.Int("port", 8920, "HTTPS authority port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *packageDir == "" || *verifyKey == "" || *outputPath == "" {
		return errors.New("usage: helicoid-server installer plan --package-dir DIR --verify-key HEX --output NEW_FILE [--deployment-kind linux_systemd|linux_compose] [--scope lan|private_dns --bind-address IP --client-hostname DNS_NAME --port 8920] [--data-dir DIR] [--backup-dir DIR]")
	}
	configuration := defaultInstallConfiguration()
	if *deploymentKind != "linux_systemd" && *deploymentKind != "linux_compose" {
		return errors.New("--deployment-kind must be linux_systemd or linux_compose")
	}
	configuration.DeploymentKind = *deploymentKind
	switch *scope {
	case "lan", "private_dns":
		if *authorityPort < 1 || *authorityPort > 65535 {
			return errors.New("--port must be between 1 and 65535")
		}
		configuration.Network.Scope = *scope
		configuration.Network.AuthorityPort = uint16(*authorityPort)
		configuration.Network.BindAddress = *bindAddress
		configuration.Network.ClientHostname = strings.TrimSpace(*clientHostname)
	case "loopback_development":
		if *bindAddress != "" || *clientHostname != "" || (*authorityPort != 8920 && *authorityPort != 8787) {
			return errors.New("loopback_development does not accept --bind-address, --client-hostname, or a custom LAN --port")
		}
		configuration.Network = networkConfiguration{Scope: "loopback_development", AuthorityPort: 8787}
	default:
		return errors.New("--scope must be lan, private_dns, or loopback_development")
	}
	configuration.Storage.DataDirectory = *dataDirectory
	configuration.Storage.BackupDirectory = *backupDirectory
	if err := validateDeploymentConfiguration(configuration); err != nil {
		return err
	}
	if err := validateVerifyKey(*verifyKey); err != nil {
		return err
	}
	absolutePackageDir, err := filepath.Abs(*packageDir)
	if err != nil {
		return fmt.Errorf("resolve package directory: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), backendTimeout*2)
	defer cancel()
	var preflight preflightResult
	if err := callBackend(ctx, "preflight-v2", preflightInput{
		ContractVersion: 2,
		Configuration:   configuration,
	}, &preflight); err != nil {
		return err
	}
	if preflight.ContractVersion != 2 || preflight.Configuration != configuration {
		return errors.New("installer backend returned a mismatched preflight contract")
	}
	if !preflight.OK {
		return errors.New("host preflight did not pass; no installation plan was created")
	}
	var plan planV2Response
	if err := callBackendArgs(ctx, []string{
		"plan-v2", "--package-dir", absolutePackageDir, "--verify-key", *verifyKey,
	}, planV2Input{
		ContractVersion: 2,
		Configuration:   configuration,
		Preflight:       preflight,
		PackageDir:      absolutePackageDir,
	}, &plan); err != nil {
		return err
	}
	if !plan.OK || len(plan.Plan) == 0 || plan.ReviewedPlanDigest == "" {
		if plan.Error != "" {
			return fmt.Errorf("installer backend refused the plan: %s", plan.Error)
		}
		return errors.New("installer backend returned no applicable reviewed plan")
	}
	request := reviewedInstallRequest{
		ContractVersion:    2,
		Configuration:      configuration,
		Preflight:          preflight,
		Plan:               plan.Plan,
		ReviewedPlanDigest: plan.ReviewedPlanDigest,
		PackageDir:         absolutePackageDir,
		VerifyKey:          *verifyKey,
	}
	encoded, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("encode reviewed installer request: %w", err)
	}
	if err := writeNewPrivateFile(*outputPath, encoded); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Reviewed plan written to %s\n", *outputPath)
	fmt.Fprintf(os.Stdout, "Reviewed plan digest: %s\n", plan.ReviewedPlanDigest)
	for _, warning := range plan.Warnings {
		fmt.Fprintf(os.Stdout, "Warning: %s\n", warning)
	}
	fmt.Fprintln(os.Stdout, "Inspect that file before running installer apply --confirm.")
	return nil
}

func runInstallerApply(args []string) error {
	flags := flag.NewFlagSet("installer apply", flag.ContinueOnError)
	requestPath := flags.String("request", "", "reviewed request file created by installer plan")
	confirm := flags.Bool("confirm", false, "confirm the exact reviewed plan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *requestPath == "" || !*confirm {
		return errors.New("usage: helicoid-server installer apply --request FILE --confirm")
	}
	request, err := readReviewedInstallRequest(*requestPath)
	if err != nil {
		return err
	}
	if err := validateReviewedRequest(request); err != nil {
		return err
	}
	request.Confirm = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var result operationStatus
	if err := callBackendArgs(ctx, []string{"apply-v2", "--state-dir", "/opt/helicoid/.installer"}, request, &result); err != nil {
		return err
	}
	if err := writeJSON(os.Stdout, result); err != nil {
		return err
	}
	if result.State != "completed" {
		return fmt.Errorf("installer operation %s ended in state %s", optionalText(result.OperationID), result.State)
	}
	return nil
}

func runInstallerResume(args []string) error {
	if len(args) == 0 {
		return runInstallerResumeInteractively()
	}
	if os.Geteuid() != 0 {
		return errors.New("resuming installation changes the local host; run this workflow from a root terminal")
	}
	flags := flag.NewFlagSet("installer resume", flag.ContinueOnError)
	requestPath := flags.String("request", "", "same reviewed request file used by the interrupted install")
	confirm := flags.Bool("confirm", false, "confirm resuming the existing journaled operation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *requestPath == "" || !*confirm {
		return errors.New("usage: helicoid-server installer resume --request FILE --confirm")
	}
	request, err := readReviewedInstallRequest(*requestPath)
	if err != nil {
		return err
	}
	if err := validateReviewedRequest(request); err != nil {
		return err
	}
	request.Confirm = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var result operationStatus
	if err := callBackendArgs(ctx, []string{"resume-v2", "--state-dir", "/opt/helicoid/.installer"}, request, &result); err != nil {
		return err
	}
	if err := writeJSON(os.Stdout, result); err != nil {
		return err
	}
	if result.State != "completed" {
		return fmt.Errorf("installer operation %s ended in state %s", optionalText(result.OperationID), result.State)
	}
	return nil
}

func runInstallerResumeInteractively() error {
	if os.Geteuid() != 0 {
		return errors.New("resuming installation changes the local host; run this workflow from a root terminal")
	}
	requestPath, err := readPromptLine("Path to the retained reviewed request: ")
	if err != nil {
		return fmt.Errorf("read reviewed request path: %w", err)
	}
	requestPath = strings.TrimSpace(requestPath)
	if requestPath == "" {
		return errors.New("reviewed request path is required")
	}
	confirmation, err := readPromptLine("Type resume helicoid server to continue the journaled operation: ")
	if err != nil {
		return fmt.Errorf("read resume confirmation: %w", err)
	}
	if confirmation != "resume helicoid server" {
		return errors.New("resume was not confirmed; no host changes were made")
	}
	return runInstallerResume([]string{"--request", requestPath, "--confirm"})
}

func validateReviewedRequest(request reviewedInstallRequest) error {
	if request.ContractVersion != 2 ||
		len(request.Plan) == 0 || request.ReviewedPlanDigest == "" || request.PackageDir == "" {
		return errors.New("reviewed request is incomplete or uses unsupported installer configuration")
	}
	if err := validateDeploymentConfiguration(request.Configuration); err != nil {
		return fmt.Errorf("reviewed request configuration: %w", err)
	}
	if request.Preflight.ContractVersion != 2 || request.Preflight.Configuration != request.Configuration ||
		!request.Preflight.OK || len(request.Preflight.HostChecks) == 0 {
		return errors.New("reviewed request does not contain a passing preflight for its configuration")
	}
	if (request.Configuration.Network.Scope == "lan" || request.Configuration.Network.Scope == "private_dns") && request.Preflight.TLSCertificateSHA256 == "" {
		return errors.New("reviewed LAN/private DNS request is missing the validated TLS certificate digest")
	}
	return validateVerifyKey(request.VerifyKey)
}

func validateDeploymentConfiguration(configuration deploymentConfiguration) error {
	if configuration.DeploymentKind != "linux_systemd" && configuration.DeploymentKind != "linux_compose" {
		return errors.New("installer supports linux_systemd and linux_compose deployments")
	}
	switch configuration.Network.Scope {
	case "loopback_development":
		if configuration.Network.AuthorityPort != 8787 || configuration.Network.BindAddress != "" || configuration.Network.ClientHostname != "" {
			return errors.New("loopback_development requires port 8787 and no bind address or client hostname")
		}
	case "lan", "private_dns":
		if configuration.Network.AuthorityPort < 1024 || configuration.Network.AuthorityPort == 8787 || configuration.Network.BindAddress == "" {
			return errors.New("lan and private_dns require a private bind address and an unprivileged port other than 8787")
		}
		ip := net.ParseIP(configuration.Network.BindAddress)
		if ip == nil || !ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("lan and private_dns bind address must be an RFC1918 IPv4 or unique-local IPv6 literal")
		}
		if configuration.Network.Scope == "private_dns" && configuration.Network.ClientHostname == "" {
			return errors.New("private_dns requires a Manager client hostname")
		}
		if configuration.Network.ClientHostname != "" && !validClientHostname(configuration.Network.ClientHostname) {
			return errors.New("lan and private_dns client hostname must be a DNS hostname, not an IP address or localhost name")
		}
	default:
		return errors.New("installer supports network scopes lan, private_dns, and loopback_development")
	}
	if err := validateOwnedStoragePath(configuration.Storage.DataDirectory,
		[]string{"/var/lib/helicoid/data"}, "data"); err != nil {
		return err
	}
	if err := validateOwnedStoragePath(configuration.Storage.BackupDirectory,
		[]string{"/var/lib/helicoid/backups", "/var/backups/helicoid"}, "backup"); err != nil {
		return err
	}
	if storagePathsOverlap(configuration.Storage.DataDirectory, configuration.Storage.BackupDirectory) {
		return errors.New("data and backup directories cannot overlap")
	}
	return nil
}

func validClientHostname(hostname string) bool {
	lowercase := strings.ToLower(hostname)
	if len(hostname) == 0 || len(hostname) > 253 || net.ParseIP(hostname) != nil ||
		lowercase == "localhost" || strings.HasSuffix(lowercase, ".localhost") ||
		!strings.ContainsAny(hostname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if !isASCIIAlphaNumeric(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func validateOwnedStoragePath(path string, roots []string, label string) error {
	if len(path) == 0 || len(path) > 512 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s directory must be a normalized absolute path", label)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("%s directory must not contain empty or traversal segments", label)
		}
		for _, character := range segment {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
				return fmt.Errorf("%s directory contains an unsupported path character", label)
			}
		}
	}
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return nil
		}
	}
	return fmt.Errorf("%s directory must remain inside a Helicoid-owned storage root", label)
}

func storagePathsOverlap(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+string(filepath.Separator)) ||
		strings.HasPrefix(second, first+string(filepath.Separator))
}

func validateVerifyKey(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("trusted package verification key must be exactly 32 bytes encoded as hex")
	}
	return nil
}

func readReviewedInstallRequest(path string) (reviewedInstallRequest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return reviewedInstallRequest{}, fmt.Errorf("inspect reviewed request: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxReviewedPlanBytes {
		return reviewedInstallRequest{}, errors.New("reviewed request must be a regular file within the allowed size")
	}
	file, err := os.Open(path)
	if err != nil {
		return reviewedInstallRequest{}, fmt.Errorf("open reviewed request: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return reviewedInstallRequest{}, errors.New("reviewed request changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxReviewedPlanBytes+1))
	if err != nil {
		return reviewedInstallRequest{}, fmt.Errorf("read reviewed request: %w", err)
	}
	if len(body) > maxReviewedPlanBytes {
		return reviewedInstallRequest{}, errors.New("reviewed request exceeds the allowed size")
	}
	var request reviewedInstallRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return reviewedInstallRequest{}, fmt.Errorf("decode reviewed request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return reviewedInstallRequest{}, errors.New("reviewed request contains trailing data")
	}
	return request, nil
}

func writeNewPrivateFile(path string, content []byte) (result error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create reviewed request without overwriting existing files: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); result == nil && closeErr != nil {
			result = fmt.Errorf("close reviewed request: %w", closeErr)
		}
		if result != nil {
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("remove partial reviewed request: %w", removeErr))
			}
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write reviewed request: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync reviewed request: %w", err)
	}
	return nil
}
