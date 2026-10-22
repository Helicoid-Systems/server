package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const maxSupportBundleBytes = 64 << 10

type supportHealth struct {
	Status                        string         `json:"status"`
	StorageSchemaVersion          uint32         `json:"storage_schema_version"`
	AcceptingAuthorizedOperations bool           `json:"accepting_authorized_operations"`
	BootstrapCompleted            bool           `json:"bootstrap_completed"`
	RecoveryQuarantined           bool           `json:"recovery_quarantined"`
	Features                      healthFeatures `json:"features"`
}

type supportInstaller struct {
	Available             bool   `json:"available"`
	State                 string `json:"state"`
	Action                string `json:"action"`
	CurrentPhase          string `json:"current_phase"`
	ServiceInstalled      bool   `json:"service_installed"`
	BootstrapReady        bool   `json:"bootstrap_ready"`
	ReadyForEnrollment    bool   `json:"server_ready_for_enrollment"`
	ResumeAvailable       bool   `json:"resume_available"`
	CancellationAvailable bool   `json:"cancellation_available"`
	PhaseCount            int    `json:"phase_count"`
}

type supportCapabilities struct {
	DeploymentKinds []string `json:"deployment_kinds"`
	NetworkScopes   []string `json:"network_scopes"`
	Actions         []string `json:"actions"`
}

type supportDoctorSummary struct {
	Available          bool  `json:"available"`
	Passed             bool  `json:"passed"`
	FailedCheckCount   int   `json:"failed_check_count"`
	HealthAvailable    bool  `json:"health_available"`
	CapabilitiesKnown  bool  `json:"capabilities_known"`
	PreflightAvailable bool  `json:"preflight_available"`
	PreflightPassed    *bool `json:"preflight_passed,omitempty"`
}

type supportBundle struct {
	SchemaVersion       uint32               `json:"schema_version"`
	Product             string               `json:"product"`
	Component           string               `json:"component"`
	CollectedAt         string               `json:"collected_at"`
	Runtime             supportRuntime       `json:"runtime"`
	Health              *supportHealth       `json:"health,omitempty"`
	Installer           *supportInstaller    `json:"installer,omitempty"`
	Capabilities        *supportCapabilities `json:"capabilities,omitempty"`
	Doctor              supportDoctorSummary `json:"doctor"`
	AuditMetadata       string               `json:"audit_metadata"`
	RecentServiceEvents supportLogSummary    `json:"recent_service_events"`
	Privacy             supportPrivacy       `json:"privacy"`
}

type supportRuntime struct {
	OS        string `json:"os"`
	Arch      string `json:"architecture"`
	GoVersion string `json:"go_version"`
}

type supportPrivacy struct {
	Excluded []string `json:"excluded"`
	Included []string `json:"included"`
}

func runSupportCommand(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("support export is available only from the Linux server TUI")
	}
	if len(args) == 0 || args[0] != "export" {
		return errors.New("usage: helicoid-server support export [--output NEW_FILE]")
	}
	flags := flag.NewFlagSet("support export", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new support bundle path; existing files are never overwritten")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: helicoid-server support export [--output NEW_FILE]")
	}
	if strings.TrimSpace(*outputPath) == "" {
		value, err := readPromptLine("New support bundle path (existing files are never overwritten): ")
		if err != nil {
			return fmt.Errorf("read support bundle path: %w", err)
		}
		*outputPath = strings.TrimSpace(value)
	}
	if *outputPath == "" {
		return errors.New("support bundle path is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	doctor := runDoctor(ctx)
	status, statusErr := loadStatus(ctx)
	bundle := buildSupportBundle(doctor, status, statusErr == nil, time.Now().UTC())
	bundle.RecentServiceEvents = supportLogSummary{
		Source: "systemd_journal", Reason: "status_unavailable", Events: []supportLogEvent{},
	}
	if statusErr == nil {
		bundle.RecentServiceEvents = collectRecentServiceEvents(ctx, status.Configuration.DeploymentKind, status.ServiceInstalled)
	}
	bundlePath, err := writeSupportBundle(*outputPath, bundle)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Redacted support bundle written to %s. Audit records and raw log lines were not included.\n", bundlePath)
	return nil
}

func buildSupportBundle(doctor doctorReport, status operationStatus, statusAvailable bool, collectedAt time.Time) supportBundle {
	bundle := supportBundle{
		SchemaVersion: 2,
		Product:       "Helicoid",
		Component:     "server",
		CollectedAt:   collectedAt.UTC().Format(time.RFC3339),
		Runtime:       supportRuntime{OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version()},
		Doctor: supportDoctorSummary{
			Available:          true,
			Passed:             doctor.OK,
			FailedCheckCount:   len(doctor.Errors),
			HealthAvailable:    doctor.Health != nil,
			CapabilitiesKnown:  doctor.Capabilities != nil,
			PreflightAvailable: doctor.Preflight != nil,
		},
		AuditMetadata: "unavailable_not_exported",
		Privacy: supportPrivacy{
			Included: []string{"allowlisted health flags", "installer state enums and phase count", "allowlisted backend capabilities", "runtime version and architecture", "diagnostic pass/fail counts", "allowlisted service event codes, severities, and UTC timestamps when available"},
			Excluded: []string{"audit records", "raw log messages and journal fields", "user and manager identities", "deployment IDs", "server addresses and hostnames", "filesystem paths", "file names and content", "database contents", "credentials, tokens, recovery material, and private keys", "raw error messages and command output"},
		},
	}
	if doctor.Health != nil {
		bundle.Health = &supportHealth{
			Status:                        allowlisted(doctor.Health.Status, "ok", "degraded", "unavailable"),
			StorageSchemaVersion:          doctor.Health.StorageSchemaVersion,
			AcceptingAuthorizedOperations: doctor.Health.AcceptingAuthorizedOperations,
			BootstrapCompleted:            doctor.Health.BootstrapCompleted,
			RecoveryQuarantined:           doctor.Health.RecoveryQuarantined,
			Features:                      doctor.Health.Features,
		}
	}
	if doctor.Capabilities != nil {
		bundle.Capabilities = &supportCapabilities{
			DeploymentKinds: allowlistedValues(doctor.Capabilities.SupportedDeploymentKinds,
				"linux_systemd", "linux_compose", "macos_launchd", "windows_service"),
			NetworkScopes: allowlistedValues(doctor.Capabilities.SupportedNetworkScopes,
				"loopback_development", "lan", "private_dns", "public_edge"),
			Actions: allowlistedValues(doctor.Capabilities.SupportedActions,
				"preflight", "plan", "install", "resume", "inspect", "update", "backup", "restore", "rollback", "remove"),
		}
	}
	if doctor.Preflight != nil {
		passed := doctor.Preflight.OK
		bundle.Doctor.PreflightPassed = &passed
	}
	if statusAvailable {
		phase := ""
		if status.CurrentPhase != nil {
			phase = allowlisted(*status.CurrentPhase, "service_user", "directories", "files", "units", "firewall", "completed", "rolled_back")
		}
		bundle.Installer = &supportInstaller{
			Available:             true,
			State:                 allowlisted(status.State, "not_installed", "in_progress", "attention_required", "completed"),
			Action:                allowlisted(status.Action, "preflight", "plan", "install", "resume", "inspect", "update", "backup", "restore", "rollback", "remove"),
			CurrentPhase:          phase,
			ServiceInstalled:      status.ServiceInstalled,
			BootstrapReady:        status.BootstrapReady,
			ReadyForEnrollment:    status.ServerReadyForEnrollment,
			ResumeAvailable:       status.ResumeAvailable,
			CancellationAvailable: status.CancellationAvailable,
			PhaseCount:            len(status.Phases),
		}
	}
	return bundle
}

func allowlisted(value string, values ...string) string {
	for _, allowed := range values {
		if value == allowed {
			return value
		}
	}
	return "unknown"
}

func allowlistedValues(values []string, allowed ...string) []string {
	set := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := set[value]; exists {
			if !containsString(result, value) {
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func writeSupportBundle(path string, bundle supportBundle) (string, error) {
	if len(path) > 4096 || strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("support bundle path is invalid or too long")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve support bundle path: %w", err)
	}
	directory := filepath.Dir(absolutePath)
	directoryInfo, err := os.Stat(directory)
	if err != nil || !directoryInfo.IsDir() {
		return "", errors.New("support bundle directory is unavailable")
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode support bundle: %w", err)
	}
	if len(data)+1 > maxSupportBundleBytes {
		return "", errors.New("support bundle exceeds the allowed size")
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(directory, ".helicoid-support-*")
	if err != nil {
		return "", fmt.Errorf("create private support bundle staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", errors.New("cannot set private support bundle permissions")
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("write support bundle: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync support bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close support bundle: %w", err)
	}
	if err := os.Link(temporaryPath, absolutePath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", errors.New("support bundle path already exists; choose a new file name")
		}
		return "", fmt.Errorf("publish support bundle without replacing existing files: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(absolutePath)
		return "", fmt.Errorf("remove support bundle staging link: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		_ = os.Remove(absolutePath)
		return "", fmt.Errorf("open support bundle directory: %w", err)
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(absolutePath)
		return "", fmt.Errorf("sync support bundle directory: %w", errors.Join(syncErr, closeErr))
	}
	return absolutePath, nil
}
