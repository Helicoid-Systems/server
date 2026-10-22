package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxBackendOutput = 1 << 20
	maxHealthOutput  = 64 << 10
	backendTimeout   = 15 * time.Second
)

type deploymentConfiguration struct {
	DeploymentKind string               `json:"deployment_kind"`
	Network        networkConfiguration `json:"network"`
	Storage        storageConfiguration `json:"storage"`
}

type networkConfiguration struct {
	Scope          string `json:"scope"`
	AuthorityPort  uint16 `json:"authority_port"`
	BindAddress    string `json:"bind_address,omitempty"`
	ClientHostname string `json:"client_hostname,omitempty"`
}

type storageConfiguration struct {
	DataDirectory         string `json:"data_directory"`
	BackupDirectory       string `json:"backup_directory"`
	PreserveDataOnRemoval bool   `json:"preserve_data_on_remove"`
}

type statusInput struct {
	ContractVersion uint32                  `json:"contract_version"`
	Configuration   deploymentConfiguration `json:"configuration"`
}

type preflightInput struct {
	ContractVersion uint32                  `json:"contract_version"`
	Configuration   deploymentConfiguration `json:"configuration"`
}

type operationResult struct {
	Code     string   `json:"code"`
	Summary  string   `json:"summary"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

type operationStatus struct {
	ContractVersion          uint32                  `json:"contract_version"`
	Configuration            deploymentConfiguration `json:"configuration"`
	OperationID              *string                 `json:"operation_id"`
	Action                   string                  `json:"action"`
	State                    string                  `json:"state"`
	CurrentPhase             *string                 `json:"current_phase"`
	CancellationAvailable    bool                    `json:"cancellation_available"`
	ResumeAvailable          bool                    `json:"resume_available"`
	ServiceInstalled         bool                    `json:"service_installed"`
	BootstrapReady           bool                    `json:"bootstrap_ready"`
	ServerReadyForEnrollment bool                    `json:"server_ready_for_enrollment"`
	Result                   operationResult         `json:"result"`
	Phases                   map[string]string       `json:"phases"`
}

type removeV2Input struct {
	ContractVersion uint32                  `json:"contract_version"`
	Configuration   deploymentConfiguration `json:"configuration"`
	Confirm         bool                    `json:"confirm"`
}

type capabilities struct {
	ContractVersion          uint32            `json:"contract_version"`
	SupportedDeploymentKinds []string          `json:"supported_deployment_kinds"`
	SupportedNetworkScopes   []string          `json:"supported_network_scopes"`
	SupportedActions         []string          `json:"supported_actions"`
	CustomStorageDirectories bool              `json:"custom_storage_directories"`
	DurableOperationJournal  bool              `json:"durable_operation_journal"`
	Cancellation             bool              `json:"cancellation"`
	OnlineUpdate             bool              `json:"online_update"`
	BackupAndRestore         bool              `json:"backup_and_restore"`
	PublicEdgeIntegration    bool              `json:"public_edge_integration"`
	ReasonsUnavailable       map[string]string `json:"reasons_unavailable"`
}

type preflightResult struct {
	ContractVersion        uint32                  `json:"contract_version"`
	Configuration          deploymentConfiguration `json:"configuration"`
	OK                     bool                    `json:"ok"`
	HostChecks             json.RawMessage         `json:"host_checks"`
	TLSCertificateSHA256   string                  `json:"tls_certificate_sha256,omitempty"`
	TLSSubjectNameVerified bool                    `json:"tls_subject_name_verified"`
	DockerComposeRuntime   json.RawMessage         `json:"docker_compose_runtime,omitempty"`
	Capabilities           json.RawMessage         `json:"capabilities"`
}

type doctorReport struct {
	SchemaVersion uint32           `json:"schema_version"`
	OK            bool             `json:"ok"`
	Health        *healthReport    `json:"health,omitempty"`
	Capabilities  *capabilities    `json:"capabilities,omitempty"`
	Preflight     *preflightResult `json:"preflight,omitempty"`
	Errors        []string         `json:"errors"`
}

type healthFeatures struct {
	LocalAccounts     bool `json:"local_accounts"`
	ManagerEnrollment bool `json:"manager_enrollment"`
	ScopedInventory   bool `json:"scoped_inventory"`
	MFA               bool `json:"mfa"`
	FileJobs          bool `json:"file_jobs"`
	SecurityRecovery  bool `json:"security_recovery"`
	RemoteControl     bool `json:"remote_control"`
	ScreenObservation bool `json:"screen_observation"`
}

type healthReport struct {
	SchemaVersion                 uint32         `json:"schema_version"`
	StorageSchemaVersion          uint32         `json:"storage_schema_version"`
	Status                        string         `json:"status"`
	AcceptingAuthorizedOperations bool           `json:"accepting_authorized_operations"`
	BootstrapCompleted            bool           `json:"bootstrap_completed"`
	RecoveryQuarantined           bool           `json:"recovery_quarantined"`
	Features                      healthFeatures `json:"features"`
}

func defaultConfiguration() deploymentConfiguration {
	return deploymentConfiguration{
		DeploymentKind: "linux_systemd",
		Network: networkConfiguration{
			Scope:         "loopback_development",
			AuthorityPort: 8787,
		},
		Storage: storageConfiguration{
			DataDirectory:         "/var/lib/helicoid/data",
			BackupDirectory:       "/var/lib/helicoid/backups",
			PreserveDataOnRemoval: true,
		},
	}
}

func defaultInstallConfiguration() deploymentConfiguration {
	configuration := defaultConfiguration()
	configuration.Network = networkConfiguration{
		Scope:         "lan",
		AuthorityPort: 8920,
	}
	return configuration
}

func resolveBackend() (string, error) {
	if os.Geteuid() == 0 {
		return resolvePrivilegedBackend()
	}
	if configured := os.Getenv("HELICOID_SERVER_BACKEND"); configured != "" {
		return executablePath(configured)
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "hs-server")
		if path, pathErr := executablePath(candidate); pathErr == nil {
			return path, nil
		}
	}
	if path, err := executablePath("/opt/helicoid/bin/hs-server"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("hs-server"); err == nil {
		return executablePath(path)
	}
	return "", errors.New("hs-server backend was not found; install the product bundle or set HELICOID_SERVER_BACKEND")
}

func resolvePrivilegedBackend() (string, error) {
	for _, candidate := range []string{
		"/opt/helicoid/bin/hs-server",
		"/usr/local/bin/hs-server",
		"/usr/bin/hs-server",
	} {
		if rootOwnedExecutablePath(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("privileged installer requires a root-owned hs-server under /opt/helicoid/bin, /usr/local/bin, or /usr/bin")
}

func rootOwnedExecutablePath(path string) bool {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return false
	}
	for current := cleanPath; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if current == cleanPath {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				return false
			}
		} else if !info.IsDir() {
			return false
		}
		if current == string(filepath.Separator) {
			return true
		}
	}
}

func executablePath(path string) (string, error) {
	resolved, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("find backend %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect backend %q: %w", resolved, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("backend %q is not an executable regular file", resolved)
	}
	return resolved, nil
}

func callBackend(ctx context.Context, action string, input any, output any) error {
	return callBackendArgs(ctx, []string{action}, input, output)
}

func callBackendArgs(ctx context.Context, args []string, input any, output any) error {
	backend, err := resolveBackend()
	if err != nil {
		return err
	}
	var stdin io.Reader
	if input != nil {
		body, marshalErr := json.Marshal(input)
		if marshalErr != nil {
			return fmt.Errorf("encode backend request: %w", marshalErr)
		}
		stdin = bytes.NewReader(body)
	}
	backendArgs := append([]string{"installer"}, args...)
	command := exec.CommandContext(ctx, backend, backendArgs...)
	command.Stdin = stdin
	stdout := &boundedBuffer{limit: maxBackendOutput}
	stderr := &boundedBuffer{limit: maxBackendOutput}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if stderr.overflow {
			return errors.New("backend error output exceeded the allowed size")
		}
		if ctx.Err() != nil {
			return fmt.Errorf("backend %s timed out: %w", strings.Join(args, " "), ctx.Err())
		}
		detail := bytes.TrimSpace(stderr.Bytes())
		if len(detail) == 0 {
			return fmt.Errorf("backend %s failed: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("backend %s failed: %s", strings.Join(args, " "), detail)
	}
	if stdout.overflow {
		return errors.New("backend output exceeded the allowed size")
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode backend %s response: %w", strings.Join(args, " "), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("backend %s returned multiple JSON values", strings.Join(args, " "))
		}
		return fmt.Errorf("backend %s returned trailing data: %w", strings.Join(args, " "), err)
	}
	return nil
}

func loadStatus(ctx context.Context) (operationStatus, error) {
	configuration, err := loadStoredConfiguration(ctx)
	if err != nil {
		return operationStatus{}, err
	}
	var status operationStatus
	err = callBackend(ctx, "status-v2", statusInput{
		ContractVersion: 2,
		Configuration:   configuration,
	}, &status)
	return status, err
}

func loadStoredConfiguration(ctx context.Context) (deploymentConfiguration, error) {
	var stored *deploymentConfiguration
	if err := callBackendArgs(ctx, []string{
		"configuration-v2", "--state-dir", "/opt/helicoid/.installer",
	}, nil, &stored); err != nil {
		return deploymentConfiguration{}, err
	}
	if stored == nil {
		return defaultConfiguration(), nil
	}
	if err := validateDeploymentConfiguration(*stored); err != nil {
		return deploymentConfiguration{}, fmt.Errorf("stored installer configuration: %w", err)
	}
	return *stored, nil
}

func loadCapabilities(ctx context.Context) (capabilities, error) {
	var result capabilities
	err := callBackend(ctx, "capabilities-v2", nil, &result)
	return result, err
}

func runDoctor(ctx context.Context) doctorReport {
	report := doctorReport{SchemaVersion: 1, Errors: []string{}}
	health, err := loadHealth(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.Health = &health
		if !health.AcceptingAuthorizedOperations {
			report.Errors = append(report.Errors, "server is not accepting authorized operations")
		}
	}
	capabilityResult, err := loadCapabilities(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.Capabilities = &capabilityResult
	}
	configuration, err := loadStoredConfiguration(ctx)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	var preflight preflightResult
	err = callBackend(ctx, "preflight-v2", preflightInput{
		ContractVersion: 2,
		Configuration:   configuration,
	}, &preflight)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		report.Preflight = &preflight
		if !preflight.OK {
			report.Errors = append(report.Errors, "host preflight has one or more failed checks")
		}
	}
	report.OK = len(report.Errors) == 0
	return report
}

func loadHealth(ctx context.Context) (healthReport, error) {
	endpoint, err := url.Parse("http://127.0.0.1:8787/health")
	if err != nil {
		return healthReport{}, fmt.Errorf("parse local health endpoint: %w", err)
	}
	if endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() != "8787" {
		return healthReport{}, errors.New("local health endpoint is outside the expected loopback authority")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return healthReport{}, fmt.Errorf("create local health request: %w", err)
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return healthReport{}, fmt.Errorf("read local server health: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return healthReport{}, fmt.Errorf("local server health returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxHealthOutput+1))
	if err != nil {
		return healthReport{}, fmt.Errorf("read local server health body: %w", err)
	}
	if len(body) > maxHealthOutput {
		return healthReport{}, errors.New("local server health exceeded the allowed response size")
	}
	var health healthReport
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&health); err != nil {
		return healthReport{}, fmt.Errorf("decode local server health: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return healthReport{}, errors.New("local server health returned trailing data")
	}
	if health.SchemaVersion != 1 || (health.Status != "ok" && health.Status != "degraded") {
		return healthReport{}, errors.New("local server returned an unsupported health response")
	}
	return health, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := buffer.limit - buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
			buffer.overflow = true
		}
		_, _ = buffer.Buffer.Write(data)
	} else if len(data) > 0 {
		buffer.overflow = true
	}
	return originalLength, nil
}
