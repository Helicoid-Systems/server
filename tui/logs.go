package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	maxRecentJournalEvents = 100
	maxJournalOutputBytes  = 512 << 10
	maxJournalRecordBytes  = 64 << 10
	composeControlSocket   = "/run/helicoid/backup-control/backup-control.sock"
	maxComposeLogBytes     = 256 << 10
)

type supportLogEvent struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Event     string `json:"event"`
}

type supportLogSummary struct {
	Source       string            `json:"source"`
	Available    bool              `json:"available"`
	Reason       string            `json:"reason"`
	OmittedCount int               `json:"omitted_event_count"`
	Events       []supportLogEvent `json:"events"`
}

type journalEventDescriptor struct {
	Code  string
	Label string
}

var allowlistedJournalMessages = map[string]journalEventDescriptor{
	"hs-server listening over HTTPS":                           {Code: "server_listening_https", Label: "Server listening over HTTPS"},
	"hs-server listening (HTTP, development foundation)":       {Code: "server_listening_development_http", Label: "Server listening on development HTTP"},
	"shutdown requested":                                       {Code: "server_shutdown_requested", Label: "Server shutdown requested"},
	"corrupt operator_mfa_policy; denying authority":           {Code: "operator_mfa_policy_corrupt", Label: "Operator MFA policy is corrupt; authority denied"},
	"security_policy row missing; denying authority":           {Code: "security_policy_missing", Label: "Security policy is missing; authority denied"},
	"failed to hydrate durable security state; failing closed": {Code: "security_state_hydration_failed", Label: "Durable security state could not be loaded"},
	"latched Security State Unavailable":                       {Code: "security_state_unavailable", Label: "Security state unavailable"},
	"required storage operation failed":                        {Code: "required_storage_operation_failed", Label: "Required storage operation failed"},
	"required storage lock/internal failure":                   {Code: "required_storage_lock_failed", Label: "Required storage lock failed"},
	"file-job expiry maintenance failed":                       {Code: "file_job_expiry_maintenance_failed", Label: "File-job expiry maintenance failed"},
	"file-request deadline maintenance failed":                 {Code: "file_request_deadline_maintenance_failed", Label: "File-request deadline maintenance failed"},
	"storage operation failed":                                 {Code: "storage_operation_failed", Label: "Storage operation failed"},
	"password hashing failed":                                  {Code: "password_hashing_failed", Label: "Password hashing failed"},
	"secure randomness failed":                                 {Code: "secure_randomness_failed", Label: "Secure randomness failed"},
}

type journalRecord struct {
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	Priority          string `json:"PRIORITY"`
	Message           string `json:"MESSAGE"`
}

type composeLogMetadata struct {
	Events       []composeLogEvent `json:"events"`
	OmittedCount int               `json:"omitted_count"`
}

type composeLogEvent struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
}

type boundedJournalOutput struct {
	data     []byte
	exceeded bool
}

func (output *boundedJournalOutput) Write(data []byte) (int, error) {
	if len(data) > maxJournalOutputBytes-len(output.data) {
		output.exceeded = true
		return 0, errors.New("journal output bound exceeded")
	}
	output.data = append(output.data, data...)
	return len(data), nil
}

func collectRecentServiceEvents(ctx context.Context, deploymentKind string, installed bool) supportLogSummary {
	summary := supportLogSummary{
		Source: "systemd_journal",
		Reason: "unsupported_deployment",
		Events: []supportLogEvent{},
	}
	if deploymentKind == "linux_compose" {
		summary.Source = "docker_compose"
	}
	if runtime.GOOS != "linux" {
		return summary
	}
	if !installed {
		summary.Reason = "service_not_installed"
		return summary
	}
	if deploymentKind == "linux_compose" {
		data, err := readRecentComposeServiceLogs(ctx)
		if err != nil {
			summary.Source = "docker_compose"
			summary.Reason = "host_logs_unavailable"
			return summary
		}
		parsed, err := parseSafeComposeServiceEvents(data)
		if err != nil {
			summary.Source = "docker_compose"
			summary.Reason = "invalid_compose_log_output"
			return summary
		}
		parsed.Source = "docker_compose"
		parsed.Available = true
		if len(parsed.Events) == 0 {
			parsed.Reason = "no_allowlisted_events"
		} else {
			parsed.Reason = "available"
		}
		return parsed
	}
	if deploymentKind != "linux_systemd" {
		return summary
	}
	journalctl, err := exec.LookPath("journalctl")
	if err != nil || !rootOwnedExecutablePath(journalctl) {
		summary.Reason = "journal_unavailable"
		return summary
	}

	commandContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, journalctl,
		"--unit=hs-server.service",
		"--since=15 minutes ago",
		"--output=json",
		"--no-pager",
		"--lines=100",
	)
	output := &boundedJournalOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if output.exceeded {
			summary.Reason = "output_limit"
		} else if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			summary.Reason = "read_timeout"
		} else {
			summary.Reason = "journal_unavailable"
		}
		return summary
	}
	parsed, err := parseSafeJournalEvents(output.data)
	if err != nil {
		summary.Reason = "invalid_journal_output"
		return summary
	}
	parsed.Source = summary.Source
	parsed.Available = true
	if len(parsed.Events) == 0 {
		parsed.Reason = "no_allowlisted_events"
	} else {
		parsed.Reason = "available"
	}
	return parsed
}

func readRecentComposeServiceLogs(ctx context.Context) ([]byte, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	stream, err := dialer.DialContext(ctx, "unix", composeControlSocket)
	if err != nil {
		return nil, errors.New("host Compose log control is unavailable")
	}
	defer stream.Close()
	connection, ok := stream.(*net.UnixConn)
	if !ok {
		return nil, errors.New("host Compose log control is not a Unix socket")
	}
	deadline := time.Now().Add(25 * time.Second)
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, errors.New("set host Compose log deadline")
	}
	if _, err := connection.Write([]byte{3, 0, 0, 0, 0}); err != nil {
		return nil, errors.New("send host Compose log request")
	}
	if err := connection.CloseWrite(); err != nil {
		return nil, errors.New("finish host Compose log request")
	}
	var status [1]byte
	if _, err := io.ReadFull(connection, status[:]); err != nil || status[0] != 1 {
		return nil, errors.New("host rejected Compose log request")
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		return nil, errors.New("host Compose log response is incomplete")
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length > maxComposeLogBytes {
		return nil, errors.New("host Compose log response exceeds its bound")
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(connection, data); err != nil {
		return nil, errors.New("host Compose log response is incomplete")
	}
	var trailing [1]byte
	if count, err := connection.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.New("host Compose log response has trailing data")
	}
	return data, nil
}

func parseSafeJournalEvents(data []byte) (supportLogSummary, error) {
	if len(data) > maxJournalOutputBytes {
		return supportLogSummary{}, errors.New("journal output exceeds its bound")
	}
	summary := supportLogSummary{Events: []supportLogEvent{}}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxJournalRecordBytes)
	for scanner.Scan() {
		if len(summary.Events)+summary.OmittedCount >= maxRecentJournalEvents {
			return supportLogSummary{}, errors.New("journal record count exceeds its bound")
		}
		var record journalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return supportLogSummary{}, errors.New("journal record is invalid")
		}
		descriptor, known := allowlistedFormattedLogMessage(record.Message)
		if !known {
			summary.OmittedCount++
			continue
		}
		micros, err := strconv.ParseInt(record.RealtimeTimestamp, 10, 64)
		if err != nil || micros <= 0 {
			summary.OmittedCount++
			continue
		}
		priority, err := strconv.Atoi(record.Priority)
		severity, validPriority := journalSeverity(priority)
		if err != nil || !validPriority {
			summary.OmittedCount++
			continue
		}
		summary.Events = append(summary.Events, supportLogEvent{
			Timestamp: time.UnixMicro(micros).UTC().Format(time.RFC3339),
			Severity:  severity,
			Event:     descriptor.Code,
		})
	}
	if err := scanner.Err(); err != nil {
		return supportLogSummary{}, errors.New("journal record exceeds its bound")
	}
	return summary, nil
}

func allowlistedFormattedLogMessage(message string) (journalEventDescriptor, bool) {
	if descriptor, ok := allowlistedJournalMessages[message]; ok {
		return descriptor, true
	}
	message = strings.TrimSpace(message)
	if first, rest, ok := strings.Cut(message, " "); ok {
		if _, err := time.Parse(time.RFC3339Nano, first); err == nil {
			message = strings.TrimSpace(rest)
		}
	}
	if level, rest, ok := strings.Cut(message, " "); ok &&
		(level == "TRACE" || level == "DEBUG" || level == "INFO" || level == "WARN" || level == "ERROR") {
		message = strings.TrimSpace(rest)
	}
	for staticMessage, descriptor := range allowlistedJournalMessages {
		if hasLogMessagePrefix(message, staticMessage) || hasLogMessagePrefix(message, strconv.Quote(staticMessage)) {
			return descriptor, true
		}
	}
	return journalEventDescriptor{}, false
}

func hasLogMessagePrefix(message, prefix string) bool {
	if message == prefix {
		return true
	}
	return strings.HasPrefix(message, prefix) && len(message) > len(prefix) &&
		(message[len(prefix)] == ' ' || message[len(prefix)] == '\t')
}

func parseSafeComposeServiceEvents(data []byte) (supportLogSummary, error) {
	if len(data) > maxComposeLogBytes {
		return supportLogSummary{}, errors.New("Compose event metadata exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var metadata composeLogMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return supportLogSummary{}, errors.New("Compose event metadata is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return supportLogSummary{}, errors.New("Compose event metadata has trailing data")
	}
	if metadata.Events == nil || len(metadata.Events)+metadata.OmittedCount > maxRecentJournalEvents || metadata.OmittedCount < 0 {
		return supportLogSummary{}, errors.New("Compose event metadata exceeds its record bound")
	}
	summary := supportLogSummary{Events: []supportLogEvent{}, OmittedCount: metadata.OmittedCount}
	for _, event := range metadata.Events {
		timestamp, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		known := false
		for _, descriptor := range allowlistedJournalMessages {
			if descriptor.Code == event.Event {
				known = true
				break
			}
		}
		if err != nil || !known {
			return supportLogSummary{}, errors.New("Compose event metadata contains an invalid event")
		}
		summary.Events = append(summary.Events, supportLogEvent{
			Timestamp: timestamp.UTC().Format(time.RFC3339),
			Severity:  "unspecified",
			Event:     event.Event,
		})
	}
	return summary, nil
}

func journalSeverity(priority int) (string, bool) {
	severities := [...]string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}
	if priority < 0 || priority >= len(severities) {
		return "", false
	}
	return severities[priority], true
}

func runLogsCommand(args []string) error {
	if runtime.GOOS != "linux" {
		return errors.New("service logs are available only from the Linux server TUI")
	}
	if len(args) != 1 || args[0] != "recent" {
		return errors.New("usage: helicoid-server logs recent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := loadStatus(ctx)
	if err != nil {
		return errors.New("local service status is unavailable")
	}
	summary := collectRecentServiceEvents(ctx, status.Configuration.DeploymentKind, status.ServiceInstalled)
	if !summary.Available {
		if summary.Reason == "unsupported_deployment" {
			return errors.New("recent log view is available for Linux systemd and Compose deployments")
		}
		return errors.New("recent service events are unavailable; check local journal or host control access")
	}
	if len(summary.Events) == 0 {
		fmt.Fprintln(os.Stdout, "No allowlisted Helicoid service events were recorded in the last 15 minutes.")
		if summary.OmittedCount > 0 {
			fmt.Fprintf(os.Stdout, "%d non-allowlisted or invalid journal events were omitted.\n", summary.OmittedCount)
		}
		return nil
	}
	fmt.Fprintf(os.Stdout, "Recent Helicoid service events from %s (last 15 minutes; raw messages and fields are excluded):\n", summary.Source)
	for _, event := range summary.Events {
		label := allowlistedJournalMessagesLabel(event.Event)
		fmt.Fprintf(os.Stdout, "%s [%s] %s\n", event.Timestamp, event.Severity, label)
	}
	if summary.OmittedCount > 0 {
		fmt.Fprintf(os.Stdout, "%d non-allowlisted or invalid journal events were omitted.\n", summary.OmittedCount)
	}
	return nil
}

func allowlistedJournalMessagesLabel(code string) string {
	for _, descriptor := range allowlistedJournalMessages {
		if descriptor.Code == code {
			return descriptor.Label
		}
	}
	return "Unknown service event"
}
