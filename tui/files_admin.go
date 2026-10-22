package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type fileJobTargetView struct {
	ComputerID           string  `json:"computer_id"`
	FriendlyName         string  `json:"friendly_name"`
	RecipientDisplayName *string `json:"recipient_display_name"`
	State                string  `json:"state"`
	ResultDetail         *string `json:"result_detail"`
}

type fileJobView struct {
	ID                    string              `json:"id"`
	Direction             string              `json:"direction"`
	FileName              string              `json:"file_name"`
	FileSizeBytes         uint64              `json:"file_size_bytes"`
	State                 string              `json:"state"`
	CreatedAtUnix         int64               `json:"created_at_unix"`
	DeliveryExpiresAtUnix int64               `json:"delivery_expires_at_unix"`
	Targets               []fileJobTargetView `json:"targets"`
}

type fileJobListOutput struct {
	Jobs        []fileJobView `json:"jobs"`
	MaxPageSize int           `json:"max_page_size"`
}

type fileStorageSummary struct {
	PayloadLimitBytes        uint64 `json:"payload_limit_bytes"`
	DeliveryPayloadBytes     uint64 `json:"delivery_payload_bytes"`
	RequestPayloadBytes      uint64 `json:"request_payload_bytes"`
	ReservedPayloadBytes     uint64 `json:"reserved_payload_bytes"`
	AvailablePayloadBytes    uint64 `json:"available_payload_bytes"`
	ActiveFileJobs           uint64 `json:"active_file_jobs"`
	ActiveFileJobLimit       uint64 `json:"active_file_job_limit"`
	ActiveRequestUploads     uint64 `json:"active_request_uploads"`
	ActiveRequestUploadLimit uint64 `json:"active_request_upload_limit"`
	RetainedReceivedFiles    uint64 `json:"retained_received_files"`
	RetainedReceivedBytes    uint64 `json:"retained_received_bytes"`
}

type cancelFileJobInput struct {
	ConfirmJobID string `json:"confirm_job_id"`
}

type fileRequestView struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Instructions       string   `json:"instructions"`
	Revision           int64    `json:"revision"`
	State              string   `json:"state"`
	ComputerIDs        []string `json:"computer_ids"`
	AllowedExtensions  []string `json:"allowed_extensions"`
	MaxFileCount       uint32   `json:"max_file_count"`
	MaxTotalSizeBytes  uint64   `json:"max_total_size_bytes"`
	ClosesAtUnix       int64    `json:"closes_at_unix"`
	ReplacementAllowed bool     `json:"replacement_allowed"`
	CreatedAtUnix      int64    `json:"created_at_unix"`
	UpdatedAtUnix      int64    `json:"updated_at_unix"`
	PublishedAtUnix    *int64   `json:"published_at_unix"`
	ClosedAtUnix       *int64   `json:"closed_at_unix"`
}

type fileRequestListOutput struct {
	Requests    []fileRequestView `json:"requests"`
	MaxPageSize int               `json:"max_page_size"`
}

type createFileRequestInput struct {
	Title              string   `json:"title"`
	Instructions       string   `json:"instructions"`
	ComputerIDs        []string `json:"computer_ids"`
	AllowedExtensions  []string `json:"allowed_extensions"`
	MaxFileCount       uint32   `json:"max_file_count"`
	MaxTotalSizeBytes  uint64   `json:"max_total_size_bytes"`
	ClosesAtUnix       int64    `json:"closes_at_unix"`
	ReplacementAllowed bool     `json:"replacement_allowed"`
}

type fileRequestRevisionInput struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

type closeFileRequestInput struct {
	ExpectedRevision int64  `json:"expected_revision"`
	ConfirmRequestID string `json:"confirm_request_id"`
}

type deleteFileRequestSubmissionInput struct {
	ConfirmSubmissionID string `json:"confirm_submission_id"`
}

type fileRequestSubmissionFileView struct {
	ID            string `json:"id"`
	FileName      string `json:"file_name"`
	FileSizeBytes uint64 `json:"file_size_bytes"`
	SHA256        string `json:"sha256"`
	ChunkSize     uint32 `json:"chunk_size_bytes"`
	ChunkCount    uint32 `json:"chunk_count"`
	State         string `json:"state"`
}

type fileRequestSubmissionView struct {
	ID                   string                          `json:"id"`
	RequestID            string                          `json:"request_id"`
	RequestRevision      int64                           `json:"request_revision"`
	ComputerID           string                          `json:"computer_id"`
	LocalUserDisplayName string                          `json:"local_user_display_name"`
	State                string                          `json:"state"`
	CreatedAtUnix        int64                           `json:"created_at_unix"`
	ReplacesSubmissionID *string                         `json:"replaces_submission_id"`
	ContentDeletedAtUnix *int64                          `json:"content_deleted_at_unix"`
	ContentDeletedBy     *string                         `json:"content_deleted_by_account_id"`
	Files                []fileRequestSubmissionFileView `json:"files"`
}

const (
	maxListedFileJobs = 100
	maxFileJobTargets = 50
	maxFileRequests   = 100
	maxRequestFiles   = 50
	maxRequestSize    = 128 << 20
)

func runFilesCommand(args []string) error {
	if !validFilesCommand(args) {
		return errors.New("usage: helicoid-server files storage | jobs | cancel [JOB_ID] | requests list | create | publish [REQUEST_ID] | close [REQUEST_ID] | submissions [REQUEST_ID] | download [REQUEST_ID] | delete-submission [REQUEST_ID]")
	}
	if err := requireInteractiveTerminal(); err != nil {
		return err
	}
	if err := verifyLocalServerAuthority(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	health, err := loadHealth(ctx)
	if err != nil {
		return err
	}
	isJobCommand := args[0] == "jobs" || args[0] == "cancel"
	if isJobCommand && !health.Features.FileJobs {
		return errors.New("file delivery jobs are disabled by this deployment")
	}
	client := newLoopbackAPIClient()
	return withAuthenticatedManager(ctx, client, func(deployment deploymentInfo, session *authenticatedSession) error {
		if args[0] == "storage" {
			return showFileStorageSummary(ctx, client, deployment, session)
		}
		if args[0] == "requests" {
			return runFileRequestsCommand(ctx, client, deployment, session, args[1:])
		}
		if args[0] == "cancel" {
			return cancelFileJobInteractively(ctx, client, deployment, session, args)
		}
		jobs, err := fetchLoopbackJSONWithBearer[fileJobListOutput](
			ctx, client, http.MethodGet, "/v2/files/jobs", nil, session.Token)
		if err != nil {
			return err
		}
		if jobs.MaxPageSize < 1 || jobs.MaxPageSize > maxListedFileJobs || len(jobs.Jobs) > jobs.MaxPageSize {
			return errors.New("file job list exceeded its declared page limit")
		}
		fmt.Fprintf(os.Stdout, "File jobs owned by %s on deployment %s:\n", strconv.QuoteToASCII(session.Account.Username), deployment.DeploymentID)
		for _, job := range jobs.Jobs {
			if !validUUID(job.ID) || job.Direction != "push" || job.DeliveryExpiresAtUnix <= 0 || len(job.Targets) > maxFileJobTargets {
				return errors.New("server returned an invalid file job identity")
			}
			created := "unknown"
			if job.CreatedAtUnix > 0 {
				created = time.Unix(job.CreatedAtUnix, 0).UTC().Format(time.RFC3339)
			}
			expires := time.Unix(job.DeliveryExpiresAtUnix, 0).UTC().Format(time.RFC3339)
			fmt.Fprintf(os.Stdout, "%s  %s  %s  %d bytes  %s  expires=%s  %s\n",
				job.ID, strconv.QuoteToASCII(job.Direction), strconv.QuoteToASCII(job.FileName),
				job.FileSizeBytes, strconv.QuoteToASCII(job.State), expires, created)
			for _, target := range job.Targets {
				if !validUUID(target.ComputerID) {
					return errors.New("server returned an invalid file job target")
				}
				recipient := "not confirmed"
				if target.RecipientDisplayName != nil {
					recipient = strconv.QuoteToASCII(*target.RecipientDisplayName)
				}
				detail := ""
				if target.ResultDetail != nil {
					detail = " detail=" + strconv.QuoteToASCII(*target.ResultDetail)
				}
				fmt.Fprintf(os.Stdout, "  %s  %s  recipient=%s  state=%s%s\n",
					target.ComputerID, strconv.QuoteToASCII(target.FriendlyName), recipient,
					strconv.QuoteToASCII(target.State), detail)
			}
		}
		if len(jobs.Jobs) == 0 {
			fmt.Fprintln(os.Stdout, "No owned file jobs are available.")
		}
		return nil
	})
}

func validFilesCommand(args []string) bool {
	if len(args) == 1 {
		return args[0] == "storage" || args[0] == "jobs" || args[0] == "cancel"
	}
	if len(args) == 2 && args[0] == "cancel" {
		return validUUID(args[1])
	}
	if len(args) < 2 || args[0] != "requests" {
		return false
	}
	switch args[1] {
	case "list", "create":
		return len(args) == 2
	case "publish", "close", "submissions", "download", "delete-submission":
		return len(args) == 2 || len(args) == 3 && validUUID(args[2])
	default:
		return false
	}
}

func showFileStorageSummary(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
) error {
	storage, err := fetchLoopbackJSONWithBearer[fileStorageSummary](
		ctx, client, http.MethodGet, "/v2/files/storage", nil, session.Token)
	if err != nil {
		return err
	}
	if storage.PayloadLimitBytes == 0 ||
		storage.DeliveryPayloadBytes > ^uint64(0)-storage.RequestPayloadBytes ||
		storage.ReservedPayloadBytes != storage.DeliveryPayloadBytes+storage.RequestPayloadBytes ||
		storage.AvailablePayloadBytes != saturatingSub(storage.PayloadLimitBytes, storage.ReservedPayloadBytes) ||
		storage.RetainedReceivedBytes > storage.RequestPayloadBytes {
		return errors.New("server returned an inconsistent file storage summary")
	}
	fmt.Fprintf(os.Stdout, "Logical file payload quota on deployment %s:\n", deployment.DeploymentID)
	fmt.Fprintf(os.Stdout, "Reserved: %s / %s (%s available)\n",
		formatRequestSize(storage.ReservedPayloadBytes), formatRequestSize(storage.PayloadLimitBytes),
		formatRequestSize(storage.AvailablePayloadBytes))
	fmt.Fprintf(os.Stdout, "  Delivery jobs: %s across %d active jobs (limit %d)\n",
		formatRequestSize(storage.DeliveryPayloadBytes), storage.ActiveFileJobs, storage.ActiveFileJobLimit)
	fmt.Fprintf(os.Stdout, "  File requests: %s across %d active uploads (limit %d)\n",
		formatRequestSize(storage.RequestPayloadBytes), storage.ActiveRequestUploads, storage.ActiveRequestUploadLimit)
	fmt.Fprintf(os.Stdout, "  Retained received files: %d files, %s\n",
		storage.RetainedReceivedFiles, formatRequestSize(storage.RetainedReceivedBytes))
	fmt.Fprintln(os.Stdout, "This reports logical payload reservations, not database, backup, or filesystem usage.")
	return nil
}

func saturatingSub(left, right uint64) uint64 {
	if right >= left {
		return 0
	}
	return left - right
}

func runFileRequestsCommand(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
	args []string,
) error {
	action := args[0]
	if action == "create" {
		if !session.Account.Capabilities.Operate {
			return errors.New("computer operation permission is required to create file requests")
		}
		return createFileRequestInteractively(ctx, client, deployment, session)
	}

	requestID := ""
	if len(args) == 2 {
		requestID = strings.ToLower(args[1])
	} else if action == "publish" || action == "close" || action == "submissions" ||
		action == "download" || action == "delete-submission" {
		input, err := readPromptLine("File request ID: ")
		if err != nil {
			return err
		}
		requestID = strings.ToLower(strings.TrimSpace(input))
	}
	if requestID != "" && !validUUID(requestID) {
		return errors.New("file request ID must be a UUID")
	}

	switch action {
	case "list":
		return listFileRequests(ctx, client, deployment, session)
	case "publish":
		if !session.Account.Capabilities.Operate {
			return errors.New("computer operation permission is required to publish file requests")
		}
		return publishFileRequestInteractively(ctx, client, deployment, session, requestID)
	case "close":
		if !session.Account.Capabilities.Operate {
			return errors.New("computer operation permission is required to close file requests")
		}
		return closeFileRequestInteractively(ctx, client, deployment, session, requestID)
	case "submissions":
		return listFileRequestSubmissions(ctx, client, deployment, session, requestID)
	case "download":
		if !session.Account.Capabilities.Operate {
			return errors.New("computer operation permission is required to retrieve file request submissions")
		}
		return downloadFileRequestInteractively(ctx, client, deployment, session, requestID)
	case "delete-submission":
		if !session.Account.Capabilities.Operate {
			return errors.New("computer operation permission is required to delete submission content")
		}
		return deleteFileRequestSubmissionInteractively(ctx, client, deployment, session, requestID)
	default:
		return errors.New("unsupported file request action")
	}
}

func listFileRequests(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession) error {
	result, err := fetchLoopbackJSONWithBearer[fileRequestListOutput](
		ctx, client, http.MethodGet, "/v2/files/requests", nil, session.Token)
	if err != nil {
		return err
	}
	if result.MaxPageSize < 1 || result.MaxPageSize > maxFileRequests ||
		len(result.Requests) > result.MaxPageSize {
		return errors.New("file request list exceeded its declared page limit")
	}
	fmt.Fprintf(os.Stdout, "File requests owned by %s on deployment %s:\n",
		strconv.QuoteToASCII(session.Account.Username), deployment.DeploymentID)
	for _, request := range result.Requests {
		if err := validateFileRequestView(request); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s  r%d  %-8s  %s  targets=%d  max=%d files/%s  closes=%s  replace=%t\n",
			request.ID, request.Revision, strconv.QuoteToASCII(request.State),
			strconv.QuoteToASCII(request.Title), len(request.ComputerIDs),
			request.MaxFileCount, formatRequestSize(request.MaxTotalSizeBytes),
			time.Unix(request.ClosesAtUnix, 0).UTC().Format(time.RFC3339),
			request.ReplacementAllowed)
	}
	if len(result.Requests) == 0 {
		fmt.Fprintln(os.Stdout, "No owned file requests are available.")
	}
	return nil
}

func createFileRequestInteractively(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
) error {
	computers, err := fetchLoopbackJSONWithBearer[computerListOutput](
		ctx, client, http.MethodGet, "/v2/computers", nil, session.Token)
	if err != nil {
		return err
	}
	if len(computers.Computers) > maxFileRequests {
		return errors.New("computer inventory exceeded the file request scope limit")
	}
	if computers.MaxPageSize < 1 || computers.MaxPageSize > maxFileRequests ||
		len(computers.Computers) > computers.MaxPageSize {
		return errors.New("computer inventory exceeded its declared page limit")
	}
	fmt.Fprintln(os.Stdout, "Computers currently visible to this account:")
	eligibleComputers := make(map[string]struct{}, len(computers.Computers))
	for _, computer := range computers.Computers {
		if !validUUID(computer.ID) || strings.ToLower(computer.ID) != computer.ID {
			return errors.New("server returned an invalid computer identity")
		}
		if computer.EnrollmentState == "enrolled" {
			eligibleComputers[computer.ID] = struct{}{}
		}
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			computer.ID, strconv.QuoteToASCII(computer.FriendlyName),
			strconv.QuoteToASCII(computer.EnrollmentState))
	}
	if len(computers.Computers) == 0 {
		return errors.New("no computers are available to target")
	}

	title, err := readPromptLine("Request title (1-120 characters): ")
	if err != nil {
		return err
	}
	title = strings.TrimSpace(title)
	if utf8.RuneCountInString(title) == 0 || utf8.RuneCountInString(title) > 120 ||
		strings.IndexFunc(title, unicode.IsControl) >= 0 {
		return errors.New("request title must contain 1 to 120 printable characters")
	}
	instructions, err := readPromptLine("Instructions (up to 2000 characters): ")
	if err != nil {
		return err
	}
	if utf8.RuneCountInString(instructions) > 2000 ||
		strings.IndexFunc(instructions, func(character rune) bool {
			return unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t'
		}) >= 0 {
		return errors.New("request instructions exceed the allowed text length or contain unsupported controls")
	}
	targetInput, err := readPromptLine("Target computer IDs, comma separated: ")
	if err != nil {
		return err
	}
	targetIDs, err := parseRequestComputerIDs(targetInput)
	if err != nil {
		return err
	}
	for _, id := range targetIDs {
		if _, exists := eligibleComputers[id]; !exists {
			return errors.New("every target must be an enrolled computer in the displayed inventory; the server checks current operate scope when saving")
		}
	}
	extensionInput, err := readPromptLine("Allowed file extensions, comma separated, or * for any: ")
	if err != nil {
		return err
	}
	extensions, err := parseRequestExtensions(extensionInput)
	if err != nil {
		return err
	}
	fileCountInput, err := readPromptLine("Maximum file count (1-50): ")
	if err != nil {
		return err
	}
	fileCount, err := strconv.ParseUint(strings.TrimSpace(fileCountInput), 10, 32)
	if err != nil || fileCount < 1 || fileCount > maxRequestFiles {
		return errors.New("maximum file count must be between 1 and 50")
	}
	sizeInput, err := readPromptLine("Maximum aggregate size in MiB (1-128): ")
	if err != nil {
		return err
	}
	sizeMiB, err := strconv.ParseUint(strings.TrimSpace(sizeInput), 10, 8)
	if err != nil || sizeMiB < 1 || sizeMiB > 128 {
		return errors.New("maximum aggregate size must be between 1 and 128 MiB")
	}
	deadlineInput, err := readPromptLine("Close deadline (RFC3339, with time zone): ")
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339, strings.TrimSpace(deadlineInput))
	if err != nil {
		return errors.New("close deadline must be an RFC3339 timestamp with a time zone")
	}
	now := time.Now().UTC()
	if deadline.Before(now.Add(time.Minute)) || deadline.After(now.Add(30*24*time.Hour)) {
		return errors.New("close deadline must be at least one minute and at most 30 days from now")
	}
	replacementInput, err := readPromptLine("Allow a later explicitly confirmed replacement? (yes/no): ")
	if err != nil {
		return err
	}
	replacementAllowed, err := parseYesNo(replacementInput)
	if err != nil {
		return err
	}

	input := createFileRequestInput{
		Title:              title,
		Instructions:       instructions,
		ComputerIDs:        targetIDs,
		AllowedExtensions:  extensions,
		MaxFileCount:       uint32(fileCount),
		MaxTotalSizeBytes:  sizeMiB * 1024 * 1024,
		ClosesAtUnix:       deadline.UTC().Unix(),
		ReplacementAllowed: replacementAllowed,
	}
	confirmation := "create file request " + title
	fmt.Fprintf(os.Stdout,
		"\nCreate draft %q on deployment %s for %d computers, up to %d files / %s, closing %s UTC?\n",
		title, deployment.DeploymentID, len(targetIDs), input.MaxFileCount,
		formatRequestSize(input.MaxTotalSizeBytes), deadline.UTC().Format(time.RFC3339))
	answer, err := readPromptLine("Type " + confirmation + " to save the draft: ")
	if err != nil {
		return err
	}
	if answer != confirmation {
		return errors.New("file request draft creation was not confirmed")
	}
	created, err := fetchLoopbackJSONWithBearer[fileRequestView](
		ctx, client, http.MethodPost, "/v2/files/requests", input, session.Token)
	if err != nil {
		return err
	}
	if err := validateFileRequestView(created); err != nil {
		return err
	}
	if created.State != "draft" || created.Title != title || created.Revision != 1 {
		return errors.New("server did not confirm the new file request draft")
	}
	fmt.Fprintf(os.Stdout, "Created file request draft %s on deployment %s. Review it, then publish explicitly.\n",
		created.ID, deployment.DeploymentID)
	return nil
}

func publishFileRequestInteractively(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
	requestID string,
) error {
	request, err := fetchFileRequest(ctx, client, session.Token, requestID)
	if err != nil {
		return err
	}
	if request.State != "draft" {
		return errors.New("only an owned draft request can be published")
	}
	printFileRequestReview(request)
	confirmation, err := readPromptLine("Type the exact request ID to publish this request to its listed computers: ")
	if err != nil {
		return err
	}
	if confirmation != request.ID {
		return errors.New("file request publication was not confirmed")
	}
	updated, err := fetchLoopbackJSONWithBearer[fileRequestView](
		ctx, client, http.MethodPost, "/v2/files/requests/"+request.ID+"/publish",
		fileRequestRevisionInput{ExpectedRevision: request.Revision}, session.Token)
	if err != nil {
		return err
	}
	if err := validateFileRequestView(updated); err != nil {
		return err
	}
	if updated.ID != request.ID || updated.State != "open" || updated.Revision != request.Revision+1 {
		return errors.New("server did not confirm the requested file request publication")
	}
	fmt.Fprintf(os.Stdout, "Published file request %s on deployment %s.\n", request.ID, deployment.DeploymentID)
	return nil
}

func closeFileRequestInteractively(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
	requestID string,
) error {
	request, err := fetchFileRequest(ctx, client, session.Token, requestID)
	if err != nil {
		return err
	}
	if request.State != "open" {
		return errors.New("only an open file request can be closed")
	}
	printFileRequestReview(request)
	fmt.Fprintln(os.Stdout, "Closing stops new submissions. Completed files remain available for authorized review.")
	confirmation, err := readPromptLine("Type the exact request ID to close it: ")
	if err != nil {
		return err
	}
	if confirmation != request.ID {
		return errors.New("file request closure was not confirmed")
	}
	updated, err := fetchLoopbackJSONWithBearer[fileRequestView](
		ctx, client, http.MethodPost, "/v2/files/requests/"+request.ID+"/close",
		closeFileRequestInput{
			ExpectedRevision: request.Revision,
			ConfirmRequestID: request.ID,
		}, session.Token)
	if err != nil {
		return err
	}
	if err := validateFileRequestView(updated); err != nil {
		return err
	}
	if updated.ID != request.ID || updated.State != "closed" || updated.Revision != request.Revision+1 {
		return errors.New("server did not confirm the requested file request closure")
	}
	fmt.Fprintf(os.Stdout, "Closed file request %s on deployment %s; completed submissions remain stored.\n",
		request.ID, deployment.DeploymentID)
	return nil
}

func listFileRequestSubmissions(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
	requestID string,
) error {
	if !session.Account.Capabilities.Operate {
		return errors.New("computer operation permission is required to review file request submissions")
	}
	request, err := fetchFileRequest(ctx, client, session.Token, requestID)
	if err != nil {
		return err
	}
	submissions, err := fetchLoopbackJSONWithBearer[[]fileRequestSubmissionView](
		ctx, client, http.MethodGet, "/v2/files/requests/"+requestID+"/submissions", nil, session.Token)
	if err != nil {
		return err
	}
	if len(submissions) > maxFileRequests {
		return errors.New("file request submission list exceeded its page limit")
	}
	fmt.Fprintf(os.Stdout, "Submissions for %q (%s) on deployment %s:\n",
		strconv.QuoteToASCII(request.Title), requestID, deployment.DeploymentID)
	for _, submission := range submissions {
		if err := validateFileRequestSubmission(submission, request); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "%s  %s  computer=%s  user=%s  created=%s\n",
			submission.ID, strconv.QuoteToASCII(submission.State), submission.ComputerID,
			strconv.QuoteToASCII(submission.LocalUserDisplayName),
			time.Unix(submission.CreatedAtUnix, 0).UTC().Format(time.RFC3339))
		if submission.ContentDeletedAtUnix != nil {
			actor := "unknown"
			if submission.ContentDeletedBy != nil {
				actor = *submission.ContentDeletedBy
			}
			fmt.Fprintf(os.Stdout, "  content-deleted=%s  manager-account=%s\n",
				time.Unix(*submission.ContentDeletedAtUnix, 0).UTC().Format(time.RFC3339),
				strconv.QuoteToASCII(actor))
		}
		for _, file := range submission.Files {
			fmt.Fprintf(os.Stdout, "  %s  %s  %d bytes  sha256=%s  %s\n",
				file.ID, strconv.QuoteToASCII(file.FileName), file.FileSizeBytes,
				file.SHA256, strconv.QuoteToASCII(file.State))
		}
	}
	if len(submissions) == 0 {
		fmt.Fprintln(os.Stdout, "No submissions are available for this request.")
	}
	return nil
}

func deleteFileRequestSubmissionInteractively(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
	requestID string,
) error {
	request, err := fetchFileRequest(ctx, client, session.Token, requestID)
	if err != nil {
		return err
	}
	submissions, err := fetchLoopbackJSONWithBearer[[]fileRequestSubmissionView](
		ctx, client, http.MethodGet, "/v2/files/requests/"+requestID+"/submissions", nil, session.Token)
	if err != nil {
		return err
	}
	if len(submissions) > maxFileRequests {
		return errors.New("file request submission list exceeded its page limit")
	}
	fmt.Fprintf(os.Stdout, "Received submissions for %q on deployment %s:\n",
		strconv.QuoteToASCII(request.Title), deployment.DeploymentID)
	for _, submission := range submissions {
		if err := validateFileRequestSubmission(submission, request); err != nil {
			return err
		}
		if submission.State == "received" {
			var available int
			for _, file := range submission.Files {
				if file.State == "received" {
					available++
				}
			}
			fmt.Fprintf(os.Stdout, "  %s  computer=%s  user=%s  files=%d  retained=%d\n",
				submission.ID, submission.ComputerID,
				strconv.QuoteToASCII(submission.LocalUserDisplayName), len(submission.Files), available)
		}
	}
	submissionID, err := readPromptLine("Received submission ID whose content should be deleted: ")
	if err != nil {
		return err
	}
	submissionID = strings.ToLower(strings.TrimSpace(submissionID))
	if !validUUID(submissionID) {
		return errors.New("submission ID must be a UUID")
	}
	var selected *fileRequestSubmissionView
	for index := range submissions {
		if submissions[index].ID == submissionID && submissions[index].State == "received" {
			selected = &submissions[index]
			break
		}
	}
	if selected == nil {
		return errors.New("the selected submission is not received under this request")
	}
	var retainedBytes uint64
	var retainedFiles int
	for _, file := range selected.Files {
		if file.State == "received" {
			retainedBytes += file.FileSizeBytes
			retainedFiles++
		}
	}
	if retainedFiles == 0 {
		return errors.New("the selected submission has no retained file content")
	}
	fmt.Fprintf(os.Stdout,
		"Remove %d retained bytes from submission %s on deployment %s? File metadata remains. This removes the content through the application; prior database backups or SQLite free pages may retain bytes.\n",
		retainedBytes, submissionID, deployment.DeploymentID)
	confirmation, err := readPromptLine("Type the exact submission ID to delete its content: ")
	if err != nil {
		return err
	}
	if confirmation != submissionID {
		return errors.New("file request submission content deletion was not confirmed")
	}
	deleted, err := fetchLoopbackJSONWithBearer[fileRequestSubmissionView](
		ctx, client, http.MethodDelete,
		"/v2/files/requests/"+requestID+"/submissions/"+submissionID,
		deleteFileRequestSubmissionInput{ConfirmSubmissionID: submissionID}, session.Token)
	if err != nil {
		return err
	}
	if err := validateFileRequestSubmission(deleted, request); err != nil {
		return err
	}
	if deleted.ID != submissionID || deleted.State != "received" || deleted.ContentDeletedAtUnix == nil {
		return errors.New("server did not confirm the requested submission content deletion")
	}
	for _, file := range deleted.Files {
		if file.State != "deleted" {
			return errors.New("server returned a submission with content that remains available")
		}
	}
	fmt.Fprintf(os.Stdout,
		"Removed retained content for submission %s on deployment %s; metadata remains available.\n",
		submissionID, deployment.DeploymentID)
	return nil
}

func downloadFileRequestInteractively(
	ctx context.Context,
	client *http.Client,
	deployment deploymentInfo,
	session *authenticatedSession,
	requestID string,
) error {
	request, err := fetchFileRequest(ctx, client, session.Token, requestID)
	if err != nil {
		return err
	}
	submissions, err := fetchLoopbackJSONWithBearer[[]fileRequestSubmissionView](
		ctx, client, http.MethodGet, "/v2/files/requests/"+requestID+"/submissions", nil, session.Token)
	if err != nil {
		return err
	}
	if len(submissions) > maxFileRequests {
		return errors.New("file request submission list exceeded its page limit")
	}
	var selected *fileRequestSubmissionView
	fmt.Fprintf(os.Stdout, "Received submissions for %q on deployment %s:\n",
		strconv.QuoteToASCII(request.Title), deployment.DeploymentID)
	for index := range submissions {
		if err := validateFileRequestSubmission(submissions[index], request); err != nil {
			return err
		}
		if submissions[index].State == "received" {
			fmt.Fprintf(os.Stdout, "  %s  computer=%s  user=%s  files=%d\n",
				submissions[index].ID, submissions[index].ComputerID,
				strconv.QuoteToASCII(submissions[index].LocalUserDisplayName), len(submissions[index].Files))
		}
	}
	submissionID, err := readPromptLine("Received submission ID: ")
	if err != nil {
		return err
	}
	submissionID = strings.ToLower(strings.TrimSpace(submissionID))
	if !validUUID(submissionID) {
		return errors.New("submission ID must be a UUID")
	}
	for index := range submissions {
		if submissions[index].ID == submissionID && submissions[index].State == "received" {
			selected = &submissions[index]
			break
		}
	}
	if selected == nil {
		return errors.New("the selected submission is not received under this request")
	}
	for _, file := range selected.Files {
		fmt.Fprintf(os.Stdout, "  %s  %s  %d bytes  sha256=%s  %s\n",
			file.ID, strconv.QuoteToASCII(file.FileName), file.FileSizeBytes,
			file.SHA256, strconv.QuoteToASCII(file.State))
	}
	fileID, err := readPromptLine("Received file ID: ")
	if err != nil {
		return err
	}
	fileID = strings.ToLower(strings.TrimSpace(fileID))
	if !validUUID(fileID) {
		return errors.New("file ID must be a UUID")
	}
	var selectedFile *fileRequestSubmissionFileView
	for index := range selected.Files {
		if selected.Files[index].ID == fileID && selected.Files[index].State == "received" {
			selectedFile = &selected.Files[index]
			break
		}
	}
	if selectedFile == nil {
		return errors.New("the selected file is not received in this submission")
	}
	directoryInput, err := readPromptLineLimit("Existing destination directory (file will keep its received name): ", 4096)
	if err != nil {
		return err
	}
	directoryInput = strings.TrimSpace(directoryInput)
	if directoryInput == "" {
		return errors.New("destination directory is required")
	}
	directory, err := filepath.Abs(directoryInput)
	if err != nil {
		return errors.New("destination directory path is invalid")
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil || !directoryInfo.IsDir() {
		return errors.New("destination must be an existing directory")
	}
	destination := filepath.Join(directory, selectedFile.FileName)
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("destination file already exists; choose an empty directory")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not inspect destination file")
	}
	fmt.Fprintf(os.Stdout, "Save %q (%d bytes) from submission %s on deployment %s to %s?\n",
		selectedFile.FileName, selectedFile.FileSizeBytes, selected.ID, deployment.DeploymentID, destination)
	confirmation, err := readPromptLine("Type the exact file ID to save this received file: ")
	if err != nil {
		return err
	}
	if confirmation != selectedFile.ID {
		return errors.New("received-file download was not confirmed")
	}
	if err := saveReceivedFileChunks(ctx, client, session.Token, request.ID, selected.ID, *selectedFile, destination); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Saved verified received file to %s.\n", destination)
	return nil
}

func saveReceivedFileChunks(
	ctx context.Context,
	client *http.Client,
	bearer, requestID, submissionID string,
	file fileRequestSubmissionFileView,
	destination string,
) error {
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".helicoid-received-*")
	if err != nil {
		return errors.New("could not create a private temporary file in the destination directory")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("could not protect the temporary received file")
	}
	digest := sha256.New()
	var written uint64
	for index := uint32(0); index < file.ChunkCount; index++ {
		path := fmt.Sprintf("/v2/files/requests/%s/submissions/%s/files/%s/chunks/%d",
			requestID, submissionID, file.ID, index)
		chunk, err := fetchLoopbackBytesWithBearer(ctx, client, path, bearer)
		if err != nil {
			_ = temporary.Close()
			return err
		}
		remaining := file.FileSizeBytes - written
		expectedLength := uint64(file.ChunkSize)
		if remaining < expectedLength {
			expectedLength = remaining
		}
		if uint64(len(chunk)) != expectedLength {
			zeroBytes(chunk)
			_ = temporary.Close()
			return errors.New("server returned a received-file chunk with an unexpected size")
		}
		writtenChunk, writeErr := temporary.Write(chunk)
		if writeErr == nil && writtenChunk != len(chunk) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			_, writeErr = digest.Write(chunk)
		}
		zeroBytes(chunk)
		if writeErr != nil {
			_ = temporary.Close()
			return errors.New("could not write the received-file chunk")
		}
		written += expectedLength
	}
	if written != file.FileSizeBytes || hex.EncodeToString(digest.Sum(nil)) != file.SHA256 {
		_ = temporary.Close()
		return errors.New("downloaded received file failed its size or SHA-256 verification")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("could not sync the verified temporary received file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("could not close the verified temporary received file")
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("destination file appeared during download; no file was overwritten")
		}
		return errors.New("could not publish the verified file without overwriting an existing destination")
	}
	if err := os.Remove(temporaryPath); err != nil {
		return errors.New("verified file was saved, but its temporary link could not be removed")
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errors.New("verified file was saved, but the destination directory could not be synced")
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("verified file was saved, but the destination directory sync did not complete")
	}
	return nil
}

func fetchLoopbackBytesWithBearer(ctx context.Context, client *http.Client, path, bearer string) ([]byte, error) {
	var zero []byte
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "?") || strings.Contains(path, "#") || strings.Contains(path, "..") {
		return zero, errors.New("invalid local file-content API path")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+localAuthority+path, nil)
	if err != nil {
		return zero, errors.New("create local file-content request")
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := client.Do(request)
	if err != nil {
		return zero, errors.New("local received-file request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, fmt.Errorf("local received-file API returned HTTP %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/octet-stream" {
		return zero, errors.New("server returned an unexpected received-file content type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if err != nil {
		zeroBytes(body)
		return zero, errors.New("read local received-file chunk")
	}
	if len(body) > 256*1024 {
		zeroBytes(body)
		return zero, errors.New("server returned an oversized received-file chunk")
	}
	return body, nil
}

func fetchFileRequest(ctx context.Context, client *http.Client, bearer, requestID string) (fileRequestView, error) {
	if !validUUID(requestID) {
		return fileRequestView{}, errors.New("file request ID must be a UUID")
	}
	request, err := fetchLoopbackJSONWithBearer[fileRequestView](
		ctx, client, http.MethodGet, "/v2/files/requests/"+requestID, nil, bearer)
	if err != nil {
		return fileRequestView{}, err
	}
	if err := validateFileRequestView(request); err != nil {
		return fileRequestView{}, err
	}
	if request.ID != requestID {
		return fileRequestView{}, errors.New("server returned a different file request")
	}
	return request, nil
}

func validateFileRequestView(request fileRequestView) error {
	if !validUUID(request.ID) || strings.ToLower(request.ID) != request.ID ||
		request.Revision <= 0 || request.State != "draft" && request.State != "open" && request.State != "closed" ||
		utf8.RuneCountInString(request.Title) == 0 || utf8.RuneCountInString(request.Title) > 120 ||
		strings.IndexFunc(request.Title, unicode.IsControl) >= 0 ||
		utf8.RuneCountInString(request.Instructions) > 2000 ||
		request.MaxFileCount < 1 || request.MaxFileCount > maxRequestFiles ||
		request.MaxTotalSizeBytes < 1 || request.MaxTotalSizeBytes > maxRequestSize ||
		request.ClosesAtUnix <= 0 || request.CreatedAtUnix <= 0 ||
		len(request.ComputerIDs) == 0 || len(request.ComputerIDs) > maxFileJobTargets ||
		len(request.AllowedExtensions) == 0 || len(request.AllowedExtensions) > 64 {
		return errors.New("server returned invalid file request metadata")
	}
	seenComputers := make(map[string]struct{}, len(request.ComputerIDs))
	for _, id := range request.ComputerIDs {
		if !validUUID(id) || strings.ToLower(id) != id {
			return errors.New("server returned an invalid file request computer ID")
		}
		if _, exists := seenComputers[id]; exists {
			return errors.New("server returned duplicate file request computer IDs")
		}
		seenComputers[id] = struct{}{}
	}
	if _, err := parseRequestExtensions(strings.Join(request.AllowedExtensions, ",")); err != nil {
		return errors.New("server returned invalid file request extension rules")
	}
	if request.State == "open" && request.ClosesAtUnix <= time.Now().UTC().Unix() {
		return errors.New("server returned an expired open file request")
	}
	return nil
}

func validateFileRequestSubmission(submission fileRequestSubmissionView, request fileRequestView) error {
	if !validUUID(submission.ID) || strings.ToLower(submission.ID) != submission.ID ||
		submission.RequestID != request.ID || !validUUID(submission.ComputerID) ||
		strings.ToLower(submission.ComputerID) != submission.ComputerID ||
		submission.RequestRevision <= 0 || submission.CreatedAtUnix <= 0 ||
		submission.RequestRevision > request.Revision ||
		submission.CreatedAtUnix > time.Now().UTC().Unix()+300 ||
		strings.TrimSpace(submission.LocalUserDisplayName) == "" ||
		utf8.RuneCountInString(submission.LocalUserDisplayName) > 128 ||
		strings.IndexFunc(submission.LocalUserDisplayName, unicode.IsControl) >= 0 ||
		submission.State != "uploading" && submission.State != "received" &&
			submission.State != "failed" && submission.State != "expired" &&
			submission.State != "superseded" ||
		len(submission.Files) == 0 || len(submission.Files) > int(request.MaxFileCount) {
		return errors.New("server returned invalid or out-of-scope file request submission metadata")
	}
	if submission.ContentDeletedAtUnix != nil &&
		(*submission.ContentDeletedAtUnix <= 0 ||
			*submission.ContentDeletedAtUnix > time.Now().UTC().Unix()+300 ||
			submission.State != "received") {
		return errors.New("server returned invalid content deletion metadata")
	}
	if submission.ContentDeletedBy != nil &&
		(!validUUID(*submission.ContentDeletedBy) || strings.ToLower(*submission.ContentDeletedBy) != *submission.ContentDeletedBy ||
			submission.ContentDeletedAtUnix == nil) {
		return errors.New("server returned invalid content deletion actor")
	}
	computerInRequest := false
	for _, computerID := range request.ComputerIDs {
		if computerID == submission.ComputerID {
			computerInRequest = true
			break
		}
	}
	if !computerInRequest {
		return errors.New("server returned a submission from outside the request's computer scope")
	}
	seenNames := make(map[string]struct{}, len(submission.Files))
	seenFileIDs := make(map[string]struct{}, len(submission.Files))
	var total uint64
	hasRetainedContent := false
	for _, file := range submission.Files {
		if !validUUID(file.ID) || strings.ToLower(file.ID) != file.ID ||
			!validRequestFileName(file.FileName) ||
			file.FileSizeBytes > request.MaxTotalSizeBytes ||
			file.FileSizeBytes > request.MaxTotalSizeBytes-total ||
			len(file.SHA256) != 64 || !isLowerHex(file.SHA256) ||
			file.ChunkSize != 256*1024 ||
			file.ChunkCount != uint32((file.FileSizeBytes+256*1024-1)/(256*1024)) ||
			file.State != "uploading" && file.State != "received" &&
				file.State != "failed" && file.State != "deleted" ||
			!requestAllowsFileName(file.FileName, request.AllowedExtensions) {
			return errors.New("server returned invalid file request submission file metadata")
		}
		name := strings.ToLower(file.FileName)
		if _, exists := seenNames[name]; exists {
			return errors.New("server returned duplicate file names in a submission")
		}
		seenNames[name] = struct{}{}
		if _, exists := seenFileIDs[file.ID]; exists {
			return errors.New("server returned duplicate file identities in a submission")
		}
		seenFileIDs[file.ID] = struct{}{}
		if file.State == "received" {
			hasRetainedContent = true
		}
		total += file.FileSizeBytes
	}
	if submission.ContentDeletedAtUnix != nil && hasRetainedContent {
		return errors.New("server returned deletion metadata while received content remains")
	}
	if total > request.MaxTotalSizeBytes {
		return errors.New("server returned a submission over the request aggregate size limit")
	}
	if submission.ReplacesSubmissionID != nil &&
		(!validUUID(*submission.ReplacesSubmissionID) ||
			strings.ToLower(*submission.ReplacesSubmissionID) != *submission.ReplacesSubmissionID) {
		return errors.New("server returned an invalid replacement submission identity")
	}
	return nil
}

func requestAllowsFileName(fileName string, allowedExtensions []string) bool {
	name := strings.ToLower(fileName)
	for _, extension := range allowedExtensions {
		if extension == "*" || strings.HasSuffix(name, "."+extension) && len(name) > len(extension)+1 {
			return true
		}
	}
	return false
}

func printFileRequestReview(request fileRequestView) {
	fmt.Fprintf(os.Stdout, "Request %s  revision %d  state=%s\n", request.ID, request.Revision, request.State)
	fmt.Fprintf(os.Stdout, "Title: %s\nInstructions: %s\n",
		strconv.QuoteToASCII(request.Title), strconv.QuoteToASCII(request.Instructions))
	fmt.Fprintf(os.Stdout, "Targets: %s\nExtensions: %s\nLimits: %d files / %s\nCloses: %s UTC\n",
		strings.Join(request.ComputerIDs, ", "), strings.Join(request.AllowedExtensions, ", "),
		request.MaxFileCount, formatRequestSize(request.MaxTotalSizeBytes),
		time.Unix(request.ClosesAtUnix, 0).UTC().Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "Replacement allowed: %t\n", request.ReplacementAllowed)
}

func parseRequestComputerIDs(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > maxFileJobTargets {
		return nil, errors.New("choose between 1 and 50 target computers")
	}
	seen := make(map[string]struct{}, len(parts))
	ids := make([]string, 0, len(parts))
	for _, part := range parts {
		id := strings.ToLower(strings.TrimSpace(part))
		if !validUUID(id) {
			return nil, errors.New("every target computer ID must be a UUID from the listed inventory")
		}
		if _, exists := seen[id]; exists {
			return nil, errors.New("target computer IDs must be unique")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

func parseRequestExtensions(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, errors.New("choose between 1 and 64 allowed extensions")
	}
	seen := make(map[string]struct{}, len(parts))
	extensions := make([]string, 0, len(parts))
	for _, part := range parts {
		extension := strings.ToLower(strings.TrimSpace(part))
		if extension == "" || len(extension) > 32 {
			return nil, errors.New("allowed extensions must be safe and at most 32 characters")
		}
		if extension != "*" {
			for _, character := range extension {
				if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
					character == '.' || character == '+' || character == '_' || character == '-') {
					return nil, errors.New("allowed extensions may contain only letters, digits, dot, plus, underscore, and hyphen")
				}
			}
			if strings.HasPrefix(extension, ".") || strings.HasSuffix(extension, ".") || strings.Contains(extension, "..") {
				return nil, errors.New("allowed extensions cannot start or end with a dot or contain two dots")
			}
		}
		if _, exists := seen[extension]; exists {
			return nil, errors.New("allowed extensions must be unique")
		}
		seen[extension] = struct{}{}
		extensions = append(extensions, extension)
	}
	if _, wildcard := seen["*"]; wildcard && len(extensions) != 1 {
		return nil, errors.New("the wildcard extension cannot be combined with specific extensions")
	}
	return extensions, nil
}

func parseYesNo(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "y":
		return true, nil
	case "no", "n":
		return false, nil
	default:
		return false, errors.New("answer yes or no")
	}
}

func validRequestFileName(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || len([]byte(value)) > 255 ||
		value == "." || value == ".." || strings.HasSuffix(value, ".") || strings.HasSuffix(value, " ") ||
		strings.ContainsAny(value, `/\:`) ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	stem := strings.ToUpper(strings.TrimRight(strings.SplitN(value, ".", 2)[0], " ."))
	return stem != "CON" && stem != "PRN" && stem != "AUX" && stem != "NUL" &&
		!(len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) &&
			stem[3] >= '1' && stem[3] <= '9')
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func formatRequestSize(bytes uint64) string {
	return fmt.Sprintf("%.0f MiB", float64(bytes)/(1024*1024))
}

func cancelFileJobInteractively(ctx context.Context, client *http.Client, deployment deploymentInfo, session *authenticatedSession, args []string) error {
	jobID := ""
	if len(args) == 2 {
		jobID = args[1]
	} else {
		value, err := readPromptLine("File job ID to cancel: ")
		if err != nil {
			return err
		}
		jobID = strings.TrimSpace(value)
	}
	if !validUUID(jobID) {
		return errors.New("file job ID must be a UUID")
	}
	job, err := fetchLoopbackJSONWithBearer[fileJobView](
		ctx, client, http.MethodGet, "/v2/files/jobs/"+jobID, nil, session.Token)
	if err != nil {
		return err
	}
	if job.ID != jobID || job.Direction != "push" || job.DeliveryExpiresAtUnix <= 0 || len(job.Targets) > maxFileJobTargets {
		return errors.New("server returned an invalid file job")
	}
	expires := time.Unix(job.DeliveryExpiresAtUnix, 0).UTC().Format(time.RFC3339)
	fmt.Fprintf(os.Stdout, "Job %s: %s  %s  %d bytes  state=%s  expires=%s\n",
		job.ID, strconv.QuoteToASCII(job.Direction), strconv.QuoteToASCII(job.FileName),
		job.FileSizeBytes, strconv.QuoteToASCII(job.State), expires)
	for _, target := range job.Targets {
		if !validUUID(target.ComputerID) {
			return errors.New("server returned an invalid file job target")
		}
		recipient := "not confirmed"
		if target.RecipientDisplayName != nil {
			recipient = strconv.QuoteToASCII(*target.RecipientDisplayName)
		}
		fmt.Fprintf(os.Stdout, "  %s  %s  recipient=%s  state=%s\n",
			target.ComputerID, strconv.QuoteToASCII(target.FriendlyName), recipient,
			strconv.QuoteToASCII(target.State))
	}
	if job.State == "cancelled" {
		fmt.Fprintln(os.Stdout, "This file job is already cancelled.")
		return nil
	}
	if job.State != "uploading" && job.State != "queued" {
		return errors.New("only uploading or unleased queued file jobs can be cancelled")
	}
	confirmation, err := readPromptLine("Type the exact file job ID to cancel; a leased delivery cannot be recalled: ")
	if err != nil {
		return err
	}
	if confirmation != jobID {
		return errors.New("file job cancellation was not confirmed")
	}
	updated, err := fetchLoopbackJSONWithBearer[fileJobView](
		ctx, client, http.MethodPost, "/v2/files/jobs/"+jobID,
		cancelFileJobInput{ConfirmJobID: jobID}, session.Token)
	if err != nil {
		return err
	}
	if updated.ID != jobID || updated.State != "cancelled" {
		return errors.New("server did not confirm file job cancellation")
	}
	fmt.Fprintf(os.Stdout, "Cancelled file job %s on deployment %s.\n", jobID, deployment.DeploymentID)
	return nil
}
