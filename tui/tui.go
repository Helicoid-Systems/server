package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/list"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type sectionItem struct {
	key         string
	title       string
	description string
}

func (item sectionItem) Title() string       { return item.title }
func (item sectionItem) Description() string { return item.description }
func (item sectionItem) FilterValue() string { return item.title + " " + item.description }

type statusMessage struct {
	generation uint64
	status     operationStatus
	err        error
}

type capabilitiesMessage struct {
	generation   uint64
	capabilities capabilities
	err          error
}

type healthMessage struct {
	generation uint64
	health     healthReport
	err        error
}

type doctorMessage struct {
	generation uint64
	report     doctorReport
}

type removeMessage struct {
	generation uint64
	status     operationStatus
	err        error
}

type installerFinishedMessage struct {
	generation uint64
	err        error
}

type bootstrapFinishedMessage struct {
	err error
}

type accountsFinishedMessage struct {
	err error
}

type computersFinishedMessage struct {
	err error
}

type groupsFinishedMessage struct {
	err error
}

type managersFinishedMessage struct {
	err error
}

type filesFinishedMessage struct {
	err error
}

type supportFinishedMessage struct {
	err error
}

type logsFinishedMessage struct {
	err error
}

type auditFinishedMessage struct {
	err       error
	retention bool
}

type backupFinishedMessage struct {
	err error
}

type recoveryFinishedMessage struct {
	generation uint64
	err        error
}

type cutoverFinishedMessage struct {
	action string
	err    error
}

type model struct {
	sections          list.Model
	status            *operationStatus
	caps              *capabilities
	statusError       string
	capsError         string
	health            *healthReport
	healthError       string
	doctor            *doctorReport
	network           *networkDiagnostics
	networkError      string
	networkLoading    bool
	networkGeneration uint64
	active            string
	width             int
	generation        uint64
	removePrompt      bool
	removeText        string
	removeRunning     bool
	removeError       string
	installRunning    bool
	installError      string
	bootstrapRunning  bool
	bootstrapError    string
	accountsRunning   bool
	accountsError     string
	computersRunning  bool
	computersError    string
	groupsRunning     bool
	groupsError       string
	managersRunning   bool
	managersError     string
	filesRunning      bool
	filesError        string
	supportRunning    bool
	supportMessage    string
	logsRunning       bool
	logsMessage       string
	auditRunning      bool
	auditRetention    bool
	auditMessage      string
	backupRunning     bool
	backupMessage     string
	recoveryRunning   bool
	recoveryMessage   string
	cutoverRunning    bool
	cutoverAction     string
	cutoverMessage    string
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5DB7DE"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#9099A3"))
	goodStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#78C091"))
	badStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E07A5F"))
)

func newModel() model {
	items := []list.Item{
		sectionItem{key: "overview", title: "Overview", description: "Installation state and readiness"},
		sectionItem{key: "installation", title: "Installation", description: "Reviewed install plan and durable operation"},
		sectionItem{key: "services", title: "Services and storage", description: "Local service and owned storage status"},
		sectionItem{key: "computers", title: "Computers and enrollment", description: "Endpoint enrollment and approvals"},
		sectionItem{key: "accounts", title: "Accounts and access", description: "Roles, manager approvals, and MFA"},
		sectionItem{key: "files", title: "Files and quotas", description: "Requests, transfers, and storage"},
		sectionItem{key: "network", title: "Network and certificates", description: "Local host and saved endpoint diagnostics"},
		sectionItem{key: "backup", title: "Backup and restore", description: "Encrypted backup and recovery"},
		sectionItem{key: "cutover", title: "Recovery cutover", description: "Drain and independently review restored authority"},
		sectionItem{key: "updates", title: "Updates and rollback", description: "Signed release and compatibility review"},
		sectionItem{key: "audit", title: "Diagnostics and support", description: "Health, audit availability, and redacted support data"},
		sectionItem{key: "removal", title: "Removal", description: "Remove owned resources and preserve data"},
	}
	menu := list.New(items, list.NewDefaultDelegate(), 34, 18)
	menu.Title = "Helicoid Server"
	menu.SetShowStatusBar(false)
	menu.SetFilteringEnabled(false)
	menu.SetShowHelp(false)
	return model{sections: menu}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(refreshStatus(m.generation), refreshCapabilities(m.generation), refreshHealth(m.generation))
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.sections.SetWidth(max(30, msg.Width/3))
		m.sections.SetHeight(max(10, msg.Height-8))
		return m, nil
	case statusMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		if msg.err != nil {
			m.statusError = msg.err.Error()
			m.status = nil
		} else {
			m.statusError = ""
			m.status = &msg.status
		}
		return m, nil
	case capabilitiesMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		if msg.err != nil {
			m.capsError = msg.err.Error()
			m.caps = nil
		} else {
			m.capsError = ""
			m.caps = &msg.capabilities
		}
		return m, nil
	case healthMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		if msg.err != nil {
			m.healthError = msg.err.Error()
			m.health = nil
		} else {
			m.healthError = ""
			m.health = &msg.health
		}
		return m, nil
	case doctorMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		m.doctor = &msg.report
		return m, nil
	case networkDiagnosticsMessage:
		if msg.generation != m.networkGeneration {
			return m, nil
		}
		m.networkLoading = false
		if msg.err != nil {
			m.network = nil
			m.networkError = msg.err.Error()
		} else {
			m.network = &msg.report
			m.networkError = ""
		}
		return m, nil
	case removeMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		m.removeRunning = false
		if msg.err != nil {
			m.removeError = msg.err.Error()
			return m, nil
		}
		m.removeError = ""
		m.status = &msg.status
		m.statusError = ""
		return m, nil
	case installerFinishedMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		m.installRunning = false
		if msg.err != nil {
			m.installError = msg.err.Error()
		} else {
			m.installError = ""
		}
		m.generation++
		return m, tea.Batch(
			refreshStatus(m.generation),
			refreshCapabilities(m.generation),
			refreshHealth(m.generation),
		)
	case bootstrapFinishedMessage:
		m.bootstrapRunning = false
		if msg.err != nil {
			m.bootstrapError = "Bootstrap command ended without success. Read its terminal output, then retry if enrollment is pending."
		} else {
			m.bootstrapError = ""
		}
		m.generation++
		return m, refreshHealth(m.generation)
	case accountsFinishedMessage:
		m.accountsRunning = false
		if msg.err != nil {
			m.accountsError = "Account listing did not complete. Read its terminal output for details."
		} else {
			m.accountsError = ""
		}
		return m, nil
	case computersFinishedMessage:
		m.computersRunning = false
		if msg.err != nil {
			m.computersError = "Computer or endpoint enrollment workflow did not complete. Read its terminal output for details."
		} else {
			m.computersError = ""
		}
		return m, nil
	case groupsFinishedMessage:
		m.groupsRunning = false
		if msg.err != nil {
			m.groupsError = "Computer group workflow did not complete. Read its terminal output for details."
		} else {
			m.groupsError = ""
		}
		return m, nil
	case managersFinishedMessage:
		m.managersRunning = false
		if msg.err != nil {
			m.managersError = "Management-device workflow did not complete. Read its terminal output for details."
		} else {
			m.managersError = ""
		}
		return m, nil
	case filesFinishedMessage:
		m.filesRunning = false
		if msg.err != nil {
			m.filesError = "File administration did not complete. Read its terminal output for details."
		} else {
			m.filesError = ""
		}
		return m, nil
	case supportFinishedMessage:
		m.supportRunning = false
		if msg.err != nil {
			m.supportMessage = badStyle.Render("Support bundle export did not complete. Read the terminal output for details.")
		} else {
			m.supportMessage = goodStyle.Render("Redacted support bundle exported. It contains no audit records or raw log lines.")
		}
		return m, nil
	case logsFinishedMessage:
		m.logsRunning = false
		if msg.err != nil {
			m.logsMessage = badStyle.Render("Recent service events are unavailable. Read the terminal output for the bounded status reason.")
		} else {
			m.logsMessage = goodStyle.Render("Recent allowlisted service events displayed; raw journal fields were excluded.")
		}
		return m, nil
	case auditFinishedMessage:
		m.auditRunning = false
		m.auditRetention = false
		if msg.err != nil {
			m.auditMessage = badStyle.Render("Audit operation did not complete. Check the security-admin role and fresh MFA, then review the terminal response.")
		} else if msg.retention {
			m.auditMessage = goodStyle.Render("Audit retention review completed.")
		} else {
			m.auditMessage = goodStyle.Render("Bounded audit metadata page displayed; the temporary MFA-backed session was revoked.")
		}
		return m, nil
	case backupFinishedMessage:
		m.backupRunning = false
		if msg.err != nil {
			m.backupMessage = badStyle.Render("Backup operation did not complete. Read its terminal output for details.")
		} else {
			m.backupMessage = goodStyle.Render("Backup operation completed.")
		}
		return m, nil
	case recoveryFinishedMessage:
		if msg.generation != m.generation {
			return m, nil
		}
		if msg.err != nil {
			m.recoveryMessage = badStyle.Render("Recovery review did not complete. Read its terminal output for details.")
		} else {
			m.recoveryMessage = goodStyle.Render("Recovery review completed; local health is refreshing.")
		}
		m.recoveryRunning = false
		m.generation++
		return m, tea.Batch(refreshHealth(m.generation), refreshStatus(m.generation))
	case cutoverFinishedMessage:
		m.cutoverRunning = false
		if msg.err != nil {
			m.cutoverMessage = badStyle.Render("Cutover command did not complete. Read the terminal output, then press l to reconcile the current authority state.")
		} else {
			m.cutoverMessage = goodStyle.Render("Cutover command completed. Press l to review the current authority state.")
		}
		if msg.action == "status" {
			return m, nil
		}
		m.generation++
		return m, tea.Batch(refreshHealth(m.generation), refreshStatus(m.generation))
	case tea.KeyPressMsg:
		if m.active == "removal" && m.removePrompt {
			return m.handleRemovalKey(msg)
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "Q":
			if m.active == "backup" {
				return m.startRecoveryCommand("release-quarantine")
			}
		case "r":
			if m.active == "files" {
				return m.startFilesCommand("requests", "list")
			}
			if m.active == "removal" && m.removeRunning {
				return m, nil
			}
			m.generation++
			m.doctor = nil
			commands := []tea.Cmd{
				refreshStatus(m.generation),
				refreshCapabilities(m.generation),
				refreshHealth(m.generation),
			}
			if m.active == "audit" {
				commands = append(commands, refreshDiagnostics(m.generation))
			} else if m.active == "network" {
				m.networkGeneration++
				m.networkLoading = true
				m.networkError = ""
				commands = append(commands, refreshNetworkDiagnostics(
					m.networkGeneration, m.currentNetworkConfiguration()))
			}
			return m, tea.Batch(commands...)
		case "enter":
			if selected, ok := m.sections.SelectedItem().(sectionItem); ok {
				m.active = selected.key
				if m.active == "audit" {
					return m, refreshDiagnostics(m.generation)
				} else if m.active == "network" {
					m.networkGeneration++
					m.networkLoading = true
					m.networkError = ""
					return m, refreshNetworkDiagnostics(
						m.networkGeneration, m.currentNetworkConfiguration())
				}
			}
		case "d":
			if m.active == "cutover" {
				return m.startCutoverCommand("drain")
			} else if m.active == "removal" {
				m.removeText = ""
				m.removeError = ""
				m.removePrompt = true
				return m, nil
			} else if m.active == "network" {
				m.networkGeneration++
				m.networkLoading = true
				m.networkError = ""
				return m, refreshNetworkDiagnostics(
					m.networkGeneration, m.currentNetworkConfiguration())
			}
			if m.active == "computers" {
				return m.startGroupsCommand("delete")
			} else if m.active == "files" {
				return m.startFilesCommand("requests", "close")
			}
		case "R":
			if m.active == "installation" && m.status != nil && m.status.ResumeAvailable && !m.installRunning {
				executable, err := os.Executable()
				if err != nil {
					m.installError = "Could not locate the running management application."
					return m, nil
				}
				m.installRunning = true
				m.installError = ""
				var command *exec.Cmd
				if m.status.Action == "remove" {
					command = exec.Command(executable, "installer", "remove", "--confirm")
				} else {
					command = exec.Command(executable, "installer", "resume")
				}
				generation := m.generation
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return installerFinishedMessage{generation: generation, err: err}
				})
			} else if m.active == "backup" {
				return m.startBackupCommand("restore")
			}
		case "D":
			if m.active == "backup" {
				return m.startBackupCommand("disable-schedule")
			}
		case "P":
			if m.active == "backup" {
				return m.startBackupCommand("prune")
			}
		case "b":
			if m.active == "accounts" && m.health != nil && !m.health.BootstrapCompleted && !m.bootstrapRunning {
				executable, err := os.Executable()
				if err != nil {
					m.bootstrapError = "Could not locate the running management application."
					return m, nil
				}
				m.bootstrapRunning = true
				m.bootstrapError = ""
				command := exec.Command(executable, "bootstrap")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return bootstrapFinishedMessage{err: err}
				})
			}
		case "l":
			if m.active == "cutover" {
				return m.startCutoverCommand("status")
			} else if m.active == "audit" && !m.logsRunning {
				executable, err := os.Executable()
				if err != nil {
					m.logsMessage = badStyle.Render("Could not locate the running management application.")
					return m, nil
				}
				m.logsRunning = true
				m.logsMessage = ""
				command := exec.Command(executable, "logs", "recent")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return logsFinishedMessage{err: err}
				})
			} else if m.active == "backup" {
				return m.startBackupCommand("list")
			} else if m.active == "accounts" && m.health != nil && m.health.BootstrapCompleted && !m.accountsRunning {
				executable, err := os.Executable()
				if err != nil {
					m.accountsError = "Could not locate the running management application."
					return m, nil
				}
				m.accountsRunning = true
				m.accountsError = ""
				command := exec.Command(executable, "accounts", "list")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return accountsFinishedMessage{err: err}
				})
			}
		case "A", "T":
			if m.active == "audit" && !m.auditRunning {
				executable, err := os.Executable()
				if err != nil {
					m.auditMessage = badStyle.Render("Could not locate the running management application.")
					return m, nil
				}
				m.auditRunning = true
				m.auditRetention = msg.String() == "T"
				m.auditMessage = ""
				commandArgs := []string{"audit", "recent"}
				if msg.String() == "T" {
					commandArgs = []string{"audit", "retention"}
				}
				command := exec.Command(executable, commandArgs...)
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return auditFinishedMessage{err: err, retention: msg.String() == "T"}
				})
			}
		case "n", "e", "s", "w":
			if m.active == "backup" && msg.String() == "s" {
				return m.startBackupCommand("schedule")
			} else if m.active == "audit" && msg.String() == "e" && !m.supportRunning {
				executable, err := os.Executable()
				if err != nil {
					m.supportMessage = badStyle.Render("Could not locate the running management application.")
					return m, nil
				}
				m.supportRunning = true
				m.supportMessage = ""
				command := exec.Command(executable, "support", "export")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return supportFinishedMessage{err: err}
				})
			} else if m.active == "accounts" && (msg.String() == "n" || msg.String() == "e" || msg.String() == "s") &&
				m.health != nil && m.health.BootstrapCompleted && !m.accountsRunning {
				executable, err := os.Executable()
				if err != nil {
					m.accountsError = "Could not locate the running management application."
					return m, nil
				}
				m.accountsRunning = true
				m.accountsError = ""
				var command *exec.Cmd
				switch msg.String() {
				case "n":
					command = exec.Command(executable, "accounts", "create")
				case "e":
					command = exec.Command(executable, "accounts", "capabilities")
				default:
					command = exec.Command(executable, "accounts", "state")
				}
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return accountsFinishedMessage{err: err}
				})
			} else if m.active == "computers" && (msg.String() == "n" || msg.String() == "e") {
				return m.startGroupsCommand(map[string]string{"n": "create", "e": "rename"}[msg.String()])
			} else if m.active == "files" && msg.String() == "n" {
				return m.startFilesCommand("requests", "create")
			} else if m.active == "files" && msg.String() == "s" {
				return m.startFilesCommand("requests", "submissions")
			} else if m.active == "files" && msg.String() == "w" {
				return m.startFilesCommand("requests", "download")
			}
		case "i", "g", "x", "p", "f":
			if m.active == "cutover" && msg.String() == "x" {
				return m.startCutoverCommand("cancel")
			} else if m.active == "backup" && msg.String() == "i" {
				return m.startRecoveryCommand("status")
			} else if m.active == "installation" && msg.String() == "i" && !m.installRunning {
				executable, err := os.Executable()
				if err != nil {
					m.installError = "Could not locate the running management application."
					return m, nil
				}
				m.installRunning = true
				m.installError = ""
				command := exec.Command(executable, "installer", "install")
				generation := m.generation
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return installerFinishedMessage{generation: generation, err: err}
				})
			} else if m.active == "accounts" && m.health != nil && m.health.BootstrapCompleted && !m.accountsRunning {
				executable, err := os.Executable()
				if err != nil {
					m.accountsError = "Could not locate the running management application."
					return m, nil
				}
				m.accountsRunning = true
				m.accountsError = ""
				var command *exec.Cmd
				switch msg.String() {
				case "i":
					command = exec.Command(executable, "accounts", "access", "list")
				case "g":
					command = exec.Command(executable, "accounts", "access", "grant")
				case "x":
					command = exec.Command(executable, "accounts", "access", "revoke")
				case "p":
					command = exec.Command(executable, "accounts", "mfa-policy")
				default:
					command = exec.Command(executable, "mfa", "recover")
				}
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return accountsFinishedMessage{err: err}
				})
			} else if m.active == "computers" && msg.String() == "g" {
				return m.startGroupsCommand("list")
			} else if m.active == "computers" && msg.String() == "i" {
				return m.startEndpointCommand("invitations")
			} else if m.active == "files" && msg.String() == "x" {
				return m.startFilesCommand("requests", "delete-submission")
			} else if m.active == "files" && msg.String() == "p" {
				return m.startFilesCommand("requests", "publish")
			} else if m.active == "files" && msg.String() == "f" &&
				m.health != nil && m.health.BootstrapCompleted && m.health.Features.FileJobs && !m.filesRunning {
				executable, err := os.Executable()
				if err != nil {
					m.filesError = "Could not locate the running management application."
					return m, nil
				}
				m.filesRunning = true
				m.filesError = ""
				command := exec.Command(executable, "files", "jobs")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return filesFinishedMessage{err: err}
				})
			}
		case "m":
			if m.active == "accounts" && m.health != nil && m.health.BootstrapCompleted && !m.managersRunning {
				executable, err := os.Executable()
				if err != nil {
					m.managersError = "Could not locate the running management application."
					return m, nil
				}
				m.managersRunning = true
				m.managersError = ""
				command := exec.Command(executable, "managers", "list")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return managersFinishedMessage{err: err}
				})
			} else if m.active == "computers" {
				return m.startGroupsCommand("member")
			}
		case "a":
			if m.active == "cutover" {
				return m.startCutoverCommand("approve")
			} else if m.active == "accounts" && m.health != nil && m.health.BootstrapCompleted && !m.managersRunning {
				executable, err := os.Executable()
				if err != nil {
					m.managersError = "Could not locate the running management application."
					return m, nil
				}
				m.managersRunning = true
				m.managersError = ""
				command := exec.Command(executable, "managers", "approve")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return managersFinishedMessage{err: err}
				})
			} else if m.active == "computers" {
				return m.startEndpointCommand("approve")
			}
		case "v":
			if m.active == "backup" {
				return m.startBackupCommand("verify")
			} else if m.active == "files" {
				return m.startFilesCommand("storage")
			} else if m.active == "accounts" && m.health != nil && m.health.BootstrapCompleted && !m.managersRunning {
				executable, err := os.Executable()
				if err != nil {
					m.managersError = "Could not locate the running management application."
					return m, nil
				}
				m.managersRunning = true
				m.managersError = ""
				command := exec.Command(executable, "managers", "revoke")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return managersFinishedMessage{err: err}
				})
			} else if m.active == "computers" {
				return m.startEndpointCommand("revoke")
			}
		case "j":
			if m.active == "computers" {
				return m.startEndpointCommand("invite")
			}
		case "k":
			if m.active == "computers" {
				return m.startEndpointCommand("revoke-invitation")
			}
		case "c":
			if m.active == "backup" {
				return m.startBackupCommand("create")
			} else if m.active == "computers" && m.health != nil && m.health.BootstrapCompleted && !m.computersRunning {
				executable, err := os.Executable()
				if err != nil {
					m.computersError = "Could not locate the running management application."
					return m, nil
				}
				m.computersRunning = true
				m.computersError = ""
				command := exec.Command(executable, "computers", "list")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return computersFinishedMessage{err: err}
				})
			} else if m.active == "files" && m.health != nil && m.health.BootstrapCompleted &&
				m.health.Features.FileJobs && !m.filesRunning {
				executable, err := os.Executable()
				if err != nil {
					m.filesError = "Could not locate the running management application."
					return m, nil
				}
				m.filesRunning = true
				m.filesError = ""
				command := exec.Command(executable, "files", "cancel")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return filesFinishedMessage{err: err}
				})
			}
		case "u":
			if m.active == "computers" && m.health != nil && m.health.BootstrapCompleted && !m.computersRunning {
				executable, err := os.Executable()
				if err != nil {
					m.computersError = "Could not locate the running management application."
					return m, nil
				}
				m.computersRunning = true
				m.computersError = ""
				command := exec.Command(executable, "computers", "enrollment-list")
				return m, tea.ExecProcess(command, func(err error) tea.Msg {
					return computersFinishedMessage{err: err}
				})
			}
		case "esc", "backspace":
			m.active = ""
		}
	}
	var command tea.Cmd
	m.sections, command = m.sections.Update(message)
	return m, command
}

func (m model) startGroupsCommand(action string) (tea.Model, tea.Cmd) {
	if m.health == nil || !m.health.BootstrapCompleted || m.groupsRunning {
		return m, nil
	}
	executable, err := os.Executable()
	if err != nil {
		m.groupsError = "Could not locate the running management application."
		return m, nil
	}
	m.groupsRunning = true
	m.groupsError = ""
	command := exec.Command(executable, "groups", action)
	return m, tea.ExecProcess(command, func(err error) tea.Msg {
		return groupsFinishedMessage{err: err}
	})
}

func (m model) startRecoveryCommand(action string) (tea.Model, tea.Cmd) {
	if m.health == nil || !m.health.BootstrapCompleted || m.recoveryRunning {
		return m, nil
	}
	executable, err := os.Executable()
	if err != nil {
		m.recoveryMessage = badStyle.Render("Could not locate the running management application.")
		return m, nil
	}
	m.recoveryRunning = true
	m.recoveryMessage = ""
	command := exec.Command(executable, "recovery", action)
	generation := m.generation
	return m, tea.ExecProcess(command, func(err error) tea.Msg {
		return recoveryFinishedMessage{generation: generation, err: err}
	})
}

func (m model) startEndpointCommand(action string) (tea.Model, tea.Cmd) {
	if m.health == nil || !m.health.BootstrapCompleted || m.computersRunning {
		return m, nil
	}
	executable, err := os.Executable()
	if err != nil {
		m.computersError = "Could not locate the running management application."
		return m, nil
	}
	m.computersRunning = true
	m.computersError = ""
	command := exec.Command(executable, "enrollment", action)
	return m, tea.ExecProcess(command, func(err error) tea.Msg {
		return computersFinishedMessage{err: err}
	})
}

func (m model) startFilesCommand(args ...string) (tea.Model, tea.Cmd) {
	requiresFileJobFeature := len(args) == 0 || args[0] != "requests"
	if m.health == nil || !m.health.BootstrapCompleted ||
		(requiresFileJobFeature && !m.health.Features.FileJobs) || m.filesRunning {
		return m, nil
	}
	executable, err := os.Executable()
	if err != nil {
		m.filesError = "Could not locate the running management application."
		return m, nil
	}
	m.filesRunning = true
	m.filesError = ""
	commandArgs := append([]string{"files"}, args...)
	command := exec.Command(executable, commandArgs...)
	return m, tea.ExecProcess(command, func(err error) tea.Msg {
		return filesFinishedMessage{err: err}
	})
}

func (m model) startBackupCommand(action string) (tea.Model, tea.Cmd) {
	if m.backupRunning {
		return m, nil
	}
	dataDirectory := ""
	if m.status != nil {
		dataDirectory = m.status.Configuration.Storage.DataDirectory
	}
	var args []string
	var err error
	if action == "prune" || action == "list" {
		backupDirectory := ""
		if m.status != nil {
			backupDirectory = m.status.Configuration.Storage.BackupDirectory
		}
		if action == "prune" {
			args, err = backupPruneCommandArgs(backupDirectory)
		} else {
			args, err = backupListCommandArgs(backupDirectory)
		}
	} else {
		args, err = backupCommandArgs(action, dataDirectory)
	}
	if err != nil {
		m.backupMessage = badStyle.Render(err.Error())
		return m, nil
	}
	if (action == "schedule" || action == "disable-schedule") && (m.status == nil || !supportsBackupSchedule(m.status.Configuration.DeploymentKind)) {
		m.backupMessage = badStyle.Render("Scheduled backups require an installed Linux systemd or Compose deployment.")
		return m, nil
	}
	var backend string
	if action == "schedule" || action == "disable-schedule" {
		backend, err = resolvePrivilegedBackend()
	} else {
		backend, err = resolveBackend()
	}
	if err != nil {
		m.backupMessage = badStyle.Render("Could not locate the installed server backend.")
		return m, nil
	}
	m.backupRunning = true
	m.backupMessage = ""
	var command *exec.Cmd
	if (action == "schedule" || action == "disable-schedule") && os.Geteuid() != 0 && !isContainerEnvironment() {
		command = exec.Command("/usr/bin/sudo", append([]string{backend}, args...)...)
	} else {
		command = exec.Command(backend, args...)
	}
	return m, tea.ExecProcess(command, func(err error) tea.Msg {
		return backupFinishedMessage{err: err}
	})
}

func isContainerEnvironment() bool {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return false
	}
	return true
}

func supportsBackupSchedule(deploymentKind string) bool {
	return deploymentKind == "linux_systemd" || deploymentKind == "linux_compose"
}

func backupPruneCommandArgs(backupDirectory string) ([]string, error) {
	if !filepath.IsAbs(backupDirectory) {
		return nil, fmt.Errorf("server backup directory is unavailable; refresh installation status first")
	}
	return []string{"backup", "prune", "--directory", backupDirectory}, nil
}

func backupListCommandArgs(backupDirectory string) ([]string, error) {
	if !filepath.IsAbs(backupDirectory) {
		return nil, fmt.Errorf("server backup directory is unavailable; refresh installation status first")
	}
	return []string{"backup", "list", "--directory", backupDirectory}, nil
}

func backupCommandArgs(action string, dataDirectory string) ([]string, error) {
	if action == "schedule" {
		return []string{"backup", "enable-schedule"}, nil
	}
	if action == "disable-schedule" {
		return []string{"backup", "disable-schedule"}, nil
	}
	if action == "create" {
		if !filepath.IsAbs(dataDirectory) {
			return nil, fmt.Errorf("server data directory is unavailable; refresh installation status first")
		}
		return []string{
			"--data", filepath.Join(dataDirectory, "hs-server.db"),
			"backup", "create", "--passphrase-stdin",
		}, nil
	}
	if action == "verify" || action == "restore" {
		return []string{"backup", action, "--passphrase-stdin"}, nil
	}
	return nil, fmt.Errorf("unsupported backup action")
}

func (m model) View() tea.View {
	var content string
	if m.active == "" {
		content = m.overview()
	} else if m.active == "audit" {
		content = m.diagnostics()
	} else {
		content = m.sectionDetail()
	}
	left := m.sections.View()
	if m.width > 0 {
		left = lipgloss.NewStyle().Width(max(30, m.width/3)).Render(left)
		content = lipgloss.NewStyle().Width(max(34, m.width-m.width/3-4)).PaddingLeft(2).Render(content)
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, content)
	help := mutedStyle.Render("↑/↓ navigate   enter open   i install/access/invitations   R resume/restore   b bootstrap   l list backups/accounts/logs/cutover   A audit page   T audit retention   n new account/group/request   e export support/roles/rename group   s state/submissions/schedule backup   w download received file   g grant/groups   x revoke access/delete content/cancel cutover   p MFA policy/publish request   f recover MFA/list file jobs   m managers/membership   a approve/cutover review   v quota/revoke access/verify backup   c computers/cancel file job/create backup   u enrollment inventory   j issue invite   k revoke invite   d remove/delete/close/drain cutover/network diagnostics   P prune backups   D disable backup schedule   r refresh/list requests   esc back   q quit")
	view := tea.NewView(titleStyle.Render("HELICOID SERVER") + "\n\n" + body + "\n\n" + help)
	view.AltScreen = true
	return view
}

func (m model) overview() string {
	var lines []string
	lines = append(lines, titleStyle.Render("Installation status"))
	if m.statusError != "" {
		lines = append(lines, badStyle.Render("Status unavailable"), m.statusError)
	} else if m.status == nil {
		lines = append(lines, mutedStyle.Render("Loading status from the local installer backend."))
	} else {
		lines = append(lines,
			fmt.Sprintf("State: %s", m.status.State),
			fmt.Sprintf("Action: %s", optionalString(m.status.Action)),
			fmt.Sprintf("Current phase: %s", optionalText(m.status.CurrentPhase)),
			fmt.Sprintf("Operation: %s", optionalText(m.status.OperationID)),
			fmt.Sprintf("Service installed: %t", m.status.ServiceInstalled),
			fmt.Sprintf("Bootstrap ready: %t", m.status.BootstrapReady),
			fmt.Sprintf("Ready for enrollment: %t", m.status.ServerReadyForEnrollment),
			"Public integration: Pending; DNS, certificate trust, firewall, and proxy are not validated by this lifecycle backend.",
			"Deployment verification: Not recorded; it requires authorized endpoint runtime evidence.",
			fmt.Sprintf("Resume available: %t", m.status.ResumeAvailable),
			fmt.Sprintf("Cancellation available: %t", m.status.CancellationAvailable),
		)
		phaseNames := make([]string, 0, len(m.status.Phases))
		for name := range m.status.Phases {
			phaseNames = append(phaseNames, name)
		}
		sort.Strings(phaseNames)
		for _, name := range phaseNames {
			lines = append(lines, fmt.Sprintf("  %s: %s", name, m.status.Phases[name]))
		}
		if m.status.Result.Summary != "" {
			lines = append(lines, "", m.status.Result.Summary)
		}
		for _, message := range m.status.Result.Errors {
			lines = append(lines, badStyle.Render("Error: "+message))
		}
		for _, message := range m.status.Result.Warnings {
			lines = append(lines, "Warning: "+message)
		}
	}
	lines = append(lines, "", titleStyle.Render("Backend capabilities"))
	if m.capsError != "" {
		lines = append(lines, badStyle.Render("Capabilities unavailable"), m.capsError)
	} else if m.caps == nil {
		lines = append(lines, mutedStyle.Render("Loading capabilities."))
	} else {
		lines = append(lines,
			"Deployment kinds: "+joinOrNone(m.caps.SupportedDeploymentKinds),
			"Network scopes: "+joinOrNone(m.caps.SupportedNetworkScopes),
			"Actions: "+joinOrNone(m.caps.SupportedActions),
		)
	}
	lines = append(lines, "", titleStyle.Render("Local server health"))
	if m.healthError != "" {
		lines = append(lines, badStyle.Render("Health unavailable"), m.healthError)
	} else if m.health == nil {
		lines = append(lines, mutedStyle.Render("Checking http://127.0.0.1:8787/health."))
	} else {
		lines = append(lines,
			fmt.Sprintf("HTTP state: %s", m.health.Status),
			fmt.Sprintf("Accepting authorized operations: %t", m.health.AcceptingAuthorizedOperations),
			fmt.Sprintf("Bootstrap completed: %t", m.health.BootstrapCompleted),
			fmt.Sprintf("Recovery quarantine: %t", m.health.RecoveryQuarantined),
			fmt.Sprintf("Storage schema: %d", m.health.StorageSchemaVersion),
			fmt.Sprintf("Screen observation: %t", m.health.Features.ScreenObservation),
			fmt.Sprintf("Remote control: %t", m.health.Features.RemoteControl),
			fmt.Sprintf("File jobs: %t", m.health.Features.FileJobs),
		)
	}
	return strings.Join(lines, "\n")
}

func (m model) diagnostics() string {
	var lines []string
	lines = append(lines, titleStyle.Render("Diagnostics and support"),
		"Local, read-only checks from this server.",
		"Press l to view bounded, redacted service events; press A to view audit records; press T to review or update retention; press e to export a bounded support bundle.",
		"Audit records require a security-admin account and a fresh MFA challenge. They are allowlisted metadata; raw logs and audit records are not exported. Compose events come through the verified host control socket.", "")
	if m.doctor == nil {
		lines = append(lines, mutedStyle.Render("Checking local health, capabilities, and host preflight."))
		return strings.Join(lines, "\n")
	}
	if m.doctor.OK {
		lines = append(lines, goodStyle.Render("All currently available doctor checks passed."))
	} else {
		lines = append(lines, badStyle.Render("One or more checks need attention."))
	}
	if m.doctor.Health != nil {
		lines = append(lines, fmt.Sprintf("Server health: %s; authorized operations: %t; bootstrap complete: %t",
			m.doctor.Health.Status,
			m.doctor.Health.AcceptingAuthorizedOperations,
			m.doctor.Health.BootstrapCompleted))
	}
	if m.doctor.Preflight != nil {
		lines = append(lines, fmt.Sprintf("Host preflight: %t", m.doctor.Preflight.OK))
		var indented bytes.Buffer
		if err := json.Indent(&indented, m.doctor.Preflight.HostChecks, "", "  "); err == nil {
			lines = append(lines, "", indented.String())
		}
	}
	for _, message := range m.doctor.Errors {
		lines = append(lines, "• "+message)
	}
	if m.doctor.Capabilities != nil {
		lines = append(lines, "", "Supported actions: "+joinOrNone(m.doctor.Capabilities.SupportedActions))
		keys := make([]string, 0, len(m.doctor.Capabilities.ReasonsUnavailable))
		for key := range m.doctor.Capabilities.ReasonsUnavailable {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lines = append(lines, "• "+m.doctor.Capabilities.ReasonsUnavailable[key])
		}
	}
	if m.supportRunning {
		lines = append(lines, "", mutedStyle.Render("Preparing the support bundle. Enter a new output file path in the terminal."))
	} else if m.supportMessage != "" {
		lines = append(lines, "", m.supportMessage)
	}
	if m.logsRunning {
		lines = append(lines, "", mutedStyle.Render("Reading at most 100 allowlisted service events from the last 15 minutes."))
	} else if m.logsMessage != "" {
		lines = append(lines, "", m.logsMessage)
	}
	if m.auditRunning {
		progress := "Opening a short-lived MFA-backed session to read the latest 50 audit events."
		if m.auditRetention {
			progress = "Opening a short-lived MFA-backed session to review the retention policy."
		}
		lines = append(lines, "", mutedStyle.Render(progress))
	} else if m.auditMessage != "" {
		lines = append(lines, "", m.auditMessage)
	}
	lines = append(lines, "", mutedStyle.Render("Press r to refresh. This report does not claim deployment verification."))
	return strings.Join(lines, "\n")
}

func (m model) sectionDetail() string {
	selected, ok := m.sections.SelectedItem().(sectionItem)
	if !ok {
		return mutedStyle.Render("Select a section from the menu.")
	}
	var lines []string
	lines = append(lines, titleStyle.Render(selected.title), selected.description, "")
	if m.active == "overview" {
		return m.overview()
	}
	if m.active == "installation" {
		return m.installationDetail()
	}
	if m.active == "services" {
		return m.servicesDetail()
	}
	if m.active == "removal" {
		return m.removalDetail()
	}
	if m.active == "accounts" {
		return m.accountsDetail()
	}
	if m.active == "computers" {
		return m.computersDetail()
	}
	if m.active == "files" {
		return m.filesDetail()
	}
	if m.active == "backup" {
		return m.backupDetail()
	}
	if m.active == "cutover" {
		return m.cutoverDetail()
	}
	if m.active == "updates" {
		return m.updatesDetail()
	}
	if m.active == "network" {
		return m.networkDetail()
	}
	if m.capsError != "" {
		lines = append(lines, badStyle.Render("Capability discovery failed."), m.capsError)
		return strings.Join(lines, "\n")
	}
	lines = append(lines, mutedStyle.Render("This workflow is not available in the current backend build."))
	if m.caps != nil {
		keys := make([]string, 0, len(m.caps.ReasonsUnavailable))
		for key := range m.caps.ReasonsUnavailable {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lines = append(lines, "• "+m.caps.ReasonsUnavailable[key])
		}
	}
	lines = append(lines, "", mutedStyle.Render("Use the current installer capability report as the source of truth."))
	return strings.Join(lines, "\n")
}

func (m model) backupDetail() string {
	lines := []string{
		titleStyle.Render("Encrypted database snapshots"),
		"Create, verify, or restore passphrase-encrypted SQLite snapshots on Unix.",
		"Backup and restore commands prompt in the terminal for paths and the no-echo passphrase. Retention prompts for a keep count and typed confirmation.",
		"Run the command as the Unix owner of the server database so private-store ownership checks pass.",
		"",
		"Press l to list archives, c to create, v to verify, R to restore, s to enable, D to disable the daily schedule, or P to prune older scheduled archives.",
		"After a fresh bootstrap on a restored service, press i to review recovery quarantine or Q to run its explicit, locally authorized release flow. Press q to quit.",
		"",
		"Creation asks for the same passphrase twice; the no-echo prompt requires at least 16 bytes. Keep it separately from the server and backup file.",
		"Verification decrypts to a private temporary database and checks SQLite integrity, foreign keys, and schema compatibility.",
		"Restore publishes only to a new private database path after verification, then revokes restored sessions and pending authority. It does not switch the running service to that database.",
		"The daily schedule requires systemd 250 or newer and stores its passphrase as a systemd encrypted credential using host-local keys, with TPM binding when available. Save the phrase independently so backups remain recoverable after host loss.",
		"P asks how many newest scheduled archives to keep and requires you to type an explicit confirmation before it removes older matching archives.",
		"This is database-only recovery. TLS keys, external signing keys, and host cutover remain outside the database restore workflow.",
	}
	if m.backupRunning {
		lines = append(lines, "", mutedStyle.Render("Backup command is running in the terminal."))
	} else if m.backupMessage != "" {
		lines = append(lines, "", m.backupMessage)
	}
	if m.recoveryRunning {
		lines = append(lines, "", mutedStyle.Render("Recovery review is running in the terminal."))
	} else if m.recoveryMessage != "" {
		lines = append(lines, "", m.recoveryMessage)
	}
	return strings.Join(lines, "\n")
}

func (m model) cutoverDetail() string {
	lines := []string{
		titleStyle.Render("Recovery authority cutover"),
		"Server-local authority transition controls for a planned restore to a replacement host.",
		"These commands require an authenticated security administrator and exact typed confirmations.",
		"",
		"Press l to inspect the local authority, d to drain the active predecessor, a to approve the restored host after independent fencing review, or x to cancel a still-cancellable drain.",
		"",
		"Drain pauses ordinary authority on this server. End active interactions and settle or cancel pending grants and file jobs first.",
		"Approval records an operator attestation; it cannot prove that the predecessor was powered off or fenced.",
		"The restored deployment remains quarantined until its separate recovery review is released.",
		"",
		"Two-host coordination, peer trust reconciliation, and independent proof of predecessor fencing are not provided by these local commands.",
	}
	if m.cutoverRunning {
		lines = append(lines, "", mutedStyle.Render(fmt.Sprintf("Running the local %s cutover command in the terminal.", m.cutoverAction)))
	} else if m.cutoverMessage != "" {
		lines = append(lines, "", m.cutoverMessage)
	}
	return strings.Join(lines, "\n")
}

func (m model) updatesDetail() string {
	lines := []string{
		titleStyle.Render("Signed updates and rollback"),
		"Release packages are verified against a separately trusted Ed25519 key before installation.",
		"",
	}
	if m.capsError != "" {
		lines = append(lines, badStyle.Render("Lifecycle capability discovery failed."), m.capsError)
		return strings.Join(lines, "\n")
	}
	if m.caps == nil {
		lines = append(lines, mutedStyle.Render("Loading the lifecycle capability report."))
		return strings.Join(lines, "\n")
	}

	lines = append(lines,
		fmt.Sprintf("Online update: %t", m.caps.OnlineUpdate),
		fmt.Sprintf("Lifecycle backup and restore: %t", m.caps.BackupAndRestore),
		fmt.Sprintf("Update action advertised: %t", containsText(m.caps.SupportedActions, "update")),
		fmt.Sprintf("Rollback action advertised: %t", containsText(m.caps.SupportedActions, "rollback")),
		"",
	)
	updateReason := m.caps.ReasonsUnavailable["online_update"]
	restoreReason := m.caps.ReasonsUnavailable["backup_and_restore"]
	legacyReason := m.caps.ReasonsUnavailable["online_update_backup_restore"]
	if updateReason == "" && restoreReason == "" && legacyReason != "" {
		lines = append(lines, badStyle.Render("Update and deployment recovery are unavailable."), legacyReason)
	} else {
		if !m.caps.OnlineUpdate || !containsText(m.caps.SupportedActions, "update") {
			lines = append(lines, badStyle.Render("Signed online updates and service rollback are unavailable."))
			if updateReason != "" {
				lines = append(lines, updateReason)
			} else if legacyReason != "" {
				lines = append(lines, legacyReason)
			}
		}
		if !m.caps.BackupAndRestore || !containsText(m.caps.SupportedActions, "restore") {
			lines = append(lines, badStyle.Render("Lifecycle deployment backup and restore are unavailable."))
			if restoreReason != "" {
				lines = append(lines, restoreReason)
			} else if legacyReason != "" && updateReason != "" {
				lines = append(lines, legacyReason)
			}
		}
	}
	lines = append(lines,
		"",
		"Installation can review a signed Linux package and apply its exact canonical plan from the Installation screen.",
		"Encrypted database backup and restore-to-new-file are separate workflows under Backup and restore; they do not roll back service binaries or switch the running deployment.",
		"Use the Recovery Cutover screen for the server-local predecessor drain and restored-authority review.",
	)
	return strings.Join(lines, "\n")
}

func (m model) startCutoverCommand(action string) (tea.Model, tea.Cmd) {
	if m.cutoverRunning {
		return m, nil
	}
	if !oneOf(action, "status", "drain", "approve", "cancel") {
		m.cutoverMessage = badStyle.Render("Unsupported local cutover action.")
		return m, nil
	}
	executable, err := os.Executable()
	if err != nil {
		m.cutoverMessage = badStyle.Render("Could not locate the running management application.")
		return m, nil
	}
	m.cutoverRunning = true
	m.cutoverAction = action
	m.cutoverMessage = ""
	command := exec.Command(executable, "cutover", action)
	return m, tea.ExecProcess(command, func(err error) tea.Msg {
		return cutoverFinishedMessage{action: action, err: err}
	})
}

func (m model) servicesDetail() string {
	lines := []string{titleStyle.Render("Services and storage"), "Read-only status from the local lifecycle backend.", ""}
	if m.statusError != "" {
		lines = append(lines, badStyle.Render("Lifecycle status unavailable."), m.statusError)
		return strings.Join(lines, "\n")
	}
	if m.status == nil {
		lines = append(lines, mutedStyle.Render("Loading the current installation configuration and service state."))
		return strings.Join(lines, "\n")
	}
	lines = append(lines,
		fmt.Sprintf("Deployment kind: %s", m.status.Configuration.DeploymentKind),
		fmt.Sprintf("Service installed: %t", m.status.ServiceInstalled),
		fmt.Sprintf("Ready for enrollment: %t", m.status.ServerReadyForEnrollment),
		fmt.Sprintf("Data directory: %s", m.status.Configuration.Storage.DataDirectory),
		fmt.Sprintf("Backup directory: %s", m.status.Configuration.Storage.BackupDirectory),
		fmt.Sprintf("Preserve data on removal: %t", m.status.Configuration.Storage.PreserveDataOnRemoval),
		fmt.Sprintf("Lifecycle operation: %s (%s)", m.status.State, optionalString(m.status.Action)),
		fmt.Sprintf("Current phase: %s", optionalText(m.status.CurrentPhase)),
	)
	phaseNames := make([]string, 0, len(m.status.Phases))
	for name := range m.status.Phases {
		phaseNames = append(phaseNames, name)
	}
	sort.Strings(phaseNames)
	if len(phaseNames) > 0 {
		lines = append(lines, "", titleStyle.Render("Journal phases"))
		for _, name := range phaseNames {
			lines = append(lines, fmt.Sprintf("%s: %s", name, m.status.Phases[name]))
		}
	}
	lines = append(lines, "", titleStyle.Render("Available lifecycle operations"))
	if m.capsError != "" {
		lines = append(lines, badStyle.Render("Capability discovery unavailable."), m.capsError)
	} else if m.caps == nil {
		lines = append(lines, mutedStyle.Render("Loading backend capabilities."))
	} else {
		lines = append(lines, "Supported actions: "+joinOrNone(m.caps.SupportedActions))
		lines = append(lines,
			fmt.Sprintf("Durable operation journal: %t", m.caps.DurableOperationJournal),
			fmt.Sprintf("Cancellation: %t", m.caps.Cancellation),
			fmt.Sprintf("Online update: %t", m.caps.OnlineUpdate),
			fmt.Sprintf("Backup and restore: %t", m.caps.BackupAndRestore),
		)
		if reason := m.caps.ReasonsUnavailable["service_repair"]; reason != "" {
			lines = append(lines, "Service repair: "+reason)
		}
		updateReason := m.caps.ReasonsUnavailable["online_update"]
		restoreReason := m.caps.ReasonsUnavailable["backup_and_restore"]
		cutoverReason := m.caps.ReasonsUnavailable["cutover"]
		legacyReason := m.caps.ReasonsUnavailable["online_update_backup_restore"]
		if updateReason != "" {
			lines = append(lines, "Online update and rollback: "+updateReason)
		}
		if restoreReason != "" {
			lines = append(lines, "Deployment restore: "+restoreReason)
		}
		if cutoverReason != "" {
			lines = append(lines, "Authority cutover: "+cutoverReason)
		}
		if updateReason == "" && restoreReason == "" && cutoverReason == "" && legacyReason != "" {
			lines = append(lines, "Update and recovery: "+legacyReason)
		}
	}
	lines = append(lines, "", mutedStyle.Render("Press r to refresh. Host mutation and storage recovery are not exposed by this backend capability set."))
	return strings.Join(lines, "\n")
}

func (m model) filesDetail() string {
	lines := []string{titleStyle.Render("Files and requests"), "File delivery jobs and owner-scoped requests.", ""}
	if m.healthError != "" {
		lines = append(lines, badStyle.Render("Local server health is unavailable."), m.healthError)
		return strings.Join(lines, "\n")
	}
	if m.health == nil {
		lines = append(lines, mutedStyle.Render("Checking local server feature availability."))
		return strings.Join(lines, "\n")
	}
	if m.health.Features.FileJobs {
		lines = append(lines, "Press f to list owned jobs or c to cancel an uploading or queued job after exact ID confirmation.")
	} else {
		lines = append(lines, mutedStyle.Render("File delivery jobs are disabled by this deployment."))
	}
	lines = append(lines, "Press v to view logical payload quota, r to list owned file requests, n to create a draft, p to publish, s to review submissions, w to save a received file, x to delete retained submission content, or d to close an open request.")
	lines = append(lines,
		"Mutations show the exact target and require explicit confirmation. Commands authenticate with an approved manager key and MFA.",
		"The list is bounded by the server page limit and the short-lived session is revoked when the command finishes.",
		"Quota reporting covers logical active reservations and retained received files. Manual content removal releases active quota; database free pages and old backups can still contain prior bytes.",
	)
	if m.filesRunning {
		lines = append(lines, "", mutedStyle.Render("Complete the file history sign-in prompts in the terminal."))
	}
	if m.filesError != "" {
		lines = append(lines, "", badStyle.Render(m.filesError))
	}
	return strings.Join(lines, "\n")
}

func (m model) computersDetail() string {
	lines := []string{titleStyle.Render("Computers and enrollment"), "Authorized server inventory.", ""}
	if m.healthError != "" {
		lines = append(lines, badStyle.Render("Local server health is unavailable."), m.healthError)
		return strings.Join(lines, "\n")
	}
	if m.health == nil {
		lines = append(lines, mutedStyle.Render("Checking local server bootstrap state."))
		return strings.Join(lines, "\n")
	}
	if !m.health.BootstrapCompleted {
		lines = append(lines, mutedStyle.Render("Complete first-administrator bootstrap before reading inventory."))
		return strings.Join(lines, "\n")
	}
	lines = append(lines,
		"Press c to sign in with the approved manager key and MFA, then read computers assigned to that account.",
		"The list contains server-side enrollment metadata only. Screen observation and control are unavailable.",
		"The command revokes its short-lived session when it finishes.",
		"Press g to list groups, n to create, e to rename, m to change membership, or d to delete a group.",
		"Groups are labels only. Membership never grants access; each mutation requires enrollment permission and confirmation.",
		"Press i to list invitations, j to issue one, k to revoke an unredeemed code, a to approve a proof-backed endpoint, or v to revoke an endpoint.",
		"Invitation codes display once and expire after 15 minutes. Endpoint approval and revocation require fresh MFA and advance the enrollment epoch.",
	)
	if m.computersRunning {
		lines = append(lines, "", mutedStyle.Render("Complete the inventory sign-in prompts in the terminal."))
	}
	if m.computersError != "" {
		lines = append(lines, "", badStyle.Render(m.computersError))
	}
	if m.groupsRunning {
		lines = append(lines, "", mutedStyle.Render("Complete the group administration prompts in the terminal."))
	}
	if m.groupsError != "" {
		lines = append(lines, "", badStyle.Render(m.groupsError))
	}
	return strings.Join(lines, "\n")
}

func (m model) accountsDetail() string {
	lines := []string{titleStyle.Render("Accounts and access"), "First administrator setup and account administration.", ""}
	if m.healthError != "" {
		lines = append(lines, badStyle.Render("Local server health is unavailable."), m.healthError)
		return strings.Join(lines, "\n")
	}
	if m.health == nil {
		lines = append(lines, mutedStyle.Render("Checking local server bootstrap state."))
		return strings.Join(lines, "\n")
	}
	if m.health.BootstrapCompleted {
		lines = append(lines,
			goodStyle.Render("First administrator bootstrap is complete."),
			"Press l to sign in with the approved manager key and MFA, then list authorized accounts.",
			"Press n to create an account with mandatory MFA, e to change capabilities, or s to enable or disable an account.",
			"Press m to list management devices, a to approve a device, or v to revoke one. Each change requires exact ID confirmation and fresh MFA.",
			"Account provisioning displays one-time MFA and recovery material for independent storage; changes use revision checks and revoke the short-lived session when they finish.",
			"Press i to list access assignments, g to grant scoped access, or p to review and change the operator MFA policy.",
			"Press f for factor recovery with the account password and one unused recovery code; recovery does not create a session or reset the password.",
			"Access revocation uses the assignment's current server revision and exact confirmation. File delivery and requests are available in Files; screen observation and control remain unavailable from this TUI.",
		)
		if m.accountsRunning {
			lines = append(lines, "", mutedStyle.Render("Complete the account workflow prompts in the terminal."))
		}
		if m.accountsError != "" {
			lines = append(lines, "", badStyle.Render(m.accountsError))
		}
		if m.managersRunning {
			lines = append(lines, "", mutedStyle.Render("Complete the management-device sign-in prompts in the terminal."))
		}
		if m.managersError != "" {
			lines = append(lines, "", badStyle.Render(m.managersError))
		}
		return strings.Join(lines, "\n")
	}
	if !m.health.Features.MFA || !m.health.Features.ManagerEnrollment {
		lines = append(lines, badStyle.Render("This server build does not advertise the required MFA and manager-enrollment features."))
		return strings.Join(lines, "\n")
	}
	if m.bootstrapRunning {
		lines = append(lines, mutedStyle.Render("Complete the one-time bootstrap prompts in the terminal."))
	} else {
		lines = append(lines,
			"Create the first administrator with mandatory TOTP MFA and recovery material.",
			"The bootstrap token and password are entered without echo and never placed in command arguments.",
			"Recovery codes are shown once; save them away from this server before activating the account.",
			"",
			"Press b to start the interactive bootstrap.",
		)
	}
	if m.bootstrapError != "" {
		lines = append(lines, "", badStyle.Render(m.bootstrapError), "Retry MFA confirmation with: helicoid-server mfa confirm ENROLLMENT_ID")
	}
	return strings.Join(lines, "\n")
}

func (m model) removalDetail() string {
	lines := []string{
		titleStyle.Render("Remove Helicoid Server"),
		"The v2 removal removes journaled Helicoid service resources and keeps data and backups.",
	}
	if m.capsError != "" {
		lines = append(lines, "", badStyle.Render("Capability discovery failed."), m.capsError)
		return strings.Join(lines, "\n")
	}
	if m.caps == nil {
		lines = append(lines, "", mutedStyle.Render("Loading installer capabilities."))
		return strings.Join(lines, "\n")
	}
	if !containsText(m.caps.SupportedActions, "remove") {
		lines = append(lines, "", mutedStyle.Render("Removal is unavailable in this backend build."))
		return strings.Join(lines, "\n")
	}
	if m.statusError != "" {
		lines = append(lines, "", badStyle.Render("Installation status unavailable."), m.statusError)
		return strings.Join(lines, "\n")
	}
	if m.status == nil {
		lines = append(lines, "", mutedStyle.Render("Loading the current installation status."))
		return strings.Join(lines, "\n")
	}
	lines = append(lines, "", fmt.Sprintf("Current state: %s", m.status.State))
	if m.status.State == "not_installed" {
		lines = append(lines, mutedStyle.Render("No installation is recorded."))
		return strings.Join(lines, "\n")
	}
	if m.status.Action == "remove" && m.status.State == "completed" {
		lines = append(lines, goodStyle.Render("The latest removal completed."))
	}
	if m.removeRunning {
		lines = append(lines, mutedStyle.Render("Removing owned service resources; keeping data and backups."))
	}
	if m.removeError != "" {
		lines = append(lines, badStyle.Render("Removal command failed: "+m.removeError))
	}
	if m.status.Result.Summary != "" {
		lines = append(lines, m.status.Result.Summary)
	}
	for _, message := range m.status.Result.Errors {
		lines = append(lines, badStyle.Render("Error: "+message))
	}
	if m.removePrompt {
		lines = append(lines, "", "Type remove helicoid server and press enter to confirm:", "> "+m.removeText+"_")
		lines = append(lines, mutedStyle.Render("Press esc to cancel. Data and backups will be preserved."))
	} else if !m.removeRunning && m.status.State != "not_installed" &&
		!(m.status.Action == "remove" && m.status.State == "completed") {
		lines = append(lines, "", "Press d to begin removal confirmation.")
	}
	return strings.Join(lines, "\n")
}

func (m model) handleRemovalKey(message tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := strings.ToLower(message.String())
	switch key {
	case "esc":
		m.removePrompt = false
		m.removeText = ""
		return m, nil
	case "enter":
		if m.removeText != "remove helicoid server" {
			m.removeError = "confirmation text did not match"
			m.removeText = ""
			return m, nil
		}
		m.removePrompt = false
		m.removeRunning = true
		m.removeText = ""
		m.removeError = ""
		return m, removeInstallation(m.generation)
	case "backspace":
		if len(m.removeText) > 0 {
			m.removeText = m.removeText[:len(m.removeText)-1]
		}
		return m, nil
	case "space", " ":
		m.removeText += " "
		return m, nil
	default:
		if len(key) == 1 && key[0] >= 'a' && key[0] <= 'z' {
			m.removeText += key
		}
		return m, nil
	}
}

func removeInstallation(generation uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		configuration, err := loadStoredConfiguration(ctx)
		if err != nil {
			return removeMessage{generation: generation, err: err}
		}
		configuration.Storage.PreserveDataOnRemoval = true
		var status operationStatus
		err = callBackendArgs(ctx, []string{
			"remove-v2", "--state-dir", "/opt/helicoid/.installer",
		}, removeV2Input{
			ContractVersion: 2,
			Configuration:   configuration,
			Confirm:         true,
		}, &status)
		if err == nil && status.State != "completed" && status.State != "not_installed" {
			err = fmt.Errorf("removal operation %s ended in state %s", optionalText(status.OperationID), status.State)
		}
		return removeMessage{generation: generation, status: status, err: err}
	}
}

func containsText(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (m model) installationDetail() string {
	var lines []string
	lines = append(lines, titleStyle.Render("Durable lifecycle operation"),
		"This screen reads the local v2 operation record and phase journal.", "")
	if m.installRunning {
		lines = append(lines, mutedStyle.Render("The interactive installer is running in this terminal."),
			"It will return here after plan review and apply complete.", "")
	} else if m.installError != "" {
		lines = append(lines, badStyle.Render("Installation did not complete."), m.installError, "")
	}
	if m.statusError != "" {
		lines = append(lines, badStyle.Render("Status unavailable"), m.statusError)
		return strings.Join(lines, "\n")
	}
	if m.status == nil {
		lines = append(lines, mutedStyle.Render("Loading the installer operation record."))
		return strings.Join(lines, "\n")
	}
	lines = append(lines,
		fmt.Sprintf("State: %s", m.status.State),
		fmt.Sprintf("Action: %s", optionalString(m.status.Action)),
		fmt.Sprintf("Operation ID: %s", optionalText(m.status.OperationID)),
		fmt.Sprintf("Current phase: %s", optionalText(m.status.CurrentPhase)),
		fmt.Sprintf("Deployment kind: %s", m.status.Configuration.DeploymentKind),
		fmt.Sprintf("Network scope: %s on port %d", m.status.Configuration.Network.Scope,
			m.status.Configuration.Network.AuthorityPort),
		fmt.Sprintf("Data directory: %s", m.status.Configuration.Storage.DataDirectory),
		fmt.Sprintf("Backup directory: %s", m.status.Configuration.Storage.BackupDirectory),
		fmt.Sprintf("Resume available: %t", m.status.ResumeAvailable),
		fmt.Sprintf("Bootstrap ready: %t", m.status.BootstrapReady),
		fmt.Sprintf("Server ready for enrollment: %t", m.status.ServerReadyForEnrollment),
	)
	phaseNames := make([]string, 0, len(m.status.Phases))
	for name := range m.status.Phases {
		phaseNames = append(phaseNames, name)
	}
	sort.Strings(phaseNames)
	if len(phaseNames) > 0 {
		lines = append(lines, "", titleStyle.Render("Journal phases"))
		for _, name := range phaseNames {
			lines = append(lines, fmt.Sprintf("%s: %s", name, m.status.Phases[name]))
		}
	}
	if m.status.State == "not_installed" && !m.installRunning {
		lines = append(lines, "", "Press i to review and install a signed Linux systemd or Docker Compose package.",
			"The workflow requires a root terminal and exact plan confirmation.")
	}
	if m.status.ResumeAvailable {
		if m.status.Action == "remove" {
			lines = append(lines, "", "Press R to retry the already confirmed removal, or run:",
				"sudo helicoid-server installer remove --confirm")
		} else {
			lines = append(lines, "", "Press R to select the retained request and resume, or keep the same signed package directory available and run:",
				"helicoid-server installer resume --request <reviewed-request.json> --confirm")
		}
	}
	if m.status.Result.Summary != "" {
		lines = append(lines, "", m.status.Result.Summary)
	}
	for _, message := range m.status.Result.Errors {
		lines = append(lines, badStyle.Render("Error: "+message))
	}
	for _, message := range m.status.Result.Warnings {
		lines = append(lines, "Warning: "+message)
	}
	if m.status.Action == "remove" {
		lines = append(lines, "", mutedStyle.Render("Removal status does not mark the deployment verified."))
	} else {
		lines = append(lines, "", mutedStyle.Render("A completed install is not the same as a verified deployment."))
	}
	return strings.Join(lines, "\n")
}

func refreshStatus(generation uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		status, err := loadStatus(ctx)
		return statusMessage{generation: generation, status: status, err: err}
	}
}

func refreshCapabilities(generation uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout)
		defer cancel()
		caps, err := loadCapabilities(ctx)
		return capabilitiesMessage{generation: generation, capabilities: caps, err: err}
	}
}

func refreshHealth(generation uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		health, err := loadHealth(ctx)
		return healthMessage{generation: generation, health: health, err: err}
	}
}

func refreshDiagnostics(generation uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backendTimeout*2+3*time.Second)
		defer cancel()
		return doctorMessage{generation: generation, report: runDoctor(ctx)}
	}
}

func optionalText(value *string) string {
	if value == nil || *value == "" {
		return "Not available"
	}
	return *value
}

func optionalString(value string) string {
	if value == "" {
		return "Not available"
	}
	return value
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "None"
	}
	return strings.Join(values, ", ")
}

func runTUI() error {
	program := tea.NewProgram(newModel())
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("run server TUI: %w", err)
	}
	return nil
}
