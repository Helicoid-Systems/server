package main

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestCutoverScreenExplainsActionsAndProofBoundary(t *testing.T) {
	m := newModel()
	m.active = "cutover"

	view := m.sectionDetail()
	for _, text := range []string{
		"Press l to inspect the local authority",
		"d to drain the active predecessor",
		"a to approve the restored host",
		"x to cancel a still-cancellable drain",
		"cannot prove that the predecessor was powered off or fenced",
		"Two-host coordination",
	} {
		if !strings.Contains(view, text) {
			t.Errorf("cutover screen does not contain %q", text)
		}
	}
}

func TestUpdatesScreenReportsBackendCapabilityAndReason(t *testing.T) {
	m := newModel()
	m.active = "updates"
	m.caps = &capabilities{
		SupportedActions: []string{"preflight", "plan", "install", "inspect"},
		ReasonsUnavailable: map[string]string{
			"online_update_backup_restore": "online updates and rollback are not implemented",
		},
	}

	view := m.sectionDetail()
	for _, text := range []string{
		"Online update: false",
		"Update action advertised: false",
		"Rollback action advertised: false",
		"online updates and rollback are not implemented",
		"restore-to-new-file",
	} {
		if !strings.Contains(view, text) {
			t.Errorf("updates screen does not contain %q", text)
		}
	}
}

func TestUpdatesScreenKeepsUpdateAndRestoreReasonsDistinct(t *testing.T) {
	m := newModel()
	m.active = "updates"
	m.caps = &capabilities{
		ReasonsUnavailable: map[string]string{
			"online_update":      "signed service update and downgrade protection are unavailable",
			"backup_and_restore": "deployment restore orchestration is unavailable",
		},
	}

	view := m.sectionDetail()
	for _, text := range []string{
		"Signed online updates and service rollback are unavailable.",
		"signed service update and downgrade protection are unavailable",
		"Lifecycle deployment backup and restore are unavailable.",
		"deployment restore orchestration is unavailable",
	} {
		if !strings.Contains(view, text) {
			t.Errorf("updates screen does not contain %q", text)
		}
	}
}

func TestCutoverMutationCompletionPromptsForStateReconciliation(t *testing.T) {
	m := newModel()
	m.cutoverRunning = true

	updated, cmd := m.Update(cutoverFinishedMessage{action: "drain"})
	result, ok := updated.(model)
	if !ok {
		t.Fatal("Update returned an unexpected model type")
	}
	if result.cutoverRunning {
		t.Fatal("cutover command should no longer be marked as running")
	}
	if !strings.Contains(result.cutoverMessage, "Press l to review the current authority state") {
		t.Fatalf("mutation result should request a fresh status read: %q", result.cutoverMessage)
	}
	if cmd == nil {
		t.Fatal("completed mutation should refresh lifecycle status")
	}
}

func TestCutoverScreenKeysDispatchExpectedLocalActions(t *testing.T) {
	for key, action := range map[string]string{
		"l": "status",
		"d": "drain",
		"a": "approve",
		"x": "cancel",
	} {
		t.Run(action, func(t *testing.T) {
			m := newModel()
			m.active = "cutover"
			updated, cmd := m.Update(tea.KeyPressMsg{Text: key, Code: []rune(key)[0]})
			result, ok := updated.(model)
			if !ok {
				t.Fatal("Update returned an unexpected model type")
			}
			if !result.cutoverRunning || result.cutoverAction != action {
				t.Fatalf("key %q selected cutover action %q; expected %q", key, result.cutoverAction, action)
			}
			if cmd == nil {
				t.Fatalf("key %q did not schedule the local %s command", key, action)
			}
		})
	}
}
