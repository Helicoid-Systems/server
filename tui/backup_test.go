package main

import (
	"reflect"
	"testing"
)

func TestBackupCommandArgsUseInstalledDatabaseForCreate(t *testing.T) {
	got, err := backupCommandArgs("create", "/var/lib/helicoid/data")
	if err != nil {
		t.Fatalf("backupCommandArgs returned error: %v", err)
	}
	want := []string{
		"--data", "/var/lib/helicoid/data/hs-server.db",
		"backup", "create", "--passphrase-stdin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("backupCommandArgs = %#v, want %#v", got, want)
	}
}

func TestBackupCommandArgsVerifyAndRestorePromptForPaths(t *testing.T) {
	for _, action := range []string{"verify", "restore"} {
		t.Run(action, func(t *testing.T) {
			got, err := backupCommandArgs(action, "")
			if err != nil {
				t.Fatalf("backupCommandArgs returned error: %v", err)
			}
			want := []string{"backup", action, "--passphrase-stdin"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("backupCommandArgs = %#v, want %#v", got, want)
			}
		})
	}
}

func TestBackupCommandArgsRejectInvalidActionsAndMissingDataDirectory(t *testing.T) {
	if _, err := backupCommandArgs("create", "relative/path"); err == nil {
		t.Fatal("create must require an absolute installed data directory")
	}
	if _, err := backupCommandArgs("cutover", "/var/lib/helicoid/data"); err == nil {
		t.Fatal("unsupported backup action must be rejected")
	}
}

func TestBackupScheduleSupportsLinuxSystemdAndCompose(t *testing.T) {
	if !supportsBackupSchedule("linux_systemd") {
		t.Fatal("native systemd deployments should support scheduled backups")
	}
	if !supportsBackupSchedule("linux_compose") {
		t.Fatal("Compose deployments should support host-systemd scheduled backups")
	}
	if supportsBackupSchedule("windows_service") || supportsBackupSchedule("macos_launchd") {
		t.Fatal("non-Linux deployments must not advertise scheduled backups")
	}
}
