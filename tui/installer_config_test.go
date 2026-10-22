package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightResultPreservesComposeRuntimeDiagnostic(t *testing.T) {
	input := []byte(`{"docker_compose_runtime":{"available":true,"docker_server_version":"28.3.3","compose_version":"2.39.4"}}`)
	var result preflightResult
	if err := json.Unmarshal(input, &result); err != nil {
		t.Fatalf("decode preflight result: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode preflight result: %v", err)
	}
	var output map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("decode round-tripped preflight result: %v", err)
	}
	if string(output["docker_compose_runtime"]) != string(result.DockerComposeRuntime) {
		t.Fatalf("Compose runtime diagnostic changed during round trip: %s", output["docker_compose_runtime"])
	}
}

func TestWritePrivateReviewCreatesPrivateDurableFile(t *testing.T) {
	directory := t.TempDir()
	content := []byte(`{"reviewed_plan_digest":"digest"}`)

	path, err := writePrivateReviewInDir(directory, content)
	if err != nil {
		t.Fatalf("write private review: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove private review: %v", err)
		}
	})
	if filepath.Dir(path) != directory {
		t.Fatalf("review path is outside requested directory: %s", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("inspect private review: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("review mode/type = %v; want regular file with mode 0600", info.Mode())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read private review: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("review content = %q; want %q", got, content)
	}
}

func TestValidateDeploymentConfigurationAllowsOwnedCustomStorage(t *testing.T) {
	configuration := defaultConfiguration()
	configuration.Storage.DataDirectory = "/var/lib/helicoid/data/school-a"
	configuration.Storage.BackupDirectory = "/var/backups/helicoid/nightly"

	if err := validateDeploymentConfiguration(configuration); err != nil {
		t.Fatalf("custom owned storage was rejected: %v", err)
	}
}

func TestValidateDeploymentConfigurationRejectsUnsafeStorage(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		backup string
	}{
		{name: "outside owned root", data: "/srv/helicoid/data", backup: "/var/lib/helicoid/backups"},
		{name: "traversal", data: "/var/lib/helicoid/data/../outside", backup: "/var/lib/helicoid/backups"},
		{name: "overlap", data: "/var/lib/helicoid/data/site-a", backup: "/var/lib/helicoid/data/site-a/backups"},
		{name: "unsupported character", data: "/var/lib/helicoid/data/site a", backup: "/var/lib/helicoid/backups"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := defaultConfiguration()
			configuration.Storage.DataDirectory = test.data
			configuration.Storage.BackupDirectory = test.backup
			if err := validateDeploymentConfiguration(configuration); err == nil {
				t.Fatal("unsafe storage configuration was accepted")
			}
		})
	}
}
