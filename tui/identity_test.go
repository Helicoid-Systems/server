package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerIdentityCreatesPrivateStableKey(t *testing.T) {
	directory := filepath.Join(canonicalTempDir(t), "state", "helicoid")
	first, err := loadOrCreateManagerIdentityAt(directory, "dep_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateManagerIdentityAt(directory, "dep_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if first.publicKeyHex() != second.publicKeyHex() {
		t.Fatal("manager identity changed between loads")
	}
	filename, err := managerIdentityFilename("dep_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(directory, filename))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Fatalf("private identity permissions = %04o, want no group/other access", got)
	}
	if got := info.Size(); got != ed25519.PrivateKeySize {
		t.Fatalf("private identity size = %d, want %d", got, ed25519.PrivateKeySize)
	}
}

func TestManagerIdentityRejectsInsecureOrInvalidFiles(t *testing.T) {
	t.Run("broad permissions", func(t *testing.T) {
		directory := filepath.Join(canonicalTempDir(t), "state")
		if _, err := loadOrCreateManagerIdentityAt(directory, "dep_0123456789abcdef0123456789abcdef"); err != nil {
			t.Fatal(err)
		}
		filename, err := managerIdentityFilename("dep_0123456789abcdef0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, filename)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateManagerIdentityAt(directory, "dep_0123456789abcdef0123456789abcdef"); err == nil {
			t.Fatal("accepted manager identity readable by other users")
		}
	})

	t.Run("malformed length", func(t *testing.T) {
		directory := filepath.Join(canonicalTempDir(t), "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		filename, err := managerIdentityFilename("dep_0123456789abcdef0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, filename)
		if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateManagerIdentityAt(directory, "dep_0123456789abcdef0123456789abcdef"); err == nil {
			t.Fatal("accepted malformed manager identity")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := filepath.Join(canonicalTempDir(t), "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		other := filepath.Join(t.TempDir(), "other-key")
		if err := os.WriteFile(other, make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
			t.Fatal(err)
		}
		filename, err := managerIdentityFilename("dep_0123456789abcdef0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, filepath.Join(directory, filename)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOrCreateManagerIdentityAt(directory, "dep_0123456789abcdef0123456789abcdef"); err == nil {
			t.Fatal("accepted symlinked manager identity")
		}
	})
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestBootstrapManagerProofMatchesServerContract(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	identity := managerIdentity{private: private}
	const token = "one-use-bootstrap-token"
	const deploymentID = "dep_0123456789abcdef0123456789abcdef"
	message, err := bootstrapManagerProofMessage(deploymentID, token, identity.publicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	want := "hs-bootstrap-v2|deployment:" + deploymentID + "|token:" + hex.EncodeToString(tokenHash[:]) + "|manager:" + identity.publicKeyHex()
	if string(message) != want {
		t.Fatalf("proof message = %q, want %q", message, want)
	}
	proof, err := hex.DecodeString(identity.sign(message))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, proof) {
		t.Fatal("manager signature did not verify")
	}
}

func TestBootstrapManagerProofRejectsMissingBindings(t *testing.T) {
	for _, values := range [][3]string{
		{"", "token", strings.Repeat("a", 64)},
		{"deployment", "", strings.Repeat("a", 64)},
		{"deployment", "token", "not-hex"},
	} {
		if _, err := bootstrapManagerProofMessage(values[0], values[1], values[2]); err == nil {
			t.Fatalf("accepted incomplete proof binding %q", values)
		}
	}
}
