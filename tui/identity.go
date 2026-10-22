package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

// managerIdentity is the local proof key for one manager device. Its private
// bytes must never be formatted, logged, or serialized into support output.
type managerIdentity struct {
	private ed25519.PrivateKey
}

func (identity managerIdentity) publicKeyHex() string {
	return hex.EncodeToString(identity.private.Public().(ed25519.PublicKey))
}

func (identity managerIdentity) sign(message []byte) string {
	return hex.EncodeToString(ed25519.Sign(identity.private, message))
}

// loadOrCreateManagerIdentity uses an owner-only state directory and a
// create-exclusive key file. Existing keys are accepted only when their file,
// owner, permissions, size, and Ed25519 public suffix are valid.
func loadOrCreateManagerIdentity(deploymentID string) (managerIdentity, error) {
	stateDir, err := managerStateDirectory()
	if err != nil {
		return managerIdentity{}, err
	}
	return loadOrCreateManagerIdentityAt(stateDir, deploymentID)
}

func loadManagerIdentity(deploymentID string) (managerIdentity, error) {
	stateDir, err := managerStateDirectory()
	if err != nil {
		return managerIdentity{}, err
	}
	filename, err := managerIdentityFilename(deploymentID)
	if err != nil {
		return managerIdentity{}, err
	}
	key, err := readManagerIdentity(filepath.Join(stateDir, filename))
	if err != nil {
		return managerIdentity{}, errors.New("approved manager identity is unavailable or invalid")
	}
	return managerIdentity{private: key}, nil
}

func loadOrCreateManagerIdentityAt(stateDir, deploymentID string) (managerIdentity, error) {
	if !filepath.IsAbs(stateDir) {
		return managerIdentity{}, errors.New("manager identity directory must be absolute")
	}
	filename, err := managerIdentityFilename(deploymentID)
	if err != nil {
		return managerIdentity{}, err
	}
	if err := ensurePrivateStateDirectory(stateDir); err != nil {
		return managerIdentity{}, err
	}
	path := filepath.Join(stateDir, filename)
	key, err := readManagerIdentity(path)
	if err == nil {
		return managerIdentity{private: key}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return managerIdentity{}, err
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return managerIdentity{}, errors.New("generate manager device identity")
	}
	keyBytes := append([]byte(nil), private...)
	defer zeroBytes(keyBytes)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		key, readErr := readManagerIdentity(path)
		if readErr != nil {
			return managerIdentity{}, readErr
		}
		return managerIdentity{private: key}, nil
	}
	if err != nil {
		return managerIdentity{}, errors.New("create private manager identity file")
	}
	writeErr := writeAll(file, keyBytes)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return managerIdentity{}, errors.New("persist private manager identity file")
	}
	if err := verifyOwnedPrivateFile(path); err != nil {
		_ = os.Remove(path)
		return managerIdentity{}, err
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		_ = os.Remove(path)
		return managerIdentity{}, errors.New("open manager identity state directory")
	}
	syncErr := directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return managerIdentity{}, errors.New("persist manager identity directory entry")
	}
	if !ed25519.PublicKey(private.Public().(ed25519.PublicKey)).Equal(public) {
		_ = os.Remove(path)
		return managerIdentity{}, errors.New("generated manager identity is inconsistent")
	}
	return managerIdentity{private: private}, nil
}

func managerIdentityFilename(deploymentID string) (string, error) {
	if err := validateDeploymentID(deploymentID); err != nil {
		return "", err
	}
	deploymentHash := sha256.Sum256([]byte(deploymentID))
	return "manager-ed25519-" + hex.EncodeToString(deploymentHash[:]) + ".key", nil
}

func readManagerIdentity(path string) (ed25519.PrivateKey, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := validatePrivateFileInfo(linkInfo); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("read private manager identity file")
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil || !sameFileIdentity(linkInfo, fileInfo) {
		return nil, errors.New("manager identity changed while it was being opened")
	}
	if err := validatePrivateFileInfo(fileInfo); err != nil {
		return nil, err
	}
	keyBytes, err := io.ReadAll(io.LimitReader(file, ed25519.PrivateKeySize+1))
	if err != nil {
		return nil, errors.New("read private manager identity file")
	}
	defer zeroBytes(keyBytes)
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, errors.New("private manager identity file has an invalid size")
	}
	private := append(ed25519.PrivateKey(nil), keyBytes...)
	public := private.Public().(ed25519.PublicKey)
	if !public.Equal(ed25519.PublicKey(private[ed25519.SeedSize:])) {
		zeroBytes(private)
		return nil, errors.New("private manager identity file is inconsistent")
	}
	return private, nil
}

func verifyOwnedPrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validatePrivateFileInfo(info)
}

func validatePrivateFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("manager identity path is not a regular file")
	}
	if info.Size() != ed25519.PrivateKeySize {
		return errors.New("private manager identity file has an invalid size")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("manager identity file permissions must deny group and other access")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify manager identity file owner")
	}
	current, err := user.Current()
	if err != nil {
		return errors.New("cannot verify current user for manager identity")
	}
	if fmt.Sprint(stat.Uid) != current.Uid {
		return errors.New("manager identity file is owned by another user")
	}
	return nil
}

func sameFileIdentity(left, right os.FileInfo) bool {
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Dev == rightStat.Dev && leftStat.Ino == rightStat.Ino
}

func managerStateDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("cannot resolve an absolute user home for manager identity")
	}
	directory := filepath.Join(home, ".local", "state", "helicoid")
	if err := ensurePrivateStateDirectory(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func ensurePrivateStateDirectory(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("resolve manager identity directory")
	}
	volume := filepath.VolumeName(absolute)
	currentPath := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(strings.TrimPrefix(absolute, volume), string(filepath.Separator))
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		currentPath = filepath.Join(currentPath, component)
		info, statErr := os.Lstat(currentPath)
		if errors.Is(statErr, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(currentPath, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return errors.New("create manager identity state directory")
			}
			info, statErr = os.Lstat(currentPath)
		}
		if statErr != nil || info == nil {
			return errors.New("inspect manager identity state directory")
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("manager identity state path contains a non-directory or symlink")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("manager identity state directory is writable by group or other users")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot verify manager identity directory owner")
		}
		current, userErr := user.Current()
		if userErr != nil {
			return errors.New("cannot verify current user for manager identity directory")
		}
		if fmt.Sprint(stat.Uid) != current.Uid && stat.Uid != 0 {
			return errors.New("manager identity state directory is owned by another user")
		}
	}
	final, err := os.Lstat(absolute)
	if err != nil || !final.IsDir() || final.Mode()&os.ModeSymlink != 0 {
		return errors.New("manager identity state directory is unavailable")
	}
	if final.Mode().Perm()&0o077 != 0 {
		return errors.New("manager identity state directory must deny group and other access")
	}
	current, err := user.Current()
	if err != nil {
		return errors.New("cannot verify current user for manager identity directory")
	}
	stat, ok := final.Sys().(*syscall.Stat_t)
	if !ok || fmt.Sprint(stat.Uid) != current.Uid {
		return errors.New("manager identity state directory is not owned by the current user")
	}
	return nil
}

func bootstrapManagerProofMessage(deploymentID, bootstrapToken, publicKeyHex string) ([]byte, error) {
	if validateDeploymentID(deploymentID) != nil || bootstrapToken == "" || len(publicKeyHex) != ed25519.PublicKeySize*2 {
		return nil, errors.New("deployment, bootstrap token, and manager public key are required")
	}
	if _, err := hex.DecodeString(publicKeyHex); err != nil {
		return nil, errors.New("manager public key is not valid hexadecimal")
	}
	tokenHash := sha256.Sum256([]byte(bootstrapToken))
	return []byte(fmt.Sprintf("hs-bootstrap-v2|deployment:%s|token:%s|manager:%s",
		deploymentID, hex.EncodeToString(tokenHash[:]), strings.ToLower(publicKeyHex))), nil
}

func authChallengeProofMessage(deploymentID, challengeID, operation, publicKeyHex string) ([]byte, error) {
	if validateDeploymentID(deploymentID) != nil || strings.TrimSpace(challengeID) == "" || operation != "session" || len(publicKeyHex) != ed25519.PublicKeySize*2 {
		return nil, errors.New("deployment, challenge, session operation, and manager key are required")
	}
	if _, err := hex.DecodeString(publicKeyHex); err != nil {
		return nil, errors.New("manager public key is not valid hexadecimal")
	}
	return []byte(fmt.Sprintf("hs-auth-v2|deployment:%s|challenge:%s|operation:%s|manager:%s",
		deploymentID, challengeID, operation, strings.ToLower(publicKeyHex))), nil
}

func validateDeploymentID(deploymentID string) error {
	if !strings.HasPrefix(deploymentID, "dep_") || len(deploymentID) != len("dep_")+32 {
		return errors.New("server returned an invalid deployment identity")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(deploymentID, "dep_")); err != nil {
		return errors.New("server returned an invalid deployment identity")
	}
	return nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("short write")
		}
		data = data[written:]
	}
	return nil
}
