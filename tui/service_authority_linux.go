//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const expectedServerCommand = "/opt/helicoid/bin/hs-server --data /var/lib/helicoid/data/hs-server.db serve --bind 127.0.0.1:8787"

func verifyLocalServerAuthority() error {
	if rootOwnedRegularFile("/.dockerenv") {
		return verifyComposeContainerAuthority()
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil || !rootOwnedExecutablePath(systemctl) {
		return errors.New("cannot verify the root-owned systemd Helicoid service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, systemctl, "show", "hs-server.service",
		"--property=LoadState", "--property=ActiveState", "--property=MainPID",
		"--property=User", "--property=FragmentPath", "--property=DropInPaths", "--no-pager")
	output, err := command.Output()
	if err != nil {
		return errors.New("could not inspect the local Helicoid systemd service")
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			properties[key] = strings.TrimSpace(value)
		}
	}
	if properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" || properties["DropInPaths"] != "" {
		return errors.New("the Helicoid systemd service is not active or has unreviewed overrides")
	}
	pid, err := strconv.Atoi(properties["MainPID"])
	if err != nil || pid <= 1 {
		return errors.New("the Helicoid systemd service has no active main process")
	}
	unitUser, err := verifyRootOwnedUnit(properties["FragmentPath"])
	if err != nil {
		return err
	}
	if unitUser != properties["User"] {
		return errors.New("the active Helicoid service user differs from its trusted unit")
	}
	serviceUser, err := user.Lookup(unitUser)
	if err != nil {
		return errors.New("the Helicoid service user cannot be verified")
	}
	serviceUID, err := strconv.ParseUint(serviceUser.Uid, 10, 32)
	if err != nil {
		return errors.New("the Helicoid service user has an invalid numeric identity")
	}
	if !rootOwnedExecutablePath("/opt/helicoid/bin/hs-server") {
		return errors.New("the installed Helicoid server binary is not root-owned and protected")
	}
	if err := verifyLoopbackListener(uint32(serviceUID)); err != nil {
		return err
	}
	return nil
}

func verifyComposeContainerAuthority() error {
	tuiExecutable, err := os.Executable()
	if err != nil || !rootOwnedExecutablePath(tuiExecutable) ||
		!rootOwnedExecutablePath("/usr/local/bin/hs-server") {
		return errors.New("the container Helicoid binaries are not protected root-owned executables")
	}
	listenerInodes, err := loopbackListenerInodes(uint32(os.Geteuid()))
	if err != nil {
		return err
	}
	for _, inode := range listenerInodes {
		pid, found := findTrustedComposeServer(inode, uint32(os.Geteuid()))
		if found && pid > 1 {
			return nil
		}
	}
	return errors.New("the loopback API is not owned by the protected Compose hs-server process")
}

func findTrustedComposeServer(inode string, expectedUID uint32) (int, bool) {
	processes, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, process := range processes {
		pid, err := strconv.Atoi(process.Name())
		if err != nil || pid <= 1 || !process.IsDir() {
			continue
		}
		processPath := filepath.Join("/proc", process.Name())
		executable, err := os.Readlink(filepath.Join(processPath, "exe"))
		if err != nil || filepath.Clean(executable) != "/usr/local/bin/hs-server" {
			continue
		}
		if !processHasEffectiveUID(processPath, expectedUID) || !processRunsComposeServer(processPath) {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(processPath, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(processPath, "fd", fd.Name()))
			if err == nil && target == "socket:["+inode+"]" {
				return pid, true
			}
		}
	}
	return 0, false
}

func processHasEffectiveUID(processPath string, expectedUID uint32) bool {
	contents, err := os.ReadFile(filepath.Join(processPath, "status"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "Uid:" {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		return err == nil && uint32(uid) == expectedUID
	}
	return false
}

func processRunsComposeServer(processPath string) bool {
	contents, err := os.ReadFile(filepath.Join(processPath, "cmdline"))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimRight(string(contents), "\x00"), "\x00")
	return containsArgumentSequence(args, "--data", "/var/lib/helicoid/data/server.db") &&
		containsArgumentSequence(args, "serve-dual") &&
		containsArgumentSequence(args, "--local-bind", "127.0.0.1:8787") &&
		containsArgumentSequence(args, "--allow-network")
}

func containsArgumentSequence(args []string, sequence ...string) bool {
	for start := 0; start+len(sequence) <= len(args); start++ {
		matched := true
		for offset, expected := range sequence {
			if args[start+offset] != expected {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func verifyRootOwnedUnit(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("the Helicoid systemd unit path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !rootOwnedRegularFile(resolved) {
		return "", errors.New("the Helicoid systemd unit is not a trusted root-owned file")
	}
	contents, err := os.ReadFile(resolved)
	if err != nil {
		return "", errors.New("could not read the Helicoid systemd unit")
	}
	inService := false
	var serviceUser string
	var execStart string
	for _, rawLine := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inService = line == "[Service]"
			continue
		}
		if !inService {
			continue
		}
		if value, ok := strings.CutPrefix(line, "User="); ok {
			serviceUser = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(line, "ExecStart="); ok {
			execStart = strings.TrimSpace(value)
		}
	}
	if serviceUser == "" || serviceUser == "root" || execStart != expectedServerCommand {
		return "", errors.New("the Helicoid unit does not match the expected unprivileged loopback service")
	}
	return serviceUser, nil
}

func rootOwnedRegularFile(path string) bool {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		if current == path {
			if !info.Mode().IsRegular() {
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

func verifyLoopbackListener(expectedUID uint32) error {
	_, err := loopbackListenerInodes(expectedUID)
	return err
}

func loopbackListenerInodes(expectedUID uint32) ([]string, error) {
	address, portText, err := net.SplitHostPort(localAuthority)
	if err != nil || address != "127.0.0.1" {
		return nil, errors.New("the local Helicoid authority is invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("the local Helicoid authority port is invalid")
	}
	localAddress := fmt.Sprintf("0100007F:%04X", port)
	contents, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, errors.New("could not inspect local TCP listeners")
	}
	var inodes []string
	for _, line := range strings.Split(string(contents), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[1] != localAddress || fields[3] != "0A" {
			continue
		}
		uid, parseErr := strconv.ParseUint(fields[7], 10, 32)
		if parseErr != nil || uint32(uid) != expectedUID {
			return nil, errors.New("the loopback Helicoid port is owned by an unexpected user")
		}
		if _, parseErr := strconv.ParseUint(fields[9], 10, 64); parseErr != nil {
			return nil, errors.New("the loopback Helicoid socket identity is invalid")
		}
		inodes = append(inodes, fields[9])
	}
	if len(inodes) == 0 {
		return nil, fmt.Errorf("the verified Helicoid process is not listening on %s", localAuthority)
	}
	return inodes, nil
}
