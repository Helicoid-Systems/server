//go:build !linux

package main

import "errors"

func readSecret(string) (string, error) {
	return "", errors.New("interactive secret entry is supported only on Linux")
}

func readPromptLine(string) (string, error) {
	return "", errors.New("interactive bootstrap is supported only on Linux")
}

func readPromptLineLimit(string, int) (string, error) {
	return "", errors.New("interactive bootstrap is supported only on Linux")
}

func verifyLocalServerAuthority() error {
	return errors.New("local administrator bootstrap is supported only on Linux")
}
