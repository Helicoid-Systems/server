//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var terminalInput = bufio.NewReaderSize(os.Stdin, 8192)

func readSecret(prompt string) (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("secret input requires an interactive terminal")
	}
	var original syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&original)))
	if errno != 0 {
		return "", errors.New("could not protect terminal input")
	}
	hidden := original
	hidden.Lflag &^= syscall.ECHO
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&hidden)))
	if errno != 0 {
		return "", errors.New("could not disable terminal echo")
	}
	defer func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&original)))
	}()
	fmt.Fprint(os.Stderr, prompt)
	line, readErr := readTerminalLine(4096)
	fmt.Fprintln(os.Stderr)
	if readErr != nil {
		return "", readErr
	}
	return line, nil
}

func readPromptLine(prompt string) (string, error) {
	return readPromptLineLimit(prompt, 256)
}

func readPromptLineLimit(prompt string, limit int) (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("input requires an interactive terminal")
	}
	fmt.Fprint(os.Stdout, prompt)
	line, readErr := readTerminalLine(limit)
	if readErr != nil {
		return "", readErr
	}
	return line, nil
}

func readTerminalLine(limit int) (string, error) {
	line := make([]byte, 0, min(limit, 256))
	for {
		part, err := terminalInput.ReadSlice('\n')
		if len(line)+len(part) > limit {
			zeroBytes(line)
			zeroBytes(part)
			if err == bufio.ErrBufferFull {
				for err == bufio.ErrBufferFull {
					_, err = terminalInput.ReadSlice('\n')
				}
			}
			return "", errors.New("terminal input exceeded the allowed length")
		}
		line = append(line, part...)
		zeroBytes(part)
		if err == nil {
			break
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			zeroBytes(line)
			return "", errors.New("read terminal input")
		}
	}
	value := strings.TrimRight(string(line), "\r\n")
	zeroBytes(line)
	return value, nil
}
