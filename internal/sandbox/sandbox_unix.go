//go:build !windows
// +build !windows

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

func executeSandboxed(command []string) error {
	// MVP Unix fallback: Wrap with standard POSIX containment wrapper if available
	// Usually this would explicitly call bwrap (Linux) or sandbox-exec (macOS)

	sandboxCmd := []string{}

	// Check if bwrap exists
	if _, err := exec.LookPath("bwrap"); err == nil {
		fmt.Println("[SANDBOX] Found bwrap. Engaging Linux containment.")
		sandboxCmd = append(sandboxCmd, "bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-net")
	} else if _, err := exec.LookPath("sandbox-exec"); err == nil {
		fmt.Println("[SANDBOX] Found sandbox-exec. Engaging macOS containment.")
		sandboxCmd = append(sandboxCmd, "sandbox-exec", "-p", "(version 1)\n(allow default)\n(deny network*)")
	}

	fullCmd := append(sandboxCmd, command...)

	cmd := exec.Command(fullCmd[0], fullCmd[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Execution failed: %w", err)
	}

	fmt.Println("[SANDBOX] Execution finished cleanly.")
	return nil
}
