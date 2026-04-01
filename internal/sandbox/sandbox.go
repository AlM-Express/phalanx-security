package sandbox

import (
	"fmt"
	"runtime"
)

// RunWithSandbox attempts to execute the given command tightly contained
// via OS-native protections (Job Objects on Windows, bwrap/sandbox-exec on POSIX).
func RunWithSandbox(command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("no command provided")
	}

	fmt.Printf("[SANDBOX] Preparing to run %v in restricted environment (OS: %s)\n", command, runtime.GOOS)

	return executeSandboxed(command)
}
