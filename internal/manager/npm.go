package manager

import (
	"fmt"
	"os"
	"os/exec"
)

// Install securely fetches dependencies using npm without running scripts,
// allowing Phalanx to analyze them before deciding to execute lifecycle scripts.
func Install(safeMode bool) error {
	fmt.Println("Running 'npm install --ignore-scripts' to fetch dependencies safely...")
	cmd := exec.Command("npm", "install", "--ignore-scripts")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install failed: %w", err)
	}
	return nil
}
