package remediation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Quarantine(pkgName string) error {
	cleanPkgName := filepath.Clean(pkgName)
	if strings.Contains(cleanPkgName, "..") {
		return fmt.Errorf("SECURITY FAULT: Quarantine path traversal attempt detected: %s", pkgName)
	}

	sourceDir := filepath.Join("node_modules", cleanPkgName)
	targetDir := filepath.Join(".quarantine", cleanPkgName)

	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return fmt.Errorf("package does not exist: %s", sourceDir)
	}

	err := os.MkdirAll(filepath.Dir(targetDir), 0755)
	if err != nil {
		return err
	}

	err = os.Rename(sourceDir, targetDir)
	if err != nil {
		return fmt.Errorf("failed to quarantine package: %w", err)
	}

	fmt.Printf("[REMEDIATION] Successfully moved %s to .quarantine folder.\n", pkgName)
	return nil
}

func SuggestRollback(pkgName string, currentVersion string) {
	fmt.Printf("\n[REMEDIATION] Rollback suggestion for %s:\n", pkgName)
	fmt.Printf("1. Delete your lockfile: rm package-lock.json (or yarn.lock)\n")
	fmt.Printf("2. Install a verified previous version explicitly:\n")
	fmt.Printf("   npm install %s@<previous-stable-version> --save-exact\n", pkgName)
}
