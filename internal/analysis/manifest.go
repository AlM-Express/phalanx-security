package analysis

import (
	"encoding/json"
	"io"
	"os"
	"strings"
)

type PackageManifest struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
	Bin     interface{}       `json:"bin"`
}

func AnalyzeManifest(filePath string) ([]Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var manifest PackageManifest
	if err := json.NewDecoder(file).Decode(&manifest); err != nil && err != io.EOF {
		return nil, err
	}

	var findings []Finding
	suspiciousKeywords := []string{"curl", "wget", "base64", "nc", "bash -i"}

	for scriptName, scriptCmd := range manifest.Scripts {
		lowerCmd := strings.ToLower(scriptCmd)
		for _, kw := range suspiciousKeywords {
			if strings.Contains(lowerCmd, kw) {
				findings = append(findings, Finding{
					RuleID:      "MANIFEST-SUSPICIOUS-SCRIPT",
					Severity:    "HIGH",
					FilePath:    filePath,
					Description: "Suspicious command '" + kw + "' found in script '" + scriptName + "'",
				})
			}
		}
	}

	// Check Bin for shadowing common system binaries
	systemBinaries := []string{"ls", "grep", "node", "npm", "sudo", "bash", "sh", "rm", "cat"}

	switch b := manifest.Bin.(type) {
	case string:
		// When bin is a string, the binary name IS the package name
		for _, sysBin := range systemBinaries {
			if strings.ToLower(manifest.Name) == sysBin {
				findings = append(findings, Finding{
					RuleID:      "MANIFEST-BIN-HIJACK",
					Severity:    "CRITICAL",
					FilePath:    filePath,
					Description: "Package name '" + manifest.Name + "' shadows the common system utility '" + sysBin + "'",
				})
			}
		}
		_ = b
	case map[string]interface{}:
		for binCommand := range b {
			for _, sysBin := range systemBinaries {
				if strings.ToLower(binCommand) == sysBin {
					findings = append(findings, Finding{
						RuleID:      "MANIFEST-BIN-HIJACK",
						Severity:    "CRITICAL",
						FilePath:    filePath,
						Description: "Package attempts to alias the common system utility '" + binCommand + "'",
					})
				}
			}
		}
	}

	return findings, nil
}
