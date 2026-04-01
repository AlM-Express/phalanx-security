package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Baseline struct {
	Files map[string]string `json:"files"`
}

func GenerateBaseline(dirPath string, outFile string) error {
	baseline := Baseline{
		Files: make(map[string]string),
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			hash, err := hashFile(path)
			if err == nil {
				relPath, _ := filepath.Rel(dirPath, path)
				baseline.Files[relPath] = hash
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outFile, out, 0644)
}

func VerifyDrift(dirPath string, lockFile string) ([]string, error) {
	data, err := os.ReadFile(lockFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}

	var drift []string

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(dirPath, path)
			expectedHash, exists := baseline.Files[relPath]
			if !exists {
				drift = append(drift, fmt.Sprintf("NEW FILE: %s", relPath))
			} else {
				actualHash, err := hashFile(path)
				if err == nil && actualHash != expectedHash {
					drift = append(drift, fmt.Sprintf("MODIFIED: %s", relPath))
				}
				delete(baseline.Files, relPath)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	for missingFile := range baseline.Files {
		drift = append(drift, fmt.Sprintf("DELETED: %s", missingFile))
	}

	return drift, nil
}

func hashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
