package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"github.com/phalanx-security/phalanx/internal/analysis"
	phruntime "github.com/phalanx-security/phalanx/internal/runtime"
)

type ScriptTask struct {
	PackageName string
	PackageDir  string
	ScriptName  string
	Script      string
	Version     string
	PackageJSON string
}

type manifest struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

var scriptOrder = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"}

func Discover(root string) ([]ScriptTask, error) {
	var tasks []ScriptTask

	addManifest := func(packageJSON string) error {
		data, err := os.ReadFile(packageJSON)
		if err != nil {
			return err
		}
		var m manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return err
		}
		if len(m.Scripts) == 0 {
			return nil
		}
		pkgDir := filepath.Dir(packageJSON)
		pkgName := strings.TrimSpace(m.Name)
		if pkgName == "" {
			pkgName = filepath.Base(pkgDir)
		}
		for _, name := range scriptOrder {
			if script, ok := m.Scripts[name]; ok && strings.TrimSpace(script) != "" {
				tasks = append(tasks, ScriptTask{
					PackageName: pkgName,
					PackageDir:  pkgDir,
					ScriptName:  name,
					Script:      script,
					Version:     m.Version,
					PackageJSON: packageJSON,
				})
			}
		}
		return nil
	}

	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == ".quarantine" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) != "package.json" {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/.git/") || strings.Contains(filepath.ToSlash(path), "/.quarantine/") {
			return nil
		}
		_ = addManifest(path)
		return nil
	}); err != nil {
		return nil, err
	}

	sort.SliceStable(tasks, func(i, j int) bool {
		di := strings.Count(filepath.Clean(tasks[i].PackageDir), string(os.PathSeparator))
		dj := strings.Count(filepath.Clean(tasks[j].PackageDir), string(os.PathSeparator))
		if di != dj {
			return di > dj // deeper packages first
		}
		if tasks[i].PackageName != tasks[j].PackageName {
			return tasks[i].PackageName < tasks[j].PackageName
		}
		return tasks[i].ScriptName < tasks[j].ScriptName
	})

	return tasks, nil
}

func Run(tasks []ScriptTask) ([]analysis.Finding, error) {
	var findings []analysis.Finding
	for _, task := range tasks {
		if strings.TrimSpace(task.Script) == "" {
			continue
		}

		prep, err := phruntime.Prepare(phruntime.TaskContext{
			PackageName: task.PackageName,
			PackageDir:  task.PackageDir,
			ScriptName:  task.ScriptName,
			Script:      task.Script,
		})
		if err != nil {
			return findings, err
		}

		fmt.Printf("[PHALANX][runtime] %s @ %s → %s\n", task.PackageName, task.Version, task.ScriptName)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := shellCommand(ctx, task.Script)
		cmd.Dir = task.PackageDir
		cmd.Env = prep.Env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		runErr := cmd.Run()
		taskFindings := phruntime.ParseEvents(prep.EventLog, prep.Task)
		findings = append(findings, taskFindings...)

		if ctx.Err() == context.DeadlineExceeded {
			findings = append(findings, analysis.Finding{
				RuleID:      "RUNTIME-TIMEOUT",
				Severity:    "CRITICAL",
				FilePath:    task.PackageDir,
				Description: "Lifecycle script timed out after 2 minutes",
				Origin:      "runtime",
			})
			prep.Cleanup()
			cancel()
			return findings, fmt.Errorf("lifecycle script timed out: %s:%s", task.PackageName, task.ScriptName)
		}

		if runErr != nil {
			findings = append(findings, analysis.Finding{
				RuleID:      "RUNTIME-EXIT",
				Severity:    "CRITICAL",
				FilePath:    task.PackageDir,
				Description: fmt.Sprintf("Lifecycle script failed: %v", runErr),
				Origin:      "runtime",
			})
			prep.Cleanup()
			cancel()
			return findings, runErr
		}

		if hasSevereRuntimeFinding(taskFindings) {
			findings = append(findings, analysis.Finding{
				RuleID:      "RUNTIME-BLOCK",
				Severity:    "CRITICAL",
				FilePath:    task.PackageDir,
				Description: "Phalanx blocked further lifecycle execution because severe behavior was observed",
				Origin:      "runtime",
			})
			prep.Cleanup()
			cancel()
			return findings, fmt.Errorf("severe runtime behavior detected in %s:%s", task.PackageName, task.ScriptName)
		}

		prep.Cleanup()
		cancel()
	}
	return findings, nil
}

func hasSevereRuntimeFinding(findings []analysis.Finding) bool {
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "HIGH", "CRITICAL":
			return true
		}
	}
	return false
}

func shellCommand(ctx context.Context, script string) *exec.Cmd {
	if goruntime.GOOS == "windows" {
		return exec.CommandContext(ctx, "cmd", "/C", script)
	}
	return exec.CommandContext(ctx, "sh", "-lc", script)
}
