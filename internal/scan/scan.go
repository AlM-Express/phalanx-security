package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/analysis/rules"
)

// Collect scans node_modules and optional package manifests with the same static analysis pipeline.
func Collect(nodeModulesRoot string, manifestPaths ...string) ([]analysis.Finding, error) {
	analyzer := analysis.NewAnalyzer()
	analyzer.RegisterRule(&rules.ChildProcessRule{})
	analyzer.RegisterRule(&rules.NetworkRule{})
	analyzer.RegisterRule(&rules.ObfuscationRule{})
	analyzer.RegisterRule(&rules.FSRule{})
	analyzer.RegisterRule(&rules.AntiForensicsRule{})

	var findings []analysis.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	jobs := make(chan string, 5000)
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	worker := func() {
		defer wg.Done()
		for path := range jobs {
			switch {
			case strings.HasSuffix(path, ".js"):
				parsed, err := analysis.ParseFile(path)
				if err != nil {
					continue
				}
				f := analyzer.AnalyzeNode(parsed.AST, path)
				for i := range f {
					f[i].Origin = "static"
				}
				mu.Lock()
				findings = append(findings, f...)
				mu.Unlock()
			case strings.HasSuffix(path, "package.json"):
				f, err := analysis.AnalyzeManifest(path)
				if err != nil {
					continue
				}
				for i := range f {
					f[i].Origin = "static"
				}
				mu.Lock()
				findings = append(findings, f...)
				mu.Unlock()
			}
		}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	if _, err := os.Stat(nodeModulesRoot); err == nil {
		_ = filepath.Walk(nodeModulesRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if !info.IsDir() && (strings.HasSuffix(path, ".js") || strings.HasSuffix(path, "package.json")) {
				jobs <- path
			}
			return nil
		})
	}

	for _, manifestPath := range manifestPaths {
		if manifestPath == "" {
			continue
		}
		if _, err := os.Stat(manifestPath); err == nil {
			f, err := analysis.AnalyzeManifest(manifestPath)
			if err == nil {
				for i := range f {
					f[i].Origin = "static"
				}
				findings = append(findings, f...)
			}
		}
	}

	close(jobs)
	wg.Wait()

	return findings, nil
}
