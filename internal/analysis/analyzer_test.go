package analysis_test

import (
	"path/filepath"
	"testing"

	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/analysis/rules"
)

func TestMalwareFixtures(t *testing.T) {
	analyzer := analysis.NewAnalyzer()
	analyzer.RegisterRule(&rules.ChildProcessRule{})
	analyzer.RegisterRule(&rules.NetworkRule{})
	analyzer.RegisterRule(&rules.ObfuscationRule{})
	analyzer.RegisterRule(&rules.FSRule{})
	analyzer.RegisterRule(&rules.AntiForensicsRule{})

	t.Run("obfuscated_rce.js", func(t *testing.T) {
		path := filepath.Join("..", "..", "fixtures", "malware", "obfuscated_rce.js")
		parsed, err := analysis.ParseFile(path)
		if err != nil {
			t.Fatalf("Failed to parse fixture: %v", err)
		}

		findings := analyzer.AnalyzeNode(parsed.AST, path)
		if len(findings) == 0 {
			t.Errorf("Expected findings for obfuscated RCE but got none")
		}

		evalFound := false
		for _, f := range findings {
			if f.RuleID == "JS-OBFUSCATION" {
				evalFound = true
			}
		}

		if !evalFound {
			t.Errorf("Expected to trigger JS-OBFUSCATION rule")
		}
	})

	t.Run("ssh_stealer.js", func(t *testing.T) {
		path := filepath.Join("..", "..", "fixtures", "malware", "ssh_stealer.js")
		parsed, err := analysis.ParseFile(path)
		if err != nil {
			t.Fatalf("Failed to parse fixture: %v", err)
		}

		findings := analyzer.AnalyzeNode(parsed.AST, path)
		fsAccess := false
		networkAccess := false
		antiForensics := false

		for _, f := range findings {
			if f.RuleID == "JS-FS-ACCESS" {
				fsAccess = true
			}
			if f.RuleID == "JS-NETWORK-ACCESS" && f.Severity == "CRITICAL" {
				// Should flag critical because malicious-drop.net is in hardcoded baseline
				networkAccess = true
			}
			if f.RuleID == "JS-ANTI-FORENSICS" {
				antiForensics = true
			}
		}

		if !fsAccess {
			t.Errorf("Failed to detect SSH key file read")
		}
		if !networkAccess {
			t.Errorf("Failed to detect network exfiltration to malicious domain")
		}
		if !antiForensics {
			t.Errorf("Failed to detect fs.unlinkSync(__filename)")
		}
	})

	t.Run("package.json manifests", func(t *testing.T) {
		path := filepath.Join("..", "..", "fixtures", "malware", "package.json")
		findings, err := analysis.AnalyzeManifest(path)
		if err != nil {
			t.Fatalf("Failed to analyze manifest: %v", err)
		}

		scriptFound := false
		binFound := false

		for _, f := range findings {
			if f.RuleID == "MANIFEST-SUSPICIOUS-SCRIPT" {
				scriptFound = true
			}
			if f.RuleID == "MANIFEST-BIN-HIJACK" {
				binFound = true
			}
		}

		if !scriptFound {
			t.Errorf("Failed to detect curl | bash in manifest scripts")
		}
		if !binFound {
			t.Errorf("Failed to detect ls shadowing in manifest bin")
		}
	})
}
