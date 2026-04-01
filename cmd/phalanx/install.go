package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/lifecycle"
	"github.com/phalanx-security/phalanx/internal/manager"
	"github.com/phalanx-security/phalanx/internal/remediation"
	"github.com/phalanx-security/phalanx/internal/report"
	"github.com/phalanx-security/phalanx/internal/scan"
	"github.com/phalanx-security/phalanx/internal/scoring"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var safeMode bool

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "A secure replacement for package installation",
	Long:  `Fetches dependencies with scripts disabled first, scores risk, and then runs lifecycle scripts through Phalanx's runtime monitor.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Phalanx Install Executed")
		if safeMode {
			fmt.Println("[SAFE MODE] Lifecycle scripts will not be executed.")
		}

		if err := manager.Install(safeMode); err != nil {
			fmt.Printf("Install failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Dependencies fetched without lifecycle execution. Running Phalanx static analysis...")

		staticFindings, err := scan.Collect("node_modules", "package.json")
		if err != nil {
			fmt.Printf("Static analysis failed: %v\n", err)
			os.Exit(1)
		}

		staticScore := scoring.CalculateScore(staticFindings)
		if staticScore.Action == "BLOCK" {
			rep := report.FinalReport{PackageName: "App Dependencies", Version: "current", Findings: staticFindings, Score: staticScore}
			printReport(rep)
			quarantineIfNeeded(staticFindings)
			fmt.Println("\n[PHALANX] Static analysis blocked the install before lifecycle scripts were executed.")
			os.Exit(1)
		}

		runtimeFindings := []analysis.Finding{}
		if !safeMode {
			tasks, err := lifecycle.Discover(".")
			if err != nil {
				fmt.Printf("Lifecycle discovery failed: %v\n", err)
				os.Exit(1)
			}
			if len(tasks) > 0 {
				fmt.Printf("[PHALANX] Running %d lifecycle script(s) through the runtime monitor...\n", len(tasks))
				runtimeFindings, err = lifecycle.Run(tasks)
				if err != nil {
					fmt.Printf("[PHALANX] Runtime monitor stopped execution: %v\n", err)
				}
			} else {
				fmt.Println("[PHALANX] No lifecycle scripts found.")
			}
		}

		allFindings := append(staticFindings, runtimeFindings...)
		scoreRes := scoring.CalculateScore(allFindings)

		rep := report.FinalReport{
			PackageName: "App Dependencies",
			Version:     "current",
			Findings:    allFindings,
			Score:       scoreRes,
		}
		printReport(rep)

		if scoreRes.Action == "BLOCK" {
			fmt.Println("\n[PHALANX] High risk threshold crossed. Halting installation and quarantining suspicious artifacts.")
			quarantineIfNeeded(allFindings)
			os.Exit(1)
		}

		if scoreRes.Action == "WARN" {
			fmt.Println("\n[PHALANX] Medium risk detected. Review the findings before trusting this tree.")
		}

		if !safeMode && scoreRes.Action == "ALLOW" {
			fmt.Println("\n[PHALANX] Install completed under Phalanx control.")
		}
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.Flags().BoolVar(&safeMode, "safe", false, "Disable all lifecycle scripts unless explicitly approved")
}

func printReport(rep report.FinalReport) {
	if viper.GetBool("json") {
		report.PrintJSON(rep)
		return
	}
	report.PrintConsole(rep)
}

func quarantineIfNeeded(findings []analysis.Finding) {
	seen := make(map[string]bool)
	for _, f := range findings {
		pkg := packageFromFindingPath(f.FilePath)
		if pkg == "" || seen[pkg] {
			continue
		}
		seen[pkg] = true
		if err := remediation.Quarantine(pkg); err != nil {
			fmt.Printf("[PHALANX] Quarantine skipped for %s: %v\n", pkg, err)
			continue
		}
		remediation.SuggestRollback(pkg, "latest")
	}
}

func packageFromFindingPath(path string) string {
	clean := filepath.ToSlash(path)
	idx := strings.Index(clean, "node_modules/")
	if idx < 0 {
		return ""
	}
	rel := clean[idx+len("node_modules/"):]
	if rel == "" {
		return ""
	}
	parts := strings.Split(rel, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}
