package main

import (
	"fmt"
	"os"

	"github.com/phalanx-security/phalanx/internal/report"
	"github.com/phalanx-security/phalanx/internal/scan"
	"github.com/phalanx-security/phalanx/internal/scoring"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scans an existing node_modules tree and lockfile",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting Phalanx audit on node_modules...")

		findings, err := scan.Collect("node_modules", "package.json")
		if err != nil {
			fmt.Printf("Error scanning dependencies: %v\n", err)
			os.Exit(1)
		}

		scoreRes := scoring.CalculateScore(findings)
		rep := report.FinalReport{
			PackageName: "Workspace node_modules",
			Version:     "local",
			Findings:    findings,
			Score:       scoreRes,
		}

		if viper.GetBool("json") {
			report.PrintJSON(rep)
		} else {
			report.PrintConsole(rep)
		}

		switch scoreRes.Action {
		case "BLOCK":
			fmt.Println("\n[PHALANX] High-risk dependencies found in your tree. Immediate review required.")
			os.Exit(1)
		case "WARN":
			fmt.Println("\n[PHALANX] Suspicious patterns found. Please review the findings.")
		default:
			fmt.Println("\n[PHALANX] Audit complete. No high risk indicators found.")
		}
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
