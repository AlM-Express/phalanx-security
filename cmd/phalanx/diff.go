package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/phalanx-security/phalanx/internal/report"
	"github.com/phalanx-security/phalanx/internal/scoring"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [path-to-v1-report.json] [path-to-v2-report.json]",
	Short: "Compares two Phalanx JSON reports and shows the risk delta",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		v1, err := loadReport(args[0])
		if err != nil {
			fmt.Printf("[ERROR] Could not read report 1: %v\n", err)
			os.Exit(1)
		}
		v2, err := loadReport(args[1])
		if err != nil {
			fmt.Printf("[ERROR] Could not read report 2: %v\n", err)
			os.Exit(1)
		}

		diff := scoring.Compare(v1.Score, v2.Score, v1.Findings, v2.Findings)

		fmt.Println()
		fmt.Println("══════════════════════════════════════════════════════════")
		fmt.Println("  PHALANX RISK DIFF")
		fmt.Printf("  %s  →  %s\n", args[0], args[1])
		fmt.Println("══════════════════════════════════════════════════════════")
		fmt.Printf("  Score shift : %d → %d  (Δ %+d)\n", v1.Score.TotalScore, diff.NewScore, diff.ScoreShift)
		fmt.Println()

		if len(diff.AddedFindings) == 0 {
			fmt.Println("  ✔  No new risks introduced.")
		} else {
			fmt.Printf("  NEW RISKS (%d):\n", len(diff.AddedFindings))
			for _, f := range diff.AddedFindings {
				fmt.Println("  + " + f)
			}
		}

		fmt.Println()
		if len(diff.RemovedFindings) == 0 {
			fmt.Println("  ✔  No risks resolved.")
		} else {
			fmt.Printf("  RESOLVED RISKS (%d):\n", len(diff.RemovedFindings))
			for _, f := range diff.RemovedFindings {
				fmt.Println("  - " + f)
			}
		}

		fmt.Println()
		if diff.ScoreShift > 0 {
			fmt.Println("  Action: ⚠  RISK INCREASED — review new findings immediately.")
		} else if diff.ScoreShift < 0 {
			fmt.Println("  Action: ✔  RISK DECREASED — good progress.")
		} else {
			fmt.Println("  Action: ✔  RISK UNCHANGED.")
		}
		fmt.Println("══════════════════════════════════════════════════════════")
		fmt.Println()
	},
}

func loadReport(path string) (*report.FinalReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r report.FinalReport
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func init() {
	rootCmd.AddCommand(diffCmd)
}
