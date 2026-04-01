package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/phalanx-security/phalanx/internal/analysis"
	"github.com/phalanx-security/phalanx/internal/scoring"
)

type FinalReport struct {
	PackageName string
	Version     string
	Findings    []analysis.Finding
	Score       scoring.ScoreResult
}

func PrintConsole(r FinalReport) {
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Printf("  PHALANX SECURITY REPORT — %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("  Package : %s @ %s\n", r.PackageName, r.Version)
	fmt.Println("══════════════════════════════════════════════════════════")

	if len(r.Findings) == 0 {
		fmt.Println("  No findings detected.")
	} else {
		for _, f := range r.Findings {
			fmt.Printf("\n  [%s] %s\n", f.Severity, f.RuleID)
			fmt.Printf("  File : %s (line %d)\n", f.FilePath, f.Line)
			if f.Origin != "" {
				fmt.Printf("  Type : %s\n", f.Origin)
			}
			fmt.Printf("  Info : %s\n", f.Description)
		}
	}

	fmt.Println()
	fmt.Println("──────────────────────────────────────────────────────────")
	fmt.Printf("  Risk Score : %d / 100\n", r.Score.TotalScore)
	fmt.Printf("  Action     : %s\n", r.Score.Action)
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()
}

func PrintJSON(r FinalReport) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(r)
}
