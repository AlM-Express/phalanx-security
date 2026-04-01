package main

import (
	"fmt"
	"os"

	"github.com/phalanx-security/phalanx/internal/baseline"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Compares current dependency state against a previously trusted baseline",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Verifying node_modules against phalanx.lock...")
		drift, err := baseline.VerifyDrift("node_modules", "phalanx.lock")
		if err != nil {
			fmt.Printf("Verification failed: %v\n", err)
			os.Exit(1)
		}

		if len(drift) == 0 {
			fmt.Println("[PHALANX] Verification passed. No drift detected.")
			return
		}

		fmt.Println("[WARN] Drift detected:")
		for _, change := range drift {
			fmt.Println(" -", change)
		}
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
