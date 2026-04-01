package main

import (
	"fmt"
	"os"

	"github.com/phalanx-security/phalanx/internal/baseline"
	"github.com/spf13/cobra"
)

var trustLockCmd = &cobra.Command{
	Use:   "trust-lock",
	Short: "Creates a trusted baseline for future verification",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Generating baseline signature for node_modules...")
		err := baseline.GenerateBaseline("node_modules", "phalanx.lock")
		if err != nil {
			fmt.Printf("Failed to generate trust lock: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[PHALANX] Trust lock generated at phalanx.lock")
	},
}

func init() {
	rootCmd.AddCommand(trustLockCmd)
}
