package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "phalanx",
	Short: "Phalanx prevents Node.js supply-chain attacks",
	Long:  `Phalanx is a drop-in secure wrapper around npm, adding a security layer without requiring changes to developer workflows.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Disable cobra's mousetrap — this allows phalanx.exe to run when
	// double-clicked on Windows instead of showing "This is a command line tool."
	cobra.MousetrapHelpText = ""

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./phalanx.yml)")
	rootCmd.PersistentFlags().Bool("json", false, "Output results in JSON format")
	viper.BindPFlag("json", rootCmd.PersistentFlags().Lookup("json"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yml")
		viper.SetConfigName("phalanx")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		// config loaded successfully
	}
}
