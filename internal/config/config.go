package config

import "github.com/spf13/viper"

type NetworkPolicy struct {
	Allow []string `mapstructure:"allow"`
	Block []string `mapstructure:"block"`
}

type Policy struct {
	BlockScore int  `mapstructure:"blockScore"`
	WarnScore  int  `mapstructure:"warnScore"`
	SafeMode   bool `mapstructure:"safeMode"`
}

type PhalanxConfig struct {
	Network         NetworkPolicy `mapstructure:"network"`
	TrustedPackages []string      `mapstructure:"trustedPackages"`
	Policy          Policy        `mapstructure:"policy"`
}

// GetConfig reads the global/local viper config and unmarshals it into PhalanxConfig
func GetConfig() (*PhalanxConfig, error) {
	var cfg PhalanxConfig
	err := viper.Unmarshal(&cfg)
	return &cfg, err
}
