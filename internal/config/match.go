package config

import "github.com/spf13/viper"

// matchConfig contains all matching-related configuration options available to the user via the application config.
type matchConfig struct {
	Packages matcherConfig `mapstructure:"packages"`
}

type matcherConfig struct {
	UsePurls bool `yaml:"using-purls" json:"using-purls" mapstructure:"using-purls"` // if Purls should be used during matching
	UseCpes  bool `yaml:"using-cpes" json:"using-cpes" mapstructure:"using-cpes"`    // if CPEs should be used during matching
}

func (cfg matchConfig) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("match.packages.using-purls", true)
	v.SetDefault("match.packages.using-cpes", true)
}
