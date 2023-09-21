package options

// matchConfig contains all matching-related configuration options available to the user via the application config.
type matchConfig struct {
	Packages pkgMatcherConfig    `mapstructure:"packages"` // settings for the packages matcher
	Distro   distroMatcherConfig `mapstructure:"distro"`   // settings for the distro matcher
}

type pkgMatcherConfig struct {
	UsePURLs bool `yaml:"using-purls" json:"using-purls" mapstructure:"using-purls"` // if Purls should be used during matching
}

type distroMatcherConfig struct {
	UseCPEs bool `yaml:"using-cpes" json:"using-cpes" mapstructure:"using-cpes"` // if CPEs should be used during matching
}

func defaultMatchConfig() matchConfig {
	useCpe := distroMatcherConfig{UseCPEs: true}
	usePurl := pkgMatcherConfig{UsePURLs: true}
	return matchConfig{
		Packages: usePurl,
		Distro:   useCpe,
	}
}
