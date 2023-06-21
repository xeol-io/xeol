package config

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/anchore/go-logger"
	git "github.com/go-git/go-git/v5"
	"github.com/karrick/tparse"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/xeol-io/xeol/internal"
)

var ErrApplicationConfigNotFound = fmt.Errorf("application config not found")

type defaultValueLoader interface {
	loadDefaultValues(*viper.Viper)
}

const XEOL_API_URL = "https://engine.xeol.io/v1/scan"

type parser interface {
	parseConfigValues() error
}

type Application struct {
	Verbosity              uint           `yaml:"verbosity,omitempty" json:"verbosity" mapstructure:"verbosity"`
	ConfigPath             string         `yaml:",omitempty" json:"configPath"`                                                         // the location where the application config was read from (either from -c or discovered while loading)
	File                   string         `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	Output                 string         `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the Presenter hint string to use for report formatting
	Quiet                  bool           `yaml:"quiet" json:"quiet" mapstructure:"quiet"`                                              // -q, indicates to not show any status output to stderr (ETUI or logging UI)// -o, the Presenter hint string to use for report formatting
	CheckForAppUpdate      bool           `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Log                    logging        `yaml:"log" json:"log" mapstructure:"log"`
	DB                     database       `yaml:"db" json:"db" mapstructure:"db"`
	CliOptions             CliOnlyOptions `yaml:"-" json:"-"`
	Match                  matchConfig    `yaml:"match" json:"match" mapstructure:"match"`
	Lookahead              string         `yaml:"lookahead" json:"lookahead" mapstructure:"lookahead"`
	EolMatchDate           time.Time      `yaml:"-" json:"-"`
	FailOnEolFound         bool           `yaml:"fail-on-eol-found" json:"fail-on-eol-found" mapstructure:"fail-on-eol-found"` // whether to exit with a non-zero exit code if any EOLs are found
	ApiKey                 string         `yaml:"api-key" json:"api-key" mapstructure:"api-key"`
	ApiURL                 string         `yaml:"api-url" json:"api-url" mapstructure:"api-url"`
	ProjectName            string         `yaml:"project-name" json:"project-name" mapstructure:"project-name"`
	ImagePath              string         `yaml:"image-path" json:"image-path" mapstructure:"image-path"`
	Registry               registry       `yaml:"registry" json:"registry" mapstructure:"registry"`
	Platform               string         `yaml:"platform" json:"platform" mapstructure:"platform"` // --platform, override the target platform for a container image
	Name                   string         `yaml:"name" json:"name" mapstructure:"name"`
	DefaultImagePullSource string         `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`
	Search                 search         `yaml:"search" json:"search" mapstructure:"search"`
}

func NewApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) *Application {
	config := &Application{
		CliOptions: cliOpts,
	}
	config.loadDefaultValues(v)

	return config
}

func LoadApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) (*Application, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	config := NewApplicationConfig(v, cliOpts)

	if err := readConfig(v, cliOpts.ConfigPath); err != nil && !errors.Is(err, ErrApplicationConfigNotFound) {
		return nil, err
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	if err := config.parseConfigValues(); err != nil {
		return nil, fmt.Errorf("invalid application config: %w", err)
	}

	return config, nil
}

// init loads the default configuration values into the viper instance (before the config values are read and parsed).
func (cfg Application) loadDefaultValues(v *viper.Viper) {
	// set the default values for primitive fields in this struct
	v.SetDefault("check-for-app-update", true)
	v.SetDefault("fail-on-eol-found", false)
	v.SetDefault("project-name", getDefaultProjectName())
	v.SetDefault("api-url", XEOL_API_URL)
	v.SetDefault("image-path", "Dockerfile")
	v.SetDefault("default-image-pull-source", "")

	// for each field in the configuration struct, see if the field implements the defaultValueLoader interface and invoke it if it does
	value := reflect.ValueOf(cfg)
	for i := 0; i < value.NumField(); i++ {
		// note: the defaultValueLoader method receiver is NOT a pointer receiver.
		if loadable, ok := value.Field(i).Interface().(defaultValueLoader); ok {
			// the field implements defaultValueLoader, call it
			loadable.loadDefaultValues(v)
		}
	}
}

func getDefaultProjectName() string {
	repo, err := git.PlainOpen(".")
	if err != nil {
		return ""
	}

	p := NewProject(repo)
	return p.Name
}

// readConfig attempts to read the given config path from disk or discover an alternate store location
func readConfig(v *viper.Viper, configPath string) error {
	var err error
	v.AutomaticEnv()
	v.SetEnvPrefix(internal.ApplicationName)
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read application config=%q : %w", configPath, err)
		}
		// don't fall through to other options if the config path was explicitly provided
		return nil
	}

	// start searching for valid configs in order...

	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName("." + internal.ApplicationName)
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 3. look for ~/.<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + internal.ApplicationName)
		if err = v.ReadInConfig(); err == nil {
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}
	}

	// 4. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, internal.ApplicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, internal.ApplicationName))
	}
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	return ErrApplicationConfigNotFound
}

func (cfg *Application) parseConfigValues() error {
	// parse application config options
	for _, optionFn := range []func() error{
		cfg.parseLogLevelOption,
		cfg.parseLookaheadOption,
	} {
		if err := optionFn(); err != nil {
			return err
		}
	}

	// parse nested config options
	// for each field in the configuration struct, see if the field implements the parser interface
	// note: the app config is a pointer, so we need to grab the elements explicitly (to traverse the address)
	value := reflect.ValueOf(cfg).Elem()
	for i := 0; i < value.NumField(); i++ {
		// note: since the interface method of parser is a pointer receiver we need to get the value of the field as a pointer.
		if parsable, ok := value.Field(i).Addr().Interface().(parser); ok {
			// the field implements parser, call it
			if err := parsable.parseConfigValues(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (cfg *Application) parseLookaheadOption() error {
	if cfg.Lookahead == "none" {
		cfg.EolMatchDate = time.Now()
		return nil
	}

	var err error
	cfg.EolMatchDate, err = tparse.ParseNow(time.RFC3339, fmt.Sprintf("now+%s", cfg.Lookahead))
	if err != nil {
		return fmt.Errorf("bad --lookahead value: '%s'", cfg.Lookahead)
	}

	return nil
}

func (cfg *Application) parseLogLevelOption() error {
	switch {
	case cfg.Quiet:
		// TODO: this is bad: quiet option trumps all other logging options (such as to a file on disk)
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Log.Level = logger.DisabledLevel

	case cfg.CliOptions.Verbosity > 0:
		verb := cfg.CliOptions.Verbosity
		cfg.Log.Level = logger.LevelFromVerbosity(verb, logger.WarnLevel, logger.InfoLevel, logger.DebugLevel, logger.TraceLevel)

	case cfg.Log.Level != "":
		var err error
		cfg.Log.Level, err = logger.LevelFromString(string(cfg.Log.Level))
		if err != nil {
			return err
		}

		if logger.IsVerbose(cfg.Log.Level) {
			cfg.Verbosity = 1
		}
	default:
		cfg.Log.Level = logger.WarnLevel
	}

	return nil
}

func (cfg Application) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}
