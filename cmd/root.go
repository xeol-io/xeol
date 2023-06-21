package cmd

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/internal"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/config"
	"github.com/xeol-io/xeol/internal/format"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/internal/ui"
	"github.com/xeol-io/xeol/internal/version"
	"github.com/xeol-io/xeol/internal/xeolio"
	"github.com/xeol-io/xeol/xeol"
	"github.com/xeol-io/xeol/xeol/db"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/matcher"
	distroMatcher "github.com/xeol-io/xeol/xeol/matcher/distro"
	pkgMatcher "github.com/xeol-io/xeol/xeol/matcher/packages"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/presenter"
	"github.com/xeol-io/xeol/xeol/presenter/models"
	"github.com/xeol-io/xeol/xeol/report"
	"github.com/xeol-io/xeol/xeol/store"
	"github.com/xeol-io/xeol/xeol/xeolerr"
)

var persistentOpts = config.CliOnlyOptions{}

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
	Short: "An EOL package scanner for container images, systems, and SBOMs",
	Long: format.Tprintf(`An EOL package scanner for container images, systems, and SBOMs.

Supports the following image sources:
	 {{.appName}} yourrepo/yourimage:latest    defaults to using images from a Docker daemon

You can also explicitly specify the schema to use:
	 {{.appName}} docker://yourrepo/yourimage:latest   explicitly use the Docker daemon
`, map[string]interface{}{"appName": internal.ApplicationName}),
	Args:              validateRootArgs,
	SilenceUsage:      true,
	SilenceErrors:     true,
	RunE:              rootExec,
	ValidArgsFunction: dockerImageValidArgsFunction,
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		log.Warnf("unable to determine if there is piped input: %+v", err)
		isPipedInput = false
	}

	if len(args) == 0 && !isPipedInput {
		// in the case that no arguments are given and there is no piped input we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func init() {
	setGlobalCliOptions()
	setRootFlags(rootCmd.Flags())
}

func setGlobalCliOptions() {
	// setup global CLI options (available on all CLI commands)
	rootCmd.PersistentFlags().StringVarP(&persistentOpts.ConfigPath, "config", "c", "", "application configuration file")

	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
	rootCmd.PersistentFlags().CountVarP(&persistentOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}

func setRootFlags(flags *pflag.FlagSet) {
	flags.StringP(
		"scope", "s", source.SquashedScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", source.AllScopes),
	)

	flags.StringP(
		"name", "", "",
		"set the name of the target being analyzed",
	)

	flags.StringP(
		"output", "o", "",
		fmt.Sprintf("report output formatter, formats=%v", presenter.AvailableFormats),
	)

	flags.StringP(
		"project-name", "", "",
		"set the name of the project being analyzed for xeol.io.",
	)

	flags.StringP(
		"image-path", "", "",
		"set the path to the image being analyzed for xeol.io (e.g /src/Dockerfile)",
	)

	flags.StringP(
		"api-key", "", "",
		"set the API key for xeol.io. When this is set, scans will be uploaded to xeol.io.",
	)

	flags.BoolP(
		"fail-on-eol-found", "f", false,
		"set the return code to 1 if an EOL package is found",
	)

	flags.StringP(
		"file", "", "",
		"file to write the report output to (default is STDOUT)",
	)

	flags.StringP(
		"lookahead", "l", "30d",
		"an optional lookahead specifier when matching EOL dates (e.g. 'none', '1d', '1w', '1m', '1y'). Packages are matched when their EOL date < today+lookahead",
	)

	flags.StringP(
		"platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)
}

func bindRootConfigOptions(flags *pflag.FlagSet) error {
	if err := viper.BindPFlag("search.scope", flags.Lookup("scope")); err != nil {
		return err
	}

	if err := viper.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}

	if err := viper.BindPFlag("fail-on-eol-found", flags.Lookup("fail-on-eol-found")); err != nil {
		return err
	}

	if err := viper.BindPFlag("project-name", flags.Lookup("project-name")); err != nil {
		return err
	}

	if err := viper.BindPFlag("image-path", flags.Lookup("image-path")); err != nil {
		return err
	}

	if err := viper.BindPFlag("api-key", flags.Lookup("api-key")); err != nil {
		return err
	}

	if err := viper.BindPFlag("lookahead", flags.Lookup("lookahead")); err != nil {
		return err
	}

	if err := viper.BindPFlag("file", flags.Lookup("file")); err != nil {
		return err
	}

	if err := viper.BindPFlag("name", flags.Lookup("name")); err != nil {
		return err
	}

	err := viper.BindPFlag("platform", flags.Lookup("platform"))
	return err
}

func rootExec(_ *cobra.Command, args []string) error {
	// we may not be provided an image if the user is piping in SBOM input
	var userInput string
	if len(args) > 0 {
		userInput = args[0]
	}

	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()
	if err != nil {
		return err
	}

	return eventLoop(
		startWorker(userInput, appConfig.FailOnEolFound, appConfig.EolMatchDate),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func isVerbose() (result bool) {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		// since we can't tell if there was piped input we assume that there could be to disable the ETUI
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return true
	}
	// verbosity should consider if there is piped input (in which case we should not show the ETUI)
	return appConfig.CliOptions.Verbosity > 0 || isPipedInput
}

//nolint:funlen
func startWorker(userInput string, failOnEolFound bool, eolMatchDate time.Time) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		presenterConfig, err := presenter.ValidatedConfig(appConfig.Output)
		if err != nil {
			errs <- err
			return
		}

		checkForAppUpdate()

		var store *store.Store
		var status *db.Status
		var dbCloser *db.Closer
		var packages []pkg.Package
		var sbom *sbom.SBOM
		var pkgContext pkg.Context
		var wg = &sync.WaitGroup{}
		var loadedDB, gatheredPackages bool

		wg.Add(2)

		go func() {
			defer wg.Done()
			log.Debug("loading DB")
			store, status, dbCloser, err = xeol.LoadEolDB(appConfig.DB.ToCuratorConfig(), appConfig.DB.AutoUpdate)
			if err = validateDBLoad(err, status); err != nil {
				errs <- err
				return
			}
			loadedDB = true
		}()

		go func() {
			defer wg.Done()
			log.Debugf("gathering packages")
			packages, pkgContext, sbom, err = pkg.Provide(userInput, getProviderConfig())
			if err != nil {
				errs <- fmt.Errorf("failed to catalog: %w", err)
				return
			}
			gatheredPackages = true
		}()
		wg.Wait()
		if !loadedDB || !gatheredPackages {
			return
		}

		if dbCloser != nil {
			defer dbCloser.Close()
		}

		matchers := matcher.NewDefaultMatchers(matcher.Config{
			Packages: pkgMatcher.MatcherConfig(appConfig.Match.Packages),
			Distro:   distroMatcher.MatcherConfig(appConfig.Match.Distro),
		})

		allMatches, err := xeol.FindEol(*store, pkgContext.Distro, matchers, packages, failOnEolFound, eolMatchDate)
		if err != nil {
			errs <- err
			if !errors.Is(err, xeolerr.ErrEolFound) {
				return
			}
		}

		pb := models.PresenterConfig{
			Matches:   allMatches,
			Packages:  packages,
			SBOM:      sbom,
			Context:   pkgContext,
			AppConfig: appConfig,
			DBStatus:  status,
		}

		if appConfig.APIKey != "" && appConfig.APIURL != "" {
			x := xeolio.NewXeolEvent(appConfig.APIURL, appConfig.APIKey, report.XeolEventPayload{
				Matches:   allMatches,
				Packages:  packages,
				Context:   pkgContext,
				AppConfig: appConfig,
			})
			if err := x.Send(); err != nil {
				errs <- fmt.Errorf("failed to send eol event: %w", err)
				return
			}
		}

		bus.Publish(partybus.Event{
			Type:  event.EolScanningFinished,
			Value: presenter.GetPresenter(presenterConfig, pb),
		})
	}()
	return errs
}

func getProviderConfig() pkg.ProviderConfig {
	return pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			RegistryOptions:        appConfig.Registry.ToOptions(),
			Exclusions:             nil,
			CatalogingOptions:      appConfig.Search.ToConfig(),
			Platform:               appConfig.Platform,
			Name:                   appConfig.Name,
			DefaultImagePullSource: appConfig.DefaultImagePullSource,
		},
	}
}

func validateDBLoad(loadErr error, status *db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load eol db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine the status of the eol db")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
	}
	return nil
}

func checkForAppUpdate() {
	if !appConfig.CheckForAppUpdate {
		return
	}

	isAvailable, newVersion, err := version.IsUpdateAvailable()
	if err != nil {
		log.Errorf(err.Error())
	}
	if isAvailable {
		log.Infof("new version of %s is available: %s (currently running: %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)

		bus.Publish(partybus.Event{
			Type:  event.AppUpdateAvailable,
			Value: newVersion,
		})
	} else {
		log.Debugf("no new %s update available", internal.ApplicationName)
	}
}
