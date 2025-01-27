package cli

import (
	"os"
	"runtime/debug"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/syft"
	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/cmd/xeol/cli/commands"
	handler "github.com/xeol-io/xeol/cmd/xeol/cli/ui"
	"github.com/xeol-io/xeol/cmd/xeol/internal/ui"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/internal/redact"
	"github.com/xeol-io/xeol/xeol/eol"
)

func Application(id clio.Identification) clio.Application {
	app, _ := create(id)
	return app
}

func Command(id clio.Identification) *cobra.Command {
	_, cmd := create(id)
	return cmd
}

func create(id clio.Identification) (clio.Application, *cobra.Command) {
	clioCfg := clio.NewSetupConfig(id).
		WithGlobalConfigFlag().   // add persistent -c <path> for reading an application config from
		WithGlobalLoggingFlags(). // add persistent -v and -q flags tied to the logging config
		WithConfigInRootHelp().   // --help on the root command renders the full application config in the help text
		WithLoggingConfig(        // default to error level logging
			clio.LoggingConfig{Level: logger.ErrorLevel}).
		WithUIConstructor(
			// select a UI based on the logging configuration and state of stdin (if stdin is a tty)
			func(cfg clio.Config) ([]clio.UI, error) {
				noUI := ui.None(cfg.Log.Quiet)
				if !cfg.Log.AllowUI(os.Stdin) || cfg.Log.Quiet {
					return []clio.UI{noUI}, nil
				}

				h := handler.New(handler.DefaultHandlerConfig())

				return []clio.UI{
					ui.New(cfg.Log.Quiet, h),
					noUI,
				}, nil
			},
		).
		WithInitializers(
			func(state *clio.State) error {
				// clio is setting up and providing the bus, redact store, and logger to the application. Once loaded,
				// we can hoist them into the internal packages for global use.
				stereoscope.SetBus(state.Bus)
				syft.SetBus(state.Bus)
				bus.Set(state.Bus)

				redact.Set(state.RedactStore)

				stereoscope.SetLogger(state.Logger)
				syft.SetLogger(state.Logger)
				log.Set(state.Logger)

				return nil
			},
		)

	app := clio.New(*clioCfg)

	rootCmd := commands.Root(app)

	// add sub-commands
	rootCmd.AddCommand(
		commands.DB(app),
		commands.Completion(),
		clio.VersionCommand(id, syftVersion, dbVersion),
	)

	return app, rootCmd
}

func syftVersion() (string, any) {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Debug("unable to find the buildinfo section of the binary (syft version is unknown)")
		return "", ""
	}

	for _, d := range buildInfo.Deps {
		if d.Path == "github.com/anchore/syft" {
			return "Syft Version", d.Version
		}
	}

	log.Debug("unable to find 'github.com/anchore/syft' from the buildinfo section of the binary")
	return "", ""
}

func dbVersion() (string, any) {
	return "Supported DB Schema", eol.SchemaVersion
}
