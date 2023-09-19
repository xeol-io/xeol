package commands

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/cmd/xeol/cli/options"
	"github.com/xeol-io/xeol/internal"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/xeol/db"
)

func DBImport(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "import FILE",
		Short: "import a EOL database archive",
		Long:  fmt.Sprintf("import a EOL database archive from a local FILE.\nDB archives can be obtained from %q.", internal.DBUpdateURL),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBImport(opts.DB, args[0])
		},
	}, opts)
}

func runDBImport(opts options.Database, dbArchivePath string) error {
	defer bus.Exit()

	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.ImportFrom(dbArchivePath); err != nil {
		return fmt.Errorf("unable to import EOL database: %+v", err)
	}

	return stderrPrintLnf("EOL database imported")
}
