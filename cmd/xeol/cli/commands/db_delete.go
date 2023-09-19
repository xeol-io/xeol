package commands

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/cmd/xeol/cli/options"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/xeol/db"
)

func DBDelete(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "delete",
		Short: "delete the EOL database",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBDelete(opts.DB)
		},
	}, opts)
}

func runDBDelete(opts options.Database) error {
	defer bus.Exit()

	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete EOL database: %+v", err)
	}

	return stderrPrintLnf("EOL database deleted")
}
