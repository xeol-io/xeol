package commands

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/cmd/xeol/cli/options"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/db"
)

func DBUpdate(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "update",
		Short: "download the latest EOL database",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBUpdate(opts.DB)
		},
	}, opts)
}

func runDBUpdate(opts options.Database) error {
	defer bus.Exit()

	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}
	updated, err := dbCurator.Update()
	if err != nil {
		return fmt.Errorf("unable to update EOL database: %+v", err)
	}

	result := "No EOL database update available\n"
	if updated {
		result = "EOL database updated to latest version!\n"
	}

	log.Debugf("completed db update check with result: %s", result)

	bus.Report(result)

	return nil
}
