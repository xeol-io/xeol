package commands

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/cmd/xeol/cli/options"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/xeol/db"
)

func DBStatus(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "status",
		Short: "display database status",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBStatus(opts.DB)
		},
	}, opts)
}

func runDBStatus(opts options.Database) error {
	defer bus.Exit()

	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	status := dbCurator.Status()

	statusStr := "valid"
	if status.Err != nil {
		statusStr = "invalid"
	}

	fmt.Println("Location: ", status.Location)
	fmt.Println("Built:    ", status.Built.String())
	fmt.Println("Schema:   ", status.SchemaVersion)
	fmt.Println("Checksum: ", status.Checksum)
	fmt.Println("Status:   ", statusStr)

	return status.Err
}
