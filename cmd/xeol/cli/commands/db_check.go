package commands

import (
	"fmt"
	"os"

	"github.com/anchore/clio"
	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/cmd/xeol/cli/options"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/xeol/db"
)

const (
	exitCodeOnDBUpgradeAvailable = 100
)

func DBCheck(app clio.Application) *cobra.Command {
	opts := dbOptionsDefault(app.ID())

	return app.SetupCommand(&cobra.Command{
		Use:   "check",
		Short: "check to see if there is a database update available",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBCheck(opts.DB)
		},
	}, opts)
}

func runDBCheck(opts options.Database) error {
	defer bus.Exit()

	dbCurator, err := db.NewCurator(opts.ToCuratorConfig())
	if err != nil {
		return err
	}

	updateAvailable, currentDBMetadata, updateDBEntry, err := dbCurator.IsUpdateAvailable()
	if err != nil {
		return fmt.Errorf("unable to check for eol database update: %+v", err)
	}

	if !updateAvailable {
		return stderrPrintLnf("No update available")
	}

	fmt.Println("Update available!")

	if currentDBMetadata != nil {
		fmt.Printf("Current DB version %d was built on %s\n", currentDBMetadata.Version, currentDBMetadata.Built.String())
	}

	fmt.Printf("Updated DB version %d was built on %s\n", updateDBEntry.Version, updateDBEntry.Built.String())
	fmt.Printf("Updated DB URL: %s\n", updateDBEntry.URL.String())
	fmt.Println("You can run 'xeol db update' to update to the latest db")

	os.Exit(exitCodeOnDBUpgradeAvailable) //nolint:gocritic

	return nil
}
