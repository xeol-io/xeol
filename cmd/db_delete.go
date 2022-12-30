package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/noqcks/xeol/xeol/db"
)

var dbDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete the eol database",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBDeleteCmd,
}

func init() {
	dbCmd.AddCommand(dbDeleteCmd)
}

func runDBDeleteCmd(_ *cobra.Command, _ []string) error {
	dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
	if err != nil {
		return err
	}

	if err := dbCurator.Delete(); err != nil {
		return fmt.Errorf("unable to delete eol database: %+v", err)
	}

	return stderrPrintLnf("eol database deleted")
}
