package cmd

import (
	"github.com/spf13/cobra"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "eol database operations",
}

func init() {
	rootCmd.AddCommand(dbCmd)
}
