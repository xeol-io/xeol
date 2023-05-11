package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/xeol-io/xeol/internal"
	"github.com/xeol-io/xeol/internal/version"
)

var versionOutputFormat string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show the version",
	RunE:  printVersion,
}

func init() {
	versionCmd.Flags().StringVarP(&versionOutputFormat, "output", "o", "text", "format to display results (available=[text, json])")

	rootCmd.AddCommand(versionCmd)
}

func printVersion(_ *cobra.Command, _ []string) error {
	versionInfo := version.FromBuild()
	switch versionOutputFormat {
	case "text":
		fmt.Println("Application:         ", internal.ApplicationName)
		fmt.Println("Version:             ", versionInfo.Version)
		fmt.Println("Syft Version:        ", versionInfo.SyftVersion)
		fmt.Println("GitCommit:           ", versionInfo.GitCommit)
		fmt.Println("Platform:            ", versionInfo.Platform)
		fmt.Println("GoVersion:           ", versionInfo.GoVersion)
		fmt.Println("Compiler:            ", versionInfo.Compiler)
	case "json":

		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		err := enc.Encode(&struct {
			version.Version
			Application string `json:"application"`
		}{
			Version:     versionInfo,
			Application: internal.ApplicationName,
		})
		if err != nil {
			return fmt.Errorf("failed to show version information: %+v", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", versionOutputFormat)
	}
	return nil
}
