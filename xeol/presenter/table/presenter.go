package table

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/olekukonko/tablewriter"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/presenter/models"
)

var now = time.Now

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	matches       match.Matches
	packages      []pkg.Package
	showVulnCount bool
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		matches:       pb.Matches,
		packages:      pb.Packages,
		showVulnCount: pb.ShowVulnCount,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	rows := make([][]string, 0)

	columns := []string{"NAME", "VERSION", "EOL", "DAYS EOL", "TYPE"}
	if pres.showVulnCount {
		columns = append(columns, "# OF VULNS.")
	}

	// Generate rows for matches
	for m := range pres.matches.Enumerate() {
		if m.Package.Name == "" {
			continue
		}
		row, err := createRow(m, pres.showVulnCount)

		if err != nil {
			return err
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		_, err := io.WriteString(output, "✅ no EOL software has been found\n")
		return err
	}

	// sort by name, version, then type
	sort.SliceStable(rows, func(i, j int) bool {
		for col := 0; col < len(columns); col++ {
			if rows[i][0] != rows[j][0] {
				return rows[i][col] < rows[j][col]
			}
		}
		return false
	})

	table := tablewriter.NewWriter(output)

	table.SetHeader(columns)
	table.SetAutoWrapText(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetAutoFormatHeaders(true)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	table.AppendBulk(rows)
	table.Render()

	return nil
}

func createRow(m match.Match, showVulnCount bool) ([]string, error) {
	daysEol, err := calculateDaysEol(m)
	if err != nil {
		return nil, err
	}

	row := []string{m.Package.Name, m.Package.Version}
	if m.Cycle.EolBool {
		row = append(row, "YES", "-", string(m.Package.Type))
	} else {
		row = append(row, m.Cycle.Eol, daysEol, string(m.Package.Type))
	}

	if showVulnCount {
		row = append(row, strconv.Itoa(m.VulnCount))
	}

	return row, nil
}

func calculateDaysEol(m match.Match) (string, error) {
	today := now()
	cycleEolDate, err := time.Parse("2006-01-02", m.Cycle.Eol)
	if err != nil {
		return "", fmt.Errorf("unable to parse EOL date for package %s: %w", m.Package.PURL, err)
	}

	daysEol := int((today.Sub(cycleEolDate).Hours() / 24))
	if daysEol < 0 {
		return "-", nil
	}
	return strconv.Itoa(daysEol), nil
}
