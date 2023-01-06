package table

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/olekukonko/tablewriter"

	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/pkg"
	"github.com/noqcks/xeol/xeol/presenter/models"
)

var now = time.Now

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	results  match.Matches
	packages []pkg.Package
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		results:  pb.Matches,
		packages: pb.Packages,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	rows := make([][]string, 0)

	columns := []string{"NAME", "VERSION", "EOL", "DAYS EOL", "METHOD"}
	// Generate rows for matches
	for m := range pres.results.Enumerate() {
		if m.Package.Name == "" {
			continue
		}
		row, err := createRow(m)

		if err != nil {
			return err
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		_, err := io.WriteString(output, "No eol software found\n")
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

func createRow(m match.Match) ([]string, error) {
	daysEol, err := calculateDaysEol(m)
	if err != nil {
		return nil, err
	}

	return []string{m.Package.Name, m.Package.Version, m.Cycle.Eol, daysEol, m.Package.Type.PackageURLType()}, nil
}

func calculateDaysEol(m match.Match) (string, error) {
	today := now()
	cycleEolDate, err := time.Parse("2006-01-02", m.Cycle.Eol)
	if err != nil {
		return "", fmt.Errorf("unable to parse EOL date for package %s: %w", m.Package.PURL, err)
	}
	daysEol := strconv.Itoa(int(today.Sub(cycleEolDate).Hours() / 24))
	return daysEol, nil
}
