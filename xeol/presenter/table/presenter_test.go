package table

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/anchore/go-testutils"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"

	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/pkg"
	"github.com/noqcks/xeol/xeol/presenter/models"
)

var update = flag.Bool("update", true, "update the *.golden files for table presenters")

func TestCreateRow(t *testing.T) {
	pkg := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
	}
	match1 := match.Match{
		Cycle: eol.Cycle{
			ProductName:       "MongoDB Server",
			ReleaseDate:       "2018-07-31",
			ReleaseCycle:      "2.8",
			Eol:               "2018-07-31",
			LatestReleaseDate: "2018-07-31",
		},
		Package: pkg,
	}
	match2 := match.Match{
		Cycle: eol.Cycle{
			ProductName:       "MongoDB Server",
			ReleaseDate:       "2018-07-31",
			ReleaseCycle:      "2.8",
			Eol:               "2025-01-01",
			LatestReleaseDate: "2018-07-31",
		},
		Package: pkg,
	}

	cases := []struct {
		name           string
		match          match.Match
		severitySuffix string
		expectedErr    error
		expectedRow    []string
	}{
		{
			name:        "create row for eol",
			match:       match1,
			expectedErr: nil,
			expectedRow: []string{match1.Package.Name, match1.Package.Version, match1.Cycle.Eol, "1614", match1.Package.Type.PackageURLType()},
		},
		{
			name:        "create row for eol in the future",
			match:       match2,
			expectedErr: nil,
			expectedRow: []string{match2.Package.Name, match2.Package.Version, match2.Cycle.Eol, "-", match2.Package.Type.PackageURLType()},
		},
	}

	now = func() time.Time { return time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC) }

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			row, err := createRow(testCase.match)

			assert.Equal(t, testCase.expectedErr, err)
			assert.Equal(t, testCase.expectedRow, row)
		})
	}
}

func TestTablePresenter(t *testing.T) {

	var buffer bytes.Buffer
	matches, packages, _, _, _ := models.GenerateAnalysis(t, source.ImageScheme)

	pb := models.PresenterConfig{
		Matches:  matches,
		Packages: packages,
	}

	pres := NewPresenter(pb)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(strings.TrimSuffix(strings.TrimSpace(string(expected)), "\n"), strings.TrimSuffix(strings.TrimSpace(string(actual)), "\n"), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyTablePresenter(t *testing.T) {
	// Expected to have no output

	var buffer bytes.Buffer

	matches := match.NewMatches()

	pb := models.PresenterConfig{
		Matches:  matches,
		Packages: nil,
	}

	pres := NewPresenter(pb)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}
