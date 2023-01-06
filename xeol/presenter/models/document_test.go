package models

import (
	"testing"

	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"

	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/pkg"
)

func TestPackagesAreSorted(t *testing.T) {

	var pkg1 = pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.DebPkg,
	}

	var pkg2 = pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.2.2",
		Type:    syftPkg.DebPkg,
	}

	var match1 = match.Match{
		Cycle: eol.Cycle{
			ProductName:       "MongoDB Server",
			ReleaseDate:       "2018-07-31",
			ReleaseCycle:      "2.8",
			Eol:               "2018-07-31",
			LatestReleaseDate: "2018-07-31",
		},
		Package: pkg1,
	}

	var match2 = match.Match{
		Cycle: eol.Cycle{
			ProductName:       "MongoDB Server",
			ReleaseDate:       "2018-07-31",
			ReleaseCycle:      "3.2",
			Eol:               "2018-07-31",
			LatestReleaseDate: "2018-07-31",
		},
		Package: pkg1,
	}

	var match3 = match.Match{
		Cycle: eol.Cycle{
			ProductName:       "MongoDB Server",
			ReleaseDate:       "2020-07-31",
			ReleaseCycle:      "3.4",
			Eol:               "2020-07-31",
			LatestReleaseDate: "2020-07-31",
		},
		Package: pkg1,
	}

	matches := match.NewMatches()
	matches.Add(match1, match2, match3)

	packages := []pkg.Package{pkg1, pkg2}

	ctx := pkg.Context{
		Source: &syftSource.Metadata{
			Scheme:        syftSource.DirectoryScheme,
			ImageMetadata: syftSource.ImageMetadata{},
		},
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}
	doc, err := NewDocument(packages, ctx, matches, nil, nil)
	if err != nil {
		t.Fatalf("unable to get document: %+v", err)
	}

	var actualEols []string
	for _, m := range doc.Matches {
		actualEols = append(actualEols, m.Cycle.ReleaseCycle)
	}

	assert.Equal(t, []string{"2.8", "3.2", "3.4"}, actualEols)
}
