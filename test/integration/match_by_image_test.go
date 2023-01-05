package integration

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/noqcks/xeol/xeol"
	"github.com/noqcks/xeol/xeol/db"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/matcher"
	"github.com/noqcks/xeol/xeol/pkg"
	"github.com/noqcks/xeol/xeol/store"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

func addMongo32Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:    "mongodb-org-server",
			ID:      "5f9c938f5ff241bf",
			Version: "3.2.21",
			Type:    syftPkg.DebPkg,
			PURL:    "pkg:deb/debian/mongodb-org-server@3.2.21?arch=amd64&upstream=mongodb-org&distro=debian-8",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "3.2",
			Eol:          "2018-07-31T00:00:00Z",
		},
	})
}

func addPython34Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "python",
			ID:       "10ab199091f52dbc",
			Version:  "3.5.3",
			Type:     syftPkg.BinaryPkg,
			Language: syftPkg.Binary,
			PURL:     "pkg:generic/python@3.5.3",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "3.5",
			Eol:          "2020-09-13T00:00:00Z",
		},
	})
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "python",
			ID:       "5f9c938f5ff241bf",
			Version:  "3.4.10",
			Type:     syftPkg.BinaryPkg,
			Language: syftPkg.Binary,
			PURL:     "pkg:generic/python@3.4.10",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "3.4",
			Eol:          "2019-03-18T00:00:00Z",
		},
	})
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "python",
			ID:       "2ba17cf1680ce4f2",
			Version:  "2.7.13",
			Type:     syftPkg.BinaryPkg,
			Language: syftPkg.Binary,
			PURL:     "pkg:generic/python@2.7.13",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "2.7",
			Eol:          "2020-01-01T00:00:00Z",
		},
	})
}

func addGolang115Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "python",
			ID:       "2ba17cf1680ce4f2",
			Version:  "2.7.16",
			Type:     syftPkg.BinaryPkg,
			Language: syftPkg.Binary,
			PURL:     "pkg:generic/python@2.7.16",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "2.7",
			Eol:          "2020-01-01T00:00:00Z",
		},
	})
}

func addPostgres9Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:    "postgresql-9.6",
			ID:      "2ba17cf1680ce4f2",
			Version: "9.6.24-1.pgdg90+1",
			Type:    syftPkg.DebPkg,
			PURL:    "pkg:deb/debian/postgresql-9.6@9.6.24-1.pgdg90+1?arch=amd64&distro=debian-9",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "9.6",
			Eol:          "2021-11-11T00:00:00Z",
		},
	})
}

func addElaticsearch6Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "python",
			ID:       "2ba17cf1680ce4f2",
			Version:  "2.7.5",
			Type:     syftPkg.BinaryPkg,
			Language: syftPkg.Binary,
			PURL:     "pkg:generic/python@2.7.5",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "2.7",
			Eol:          "2020-01-01T00:00:00Z",
		},
	})
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "elasticsearch",
			ID:       "2ba17cf1680ce4f2",
			Version:  "6.8.21",
			Type:     syftPkg.JavaPkg,
			Language: syftPkg.Java,
			PURL:     "pkg:maven/org.elasticsearch%23server/elasticsearch@6.8.21",
		},
		Cycle: eol.Cycle{
			ReleaseCycle: "6",
			Eol:          "2022-02-10T00:00:00Z",
		},
	})
}

// func addDebianOSMatches(t *testing.T, theResult *match.Matches) {}
// func addUbuntuOSMatches(t *testing.T, theResult *match.Matches) {}
// func addAlpineOSMatches(t *testing.T, theResult *match.Matches) {}

func TestMatchByImage(t *testing.T) {
	tests := []struct {
		fixtureImage string
		expectedFn   func() match.Matches
	}{
		{
			fixtureImage: "image-python-3.4",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addPython34Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-mongo-3.2",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addMongo32Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-golang-1.15",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addGolang115Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-postgres-9",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addPostgres9Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-elasticsearch-6",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addElaticsearch6Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixtureImage, func(t *testing.T) {
			theStore := newMockDbStore()

			imagetest.GetFixtureImage(t, "docker-archive", test.fixtureImage)
			tarPath := imagetest.GetFixtureImageTarPath(t, test.fixtureImage)

			userImage := "docker-archive:" + tarPath

			sourceInput, err := source.ParseInput(userImage, "", true)
			require.NoError(t, err)

			// this is purely done to help setup mocks
			theSource, cleanup, err := source.New(*sourceInput, nil, nil)
			require.NoError(t, err)
			defer cleanup()

			// TODO: relationships are not verified at this time
			config := cataloger.DefaultConfig()
			config.Search.Scope = source.SquashedScope

			// enable all catalogers to cover non default cases
			config.Catalogers = []string{"all"}

			theCatalog, _, theDistro, err := syft.CatalogPackages(theSource, config)
			require.NoError(t, err)

			matchers := matcher.NewDefaultMatchers(matcher.Config{})

			ep, err := db.NewEolProvider(theStore)
			require.NoError(t, err)
			str := store.Store{
				Provider: ep,
			}

			actualResults, err := xeol.FindEolForPackage(str, theDistro, matchers, pkg.FromCatalog(theCatalog, pkg.SynthesisConfig{}))
			require.NoError(t, err)

			// build expected matches from what's discovered from the catalog
			expectedMatches := test.expectedFn()

			assertMatches(t, expectedMatches.Sorted(), actualResults.Sorted())
		})
	}
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
		cmpopts.IgnoreFields(pkg.Package{}, "CPEs"),
		cmpopts.IgnoreFields(pkg.Package{}, "Licenses"),
		cmpopts.IgnoreFields(pkg.Package{}, "Upstreams"),
		cmpopts.IgnoreFields(pkg.Package{}, "MetadataType"),
		cmpopts.IgnoreFields(pkg.Package{}, "Metadata"),
		cmpopts.IgnoreFields(pkg.Package{}, "ID"),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
