package integration

import (
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/xeol-io/xeol/xeol"
	"github.com/xeol-io/xeol/xeol/db"
	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/matcher"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/store"
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
			ProductName:  "MongoDB Server",
			ReleaseCycle: "3.2",
			Eol:          "2018-07-31",
		},
	})
}

func addRuby27Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "ruby",
			ID:       "2ba17cf1680ce4f2",
			Version:  "2.7.8p225",
			Type:     syftPkg.BinaryPkg,
			Language: "",
			PURL:     "pkg:generic/ruby@2.7.8p225",
		},
		Cycle: eol.Cycle{
			ProductName:  "Ruby",
			ReleaseCycle: "2.7",
			Eol:          "2023-03-31",
		},
	})
}

func addPython34Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "python",
			ID:       "10ab199091f52dbc",
			Version:  "3.4.10",
			Type:     syftPkg.BinaryPkg,
			Language: "",
			PURL:     "pkg:generic/python@3.4.10",
		},
		Cycle: eol.Cycle{
			ProductName:  "Python",
			ReleaseCycle: "3.4",
			Eol:          "2019-03-18",
		},
	})
	// TODO: tracking issue https://github.com/anchore/syft/issues/2153
	// theResult.Add(match.Match{
	// 	Package: pkg.Package{
	// 		Name:     "python",
	// 		ID:       "5f9c938f5ff241bf",
	// 		Version:  "3.4.10",
	// 		Type:     syftPkg.BinaryPkg,
	// 		Language: "",
	// 		PURL:     "pkg:generic/python@3.4.10",
	// 	},
	// 	Cycle: eol.Cycle{
	// 		ProductName:  "Python",
	// 		ReleaseCycle: "3.4",
	// 		Eol:          "2019-03-18",
	// 	},
	// })
	// theResult.Add(match.Match{
	// 	Package: pkg.Package{
	// 		Name:     "python",
	// 		ID:       "2ba17cf1680ce4f2",
	// 		Version:  "2.7.13",
	// 		Type:     syftPkg.BinaryPkg,
	// 		Language: "",
	// 		PURL:     "pkg:generic/python@2.7.13",
	// 	},
	// 	Cycle: eol.Cycle{
	// 		ProductName:  "Python",
	// 		ReleaseCycle: "2.7",
	// 		Eol:          "2020-01-01",
	// 	},
	// })
}

func addGolang115Matches(t *testing.T, theResult *match.Matches) {
	// TODO: tracking issue https://github.com/anchore/syft/issues/2153
	// theResult.Add(match.Match{
	// 	Package: pkg.Package{
	// 		Name:     "python",
	// 		ID:       "2ba17cf1680ce4f2",
	// 		Version:  "2.7.16",
	// 		Type:     syftPkg.BinaryPkg,
	// 		Language: "",
	// 		PURL:     "pkg:generic/python@2.7.16",
	// 	},
	// 	Cycle: eol.Cycle{
	// 		ProductName:  "Python",
	// 		ReleaseCycle: "2.7",
	// 		Eol:          "2020-01-01",
	// 	},
	// })
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "go",
			ID:       "5f9c938f5ff241bf",
			Version:  "1.15.15",
			Type:     syftPkg.BinaryPkg,
			Language: "",
			PURL:     "pkg:generic/go@1.15.15",
		},
		Cycle: eol.Cycle{
			ProductName:  "Go",
			ReleaseCycle: "1.15",
			Eol:          "2021-08-16",
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
			ProductName:  "PostgreSQL",
			ReleaseCycle: "9.6",
			Eol:          "2021-11-11",
		},
	})
}

func addElaticsearch6Matches(t *testing.T, theResult *match.Matches) {
	// TODO: tracking issue https://github.com/anchore/syft/issues/2153
	// theResult.Add(match.Match{
	// 	Package: pkg.Package{
	// 		Name:     "python",
	// 		ID:       "2ba17cf1680ce4f2",
	// 		Version:  "2.7.5",
	// 		Type:     syftPkg.BinaryPkg,
	// 		Language: "",
	// 		PURL:     "pkg:generic/python@2.7.5",
	// 	},
	// 	Cycle: eol.Cycle{
	// 		ProductName:  "Python",
	// 		ReleaseCycle: "2.7",
	// 		Eol:          "2020-01-01",
	// 	},
	// })
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
			ProductName:  "Elasticsearch",
			Eol:          "2022-02-10",
		},
	})
}

func addNodejs6Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "node",
			ID:       "2ba17cf1680ce4f2",
			Version:  "6.13.1",
			Type:     syftPkg.BinaryPkg,
			Language: syftPkg.JavaScript,
			PURL:     "pkg:generic/node@6.13.1",
		},
		Cycle: eol.Cycle{
			ProductName:  "Node.js",
			ReleaseCycle: "6",
			Eol:          "2019-04-30",
		},
	})
}

func addRedis5Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:     "redis",
			ID:       "2ba17cf1680ce4f2",
			Version:  "5.0.14",
			Type:     syftPkg.BinaryPkg,
			Language: "",
			PURL:     "pkg:generic/redis@5.0.14",
		},
		Cycle: eol.Cycle{
			ProductName:  "Redis",
			ReleaseCycle: "5.0",
			Eol:          "2021-12-31",
		},
	})
}

func addFedora29Matches(t *testing.T, theResult *match.Matches) {
	theResult.Add(match.Match{
		Package: pkg.Package{
			Name:    "Fedora",
			Version: "29",
			Type:    "os",
		},
		Cycle: eol.Cycle{
			ProductName:  "Fedora",
			ReleaseCycle: "29",
			Eol:          "2019-11-26",
		},
	})
	// requires this PR to be merged first https://github.com/endoflife-date/endoflife.date/pull/3570
	// theResult.Add(match.Match{
	// 	Package: pkg.Package{
	// 		Name:     "python",
	// 		ID:       "2ba17cf1680ce4f2",
	// 		Version:  "3.7.2",
	// 		Type:     syftPkg.BinaryPkg,
	// 		Language: "",
	// 		PURL:     "pkg:generic/python@3.7.2",
	// 	},
	// 	Cycle: eol.Cycle{
	// 		ProductName:  "Python",
	// 		ReleaseCycle: "3.7",
	// 		Eol:          "2023-06-27",
	// 	},
	// })
}

func TestMatchByImage(t *testing.T) {
	tests := []struct {
		fixtureImage string
		expectedFn   func() match.Matches
	}{
		{
			fixtureImage: "image-fedora-29",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addFedora29Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-nodejs-6.13.1",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addNodejs6Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
		{
			fixtureImage: "image-ruby-2.7",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addRuby27Matches(t, &expectedMatches)
				return expectedMatches
			},
		},
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
		{
			fixtureImage: "image-redis-5",
			expectedFn: func() match.Matches {
				expectedMatches := match.NewMatches()
				addRedis5Matches(t, &expectedMatches)
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

			detection, err := source.Detect(userImage, source.DetectConfig{})
			require.NoError(t, err)

			// this is purely done to help setup mocks
			theSource, err := detection.NewSource(source.DetectionSourceConfig{})
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, theSource.Close())
			})

			// TODO: relationships are not verified at this time
			config := cataloger.DefaultConfig()
			config.Search.Scope = source.SquashedScope

			// enable all catalogers to cover non default cases
			config.Catalogers = []string{"all"}

			collection, _, theDistro, err := syft.CatalogPackages(theSource, config)
			require.NoError(t, err)

			matchers := matcher.NewDefaultMatchers(matcher.Config{})

			ep, err := db.NewEolProvider(theStore)
			require.NoError(t, err)
			str := store.Store{
				Provider: ep,
			}

			actualResults, err := xeol.FindEol(str, theDistro, matchers, pkg.FromCollection(collection, pkg.SynthesisConfig{}), false, time.Now())
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
