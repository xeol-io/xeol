package match

import (
	"testing"

	"github.com/google/uuid"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatchesSortByCycleProductName(t *testing.T) {
	first := Match{
		Cycle: eol.Cycle{
			ProductName: "product-a",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Cycle: eol.Cycle{
			ProductName: "product-b",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())
}

func TestMatchesSortByPackage(t *testing.T) {
	first := Match{
		Cycle: eol.Cycle{
			ProductName:  "product-a",
			Eol:          "2020-01-01",
			ReleaseCycle: "1",
			ReleaseDate:  "2020-01-01",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Cycle: eol.Cycle{
			ProductName:  "product-a",
			Eol:          "2020-01-01",
			ReleaseCycle: "1",
			ReleaseDate:  "2020-01-01",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-c",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		second, first,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second}, matches.Sorted())
}

func assertMatchOrder(t *testing.T, expected, actual []Match) {

	var expectedStr []string
	for _, e := range expected {
		expectedStr = append(expectedStr, e.Package.Name)
	}

	var actualStr []string
	for _, a := range actual {
		actualStr = append(actualStr, a.Package.Name)
	}

	// makes this easier on the eyes to sanity check...
	require.Equal(t, expectedStr, actualStr)

	// make certain the fields are what you'd expect
	assert.Equal(t, expected, actual)
}

func TestMatchesSortMixedDimensions(t *testing.T) {
	first := Match{
		Cycle: eol.Cycle{
			ProductName: "product-a",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-a",
			Version: "1.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	second := Match{
		Cycle: eol.Cycle{
			ProductName: "product-b",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-b",
			Version: "1.0.0",
			Type:    syftPkg.NpmPkg,
		},
	}
	third := Match{
		Cycle: eol.Cycle{
			ProductName: "product-c",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-c",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}
	fourth := Match{
		Cycle: eol.Cycle{
			ProductName: "product-d",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-d",
			Version: "3.0.0",
			Type:    syftPkg.ApkPkg,
		},
	}
	fifth := Match{
		Cycle: eol.Cycle{
			ProductName: "product-e",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "package-e",
			Version: "2.0.0",
			Type:    syftPkg.RpmPkg,
		},
	}

	input := []Match{
		// shuffle releasecycle, package name, package version, and package type
		fifth, third, first, second, fourth,
	}
	matches := NewMatches(input...)

	assertMatchOrder(t, []Match{first, second, third, fourth, fifth}, matches.Sorted())

}
