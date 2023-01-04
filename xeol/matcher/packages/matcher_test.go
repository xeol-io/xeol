package packages

import (
	"testing"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/noqcks/xeol/xeol/distro"
	"github.com/noqcks/xeol/xeol/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/noqcks/xeol/xeol/db"
	xeolDB "github.com/noqcks/xeol/xeol/db/v1"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
)

type mockStore struct {
	backend map[string][]xeolDB.Cycle
}

func (s *mockStore) GetCyclesByPurl(purl string) ([]xeolDB.Cycle, error) {
	return s.backend[purl], nil
}

func (s *mockStore) GetAllProducts() (*[]xeolDB.Product, error) {
	return nil, nil
}

func TestMatch(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "MongoDB Server",
		ReleaseDate:       "2018-07-31T00:00:00Z",
		ReleaseCycle:      "3.2",
		Eol:               "2018-07-31T00:00:00Z",
		LatestReleaseDate: "2018-07-31T00:00:00Z",
	}

	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"pkg:deb/debian/mongodb-org-server": {cycle},
		},
	}

	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "mongodb-org-server",
		Version: "3.2.21",
		Type:    syftPkg.DebPkg,
		PURL:    "pkg:deb/debian/mongodb-org-server@3.2.21?arch=amd64&upstream=mongodb-org&distro=debian-8",
	}

	cycleFound, err := eol.NewCycle(cycle)
	assert.NoError(t, err)
	expected := match.Match{
		Cycle:   *cycleFound,
		Package: p,
	}
	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)
	assertMatches(t, expected, actual)
}

func TestMatchPurlMismatch(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "MongoDB Server",
		ReleaseDate:       "2018-07-31T00:00:00Z",
		ReleaseCycle:      "3.2",
		Eol:               "2018-07-31T00:00:00Z",
		LatestReleaseDate: "2018-07-31T00:00:00Z",
	}
	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"pkg:deb/debian/different-package": {cycle},
		},
	}
	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "mongodb-org-server",
		Version: "3.2.21",
		Type:    syftPkg.DebPkg,
		PURL:    "pkg:deb/debian/mongodb-org-server@3.2.21?arch=amd64&upstream=mongodb-org&distro=debian-8",
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)
	assertMatches(t, match.Match{}, actual)
}

func TestMatchNoMatchingVersion(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "MongoDB Server",
		ReleaseDate:       "2018-07-31T00:00:00Z",
		ReleaseCycle:      "3.3", // different version
		Eol:               "2018-07-31T00:00:00Z",
		LatestReleaseDate: "2018-07-31T00:00:00Z",
	}

	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"pkg:deb/debian/mongodb-org-server": {cycle},
		},
	}

	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	// Set up a matcher and a package with the same PURL but a different version
	m := Matcher{}
	d, err := distro.New(distro.Alpine, "3.12.0", "")
	if err != nil {
		t.Fatalf("failed to create a new distro: %+v", err)
	}
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "mongodb-org-server",
		Version: "3.2.21", // different version
		Type:    syftPkg.DebPkg,
		PURL:    "pkg:deb/debian/mongodb-org-server@3.2.21?arch=amd64&upstream=mongodb-org&distro=debian-8",
	}

	actual, err := m.Match(provider, d, p)
	assert.NoError(t, err)
	assertMatches(t, match.Match{}, actual)
}

func assertMatches(t *testing.T, expected, actual match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
