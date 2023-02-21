package distro

import (
	"testing"
	"time"

	"github.com/anchore/syft/syft/linux"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/noqcks/xeol/xeol/db"
	xeolDB "github.com/noqcks/xeol/xeol/db/v1"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/pkg"
)

type mockStore struct {
	backend map[string][]xeolDB.Cycle
}

func (s *mockStore) GetCyclesByPurl(purl string) ([]xeolDB.Cycle, error) {
	return s.backend[purl], nil
}

func (s *mockStore) GetCyclesByCpe(cpe string) ([]xeolDB.Cycle, error) {
	return s.backend[cpe], nil
}

func (s *mockStore) GetAllProducts() (*[]xeolDB.Product, error) {
	return nil, nil
}

func TestMatch(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "Fedora",
		ReleaseDate:       "2019-11-26",
		ReleaseCycle:      "29",
		Eol:               "2019-11-26",
		LatestReleaseDate: "2019-11-26",
	}

	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"cpe:/o:fedoraproject:fedora": {cycle},
		},
	}

	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	p := pkg.Package{
		ID:      "",
		Name:    "Fedora",
		Version: "29",
		Type:    "os",
	}

	cycleFound, err := eol.NewCycle(cycle)
	d := &linux.Release{
		Name:    "Fedora",
		Version: "29",
		CPEName: "cpe:/o:fedoraproject:fedora:29",
	}
	assert.NoError(t, err)
	expected := match.Match{
		Cycle:   *cycleFound,
		Package: p,
	}
	actual, err := m.Match(provider, d, time.Now())
	assert.NoError(t, err)
	assertMatches(t, expected, actual)
}

func TestMatchCpeMismatch(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "Fedora",
		ReleaseDate:       "2019-11-26",
		ReleaseCycle:      "29",
		Eol:               "2019-11-26",
		LatestReleaseDate: "2019-11-26",
	}

	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"cpe:/o:canonical:ubuntu": {cycle},
		},
	}
	m := Matcher{}
	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	d := &linux.Release{
		Name:    "Fedora",
		Version: "29",
		CPEName: "cpe:/o:fedoraproject:fedora:29",
	}

	actual, err := m.Match(provider, d, time.Now())
	assert.NoError(t, err)
	assertMatches(t, match.Match{}, actual)
}

func TestMatchNoMatchingVersion(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "Fedora",
		ReleaseDate:       "2019-11-26",
		ReleaseCycle:      "28", // different version
		Eol:               "2019-11-26",
		LatestReleaseDate: "2019-11-26",
	}

	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"cpe:/o:fedoraproject:fedora": {cycle},
		},
	}

	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	// Set up a matcher and a package with the same PURL but a different version
	m := Matcher{}
	d := &linux.Release{
		Name:    "Fedora",
		Version: "29",
		CPEName: "cpe:/o:fedoraproject:fedora:29",
	}

	actual, err := m.Match(provider, d, time.Now())
	assert.NoError(t, err)
	assertMatches(t, match.Match{}, actual)
}

func TestMatchTimeChange(t *testing.T) {
	cycle := xeolDB.Cycle{
		ProductName:       "Fedora",
		ReleaseDate:       "2019-11-26",
		ReleaseCycle:      "29",
		Eol:               "2019-11-26",
		LatestReleaseDate: "2019-11-26",
	}

	store := mockStore{
		backend: map[string][]xeolDB.Cycle{
			"cpe:/o:fedoraproject:fedora": {cycle},
		},
	}

	provider, err := db.NewEolProvider(&store)
	require.NoError(t, err)

	m := Matcher{}
	d := &linux.Release{
		Name:    "Fedora",
		Version: "29",
		CPEName: "cpe:/o:fedoraproject:fedora:29",
	}

	eolMatchTime, err := time.Parse("2006-01-02", "2018-01-01")
	assert.NoError(t, err)

	actual, err := m.Match(provider, d, eolMatchTime)
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
