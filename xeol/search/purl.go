package search

import (
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

func ByPackagePURL(store eol.Provider, p pkg.Package, _ match.MatcherType, eolMatchDate time.Time) (match.Match, error) {
	cycles, err := store.GetByPackagePurl(p)
	if err != nil {
		return match.Match{}, err
	}
	if len(cycles) < 1 {
		return match.Match{}, nil
	}

	cycle, err := cycleMatch(p.Version, cycles, eolMatchDate)
	if err != nil {
		log.Warnf("failed to match cycle for package %s: %v", p, err)
		return match.Match{}, nil
	}

	if (cycle != eol.Cycle{}) {
		return match.Match{
			Cycle:   cycle,
			Package: p,
		}, nil
	}
	return match.Match{}, nil
}

func ByDistroCpe(store eol.Provider, distro *linux.Release, eolMatchDate time.Time) (match.Match, error) {
	version, cycles, err := store.GetByDistroCpe(distro)
	if err != nil {
		return match.Match{}, err
	}
	if len(cycles) < 1 {
		return match.Match{}, nil
	}

	log.Debugf("matching distro %s with version %s", distro.Name, version)
	cycle, err := cycleMatch(version, cycles, eolMatchDate)
	if err != nil {
		log.Warnf("failed to match cycle for distro %s: %v", distro.Name, err)
		return match.Match{}, nil
	}

	if (cycle != eol.Cycle{}) {
		return match.Match{
			Cycle: cycle,
			Package: pkg.Package{
				Name:    distro.Name,
				Version: version,
				Type:    "os",
			},
		}, nil
	}

	log.Warnf("failed to match cycle for distro %s: %v", distro.Name, err)
	return match.Match{}, nil
}

// returnMatchingCycle returns the first cycle that matches the version string.
// If no cycle matches, an empty cycle is returned.
func returnMatchingCycle(version string, cycles []eol.Cycle) (eol.Cycle, error) {
	v, err := semver.NewVersion(version)
	if err != nil {
		return eol.Cycle{}, err
	}

	for _, c := range cycles {
		// direct match, if it exists
		if version == c.ReleaseCycle {
			return c, nil
		}

		// match on major, minor, or patch
		versionLength := len(strings.Split(c.ReleaseCycle, "."))
		cv, err := semver.NewVersion(c.ReleaseCycle)
		if err != nil {
			return eol.Cycle{}, err
		}
		switch versionLength {
		case 1:
			if v.Major() == cv.Major() {
				return c, nil
			}
		case 2:
			if v.Major() == cv.Major() && v.Minor() == cv.Minor() {
				return c, nil
			}
		case 3:
			if v.Major() == cv.Major() && v.Minor() == cv.Minor() && v.Patch() == cv.Patch() {
				return c, nil
			}
		}
	}

	return eol.Cycle{}, nil
}

func cycleMatch(version string, cycles []eol.Cycle, eolMatchDate time.Time) (eol.Cycle, error) {
	cycle, err := returnMatchingCycle(version, cycles)
	if err != nil {
		log.Debugf("error matching cycle for %s: %s", err)
		return eol.Cycle{}, err
	}

	if cycle == (eol.Cycle{}) {
		return cycle, nil
	}

	// return the cycle if it is boolean EOL
	if cycle.EolBool {
		return cycle, nil
	}

	// return the cycle if the EOL date is after the match date
	cycleEolDate, err := time.Parse("2006-01-02", cycle.Eol)
	if err != nil {
		log.Debugf("error parsing cycle eol date '%s' for %s: %s", cycle.Eol, err)
		return eol.Cycle{}, err
	}

	if eolMatchDate.After(cycleEolDate) {
		return cycle, nil
	}
	return eol.Cycle{}, nil
}
