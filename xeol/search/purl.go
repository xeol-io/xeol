package search

import (
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/anchore/grype/grype/pkg"

	"github.com/noqcks/xeol/internal/log"
	"github.com/noqcks/xeol/internal/purl"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
)

func ByPackagePURL(store eol.Provider, p pkg.Package, upstreamMatcher match.MatcherType) (match.Match, error) {
	shortPurl, err := purl.ShortPurl(p)
	if err != nil {
		return match.Match{}, err
	}

	cycles, err := store.GetByPurl(p)
	if err != nil {
		return match.Match{}, err
	}
	if len(cycles) < 1 {
		return match.Match{}, nil
	}

	return packageEOLMatch(shortPurl, p, cycles)
}

func returnMatchingCycle(version string, cycles []eol.Cycle) (eol.Cycle, error) {
	v, err := semver.NewVersion(version)
	if err != nil {
		return eol.Cycle{}, err
	}

	for _, c := range cycles {
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

func packageEOLMatch(shortPurl string, p pkg.Package, cycles []eol.Cycle) (match.Match, error) {
	cycle, err := returnMatchingCycle(p.Version, cycles)
	if err != nil {
		log.Debugf("error matching cycle for %s: %s", shortPurl, err)
		return match.Match{}, err
	}

	if cycle == (eol.Cycle{}) {
		return match.Match{}, nil
	}

	cycleEolDate, err := time.Parse("2006-01-02T15:04:05Z", cycle.Eol)
	if err != nil {
		log.Debugf("error parsing cycle eol date '%s' for %s: %s", cycle.Eol, shortPurl, err)
		return match.Match{}, err
	}

	today := time.Now()
	if today.After(cycleEolDate) {
		return match.Match{
			Cycle:   cycle,
			Package: p,
		}, nil
	}
	return match.Match{}, nil
}
