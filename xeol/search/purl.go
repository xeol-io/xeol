package search

import (
	"regexp"
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

func ByDistroCpe(store eol.Provider, distro *linux.Release, eolMatchDate time.Time) (match.Match, string, error) {
	version, cycles, distroCPE, err := store.GetByDistroCpe(distro)
	if err != nil {
		return match.Match{}, "", err
	}
	if len(cycles) < 1 {
		return match.Match{}, "", nil
	}

	log.Debugf("attempting to match distro %s with version %s", distro.Name, version)
	cycle, err := cycleMatch(version, cycles, eolMatchDate)
	if err != nil {
		log.Warnf("failed to match cycle for distro %s: %v", distro.Name, err)
		return match.Match{}, "", nil
	}

	if (cycle != eol.Cycle{}) {
		return match.Match{
			Cycle: cycle,
			Package: pkg.Package{
				Name:    distro.Name,
				Version: version,
				Type:    "os",
			},
		}, distroCPE, nil
	}

	log.Debugf("matched cycle for distro %s: %v", distro.Name, version)
	return match.Match{}, "", nil
}

// normalizeSemver returns the major.minor.patch portion of a semver string
// that may have other characters appended to it. We should be very careful
// here to create matches for patterns we KNOW, because otherwise we could
// introduce false positives.
func normalizeSemver(version string) string {
	// For Ruby versions. Example: 2.5.3p105 -> 2.5.3
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+)p\d+`)
	version = re.ReplaceAllString(version, "$1")

	// Handle 4-component versions.
	// Example: 5.0.20.5194 -> 5.0.20
	// Example: 2.0.4.RELEASE -> 2.0.4
	fourCompRe := regexp.MustCompile(`^(\d+\.\d+\.\d+)\.\w+`)
	version = fourCompRe.ReplaceAllString(version, "$1")

	// Handle packages with tilde (~) characters
	// Example: 1.23.3-1~bullseye
	tildeRe := regexp.MustCompile(`^(\d+\.\d+\.\d+)-\d+~\w+`)
	return tildeRe.ReplaceAllString(version, "$1")
}

func versionLength(version string) int {
	parts := strings.SplitN(version, "-", 2)
	regularVersionParts := strings.Split(parts[0], ".")
	length := len(regularVersionParts)
	// increment if there's a pre-release part
	if len(parts) > 1 && parts[1] != "" {
		length++
	}
	return length
}

// returnMatchingCycle returns the first cycle that matches the version string.
// If no cycle matches, an empty cycle is returned.
func returnMatchingCycle(version string, cycles []eol.Cycle) (eol.Cycle, error) {
	normalizedVersion := normalizeSemver(version)
	v, err := semver.NewVersion(normalizedVersion)
	if err != nil {
		return eol.Cycle{}, err
	}

	for _, c := range cycles {
		// direct match, if it exists
		if normalizedVersion == c.ReleaseCycle {
			return c, nil
		}

		// match on major, minor, or patch
		versionLength := versionLength(c.ReleaseCycle)
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
		case 4:
			if v.Major() == cv.Major() && v.Minor() == cv.Minor() && v.Patch() == cv.Patch() && v.Prerelease() == cv.Prerelease() {
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
