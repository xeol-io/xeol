package matcher

import (
	"time"

	"github.com/anchore/syft/syft/linux"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/match"
	distroMatcher "github.com/xeol-io/xeol/xeol/matcher/distro"
	pkgMatcher "github.com/xeol-io/xeol/xeol/matcher/packages"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type Monitor struct {
	PackagesProcessed progress.Monitorable
	EolDiscovered     progress.Monitorable
}

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Packages pkgMatcher.MatcherConfig
	Distro   distroMatcher.MatcherConfig
}

func NewDefaultMatchers(_ Config) []Matcher {
	return []Matcher{
		&pkgMatcher.Matcher{},
		&distroMatcher.Matcher{},
	}
}

func trackMatcher() (*progress.Manual, *progress.Manual) {
	packagesProcessed := progress.Manual{}
	eolDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.EolScanningStarted,
		Value: Monitor{
			PackagesProcessed: progress.Monitorable(&packagesProcessed),
			EolDiscovered:     progress.Monitorable(&eolDiscovered),
		},
	})
	return &packagesProcessed, &eolDiscovered
}

func FindMatches(store interface {
	eol.Provider
}, distro *linux.Release, _ []Matcher, packages []pkg.Package, _ bool, eolMatchDate time.Time) match.Matches {
	// var err error
	res := match.NewMatches()
	defaultMatcher := &pkgMatcher.Matcher{
		UsePurls: true,
	}
	distroMatcher := &distroMatcher.Matcher{
		UseCpes: true,
	}

	distroMatch, err := distroMatcher.Match(store, distro, eolMatchDate)
	if err != nil {
		log.Warnf("matcher failed for distro=%s: %+v", distro, err)
	}
	if (distroMatch.Cycle != eol.Cycle{}) {
		logDistroMatch(distro)
		res.Add(distroMatch)
	}

	packagesProcessed, eolDiscovered := trackMatcher()

	for _, p := range packages {
		packagesProcessed.Increment()
		log.Debugf("searching for eol matches for pkg=%s", p)

		pkgMatch, err := defaultMatcher.Match(store, p, eolMatchDate)
		if err != nil {
			log.Warnf("matcher failed for pkg=%s: %+v", p, err)
		}
		if (pkgMatch.Cycle != eol.Cycle{}) {
			logPkgMatch(p)
			res.Add(pkgMatch)
			eolDiscovered.Increment()
		}
	}

	packagesProcessed.SetCompleted()
	eolDiscovered.SetCompleted()

	return res
}

func logDistroMatch(d *linux.Release) {
	log.Debugf("found eol match for distro cpe=%s \n", d.CPEName)
}

func logPkgMatch(p pkg.Package) {
	log.Debugf("found eol match for pkg purl=%s \n", p.PURL)
}
