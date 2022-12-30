package matcher

import (
	"github.com/noqcks/xeol/internal/bus"
	"github.com/noqcks/xeol/internal/log"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/event"
	"github.com/noqcks/xeol/xeol/match"
	pkgMatcher "github.com/noqcks/xeol/xeol/matcher/packages"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/linux"
)

type Monitor struct {
	PackagesProcessed progress.Monitorable
	EolDiscovered     progress.Monitorable
}

// Config contains values used by individual matcher structs for advanced configuration
type Config struct {
	Packages pkgMatcher.MatcherConfig
}

func NewDefaultMatchers(mc Config) []Matcher {
	return []Matcher{
		&pkgMatcher.Matcher{},
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
}, release *linux.Release, matchers []Matcher, packages []pkg.Package) (match.Matches, error) {
	var err error
	res := match.NewMatches()
	defaultMatcher := &pkgMatcher.Matcher{UsePurls: true}

	var d *distro.Distro
	if release != nil {
		d, err = distro.NewFromRelease(*release)
		if err != nil {
			log.Warnf("unable to determine linux distribution: %+v", err)
		}
	}

	packagesProcessed, eolDiscovered := trackMatcher()

	for _, p := range packages {
		packagesProcessed.N++
		log.Debugf("searching for eol matches for pkg=%s", p)

		pkgMatch, err := defaultMatcher.Match(store, d, p)
		if err != nil {
			log.Warnf("matcher failed for pkg=%s: %+v", p, err)
		}
		if (pkgMatch.Cycle != eol.Cycle{}) {
			logMatch(p)
			res.Add(pkgMatch)
			eolDiscovered.N++
		}
	}

	packagesProcessed.SetCompleted()
	eolDiscovered.SetCompleted()

	return res, nil
}

func logMatch(p pkg.Package) {
	log.Debugf("found eol match for purl=%s \n", p.PURL)
}
