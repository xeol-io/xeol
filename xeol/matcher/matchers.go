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
	"github.com/xeol-io/xeol/xeol/event/monitor"
	"github.com/xeol-io/xeol/xeol/match"
	distroMatcher "github.com/xeol-io/xeol/xeol/matcher/distro"
	pkgMatcher "github.com/xeol-io/xeol/xeol/matcher/packages"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type Monitor struct {
	PackagesProcessed progress.Monitorable
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

type monitorWriter struct {
	PackagesProcessed *progress.Manual
	MatchesDiscovered *progress.Manual
}

func newMonitor(pkgCount int) (monitorWriter, monitor.Matching) {
	m := monitorWriter{
		PackagesProcessed: progress.NewManual(int64(pkgCount)),
		MatchesDiscovered: progress.NewManual(-1),
	}

	return m, monitor.Matching{
		PackagesProcessed: m.PackagesProcessed,
		MatchesDiscovered: m.MatchesDiscovered,
	}
}

func trackMatcher(pkgCount int) *monitorWriter {
	writer, reader := newMonitor(pkgCount)

	bus.Publish(partybus.Event{
		Type:  event.EolScanningStarted,
		Value: reader,
	})
	return &writer
}

func (m *monitorWriter) SetCompleted() {
	m.PackagesProcessed.SetCompleted()
	m.MatchesDiscovered.SetCompleted()
}

func FindMatches(store interface {
	eol.Provider
}, distro *linux.Release, _ []Matcher, packages []pkg.Package, _ bool, eolMatchDate time.Time) match.Matches {
	res := match.NewMatches()
	defaultMatcher := &pkgMatcher.Matcher{
		UsePURLs: true,
	}
	distroMatcher := &distroMatcher.Matcher{
		UseCPEs: true,
	}

	progressMonitor := trackMatcher(len(packages))
	defer progressMonitor.SetCompleted()

	distroMatch, distroCPE, err := distroMatcher.Match(store, distro, eolMatchDate)
	if err != nil {
		log.Warnf("matcher failed for distro=%s: %+v", distro, err)
	}
	if (distroMatch.Cycle != eol.Cycle{}) {
		logDistroMatch(distroCPE)
		res.Add(distroMatch)
		progressMonitor.MatchesDiscovered.Increment()
	}

	for _, p := range packages {
		progressMonitor.PackagesProcessed.Increment()
		log.Debugf("searching for eol matches for pkg=%s", p)

		pkgMatch, err := defaultMatcher.Match(store, p, eolMatchDate)
		if err != nil {
			log.Warnf("matcher failed for pkg=%s: %+v", p, err)
		}
		if (pkgMatch.Cycle != eol.Cycle{}) {
			logPkgMatch(p)
			res.Add(pkgMatch)
			progressMonitor.MatchesDiscovered.Increment()
		}
	}

	return res
}

func logDistroMatch(distroCPE string) {
	log.Debugf("found eol match for distro cpe=%s \n", distroCPE)
}

func logPkgMatch(p pkg.Package) {
	log.Debugf("found eol match for pkg purl=%s \n", p.PURL)
}
