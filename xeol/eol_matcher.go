package xeol

import (
	"time"

	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/matcher"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/store"
	"github.com/xeol-io/xeol/xeol/xeolerr"
)

type EolMatcher struct {
	Store          store.Store
	Matchers       []matcher.Matcher
	FailOnEolFound bool
	EolMatchDate   time.Time
	LinuxRelease   *linux.Release
}

func (e *EolMatcher) FindEol(packages []pkg.Package) (match.Matches, error) {
	matches := matcher.FindMatches(e.Store, e.LinuxRelease, e.Matchers, packages, e.FailOnEolFound, e.EolMatchDate)
	var err error
	if e.FailOnEolFound && matches.Count() > 0 {
		err = xeolerr.ErrEolFound
	}
	return matches, err
}
