package distro

import (
	"time"

	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/search"
)

type Matcher struct {
	UseCPEs bool
}

type MatcherConfig struct {
	UseCPEs bool
}

func NewPackageMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		UseCPEs: cfg.UseCPEs,
	}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PackageMatcher
}

func (m *Matcher) Match(store eol.Provider, d *linux.Release, eolMatchDate time.Time) (match.Match, string, error) {
	return search.ByDistroCpe(store, d, eolMatchDate)
}
