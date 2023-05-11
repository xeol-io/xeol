package distro

import (
	"time"

	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/search"
)

type Matcher struct {
	UseCpes bool
}

type MatcherConfig struct {
	UseCpes bool
}

func NewPackageMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		UseCpes: cfg.UseCpes,
	}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PackageMatcher
}

func (m *Matcher) Match(store eol.Provider, d *linux.Release, eolMatchDate time.Time) (match.Match, error) {
	return search.ByDistroCpe(store, d, eolMatchDate)
}
