package packages

import (
	"time"

	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/noqcks/xeol/xeol/distro"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
	"github.com/noqcks/xeol/xeol/pkg"
	"github.com/noqcks/xeol/xeol/search"
)

type Matcher struct {
	UsePurls bool
}

type MatcherConfig struct {
	UsePurls bool
}

func NewPackageMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{
		UsePurls: cfg.UsePurls,
	}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return nil
}

func (m *Matcher) Type() match.MatcherType {
	return match.PackageMatcher
}

func (m *Matcher) Match(store eol.Provider, d *distro.Distro, p pkg.Package, eolMatchDate time.Time) (match.Match, error) {
	return search.ByPackagePURL(store, p, m.Type(), eolMatchDate)
}
