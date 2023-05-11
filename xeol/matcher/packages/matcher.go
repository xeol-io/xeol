package packages

import (
	"time"

	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/search"
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

func (m *Matcher) Match(store eol.Provider, p pkg.Package, eolMatchDate time.Time) (match.Match, error) {
	return search.ByPackagePURL(store, p, m.Type(), eolMatchDate)
}
