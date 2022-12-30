package packages

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/match"
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

func (m *Matcher) Match(store eol.Provider, d *distro.Distro, p pkg.Package) (match.Match, error) {
	return search.ByPackagePURL(store, p, m.Type())
}
