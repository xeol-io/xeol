package terraform

import (
	"time"

	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/search"
)

type Matcher struct {}

type MatcherConfig struct {}

func NewTerraformMatcher(cfg MatcherConfig) *Matcher {
	return &Matcher{}
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	// Let's assume Syft might have a generic type or we just intercept Terraform specifically
	// "terraform" or "hashicorp" might be the package type returned by Syft's lock file cataloger
	return []syftPkg.Type{"terraform"}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PackageMatcher
}

func (m *Matcher) Match(store eol.Provider, p pkg.Package, eolMatchDate time.Time) (match.Match, error) {
	// If the package is not terraform, don't match
	if p.Type != "terraform" {
		return match.Match{}, nil
	}

	// We can mutate the PURL here if needed before passing to store,
	// or just rely on search.ByPackagePURL if it matches the DB schema.
	return search.ByPackagePURL(store, p, m.Type(), eolMatchDate)
}
