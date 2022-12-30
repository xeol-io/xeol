package matcher

import (
	syftPkg "github.com/anchore/syft/syft/pkg"

	"github.com/noqcks/xeol/xeol/match"
)

type Matcher interface {
	PackageTypes() []syftPkg.Type
	Type() match.MatcherType
}
