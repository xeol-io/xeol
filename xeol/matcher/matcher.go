package matcher

import (
	"github.com/noqcks/xeol/xeol/match"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher interface {
	PackageTypes() []syftPkg.Type
	Type() match.MatcherType
}
