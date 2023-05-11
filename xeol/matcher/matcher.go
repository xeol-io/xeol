package matcher

import (
	"github.com/xeol-io/xeol/xeol/match"
)

type Matcher interface {
	Type() match.MatcherType
}
