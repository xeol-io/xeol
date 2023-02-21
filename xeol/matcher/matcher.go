package matcher

import (
	"github.com/noqcks/xeol/xeol/match"
)

type Matcher interface {
	Type() match.MatcherType
}
