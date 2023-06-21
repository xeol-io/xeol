package report

import (
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type XeolEventPayload struct {
	Matches   match.Matches
	Packages  []pkg.Package
	Context   pkg.Context
	AppConfig interface{}
}
