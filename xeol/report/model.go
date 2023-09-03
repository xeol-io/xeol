package report

import (
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type XeolEventPayload struct {
	Matches       []match.Match
	Packages      []pkg.Package
	Context       pkg.Context
	AppConfig     interface{}
	ImageVerified bool
	EventSource   map[string]interface{}
	Sbom          string
}
