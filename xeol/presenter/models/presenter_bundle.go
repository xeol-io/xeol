package models

import (
	"github.com/anchore/syft/syft/sbom"
	"github.com/noqcks/xeol/xeol/pkg"

	"github.com/noqcks/xeol/xeol/match"
)

type PresenterConfig struct {
	Matches   match.Matches
	Packages  []pkg.Package
	Context   pkg.Context
	SBOM      *sbom.SBOM
	AppConfig interface{}
	DBStatus  interface{}
}
