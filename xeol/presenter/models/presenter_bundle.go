package models

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/sbom"

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
