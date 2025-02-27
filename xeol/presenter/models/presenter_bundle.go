package models

import (
	"github.com/anchore/syft/syft/sbom"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type PresenterConfig struct {
	Matches       match.Matches
	Packages      []pkg.Package
	Context       pkg.Context
	SBOM          *sbom.SBOM
	AppConfig     interface{}
	ShowVulnCount bool
	DBStatus      interface{}
}
