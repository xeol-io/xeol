package eol

import (
	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/xeol/pkg"
)

type Provider interface {
	ProviderByPackagePurl
	ProviderByDistroCpe
}

type ProviderByPackagePurl interface {
	GetByPackagePurl(p pkg.Package) ([]Cycle, error)
}

type ProviderByDistroCpe interface {
	GetByDistroCpe(distro *linux.Release) (string, []Cycle, string, error)
}
