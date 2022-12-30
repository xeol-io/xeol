package eol

import "github.com/anchore/grype/grype/pkg"

type Provider interface {
	ProviderByPurl
}

type ProviderByPurl interface {
	GetByPurl(p pkg.Package) ([]Cycle, error)
}
