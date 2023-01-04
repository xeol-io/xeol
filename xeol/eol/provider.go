package eol

import "github.com/noqcks/xeol/xeol/pkg"

type Provider interface {
	ProviderByPurl
}

type ProviderByPurl interface {
	GetByPurl(p pkg.Package) ([]Cycle, error)
}
