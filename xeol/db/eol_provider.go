package db

import (
	"github.com/noqcks/xeol/xeol/pkg"

	"github.com/noqcks/xeol/internal/purl"
	xeolDB "github.com/noqcks/xeol/xeol/db/v1"
	"github.com/noqcks/xeol/xeol/eol"
)

var _ eol.Provider = (*EolProvider)(nil)

type EolProvider struct {
	reader xeolDB.EolStoreReader
}

func NewEolProvider(reader xeolDB.EolStoreReader) (*EolProvider, error) {
	return &EolProvider{
		reader: reader,
	}, nil
}

func (pr *EolProvider) GetByPurl(p pkg.Package) ([]eol.Cycle, error) {
	cycles := make([]eol.Cycle, 0)

	shortPurl, err := purl.ShortPurl(p)
	if err != nil {
		return []eol.Cycle{}, err
	}

	allCycles, err := pr.reader.GetCyclesByPurl(shortPurl)
	if err != nil {
		return []eol.Cycle{}, err
	}

	for _, cycle := range allCycles {
		cycleObj, err := eol.NewCycle(cycle)
		if err != nil {
			return []eol.Cycle{}, err
		}
		cycles = append(cycles, *cycleObj)
	}

	return cycles, nil
}
