package db

import (
	"errors"

	"github.com/anchore/syft/syft/linux"

	"github.com/noqcks/xeol/internal/cpe"
	"github.com/noqcks/xeol/internal/purl"
	xeolDB "github.com/noqcks/xeol/xeol/db/v1"
	"github.com/noqcks/xeol/xeol/eol"
	"github.com/noqcks/xeol/xeol/pkg"
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

func (pr *EolProvider) GetByDistroCpe(d *linux.Release) (string, []eol.Cycle, error) {
	cycles := make([]eol.Cycle, 0)

	if d == nil || d.CPEName == "" {
		return "", []eol.Cycle{}, errors.New("empty distro CPEName")
	}

	shortCPE, version := cpe.Destructure(d.CPEName)
	if version == "" || shortCPE == "" {
		return "", []eol.Cycle{}, errors.New("invalid distro CPEName")
	}

	allCycles, err := pr.reader.GetCyclesByCpe(shortCPE)
	if err != nil {
		return "", []eol.Cycle{}, err
	}

	for _, cycle := range allCycles {
		cycleObj, err := eol.NewCycle(cycle)
		if err != nil {
			return "", []eol.Cycle{}, err
		}
		cycles = append(cycles, *cycleObj)
	}

	return version, cycles, nil
}

func (pr *EolProvider) GetByPackagePurl(p pkg.Package) ([]eol.Cycle, error) {
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
