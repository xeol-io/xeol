package db

import (
	"errors"

	"github.com/anchore/syft/syft/linux"

	"github.com/xeol-io/xeol/internal/purl"
	xeolDB "github.com/xeol-io/xeol/xeol/db/v1"
	"github.com/xeol-io/xeol/xeol/distro"
	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/pkg"
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

func (pr *EolProvider) GetByDistroCpe(r *linux.Release) (string, []eol.Cycle, string, error) {
	cycles := make([]eol.Cycle, 0)
	if r == nil {
		return "", []eol.Cycle{}, "", errors.New("empty distro release")
	}

	d, err := distro.NewFromRelease(*r)
	if err != nil {
		return "", []eol.Cycle{}, "", err
	}

	if d == nil || d.CPEName.String() == "" {
		return "", []eol.Cycle{}, "", errors.New("empty distro CPEName")
	}

	shortCPE, version := d.CPEName.Destructured()
	if version == "" || shortCPE == "" {
		return "", []eol.Cycle{}, "", errors.New("invalid distro CPEName")
	}

	allCycles, err := pr.reader.GetCyclesByCpe(shortCPE)
	if err != nil {
		return "", []eol.Cycle{}, "", err
	}

	for _, cycle := range allCycles {
		cycleObj, err := eol.NewCycle(cycle)
		if err != nil {
			return "", []eol.Cycle{}, "", err
		}
		cycles = append(cycles, *cycleObj)
	}

	return version, cycles, shortCPE, nil
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

func (pr *EolProvider) GetVulnCount(p pkg.Package) (int, error) {
	shortPurl, err := purl.ShortPurl(p)
	if err != nil {
		return 0, err
	}

	vulnCount, err := pr.reader.GetVulnCountByPurlAndVersion(shortPurl, p.Version)
	if err != nil {
		return 0, err
	}

	return vulnCount, nil
}
