package eol

import (
	xeolDB "github.com/xeol-io/xeol/xeol/db/v1"
)

type Cycle struct {
	ProductName       string
	ReleaseCycle      string
	Eol               string
	EolBool           bool
	LatestRelease     string
	LatestReleaseDate string
	ReleaseDate       string
}

func NewCycle(cycle xeolDB.Cycle) (*Cycle, error) {
	return &Cycle{
		ProductName:       cycle.ProductName,
		ReleaseCycle:      cycle.ReleaseCycle,
		Eol:               cycle.Eol,
		EolBool:           cycle.EolBool,
		LatestRelease:     cycle.LatestRelease,
		LatestReleaseDate: cycle.LatestReleaseDate,
		ReleaseDate:       cycle.ReleaseDate,
	}, nil
}
