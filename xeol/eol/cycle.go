package eol

import (
	xeolDB "github.com/noqcks/xeol/xeol/db/v1"
)

type Cycle struct {
	ProductName       string
	ReleaseCycle      string
	Eol               string
	LatestRelease     string
	LatestReleaseDate string
	ReleaseDate       string
}

func NewCycle(cycle xeolDB.Cycle) (*Cycle, error) {
	return &Cycle{
		ReleaseCycle:      cycle.ReleaseCycle,
		Eol:               cycle.Eol,
		LatestRelease:     cycle.LatestRelease,
		LatestReleaseDate: cycle.LatestReleaseDate,
		ReleaseDate:       cycle.ReleaseDate,
	}, nil
}
