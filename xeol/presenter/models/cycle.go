package models

import (
	"github.com/noqcks/xeol/xeol/eol"
)

type Cycle struct {
	ProductName       string
	ReleaseCycle      string
	Eol               string
	LatestRelease     string
	LatestReleaseDate string
	ReleaseDate       string
}

func NewCycle(c eol.Cycle) Cycle {
	return Cycle{
		ProductName:       c.ProductName,
		ReleaseCycle:      c.ReleaseCycle,
		Eol:               c.Eol,
		LatestRelease:     c.LatestRelease,
		LatestReleaseDate: c.LatestReleaseDate,
		ReleaseDate:       c.ReleaseDate,
	}
}
