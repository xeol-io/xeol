package models

import (
	"fmt"

	"github.com/xeol-io/xeol/xeol/eol"
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
	var eol string
	if c.Eol == "0001-01-01" || len(c.Eol) < 1 {
		eol = fmt.Sprintf("%t", c.EolBool)
	} else {
		eol = c.Eol
	}

	return Cycle{
		ProductName:       c.ProductName,
		ReleaseCycle:      c.ReleaseCycle,
		Eol:               eol,
		LatestRelease:     c.LatestRelease,
		LatestReleaseDate: c.LatestReleaseDate,
		ReleaseDate:       c.ReleaseDate,
	}
}
