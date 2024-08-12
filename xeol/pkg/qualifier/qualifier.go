package qualifier

import (
	"github.com/xeol-io/xeol/xeol/distro"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type Qualifier interface {
	Satisfied(d *distro.Distro, p pkg.Package) (bool, error)
}
