package qualifier

import "github.com/xeol-io/xeol/xeol/pkg"

type Qualifier interface {
	Satisfied(p pkg.Package) (bool, error)
}
