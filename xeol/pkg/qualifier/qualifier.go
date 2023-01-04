package qualifier

import "github.com/noqcks/xeol/xeol/pkg"

type Qualifier interface {
	Satisfied(p pkg.Package) (bool, error)
}
