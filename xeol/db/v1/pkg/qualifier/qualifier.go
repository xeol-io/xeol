package qualifier

import (
	"fmt"

	"github.com/xeol-io/xeol/xeol/pkg/qualifier"
)

type Qualifier interface {
	fmt.Stringer
	Parse() qualifier.Qualifier
}
