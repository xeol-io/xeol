package qualifier

import (
	"fmt"

	"github.com/noqcks/xeol/xeol/pkg/qualifier"
)

type Qualifier interface {
	fmt.Stringer
	Parse() qualifier.Qualifier
}
