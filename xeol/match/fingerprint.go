package match

import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"
)

type Fingerprint struct {
	releaseCycle string
	releaseDate  string
	productName  string
	eolDate      string
	eolBool      bool
	lts          string
}

func (m Fingerprint) String() string {
	return fmt.Sprintf("Fingerprint(releasecycle=%q releasedate=%q productname=%q eoldate=%q eolbool=%t lts=%q)", m.releaseCycle, m.releaseDate, m.productName, m.eolDate, m.eolBool, m.lts)
}

func (m Fingerprint) ID() string {
	f, err := hashstructure.Hash(&m, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return ""
	}

	return fmt.Sprintf("%x", f)
}
