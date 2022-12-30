package match

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	"github.com/mitchellh/hashstructure/v2"
)

type Fingerprint struct {
	releaseCycle string
	releaseDate  string
	packageID    pkg.ID // note: this encodes package name, version, type, location
}

func (m Fingerprint) String() string {
	return fmt.Sprintf("Fingerprint(releasecycle=%q releasedate=%q package=%q)", m.releaseCycle, m.releaseDate, m.packageID)
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
