package match

import (
	"fmt"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/pkg"
)

var ErrCannotMerge = fmt.Errorf("unable to merge eol matches")

// Match represents a finding in the eol matching process, pairing a single package and a single eol object.
type Match struct {
	Cycle     eol.Cycle
	Package   pkg.Package // The package used to search for a match.
	VulnCount int
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s releasedate=%q releasecycle=%s purl=%s)", m.Package, m.Cycle.ReleaseDate, m.Cycle.ReleaseCycle, m.Package.PURL)
}

func (m Match) Summary() string {
	return fmt.Sprintf("releasecycle=%q releasedate=%q purl=%q", m.Cycle.ReleaseCycle, m.Cycle.ReleaseDate, m.Package.PURL)
}

func (m Match) Fingerprint() Fingerprint {
	return Fingerprint{
		releaseCycle: m.Cycle.ReleaseCycle,
		releaseDate:  m.Cycle.ReleaseDate,
		productName:  m.Cycle.ProductName,
		eolDate:      m.Cycle.Eol,
		eolBool:      m.Cycle.EolBool,
		lts:          m.Cycle.LTS,
	}
}

func (m *Match) Merge(other Match) error {
	if other.Fingerprint() != m.Fingerprint() {
		return ErrCannotMerge
	}

	return nil
}
