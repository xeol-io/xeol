package models

import (
	"testing"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

// See https://github.com/xeol-io/xeol/issues/62 : the JSON presenter's Match.Package
// field (the deprecated, pre-"artifact" field kept for backwards compatibility) was
// never populated by newMatch, so every match in `xeol -o json` output reports an
// entirely blank/null Package object even though the newer Artifact field is filled in
// correctly from the very same pkg.Package.
func TestNewMatch_PackageFieldIsPopulated(t *testing.T) {
	p := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.DebPkg,
	}

	m := match.Match{
		Cycle: eol.Cycle{
			ProductName:  "MongoDB Server",
			ReleaseCycle: "3.2",
		},
		Package: p,
	}

	result := newMatch(m, p)

	assert.Equal(t, p, result.Package, "the deprecated Package field must mirror the package used to find the match, not be left as its zero value")
	assert.Equal(t, p.Name, result.Artifact.Name, "the newer Artifact field should still be populated as before")
}
