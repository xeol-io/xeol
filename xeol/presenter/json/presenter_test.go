package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/presenter/models"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer
	matches, packages, context, _, _ := models.GenerateAnalysis(t, source.ImageScheme)

	pb := models.PresenterConfig{
		Matches:  matches,
		Packages: packages,
		Context:  context,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	matches, packages, context, _, _ := models.GenerateAnalysis(t, source.DirectoryScheme)

	pb := models.PresenterConfig{
		Matches:  matches,
		Packages: packages,
		Context:  context,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyJsonPresenter(t *testing.T) {
	// Expected to have an empty JSON array back
	var buffer bytes.Buffer

	matches := match.NewMatches()

	ctx := pkg.Context{
		Source: &source.Metadata{},
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}

	pb := models.PresenterConfig{
		Matches:  matches,
		Packages: nil,
		Context:  ctx,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))
}
