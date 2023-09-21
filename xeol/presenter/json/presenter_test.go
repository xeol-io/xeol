package json

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
	"github.com/gkampitakis/go-snaps/snaps"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/presenter/internal"
	"github.com/xeol-io/xeol/xeol/presenter/models"
)

var timestampRegexp = regexp.MustCompile(`"timestamp":\s*"[^"]+"`)

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer
	matches, packages, context, _, _ := internal.GenerateAnalysis(t, internal.ImageSource)

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
	actual = redact(actual)

	snaps.MatchSnapshot(t, actual)

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	matches, packages, context, _, _ := internal.GenerateAnalysis(t, internal.DirectorySource)

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
	actual = redact(actual)

	snaps.MatchSnapshot(t, actual)
	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyJsonPresenter(t *testing.T) {
	// Expected to have an empty JSON array back
	var buffer bytes.Buffer

	matches := match.NewMatches()

	ctx := pkg.Context{
		Source: &source.Description{},
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
	actual = redact(actual)

	snaps.MatchSnapshot(t, actual)
}

func redact(content []byte) []byte {
	return timestampRegexp.ReplaceAll(content, []byte(`"timestamp":""`))
}
