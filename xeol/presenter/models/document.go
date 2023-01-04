package models

import (
	"fmt"

	"github.com/noqcks/xeol/xeol/pkg"

	"github.com/noqcks/xeol/internal"
	"github.com/noqcks/xeol/internal/version"
	"github.com/noqcks/xeol/xeol/match"
)

// Document represents the JSON document to be presented
type Document struct {
	Matches    []Match      `json:"matches"`
	Source     *source      `json:"source"`
	Distro     distribution `json:"distro"`
	Descriptor descriptor   `json:"descriptor"`
}

// NewDocument creates and populates a new Document struct, representing the populated JSON document.
func NewDocument(packages []pkg.Package, context pkg.Context, matches match.Matches, appConfig interface{}, dbStatus interface{}) (Document, error) {
	// we must preallocate the findings to ensure the JSON document does not show "null" when no matches are found
	var findings = make([]Match, 0)
	for _, m := range matches.Sorted() {
		p := pkg.ByID(m.Package.ID, packages)
		if p == nil {
			return Document{}, fmt.Errorf("unable to find package in collection: %+v", p)
		}

		matchModel := newMatch(m, *p)
		findings = append(findings, *matchModel)
	}

	var src *source
	if context.Source != nil {
		theSrc, err := newSource(*context.Source)
		if err != nil {
			return Document{}, err
		}
		src = &theSrc
	}

	return Document{
		Matches: findings,
		Source:  src,
		Distro:  newDistribution(context.Distro),
		Descriptor: descriptor{
			Name:          internal.ApplicationName,
			Version:       version.FromBuild().Version,
			Configuration: appConfig,
			EolDBStatus:   dbStatus,
		},
	}, nil
}
