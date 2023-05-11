package json

import (
	"encoding/json"
	"io"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/presenter/models"
)

// Presenter is a generic struct for holding fields needed for reporting
type Presenter struct {
	matches   match.Matches
	packages  []pkg.Package
	context   pkg.Context
	appConfig interface{}
	dbStatus  interface{}
}

// NewPresenter is a *Presenter constructor
func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		matches:   pb.Matches,
		packages:  pb.Packages,
		context:   pb.Context,
		appConfig: pb.AppConfig,
		dbStatus:  pb.DBStatus,
	}
}

// Present creates a JSON-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	doc, err := models.NewDocument(pres.packages, pres.context, pres.matches, pres.appConfig, pres.dbStatus)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
