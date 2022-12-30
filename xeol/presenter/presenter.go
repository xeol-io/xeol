package presenter

import (
	"io"

	"github.com/noqcks/xeol/xeol/presenter/json"
	"github.com/noqcks/xeol/xeol/presenter/models"
	"github.com/noqcks/xeol/xeol/presenter/table"
)

type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(c Config, pb models.PresenterConfig) Presenter {
	switch c.format {
	case jsonFormat:
		return json.NewPresenter(pb)
	case tableFormat:
		return table.NewPresenter(pb)
	default:
		return nil
	}
}
