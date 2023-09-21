package format

import (
	"github.com/wagoodman/go-presenter"

	"github.com/xeol-io/xeol/xeol/presenter/json"
	"github.com/xeol-io/xeol/xeol/presenter/models"
	"github.com/xeol-io/xeol/xeol/presenter/table"
)

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(format Format, pb models.PresenterConfig) presenter.Presenter {
	switch format {
	case JSONFormat:
		return json.NewPresenter(pb)
	case TableFormat:
		return table.NewPresenter(pb)
	default:
		return nil
	}
}
