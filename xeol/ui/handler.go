package ui

import (
	"context"
	"sync"

	syftUI "github.com/anchore/syft/ui"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	xeolEvent "github.com/xeol-io/xeol/xeol/event"
)

type Handler struct {
	syftHandler *syftUI.Handler
}

func NewHandler() *Handler {
	return &Handler{
		syftHandler: syftUI.NewHandler(),
	}
}

func (r *Handler) RespondsTo(event partybus.Event) bool {
	switch event.Type {
	case xeolEvent.EolScanningStarted, xeolEvent.UpdateEolDatabase:
		return true
	default:
		return r.syftHandler.RespondsTo(event)
	}
}

func (r *Handler) Handle(ctx context.Context, fr *frame.Frame, event partybus.Event, wg *sync.WaitGroup) error {
	switch event.Type {
	case xeolEvent.UpdateEolDatabase:
		return r.UpdateEolDatabaseHandler(ctx, fr, event, wg)
	case xeolEvent.EolScanningStarted:
		return r.EolScanningStartedHandler(ctx, fr, event, wg)
	default:
		return r.syftHandler.Handle(ctx, fr, event, wg)
	}
}
