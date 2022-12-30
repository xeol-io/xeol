package ui

import (
	"context"
	"sync"

	xeolEvent "github.com/noqcks/xeol/xeol/event"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	syftUI "github.com/anchore/syft/ui"
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
