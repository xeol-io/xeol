//go:build linux || darwin
// +build linux darwin

package ui

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/jotframe/pkg/frame"

	"github.com/noqcks/xeol/internal"
	"github.com/noqcks/xeol/internal/version"
	xeolEventParsers "github.com/noqcks/xeol/xeol/event/parsers"
)

func handleAppUpdateAvailable(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	newVersion, err := xeolEventParsers.ParseAppUpdateAvailable(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Prepend()
	if err != nil {
		return err
	}

	message := color.Magenta.Sprintf("New version of %s is available: %s (currently running: %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)
	_, _ = io.WriteString(line, message)

	return nil
}
