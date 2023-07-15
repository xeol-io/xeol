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

	"github.com/xeol-io/xeol/internal"
	"github.com/xeol-io/xeol/internal/version"
	xeolEventParsers "github.com/xeol-io/xeol/xeol/event/parsers"
	"github.com/xeol-io/xeol/xeol/policy"
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

func handlePolicyEvaluationMessage(_ context.Context, fr *frame.Frame, event partybus.Event, _ *sync.WaitGroup) error {
	pt, err := xeolEventParsers.ParsePolicyEvaluationMessage(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	line, err := fr.Append()
	if err != nil {
		return err
	}
	var message string
	if pt.Type == policy.PolicyTypeDeny {
		message = color.Red.Sprintf("[%s] Policy Violation: %s (v%s) needs to upgraded to a newer version. This scan will now exit non-zero.", pt.Type, pt.ProductName, pt.Cycle)
	} else {
		message = color.Yellow.Sprintf("[%s] Policy Violation: %s (v%s) needs to be upgraded to a newer version. This policy will fail builds starting on %s.", pt.Type, pt.ProductName, pt.Cycle, pt.FailDate)
	}
	_, _ = io.WriteString(line, message)
	return nil
}
