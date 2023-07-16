package ui

import (
	"fmt"
	"io"

	"github.com/gookit/color"
	"github.com/wagoodman/go-partybus"

	xeolEventParsers "github.com/xeol-io/xeol/xeol/event/parsers"
	"github.com/xeol-io/xeol/xeol/policy"
)

func handlePolicyEvaluationMessage(event partybus.Event, reportOutput io.Writer) error {
	// show the report to stdout
	pt, err := xeolEventParsers.ParsePolicyEvaluationMessage(event)
	if err != nil {
		return fmt.Errorf("bad %s event: %w", event.Type, err)
	}

	var message string
	if pt.Type == policy.PolicyTypeDeny {
		message = color.Red.Sprintf("[%s] Policy Violation: %s (v%s) needs to upgraded to a newer version. This scan will now exit non-zero.\n\n", pt.Type, pt.ProductName, pt.Cycle)
	} else {
		message = color.Yellow.Sprintf("[%s] Policy Violation: %s (v%s) needs to be upgraded to a newer version. This policy will fail builds starting on %s.\n\n", pt.Type, pt.ProductName, pt.Cycle, pt.FailDate)
	}
	if _, err := reportOutput.Write([]byte(message)); err != nil {
		return fmt.Errorf("unable to show policy evaluation message: %w", err)
	}
	return nil
}

func handleEolScanningFinished(event partybus.Event, reportOutput io.Writer) error {
	// show the report to stdout
	pres, err := xeolEventParsers.ParseEolScanningFinished(event)
	if err != nil {
		return fmt.Errorf("bad CatalogerFinished event: %w", err)
	}

	if err := pres.Present(reportOutput); err != nil {
		return fmt.Errorf("unable to show eol report: %w", err)
	}
	return nil
}

func handleNonRootCommandFinished(event partybus.Event, reportOutput io.Writer) error {
	// show the report to stdout
	result, err := xeolEventParsers.ParseNonRootCommandFinished(event)
	if err != nil {
		return fmt.Errorf("bad NonRootCommandFinished event: %w", err)
	}

	if _, err := reportOutput.Write([]byte(*result)); err != nil {
		return fmt.Errorf("unable to show eol report: %w", err)
	}
	return nil
}
