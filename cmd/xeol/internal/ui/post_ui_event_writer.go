package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/event/parsers"

	xeolEventParsers "github.com/xeol-io/xeol/xeol/event/parsers"
	policyTypes "github.com/xeol-io/xeol/xeol/policy/types"
)

var (
	terminalRed    = lipgloss.Color("196")
	terminalYellow = lipgloss.Color("214")
)

type postUIEventWriter struct {
	handles []postUIHandle
}

type postUIHandle struct {
	respectQuiet bool
	event        partybus.EventType
	writer       io.Writer
	dispatch     eventWriter
}

type eventWriter func(io.Writer, ...partybus.Event) error

func newPostUIEventWriter(stdout, stderr io.Writer) *postUIEventWriter {
	return &postUIEventWriter{
		handles: []postUIHandle{
			{
				event:        event.EolPolicyEvaluationMessage,
				respectQuiet: false,
				writer:       stdout,
				dispatch:     writeEolPolicyEvaluationMessage,
			},
			{
				event:        event.NotaryPolicyEvaluationMessage,
				respectQuiet: false,
				writer:       stdout,
				dispatch:     writeNotaryPolicyEvaluationMessage,
			},
			{
				event:        event.CLIReport,
				respectQuiet: false,
				writer:       stdout,
				dispatch:     writeReports,
			},
			{
				event:        event.CLINotification,
				respectQuiet: true,
				writer:       stderr,
				dispatch:     writeNotifications,
			},
			{
				event:        event.CLIAppUpdateAvailable,
				respectQuiet: true,
				writer:       stderr,
				dispatch:     writeAppUpdate,
			},
		},
	}
}

func (w postUIEventWriter) write(quiet bool, events ...partybus.Event) error {
	var errs error
	for _, h := range w.handles {
		if quiet && h.respectQuiet {
			continue
		}

		for _, e := range events {
			if e.Type != h.event {
				continue
			}

			if err := h.dispatch(h.writer, e); err != nil {
				errs = multierror.Append(errs, err)
			}
		}
	}
	return errs
}

func writeReports(writer io.Writer, events ...partybus.Event) error {
	var reports []string
	for _, e := range events {
		_, report, err := parsers.ParseCLIReport(e)
		if err != nil {
			log.WithFields("error", err).Warn("failed to gather final report")
			continue
		}

		// remove all whitespace padding from the end of the report
		reports = append(reports, strings.TrimRight(report, "\n ")+"\n")
	}

	// prevent the double new-line at the end of the report
	report := strings.Join(reports, "\n")

	if _, err := fmt.Fprint(writer, report); err != nil {
		return fmt.Errorf("failed to write final report to stdout: %w", err)
	}
	return nil
}

func writeNotifications(writer io.Writer, events ...partybus.Event) error {
	// 13 = high intensity magenta (ANSI 16 bit code)
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("13"))

	for _, e := range events {
		_, notification, err := parsers.ParseCLINotification(e)
		if err != nil {
			log.WithFields("error", err).Warn("failed to parse notification")
			continue
		}

		if _, err := fmt.Fprintln(writer, style.Render(notification)); err != nil {
			// don't let this be fatal
			log.WithFields("error", err).Warn("failed to write final notifications")
		}
	}
	return nil
}

func writeNotaryPolicyEvaluationMessage(writer io.Writer, events ...partybus.Event) error {
	for _, e := range events {
		// show the report to stdout
		nt, err := xeolEventParsers.ParseNotaryPolicyEvaluationMessage(e)
		if err != nil {
			return fmt.Errorf("bad %s event: %w", e.Type, err)
		}

		var notice string
		if nt.Action == policyTypes.PolicyActionDeny {
			notice = lipgloss.NewStyle().Foreground(terminalRed).Italic(true).Render(fmt.Sprintf("[%s][%s] Policy Violation: image '%s' is not signed by a trusted party.\n",
				nt.Action, nt.Type, nt.ImageReference))
		} else {
			if nt.FailDate != "" {
				notice = lipgloss.NewStyle().Foreground(terminalYellow).Italic(true).Render(fmt.Sprintf("[%s][%s] Policy Violation: image '%s' is not signed by a trusted party. This policy will fail builds starting on %s.\n",
					nt.Action, nt.Type, nt.ImageReference, nt.FailDate))
			} else {
				notice = lipgloss.NewStyle().Foreground(terminalYellow).Italic(true).Render(fmt.Sprintf("[%s][%s] Policy Violation: image '%s' is not signed by a trusted party.\n",
					nt.Action, nt.Type, nt.ImageReference))
			}
		}
		if _, err := fmt.Fprintln(writer, notice); err != nil {
			// don't let this be fatal
			log.WithFields("error", err).Warn("failed to write app update notification")
		}
	}
	return nil
}

func writeEolPolicyEvaluationMessage(writer io.Writer, events ...partybus.Event) error {
	for _, e := range events {
		// show the report to stdout
		pt, err := xeolEventParsers.ParseEolPolicyEvaluationMessage(e)
		if err != nil {
			return fmt.Errorf("bad %s event: %w", e.Type, err)
		}

		var notice string
		if pt.Action == policyTypes.PolicyActionDeny {
			notice = lipgloss.NewStyle().Foreground(terminalRed).Italic(true).Render(fmt.Sprintf("[%s][%s] Policy Violation: %s (v%s) needs to be upgraded to a newer version.\n", pt.Action, pt.Type, pt.ProductName, pt.Cycle))
		} else {
			if pt.FailDate != "" {
				notice = lipgloss.NewStyle().Foreground(terminalYellow).Italic(true).Render(fmt.Sprintf("[%s][%s] Policy Violation: %s (v%s) needs to be upgraded to a newer version. This policy will fail builds starting on %s.\n", pt.Action, pt.Type, pt.ProductName, pt.Cycle, pt.FailDate))
			} else {
				notice = lipgloss.NewStyle().Foreground(terminalYellow).Italic(true).Render(fmt.Sprintf("[%s][%s] Policy Violation: %s (v%s) needs to be upgraded to a newer version.\n", pt.Action, pt.Type, pt.ProductName, pt.Cycle))
			}
		}
		if _, err := fmt.Fprintln(writer, notice); err != nil {
			// don't let this be fatal
			log.WithFields("error", err).Warn("failed to write app update notification")
		}
	}
	return nil
}

func writeAppUpdate(writer io.Writer, events ...partybus.Event) error {
	// 13 = high intensity magenta (ANSI 16 bit code) + italics
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Italic(true)

	for _, e := range events {
		version, err := parsers.ParseCLIAppUpdateAvailable(e)
		if err != nil {
			log.WithFields("error", err).Warn("failed to parse app update notification")
			continue
		}

		if version.New == "" {
			continue
		}

		notice := fmt.Sprintf("A newer version of xeol is available for download: %s (installed version is %s)", version.New, version.Current)

		if _, err := fmt.Fprintln(writer, style.Render(notice)); err != nil {
			// don't let this be fatal
			log.WithFields("error", err).Warn("failed to write app update notification")
		}
	}
	return nil
}
