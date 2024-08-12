package ui

import (
	"testing"
	"time"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/event/monitor"
)

func TestHandler_handleEolScanningStarted(t *testing.T) {
	tests := []struct {
		name       string
		eventFn    func(*testing.T) partybus.Event
		iterations int
	}{
		{
			name: "eol scanning in progress",
			eventFn: func(t *testing.T) partybus.Event {
				return partybus.Event{
					Type:  event.EolScanningStarted,
					Value: getMatchMonitor(false),
				}
			},
		},
		{
			name: "eol scanning complete",
			eventFn: func(t *testing.T) partybus.Event {
				return partybus.Event{
					Type:  event.EolScanningStarted,
					Value: getMatchMonitor(true),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.eventFn(t)
			handler := New(DefaultHandlerConfig())
			handler.WindowSize = tea.WindowSizeMsg{
				Width:  100,
				Height: 80,
			}

			models, _ := handler.Handle(e)
			require.Len(t, models, 2)

			t.Run("task line", func(t *testing.T) {
				tsk, ok := models[0].(taskprogress.Model)
				require.True(t, ok)

				got := runModel(t, tsk, tt.iterations, taskprogress.TickMsg{
					Time:     time.Now(),
					Sequence: tsk.Sequence(),
					ID:       tsk.ID(),
				})
				t.Log(got)
				snaps.MatchSnapshot(t, got)
			})

			t.Run("tree", func(t *testing.T) {
				log, ok := models[1].(eolProgressTree)
				require.True(t, ok)
				got := runModel(t, log, tt.iterations, eolProgressTreeTickMsg{
					Time:     time.Now(),
					Sequence: log.sequence,
					ID:       log.id,
				})
				t.Log(got)
				snaps.MatchSnapshot(t, got)
			})

		})
	}
}

func getMatchMonitor(completed bool) monitor.Matching {
	pkgs := &progress.Manual{}
	pkgs.SetTotal(-1)
	if completed {
		pkgs.Set(2000)
		pkgs.SetCompleted()
	} else {
		pkgs.Set(300)
	}

	eol := &progress.Manual{}
	eol.SetTotal(-1)
	if completed {
		eol.Set(45)
		eol.SetCompleted()
	} else {
		eol.Set(40)
	}

	fixed := &progress.Manual{}
	fixed.SetTotal(-1)
	if completed {
		fixed.Set(35)
		fixed.SetCompleted()
	} else {
		fixed.Set(30)
	}

	ignored := &progress.Manual{}
	ignored.SetTotal(-1)
	if completed {
		ignored.Set(5)
		ignored.SetCompleted()
	} else {
		ignored.Set(4)
	}

	dropped := &progress.Manual{}
	dropped.SetTotal(-1)
	if completed {
		dropped.Set(3)
		dropped.SetCompleted()
	} else {
		dropped.Set(2)
	}

	return monitor.Matching{
		PackagesProcessed: pkgs,
		MatchesDiscovered: eol,
	}
}
