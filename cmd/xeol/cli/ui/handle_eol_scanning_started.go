package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/event/monitor"
	"github.com/xeol-io/xeol/xeol/event/parsers"
)

var _ progress.StagedProgressable = (*eolScanningAdapter)(nil)

type eolProgressTree struct {
	mon        *monitor.Matching
	windowSize tea.WindowSizeMsg
	totalCount int64

	id       uint32
	sequence int

	updateDuration time.Duration
	textStyle      lipgloss.Style
}

func neweolProgressTree(monitor *monitor.Matching, textStyle lipgloss.Style) eolProgressTree {
	return eolProgressTree{
		mon:       monitor,
		textStyle: textStyle,
	}
}

// eolProgressTreeTickMsg indicates that the timer has ticked and we should render a frame.
type eolProgressTreeTickMsg struct {
	Time     time.Time
	Sequence int
	ID       uint32
}

type eolScanningAdapter struct {
	mon *monitor.Matching
}

func (p eolScanningAdapter) Current() int64 {
	return p.mon.PackagesProcessed.Current()
}

func (p eolScanningAdapter) Error() error {
	return p.mon.MatchesDiscovered.Error()
}

func (p eolScanningAdapter) Size() int64 {
	return p.mon.PackagesProcessed.Size()
}

func (p eolScanningAdapter) Stage() string {
	return fmt.Sprintf("%d eol matches", p.mon.MatchesDiscovered.Current())
}

func (m *Handler) handleEolScanningStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	mon, err := parsers.ParseEolScanningStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Scan for EOL",
			Running: "Scanning for EOL",
			Success: "Scanned for EOL",
		},
		taskprogress.WithStagedProgressable(eolScanningAdapter{mon: mon}),
	)

	tsk.HideStageOnSuccess = false

	textStyle := tsk.HintStyle

	return []tea.Model{
		tsk,
		neweolProgressTree(mon, textStyle),
	}, nil
}

func (l eolProgressTree) Init() tea.Cmd {
	// this is the periodic update of state information
	return func() tea.Msg {
		return eolProgressTreeTickMsg{
			// The time at which the tick occurred.
			Time: time.Now(),

			// The ID of the log frame that this message belongs to. This can be
			// helpful when routing messages, however bear in mind that log frames
			// will ignore messages that don't contain ID by default.
			ID: l.id,

			Sequence: l.sequence,
		}
	}
}

func (l eolProgressTree) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.windowSize = msg
		return l, nil

	case eolProgressTreeTickMsg:
		// update the model
		l.totalCount = l.mon.MatchesDiscovered.Current()

		// kick off the next tick
		tickCmd := l.handleTick(msg)

		return l, tickCmd
	}

	return l, nil
}

func (l eolProgressTree) View() string {
	sb := strings.Builder{}
	return sb.String()
}

func (l eolProgressTree) queueNextTick() tea.Cmd {
	return tea.Tick(l.updateDuration, func(t time.Time) tea.Msg {
		return eolProgressTreeTickMsg{
			Time:     t,
			ID:       l.id,
			Sequence: l.sequence,
		}
	})
}

func (l *eolProgressTree) handleTick(msg eolProgressTreeTickMsg) tea.Cmd {
	// If an ID is set, and the ID doesn't belong to this log frame, reject the message.
	if msg.ID > 0 && msg.ID != l.id {
		return nil
	}

	// If a sequence is set, and it's not the one we expect, reject the message.
	// This prevents the log frame from receiving too many messages and
	// thus updating too frequently.
	if msg.Sequence > 0 && msg.Sequence != l.sequence {
		return nil
	}

	l.sequence++

	// note: even if the log is completed we should still respond to stage changes and window size events
	return l.queueNextTick()
}
