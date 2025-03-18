package ui

import (
	"fmt"
	"math"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/dustin/go-humanize"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/event/parsers"
)

type dbDownloadProgressStager struct {
	prog progress.StagedProgressable
}

func (s dbDownloadProgressStager) Stage() string {
	stage := s.prog.Stage()
	if stage == "downloading" {
		// note: since validation is baked into the download progress there is no visibility into this stage.
		// for that reason we report "validating" on the last byte being downloaded (which tends to be the longest
		// since go-downloader is doing this work).
		if s.prog.Current() >= s.prog.Size()-1 {
			return "validating"
		}
		// show intermediate progress of the download
		progress := uint64(math.Max(0, float64(s.prog.Current())))
		total := uint64(math.Max(1, float64(s.prog.Size())))
		return fmt.Sprintf("%s / %s", humanize.Bytes(progress), humanize.Bytes(total))
	}
	return stage
}

func (m *Handler) handleUpdateEolDatabase(e partybus.Event) ([]tea.Model, tea.Cmd) {
	prog, err := parsers.ParseUpdateEolDatabase(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "EOL DB",
		},
		taskprogress.WithStagedProgressable(prog), // ignore the static stage provided by the event
		taskprogress.WithStager(dbDownloadProgressStager{prog: prog}),
	)

	tsk.HideStageOnSuccess = false

	return []tea.Model{tsk}, nil
}
