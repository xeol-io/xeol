package monitor

import (
	"github.com/wagoodman/go-progress"
)

type Matching struct {
	PackagesProcessed progress.Progressable
	MatchesDiscovered progress.Monitorable
}
