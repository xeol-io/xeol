package model

import (
	"time"

	v1 "github.com/noqcks/xeol/xeol/db/v1"
)

const (
	CycleTableName = "cycles"
)

type CycleModel struct {
	ID                int       `gorm:"primary_key;column:id;"`
	ReleaseCycle      string    `gorm:"column:release_cycle"`
	Eol               time.Time `gorm:"column:eol"`
	LatestRelease     string    `gorm:"column:latest_release"`
	LatestReleaseDate time.Time `gorm:"column:latest_release_date"`
	ReleaseDate       time.Time `gorm:"column:release_date"`
}

func NewCycleModel(cycle v1.Cycle) CycleModel {
	return CycleModel{
		ReleaseDate:       time.Now(),
		ReleaseCycle:      cycle.ReleaseCycle,
		LatestReleaseDate: time.Now(),
		LatestRelease:     cycle.LatestRelease,
		Eol:               time.Now(),
	}
}

func (m CycleModel) TableName() string {
	return CycleTableName
}

func (m CycleModel) Inflate() (v1.Cycle, error) {
	return v1.Cycle{
		ReleaseDate:       m.ReleaseDate.Format(time.RFC3339),
		ReleaseCycle:      m.ReleaseCycle,
		LatestReleaseDate: m.LatestReleaseDate.Format(time.RFC3339),
		LatestRelease:     m.LatestRelease,
		Eol:               m.Eol.Format(time.RFC3339),
	}, nil
}
