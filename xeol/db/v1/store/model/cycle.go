package model

import (
	"time"

	v1 "github.com/noqcks/xeol/xeol/db/v1"
)

const (
	CycleTableName = "cycles"
)

type CycleModel struct {
	ProductName       string    `gorm:"column:product_name"`
	ID                int       `gorm:"primary_key;column:id;"`
	ReleaseCycle      string    `gorm:"column:release_cycle"`
	Eol               time.Time `gorm:"column:eol"`
	LatestRelease     string    `gorm:"column:latest_release"`
	LatestReleaseDate time.Time `gorm:"column:latest_release_date"`
	ReleaseDate       time.Time `gorm:"column:release_date"`
}

func NewCycleModel(cycle v1.Cycle) CycleModel {
	return CycleModel{
		ProductName:       cycle.ProductName,
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
		ProductName:       m.ProductName,
		ReleaseDate:       m.ReleaseDate.Format("2006-01-02"),
		ReleaseCycle:      m.ReleaseCycle,
		LatestReleaseDate: m.LatestReleaseDate.Format("2006-01-02"),
		LatestRelease:     m.LatestRelease,
		Eol:               m.Eol.Format("2006-01-02"),
	}, nil
}
