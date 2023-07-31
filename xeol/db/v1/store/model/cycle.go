package model

import (
	"time"

	v1 "github.com/xeol-io/xeol/xeol/db/v1"
)

const (
	CycleTableName = "cycles"
)

type CycleModel struct {
	ProductName       string    `gorm:"column:product_name"`
	ProductPermalink  string    `gorm:"column:product_permalink"`
	ID                int       `gorm:"primary_key;column:id;"`
	ReleaseCycle      string    `gorm:"column:release_cycle"`
	Eol               time.Time `gorm:"column:eol"`
	EolBool           bool      `gorm:"column:eol_bool"`
	LTS               string    `gorm:"column:lts"`
	LatestRelease     string    `gorm:"column:latest_release"`
	LatestReleaseDate time.Time `gorm:"column:latest_release_date"`
	ReleaseDate       time.Time `gorm:"column:release_date"`
}

func (m CycleModel) TableName() string {
	return CycleTableName
}

func (m CycleModel) Inflate() (v1.Cycle, error) {
	return v1.Cycle{
		ProductName:       m.ProductName,
		ProductPermalink:  m.ProductPermalink,
		ReleaseDate:       m.ReleaseDate.Format("2006-01-02"),
		ReleaseCycle:      m.ReleaseCycle,
		LatestReleaseDate: m.LatestReleaseDate.Format("2006-01-02"),
		LatestRelease:     m.LatestRelease,
		LTS:               m.LTS,
		Eol:               m.Eol.Format("2006-01-02"),
		EolBool:           m.EolBool,
	}, nil
}
