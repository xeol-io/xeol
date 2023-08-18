package model

import (
	v1 "github.com/xeol-io/xeol/xeol/db/v1"
)

const (
	CycleTableName = "cycles"
)

type CycleModel struct {
	ProductName       string `gorm:"column:product_name"`
	ProductPermalink  string `gorm:"column:product_permalink"`
	ID                int    `gorm:"primary_key;column:id;"`
	ReleaseCycle      string `gorm:"column:release_cycle"`
	Eol               string `gorm:"column:eol"`
	EolBool           bool   `gorm:"column:eol_bool"`
	LTS               string `gorm:"column:lts"`
	LatestRelease     string `gorm:"column:latest_release"`
	LatestReleaseDate string `gorm:"column:latest_release_date"`
	ReleaseDate       string `gorm:"column:release_date"`
}

func (m CycleModel) TableName() string {
	return CycleTableName
}

func (m CycleModel) Inflate() (v1.Cycle, error) {
	return v1.Cycle{
		ProductName:       m.ProductName,
		ProductPermalink:  m.ProductPermalink,
		ReleaseDate:       m.ReleaseDate,
		ReleaseCycle:      m.ReleaseCycle,
		LatestReleaseDate: m.LatestReleaseDate,
		LatestRelease:     m.LatestRelease,
		LTS:               m.LTS,
		Eol:               m.Eol,
		EolBool:           m.EolBool,
	}, nil
}
