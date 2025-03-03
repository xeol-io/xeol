package store

import (
	"fmt"

	_ "github.com/glebarez/sqlite" // provide the sqlite dialect to gorm via import
	"gorm.io/gorm"

	"github.com/xeol-io/xeol/xeol/db/internal/gormadapter"
	v1 "github.com/xeol-io/xeol/xeol/db/v1"
	"github.com/xeol-io/xeol/xeol/db/v1/store/model"
)

// store holds an instance of the database connection
type store struct {
	db *gorm.DB
}

// New creates a new instance of the store.
func New(dbFilePath string, overwrite bool) (v1.Store, error) {
	db, err := gormadapter.Open(dbFilePath, overwrite)
	if err != nil {
		return nil, err
	}

	if overwrite {
		// TODO: automigrate could write to the database,
		//  we should be validating the database is the correct database based on the version in the ID table before
		//  automigrating
		if err := db.AutoMigrate(&model.IDModel{}); err != nil {
			return nil, fmt.Errorf("unable to migrate ID model: %w", err)
		}
	}

	return &store{
		db: db,
	}, nil
}

// GetID fetches the metadata about the databases schema version and build time.
func (s *store) GetID() (*v1.ID, error) {
	var models []model.IDModel
	result := s.db.Find(&models)
	if result.Error != nil {
		return nil, result.Error
	}

	switch {
	case len(models) > 1:
		return nil, fmt.Errorf("found multiple DB IDs")
	case len(models) == 1:
		id, err := models[0].Inflate()
		if err != nil {
			return nil, err
		}
		return &id, nil
	}

	return nil, nil
}

// SetID stores the databases schema version and build time.
func (s *store) SetID(id v1.ID) error {
	var ids []model.IDModel

	// replace the existing ID with the given one
	s.db.Find(&ids).Delete(&ids)

	m := model.NewIDModel(id)
	result := s.db.Create(&m)

	if result.RowsAffected != 1 {
		return fmt.Errorf("unable to add id (%d rows affected)", result.RowsAffected)
	}

	return result.Error
}

func (s *store) Close() {
	s.db.Exec("VACUUM;")

	sqlDB, err := s.db.DB()
	if err != nil {
		_ = sqlDB.Close()
	}
}

func (s *store) GetAllProducts() (*[]v1.Product, error) {
	var models []model.ProductModel
	if result := s.db.Find(&models); result.Error != nil {
		return nil, result.Error
	}
	products := make([]v1.Product, len(models))
	for i, m := range models {
		p, err := m.Inflate()
		if err != nil {
			return nil, err
		}
		products[i] = p
	}

	return &products, nil
}

func (s *store) GetCyclesByCpe(cpe string) ([]v1.Cycle, error) {
	var models []model.CycleModel
	if result := s.db.Table("cycles").
		Select("cycles.*, products.name as product_name, products.permalink as product_permalink").
		Joins("JOIN products ON cycles.product_id = products.id").
		Joins("JOIN cpes ON products.id = cpes.product_id").
		Where("cpes.cpe = ?", cpe).Find(&models); result.Error != nil {
		return nil, result.Error
	}
	cycles := make([]v1.Cycle, len(models))

	for i, m := range models {
		c, err := m.Inflate()
		if err != nil {
			return nil, err
		}
		cycles[i] = c
	}
	return cycles, nil
}

func (s *store) GetCyclesByPurl(purl string) ([]v1.Cycle, error) {
	var models []model.CycleModel
	if result := s.db.Table("cycles").
		Select("cycles.*, products.name as product_name, products.permalink as product_permalink").
		Joins("JOIN products ON cycles.product_id = products.id").
		Joins("JOIN purls ON products.id = purls.product_id").
		Where("purls.purl = ?", purl).Find(&models); result.Error != nil {
		return nil, result.Error
	}
	cycles := make([]v1.Cycle, len(models))

	for i, m := range models {
		c, err := m.Inflate()
		if err != nil {
			return nil, err
		}
		cycles[i] = c
	}
	return cycles, nil
}

func (s *store) GetVulnCountByPurlAndVersion(purl string, version string) (int, error) {
	var vulnCount int
	if result := s.db.Table("vulns").
		Select("vulns.issue_count").
		Joins("JOIN purls ON vulns.purl_id = purls.id").
		Where("purls.purl = ? AND vulns.version = ?", purl, version).Find(&vulnCount); result.Error != nil {
		return 0, result.Error
	}
	return vulnCount, nil
}
