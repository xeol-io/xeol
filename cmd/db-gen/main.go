package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	v1 "github.com/xeol-io/xeol/xeol/db/v1"
	"github.com/xeol-io/xeol/xeol/db/v1/store/model"
	"gorm.io/gorm"
)

type EOLResponse struct {
	Cycle             string      `json:"cycle"`
	ReleaseDate       string      `json:"releaseDate"`
	Eol               interface{} `json:"eol"` // can be bool or string
	Latest            string      `json:"latest"`
	LatestReleaseDate string      `json:"latestReleaseDate"`
	Lts               interface{} `json:"lts"`
}

// PurlModel matches the DB schema used by the xeol store.
type PurlModel struct {
	ID        int    `gorm:"primary_key;column:id;"`
	ProductID int    `gorm:"column:product_id"`
	Purl      string `gorm:"column:purl"`
}

func (m PurlModel) TableName() string { return "purls" }

func main() {
	dbPath := "xeol.db"
	_ = os.Remove(dbPath)
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	if err := db.AutoMigrate(&model.IDModel{}, &model.ProductModel{}, &PurlModel{}, &model.CycleModel{}); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}

	// 1. Insert DB metadata
	db.Create(&model.IDModel{
		SchemaVersion:  v1.SchemaVersion,
		BuildTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})

	// 2. Seed the Terraform BINARY lifecycle (from endoflife.date)
	seedProduct(db, productSpec{
		Name:      "Terraform",
		Permalink: "terraform",
		Purl:      "pkg:terraform/hashicorp/terraform",
		APIURL:    "https://endoflife.date/api/terraform.json",
	})

	// 3. Seed hashicorp/aws provider with known EOL cycles.
	//    The AWS provider follows a major-version deprecation model; v4.x and below
	//    are EOL as of 2024-01-31 (announced by HashiCorp).
	seedProviderWithStaticCycles(db, productSpec{
		Name:      "Terraform AWS Provider",
		Permalink: "terraform-provider-aws",
		Purl:      "pkg:terraform/hashicorp/aws",
	}, []staticCycle{
		{Cycle: "4", EolDate: "2024-01-31", Latest: "4.67.0"},
		{Cycle: "3", EolDate: "2023-04-30", Latest: "3.76.1"},
		{Cycle: "2", EolDate: "2022-09-30", Latest: "2.70.0"},
	})

	fmt.Println("✅ xeol.db generated successfully with Terraform binary + provider EOL data!")
}

type productSpec struct {
	Name      string
	Permalink string
	Purl      string
	APIURL    string
}

type staticCycle struct {
	Cycle   string
	EolDate string
	Latest  string
}

func seedProduct(db *gorm.DB, spec productSpec) {
	product := model.ProductModel{Name: spec.Name, Permalink: spec.Permalink}
	db.Create(&product)
	db.Create(&PurlModel{ProductID: product.ID, Purl: spec.Purl})

	resp, err := http.Get(spec.APIURL)
	if err != nil {
		log.Fatalf("failed to fetch %s: %v", spec.APIURL, err)
	}
	defer resp.Body.Close()

	var data []EOLResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Fatalf("failed to decode %s: %v", spec.APIURL, err)
	}

	for _, item := range data {
		cycle := model.CycleModel{
			ProductID:        product.ID,
			ProductName:      product.Name,
			ProductPermalink: product.Permalink,
			ReleaseCycle:     item.Cycle,
			LatestRelease:    item.Latest,
		}
		if d, err := time.Parse("2006-01-02", item.ReleaseDate); err == nil {
			cycle.ReleaseDate = d
		}
		if d, err := time.Parse("2006-01-02", item.LatestReleaseDate); err == nil {
			cycle.LatestReleaseDate = d
		}
		if eolBool, ok := item.Eol.(bool); ok {
			cycle.EolBool = eolBool
		} else if eolStr, ok := item.Eol.(string); ok {
			if d, err := time.Parse("2006-01-02", eolStr); err == nil {
				cycle.Eol = d
			}
		}
		db.Create(&cycle)
	}
	fmt.Printf("  seeded %s (%d cycles)\n", spec.Name, len(data))
}

func seedProviderWithStaticCycles(db *gorm.DB, spec productSpec, cycles []staticCycle) {
	product := model.ProductModel{Name: spec.Name, Permalink: spec.Permalink}
	db.Create(&product)
	db.Create(&PurlModel{ProductID: product.ID, Purl: spec.Purl})

	for _, c := range cycles {
		cycle := model.CycleModel{
			ProductID:        product.ID,
			ProductName:      product.Name,
			ProductPermalink: product.Permalink,
			ReleaseCycle:     c.Cycle,
			LatestRelease:    c.Latest,
		}
		if d, err := time.Parse("2006-01-02", c.EolDate); err == nil {
			cycle.Eol = d
		}
		db.Create(&cycle)
	}
	fmt.Printf("  seeded %s (%d static cycles)\n", spec.Name, len(cycles))
}
