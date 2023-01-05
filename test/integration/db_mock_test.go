package integration

import (
	xeolDB "github.com/noqcks/xeol/xeol/db/v1"
)

// integrity check
var _ xeolDB.EolStoreReader = &mockStore{}

type mockStore struct {
	backend map[string][]xeolDB.Cycle
}

func (s *mockStore) GetCyclesByPurl(purl string) ([]xeolDB.Cycle, error) {
	return s.backend[purl], nil
}

func (s *mockStore) GetAllProducts() (*[]xeolDB.Product, error) {
	return nil, nil
}

func newMockDbStore() *mockStore {
	d := mockStore{
		backend: make(map[string][]xeolDB.Cycle),
	}
	d.stub()
	return &d
}

func cycles(name string) []xeolDB.Cycle {
	cycleDict := map[string][]xeolDB.Cycle{
		"mongodb": {
			{
				ProductName:  "MongoDB Server",
				ReleaseCycle: "3.0",
				Eol:          "2018-02-28T00:00:00Z",
			},
			{
				ProductName:  "MongoDB Server",
				ReleaseCycle: "3.2",
				Eol:          "2018-07-31T00:00:00Z",
			},
		},
		"python": {
			{
				ProductName:  "Python",
				ReleaseCycle: "3.11",
				Eol:          "2027-10-24T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.10",
				Eol:          "2026-10-04T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.9",
				Eol:          "2025-10-05T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.8",
				Eol:          "2024-10-14T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.7",
				Eol:          "2023-06-27T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.6",
				Eol:          "2021-12-23T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.5",
				Eol:          "2020-09-13T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.4",
				Eol:          "2019-03-18T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.3",
				Eol:          "2017-09-29T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "2.7",
				Eol:          "2020-01-01T00:00:00Z",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "2.6",
				Eol:          "2013-10-29T00:00:00Z",
			},
		},
		"golang": {
			{
				ProductName:  "Go",
				ReleaseCycle: "1.15",
				Eol:          "2021-08-16T00:00:00Z",
			},
		},
		"redis": {
			{
				ProductName:  "Redis",
				ReleaseCycle: "5.0",
				Eol:          "2021-12-31T00:00:00Z",
			},
		},
		"postgres": {
			{
				ProductName:  "PostgreSQL",
				ReleaseCycle: "9.6",
				Eol:          "2021-11-11T00:00:00Z",
			},
		},
		"elasticsearch": {
			{
				ProductName:  "Elasticsearch",
				ReleaseCycle: "6",
				Eol:          "2022-02-10T00:00:00Z",
			},
		},
	}
	return cycleDict[name]
}

func (d *mockStore) stub() {
	d.backend["pkg:deb/debian/postgresql-9.6"] = cycles("postgres")
	d.backend["pkg:maven/org.elasticsearch#server/elasticsearch"] = cycles("elasticsearch")
	d.backend["pkg:deb/debian/mongodb-org-server"] = cycles("mongodb")
	d.backend["pkg:generic//python"] = cycles("python")
}
