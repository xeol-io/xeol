package integration

import (
	xeolDB "github.com/xeol-io/xeol/xeol/db/v1"
)

// integrity check
var _ xeolDB.EolStoreReader = &mockStore{}

type mockStore struct {
	backend map[string][]xeolDB.Cycle
}

func (s *mockStore) GetCyclesByPurl(purl string) ([]xeolDB.Cycle, error) {
	return s.backend[purl], nil
}

func (s *mockStore) GetCyclesByCpe(cpe string) ([]xeolDB.Cycle, error) {
	return s.backend[cpe], nil
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
		"node": {
			{
				ProductName:  "Node.js",
				ReleaseCycle: "6",
				Eol:          "2019-04-30",
			},
		},
		"mongodb": {
			{
				ProductName:  "MongoDB Server",
				ReleaseCycle: "3.0",
				Eol:          "2018-02-28",
			},
			{
				ProductName:  "MongoDB Server",
				ReleaseCycle: "3.2",
				Eol:          "2018-07-31",
			},
		},
		"python": {
			{
				ProductName:  "Python",
				ReleaseCycle: "3.11",
				Eol:          "2027-10-24",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.10",
				Eol:          "2026-10-04",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.9",
				Eol:          "2025-10-05",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.8",
				Eol:          "2024-10-14",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.7",
				Eol:          "2023-06-27",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.6",
				Eol:          "2021-12-23",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.5",
				Eol:          "2020-09-13",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.4",
				Eol:          "2019-03-18",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "3.3",
				Eol:          "2017-09-29",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "2.7",
				Eol:          "2020-01-01",
			},
			{
				ProductName:  "Python",
				ReleaseCycle: "2.6",
				Eol:          "2013-10-29",
			},
		},
		"golang": {
			{
				ProductName:  "Go",
				ReleaseCycle: "1.15",
				Eol:          "2021-08-16",
			},
		},
		"redis": {
			{
				ProductName:  "Redis",
				ReleaseCycle: "5.0",
				Eol:          "2021-12-31",
			},
		},
		"postgres": {
			{
				ProductName:  "PostgreSQL",
				ReleaseCycle: "9.6",
				Eol:          "2021-11-11",
			},
		},
		"elasticsearch": {
			{
				ProductName:  "Elasticsearch",
				ReleaseCycle: "6",
				Eol:          "2022-02-10",
			},
		},
		"fedora": {
			{
				ProductName:  "Fedora",
				ReleaseCycle: "29",
				Eol:          "2019-11-26",
			},
		},
		"ruby": {
			{
				ProductName:  "Ruby",
				ReleaseCycle: "2.7",
				Eol:          "2023-03-31",
			},
		},
	}
	return cycleDict[name]
}

func (d *mockStore) stub() {
	d.backend["pkg:generic/ruby"] = cycles("ruby")
	d.backend["cpe:/o:fedoraproject:fedora"] = cycles("fedora")
	d.backend["pkg:generic/redis"] = cycles("redis")
	d.backend["pkg:generic/node"] = cycles("node")
	d.backend["pkg:generic/go"] = cycles("golang")
	d.backend["pkg:deb/debian/postgresql-9.6"] = cycles("postgres")
	d.backend["pkg:maven/org.elasticsearch%23server/elasticsearch"] = cycles("elasticsearch")
	d.backend["pkg:deb/debian/mongodb-org-server"] = cycles("mongodb")
	d.backend["pkg:generic/python"] = cycles("python")
}
