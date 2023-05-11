package models

import (
	"sort"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

// Match is a single item for the JSON array reported
type Match struct {
	Cycle    Cycle
	Package  pkg.Package // The package used to search for a match.
	Artifact Package     `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Type       string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"`
	Found      interface{} `json:"found"`
}

func newMatch(m match.Match, p pkg.Package) *Match {
	return &Match{
		Cycle:    NewCycle(m.Cycle),
		Artifact: newPackage(p),
	}
}

var _ sort.Interface = (*ByName)(nil)

type ByName []Match

// Len is the number of elements in the collection.
func (m ByName) Len() int {
	return len(m)
}

// Less reports whether the element with index i should sort before the element with index j.
func (m ByName) Less(i, j int) bool {
	if m[i].Artifact.Name == m[j].Artifact.Name {
		if m[i].Cycle.ReleaseCycle == m[j].Cycle.ReleaseCycle {
			if m[i].Cycle.ProductName == m[j].Cycle.ProductName {
				if m[i].Artifact.Version == m[j].Artifact.Version {
					return m[i].Artifact.Type < m[j].Artifact.Type
				}
				return m[i].Artifact.Version < m[j].Artifact.Version
			}
			return m[i].Cycle.ProductName < m[j].Cycle.ProductName
		}
		return m[i].Cycle.ReleaseCycle < m[j].Cycle.ReleaseCycle
	}
	return m[i].Artifact.Name < m[j].Artifact.Name
}

// Swap swaps the elements with indexes i and j.
func (m ByName) Swap(i, j int) {
	m[i], m[j] = m[j], m[i]
}
