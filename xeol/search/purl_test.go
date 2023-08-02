package search

import (
	"reflect"
	"testing"

	"github.com/Masterminds/semver"

	"github.com/xeol-io/xeol/xeol/eol"
)

func TestNormalizeSemver(t *testing.T) {
	testCases := []struct {
		version  string
		expected string
	}{
		{
			version:  "1.2.3",
			expected: "1.2.3",
		},
		{
			version:  "1.2.3-rc1",
			expected: "1.2.3",
		},
		{
			version:  "1.2.3-rc1+build1",
			expected: "1.2.3",
		},
		{
			version:  "1.2.3p288",
			expected: "1.2.3",
		},
		{
			version:  "1.2.3p288+1.3",
			expected: "1.2.3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.version, func(t *testing.T) {
			actual := normalizeSemver(tc.version)
			if actual != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, actual)
			}
		})
	}
}

func TestReturnMatchingCycle(t *testing.T) {
	testCases := []struct {
		name     string
		version  string
		cycles   []eol.Cycle
		expected eol.Cycle
		err      error
	}{
		{
			name:    "Match versions with rc information",
			version: "1.21.6-r1",
			cycles: []eol.Cycle{{
				ProductName:   "Nginx",
				ReleaseCycle:  "1.21",
				LatestRelease: "1.21.6",
			}},
			expected: eol.Cycle{
				ProductName:   "Nginx",
				ReleaseCycle:  "1.21",
				LatestRelease: "1.21.6",
			},
		},
		{
			name:    "Match weird Amazon Linux AMI version",
			version: "2018.03",
			cycles: []eol.Cycle{{
				ProductName:   "Amazon Linux AMI",
				ReleaseCycle:  "2018.03",
				LatestRelease: "2018.03",
			}},
			expected: eol.Cycle{
				ProductName:   "Amazon Linux AMI",
				ReleaseCycle:  "2018.03",
				LatestRelease: "2018.03",
			},
		},
		{
			name:    "Match on major version",
			version: "1.2.3",
			cycles: []eol.Cycle{{
				ProductName:       "Linux",
				ReleaseCycle:      "1",
				LatestRelease:     "1.2",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			}},
			expected: eol.Cycle{
				ProductName:       "Linux",
				ReleaseCycle:      "1",
				LatestRelease:     "1.2",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			},
			err: nil,
		},
		{
			name:    "Match on major and minor version",
			version: "1.1.3",
			cycles: []eol.Cycle{{
				ProductName:       "Linux",
				ReleaseCycle:      "1.1",
				LatestRelease:     "1.1.4",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			}},
			expected: eol.Cycle{
				ProductName:       "Linux",
				ReleaseCycle:      "1.1",
				LatestRelease:     "1.1.4",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			},
			err: nil,
		},
		{
			name:    "Match on major, minor, and patch version",
			version: "1.2.3",
			cycles: []eol.Cycle{{
				ProductName:       "Linux",
				ReleaseCycle:      "1.2.3",
				LatestRelease:     "1.2",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			}},
			expected: eol.Cycle{
				ProductName:       "Linux",
				ReleaseCycle:      "1.2.3",
				LatestRelease:     "1.2",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			},
			err: nil,
		},
		{
			name:     "Invalid version",
			version:  "invalid",
			cycles:   nil,
			expected: eol.Cycle{},
			err:      semver.ErrInvalidSemVer,
		},
		{
			name:    "No matching cycle",
			version: "1.2.3",
			cycles: []eol.Cycle{{
				ProductName:       "Linux",
				ReleaseCycle:      "1.3",
				LatestRelease:     "1.3.4",
				LatestReleaseDate: "2022-01-01",
				ReleaseDate:       "2022-01-01",
			}},
			expected: eol.Cycle{},
			err:      nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := returnMatchingCycle(tc.version, tc.cycles)
			if err != tc.err {
				t.Errorf("Expected error %v, got %v", tc.err, err)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, actual)
			}
		})
	}
}
