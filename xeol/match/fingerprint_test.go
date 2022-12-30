package match

import (
	"testing"
)

func TestFingerprint_ID(t *testing.T) {
	testCases := []struct {
		name     string
		fp       Fingerprint
		expected string
	}{
		{
			name: "Test case 1",
			fp: Fingerprint{
				releaseCycle: "3.1",
				releaseDate:  "2022-01-01",
				packageID:    "package1",
			},
			expected: "bfd2ea2060d65923",
		},
		{
			name: "Test case 2",
			fp: Fingerprint{
				releaseCycle: "3.1",
				releaseDate:  "2022-02-01",
				packageID:    "package2",
			},
			expected: "bfd2ea2060d65923",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.fp.ID()
			if actual != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, actual)
			}
		})
	}
}
