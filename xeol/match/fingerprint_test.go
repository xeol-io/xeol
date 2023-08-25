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
				productName:  "product1",
				eolDate:      "2023-01-01",
				eolBool:      true,
				lts:          "True",
			},
			expected: "bfd2ea2060d65923",
		},
		{
			name: "Test case 2",
			fp: Fingerprint{
				releaseCycle: "3.1",
				releaseDate:  "2022-02-01",
				productName:  "product2",
				eolDate:      "2023-02-01",
				eolBool:      false,
				lts:          "False",
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
