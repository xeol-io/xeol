package purl

import (
	"fmt"
	"testing"

	"github.com/xeol-io/xeol/xeol/pkg"
)

func TestShortPurl(t *testing.T) {
	testCases := []struct {
		name        string
		input       pkg.Package
		expected    string
		expectedErr error
	}{
		{
			name: "No Type PURL",
			input: pkg.Package{
				PURL: "pkg:generic/python@2.7.16",
			},
			expected: "pkg:generic/python",
		},
		{
			name: "Valid PURL",
			input: pkg.Package{
				PURL: "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
			},
			expected: "pkg:deb/debian/curl",
		},
		{
			name: "Invalid PURL",
			input: pkg.Package{
				PURL: "invalid",
			},
			expectedErr: fmt.Errorf("invalid purl"),
		},
		{
			name: "Empty PURL",
			input: pkg.Package{
				PURL: "",
			},
			expectedErr: fmt.Errorf("empty purl"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ShortPurl(tc.input)

			if err != nil {
				if tc.expectedErr == nil {
					t.Errorf("Got unexpected error: %v", err)
				} else if err.Error() != tc.expectedErr.Error() {
					t.Errorf("Expected error '%v', got '%v'", tc.expectedErr, err)
				}
			} else if tc.expectedErr != nil {
				t.Errorf("Expected error '%v', got nil", tc.expectedErr)
			}

			if got != tc.expected {
				t.Errorf("Expected '%v', got '%v'", tc.expected, got)
			}
		})
	}
}
