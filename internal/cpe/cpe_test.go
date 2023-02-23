package cpe

import (
	"testing"
)

func TestCpeDestructure(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		expectedShortCpe string
		expectedVersion  string
	}{
		{
			name:             "Exact CPE 2.2",
			input:            "cpe:/a:apache:struts:2.5.10",
			expectedShortCpe: "cpe:/a:apache:struts",
			expectedVersion:  "2.5.10",
		},
		{
			name:             "Exact CPE 2.3",
			input:            "cpe:2.3:a:apache:struts:2.5.10",
			expectedShortCpe: "cpe:2.3:a:apache:struts",
			expectedVersion:  "2.5.10",
		},
		{
			name:             "CPE 2.2",
			input:            "cpe:/a:apache:struts:2.5:*:*:*:*:*:*:*",
			expectedShortCpe: "cpe:/a:apache:struts",
			expectedVersion:  "2.5",
		},
		{
			name:             "CPE 2.3",
			input:            "cpe:2.3:a:apache:struts:2.5:*:*:*:*:*:*:*",
			expectedShortCpe: "cpe:2.3:a:apache:struts",
			expectedVersion:  "2.5",
		},
		{
			name:             "Empty CPE",
			input:            "",
			expectedShortCpe: "",
			expectedVersion:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotCpe, gotVersion := Destructure(tc.input)

			if gotVersion != tc.expectedVersion {
				t.Errorf("Expected version '%v', got '%v'", tc.expectedVersion, gotVersion)
			}
			if gotCpe != tc.expectedShortCpe {
				t.Errorf("Expected short CPE '%v', got '%v'", tc.expectedShortCpe, gotCpe)
			}
		})
	}
}
