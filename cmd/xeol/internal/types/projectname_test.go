package types

import "testing"

func TestIsValidProjectName(t *testing.T) {
	tests := []struct {
		projectName string
		wantErr     bool
	}{
		{
			projectName: "gitlab//noqcks/test",
			wantErr:     false,
		},
		{
			projectName: "github//noqcks/test",
			wantErr:     false,
		},
		{
			projectName: "azure//noqcks/test",
			wantErr:     false,
		},
		{
			projectName: "azure//noqcks/test/test",
			wantErr:     false,
		},
		{
			projectName: "azure//noqcks/test/test/test",
			wantErr:     true,
		},
		{
			projectName: "azure//noqcks",
			wantErr:     true,
		},
		{
			projectName: "test//test",
			wantErr:     true,
		},
	}

	for _, test := range tests {
		err := ProjectName(test.projectName).IsValid()
		if test.wantErr && err == nil {
			t.Errorf("Expected error for '%s', but got nil", test.projectName)
		}
	}
}
