package types

import (
	"testing"
)

func TestCommitHash_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		hash    CommitHash
		wantErr bool
	}{
		{"Valid SHA1", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", false},
		{"Invalid SHA1 - Short", "a94a8fe5cc", true},
		{"Invalid SHA1 - Long", "a94a8fe5ccb19ba61c4c0873d391e9879", true},
		{"Invalid SHA1 - Special Characters", "a94a8fe5cc#19ba61c4c0873d391e9$", true},
		{"Invalid SHA1 - Empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.hash.IsValid(); (err != nil) != tt.wantErr {
				t.Errorf("CommitHash.IsValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
