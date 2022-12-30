package file

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestExists(t *testing.T) {
	tests := []struct {
		name, path string
		setup      func(fs afero.Fs)
		expected   bool
		err        error
	}{
		{
			name: "File exists",
			path: "test.txt",
			setup: func(fs afero.Fs) {
				afero.WriteFile(fs, "test.txt", []byte("test"), 0644)
			},
			expected: true,
			err:      nil,
		},
		{
			name: "File does not exist",
			path: "missing.txt",
			setup: func(fs afero.Fs) {
				// No setup required
			},
			expected: false,
			err:      nil,
		},
		{
			name: "Path is a directory",
			path: "testdir/testdir",
			setup: func(fs afero.Fs) {
				fs.MkdirAll("testdir/testdir", 0755)
			},
			expected: false,
			err:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()

			tc.setup(fs)

			exists, err := Exists(fs, tc.path)

			assert.Equal(t, tc.expected, exists)
			assert.Equal(t, tc.err, err)
		})
	}
}
