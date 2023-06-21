package config

import (
	"testing"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{
			url:      "https://github.com/xeol-io/xeol.git",
			expected: "github//xeol-io/xeol",
		},
		{
			url:      "git@ssh.dev.azure.com:v3/xeol-io/example-dotnet/example-dotnet",
			expected: "azure//xeol-io/example-dotnet",
		},
		{
			url:      "https://xeol-io@dev.azure.com/xeol-io/example-dotnet/_git/example-dotnet",
			expected: "azure//xeol-io/example-dotnet",
		},
		{
			url:      "git@github.com:noqcks/xeol.git",
			expected: "github//noqcks/xeol",
		},
		{
			url:      "https://gitlab.com/noqcks/test.git",
			expected: "gitlab//noqcks/test",
		},
		{
			url:      "git@gitlab.com:noqcks/test.git",
			expected: "gitlab//noqcks/test",
		},
	}

	for _, test := range tests {
		formatter := URLFormatter{URL: test.url}
		result := formatter.Format()

		if result != test.expected {
			t.Errorf("Expected '%s', but got '%s'", test.expected, result)
		}
	}
}
