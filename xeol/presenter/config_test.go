package presenter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatedConfig(t *testing.T) {
	cases := []struct {
		name                    string
		outputValue             string
		includeSuppressed       bool
		outputTemplateFileValue string
		expectedConfig          Config
		assertErrExpectation    func(assert.TestingT, error, ...interface{}) bool
	}{
		{
			"unknown format",
			"some-made-up-format",
			false,
			"",
			Config{},
			assert.Error,
		},

		{
			"table format",
			"table",
			true,
			"",
			Config{
				format: tableFormat,
			},
			assert.NoError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actualConfig, actualErr := ValidatedConfig(tc.outputValue)

			assert.Equal(t, tc.expectedConfig, actualConfig)
			tc.assertErrExpectation(t, actualErr)
		})
	}
}
