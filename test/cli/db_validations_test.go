package cli

import (
	"strings"
	"testing"
)

func TestDBValidations(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			// regression: do not panic on bad DB load
			name: "fail on bad DB load",
			args: []string{"-vv", "dir:."},
			env: map[string]string{
				"XEOL_DB_CACHE_DIR": t.TempDir(),
				"XEOL_DB_CA_CERT":   "./does-not-exist.crt",
			},
			assertions: []traitAssertion{
				assertInOutput("failed to load EOL db"),
				assertFailingReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runXeol(t, test.env, test.args...)
			for _, traitAssertionFn := range test.assertions {
				traitAssertionFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}
