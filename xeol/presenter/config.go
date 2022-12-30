package presenter

import (
	"fmt"
)

// Config is the presenter domain's configuration data structure.
type Config struct {
	format format
}

// ValidatedConfig returns a new, validated presenter.Config. If a valid Config cannot be created using the given input,
// an error is returned.
func ValidatedConfig(output string) (Config, error) {
	format := parse(output)

	if format == unknownFormat {
		return Config{}, fmt.Errorf("unsupported output format %q, supported formats are: %+v", output,
			AvailableFormats)
	}

	return Config{
		format: format,
	}, nil
}
