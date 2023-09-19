package format

import (
	"strings"
)

const (
	UnknownFormat Format = "unknown"
	JSONFormat    Format = "json"
	TableFormat   Format = "table"
)

// Format is a dedicated type to represent a specific kind of presenter output format.
type Format string

func (f Format) String() string {
	return string(f)
}

// Parse returns the presenter.format specified by the given user input.
func Parse(userInput string) Format {
	switch strings.ToLower(userInput) {
	case "":
		return TableFormat
	case strings.ToLower(JSONFormat.String()):
		return JSONFormat
	case strings.ToLower(TableFormat.String()):
		return TableFormat
	default:
		return UnknownFormat
	}
}

// AvailableFormats is a list of presenter format options available to users.
var AvailableFormats = []Format{
	JSONFormat,
	TableFormat,
}
