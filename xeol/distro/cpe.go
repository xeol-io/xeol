package distro

import (
	"strings"

	"github.com/noqcks/xeol/internal/log"
)

// CPEName returns the CPE name for the distro.
type CPEName string

func (c CPEName) String() string {
	return string(c)
}

// Destructured splits a CPE name into its (cpe:2.3:o:vendor:package) and version components.
func (c CPEName) Destructured() (shortCPE, version string) {
	parts := strings.Split(c.String(), ":")

	if len(parts) < 5 {
		log.Debugf("CPE string '%s' is too short", c.String())
		return "", ""
	}

	var splitIndex int
	if parts[1] == "2.3" {
		splitIndex = 5
	} else {
		splitIndex = 4
	}

	return strings.Join(parts[:splitIndex], ":"), parts[splitIndex]
}
