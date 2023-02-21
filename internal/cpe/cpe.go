package cpe

import (
	"log"
	"strings"
)

func Destructure(cpe string) (shortCPE, version string) {
	parts := strings.Split(cpe, ":")

	if len(parts) < 5 {
		log.Printf("CPE string '%s' is too short", cpe)
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
