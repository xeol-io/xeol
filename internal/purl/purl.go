package purl

import (
	"fmt"
	"strings"

	"github.com/xeol-io/xeol/xeol/pkg"
)

func ShortPurl(pkg pkg.Package) (string, error) {
	if pkg.PURL == "" {
		return "", fmt.Errorf("empty purl")
	}
	shortPurl := strings.Split(pkg.PURL, "@")
	if len(shortPurl) < 2 {
		return "", fmt.Errorf("invalid purl")
	}
	return shortPurl[0], nil
}
