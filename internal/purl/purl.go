package purl

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	packageurl "github.com/package-url/packageurl-go"
)

func ShortPurl(pkg pkg.Package) (string, error) {
	purl, err := packageurl.FromString(pkg.PURL)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pkg:%s/%s/%s", purl.Type, purl.Namespace, purl.Name), nil
}
