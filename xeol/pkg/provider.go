package pkg

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/bmatcuk/doublestar/v2"

	tfcataloger "github.com/xeol-io/xeol/xeol/pkg/cataloger/terraform"
)

var errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")

// Provide a set of packages and context metadata describing where they were sourced from.
func Provide(userInput string, config ProviderConfig) ([]Package, Context, *sbom.SBOM, error) {
	packages, ctx, s, err := syftSBOMProvider(userInput, config)
	if !errors.Is(err, errDoesNotProvide) {
		if len(config.Exclusions) > 0 {
			var exclusionsErr error
			packages, exclusionsErr = filterPackageExclusions(packages, config.Exclusions)
			if exclusionsErr != nil {
				return nil, ctx, s, exclusionsErr
			}
		}
		return packages, ctx, s, err
	}

	packages, err = purlProvider(userInput)
	if !errors.Is(err, errDoesNotProvide) {
		return packages, Context{}, s, err
	}

	packages, ctx, s, err = syftProvider(userInput, config)

	// Inject our custom Terraform lockfile cataloger for dir: inputs.
	// Syft v1.10.0 has no native terraform cataloger, so we do it ourselves.
	if dirPath := extractDirPath(userInput); dirPath != "" {
		tfPackages, tfErr := catalogTerraform(dirPath)
		if tfErr != nil {
			fmt.Printf("terraform cataloger warning: %v\n", tfErr)
		} else {
			packages = append(packages, tfPackages...)
		}
	}

	return packages, ctx, s, err
}

// extractDirPath returns the filesystem path for a dir: prefixed input, else "".
func extractDirPath(userInput string) string {
	if strings.HasPrefix(userInput, "dir:") {
		return strings.TrimPrefix(userInput, "dir:")
	}
	return ""
}

// catalogTerraform calls the terraform cataloger and converts its output into xeol Packages.
func catalogTerraform(dirPath string) ([]Package, error) {
	providers, err := tfcataloger.CatalogDirectory(dirPath)
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	for _, p := range providers {
		pkgs = append(pkgs, terraformProviderToPackage(p))
	}
	return pkgs, nil
}

// terraformProviderToPackage converts a raw cataloger Provider into an xeol Package.
// PURL format: pkg:terraform/<namespace>/<name>@<version>
func terraformProviderToPackage(p tfcataloger.Provider) Package {
	parts := strings.Split(p.Address, "/")
	name := p.Address
	purlName := p.Address
	if len(parts) >= 2 {
		purlName = strings.Join(parts[len(parts)-2:], "/")
		name = parts[len(parts)-1]
	}

	purl := fmt.Sprintf("pkg:terraform/%s@%s", purlName, p.Version)
	loc := file.NewLocation(p.LockfilePath)

	return Package{
		ID:        ID(fmt.Sprintf("terraform-%s-%s", purlName, p.Version)),
		Name:      name,
		Version:   p.Version,
		Locations: file.NewLocationSet(loc),
		Type:      "terraform",
		PURL:      purl,
	}
}


// This will filter the provided packages list based on a set of exclusion expressions. Globs
// are allowed for the exclusions. A package will be *excluded* only if *all locations* match
// one of the provided exclusions.
func filterPackageExclusions(packages []Package, exclusions []string) ([]Package, error) {
	var out []Package
	for _, pkg := range packages {
		includePackage := true
		locations := pkg.Locations.ToSlice()
		if len(locations) > 0 {
			includePackage = false
			// require ALL locations to be excluded for the package to be excluded
		location:
			for _, location := range locations {
				for _, exclusion := range exclusions {
					match, err := locationMatches(location, exclusion)
					if err != nil {
						return nil, err
					}
					if match {
						continue location
					}
				}
				// if this point is reached, one location has not matched any exclusion, include the package
				includePackage = true
				break
			}
		}
		if includePackage {
			out = append(out, pkg)
		}
	}
	return out, nil
}

// Test a location RealPath and VirtualPath for a match against the exclusion parameter.
// The exclusion allows glob expressions such as `/usr/**` or `**/*.json`. If the exclusion
// is an invalid pattern, an error is returned; otherwise, the resulting boolean indicates a match.
func locationMatches(location file.Location, exclusion string) (bool, error) {
	matchesRealPath, err := doublestar.Match(exclusion, location.RealPath)
	if err != nil {
		return false, err
	}
	matchesVirtualPath, err := doublestar.Match(exclusion, location.AccessPath)
	if err != nil {
		return false, err
	}
	return matchesRealPath || matchesVirtualPath, nil
}
