// Package terraform provides a custom cataloger for .terraform.lock.hcl files.
// It parses the lockfile and emits lightweight provider records.
// The caller (xeol/pkg) converts these records into xeol.Package objects.
package terraform

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Provider holds the parsed data from one provider block.
type Provider struct {
	// Address is the full provider address, e.g. "registry.terraform.io/hashicorp/aws"
	Address string
	// Version is the pinned version string, e.g. "6.25.0"
	Version string
	// LockfilePath is the absolute path of the .terraform.lock.hcl file this came from.
	LockfilePath string
}

const lockfileName = ".terraform.lock.hcl"

// CatalogDirectory walks root looking for .terraform.lock.hcl files and returns
// one Provider record per provider block found.
func CatalogDirectory(root string) ([]Provider, error) {
	var all []Provider

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == lockfileName {
			providers, parseErr := parseLockfile(path)
			if parseErr != nil {
				// Warn but keep walking
				return nil
			}
			all = append(all, providers...)
		}
		return nil
	})
	return all, err
}

// parseLockfile parses .terraform.lock.hcl with a simple line-based scanner.
//
// The lockfile format is:
//
//	provider "registry.terraform.io/hashicorp/aws" {
//	  version     = "6.25.0"
//	  ...
//	}
func parseLockfile(path string) ([]Provider, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	providerHeaderRe := regexp.MustCompile(`^\s*provider\s+"([^"]+)"\s*\{`)
	versionRe := regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)

	var providers []Provider
	var current *Provider

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if current == nil {
			if m := providerHeaderRe.FindStringSubmatch(line); m != nil {
				current = &Provider{Address: m[1], LockfilePath: path}
			}
			continue
		}

		// Inside a provider block — look for version
		if m := versionRe.FindStringSubmatch(line); m != nil {
			current.Version = m[1]
		}

		// End of block
		if strings.TrimSpace(line) == "}" {
			if current.Version != "" {
				providers = append(providers, *current)
			}
			current = nil
		}
	}
	return providers, scanner.Err()
}
