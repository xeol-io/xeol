package distro

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/linux"
	hashiVer "github.com/hashicorp/go-version"
)

// Distro represents a Linux Distribution.
type Distro struct {
	Type       Type
	Version    *hashiVer.Version
	RawVersion string
	IDLike     []string
	CPEName    CPEName
}

// New creates a new Distro object populated with the given values.
func New(t Type, cpeName, version string, idLikes ...string) (*Distro, error) {
	var verObj *hashiVer.Version
	var err error

	if version != "" {
		verObj, err = hashiVer.NewVersion(version)
		if err != nil {
			return nil, fmt.Errorf("unable to parse version: %w", err)
		}
		if cpeName == "" {
			cpeName = fmt.Sprintf("cpe:2.3:o:%s:%s:%s", t.CpeVendor(), t.CpeProduct(), version)
		}
	}

	return &Distro{
		Type:       t,
		Version:    verObj,
		RawVersion: version,
		IDLike:     idLikes,
		CPEName:    CPEName(cpeName),
	}, nil
}

// NewFromRelease creates a new Distro object derived from a syft linux.Release object.
func NewFromRelease(release linux.Release) (*Distro, error) {
	t := TypeFromRelease(release)
	if t == "" {
		return nil, fmt.Errorf("unable to determine distro type")
	}

	var selectedVersion string

	for _, version := range []string{release.VersionID, release.Version} {
		if version == "" {
			continue
		}

		if _, err := hashiVer.NewVersion(version); err == nil {
			selectedVersion = version
			break
		}
	}

	if t == Debian && release.VersionID == "" && release.Version == "" && strings.Contains(release.PrettyName, "sid") {
		return &Distro{
			Type:       t,
			RawVersion: "unstable",
			IDLike:     release.IDLike,
		}, nil
	}

	return New(t, release.CPEName, selectedVersion, release.IDLike...)
}

func (d Distro) Name() string {
	return string(d.Type)
}

// MajorVersion returns the major version value from the pseudo-semantically versioned distro version value.
func (d Distro) MajorVersion() string {
	if d.Version == nil {
		return strings.Split(d.RawVersion, ".")[0]
	}
	return fmt.Sprintf("%d", d.Version.Segments()[0])
}

// FullVersion returns the original user version value.
func (d Distro) FullVersion() string {
	return d.RawVersion
}

// String returns a human-friendly representation of the Linux distribution.
func (d Distro) String() string {
	versionStr := "(version unknown)"
	if d.RawVersion != "" {
		versionStr = d.RawVersion
	}
	return fmt.Sprintf("%s %s", d.Type, versionStr)
}

func (d Distro) IsRolling() bool {
	return d.Type == Wolfi || d.Type == Chainguard || d.Type == ArchLinux || d.Type == Gentoo
}

// Unsupported Linux distributions
func (d Distro) Disabled() bool {
	switch {
	case d.Type == ArchLinux:
		return true
	default:
		return false
	}
}
