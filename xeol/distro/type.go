package distro

import (
	"github.com/anchore/syft/syft/linux"
)

// Type represents the different Linux distribution options
type Type string

const (
	// represents the set of supported Linux Distributions

	Debian       Type = "debian"
	Ubuntu       Type = "ubuntu"
	RedHat       Type = "redhat"
	CentOS       Type = "centos"
	Fedora       Type = "fedora"
	Alpine       Type = "alpine"
	Busybox      Type = "busybox"
	AmazonLinux  Type = "amazonlinux"
	OracleLinux  Type = "oraclelinux"
	ArchLinux    Type = "archlinux"
	OpenSuseLeap Type = "opensuseleap"
	SLES         Type = "sles"
	Photon       Type = "photon"
	Windows      Type = "windows"
	Mariner      Type = "mariner"
	RockyLinux   Type = "rockylinux"
	AlmaLinux    Type = "almalinux"
	Gentoo       Type = "gentoo"
	Wolfi        Type = "wolfi"
)

// All contains all Linux distribution options
var All = []Type{
	Debian,
	Ubuntu,
	RedHat,
	CentOS,
	Fedora,
	Alpine,
	Busybox,
	AmazonLinux,
	OracleLinux,
	ArchLinux,
	OpenSuseLeap,
	SLES,
	Photon,
	Windows,
	Mariner,
	RockyLinux,
	AlmaLinux,
	Gentoo,
	Wolfi,
}

// IDMapping connects a distro ID like "ubuntu" to a Distro type
var IDMapping = map[string]Type{
	"debian":        Debian,
	"ubuntu":        Ubuntu,
	"rhel":          RedHat,
	"centos":        CentOS,
	"fedora":        Fedora,
	"alpine":        Alpine,
	"busybox":       Busybox,
	"amzn":          AmazonLinux,
	"ol":            OracleLinux,
	"arch":          ArchLinux,
	"opensuse-leap": OpenSuseLeap,
	"sles":          SLES,
	"photon":        Photon,
	"windows":       Windows,
	"mariner":       Mariner,
	"rocky":         RockyLinux,
	"almalinux":     AlmaLinux,
	"gentoo":        Gentoo,
	"wolfi":         Wolfi,
}

// CpeOsVendorMapping connects a distro type to a CPE OS vendor string
// The reason this exists is because there is low coverage of CPE_NAME in /etc/os-release
// file across distros. This is a best effort to map the distro type to a CPE vendor string.
var CpeOsVendorMapping = map[Type]string{
	Debian:       "debian",
	Ubuntu:       "canonical",
	RedHat:       "redhat",
	CentOS:       "centos",
	Fedora:       "fedoraproject",
	Alpine:       "alpinelinux",
	Busybox:      "busybox",
	AmazonLinux:  "amazon",
	OracleLinux:  "oracle",
	ArchLinux:    "archlinux",
	OpenSuseLeap: "opensuse",
	SLES:         "suse",
	Photon:       "vmware",
	Windows:      "microsoft",
	Mariner:      "microsoft",
	RockyLinux:   "rocky",
	AlmaLinux:    "almalinux",
	Gentoo:       "gentoo",
	Wolfi:        "wolfi",
}

// CpeOsProductMapping connects a distro type to a CPE OS product string
// The reason this exists is because there is low coverage of CPE_NAME in /etc/os-release
// file across distros. This is a best effort to map the distro type to a CPE vendor string.
var CpeOsProductMapping = map[Type]string{
	Debian:       "debian_linux",
	Ubuntu:       "ubuntu_linux",
	RedHat:       "enterprise_linux",
	CentOS:       "centos",
	Fedora:       "fedora",
	Alpine:       "alpine_linux",
	Busybox:      "busybox",
	AmazonLinux:  "amazon_linux",
	OracleLinux:  "linux",
	ArchLinux:    "arch_linux",
	OpenSuseLeap: "leap",
	SLES:         "linux_enterprise_server",
	Photon:       "photon_os",
	Windows:      "windows",
	Mariner:      "mariner",
	RockyLinux:   "rocky",
	AlmaLinux:    "almalinux",
	Gentoo:       "gentoo",
	Wolfi:        "wolfi",
}

func (t Type) CpeVendor() string {
	return CpeOsVendorMapping[t]
}

func (t Type) CpeProduct() string {
	return CpeOsProductMapping[t]
}

func TypeFromRelease(release linux.Release) Type {
	// first try the release ID
	t, ok := IDMapping[release.ID]
	if ok {
		return t
	}

	// use ID_LIKE as a backup
	for _, l := range release.IDLike {
		if t, ok := IDMapping[l]; ok {
			return t
		}
	}

	// first try the release name as a fallback
	t, ok = IDMapping[release.Name]
	if ok {
		return t
	}

	return ""
}

// String returns the string representation of the given Linux distribution.
func (t Type) String() string {
	return string(t)
}
