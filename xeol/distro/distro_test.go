package distro

import (
	"testing"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xeol-io/xeol/internal"
)

func Test_NewDistroFromRelease(t *testing.T) {
	tests := []struct {
		name               string
		release            linux.Release
		expectedVersion    string
		expectedRawVersion string
		expectedCpe        string
		expectedType       Type
		expectErr          bool
	}{
		{
			name: "go case: derive version from version-id",
			release: linux.Release{
				ID:        "centos",
				VersionID: "8",
				Version:   "7",
			},
			expectedType:       CentOS,
			expectedRawVersion: "8",
			expectedVersion:    "8.0.0",
		},
		{
			name: "fallback to release name when release id is missing",
			release: linux.Release{
				Name:      "windows",
				VersionID: "8",
			},
			expectedType:       Windows,
			expectedRawVersion: "8",
			expectedVersion:    "8.0.0",
		},
		{
			name: "fallback to version when version-id missing",
			release: linux.Release{
				ID:      "centos",
				Version: "8",
			},
			expectedType:       CentOS,
			expectedRawVersion: "8",
			expectedVersion:    "8.0.0",
		},
		{
			name: "missing version results in error",
			release: linux.Release{
				ID: "centos",
			},
			expectedType: CentOS,
		},
		{
			name: "bogus distro type results in error",
			release: linux.Release{
				ID:        "bogosity",
				VersionID: "8",
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d, err := NewFromRelease(test.release)
			if test.expectErr {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, test.expectedType, d.Type)
			if test.expectedVersion != "" {
				assert.Equal(t, test.expectedVersion, d.Version.String())
			}
			if test.expectedRawVersion != "" {
				assert.Equal(t, test.expectedRawVersion, d.FullVersion())
			}
		})
	}

}

func Test_NewDistroFromRelease_Coverage(t *testing.T) {
	tests := []struct {
		fixture string
		Type    Type
		Version string
	}{
		{
			fixture: "test-fixtures/os/alpine",
			Type:    Alpine,
			Version: "3.11.6",
		},
		{
			fixture: "test-fixtures/os/amazon",
			Type:    AmazonLinux,
			Version: "2.0.0",
		},
		{
			fixture: "test-fixtures/os/busybox",
			Type:    Busybox,
			Version: "1.31.1",
		},
		{
			fixture: "test-fixtures/os/centos",
			Type:    CentOS,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/debian",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/fedora",
			Type:    Fedora,
			Version: "31.0.0",
		},
		{
			fixture: "test-fixtures/os/redhat",
			Type:    RedHat,
			Version: "7.3.0",
		},
		{
			fixture: "test-fixtures/os/ubuntu",
			Type:    Ubuntu,
			Version: "20.4.0",
		},
		{
			fixture: "test-fixtures/os/oraclelinux",
			Type:    OracleLinux,
			Version: "8.3.0",
		},
		{
			fixture: "test-fixtures/os/custom",
			Type:    RedHat,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/opensuse-leap",
			Type:    OpenSuseLeap,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/sles",
			Type:    SLES,
			Version: "15.2.0",
		},
		{
			fixture: "test-fixtures/os/photon",
			Type:    Photon,
			Version: "2.0.0",
		},
		{
			fixture: "test-fixtures/os/arch",
			Type:    ArchLinux,
		},
		{
			fixture: "test-fixtures/partial-fields/missing-id",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/partial-fields/unknown-id",
			Type:    Debian,
			Version: "8.0.0",
		},
		{
			fixture: "test-fixtures/os/centos6",
			Type:    CentOS,
			Version: "6.0.0",
		},
		{
			fixture: "test-fixtures/os/centos5",
			Type:    CentOS,
			Version: "5.7.0",
		},
		{
			fixture: "test-fixtures/os/mariner",
			Type:    Mariner,
			Version: "1.0.0",
		},
		{
			fixture: "test-fixtures/os/rockylinux",
			Type:    RockyLinux,
			Version: "8.4.0",
		},
		{
			fixture: "test-fixtures/os/almalinux",
			Type:    AlmaLinux,
			Version: "8.4.0",
		},
		{
			fixture: "test-fixtures/os/gentoo",
			Type:    Gentoo,
		},
		{
			fixture: "test-fixtures/os/wolfi",
			Type:    Wolfi,
		},
	}

	observedDistros := internal.NewStringSet()
	definedDistros := internal.NewStringSet()

	for _, distroType := range All {
		definedDistros.Add(string(distroType))
	}

	// Somewhat cheating with Windows. There is no support for detecting/parsing a Windows OS, so it is not
	// possible to comply with this test unless it is added manually to the "observed distros"
	definedDistros.Remove(string(Windows))

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			s, err := source.NewFromDirectory(test.fixture)
			require.NoError(t, err)

			resolver, err := s.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			// make certain syft and pick up on the raw information we need
			release := linux.IdentifyRelease(resolver)
			require.NotNil(t, release, "empty linux release info")

			// craft a new distro from the syft raw info
			d, err := NewFromRelease(*release)
			require.NoError(t, err)

			observedDistros.Add(d.Type.String())

			assert.Equal(t, test.Type, d.Type)
			if test.Version != "" {
				assert.Equal(t, d.Version.String(), test.Version)
			}

		})
	}

	// ensure that test cases stay in sync with the distros that can be identified
	if len(observedDistros) < len(definedDistros) {
		for _, d := range definedDistros.ToSlice() {
			t.Logf("   defined: %s", d)
		}
		for _, d := range observedDistros.ToSlice() {
			t.Logf("   observed: %s", d)
		}
		t.Errorf("distro coverage incomplete (defined=%d, coverage=%d)", len(definedDistros), len(observedDistros))
	}
}

func TestDistro_FullVersion(t *testing.T) {

	tests := []struct {
		version  string
		expected string
	}{
		{
			version:  "8",
			expected: "8",
		},
		{
			version:  "18.04",
			expected: "18.04",
		},
		{
			version:  "0",
			expected: "0",
		},
		{
			version:  "18.1.2",
			expected: "18.1.2",
		},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			d, err := NewFromRelease(linux.Release{
				ID:      "centos",
				Version: test.version,
			})
			require.NoError(t, err)
			assert.Equal(t, test.expected, d.FullVersion())
		})
	}

}

func TestDistro_MajorVersion(t *testing.T) {

	tests := []struct {
		version  string
		expected string
	}{
		{
			version:  "8",
			expected: "8",
		},
		{
			version:  "18.04",
			expected: "18",
		},
		{
			version:  "0",
			expected: "0",
		},
		{
			version:  "18.1.2",
			expected: "18",
		},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			d, err := NewFromRelease(linux.Release{
				ID:      "centos",
				Version: test.version,
			})
			require.NoError(t, err)
			assert.Equal(t, test.expected, d.MajorVersion())

		})
	}

}

func TestDistro_CpeName(t *testing.T) {
	tests := []struct {
		fixture     string
		expectedCpe string
	}{
		{
			fixture:     "test-fixtures/os/ubuntu",
			expectedCpe: "cpe:2.3:o:canonical:ubuntu_linux:20.04",
		},
		{
			fixture:     "test-fixtures/os/redhat",
			expectedCpe: "cpe:/o:redhat:enterprise_linux:7.3:GA:server",
		},
		{
			fixture:     "test-fixtures/os/debian",
			expectedCpe: "cpe:2.3:o:debian:debian_linux:8",
		},
		{
			fixture:     "test-fixtures/os/fedora",
			expectedCpe: "cpe:/o:fedoraproject:fedora:31",
		},
		{
			fixture:     "test-fixtures/os/photon",
			expectedCpe: "cpe:2.3:o:vmware:photon_os:2.0",
		},
		{
			fixture:     "test-fixtures/os/almalinux",
			expectedCpe: "cpe:/o:almalinux:almalinux:8.4:GA",
		},
		{
			fixture:     "test-fixtures/os/alpine",
			expectedCpe: "cpe:2.3:o:alpinelinux:alpine_linux:3.11.6",
		},
		{
			fixture:     "test-fixtures/os/amazon",
			expectedCpe: "cpe:2.3:o:amazon:amazon_linux:2",
		},
		{
			fixture:     "test-fixtures/os/arch",
			expectedCpe: "",
		},
		{
			fixture:     "test-fixtures/os/busybox",
			expectedCpe: "cpe:2.3:o:busybox:busybox:1.31.1",
		},
		{
			fixture:     "test-fixtures/os/centos",
			expectedCpe: "cpe:/o:centos:centos:8",
		},
		{
			fixture:     "test-fixtures/os/gentoo",
			expectedCpe: "",
		},
		{
			fixture:     "test-fixtures/os/oraclelinux",
			expectedCpe: "cpe:/o:oracle:linux:8:3:server",
		},
		{
			fixture:     "test-fixtures/os/opensuse-leap",
			expectedCpe: "cpe:/o:opensuse:leap:15.2",
		},
		{
			fixture:     "test-fixtures/os/sles",
			expectedCpe: "cpe:/o:suse:sles:15:sp2",
		},
		{
			fixture:     "test-fixtures/os/mariner",
			expectedCpe: "cpe:2.3:o:microsoft:mariner:1.0",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			s, err := source.NewFromDirectory(test.fixture)
			require.NoError(t, err)

			resolver, err := s.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			// make certain syft and pick up on the raw information we need
			release := linux.IdentifyRelease(resolver)
			require.NotNil(t, release, "empty linux release info")

			// craft a new distro from the syft raw info
			d, err := NewFromRelease(*release)
			require.NoError(t, err)

			assert.Equal(t, d.CPEName.String(), test.expectedCpe)
		})
	}

}

func TestDistro_CpeNameDestructured(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		expectedShortCpe string
		expectedVersion  string
	}{
		{
			name:             "Exact CPE 2.2",
			input:            "cpe:/a:apache:struts:2.5.10",
			expectedShortCpe: "cpe:/a:apache:struts",
			expectedVersion:  "2.5.10",
		},
		{
			name:             "Exact CPE 2.3",
			input:            "cpe:2.3:a:apache:struts:2.5.10",
			expectedShortCpe: "cpe:2.3:a:apache:struts",
			expectedVersion:  "2.5.10",
		},
		{
			name:             "CPE 2.2",
			input:            "cpe:/a:apache:struts:2.5:*:*:*:*:*:*:*",
			expectedShortCpe: "cpe:/a:apache:struts",
			expectedVersion:  "2.5",
		},
		{
			name:             "CPE 2.3",
			input:            "cpe:2.3:a:apache:struts:2.5:*:*:*:*:*:*:*",
			expectedShortCpe: "cpe:2.3:a:apache:struts",
			expectedVersion:  "2.5",
		},
		{
			name:             "Empty CPE",
			input:            "",
			expectedShortCpe: "",
			expectedVersion:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotCpe, gotVersion := CPEName(tc.input).Destructured()

			if gotVersion != tc.expectedVersion {
				t.Errorf("Expected version '%v', got '%v'", tc.expectedVersion, gotVersion)
			}
			if gotCpe != tc.expectedShortCpe {
				t.Errorf("Expected short CPE '%v', got '%v'", tc.expectedShortCpe, gotCpe)
			}
		})
	}
}
