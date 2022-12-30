package version

import (
	"fmt"
	"runtime"
	"strings"
)

const valueNotProvided = "[not provided]"

// all variables here are provided as build-time arguments, with clear default values
var version = valueNotProvided
var syftVersion = valueNotProvided
var gitCommit = valueNotProvided
var platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

// Version defines the application version details (generally from build information)
type Version struct {
	Version     string `json:"version"`     // application semantic version
	SyftVersion string `json:"syftVersion"` // the version of syft being used by xeol
	GitCommit   string `json:"gitCommit"`   // git SHA at build-time
	GoVersion   string `json:"goVersion"`   // go runtime version at build-time
	Compiler    string `json:"compiler"`    // compiler used at build-time
	Platform    string `json:"platform"`    // GOOS and GOARCH at build-time
}

func (v Version) isProductionBuild() bool {
	if strings.Contains(v.Version, "SNAPSHOT") || strings.Contains(v.Version, valueNotProvided) {
		return false
	}
	return true
}

// FromBuild provides all version details
func FromBuild() Version {
	return Version{
		Version:     version,
		SyftVersion: syftVersion,
		GitCommit:   gitCommit,
		GoVersion:   runtime.Version(),
		Compiler:    runtime.Compiler,
		Platform:    platform,
	}
}
