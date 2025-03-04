package options

import (
	"fmt"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source"
	git "github.com/go-git/go-git/v5"
	"github.com/karrick/tparse"

	"github.com/xeol-io/xeol/internal/format"
)

const DefaultProLookahead = "now+3y"

type Xeol struct {
	Outputs                []string    `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, <presenter>=<file> the Presenter hint string to use for report formatting and the output file
	File                   string      `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	Distro                 string      `yaml:"distro" json:"distro" mapstructure:"distro"`                                           // --distro, specify a distro to explicitly use
	CheckForAppUpdate      bool        `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Platform               string      `yaml:"platform" json:"platform" mapstructure:"platform"`                                     // --platform, override the target platform for a container image
	Search                 search      `yaml:"search" json:"search" mapstructure:"search"`
	DB                     Database    `yaml:"db" json:"db" mapstructure:"db"`
	Lookahead              string      `yaml:"lookahead" json:"lookahead" mapstructure:"lookahead"`
	EolMatchDate           time.Time   `yaml:"-" json:"-"`
	FailOnEolFound         bool        `yaml:"fail-on-eol-found" json:"fail-on-eol-found" mapstructure:"fail-on-eol-found"` // whether to exit with a non-zero exit code if any EOLs are found
	APIKey                 string      `yaml:"api-key" json:"api-key" mapstructure:"api-key"`
	ProjectName            string      `yaml:"project-name" json:"project-name" mapstructure:"project-name"`
	ImagePath              string      `yaml:"image-path" json:"image-path" mapstructure:"image-path"`
	CommitHash             string      `yaml:"commit-hash" json:"commit-hash" mapstructure:"commit-hash"`
	Match                  matchConfig `yaml:"match" json:"match" mapstructure:"match"`
	Registry               registry    `yaml:"registry" json:"registry" mapstructure:"registry"`
	Name                   string      `yaml:"name" json:"name" mapstructure:"name"`
	DefaultImagePullSource string      `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`
	ShowVulnCount          bool        `yaml:"show-vuln-count" json:"show-vuln-count" mapstructure:"show-vuln-count"`
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*Xeol)(nil)

func DefaultXeol(id clio.Identification) *Xeol {
	project, commit := getDefaultProjectNameAndCommit()

	config := &Xeol{
		Search:            defaultSearch(source.SquashedScope),
		DB:                DefaultDatabase(id),
		Match:             defaultMatchConfig(),
		CheckForAppUpdate: true,
		Lookahead:         "1y",
		FailOnEolFound:    false,
		ProjectName:       project,
		CommitHash:        commit,
		ImagePath:         "Dockerfile",
		ShowVulnCount:     false,
	}
	return config
}

func getDefaultProjectNameAndCommit() (string, string) {
	repo, err := git.PlainOpen(".")
	if err != nil {
		return "", ""
	}

	h, err := repo.Head()
	if err != nil {
		return "", ""
	}

	p := NewProject(repo)
	return p.Name, h.Hash().String()
}

// nolint:funlen
func (o *Xeol) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Search.Scope,
		"scope", "s",
		fmt.Sprintf("selection of layers to analyze, options=%v", source.AllScopes),
	)

	flags.StringArrayVarP(&o.Outputs,
		"output", "o",
		fmt.Sprintf("report output formatter, formats=%v", format.AvailableFormats),
	)

	flags.StringVarP(&o.File,
		"file", "",
		"file to write the default report output to (default is STDOUT)",
	)

	flags.StringVarP(&o.Name,
		"name", "",
		"set the name of the target being analyzed",
	)

	flags.StringVarP(&o.ProjectName,
		"project-name", "",
		"manually set the name of the project being analyzed for xeol.io. If you are running xeol inside a git repository, this will be automatically detected.",
	)

	flags.StringVarP(&o.APIKey,
		"api-key", "",
		"set the API key for xeol.io. When this is set, scans will be uploaded to xeol.io.",
	)

	flags.BoolVarP(&o.FailOnEolFound,
		"fail-on-eol-found", "f",
		"set the return code to 1 if an EOL package is found",
	)

	flags.StringVarP(&o.Lookahead,
		"lookahead", "l",
		"an optional lookahead specifier when matching EOL dates (e.g. 'none', '1d', '1w', '1m', '1y'). Packages are matched when their EOL date < today+lookahead",
	)

	flags.StringVarP(&o.Distro,
		"distro", "",
		"distro to match against in the format: <distro>:<version>",
	)

	flags.StringVarP(&o.Platform,
		"platform", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)

	flags.BoolVarP(&o.ShowVulnCount,
		"show-vuln-count", "",
		"show the number of vulnerabilities found for each package (default is false)",
	)
}

func (o *Xeol) parseLookaheadOption() (err error) {
	// if the user has specified an API key and is posting results to xeol.io, then we
	// set a default lookahead value to 3 years from now
	if o.APIKey != "" {
		o.EolMatchDate, err = tparse.ParseNow(time.RFC3339, DefaultProLookahead)
		if err != nil {
			return fmt.Errorf("bad --lookahead value: '%s'", o.Lookahead)
		}
		return nil
	}

	if o.Lookahead == "" {
		o.EolMatchDate = time.Now()
		return nil
	}

	o.EolMatchDate, err = tparse.ParseNow(time.RFC3339, fmt.Sprintf("now+%s", o.Lookahead))
	if err != nil {
		return fmt.Errorf("bad --lookahead value: '%s'", o.Lookahead)
	}

	return nil
}

func (o *Xeol) PostLoad() error {
	return o.parseLookaheadOption()
}
