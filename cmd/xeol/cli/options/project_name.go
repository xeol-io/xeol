package options

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	git "github.com/go-git/go-git/v5"

	"github.com/xeol-io/xeol/internal/log"
)

type Project struct {
	Name string
	Repo *git.Repository
}

type URLFormatter struct {
	URL string
}

type GitURL interface {
	Parse(url string) error
	String() string
}

type Azure struct {
	Owner string
	Path  string
}

func (r *Azure) Parse(rawurl string) error {
	if strings.HasPrefix(rawurl, "git@") {
		rawurl = strings.Replace(rawurl, ":", "/", 1)
		rawurl = strings.Replace(rawurl, "git@", "https://", 1)
	}

	p, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	p.Path = strings.TrimSuffix(p.Path, ".git")
	p.Path = strings.TrimPrefix(p.Path, "/")
	p.Path = regexp.MustCompile(`^v\d+\/`).ReplaceAllString(p.Path, "")
	p.Path = regexp.MustCompile(`/_git/`).ReplaceAllString(p.Path, "/")

	pathParts := strings.Split(p.Path, "/")
	r.Owner = pathParts[0]
	r.Path = strings.Join(pathParts[1:], "/")
	r.Path = strings.ReplaceAll(r.Path, " ", "%20")
	return nil
}

func (r *Azure) String() string {
	return fmt.Sprintf("azure//%s/%s", r.Owner, r.Path)
}

type GitHub struct {
	Owner string
	Path  string
}

func (r *GitHub) Parse(rawurl string) error {
	if strings.HasPrefix(rawurl, "git@") {
		rawurl = strings.Replace(rawurl, ":", "/", 1)
		rawurl = strings.Replace(rawurl, "git@", "https://", 1)
	}

	p, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	p.Path = strings.TrimSuffix(p.Path, ".git")
	p.Path = strings.TrimPrefix(p.Path, "/")

	pathParts := strings.SplitN(p.Path, "/", 2)
	r.Owner = pathParts[0]
	r.Path = pathParts[1]
	return nil
}

func (r *GitHub) String() string {
	return fmt.Sprintf("github//%s/%s", r.Owner, r.Path)
}

type GitLab struct {
	Owner string
	Path  string
}

func (r *GitLab) Parse(rawurl string) error {
	if strings.HasPrefix(rawurl, "git@") {
		rawurl = strings.Replace(rawurl, ":", "/", 1)
		rawurl = strings.Replace(rawurl, "git@", "https://", 1)
	}

	p, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	p.Path = strings.TrimSuffix(p.Path, ".git")
	p.Path = strings.TrimPrefix(p.Path, "/")

	pathParts := strings.SplitN(p.Path, "/", 2)
	r.Owner = pathParts[0]
	r.Path = pathParts[1]
	return nil
}

func (r *GitLab) String() string {
	return fmt.Sprintf("gitlab//%s/%s", r.Owner, r.Path)
}

func parseRawGitURL(rawurl string) (GitURL, error) {
	var g GitURL
	switch {
	case strings.Contains(rawurl, "github.com"):
		g = &GitHub{}
	case strings.Contains(rawurl, "gitlab.com"):
		g = &GitLab{}
	case strings.Contains(rawurl, "dev.azure.com"):
		g = &Azure{}
	default:
		return nil, fmt.Errorf("unsupported git url: %s", rawurl)
	}

	err := g.Parse(rawurl)
	return g, err
}

func (f *URLFormatter) Format() string {
	gURL, err := parseRawGitURL(f.URL)
	if err != nil {
		log.Debug(err)
		return ""
	}

	return gURL.String()
}

func NewProject(repo *git.Repository) *Project {
	p := &Project{Repo: repo}
	p.Name = p.GetDefaultProjectName()

	return p
}

func (p *Project) GetRemoteURL() string {
	// try to get the origin remote
	origin, err := p.Repo.Remote("origin")
	if err == nil {
		return origin.Config().URLs[0]
	}

	// if origin is not found, get the list of remotes
	remotes, err := p.Repo.Remotes()
	if err != nil {
		return ""
	}

	if len(remotes) == 0 {
		return ""
	}

	// return the URL of the first remote found
	return remotes[0].Config().URLs[0]
}

func (p *Project) GetDefaultProjectName() string {
	url := p.GetRemoteURL()
	formatter := URLFormatter{URL: url}

	return formatter.Format()
}
