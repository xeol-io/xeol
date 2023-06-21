package config

import (
	"fmt"
	"regexp"
	"strings"

	git "github.com/go-git/go-git/v5"
)

type Project struct {
	Name string
	Repo *git.Repository
}

type RepoType int

const (
	Unknown RepoType = iota
	HTTPS
	SSH
)

func NewProject(repo *git.Repository) *Project {
	p := &Project{Repo: repo}
	p.Name = p.GetDefaultProjectName()

	return p
}

func (p *Project) GetRemoteURL() string {
	origin, err := p.Repo.Remote("origin")
	if err != nil {
		return ""
	}

	return origin.Config().URLs[0]
}

func (p *Project) GetDefaultProjectName() string {
	url := p.GetRemoteURL()
	formatter := URLFormatter{URL: url}

	return formatter.Format()
}

type URLFormatter struct {
	URL string
}

func (f *URLFormatter) getRepoType() RepoType {
	httpsPattern := `^https://`
	sshPattern := `^git@`

	httpsRe, err := regexp.Compile(httpsPattern)
	if err != nil {
		return Unknown
	}

	sshRe, err := regexp.Compile(sshPattern)
	if err != nil {
		return Unknown
	}

	if httpsRe.MatchString(f.URL) {
		return HTTPS
	} else if sshRe.MatchString(f.URL) {
		return SSH
	}

	return Unknown
}

func (f *URLFormatter) formatStandardHTTPS() string {
	trimmedURL := strings.TrimPrefix(f.URL, "https://")
	trimmedURL = strings.TrimSuffix(trimmedURL, ".git")

	parts := strings.Split(trimmedURL, "/")
	if len(parts) > 2 {
		return fmt.Sprintf("%s/%s", parts[1], parts[2])
	}
	return ""
}

func (f *URLFormatter) formatStandardSSH() string {
	trimmedURL := strings.TrimPrefix(f.URL, "git@")
	trimmedURL = strings.TrimSuffix(trimmedURL, ".git")

	parts := strings.Split(trimmedURL, ":")
	if len(parts) < 2 {
		return ""
	}

	parts = strings.Split(parts[1], "/")
	if len(parts) > 2 {
		// azure
		return fmt.Sprintf("%s/%s", parts[1], parts[2])
	}
	if len(parts) == 2 {
		// github+gitlab
		return fmt.Sprintf("%s/%s", parts[0], parts[1])
	}

	return ""
}

func (f *URLFormatter) Format() string {
	repoType := f.getRepoType()

	var projectName string
	if repoType == HTTPS {
		projectName = f.formatStandardHTTPS()
	}

	if repoType == SSH {
		projectName = f.formatStandardSSH()
	}

	switch {
	case strings.Contains(f.URL, "github"):
		return fmt.Sprintf("github//%s", projectName)
	case strings.Contains(f.URL, "gitlab"):
		return fmt.Sprintf("gitlab//%s", projectName)
	case strings.Contains(f.URL, "azure"):
		return fmt.Sprintf("azure//%s", projectName)
	}

	return ""
}
