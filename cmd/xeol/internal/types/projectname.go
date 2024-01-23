package types

import (
	"fmt"
	"regexp"
)

type ProjectName string

func (p ProjectName) IsValid() error {
	re := regexp.MustCompile(`^(gitlab|github|azure)//([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_]+(/[a-zA-Z0-9\-_]+)?)$`)
	if ok := re.MatchString(string(p)); !ok {
		return fmt.Errorf("invalid project name. Accepted formats: 'gitlab//<owner>/<repo>', 'github//<owner>/<repo>', 'azure//<owner>/<project>/<repo>'")
	}
	return nil
}
