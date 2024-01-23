package types

import (
	"fmt"
	"regexp"
)

type CommitHash string

func (c CommitHash) IsValid() error {
	re := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	if !re.MatchString(string(c)) {
		return fmt.Errorf("invalid SHA1 hash format for commit hash '%s'", string(c))
	}
	return nil
}
