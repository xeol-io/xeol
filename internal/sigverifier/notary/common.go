package notary

import (
	"oras.land/oras-go/v2/registry/remote/auth"
)

type SecureFlagOpts struct {
	Username         string
	Password         string
	InsecureRegistry bool
}

// Credential returns an auth.Credential from opts.Username and opts.Password.
func (opts *SecureFlagOpts) Credential() auth.Credential {
	if opts.Username == "" {
		return auth.Credential{
			RefreshToken: opts.Password,
		}
	}
	return auth.Credential{
		Username: opts.Username,
		Password: opts.Password,
	}
}
