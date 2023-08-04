package notary

import (
	"context"
	"errors"
	"fmt"
	"net"

	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation/pkg/configutil"
	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	notationauth "github.com/xeol-io/xeol/internal/sigverifier/notary/auth"
	"github.com/xeol-io/xeol/internal/sigverifier/notary/version"
)

// inputType denotes the user input type
type inputType int

const (
	inputTypeRegistry  inputType = 1 + iota // inputType remote registry
	inputTypeOCILayout                      // inputType oci-layout
)

// getRepository returns a notationregistry.Repository given user input
// type and user input reference
func getRepository(ctx context.Context, inputType inputType, reference string, opts *SecureFlagOpts, allowReferrersAPI bool) (notationregistry.Repository, error) {
	switch inputType {
	case inputTypeRegistry:
		return getRemoteRepository(ctx, opts, reference, allowReferrersAPI)
	case inputTypeOCILayout:
		layoutPath, _, err := parseOCILayoutReference(reference)
		if err != nil {
			return nil, err
		}
		return notationregistry.NewOCIRepository(layoutPath, notationregistry.RepositoryOptions{})
	default:
		return nil, errors.New("unsupported input type")
	}
}

// getRemoteRepository returns a registry.Repository.
// When experimental feature is disabled OR allowReferrersAPI is not set,
// Notation always uses referrers tag schema to store and consume signatures
// by default.
// When experimental feature is enabled AND allowReferrersAPI is set, Notation
// tries the Referrers API, if not supported, fallback to use the Referrers
// tag schema.
//
// References:
// https://github.com/opencontainers/distribution-spec/blob/v1.1.0-rc1/spec.md#listing-referrers
// https://github.com/opencontainers/distribution-spec/blob/v1.1.0-rc1/spec.md#referrers-tag-schema
func getRemoteRepository(ctx context.Context, opts *SecureFlagOpts, reference string, _ bool) (notationregistry.Repository, error) {
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, err
	}

	// generate notation repository
	remoteRepo, err := getRepositoryClient(ctx, opts, ref)
	if err != nil {
		return nil, err
	}

	if err := remoteRepo.SetReferrersCapability(false); err != nil {
		return nil, err
	}
	return notationregistry.NewRepository(remoteRepo), nil
}

func getRepositoryClient(ctx context.Context, opts *SecureFlagOpts, ref registry.Reference) (*remote.Repository, error) {
	authClient, insecureRegistry, err := getAuthClient(ctx, opts, ref, true)
	if err != nil {
		return nil, err
	}

	return &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: insecureRegistry,
	}, nil
}

// getAuthClient returns an *auth.Client and a bool indicating if the registry
// is insecure.
//
// If withCredential is true, the returned *auth.Client will have its Credential
// function configured.
//
// If withCredential is false, the returned *auth.Client will have a nil
// Credential function.
func getAuthClient(_ context.Context, opts *SecureFlagOpts, ref registry.Reference, withCredential bool) (*auth.Client, bool, error) {
	var insecureRegistry bool
	if opts.InsecureRegistry {
		insecureRegistry = opts.InsecureRegistry
	} else {
		insecureRegistry = configutil.IsRegistryInsecure(ref.Registry)
		if !insecureRegistry {
			if host, _, _ := net.SplitHostPort(ref.Registry); host == "localhost" {
				insecureRegistry = true
			}
		}
	}

	// build authClient
	authClient := &auth.Client{
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}
	authClient.SetUserAgent("notation/" + version.GetVersion())
	if !withCredential {
		return authClient, insecureRegistry, nil
	}

	cred := opts.Credential()
	if cred != auth.EmptyCredential {
		// use the specified credential
		authClient.Credential = auth.StaticCredential(ref.Host(), cred)
	} else {
		// use saved credentials
		credsStore, err := notationauth.NewCredentialsStore()
		if err != nil {
			return nil, false, fmt.Errorf("failed to get credentials store: %w", err)
		}
		authClient.Credential = credentials.Credential(credsStore)
	}
	return authClient, insecureRegistry, nil
}
