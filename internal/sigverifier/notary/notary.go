package notary

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	DefaultRegistry = "docker.io"
)

func decodeBase64NotaryJSON(encoded string) (trustpolicy.Document, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return trustpolicy.Document{}, err
	}

	var policies trustpolicy.Document
	err = json.Unmarshal(decoded, &policies)
	if err != nil {
		return trustpolicy.Document{}, err
	}

	return policies, nil
}

func Verify(ctx context.Context, reference string, policy string, certsPEM string) error {
	// add default docker registry if a registry is not specified
	if !strings.Contains(reference, "/") {
		reference = fmt.Sprintf("%s/%s", DefaultRegistry, reference)
	}

	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader([]byte(certsPEM)))
	if err != nil {
		return errors.Wrapf(err, "failed to parse certificates")
	}
	trustStore := NewTrustStore("xeol.io", certs)

	trustpolicy, err := decodeBase64NotaryJSON(policy)
	if err != nil {
		return errors.Wrapf(err, "failed to decode policy")
	}
	plugins := plugin.NewCLIManager(dir.PluginFS())

	sigVerifier, err := verifier.New(&trustpolicy, trustStore, plugins)
	if err != nil {
		return errors.Wrapf(err, "failed to create signature verifier")
	}

	secureFlagOpts := &SecureFlagOpts{}
	inputType := inputTypeRegistry // remote registry by default
	sigRepo, err := getRepository(ctx, inputType, reference, secureFlagOpts, false)
	if err != nil {
		return errors.Wrapf(err, "failed to get repository %s", reference)
	}
	_, resolvedRef, err := resolveReferenceWithWarning(ctx, inputType, reference, sigRepo, "inspect")
	if err != nil {
		return errors.Wrapf(err, "failed to resolve reference %s", reference)
	}

	verifyOpts := notation.VerifyOptions{
		ArtifactReference:    resolvedRef,
		MaxSignatureAttempts: 100,
	}
	_, outcomes, err := notation.Verify(ctx, sigVerifier, sigRepo, verifyOpts)
	err = checkVerificationFailure(outcomes, resolvedRef, err)
	if err != nil {
		return errors.Wrapf(err, "failed to verify signature for %s", resolvedRef)
	}
	return nil
}

func checkVerificationFailure(outcomes []*notation.VerificationOutcome, printOut string, err error) error {
	if err != nil || len(outcomes) == 0 {
		if err != nil {
			var errorVerificationFailed notation.ErrorVerificationFailed
			if !errors.As(err, &errorVerificationFailed) {
				return fmt.Errorf("signature verification failed: %w", err)
			}
		}
		return fmt.Errorf("signature verification failed for all the signatures associated with %s", printOut)
	}
	return nil
}
