package notary

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier"
)

const (
	DefaultRegistry = "docker.io"
)

func Verify(ctx context.Context, reference string) error {
	// add default registry if not specified
	if !strings.Contains(reference, "/") {
		reference = fmt.Sprintf("%s/%s", DefaultRegistry, reference)
	}

	sigVerifier, err := verifier.NewFromConfig()
	if err != nil {
		return err
	}

	secureFlagOpts := &SecureFlagOpts{}
	inputType := inputTypeRegistry // remote registry by default
	sigRepo, err := getRepository(ctx, inputType, reference, secureFlagOpts, false)
	if err != nil {
		return err
	}
	_, resolvedRef, err := resolveReferenceWithWarning(ctx, inputType, reference, sigRepo, "inspect")
	if err != nil {
		return err
	}

	verifyOpts := notation.VerifyOptions{
		ArtifactReference:    resolvedRef,
		MaxSignatureAttempts: 100,
	}
	_, outcomes, err := notation.Verify(ctx, sigVerifier, sigRepo, verifyOpts)
	err = checkVerificationFailure(outcomes, resolvedRef, err)
	if err != nil {
		return err
	}
	// reportVerificationSuccess(outcomes, resolvedRef)
	return nil
}

func checkVerificationFailure(outcomes []*notation.VerificationOutcome, printOut string, err error) error {
	// write out on failure
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
