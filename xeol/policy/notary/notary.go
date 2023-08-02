package notary

import (
	"context"
	"time"

	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"
	sigverifier "github.com/xeol-io/xeol/internal/sigverifier/notary"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/policy/types"
)

var timeNow = time.Now

const (
	DateLayout = "2006-01-02"
)

type PolicyType struct {
	PolicyType    types.PolicyType          `json:"policy_type"`
	TrustPolicies []trustpolicy.TrustPolicy `json:"trust_policy"`
	// the date which to warn on signature verification failures
	WarnDate string `json:"warn_date,omitempty"`
	// the date which to deny on signature verification failures
	DenyDate string `json:"deny_date,omitempty"`
}

func (n PolicyType) warnMatch() bool {
	if n.WarnDate != "" {
		warnDate, err := time.Parse(DateLayout, n.WarnDate)
		if err != nil {
			log.Debugf("failed to parse warn date: %v", err)
			return false
		}

		if warnDate.IsZero() {
			return false
		}

		if timeNow().After(warnDate) {
			return true
		}
	}
	return false
}

func (n PolicyType) denyMatch() bool {
	if n.DenyDate != "" {
		denyDate, err := time.Parse(DateLayout, n.DenyDate)
		if err != nil {
			log.Debugf("failed to parse warn date: %v", err)
			return false
		}

		if denyDate.IsZero() {
			return false
		}

		if timeNow().After(denyDate) {
			return true
		}
	}
	return false
}

func (n PolicyType) Evaluate(_ match.Matches, _ string, imageReference string) (failBuild bool) {
	failBuild = false
	// image unsigned | image signed | image signed + verified

	ctx := context.Background()
	err := sigverifier.Verify(ctx, imageReference)
	if err == nil {
		return failBuild
	}
	log.Debugf("signature verification failed: %v", err)

	if n.denyMatch() {
		failBuild = true
		bus.Publish(partybus.Event{
			Type: event.NotaryPolicyEvaluationMessage,
			Value: types.NotaryEvaluationResult{
				Type:           types.PolicyTypeDeny,
				ImageReference: imageReference,
			},
		})
		return failBuild
	}

	if n.warnMatch() {
		bus.Publish(partybus.Event{
			Type: event.NotaryPolicyEvaluationMessage,
			Value: types.NotaryEvaluationResult{
				Type:           types.PolicyTypeWarn,
				ImageReference: imageReference,
				FailDate:       n.DenyDate,
			},
		})
		return failBuild
	}

	return failBuild
}
