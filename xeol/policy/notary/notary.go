package notary

import (
	"context"
	"time"

	"github.com/docker/distribution/reference"
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

type PolicyWrapper struct {
	PolicyType types.PolicyType `json:"PolicyType"`
	Policies   []Policy         `json:"Policies"`
}

type Policy struct {
	WarnDate string `json:"WarnDate"`
	DenyDate string `json:"DenyDate"`
	Policy   string `json:"Policy"`
}

func (n PolicyWrapper) GetPolicyType() types.PolicyType {
	return n.PolicyType
}

func (n Policy) warnMatch() bool {
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

func (n Policy) denyMatch() bool {
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

func (n PolicyWrapper) Evaluate(_ match.Matches, _ string, imageReference string) (bool, types.PolicyEvaluationResult) {
	if len(n.Policies) == 0 {
		log.Errorf("no notary policies provided")
		return false, types.NotaryEvaluationResult{}
	}

	if len(n.Policies) > 1 {
		log.Errorf("invalid number of notary policies, there should only be one: %d", len(n.Policies))
		return false, types.NotaryEvaluationResult{}
	}

	// validate this is a docker image reference
	isValid := reference.ReferenceRegexp.MatchString(imageReference)
	if !isValid {
		log.Errorf("invalid Docker image reference: %s", imageReference)
		return false, types.NotaryEvaluationResult{}
	}

	policy := n.Policies[0]

	failBuild := false
	ctx := context.Background()
	err := sigverifier.Verify(ctx, imageReference, policy.Policy)
	// if err is nil, then the image is verified
	if err == nil {
		return failBuild, types.NotaryEvaluationResult{
			Action:         types.PolicyActionAllow,
			Type:           types.PolicyTypeNotary,
			ImageReference: imageReference,
			Verified:       true,
		}
	}
	log.Debugf("signature verification failed: %v", err)

	if policy.denyMatch() {
		failBuild = true
		result := types.NotaryEvaluationResult{
			Action:         types.PolicyActionDeny,
			Type:           types.PolicyTypeNotary,
			ImageReference: imageReference,
			Verified:       false,
		}
		bus.Publish(partybus.Event{
			Type:  event.NotaryPolicyEvaluationMessage,
			Value: result,
		})
		return failBuild, result
	}

	if policy.warnMatch() {
		result := types.NotaryEvaluationResult{
			Action:         types.PolicyActionWarn,
			Type:           types.PolicyTypeNotary,
			ImageReference: imageReference,
			Verified:       false,
			FailDate:       policy.DenyDate,
		}
		bus.Publish(partybus.Event{
			Type:  event.NotaryPolicyEvaluationMessage,
			Value: result,
		})
		return failBuild, result
	}

	return failBuild, types.NotaryEvaluationResult{}
}
