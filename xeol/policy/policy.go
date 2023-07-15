package policy

import (
	"time"

	"github.com/wagoodman/go-partybus"
	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"

	"github.com/Masterminds/semver"
	"github.com/xeol-io/xeol/internal/xeolio"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/match"
)

const (
	DateLayout                          = "2006-01-02"
	PolicyTypeWarn PolicyEvaluationType = "WARN"
	PolicyTypeDeny PolicyEvaluationType = "DENY"
)

type PolicyEvaluationType string

type PolicyEvaluationResult struct {
	Type        PolicyEvaluationType
	ProductName string
	Cycle       string
	FailDate    string
}

func cycleOperatorMatch(m match.Match, policy xeolio.Policy) bool {
	if m.Cycle.ProductName != policy.ProductName {
		return false
	}

	pv, err := semver.NewVersion(policy.Cycle)
	if err != nil {
		log.Debugf("Invalid policy cycle version: %s", policy.Cycle)
		return false
	}

	mv, err := semver.NewVersion(m.Cycle.ReleaseCycle)
	if err != nil {
		log.Debugf("Invalid match cycle version: %s", m.Cycle.ReleaseCycle)
		return false
	}

	switch policy.CycleOperator {
	case xeolio.CycleOperatorLessThan:
		return mv.LessThan(pv)
	case xeolio.CycleOperatorLessThanOrEqual:
		return !mv.GreaterThan(pv) // equivalent to mv <= pv
	case xeolio.CycleOperatorEqual:
		return mv.Equal(pv)
	default:
		log.Debugf("Invalid policy cycle operator: %s", policy.CycleOperator)
		return false
	}
}

func warnMatch(policy xeolio.Policy) bool {
	warnDate, err := time.Parse(DateLayout, policy.WarnDate)
	if err != nil {
		log.Debugf("Invalid policy warn date: %s", policy.WarnDate)
		return false
	}
	if time.Now().After(warnDate) {
		return true
	}
	return false
}

func denyMatch(policy xeolio.Policy) bool {
	denyDate, err := time.Parse(DateLayout, policy.DenyDate)
	if err != nil {
		log.Debugf("Invalid policy deny date: %s", policy.DenyDate)
		return false
	}
	if time.Now().After(denyDate) {
		return true
	}
	return false
}

// Evaluate evaluates a set of policies against a set of matches.
func Evaluate(policies []xeolio.Policy, matches match.Matches) error {
	for _, policy := range policies {
		for _, match := range matches.Sorted() {
			if cycleOperatorMatch(match, policy) {
				if denyMatch(policy) {
					bus.Publish(partybus.Event{
						Type: event.PolicyEvaluationMessage,
						Value: PolicyEvaluationResult{
							Type:        PolicyTypeDeny,
							ProductName: match.Cycle.ProductName,
							Cycle:       match.Cycle.ReleaseCycle,
						},
					})
					continue
				}
				if warnMatch(policy) {
					bus.Publish(partybus.Event{
						Type: event.PolicyEvaluationMessage,
						Value: PolicyEvaluationResult{
							Type:        PolicyTypeWarn,
							ProductName: match.Cycle.ProductName,
							Cycle:       match.Cycle.ReleaseCycle,
							FailDate:    policy.DenyDate,
						},
					})
					continue
				}
			}
		}
	}
	return nil
}
