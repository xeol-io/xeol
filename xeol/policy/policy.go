package policy

import (
	"time"

	"github.com/Masterminds/semver"
	"github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/internal/xeolio"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/match"
)

const (
	DateLayout                    = "2006-01-02"
	PolicyTypeWarn EvaluationType = "WARN"
	PolicyTypeDeny EvaluationType = "DENY"
)

var timeNow = time.Now

type EvaluationType string

type EvaluationResult struct {
	Type        EvaluationType
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
	if timeNow().After(warnDate) {
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
	if timeNow().After(denyDate) {
		return true
	}
	return false
}

func evaluateMatches(policies []xeolio.Policy, matches match.Matches) []EvaluationResult {
	var results []EvaluationResult
	for _, policy := range policies {
		for _, match := range matches.Sorted() {
			if cycleOperatorMatch(match, policy) {
				if denyMatch(policy) {
					results = append(results, EvaluationResult{
						Type:        PolicyTypeDeny,
						ProductName: match.Cycle.ProductName,
						Cycle:       match.Cycle.ReleaseCycle,
					},
					)
					continue
				}
				if warnMatch(policy) {
					results = append(results, EvaluationResult{
						Type:        PolicyTypeWarn,
						ProductName: match.Cycle.ProductName,
						Cycle:       match.Cycle.ReleaseCycle,
						FailDate:    policy.DenyDate,
					},
					)
					continue
				}
			}
		}
	}
	return results
}

// Evaluate evaluates a set of policies against a set of matches.
func Evaluate(policies []xeolio.Policy, matches match.Matches) bool {
	policyMatches := evaluateMatches(policies, matches)
	// whether we should fail the scan or not
	failScan := false

	for _, policyMatch := range policyMatches {
		if policyMatch.Type == PolicyTypeDeny {
			failScan = true
		}
		bus.Publish(partybus.Event{
			Type:  event.PolicyEvaluationMessage,
			Value: policyMatch,
		})
	}
	return failScan
}
