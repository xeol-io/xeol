package policy

import (
	"sort"
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

type ByPolicyScope []xeolio.Policy

func (a ByPolicyScope) Len() int      { return len(a) }
func (a ByPolicyScope) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByPolicyScope) Less(i, j int) bool {
	// The priority will be: software > project > global
	switch a[i].PolicyScope {
	case xeolio.PolicyScopeSoftware:
		return true
	case xeolio.PolicyScopeProject:
		return a[j].PolicyScope != xeolio.PolicyScopeSoftware
	case xeolio.PolicyScopeGlobal:
		return a[j].PolicyScope == xeolio.PolicyScopeGlobal
	default:
		// Handle unknown cases
		return false
	}
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

func createEvaluationResult(policy xeolio.Policy, match match.Match, policyType EvaluationType) EvaluationResult {
	result := EvaluationResult{
		Type:        policyType,
		ProductName: match.Cycle.ProductName,
		Cycle:       match.Cycle.ReleaseCycle,
	}
	if policyType == PolicyTypeWarn {
		result.FailDate = policy.DenyDate
	}
	return result
}

func evaluateMatches(policies []xeolio.Policy, matches match.Matches, projectName string) []EvaluationResult {
	var results []EvaluationResult

	// keep track of which matches have been evaluated
	// so we don't evaluate the same match twice
	evaluatedMatches := make(map[string]bool)

	// policies are first sorted by scope according to
	// this order: software > project > global
	// software policies are evaluated first, then project
	// policies, then global policies
	sort.Stable(ByPolicyScope(policies))

	for _, policy := range policies {
		for _, match := range matches.Sorted() {
			if evaluatedMatches[match.Cycle.ProductName] {
				continue
			}

			switch policy.PolicyScope {
			case xeolio.PolicyScopeSoftware:
				if !cycleOperatorMatch(match, policy) {
					continue
				}
			case xeolio.PolicyScopeProject:
				if policy.ProjectName != projectName {
					continue
				}
			}

			// deny policy takes precedence over warn policy, so order is important here
			if denyMatch(policy) {
				results = append(results, createEvaluationResult(policy, match, PolicyTypeDeny))
				evaluatedMatches[match.Cycle.ProductName] = true
				continue
			}
			if warnMatch(policy) {
				results = append(results, createEvaluationResult(policy, match, PolicyTypeWarn))
				evaluatedMatches[match.Cycle.ProductName] = true
			}
		}
	}
	return results
}

// Evaluate evaluates a set of policies against a set of matches.
func Evaluate(policies []xeolio.Policy, matches match.Matches, projectName string) bool {
	policyMatches := evaluateMatches(policies, matches, projectName)
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
