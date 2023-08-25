package eol

import (
	"math"
	"sort"
	"time"

	"github.com/Masterminds/semver"
	"github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/internal/bus"
	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/policy/types"
)

var timeNow = time.Now

const (
	DateLayout                                 = "2006-01-02"
	CycleOperatorLessThan        CycleOperator = "LT"
	CycleOperatorLessThanOrEqual CycleOperator = "LTE"
	CycleOperatorEqual           CycleOperator = "EQ"

	PolicyScopeGlobal   PolicyScope = "global"
	PolicyScopeProject  PolicyScope = "project"
	PolicyScopeSoftware PolicyScope = "software"

	// set a max days for deny/warn policies
	// to avoid overflow/underflow errors when
	// calculating dates. 10 years should be
	// more than enough for most use cases
	MaxNumDays = 10 * 365
)

type PolicyWrapper struct {
	PolicyType types.PolicyType `json:"PolicyType"`
	Policies   []Policy         `json:"Policies"`
}

type Policy struct {
	ID         string           `json:"ID"`
	PolicyType types.PolicyType `json:"PolicyType"`
	// the policy scope can be one of: global, project, software
	// global: the policy applies to all projects and software
	// project: the policy applies to all software in a project
	// software: the policy applies to a specific software
	PolicyScope PolicyScope `json:"PolicyScope"`
	// the date which to start warning xeol scans
	WarnDate string `json:"WarnDate,omitempty"`
	// the date which to start failing xeol scans
	DenyDate string `json:"DenyDate,omitempty"`
	// the days before eol to start warning xeol scans
	WarnDays *int `json:"WarnDays,omitempty"`
	// the days before eol to start failing xeol scans
	DenyDays *int `json:"DenyDays,omitempty"`
	// the project name to match policy against. Valid when PolicyScope is 'project'
	ProjectName string `json:"ProjectName,omitempty"`
	//
	// the following fields are only used when PolicyScope is 'software'
	//
	// the product name to match policy against.
	ProductName string `json:"ProductName,omitempty"`
	// the cycle to match policy against.
	Cycle string `json:"Cycle,omitempty"`
	// the cycle operator to match policy against.
	CycleOperator CycleOperator `json:"CycleOperator,omitempty"`
}

type CycleOperator string
type PolicyScope string

type ByPolicyScope []Policy

func (a ByPolicyScope) Len() int      { return len(a) }
func (a ByPolicyScope) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByPolicyScope) Less(i, j int) bool {
	// The priority will be: software > project > global
	switch a[i].PolicyScope {
	case PolicyScopeSoftware:
		return true
	case PolicyScopeProject:
		return a[j].PolicyScope != PolicyScopeSoftware
	case PolicyScopeGlobal:
		return a[j].PolicyScope == PolicyScopeGlobal
	default:
		// Handle unknown cases
		return false
	}
}

func (e PolicyWrapper) GetPolicyType() types.PolicyType {
	return e.PolicyType
}

func (e PolicyWrapper) Evaluate(matches match.Matches, projectName string, _ string) (bool, types.PolicyEvaluationResult) {
	policyMatches := evaluateMatches(e.Policies, matches, projectName)

	// whether we should fail the scan or not
	failScan := false

	for _, policyMatch := range policyMatches {
		if policyMatch.Action == types.PolicyActionDeny {
			failScan = true
		}
		bus.Publish(partybus.Event{
			Type:  event.EolPolicyEvaluationMessage,
			Value: policyMatch,
		})
	}

	return failScan, types.EolEvaluationResult{}
}

func evaluateMatches(policies []Policy, matches match.Matches, projectName string) []types.EolEvaluationResult {
	var results []types.EolEvaluationResult

	// keep track of which matches have been evaluated
	// so we don't evaluate the same match twice
	evaluatedMatches := make(map[string]bool)

	// policies are first sorted by scope according to
	// this order: software > project > global
	// software policies are evaluated first, then project
	// policies, then global policies
	sort.Stable(ByPolicyScope(policies))

	for _, policy := range policies {
		policyCopy := policy
		for _, match := range matches.Sorted() {
			// skip matches eol bool set to true. Unfortunately, setting
			// a policy around a software that has EOL true does not give operators
			// enough time to respond so we will skip for now
			if match.Cycle.EolBool {
				results = append(results, createEolEvaluationResult(Policy{}, match, types.PolicyActionWarn))
				evaluatedMatches[match.Cycle.ProductName] = true
				continue
			}

			if evaluatedMatches[match.Cycle.ProductName] {
				continue
			}

			switch policy.PolicyScope {
			case PolicyScopeSoftware:
				if !cycleOperatorMatch(match, policy) {
					continue
				}
			case PolicyScopeProject:
				if policy.ProjectName != projectName {
					continue
				}
			}

			// deny policy takes precedence over warn policy, so order is important here
			if denyMatch(&policyCopy, match) {
				results = append(results, createEolEvaluationResult(policyCopy, match, types.PolicyActionDeny))
				evaluatedMatches[match.Cycle.ProductName] = true
				continue
			}
			if warnMatch(&policyCopy, match) {
				results = append(results, createEolEvaluationResult(policyCopy, match, types.PolicyActionWarn))
				evaluatedMatches[match.Cycle.ProductName] = true
				continue
			}
		}
	}
	return results
}

func cycleOperatorMatch(m match.Match, policy Policy) bool {
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
	case CycleOperatorLessThan:
		return mv.LessThan(pv)
	case CycleOperatorLessThanOrEqual:
		return !mv.GreaterThan(pv) // equivalent to mv <= pv
	case CycleOperatorEqual:
		return mv.Equal(pv)
	default:
		log.Debugf("Invalid policy cycle operator: %s", policy.CycleOperator)
		return false
	}
}

func warnMatch(policy *Policy, match match.Match) bool {
	var warnDate time.Time

	if policy.WarnDate != "" {
		var err error
		warnDate, err = time.Parse(DateLayout, policy.WarnDate)
		if err != nil {
			log.Errorf("invalid policy warn date: %s", policy.WarnDate)
			return false
		}
	}

	if policy.WarnDays != nil {
		warnDays := *policy.WarnDays * -1
		if math.Abs(float64(warnDays)) > MaxNumDays {
			log.Debugf("warn days (%d) is greater than max days, setting to max days (%d)", warnDays, MaxNumDays)
			warnDays = MaxNumDays
		}
		eolDate, err := time.Parse(DateLayout, match.Cycle.Eol)
		if err != nil {
			log.Errorf("invalid eol date: %s, %s", match.Cycle.Eol, err)
			return false
		}
		warnDate = eolDate.Add(time.Duration(warnDays) * time.Hour * 24)
	}

	if warnDate.IsZero() {
		return false
	}

	if timeNow().After(warnDate) {
		return true
	}

	return false
}

func denyMatch(policy *Policy, match match.Match) bool {
	var denyDate time.Time

	if policy.DenyDate != "" {
		var err error
		denyDate, err = time.Parse(DateLayout, policy.DenyDate)
		if err != nil {
			log.Errorf("invalid policy deny date: %s", policy.DenyDate)
			return false
		}
	}

	if policy.DenyDays != nil {
		denyDays := *policy.DenyDays * -1
		if math.Abs(float64(denyDays)) > MaxNumDays {
			log.Debugf("deny days (%d) is greater than max days, setting to max days (%d)", denyDays, MaxNumDays)
			denyDays = MaxNumDays
		}

		eolDate, err := time.Parse(DateLayout, match.Cycle.Eol)
		if err != nil {
			log.Errorf("invalid eol date: %s, %s", match.Cycle.Eol, err)
			return false
		}
		denyDate = eolDate.Add(time.Duration(denyDays) * time.Hour * 24)
		policy.DenyDate = denyDate.Format(DateLayout)
	}

	if denyDate.IsZero() {
		return false
	}

	if timeNow().After(denyDate) {
		return true
	}

	return false
}

func createEolEvaluationResult(policy Policy, match match.Match, policyAction types.PolicyAction) types.EolEvaluationResult {
	result := types.EolEvaluationResult{
		Action:      policyAction,
		Type:        types.PolicyTypeEol,
		ProductName: match.Cycle.ProductName,
		Cycle:       match.Cycle.ReleaseCycle,
	}
	if policy != (Policy{}) {
		if policyAction == types.PolicyActionWarn {
			result.FailDate = policy.DenyDate
		}
	}
	return result
}
