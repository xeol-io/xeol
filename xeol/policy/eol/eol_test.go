package eol

import (
	"reflect"
	"sort"
	"testing"
	"time"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/google/uuid"

	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
	"github.com/xeol-io/xeol/xeol/policy/types"
)

func Int(value int) *int {
	return &value
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name    string
		policy  []Policy
		matches []match.Match
		want    []types.EolEvaluationResult
	}{
		{
			name: "policy with no matches",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0.0",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorLessThan,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-01-01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "product-e",
						ReleaseCycle: "1.0.0",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "package-e",
						Version: "2.0.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: nil,
		},
		{
			name: "policy with deny match",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorLessThanOrEqual,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-01-29",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.0",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.2.1",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "foo",
					Cycle:       "1.0",
				},
			},
		},
		{
			name: "policy with warn match, version less than equal",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorLessThanOrEqual,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-03-01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.0",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.2.1",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.0",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "policy with warn match, version less than",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorLessThan,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-03-01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "0.9",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "0.9.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "0.9",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "policy with warn match, version equal",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorEqual,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-03-01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.0",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.0.1",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.0",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "test multiple policy matches",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.3",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorEqual,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-03-01",
				},
				{
					ProductName:   "bar",
					Cycle:         "2.1",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorLessThanOrEqual,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-01-29",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
				{
					Cycle: eol.Cycle{
						ProductName:  "bar",
						ReleaseCycle: "2.0",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "bar",
						Version: "2.0.1",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "bar",
					Cycle:       "2.0",
				},
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.3",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "test bad dates",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.3",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorEqual,
					WarnDate:      "2021/01/01",
					DenyDate:      "2021/03/01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: nil,
		},
		{
			name: "test bad cycles",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.4",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorEqual,
					WarnDate:      "2021/01/01",
					DenyDate:      "2021/03/01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: nil,
		},
		{
			name: "test future dates",
			policy: []Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.3",
					PolicyScope:   PolicyScopeSoftware,
					CycleOperator: CycleOperatorEqual,
					WarnDate:      "2021-04-01",
					DenyDate:      "2021-05-01",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: nil,
		},
		{
			name: "test global policy",
			policy: []Policy{
				{
					PolicyScope: PolicyScopeGlobal,
					PolicyType:  types.PolicyTypeEol,
					WarnDate:    "2021-01-01",
					DenyDate:    "2021-01-29",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
				{
					Cycle: eol.Cycle{
						ProductName:  "bar",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "bar",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "bar",
					Cycle:       "1.3",
				},
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "foo",
					Cycle:       "1.3",
				},
			},
		},
		{
			name: "test project and software precedence",
			policy: []Policy{
				{
					PolicyScope: PolicyScopeProject,
					PolicyType:  types.PolicyTypeEol,
					WarnDate:    "2021-01-17",
					DenyDate:    "2021-01-18",
					ProjectName: "github//foo/bar",
				},
				{
					PolicyScope:   PolicyScopeSoftware,
					PolicyType:    types.PolicyTypeEol,
					WarnDate:      "2021-01-29",
					DenyDate:      "2021-02-29",
					ProductName:   "foo",
					Cycle:         "1.3",
					CycleOperator: CycleOperatorEqual,
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
				{
					Cycle: eol.Cycle{
						ProductName:  "bar",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "bar",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.3",
					FailDate:    "2021-02-29",
				},
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "bar",
					Cycle:       "1.3",
				},
			},
		},
		{
			name: "test project and global precedence",
			policy: []Policy{
				{
					PolicyScope: PolicyScopeGlobal,
					PolicyType:  types.PolicyTypeEol,
					WarnDate:    "2021-01-15",
					DenyDate:    "2021-01-16",
				},
				{
					PolicyScope: PolicyScopeProject,
					PolicyType:  types.PolicyTypeEol,
					WarnDate:    "2021-01-29",
					DenyDate:    "2021-02-29",
					ProjectName: "github//foo/bar",
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
				{
					Cycle: eol.Cycle{
						ProductName:  "bar",
						ReleaseCycle: "1.3",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "bar",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "bar",
					Cycle:       "1.3",
					FailDate:    "2021-02-29",
				},
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.3",
					FailDate:    "2021-02-29",
				},
			},
		},
		{
			name: "test sliding global policy [deny]",
			policy: []Policy{
				{
					PolicyScope: PolicyScopeGlobal,
					PolicyType:  types.PolicyTypeEol,
					WarnDays:    Int(60),
					DenyDays:    Int(30),
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
						Eol:          "2021-02-28",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "foo",
					Cycle:       "1.3",
				},
			},
		},
		{
			name: "test sliding global policy [warn]",
			policy: []Policy{
				{
					PolicyScope: PolicyScopeGlobal,
					PolicyType:  types.PolicyTypeEol,
					WarnDays:    Int(60),
					DenyDays:    Int(30),
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
						Eol:          "2021-03-28",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.3",
					FailDate:    "2021-02-26",
				},
			},
		},
		{
			name: "test sliding global policy [deny, no warn]",
			policy: []Policy{
				{
					PolicyScope: PolicyScopeGlobal,
					PolicyType:  types.PolicyTypeEol,
					DenyDays:    Int(30),
				},
			},
			matches: []match.Match{
				{
					Cycle: eol.Cycle{
						ProductName:  "foo",
						ReleaseCycle: "1.3",
						Eol:          "2021-02-28",
					},
					Package: pkg.Package{
						ID:      pkg.ID(uuid.NewString()),
						Name:    "foo",
						Version: "1.3.0",
						Type:    syftPkg.RpmPkg,
					},
				},
			},
			want: []types.EolEvaluationResult{
				{
					Type:        types.PolicyTypeDeny,
					ProductName: "foo",
					Cycle:       "1.3",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeNow = func() time.Time {
				return time.Date(2021, 2, 1, 0, 0, 0, 0, time.UTC)
			}

			matches := match.NewMatches(tt.matches...)
			policyMatches := evaluateMatches(tt.policy, matches, "github//foo/bar")
			if len(policyMatches) != len(tt.want) {
				t.Errorf("expected %d policy matches, got %d", len(tt.want), len(policyMatches))
			}
			if !reflect.DeepEqual(policyMatches, tt.want) {
				t.Errorf("expected policy matches to be %v, got %v", tt.want, policyMatches)
			}
		})
	}
}

func TestByPolicyScope(t *testing.T) {
	policies := []Policy{
		{ID: "1", PolicyScope: PolicyScopeGlobal},
		{ID: "2", PolicyScope: PolicyScopeSoftware},
		{ID: "3", PolicyScope: PolicyScopeProject},
		{ID: "4", PolicyScope: PolicyScopeSoftware},
		{ID: "5", PolicyScope: PolicyScopeGlobal},
		{ID: "6", PolicyScope: PolicyScopeProject},
	}

	sort.Stable(ByPolicyScope(policies))

	expected := []Policy{
		{ID: "4", PolicyScope: PolicyScopeSoftware},
		{ID: "2", PolicyScope: PolicyScopeSoftware},
		{ID: "6", PolicyScope: PolicyScopeProject},
		{ID: "3", PolicyScope: PolicyScopeProject},
		{ID: "5", PolicyScope: PolicyScopeGlobal},
		{ID: "1", PolicyScope: PolicyScopeGlobal},
	}

	if !reflect.DeepEqual(policies, expected) {
		t.Errorf("Sorting failed. Expected %v but got %v", expected, policies)
	}
}
