package policy

import (
	"reflect"
	"testing"
	"time"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/google/uuid"

	"github.com/xeol-io/xeol/internal/xeolio"
	"github.com/xeol-io/xeol/xeol/eol"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name    string
		policy  []xeolio.Policy
		matches []match.Match
		want    []EvaluationResult
	}{
		{
			name: "policy with no matches",
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0.0",
					CycleOperator: xeolio.CycleOperatorLessThan,
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
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					CycleOperator: xeolio.CycleOperatorLessThanOrEqual,
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
			want: []EvaluationResult{
				{
					Type:        PolicyTypeDeny,
					ProductName: "foo",
					Cycle:       "1.0",
				},
			},
		},
		{
			name: "policy with warn match, version less than equal",
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					CycleOperator: xeolio.CycleOperatorLessThanOrEqual,
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
			want: []EvaluationResult{
				{
					Type:        PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.0",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "policy with warn match, version less than",
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					CycleOperator: xeolio.CycleOperatorLessThan,
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
			want: []EvaluationResult{
				{
					Type:        PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "0.9",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "policy with warn match, version equal",
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.0",
					CycleOperator: xeolio.CycleOperatorEqual,
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
			want: []EvaluationResult{
				{
					Type:        PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.0",
					FailDate:    "2021-03-01",
				},
			},
		},
		{
			name: "test multiple policy matches",
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.3",
					CycleOperator: xeolio.CycleOperatorEqual,
					WarnDate:      "2021-01-01",
					DenyDate:      "2021-03-01",
				},
				{
					ProductName:   "bar",
					Cycle:         "2.1",
					CycleOperator: xeolio.CycleOperatorLessThanOrEqual,
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
			want: []EvaluationResult{
				{
					Type:        PolicyTypeWarn,
					ProductName: "foo",
					Cycle:       "1.3",
					FailDate:    "2021-03-01",
				},
				{
					Type:        PolicyTypeDeny,
					ProductName: "bar",
					Cycle:       "2.0",
				},
			},
		},
		{
			name: "test bad dates",
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.3",
					CycleOperator: xeolio.CycleOperatorEqual,
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
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.4",
					CycleOperator: xeolio.CycleOperatorEqual,
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
			policy: []xeolio.Policy{
				{
					ProductName:   "foo",
					Cycle:         "1.3",
					CycleOperator: xeolio.CycleOperatorEqual,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeNow = func() time.Time {
				return time.Date(2021, 2, 1, 0, 0, 0, 0, time.UTC)
			}

			matches := match.NewMatches(tt.matches...)
			policyMatches := evaluateMatches(tt.policy, matches)
			if len(policyMatches) != len(tt.want) {
				t.Errorf("expected %d policy matches, got %d", len(tt.want), len(policyMatches))
			}
			if !reflect.DeepEqual(policyMatches, tt.want) {
				t.Errorf("expected policy matches to be %v, got %v", tt.want, policyMatches)
			}
		})
	}
}
