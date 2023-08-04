package policy

import (
	"encoding/json"
	"fmt"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/policy/eol"
	"github.com/xeol-io/xeol/xeol/policy/notary"
	"github.com/xeol-io/xeol/xeol/policy/types"
)

type Policy interface {
	Evaluate(match.Matches, string, string) (bool, types.PolicyEvaluationResult)
	GetPolicyType() types.PolicyType
}

func UnmarshalPolicies(data []byte) ([]Policy, error) {
	var rawPolicies []map[string]json.RawMessage

	if err := json.Unmarshal(data, &rawPolicies); err != nil {
		return nil, err
	}

	var policies []Policy
	for _, rawPolicy := range rawPolicies {
		var policyType string
		if err := json.Unmarshal(rawPolicy["PolicyType"], &policyType); err != nil {
			return nil, err
		}

		switch policyType {
		case "EOL":
			var container eol.PolicyWrapper
			rawJSON, err := json.Marshal(rawPolicy)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(rawJSON, &container); err != nil {
				return nil, err
			}
			policies = append(policies, container)
		case "NOTARY":
			var container notary.PolicyWrapper
			rawJSON, err := json.Marshal(rawPolicy)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(rawJSON, &container); err != nil {
				return nil, err
			}
			policies = append(policies, container)
		default:
			return nil, fmt.Errorf("unknown policy type: %s", policyType)
		}
	}

	return policies, nil
}
