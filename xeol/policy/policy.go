package policy

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/policy/eol"
	"github.com/xeol-io/xeol/xeol/policy/notary"
)

type Policy interface {
	Evaluate(match.Matches, string, string) bool
}

func UnmarshalPolicy(data []byte) (Policy, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	policyType, ok := raw["PolicyType"].(string)
	if !ok {
		return nil, errors.New("missing or incorrect type for PolicyType")
	}

	switch policyType {
	case "EOL":
		var container eol.PolicyType
		if err := json.Unmarshal(data, &container); err != nil {
			return nil, err
		}
		return container, nil
	case "NOTARY":
		var container notary.PolicyType
		if err := json.Unmarshal(data, &container); err != nil {
			return nil, err
		}
		return container, nil
	default:
		return nil, fmt.Errorf("unknown policy type: %s", policyType)
	}
}
