package types

type PolicyType string

const (
	PolicyActionWarn  PolicyAction = "WARN"
	PolicyActionDeny  PolicyAction = "DENY"
	PolicyActionAllow PolicyAction = "ALLOW"

	PolicyTypeEol    PolicyType = "EOL"
	PolicyTypeNotary PolicyType = "NOTARY"
)

type PolicyAction string

type EolEvaluationResult struct {
	Type        PolicyType
	Action      PolicyAction
	ProductName string
	Cycle       string
	FailDate    string
}

type NotaryEvaluationResult struct {
	Type           PolicyType
	Action         PolicyAction
	ImageReference string
	Verified       bool
	FailDate       string
}

type PolicyEvaluationResult interface {
	GetPolicyAction() PolicyAction
	GetPolicyType() PolicyType
	GetFailDate() string
	GetVerified() bool
}

func (n NotaryEvaluationResult) GetVerified() bool {
	return n.Verified
}

func (n NotaryEvaluationResult) GetPolicyAction() PolicyAction {
	return n.Action
}

func (n NotaryEvaluationResult) GetPolicyType() PolicyType {
	return n.Type
}

func (n NotaryEvaluationResult) GetFailDate() string {
	return n.FailDate
}

func (e EolEvaluationResult) GetVerified() bool {
	return false
}

func (e EolEvaluationResult) GetPolicyAction() PolicyAction {
	return e.Action
}

func (e EolEvaluationResult) GetPolicyType() PolicyType {
	return e.Type
}

func (e EolEvaluationResult) GetFailDate() string {
	return e.FailDate
}
