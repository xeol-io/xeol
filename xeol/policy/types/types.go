package types

type PolicyType string

const (
	PolicyTypeWarn EvaluationType = "WARN"
	PolicyTypeDeny EvaluationType = "DENY"

	PolicyTypeEol    PolicyType = "EOL"
	PolicyTypeNotary PolicyType = "NOTARY"
)

type EvaluationType string

type EolEvaluationResult struct {
	Type        EvaluationType
	ProductName string
	Cycle       string
	FailDate    string
}

type NotaryEvaluationResult struct {
	Type           EvaluationType
	ImageReference string
	FailDate       string
}

type PolicyEvaluationResult interface {
	GetType() EvaluationType
	GetFailDate() string
}

func (n NotaryEvaluationResult) GetType() EvaluationType {
	return n.Type
}

func (n NotaryEvaluationResult) GetFailDate() string {
	return n.FailDate
}

func (e EolEvaluationResult) GetType() EvaluationType {
	return e.Type
}

func (e EolEvaluationResult) GetFailDate() string {
	return e.FailDate
}
