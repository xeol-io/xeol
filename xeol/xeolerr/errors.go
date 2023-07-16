package xeolerr

var (
	// ErrEolFound indicates when an EOL package is found and --fail-on-eol-found is set
	ErrEolFound = NewExpectedErr("discovered EOL packages")
	// ErrPolicyViolation indicates when a policy violation has occurred
	ErrPolicyViolation = NewExpectedErr("policy violation")
)
