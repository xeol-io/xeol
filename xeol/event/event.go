package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable             partybus.EventType = "xeol-app-update-available"
	UpdateEolDatabase              partybus.EventType = "xeol-update-eol-database"
	EolScanningStarted             partybus.EventType = "xeol-eol-scanning-started"
	EolScanningFinished            partybus.EventType = "xeol-eol-scanning-finished"
	PolicyEvaluationMessage        partybus.EventType = "xeol-policy-evaluation-message"
	AttestationVerified            partybus.EventType = "xeol-attestation-signature-passed"
	AttestationVerificationSkipped partybus.EventType = "xeol-attestation-verification-skipped"
	NonRootCommandFinished         partybus.EventType = "xeol-non-root-command-finished"
)
