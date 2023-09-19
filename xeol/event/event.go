package event

import (
	"github.com/wagoodman/go-partybus"
)

const (
	typePrefix    = "xeol"
	cliTypePrefix = typePrefix + "-cli"

	// Events from the xeol library

	UpdateEolDatabase             partybus.EventType = typePrefix + "-update-eol-database"
	EolScanningStarted            partybus.EventType = typePrefix + "-eol-scanning-started"
	EolScanningFinished           partybus.EventType = typePrefix + "-eol-scanning-finished"
	EolPolicyEvaluationMessage    partybus.EventType = typePrefix + "-eol-policy-evaluation-message"
	NotaryPolicyEvaluationMessage partybus.EventType = typePrefix + "-notary-policy-evaluation-message"
	DatabaseDiffingStarted        partybus.EventType = typePrefix + "-database-diffing-started"

	// Events exclusively for the CLI

	// CLIAppUpdateAvailable is a partybus event that occurs when an application update is available
	CLIAppUpdateAvailable partybus.EventType = cliTypePrefix + "-app-update-available"

	// CLIReport is a partybus event that occurs when an analysis result is ready for final presentation to stdout
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLINotification is a partybus event that occurs when auxiliary information is ready for presentation to stderr
	CLINotification partybus.EventType = cliTypePrefix + "-notification"

	// CLIExit is a partybus event that occurs when an analysis result is ready for final presentation
	CLIExit partybus.EventType = cliTypePrefix + "-exit-event"
)
