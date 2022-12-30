package event

import "github.com/wagoodman/go-partybus"

const (
	AppUpdateAvailable     partybus.EventType = "xeol-app-update-available"
	UpdateEolDatabase      partybus.EventType = "xeol-update-eol-database"
	EolScanningStarted     partybus.EventType = "xeol-eol-scanning-started"
	EolScanningFinished    partybus.EventType = "xeol-eol-scanning-finished"
	NonRootCommandFinished partybus.EventType = "xeol-non-root-command-finished"
)
