package bus

import (
	partybus "github.com/wagoodman/go-partybus"

	"github.com/xeol-io/xeol/xeol/event"
)

func Exit() {
	Publish(partybus.Event{
		Type: event.CLIExit,
	})
}

func Report(report string) {
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: report,
	})
}

func Notify(message string) {
	Publish(partybus.Event{
		Type:  event.CLINotification,
		Value: message,
	})
}
