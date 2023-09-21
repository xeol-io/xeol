package parsers

import (
	"fmt"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/xeol-io/xeol/xeol/event"
	"github.com/xeol-io/xeol/xeol/event/monitor"
	policyTypes "github.com/xeol-io/xeol/xeol/policy/types"
	"github.com/xeol-io/xeol/xeol/presenter"
)

type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field='%v': '%+v'", string(e.Type), e.Field, e.Value)
}

type UpdateCheck struct {
	New     string
	Current string
}

func ParseCLIAppUpdateAvailable(e partybus.Event) (*UpdateCheck, error) {
	if err := checkEventType(e.Type, event.CLIAppUpdateAvailable); err != nil {
		return nil, err
	}

	updateCheck, ok := e.Value.(UpdateCheck)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &updateCheck, nil
}

func newPayloadErr(t partybus.EventType, field string, value interface{}) error {
	return &ErrBadPayload{
		Type:  t,
		Field: field,
		Value: value,
	}
}

func checkEventType(actual, expected partybus.EventType) error {
	if actual != expected {
		return newPayloadErr(expected, "Type", actual)
	}
	return nil
}

func ParseNotaryPolicyEvaluationMessage(e partybus.Event) (*policyTypes.NotaryEvaluationResult, error) {
	if err := checkEventType(e.Type, event.NotaryPolicyEvaluationMessage); err != nil {
		return nil, err
	}

	pt, ok := e.Value.(policyTypes.NotaryEvaluationResult)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}
	return &pt, nil
}

func ParseEolPolicyEvaluationMessage(e partybus.Event) (*policyTypes.EolEvaluationResult, error) {
	if err := checkEventType(e.Type, event.EolPolicyEvaluationMessage); err != nil {
		return nil, err
	}

	pt, ok := e.Value.(policyTypes.EolEvaluationResult)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}
	return &pt, nil
}
func ParseEolScanningStarted(e partybus.Event) (*monitor.Matching, error) {
	if err := checkEventType(e.Type, event.EolScanningStarted); err != nil {
		return nil, err
	}

	monitor, ok := e.Value.(monitor.Matching)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return &monitor, nil
}

func ParseCLIReport(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLIReport); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	report, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, report, nil
}

func ParseEolScanningFinished(e partybus.Event) (presenter.Presenter, error) {
	if err := checkEventType(e.Type, event.EolScanningFinished); err != nil {
		return nil, err
	}

	pres, ok := e.Value.(presenter.Presenter)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return pres, nil
}

func ParseCLINotification(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, event.CLINotification); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	notification, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, notification, nil
}

func ParseUpdateEolDatabase(e partybus.Event) (progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, event.UpdateEolDatabase); err != nil {
		return nil, err
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return prog, nil
}
