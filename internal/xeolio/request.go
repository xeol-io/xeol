package xeolio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/match"
	"github.com/xeol-io/xeol/xeol/pkg"
)

type XeolEvent struct {
	URL     string
	ApiKey  string
	Payload XeolEventPayload
}

type XeolEventPayload struct {
	Matches   match.Matches
	Packages  []pkg.Package
	Context   pkg.Context
	AppConfig interface{}
}

func (x *XeolEvent) Send() error {
	payload, err := json.Marshal(x.Payload)
	if err != nil {
		return fmt.Errorf("error marshalling xeol.io API request: %v", err)
	}

	req, err := http.NewRequest("PUT", x.URL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %v", x.ApiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("xeol.io API request failed: %v", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xeol.io API unexpected status code %d", resp.StatusCode)
	}

	log.Debug("sent event to xeol.io API at %s", x.URL)
	return nil
}

func NewXeolEvent(url string, apiKey string, payload XeolEventPayload) *XeolEvent {
	return &XeolEvent{
		URL:     url,
		ApiKey:  apiKey,
		Payload: payload,
	}
}
