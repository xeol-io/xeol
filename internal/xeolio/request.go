package xeolio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/report"
)

type XeolEvent struct {
	URL     string
	APIKey  string
	Payload report.XeolEventPayload
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
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %v", x.APIKey))

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
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

func NewXeolEvent(url string, apiKey string, payload report.XeolEventPayload) *XeolEvent {
	return &XeolEvent{
		URL:     url,
		APIKey:  apiKey,
		Payload: payload,
	}
}
