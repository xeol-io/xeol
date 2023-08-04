package xeolio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/policy"
	"github.com/xeol-io/xeol/xeol/report"
)

const (
	XeolAPIURL    = "https://e885b265e7f6.ngrok.app"
	XeolEngineURL = "https://e885b265e7f6.ngrok.app"
)

type XeolClient struct {
	APIKey string
}

func NewXeolClient(apiKey string) *XeolClient {
	return &XeolClient{
		APIKey: apiKey,
	}
}

func (x *XeolClient) makeRequest(method, url, path string, body io.Reader, out interface{}) error {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/%s", url, path), body)
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

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("xeol.io API response decode failed: %v", err)
		}
	} else {
		log.Debugf("sent event to xeol.io API at %s", req.URL.String())
	}

	return nil
}

func (x *XeolClient) FetchPolicies() ([]policy.Policy, error) {
	var raw json.RawMessage
	err := x.makeRequest("GET", XeolAPIURL, "v2/policy", nil, &raw)
	if err != nil {
		return nil, err
	}

	return policy.UnmarshalPolicies(raw)
}

func (x *XeolClient) SendEvent(payload report.XeolEventPayload) error {
	p, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling xeol.io API request: %v", err)
	}

	return x.makeRequest("PUT", XeolEngineURL, "v1/scan", bytes.NewBuffer(p), nil)
}
