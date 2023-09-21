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
	XeolAPIURL = "https://api.xeol.io"
)

type XeolClient struct {
	APIKey string
}

func NewXeolClient(apiKey string) *XeolClient {
	return &XeolClient{
		APIKey: apiKey,
	}
}

func (x *XeolClient) makeRequest(method, url, path string, body io.Reader, out interface{}) (int, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/%s", url, path), body)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %v", x.APIKey))

	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("xeol.io API request failed: %v", err)
	}
	defer resp.Body.Close()

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("xeol.io API response decode failed: %v", err)
		}
	} else {
		log.Debugf("sent event to xeol.io API at %s", req.URL.String())
	}

	return resp.StatusCode, nil
}

func (x *XeolClient) FetchCertificates() (string, error) {
	type CertificateResponse struct {
		Certificate string `json:"certificate"`
	}

	var raw json.RawMessage
	statusCode, err := x.makeRequest("GET", XeolAPIURL, "certificate", nil, &raw)
	if err != nil {
		log.Warnf("failed to fetch certificates, continuing without notary policy evaluation")
		return "", nil
	}

	if statusCode == http.StatusNotFound {
		log.Warnf("no certificates found in xeol.io API response")
		return "", nil
	}

	var resp CertificateResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		log.Warnf("failed to unmarshal certificates, continuing without notary policy evaluation")
		return "", nil
	}

	return resp.Certificate, nil
}

func (x *XeolClient) FetchPolicies() ([]policy.Policy, error) {
	var raw json.RawMessage
	statusCode, err := x.makeRequest("GET", XeolAPIURL, "v2/policy", nil, &raw)
	if err != nil {
		log.Warnf("failed to fetch policies, continuing without policy evaluation")
		return nil, nil
	}

	if statusCode == http.StatusNotFound {
		log.Warnf("no policies found in xeol.io API response")
		return nil, nil
	}

	policies, err := policy.UnmarshalPolicies(raw)
	if err != nil {
		log.Warnf("failed to unmarshal policies, continuing without policy evaluation")
		return nil, nil
	}
	return policies, nil
}

func (x *XeolClient) SendEvent(payload report.XeolEventPayload) error {
	p, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling xeol.io API request: %v", err)
	}

	_, err = x.makeRequest("PUT", XeolAPIURL, "v2/scan", bytes.NewBuffer(p), nil)
	return err
}
