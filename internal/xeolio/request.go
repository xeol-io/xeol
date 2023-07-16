package xeolio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xeol-io/xeol/internal/log"
	"github.com/xeol-io/xeol/xeol/report"
)

type PolicyType string
type CycleOperator string

const (
	XeolAPIURL    = "https://api.xeol.io"
	XeolEngineURL = "https://engine.xeol.io"

	PolicyTypeEol PolicyType = "EOL"

	CycleOperatorLessThan        CycleOperator = "LT"
	CycleOperatorLessThanOrEqual CycleOperator = "LTE"
	CycleOperatorEqual           CycleOperator = "EQ"
)

type Policy struct {
	ID            string        `json:"id"`
	PolicyType    PolicyType    `json:"policy_type"`
	WarnDate      string        `json:"warn_date"`
	DenyDate      string        `json:"deny_date"`
	ProductName   string        `json:"product_name"`
	Cycle         string        `json:"cycle"`
	CycleOperator CycleOperator `json:"cycle_operator"`
}

func (pt *PolicyType) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), "\"")
	if str != string(PolicyTypeEol) {
		return fmt.Errorf("invalid PolicyType %s", str)
	}
	*pt = PolicyType(str)
	return nil
}

func (co *CycleOperator) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), "\"")
	switch str {
	case string(CycleOperatorLessThan), string(CycleOperatorLessThanOrEqual), string(CycleOperatorEqual):
		*co = CycleOperator(str)
	default:
		return fmt.Errorf("invalid CycleOperator %s", str)
	}
	return nil
}

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
		log.Debug("sent event to xeol.io API at %s", req.URL.String())
	}

	return nil
}

func (x *XeolClient) FetchPolicies() ([]Policy, error) {
	var policies []Policy
	err := x.makeRequest("GET", XeolAPIURL, "v1/policy", nil, &policies)
	if err != nil {
		return nil, err
	}

	return policies, nil
}

func (x *XeolClient) SendEvent(payload report.XeolEventPayload) error {
	p, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling xeol.io API request: %v", err)
	}

	return x.makeRequest("PUT", XeolEngineURL, "v1/scan", bytes.NewBuffer(p), nil)
}
