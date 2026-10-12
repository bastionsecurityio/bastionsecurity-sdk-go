package bastion

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const DefaultEndpoint = "https://api.bastionsecurity.io"

type Client struct {
	SiteKey  string
	Secret   string
	Endpoint string
	HTTP     *http.Client
}

type Config struct {
	SiteKey  string
	Secret   string
	Endpoint string
}

func New(cfg Config) *Client {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &Client{
		SiteKey:  cfg.SiteKey,
		Secret:   cfg.Secret,
		Endpoint: endpoint,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

type ClassifyRequest struct {
	Token string `json:"token"`
}

type ClassifyResult struct {
	Verdict   string   `json:"verdict"`
	Score     int      `json:"score"`
	Signals   []string `json:"signals"`
	Action    string   `json:"action"`
	SessionID string   `json:"session_id"`
}

type TrackEvent struct {
	Event   string                 `json:"event"`
	Data    map[string]interface{} `json:"data"`
	SiteKey string                 `json:"site_key"`
	TS      int64                  `json:"ts"`
}

func (c *Client) Classify(token string) (*ClassifyResult, error) {
	body, _ := json.Marshal(ClassifyRequest{Token: token})
	req, err := http.NewRequest("POST", c.Endpoint+"/v1/classify", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bastion-Site-Key", c.SiteKey)
	req.Header.Set("X-Bastion-Signature", c.sign(body))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bastion: classify returned %d", resp.StatusCode)
	}

	var result ClassifyResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) Track(event string, data map[string]interface{}) error {
	payload := TrackEvent{
		Event:   event,
		Data:    data,
		SiteKey: c.SiteKey,
		TS:      time.Now().UnixMilli(),
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", c.Endpoint+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bastion-Site-Key", c.SiteKey)
	req.Header.Set("X-Bastion-Signature", c.sign(body))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("bastion: track returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) sign(data []byte) string {
	mac := hmac.New(sha256.New, []byte(c.Secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
