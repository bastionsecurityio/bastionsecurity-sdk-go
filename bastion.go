// Package bastion provides authenticated server-side scoring and webhook verification.
package bastion

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultEndpoint = "https://api.bastionsecurity.io/api/antibot"

type Config struct {
	SiteKey, Secret, Endpoint string
	Timeout                   time.Duration
	Retries                   int
}
type Client struct {
	SiteKey, Secret, Endpoint string
	HTTP                      *http.Client
	Retries                   int
}

func New(cfg Config) *Client {
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if parsed, err := url.Parse(endpoint); err == nil {
		if parsed.Path == "" {
			endpoint += "/api/antibot"
		} else if parsed.Path == "/api" {
			endpoint += "/antibot"
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	retries := cfg.Retries
	if retries == 0 {
		retries = 2
	}
	if retries < 0 {
		retries = 0
	}
	if retries > 3 {
		retries = 3
	}
	return &Client{SiteKey: cfg.SiteKey, Secret: cfg.Secret, Endpoint: endpoint, HTTP: &http.Client{Timeout: timeout}, Retries: retries}
}

type Error struct {
	Status   int
	Message  string
	Response json.RawMessage
	Cause    error
}

func (e *Error) Error() string { return fmt.Sprintf("bastion: %s (status %d)", e.Message, e.Status) }
func (e *Error) Unwrap() error { return e.Cause }

type ClassifyContext struct {
	EventType      string  `json:"event_type"`
	AccountID      string  `json:"account_id"`
	Email          string  `json:"email,omitempty"`
	IPAddress      string  `json:"ip_address,omitempty"`
	UserAgent      string  `json:"user_agent,omitempty"`
	PaymentHash    string  `json:"payment_hash,omitempty"`
	PromoCode      string  `json:"promo_code,omitempty"`
	OrderAmount    float64 `json:"order_amount,omitempty"`
	RequestURL     string  `json:"request_url,omitempty"`
	LoginSucceeded *bool   `json:"login_succeeded,omitempty"`
}
type ClassifyRequest struct {
	BrowserReceipt string            `json:"browser_receipt,omitempty"`
	Token          string            `json:"token,omitempty"`
	Context        ClassifyContext   `json:"context"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	Fingerprint    map[string]any    `json:"fingerprint,omitempty"`
	Behavior       map[string]any    `json:"behavior,omitempty"`
	Environment    map[string]any    `json:"environment,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Username       string            `json:"username,omitempty"`
}
type Signal struct {
	Rule        string `json:"rule"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}
type Identity struct {
	ClusterID      string `json:"cluster_id"`
	LinkedAccounts int    `json:"linked_accounts"`
	SharedDevices  int    `json:"shared_devices"`
	SharedIPs      int    `json:"shared_ips"`
	SharedPayments int    `json:"shared_payments"`
}
type Challenge struct {
	ChallengeID string    `json:"challenge_id"`
	Prefix      string    `json:"prefix"`
	Difficulty  int       `json:"difficulty"`
	ExpiresAt   time.Time `json:"expires_at"`
}
type BrowserEvidence struct {
	Active            bool   `json:"active"`
	Mode              string `json:"mode"`
	Status            string `json:"status"`
	Encrypted         bool   `json:"encrypted"`
	Interacted        bool   `json:"interacted"`
	NeedsVerification bool   `json:"needsVerification"`
}
type ClassifyResult struct {
	BrowserEvidence *BrowserEvidence `json:"browser_evidence,omitempty"`
	Classification  string           `json:"classification"`
	RiskScore       int              `json:"risk_score"`
	RiskLevel       string           `json:"risk_level"`
	Signals         []Signal         `json:"signals"`
	Action          string           `json:"action"`
	RequestID       string           `json:"request_id"`
	DeviceID        string           `json:"device_id"`
	Identity        *Identity        `json:"identity,omitempty"`
	Challenge       *Challenge       `json:"challenge,omitempty"`
	DecisionMs      float64          `json:"decision_ms"`
	Timestamp       time.Time        `json:"timestamp"`
}
type FingerprintResult struct {
	Token         string    `json:"token"`
	DeviceID      string    `json:"device_id"`
	ExpiresAt     time.Time `json:"expires_at"`
	SpoofingScore float64   `json:"spoofing_score"`
	Timestamp     time.Time `json:"timestamp"`
}
type ChallengeResult struct {
	Valid bool `json:"valid"`
}
type BatchItem struct {
	Index    int             `json:"index"`
	Success  bool            `json:"success"`
	Decision *ClassifyResult `json:"decision,omitempty"`
	Status   int             `json:"status,omitempty"`
	Message  string          `json:"message,omitempty"`
}
type BatchResult struct {
	Accepted int         `json:"accepted"`
	Results  []BatchItem `json:"results"`
}

func newKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func (c *Client) Verify(ctx context.Context, request ClassifyRequest) (*ClassifyResult, error) {
	if request.IdempotencyKey == "" {
		request.IdempotencyKey = newKey()
	}
	var result ClassifyResult
	err := c.post(ctx, "/verify", request, &result, true)
	return &result, err
}
func (c *Client) Classify(token string, contexts ...ClassifyContext) (*ClassifyResult, error) {
	if len(contexts) != 1 {
		return nil, errors.New("bastion: an event_type and account_id context is required")
	}
	return c.Verify(context.Background(), ClassifyRequest{Token: token, Context: contexts[0]})
}
func (c *Client) Track(ctx context.Context, event string, data ClassifyContext, token string) (*ClassifyResult, error) {
	data.EventType = event
	return c.Verify(ctx, ClassifyRequest{Token: token, Context: data})
}
func (c *Client) Fingerprint(ctx context.Context, fingerprint, behavior map[string]any) (*FingerprintResult, error) {
	var result FingerprintResult
	err := c.post(ctx, "/verify/fingerprint", map[string]any{"fingerprint": fingerprint, "behavior": behavior}, &result, false)
	return &result, err
}
func (c *Client) Batch(ctx context.Context, events []ClassifyRequest) (*BatchResult, error) {
	batch := append([]ClassifyRequest(nil), events...)
	for i := range batch {
		if batch[i].IdempotencyKey == "" {
			batch[i].IdempotencyKey = newKey()
		}
	}
	var result BatchResult
	err := c.post(ctx, "/verify/batch", map[string]any{"events": batch}, &result, true)
	return &result, err
}
func (c *Client) CreateChallenge(ctx context.Context, difficulty int) (*Challenge, error) {
	var result Challenge
	err := c.post(ctx, "/verify/challenge", map[string]int{"difficulty": difficulty}, &result, false)
	return &result, err
}
func (c *Client) VerifyChallenge(ctx context.Context, challengeID, nonce string) (*ChallengeResult, error) {
	var result ChallengeResult
	err := c.post(ctx, "/verify/challenge/verify", map[string]string{"challenge_id": challengeID, "nonce": nonce}, &result, false)
	return &result, err
}
func (c *Client) post(ctx context.Context, path string, value, out any, safe bool) error {
	parsed, err := url.Parse(c.Endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")) {
		return errors.New("bastion: HTTPS required except on localhost")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || c.SiteKey == "" || c.Secret == "" || strings.ContainsAny(c.SiteKey+c.Secret, "\r\n") {
		return errors.New("bastion: invalid endpoint or credentials")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Site-Key", c.SiteKey)
		req.Header.Set("X-Secret-Key", c.Secret)
		resp, err := client.Do(req)
		var failure *Error
		if err != nil {
			failure = &Error{Message: "API request could not reach the server", Cause: err}
		} else {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if readErr != nil {
				failure = &Error{Message: "Could not read API response", Status: resp.StatusCode, Cause: readErr}
			} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				var api struct {
					Message string `json:"message"`
				}
				_ = json.Unmarshal(raw, &api)
				if api.Message == "" {
					api.Message = "API request failed"
				}
				failure = &Error{Status: resp.StatusCode, Message: api.Message, Response: raw}
			} else {
				var envelope struct {
					Data    json.RawMessage `json:"data"`
					Success *bool           `json:"success"`
				}
				if err = json.Unmarshal(raw, &envelope); err != nil || (envelope.Success != nil && !*envelope.Success) {
					return &Error{Status: resp.StatusCode, Message: "Invalid API JSON response", Cause: err}
				}
				if len(envelope.Data) > 0 {
					raw = envelope.Data
				}
				if string(raw) == "null" {
					return &Error{Status: resp.StatusCode, Message: "Invalid API response"}
				}
				if err = json.Unmarshal(raw, out); err != nil {
					return &Error{Status: resp.StatusCode, Message: "Invalid decision response", Cause: err}
				}
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !safe || attempt >= c.Retries || (failure.Status > 0 && failure.Status != 429 && failure.Status < 500) {
			return failure
		}
		timer := time.NewTimer(time.Duration(250*(1<<attempt)) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

var stampPattern = regexp.MustCompile(`^t=([0-9]+)$`)
var signaturePattern = regexp.MustCompile(`^v1=([0-9a-f]{64})$`)

// VerifyWebhook accepts the exact raw request body; reject stale signatures and tampering.
func VerifyWebhook(secret string, rawBody []byte, signature string, tolerance time.Duration, now time.Time) bool {
	if secret == "" || tolerance < 0 {
		return false
	}
	parts := strings.Split(signature, ",")
	var stamp string
	for _, part := range parts {
		if match := stampPattern.FindStringSubmatch(strings.TrimSpace(part)); match != nil {
			stamp = match[1]
			break
		}
	}
	timestamp, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return false
	}
	delta := now.Unix() - timestamp
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(tolerance/time.Second) {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stamp + "."))
	mac.Write(rawBody)
	expected := mac.Sum(nil)
	for _, part := range parts {
		if match := signaturePattern.FindStringSubmatch(strings.TrimSpace(part)); match != nil {
			given, err := hex.DecodeString(match[1])
			if err == nil && hmac.Equal(expected, given) {
				return true
			}
		}
	}
	return false
}
