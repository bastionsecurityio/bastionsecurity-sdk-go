package bastion

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestContractAndRetry(t *testing.T) {
	calls := 0
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/antibot/verify" || r.Header.Get("X-Site-Key") != "public" || r.Header.Get("X-Secret-Key") != "private" {
			t.Error("incorrect route/auth")
		}
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		calls++
		if calls == 1 {
			w.WriteHeader(503)
			io.WriteString(w, `{"message":"retry"}`)
			return
		}
		io.WriteString(w, `{"success":true,"data":{"action":"block","risk_score":70,"signals":[{"rule":"card_testing","score":40,"description":"5 payment attempts"}]}}`)
	}))
	defer server.Close()
	client := New(Config{SiteKey: "public", Secret: "private", Endpoint: server.URL})
	result, err := client.Verify(context.Background(), ClassifyRequest{Context: ClassifyContext{EventType: "checkout", AccountID: "a"}, Environment: map[string]any{"nonce": "test"}})
	if err != nil || calls != 2 || bodies[0] != bodies[1] || result.Signals[0].Rule != "card_testing" {
		t.Fatalf("contract/retry failure: %v", err)
	}
	var body map[string]any
	json.Unmarshal([]byte(bodies[0]), &body)
	if body["idempotency_key"] == nil {
		t.Error("missing retry key")
	}
}
func TestAuthNoRetry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Invalid site keys"}`)
	}))
	defer server.Close()
	client := New(Config{SiteKey: "public", Secret: "wrong", Endpoint: server.URL})
	_, err := client.Verify(context.Background(), ClassifyRequest{})
	var failure *Error
	if !errors.As(err, &failure) || failure.Status != 401 || calls != 1 {
		t.Fatalf("bad auth handling: %v", err)
	}
}
func TestWebhook(t *testing.T) {
	payload := []byte(`{"text":"fraud 🚨"}`)
	now := time.Unix(12345, 0)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("12345."))
	mac.Write(payload)
	sig := "t=12345,v1=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifyWebhook("secret", payload, sig, 300*time.Second, now) || VerifyWebhook("secret", append(payload, ' '), sig, 300*time.Second, now) || VerifyWebhook("secret", payload, sig, 300*time.Second, now.Add(301*time.Second)) {
		t.Fatal("webhook validation failed")
	}
}
