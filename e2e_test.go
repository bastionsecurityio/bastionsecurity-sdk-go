package bastion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestRealPlatform(t *testing.T) {
	path := os.Getenv("BASTION_QA_SESSION")
	if path == "" {
		t.Skip("Set BASTION_QA_SESSION to an isolated local QA session")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Endpoint string `json:"endpoint"`
		SiteKey  string `json:"site_key"`
		Secret   string `json:"secret"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.Endpoint, "http://localhost:") && !strings.HasPrefix(cfg.Endpoint, "http://127.0.0.1:") {
		t.Fatal("Local QA only")
	}
	ctx := context.Background()
	client := New(Config{SiteKey: cfg.SiteKey, Secret: cfg.Secret, Endpoint: cfg.Endpoint})
	fp, err := client.Fingerprint(ctx, map[string]any{"canvas_hash": "go-sdk-e2e", "platform": "MacIntel", "user_agent": "Mozilla/5.0 Chrome/130.0", "language": "en-US", "languages": []string{"en-US"}}, nil)
	if err != nil || fp.Token == "" || fp.ExpiresAt.IsZero() {
		t.Fatalf("fingerprint: %v", err)
	}
	failed := false
	request := ClassifyRequest{Token: fp.Token, Context: ClassifyContext{EventType: "login", AccountID: "go-sdk-e2e", LoginSucceeded: &failed}, IdempotencyKey: newKey()}
	first, err := client.Verify(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.Verify(ctx, request)
	if err != nil || again.RequestID != first.RequestID || first.Signals == nil {
		t.Fatalf("scoring/dedupe: %v", err)
	}
	if _, err = client.Classify(fp.Token, ClassifyContext{EventType: "signup", AccountID: "go-sdk-classify"}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Track(ctx, "checkout", ClassifyContext{AccountID: "go-sdk-track", OrderAmount: 4, PaymentHash: "go-test-card"}, fp.Token); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = newKey()
	batch, err := client.Batch(ctx, []ClassifyRequest{request, {Context: ClassifyContext{EventType: "unsupported", AccountID: "invalid"}}})
	if err != nil || batch.Accepted != 1 || batch.Results[1].Status != 400 {
		t.Fatalf("batch: %v", err)
	}
	bad := New(Config{SiteKey: cfg.SiteKey, Secret: "wrong", Endpoint: cfg.Endpoint})
	_, err = bad.Verify(ctx, request)
	var failure *Error
	if !errors.As(err, &failure) || failure.Status != 401 {
		t.Fatalf("auth: %v", err)
	}
	challenge, err := client.CreateChallenge(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	var nonce int64
	for {
		hash := sha256.Sum256([]byte(challenge.Prefix + strconv.FormatInt(nonce, 36)))
		if strings.HasPrefix(hex.EncodeToString(hash[:]), strings.Repeat("0", challenge.Difficulty)) {
			break
		}
		nonce++
	}
	verified, err := client.VerifyChallenge(ctx, challenge.ChallengeID, strconv.FormatInt(nonce, 36))
	if err != nil || !verified.Valid {
		t.Fatalf("proof: %v", err)
	}
	_, err = client.VerifyChallenge(ctx, challenge.ChallengeID, strconv.FormatInt(nonce, 36))
	if !errors.As(err, &failure) || failure.Status != 400 {
		t.Fatalf("replay: %v", err)
	}
}
