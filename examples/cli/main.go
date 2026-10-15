package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	bastion "github.com/bastionsecurityio/sdk-go"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

func readJSON(file string, out any) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
func required(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}
func run() (any, int, error) {
	args := os.Args[1:]
	if len(args) == 0 {
		return nil, 1, errors.New("usage: verify telemetry.json order.json | batch requests.json | challenge | webhook raw-body.json signature.txt")
	}
	if args[0] == "webhook" {
		if len(args) != 3 {
			return nil, 1, errors.New("usage: webhook raw-body.json signature.txt")
		}
		secret, err := required("BASTION_WEBHOOK_SECRET")
		if err != nil {
			return nil, 1, err
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return nil, 1, err
		}
		signature, err := os.ReadFile(args[2])
		if err != nil {
			return nil, 1, err
		}
		if !bastion.VerifyWebhook(secret, raw, strings.TrimSpace(string(signature)), 5*time.Minute, time.Now()) {
			return nil, 1, errors.New("invalid or stale webhook signature")
		}
		var event any
		if err = json.Unmarshal(raw, &event); err != nil {
			return nil, 1, err
		}
		return map[string]any{"verified": true, "event": event}, 0, nil
	}
	if args[0] != "verify" && args[0] != "batch" && args[0] != "challenge" {
		return nil, 1, errors.New("unknown example command")
	}
	site, err := required("BASTION_SITE_KEY")
	if err != nil {
		return nil, 1, err
	}
	secret, err := required("BASTION_SECRET_KEY")
	if err != nil {
		return nil, 1, err
	}
	client := bastion.New(bastion.Config{SiteKey: site, Secret: secret, Endpoint: os.Getenv("BASTION_ENDPOINT")})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch args[0] {
	case "verify":
		if len(args) != 3 {
			return nil, 1, errors.New("usage: verify telemetry.json order.json")
		}
		var telemetry bastion.ClassifyRequest
		if err := readJSON(args[1], &telemetry); err != nil {
			return nil, 1, err
		}
		var order struct {
			CustomerID string   `json:"customerId"`
			Amount     *float64 `json:"amount"`
			PaymentID  string   `json:"paymentId"`
		}
		if err := readJSON(args[2], &order); err != nil {
			return nil, 1, err
		}
		if (telemetry.BrowserReceipt == "" && (telemetry.Token == "" || len(telemetry.Fingerprint) == 0)) || telemetry.IdempotencyKey == "" {
			return nil, 1, errors.New("complete buildRequest() telemetry with a stable idempotency_key is required")
		}
		if order.CustomerID == "" || order.PaymentID == "" || order.Amount == nil || math.IsNaN(*order.Amount) || math.IsInf(*order.Amount, 0) || *order.Amount < 0 {
			return nil, 1, errors.New("trusted order needs customerId, paymentId, and a finite nonnegative amount")
		}
		request := bastion.ClassifyRequest{BrowserReceipt: telemetry.BrowserReceipt, Token: telemetry.Token, Fingerprint: telemetry.Fingerprint, Behavior: telemetry.Behavior, Environment: telemetry.Environment, IdempotencyKey: telemetry.IdempotencyKey, Context: bastion.ClassifyContext{EventType: "checkout", AccountID: order.CustomerID, OrderAmount: *order.Amount, PaymentHash: order.PaymentID}}
		decision, err := client.Verify(ctx, request)
		if err != nil {
			return nil, 1, err
		}
		return map[string]any{"allowed": decision.Action == "allow", "decision": decision}, 0, nil
	case "batch":
		if len(args) != 2 {
			return nil, 1, errors.New("usage: batch requests.json")
		}
		var requests []bastion.ClassifyRequest
		if err := readJSON(args[1], &requests); err != nil {
			return nil, 1, err
		}
		if len(requests) < 1 || len(requests) > 50 {
			return nil, 1, errors.New("batch needs 1–50 server-owned requests")
		}
		for _, request := range requests {
			if request.IdempotencyKey == "" {
				return nil, 1, errors.New("every batch item requires a stable idempotency_key")
			}
		}
		result, err := client.Batch(ctx, requests)
		if err != nil {
			return nil, 1, err
		}
		items := make([]map[string]any, 0, len(result.Results))
		status := 0
		for _, item := range result.Results {
			items = append(items, map[string]any{"index": item.Index, "success": item.Success, "decision": item.Decision, "status": item.Status, "message": item.Message, "allowed": item.Success && item.Decision != nil && item.Decision.Action == "allow"})
			if !item.Success {
				status = 2
			}
		}
		return map[string]any{"accepted": result.Accepted, "results": items}, status, nil
	case "challenge":
		challenge, err := client.CreateChallenge(ctx, 4)
		if err != nil {
			return nil, 1, err
		}
		var nonce int64
		for {
			select {
			case <-ctx.Done():
				return nil, 1, ctx.Err()
			default:
			}
			if time.Now().After(challenge.ExpiresAt) {
				return nil, 1, errors.New("challenge expired")
			}
			digest := sha256.Sum256([]byte(challenge.Prefix + strconv.FormatInt(nonce, 36)))
			if strings.HasPrefix(hex.EncodeToString(digest[:]), strings.Repeat("0", challenge.Difficulty)) {
				break
			}
			nonce++
		}
		result, err := client.VerifyChallenge(ctx, challenge.ChallengeID, strconv.FormatInt(nonce, 36))
		if err != nil {
			return nil, 1, err
		}
		if !result.Valid {
			return nil, 1, errors.New("proof was rejected")
		}
		return map[string]any{"valid": true, "fulfillment_authorized": false}, 0, nil
	}
	return nil, 1, errors.New("unknown command")
}
func main() {
	output, status, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Example failed:", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(status)
}
