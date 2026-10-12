# Bastion Security Go SDK

Official Go SDK for [Bastion Security](https://bastionsecurity.io) — real-time bot detection and fraud prevention.

## Installation

```bash
go get github.com/bastionsecurityio/sdk-go
```

## Usage

```go
package main

import (
    "fmt"
    "log"

    bastion "github.com/bastionsecurityio/sdk-go"
)

func main() {
    client := bastion.New(bastion.Config{
        SiteKey: "pk_live_your_site_key",
        Secret:  "sk_live_your_secret_key",
    })

    // Classify a token from the frontend SDK
    result, err := client.Classify("token-from-frontend")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Verdict: %s, Score: %d\n", result.Verdict, result.Score)

    // Track a server-side event
    err = client.Track("purchase", map[string]interface{}{
        "amount": 49.99,
        "user_id": "usr_123",
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

## API

### `bastion.New(cfg Config) *Client`

Create a new Bastion client.

| Field | Type | Required | Description |
|---|---|---|---|
| SiteKey | string | Yes | Your site's public key |
| Secret | string | Yes | Your site's secret key |
| Endpoint | string | No | API endpoint (default: https://api.bastionsecurity.io) |

### `client.Classify(token string) (*ClassifyResult, error)`

Classify a token from the frontend SDK.

### `client.Track(event string, data map[string]interface{}) error`

Track a server-side event.

## License

MIT — © 2024 Bastion Security
