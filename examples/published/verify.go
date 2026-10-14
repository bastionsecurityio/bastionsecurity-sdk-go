package integration

import (
    "context"
    "os"
    bastion "github.com/bastionsecurityio/sdk-go"
)

func Verify(ctx context.Context, request bastion.ClassifyRequest) (*bastion.ClassifyResult, error) {
    client := bastion.New(bastion.Config{
        SiteKey: os.Getenv("BASTION_SITE_KEY"),
        Secret: os.Getenv("BASTION_SECRET_KEY"),
        Endpoint: os.Getenv("BASTION_ENDPOINT"),
    })
    return client.Verify(ctx, request)
}
// Only decision.Action == "allow" permits fulfillment; any error stops it.
