package r2

import (
	"context"
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
	"testing"
)

func TestStorageCollectorUsesMockedCommand(t *testing.T) {
	previous := commandOutput
	t.Cleanup(func() { commandOutput = previous })
	calls := 0
	commandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "/usr/local/bin/aws" {
			t.Fatal("unexpected executable")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("command lacks timeout")
		}
		return []byte("Total Objects: 2\nTotal Size: 123\n"), nil
	}
	got, err := (&Collector{}).Collect(optional.Config{Cloudflare: optional.CloudflareConfig{AccountID: "example123", AccessKeyID: "synthetic", Bucket: "example-bucket"}})
	if err != nil {
		t.Fatal(err)
	}
	result := got.(*CollectResult)
	if result.Storage.ObjectCount != "2" || result.Storage.PayloadSize != "123" || result.Storage.Buckets["example-bucket"].ObjectCount != "2" || calls != 1 {
		t.Fatalf("result=%+v calls%d", result, calls)
	}
	if got, err := (&Collector{}).Collect(optional.Config{}); got != nil || err != nil {
		t.Fatal("unconfigured collector should skip")
	}
}
