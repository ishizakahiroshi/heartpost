package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	license "github.com/ishizakahiroshi/heartpost/agentlicense"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTokenCacheSignatureAgentKIDExpiryAndIO(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	verifier := license.NewWithConfig(license.Config{VendorPublicKeysB64: "example=" + base64.StdEncoding.EncodeToString(public)})
	token, err := license.SignJWT(private, "example", license.Claims{Subject: "example-agent", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "agent_token.json")
	if err := SaveTokenCache(path, "example-agent", token, verifier); err != nil {
		t.Fatal(err)
	}
	cache, err := LoadTokenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := cache.Valid("example-agent", verifier, time.Now()); !ok || err != nil {
		t.Fatalf("valid: %v %v", ok, err)
	}
	if ok, _ := cache.Valid("other-agent", verifier, time.Now()); ok {
		t.Fatal("wrong agent accepted")
	}
	if ok, _ := cache.Valid("example-agent", verifier, time.Now().Add(58*time.Minute)); ok {
		t.Fatal("renewal window ignored")
	}
	cache.KID = "other"
	if ok, err := cache.Valid("example-agent", verifier, time.Now()); ok || err == nil {
		t.Fatal("wrong KID accepted")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("cache is readable by others")
		}
	}
	if err := SaveTokenCache(path, "other-agent", token, verifier); err == nil {
		t.Fatal("wrong subject saved")
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("example"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveTokenCache(filepath.Join(blocker, "cache"), "example-agent", token, verifier); err == nil {
		t.Fatal("cache IO failure ignored")
	}
	if err := ClearTokenCache(path); err != nil {
		t.Fatal(err)
	}
	if err := SaveTokenCache(filepath.Join(path, "..", "..", "missing", "cache"), "example-agent", "bad-token", verifier); err == nil {
		t.Fatal("malformed token saved")
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokenCache(path); err == nil {
		t.Fatal("corrupt cache accepted")
	}
	if err := ClearTokenCache(filepath.Dir(path)); err == nil {
		t.Fatal("directory removal should fail when nonempty")
	}
}
