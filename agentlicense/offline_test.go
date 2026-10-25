package license

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineWireAndValidation(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Now()
	agentID := "tenant-vps-example"
	v := NewWithConfig(keyConfig("", pub))
	base := Claims{Subject: agentID, TenantID: "tenant", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Type: "offline"}
	issue := func(claims Claims) []byte {
		t.Helper()
		data, err := IssueOfflineLicense(priv, "test-kid", claims, OfflineMeta{TenantName: "Example", MaxAgents: 3})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := issue(base)
	parsed, err := ParseOfflineLicense(data)
	if err != nil || parsed.Version != 1 || parsed.Header.Typ != "sab-offline-license" || parsed.Header.Alg != "EdDSA" {
		t.Fatal("offline wire format changed", err)
	}
	path := filepath.Join(t.TempDir(), "license.json")
	check := func(data []byte, subject string) error {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := v.VerifyOfflineLicense(subject, path)
		return err
	}
	if err := check(data, agentID); err != nil {
		t.Fatal(err)
	}
	if err := check(data, "tenant-vps-other"); err == nil {
		t.Fatal("wrong agent accepted")
	}
	expired := base
	expired.ExpiresAt = now.Add(-time.Hour).Unix()
	if err := check(issue(expired), agentID); !errors.Is(err, ErrTokenExpired) {
		t.Fatal("expired offline license accepted", err)
	}
	future := base
	future.NotBefore = now.Add(time.Hour).Unix()
	if err := check(issue(future), agentID); !errors.Is(err, ErrTokenNotYetValid) {
		t.Fatal("future offline license accepted", err)
	}
	future = base
	future.IssuedAt = now.Add(25 * time.Hour).Unix()
	if err := check(issue(future), agentID); err == nil {
		t.Fatal("future issued-at accepted")
	}
	parsed.Claims.Subject = "tenant-vps-other"
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(tampered, "tenant-vps-other"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("tampered offline license accepted", err)
	}
	if _, err := New().VerifyOfflineLicense(agentID, path); !errors.Is(err, ErrUnknownKid) {
		t.Fatal("unconfigured verifier trusted offline key", err)
	}
	if _, err := v.VerifyOfflineLicense(agentID, filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}
