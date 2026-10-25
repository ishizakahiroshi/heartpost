package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func TestOfflineTypeLegacyGolden(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	claims := Claims{Issuer: "example-vendor", Subject: "example-vps-synthetic", Audience: "example-agent", TenantID: "example", IssuedAt: 1700000000, ExpiresAt: 4102444800, JTI: "synthetic-golden", Scope: "agent.report", Type: "offline"}
	data, err := IssueOfflineLicense(privateKey, "synthetic", claims, OfflineMeta{TenantName: "Synthetic", MaxAgents: 3, GraceDays: 7, Features: []string{"agent.report", "monitor.view"}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != "98b0336cdba43090487924e1796236d08f0101c32aa70dc495d7dc825b020f17" {
		t.Fatal("existing signed offline wire bytes changed")
	}
	explicit, err := IssueOfflineLicenseWithType(privateKey, "synthetic", claims, OfflineMeta{TenantName: "Synthetic", MaxAgents: 3, GraceDays: 7, Features: []string{"agent.report", "monitor.view"}}, "sab-offline-license")
	if err != nil || !bytes.Equal(data, explicit) {
		t.Fatal("legacy wrapper differs from explicit legacy type", err)
	}
}

func TestOfflineExplicitTypeIsSignedAndJSONEncoded(t *testing.T) {
	pub, priv := testKeys(t)
	claims := Claims{Issuer: "example-vendor", Subject: "example-vps-synthetic", Audience: "example-agent", TenantID: "example", ExpiresAt: 4102444800, Scope: "agent.report", Type: "offline"}
	resolve := func(kid string) (ed25519.PublicKey, bool) { return pub, kid == "synthetic" }
	for _, offlineType := range []string{"heartdesk-offline-license", "custom-offline-license", "quote\" slash\\ newline\n<script>"} {
		data, err := IssueOfflineLicenseWithType(priv, "synthetic", claims, OfflineMeta{}, offlineType)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseOfflineLicense(data)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Header.Typ != offlineType || parsed.Claims != claims {
			t.Fatal("explicit type or claims changed during JSON encoding")
		}
		if _, err := VerifyOfflineFile(data, resolve); err != nil {
			t.Fatal("explicit type signature failed", err)
		}
		parsed.Header.Typ += "-tampered"
		tampered, err := json.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyOfflineFile(tampered, resolve); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatal("changed type bypassed signature validation", err)
		}
	}
}

func TestOfflineExplicitTypeRejectsEmpty(t *testing.T) {
	_, priv := testKeys(t)
	if data, err := IssueOfflineLicenseWithType(priv, "synthetic", Claims{}, OfflineMeta{}, ""); err == nil || data != nil {
		t.Fatal("empty signed type accepted")
	}
}
