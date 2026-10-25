package license

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func keyConfig(secret string, pub ed25519.PublicKey) Config {
	return Config{VendorSecret: secret, VendorPublicKeysB64: "test-kid=" + base64.StdEncoding.EncodeToString(pub)}
}

func issueTestToken(t *testing.T, priv ed25519.PrivateKey, claims Claims) string {
	t.Helper()
	token, err := SignJWT(priv, "test-kid", claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestVerifierConfigurationAndTokenIsolation(t *testing.T) {
	pubA, privA := testKeys(t)
	pubB, privB := testKeys(t)
	cfg := keyConfig("test-a", pubA)
	a := NewWithConfig(cfg)
	cfg.VendorSecret = "test-b"
	cfg.VendorPublicKeysB64 = keyConfig("", pubB).VendorPublicKeysB64
	b := NewWithConfig(cfg)
	agentID := "tenant-vps-example"
	keyA := "tenant." + agentID + "." + ComputeLicenseSig("test-a", "tenant", agentID)
	keyB := "tenant." + agentID + "." + ComputeLicenseSig("test-b", "tenant", agentID)
	claims := Claims{Subject: agentID, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	tokenA := issueTestToken(t, privA, claims)
	tokenB := issueTestToken(t, privB, claims)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.Verify(agentID, keyA) != nil || b.Verify(agentID, keyB) != nil {
				t.Error("instance rejected its own license")
			}
			if a.Verify(agentID, keyB) == nil || b.Verify(agentID, keyA) == nil {
				t.Error("instance accepted another signing secret")
			}
			if _, err := a.VerifyToken(agentID, tokenA); err != nil {
				t.Error(err)
			}
			if _, err := b.VerifyToken(agentID, tokenB); err != nil {
				t.Error(err)
			}
			if _, err := a.VerifyToken(agentID, tokenB); !errors.Is(err, ErrSignatureInvalid) {
				t.Error("instance accepted another public key")
			}
			a.SetCurrentToken("test-token-a")
			b.SetCurrentToken("test-token-b")
			if a.CurrentToken() != "test-token-a" || b.CurrentToken() != "test-token-b" {
				t.Error("token store mixed instances")
			}
		}()
	}
	wg.Wait()
}

func TestLicenseSignatureWireAndRejections(t *testing.T) {
	const tenant, agentID, secret = "tenant", "tenant-vps-example", "test-key"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tenant + "." + agentID))
	want := hex.EncodeToString(mac.Sum(nil))
	if got := ComputeLicenseSig(secret, tenant, agentID); got != want {
		t.Fatal("license wire signature changed")
	}
	got, ok := ComputeVendorLicenseSig(secret, tenant, agentID)
	if !ok || got != want {
		t.Fatal("vendor signature differs")
	}
	if got, ok := ComputeVendorLicenseSig("", tenant, agentID); ok || got != "" {
		t.Fatal("empty secret accepted")
	}
	v := NewWithConfig(Config{VendorSecret: secret})
	valid := tenant + "." + agentID + "." + want
	if err := v.Verify(agentID, valid); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, agent, key string }{
		{"empty", agentID, ""},
		{"malformed", agentID, "invalid"},
		{"tenant mismatch", "other-vps-example", valid},
		{"agent mismatch", "tenant-vps-other", valid},
		{"wrong signature", agentID, tenant + "." + agentID + ".invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if v.Verify(tc.agent, tc.key) == nil {
				t.Fatal("invalid license accepted")
			}
		})
	}
	if New().Verify(agentID, valid) == nil {
		t.Fatal("unconfigured verifier accepted license")
	}
}

func TestPublicKeyParsingHasExplicitInput(t *testing.T) {
	pub, _ := testKeys(t)
	for _, encoded := range []string{base64.StdEncoding.EncodeToString(pub), base64.RawStdEncoding.EncodeToString(pub)} {
		keys, err := ParseVendorPublicKeys("test-kid=" + encoded)
		if err != nil || !pub.Equal(keys["test-kid"]) {
			t.Fatal("public key parsing failed")
		}
		resolver, err := VendorPublicKeyResolver("test-kid=" + encoded)
		if err != nil {
			t.Fatal(err)
		}
		if k, ok := resolver("test-kid"); !ok || !pub.Equal(k) {
			t.Fatal("resolver lost configured key")
		}
		if _, ok := resolver("unknown"); ok {
			t.Fatal("unknown kid accepted")
		}
	}
	for _, input := range []string{"missing-separator", "test-kid=invalid!", "test-kid=" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseVendorPublicKeys(input); err == nil {
			t.Errorf("invalid key input accepted: %q", input)
		}
		resolver, err := VendorPublicKeyResolver(input)
		if err == nil {
			t.Fatal("invalid resolver input accepted")
		}
		if _, ok := resolver("test-kid"); ok {
			t.Fatal("failed resolver trusted key")
		}
	}
	if keys, err := ParseVendorPublicKeys(""); err != nil || len(keys) != 0 {
		t.Fatal("empty list changed semantics")
	}
}

func TestJWTWireAndValidation(t *testing.T) {
	pub, priv := testKeys(t)
	now := time.Now()
	base := Claims{Issuer: "example-vendor", Subject: "tenant-vps-example", Audience: "example-agent", TenantID: "tenant", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), NotBefore: now.Add(-time.Minute).Unix(), JTI: "test-jti", Scope: "agent.report", Type: "session"}
	v := NewWithConfig(keyConfig("", pub))
	token := issueTestToken(t, priv, base)
	got, err := v.VerifyToken(base.Subject, token)
	if err != nil || *got != base {
		t.Fatal("token roundtrip lost claims", err)
	}
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("JWT wire signature changed")
	}
	for _, tc := range []struct {
		name   string
		claims Claims
		want   error
	}{
		{"expired", Claims{Subject: base.Subject, ExpiresAt: now.Add(-time.Hour).Unix()}, ErrTokenExpired},
		{"not yet valid", Claims{Subject: base.Subject, NotBefore: now.Add(time.Hour).Unix()}, ErrTokenNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.VerifyToken(base.Subject, issueTestToken(t, priv, tc.claims))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := v.VerifyToken("tenant-vps-other", token); err == nil {
		t.Fatal("wrong subject accepted")
	}
	if _, err := New().VerifyToken(base.Subject, token); !errors.Is(err, ErrUnknownKid) {
		t.Fatal("unconfigured verifier trusted key")
	}
	if _, err := VerifyJWT("invalid", func(string) (ed25519.PublicKey, bool) { return pub, true }); !errors.Is(err, ErrTokenMalformed) {
		t.Fatal("malformed token accepted")
	}
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := v.VerifyToken(base.Subject, strings.Join(parts, ".")); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("tampered token accepted")
	}
	if claims, err := ExtractClaimsUnverified(token); err != nil || *claims != base {
		t.Fatal("claims extraction changed")
	}
	if kid, err := ExtractKid(token); err != nil || kid != "test-kid" {
		t.Fatal("kid extraction changed")
	}
	if jti, err := NewJTI(); err != nil || len(jti) != 32 {
		t.Fatal("JTI shape changed")
	}
}
