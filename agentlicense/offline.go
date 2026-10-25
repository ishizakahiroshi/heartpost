package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// OfflineFileVersion はオフラインライセンスファイルのバージョン。
const OfflineFileVersion = 1

// OfflineMeta はオフラインライセンスファイル固有のメタデータ。
type OfflineMeta struct {
	TenantName string   `json:"tenant_name,omitempty"`
	MaxAgents  int      `json:"max_agents,omitempty"`
	GraceDays  int      `json:"grace_days,omitempty"`
	Features   []string `json:"features,omitempty"`
}

// OfflineFile はオフラインライセンスファイルの構造体。
type OfflineFile struct {
	Version int `json:"v"`
	Header  struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	} `json:"header"`
	Claims    Claims      `json:"claims"`
	Meta      OfflineMeta `json:"meta,omitempty"`
	Signature string      `json:"signature"` // base64url(ed25519.Sign)
}

// IssueOfflineLicense はオフラインライセンスファイルをJSON形式で発行する。
func IssueOfflineLicense(priv ed25519.PrivateKey, kid string, claims Claims, meta OfflineMeta) ([]byte, error) {
	f := OfflineFile{
		Version: OfflineFileVersion,
		Claims:  claims,
		Meta:    meta,
	}
	f.Header.Alg = "EdDSA"
	f.Header.Kid = kid
	// This identifier is part of the existing signed wire format.
	f.Header.Typ = "sab-offline-license"

	// 署名対象: canonical JSON of {header, claims}
	sigTarget, err := json.Marshal(struct {
		Header interface{} `json:"header"`
		Claims Claims      `json:"claims"`
	}{f.Header, f.Claims})
	if err != nil {
		return nil, fmt.Errorf("offline license: marshal failed: %w", err)
	}

	sig := ed25519.Sign(priv, sigTarget)
	f.Signature = base64.RawURLEncoding.EncodeToString(sig)

	return json.MarshalIndent(f, "", "  ")
}

// ParseOfflineLicense はJSONデータをOfflineFileにパースする（署名検証なし）。
func ParseOfflineLicense(data []byte) (*OfflineFile, error) {
	var f OfflineFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("offline license: parse failed: %w", err)
	}
	if f.Version != OfflineFileVersion {
		return nil, fmt.Errorf("offline license: unsupported version %d", f.Version)
	}
	return &f, nil
}

// VerifyOfflineFile はオフラインライセンスファイルを署名検証してclaimsを返す。
// resolver はkid → 公開鍵の解決を行う。
func VerifyOfflineFile(data []byte, resolver func(kid string) (ed25519.PublicKey, bool)) (*Claims, error) {
	f, err := ParseOfflineLicense(data)
	if err != nil {
		return nil, err
	}

	pubKey, ok := resolver(f.Header.Kid)
	if !ok {
		return nil, ErrUnknownKid
	}

	sig, err := base64.RawURLEncoding.DecodeString(f.Signature)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	sigTarget, err := json.Marshal(struct {
		Header interface{} `json:"header"`
		Claims Claims      `json:"claims"`
	}{f.Header, f.Claims})
	if err != nil {
		return nil, fmt.Errorf("offline license: marshal for verify failed: %w", err)
	}

	if !ed25519.Verify(pubKey, sigTarget, sig) {
		return nil, ErrSignatureInvalid
	}

	// オンライン経路 VerifyJWT と同一の有効期限検証をオフライン経路にも適用する。
	// これが無いと、署名さえ正しければ exp を過ぎた（失効した）オフラインライセンスが
	// Monitor 不達時に無期限受理されてしまう。
	now := time.Now().Unix()
	if f.Claims.NotBefore > 0 && now < f.Claims.NotBefore {
		return nil, ErrTokenNotYetValid
	}
	if f.Claims.ExpiresAt > 0 && now > f.Claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	// claims.iat が未来すぎる場合は時計ずらし対策で拒否（24h超）
	// （iat の未来スキュー判定はverifier.go側で行う）
	return &f.Claims, nil
}

// LoadAndVerifyOfflineLicense はファイルパスから読み込み、署名検証してclaimsを返す。
func LoadAndVerifyOfflineLicense(filePath string, resolver func(kid string) (ed25519.PublicKey, bool)) (*Claims, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("offline license: read file %q: %w", filePath, err)
	}
	return VerifyOfflineFile(data, resolver)
}
