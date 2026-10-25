package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseVendorPublicKeys は明示的に渡された公開鍵一覧を解析する。
// フォーマット: "k1=<base64(pub)>,k2=<base64(pub)>"
// ローテーション時は複数キーをカンマ区切りで渡す。
func ParseVendorPublicKeys(vendorPublicKeysB64 string) (map[string]ed25519.PublicKey, error) {
	result := make(map[string]ed25519.PublicKey)
	if vendorPublicKeysB64 == "" {
		return result, nil
	}
	for _, entry := range strings.Split(vendorPublicKeysB64, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.Index(entry, "=")
		if idx < 1 {
			return nil, fmt.Errorf("license: invalid public key entry %q", entry)
		}
		kid := entry[:idx]
		pubB64 := entry[idx+1:]
		pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			// RawStdEncoding でも試す
			pubBytes, err = base64.RawStdEncoding.DecodeString(pubB64)
			if err != nil {
				return nil, fmt.Errorf("license: failed to decode public key for kid %q: %w", kid, err)
			}
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("license: invalid public key size for kid %q: got %d, want %d", kid, len(pubBytes), ed25519.PublicKeySize)
		}
		result[kid] = ed25519.PublicKey(pubBytes)
	}
	return result, nil
}

// VendorPublicKeyResolver はParseVendorPublicKeys から resolver 関数を生成する。
// 解析に失敗した場合はすべてのkidに対してfalseを返すresolver を返す（errも返す）。
func VendorPublicKeyResolver(vendorPublicKeysB64 string) (func(kid string) (ed25519.PublicKey, bool), error) {
	keys, err := ParseVendorPublicKeys(vendorPublicKeysB64)
	if err != nil {
		return func(string) (ed25519.PublicKey, bool) { return nil, false }, err
	}
	return func(kid string) (ed25519.PublicKey, bool) {
		k, ok := keys[kid]
		return k, ok
	}, nil
}

// ParsePrivateKey はbase64エンコードされた秘密鍵をデコードして返す。
func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("license: failed to decode private key: %w", err)
		}
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("license: invalid private key size: got %d, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

// ParsePublicKey はbase64エンコードされた公開鍵をデコードして返す。
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("license: failed to decode public key: %w", err)
		}
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("license: invalid public key size: got %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
