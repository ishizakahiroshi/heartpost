package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrTokenMalformed   = errors.New("license: malformed token")
	ErrTokenExpired     = errors.New("license: token expired")
	ErrTokenNotYetValid = errors.New("license: token not yet valid")
	ErrSignatureInvalid = errors.New("license: invalid signature")
	ErrUnknownKid       = errors.New("license: unknown kid")
)

// Claims はエージェント用 JWT のペイロード。
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"` // agent_id
	Audience  string `json:"aud"`
	TenantID  string `json:"tid"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	NotBefore int64  `json:"nbf"`
	JTI       string `json:"jti"`
	Scope     string `json:"scope"`
	Type      string `json:"type"` // "session" | "offline"
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// SignJWT はed25519秘密鍵でclaimsに署名してJWTを返す。
func SignJWT(priv ed25519.PrivateKey, kid string, claims Claims) (string, error) {
	hdr := jwtHeader{Alg: "EdDSA", Typ: "JWT", Kid: kid}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	msg := hdrB64 + "." + claimsB64

	sig := ed25519.Sign(priv, []byte(msg))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return msg + "." + sigB64, nil
}

// VerifyJWT はJWTを検証してclaimsを返す。
// resolver はkid → 公開鍵の解決を行う。
func VerifyJWT(token string, resolver func(kid string) (ed25519.PublicKey, bool)) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, ErrTokenMalformed
	}
	if hdr.Alg != "EdDSA" {
		return nil, ErrTokenMalformed
	}

	pubKey, ok := resolver(hdr.Kid)
	if !ok {
		return nil, ErrUnknownKid
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	msg := parts[0] + "." + parts[1]
	if !ed25519.Verify(pubKey, []byte(msg), sig) {
		return nil, ErrSignatureInvalid
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	now := time.Now().Unix()
	if claims.NotBefore > 0 && now < claims.NotBefore {
		return nil, ErrTokenNotYetValid
	}
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

// ExtractClaimsUnverified はJWTの署名を検証せずclaimsだけ取り出す。
// 失効チェック等で使う（署名済みであることは呼び出し元が保証する）。
func ExtractClaimsUnverified(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrTokenMalformed
	}
	return &claims, nil
}

// ExtractKid はJWTのヘッダーからkidだけを取り出す。
func ExtractKid(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrTokenMalformed
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrTokenMalformed
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return "", ErrTokenMalformed
	}
	return hdr.Kid, nil
}

// NewJTI は乱数16バイトのhex文字列を生成してJTIとして返す。
func NewJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	const hexChars = "0123456789abcdef"
	result := make([]byte, 32)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result), nil
}
