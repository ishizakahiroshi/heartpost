// Package license provides agent license signatures, tokens and offline files.
// Signing material belongs to each Verifier instance and is supplied by its caller.
package license

import (
	"context"
	"time"
)

// Config supplies the signing material for one verifier. Its zero value rejects
// locally signed license keys and has no trusted public keys.
type Config struct {
	VendorSecret        string
	VendorPublicKeysB64 string
}

// Verifier はライセンスキーを検証するインターフェース。
type Verifier interface {
	// Verify はライセンスキーとエージェントIDをローカルで検証する（起動時・オフライン）。
	// 不正なキーの場合は error を返す。
	Verify(agentID, licenseKey string) error

	// VerifyWithMonitor はMonitor APIにHTTPで検証を依頼してトークンを取得する。
	// 成功時はトークン文字列を返す。エンドポイント未設定の場合は "" を返しエラーなし。
	VerifyWithMonitor(ctx context.Context, agentID, licenseKey, monitorEndpoint string) (token string, err error)

	// StartHeartbeat はトークンの有効期限を維持するためのバックグラウンドgoroutineを起動する。
	// ctx がキャンセルされるまで interval ごとに /api/license/heartbeat を叩く。
	// 401/403 受信時は VerifyWithMonitor で再認証してgoroutineを継続する（再起動不要）。
	StartHeartbeat(ctx context.Context, agentID, licenseKey, token, monitorEndpoint string, interval time.Duration)

	// VerifyToken はMonitorから受け取ったJWT（ed25519署名）を検証しclaimsを返す。
	// インスタンスに設定された公開鍵で署名を確認し、有効期限・agentIDの一致も検証する。
	VerifyToken(agentID, token string) (*Claims, error)

	// VerifyOfflineLicense はオフラインライセンスファイルを検証してclaimsを返す。
	// Monitor不到達時のフォールバックとして使用する。
	VerifyOfflineLicense(agentID, filePath string) (*Claims, error)

	// CurrentToken は最新の検証済み Bearer JWT を返す。
	// StartHeartbeat 起動前は VerifyWithMonitor の戻り値を SetCurrentToken で設定する想定。
	// トークン未取得時は空文字を返す。
	CurrentToken() string

	// SetCurrentToken は外部から取得した最新トークンを Verifier 内に保存する。
	// 通常は main 側で VerifyWithMonitor 直後に呼び、StartHeartbeat 開始前に初期値を埋める。
	SetCurrentToken(token string)
}

// New returns a verifier without signing material. Use NewWithConfig to supply it.
func New() Verifier {
	return NewWithConfig(Config{})
}

// NewWithConfig returns an independent verifier with its own token and immutable
// configuration. Config is copied; constructing another verifier cannot change it.
func NewWithConfig(cfg Config) Verifier {
	return newVerifier(cfg)
}
