// Package agentsig は agent から monitor へ送るレポートの署名計算を 1 箇所に集約する。
//
// 署名する側と検証する側で別実装を持つと、片方だけ変えたときに全 agent が認証に失敗する。
// 送信側も受信側もこのパッケージだけを呼ぶ。
package agentsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Compute は HMAC-SHA256(key, tsStr + "." + body) を 16 進数文字列で返す。
// Agent 側（署名生成）と Monitor 側（検証）の双方がこの関数を呼ぶことで、
// 署名フォーマットを 1 箇所に固定する。
func Compute(key, tsStr string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(tsStr + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify は受信した signature が key/tsStr/body から計算した署名と一致するかを
// 定数時間比較で判定する。
func Verify(key, tsStr string, body []byte, signature string) bool {
	expected := Compute(key, tsStr, body)
	return hmac.Equal([]byte(signature), []byte(expected))
}
