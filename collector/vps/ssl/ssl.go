// ssl パッケージはサーバー自身の SSL 証明書有効期限を収集する。
// openssl s_client でローカル TLS エンドポイントに接続し残日数を確認する。
// Linux 専用。FreeBSD 等では nil を返しレポートに含めない。
package ssl

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

func (c *Collector) Name() string { return "ssl" }

// Result は Monitor 側 SSLData と互換な json タグを持つ。
type Result struct {
	SSLExpiry      string `json:"ssl_expiry"`
	SSLDays        int    `json:"ssl_days"`
	SSLRenewalDate string `json:"ssl_renewal_date"`
	LeStatus       string `json:"le_status"`
	LeStatusClass  string `json:"le_status_class"`
	LeLastDate     string `json:"le_last_date"`
}

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	domain := cfg.Domain
	if domain == "" {
		return nil, nil
	}

	res := &Result{
		LeStatus:      "不明",
		LeStatusClass: "warning",
	}

	// SSL 証明書の有効期限を openssl s_client で取得（domain は引数渡し＝シェル展開なし）
	raw := opensslEnddate(domain)
	if idx := strings.Index(raw, "="); idx >= 0 {
		dateStr := strings.TrimSpace(raw[idx+1:])
		wdays := []string{"日", "月", "火", "水", "木", "金", "土"}
		for _, layout := range []string{"Jan  2 15:04:05 2006 MST", "Jan 2 15:04:05 2006 MST"} {
			t, err := time.Parse(layout, dateStr)
			if err != nil {
				continue
			}
			jst := collector.Location()
			tjst := t.In(jst)
			res.SSLExpiry = tjst.Format("2006-01-02(") + wdays[tjst.Weekday()] + ") " + tjst.Format("15:04:05")
			res.SSLDays = int(time.Until(t).Hours() / 24)
			renewal := t.AddDate(0, 0, -30).In(jst)
			res.SSLRenewalDate = renewal.Format("2006-01-02") + "(" + wdays[renewal.Weekday()] + ")"
			break
		}
	}

	// 証明書更新タイマーの状態確認。**ユニット名はホストによって違う**ので設定で上書きできる。
	// 未設定なら既定の certbot.timer を見る。
	//
	// 決め打ちにしてはいけない。独自名のタイマーを使っているホストでは systemctl が
	// 空文字を返し、「タイマー稼働中」も「次回」も**エラーにならないまま永久に埋まらない**。
	// 落ちないので気づけない類の欠測になる。
	renewTimer := cfg.RenewTimer
	if renewTimer == "" {
		renewTimer = "certbot.timer"
	}
	timerRaw := runArgs(5*time.Second, "systemctl", "status", renewTimer)
	if strings.Contains(timerRaw, "Active: active") {
		res.LeStatus = "タイマー稼働中"
		res.LeStatusClass = "ok"
	}
	if idx := strings.Index(timerRaw, "Trigger:"); idx >= 0 {
		rest := timerRaw[idx+8:]
		if end := strings.Index(rest, ";"); end >= 0 {
			parts := strings.Fields(strings.TrimSpace(rest[:end]))
			for i, p := range parts {
				if len(p) == 10 && strings.Count(p, "-") == 2 && i+1 < len(parts) {
					res.LeLastDate = "次回: " + p + " " + parts[i+1]
					break
				}
			}
		}
	}

	// Let's Encrypt ログ確認
	leLog := runArgs(5*time.Second, "tail", "-50", "/var/log/letsencrypt/letsencrypt.log")
	hasFailure := false
	for _, line := range strings.Split(leLog, "\n") {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "no renewal failures"),
			strings.Contains(lower, "not yet due"),
			strings.Contains(lower, "certificate not yet due"):
			res.LeStatus = "正常（更新不要）"
			res.LeStatusClass = "ok"
		case strings.Contains(lower, "success"),
			strings.Contains(lower, "renewed"),
			strings.Contains(lower, "congratulations"):
			res.LeStatus = "更新成功"
			res.LeStatusClass = "ok"
		case strings.Contains(lower, "renewal fail"),
			strings.Contains(lower, "error") && !strings.Contains(lower, "no renewal"):
			hasFailure = true
		}
	}
	if hasFailure && res.LeStatusClass != "ok" {
		res.LeStatus = "失敗"
		res.LeStatusClass = "danger"
	}

	if res.LeLastDate == "" && res.SSLExpiry != "" {
		res.LeLastDate = "残り " + strconv.Itoa(res.SSLDays) + " 日"
	}

	return res, nil
}

// runArgs はコマンドを引数配列で実行する（シェル非経由）。タイムアウト付きで、
// 失敗時は空文字を返す（旧 runShell の 2>/dev/null 相当）。
func runArgs(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// opensslEnddate は openssl s_client → x509 -noout -enddate を Go 側でパイプ接続して
// 証明書の enddate 行を返す。domain は引数として渡すためシェル展開・注入の余地がない。
func opensslEnddate(domain string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// echo | 相当: stdin を即 EOF にして s_client をハンドシェイク後に終了させる。
	sclient := exec.CommandContext(ctx, "openssl", "s_client",
		"-servername", domain, "-connect", domain+":443")
	sclient.Stdin = strings.NewReader("")
	pem, err := sclient.Output()
	if err != nil && len(pem) == 0 {
		return ""
	}

	x509 := exec.CommandContext(ctx, "openssl", "x509", "-noout", "-enddate")
	x509.Stdin = bytes.NewReader(pem)
	out, err := x509.Output()
	if err != nil {
		return ""
	}
	return string(out)
}
