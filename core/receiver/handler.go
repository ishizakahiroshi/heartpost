// Package receiver は agent から届くレポートを受け取り、保存し、来なくなったことを
// 判定するところまでを持つ。
//
// 受信の入口はここ 1 つで、テナントや RBAC といった利用側固有の概念は持ち込まない。
// agent_id に意味づけ（テナントの接頭辞など）を強制しないのも同じ理由で、
// 受信側が要求するのは「パスとして安全な識別子であること」だけ。
package receiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/report"
)

const (
	// DefaultMaxBodyBytes は 1 レポートの上限。collector を全部載せても数十 KB なので、
	// 1MB あれば足りる。上限が無いと 1 通で monitor のメモリを埋められる。
	DefaultMaxBodyBytes int64 = 1 << 20
	// DefaultTimestampSkew は X-Agent-Timestamp に許す前後のずれ。
	// 署名済みのリクエストをそのまま送り直す攻撃を、この幅の外で弾く。
	DefaultTimestampSkew = 120 * time.Second
)

// Config は受信ハンドラの設定。
type Config struct {
	// AgentKeys は agent_id → 共有鍵。ここに無い agent_id は未知として弾く。
	AgentKeys map[string]string

	// AllowedIPs は許可する送信元。空なら IP による制限をしない（既定は無効）。
	// 単一 IP（"203.0.113.10"）と CIDR（"198.51.100.0/24"）を混ぜて書ける。
	AllowedIPs []string

	// TrustForwardedFor が true のとき、TCP の接続元がループバックの場合に限り
	// X-Forwarded-For の最終ホップを送信元とみなす。リバースプロキシの背後に置く場合に使う。
	// 直接 listen しているなら false のままにする（false なら偽装ヘッダは一切見ない）。
	TrustForwardedFor bool

	// TimestampSkew は 0 なら DefaultTimestampSkew。
	TimestampSkew time.Duration
	// MaxBodyBytes は 0 以下なら DefaultMaxBodyBytes。
	MaxBodyBytes int64

	// Now はテスト用の時刻差し替え。nil なら time.Now。
	Now func() time.Time
	// Logf は nil なら log.Printf。
	Logf func(format string, args ...any)
}

func (c Config) skew() time.Duration {
	if c.TimestampSkew <= 0 {
		return DefaultTimestampSkew
	}
	return c.TimestampSkew
}

func (c Config) maxBody() int64 {
	if c.MaxBodyBytes <= 0 {
		return DefaultMaxBodyBytes
	}
	return c.MaxBodyBytes
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Handler は POST /api/agent/report を処理する。
type Handler struct {
	store   *Store
	cfg     Config
	allowed []*net.IPNet
}

// NewHandler は受信ハンドラを作る。AllowedIPs に解釈できない値があればエラーにする
// （黙って「全許可」へ倒れないようにする）。
func NewHandler(store *Store, cfg Config) (*Handler, error) {
	if store == nil {
		return nil, errors.New("receiver: store is nil")
	}
	nets, err := parseAllowedIPs(cfg.AllowedIPs)
	if err != nil {
		return nil, err
	}
	return &Handler{store: store, cfg: cfg, allowed: nets}, nil
}

func parseAllowedIPs(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range list {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			_, n, err := net.ParseCIDR(v)
			if err != nil {
				return nil, fmt.Errorf("receiver: invalid allowed_ips entry %q: %w", v, err)
			}
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("receiver: invalid allowed_ips entry %q", v)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ServeHTTP は 1 通のレポートを検証して保存する。
//
// 検証の順序は「安いものから」。署名の計算はボディ全体を舐めるので、
// メソッド・agent_id の形・送信元 IP・ボディ長を先に落としてから署名へ進む。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	agentID := strings.TrimSpace(r.Header.Get(report.HeaderAgentID))
	if agentID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing agent id header")
		return
	}
	if !ValidAgentID(agentID) {
		// 形が不正な agent_id はここで止める。パス連結まで到達させない。
		writeJSONError(w, http.StatusBadRequest, "invalid agent id")
		return
	}

	if !h.ipAllowed(r) {
		h.cfg.logf("heartpost: report rejected (ip not allowed) agent=%s", agentID)
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}

	limited := http.MaxBytesReader(w, r.Body, h.cfg.maxBody())
	body, err := io.ReadAll(limited)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			h.cfg.logf("heartpost: report rejected (body too large) agent=%s", agentID)
			writeJSONError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "body read error")
		return
	}

	tsStr := strings.TrimSpace(r.Header.Get(report.HeaderTimestamp))
	sig := strings.TrimSpace(r.Header.Get(report.HeaderSignature))
	if tsStr == "" || sig == "" {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	now := h.cfg.now()
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(h.cfg.skew()/time.Second) {
		h.cfg.logf("heartpost: report rejected (timestamp out of range %ds) agent=%s", diff, agentID)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	key := h.cfg.AgentKeys[agentID]
	// 未知の agent_id と署名不一致は同じ応答にする。どの agent_id が登録済みかを
	// 応答の差から探れないようにするため。
	if key == "" || !agentsig.Verify(key, tsStr, body, sig) {
		h.cfg.logf("heartpost: report rejected (signature) agent=%s", agentID)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var payload report.Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if payload.AgentID != agentID {
		// ヘッダで署名を検証した agent と、本文が名乗る agent がずれている。
		writeJSONError(w, http.StatusBadRequest, "agent id mismatch")
		return
	}

	rec := Record{
		ReceivedAt: now.UTC().Format(time.RFC3339),
		AgentID:    payload.AgentID,
		AgentLabel: payload.AgentLabel,
		AgentType:  payload.AgentType,
		ReportedAt: payload.ReportedAt,
		Collectors: payload.Collectors,
	}
	if err := h.store.Append(rec, now); err != nil {
		h.cfg.logf("heartpost: report save failed agent=%s: %v", agentID, err)
		writeJSONError(w, http.StatusInternalServerError, "save failed")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// ipAllowed は送信元が allowlist に含まれるかを返す。allowlist が空なら常に true。
func (h *Handler) ipAllowed(r *http.Request) bool {
	if len(h.allowed) == 0 {
		return true
	}
	ip := h.remoteIP(r)
	if ip == nil {
		return false
	}
	for _, n := range h.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP は送信元 IP を返す。
//
// 既定では TCP の接続元しか見ない。X-Forwarded-For は誰でも付けられるので、
// TrustForwardedFor が明示され、かつ接続元がループバック（= 同じホストの
// リバースプロキシ）の場合に限って読む。
func (h *Handler) remoteIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if hh, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = hh
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return nil
	}
	if h.cfg.TrustForwardedFor && ip.IsLoopback() {
		if fwd := forwardedFor(r); fwd != nil {
			return fwd
		}
	}
	return ip
}

func forwardedFor(r *http.Request) net.IP {
	raw := r.Header.Get("X-Forwarded-For")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	// 直近のプロキシが付けた最後のエントリを使う。前方の値は偽装され得る。
	last := strings.TrimSpace(parts[len(parts)-1])
	return net.ParseIP(last)
}
