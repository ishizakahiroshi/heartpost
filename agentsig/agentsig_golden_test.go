package agentsig

import "testing"

// このファイルは署名アルゴリズムを固定する。落ちたときは「テストを直す」前に、
// **稼働中の agent が受信側から拒否されないか**を先に考える。署名の作り方を変えると、
// 更新前の agent が送るレポートは受信側で一切検証できなくなる。
//
// 固定しているのは次の 3 点。
//   - HMAC-SHA256 であること
//   - 署名対象が timestamp + "." + body の連結であること（区切り文字を含む）
//   - 出力が小文字 16 進文字列であること

func TestComputeGolden(t *testing.T) {
	const (
		key  = "0123456789abcdef"
		ts   = "1767322845"
		body = `{"agent_id":"demo-web-01","collectors":{}}`
		// key / ts / body を固定したときの期待値。
		want = "f2eb4ffde0e2a60d6593d410a2eb8b1c3322596e0202f1334ba51f261263be32"
	)

	got := Compute(key, ts, []byte(body))
	if got != want {
		t.Fatalf("signature format changed.\n got: %s\nwant: %s", got, want)
	}
}

// TestSeparatorIsPartOfInput は区切り文字が署名対象に含まれることを固定する。
// 区切りが無ければ ts="12" body="3abc" と ts="123" body="abc" が同じ入力になり、
// timestamp と body の境界を動かした改竄を見逃す。
//
// なおこの区切りが境界を一意に決めるのは **timestamp に "." が現れない前提**に依る。
// timestamp は Unix 秒の 10 進表記なので現状その前提は成り立つ。小数や別形式を
// 入れるようになったら、この前提が崩れることをここで思い出すこと。
func TestSeparatorIsPartOfInput(t *testing.T) {
	key := "k"
	a := Compute(key, "12", []byte("3abc"))
	b := Compute(key, "123", []byte("abc"))
	if a == b {
		t.Fatal("separator is not part of the signed input")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	const key = "0123456789abcdef"
	const ts = "1767322845"
	body := []byte(`{"agent_id":"demo-web-01","collectors":{}}`)

	sig := Compute(key, ts, body)

	if !Verify(key, ts, body, sig) {
		t.Fatal("Verify rejected a valid signature")
	}
	if Verify(key, ts, append(body, ' '), sig) {
		t.Fatal("Verify accepted a tampered body")
	}
	if Verify(key, "1767322846", body, sig) {
		t.Fatal("Verify accepted a tampered timestamp")
	}
	if Verify("other-key", ts, body, sig) {
		t.Fatal("Verify accepted a wrong key")
	}
}
