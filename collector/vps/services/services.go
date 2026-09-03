package services

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

func (c *Collector) Name() string { return "services" }

// Result は 1 回の収集で得たサービスの状態一覧。
//
// 「特定の製品が入っているか」の真偽値はここに持たない。監視したいものは
// Config.ServiceNames に systemd のユニット名で並べる。
type Result struct {
	Services map[string]Entry `json:"services"`
	Order    []string         `json:"order"`
}

type Entry struct {
	Status  string  `json:"status"` // "active" / "inactive" / "unknown"
	Mem     float64 `json:"mem"`    // MB (RSS合計)
	Version string  `json:"version"`
}

var versionRe = regexp.MustCompile(`\d+(\.\d+)+`)

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	if len(cfg.ServiceNames) == 0 {
		return nil, nil
	}

	statuses, err := collectStatuses(cfg.ServiceNames)
	if err != nil {
		return nil, fmt.Errorf("services: systemctl: %w", err)
	}

	// ps aux はサービス数に比例して毎回フル実行すると N サービスで N 回になるため、
	// 1 Collect につき 1 回だけ実行して結果を全サービスで共有する。
	// 取得に失敗した場合 memByName は空マップになる。
	memByName := collectMemAll(cfg.ServiceNames)

	result := &Result{
		Services: make(map[string]Entry, len(cfg.ServiceNames)),
		Order:    cfg.ServiceNames,
	}

	for _, name := range cfg.ServiceNames {
		status := statuses[name]
		ver := collectVersion(name)
		result.Services[name] = Entry{
			Status:  status,
			Mem:     memByName[name],
			Version: ver,
		}
	}

	return result, nil
}

// collectStatuses は systemctl is-active を一括実行してサービス名→状態マップを返す
func collectStatuses(names []string) (map[string]string, error) {
	args := append([]string{"is-active", "--"}, names...)
	// systemctl のハング防止に RunWithTimeout 経由で実行する
	// （C1: exec-no-timeout-blocks-loop）。is-active は非activeサービスがあると
	// exit code != 0 になり .Output() は error を返すが、stdout は使えるので無視する。
	out, _ := collector.RunWithTimeout(5*time.Second, "systemctl", args...)

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	result := make(map[string]string, len(names))
	for i, name := range names {
		status := "unknown"
		if i < len(lines) {
			s := strings.TrimSpace(lines[i])
			if s == "active" || s == "inactive" || s == "activating" || s == "deactivating" || s == "failed" {
				status = s
			}
		}
		result[name] = status
	}
	return result, nil
}

// collectMemAll は ps aux を 1 回だけ実行し、全サービスの RSS 合計（MB）を返す。
// 以前は部分文字列一致（strings.Contains(line, name)）で過大計上していた
// （name="nginx" が nginx-debug やパスに nginx を含む無関係プロセスにマッチ）ため、
// 実行ファイル名（ps aux の COMMAND フィールド先頭トークンの basename）の厳密一致で
// 集計する（C5: services-mem-substring-overcount）。ps は RunWithTimeout 経由で実行する
// （C1: exec-no-timeout-blocks-loop）。
func collectMemAll(names []string) map[string]float64 {
	result := make(map[string]float64, len(names))
	out, err := collector.RunWithTimeout(5*time.Second, "ps", "aux")
	if err != nil {
		return result
	}

	// サービス名 → 突き合わせる実行ファイル basename 候補。unit 名 ≠ プロセス名の代表例
	// （mariadb→mysqld 等）を吸収する。
	procNames := make(map[string][]string, len(names))
	for _, name := range names {
		procNames[name] = processBasenames(name)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND...
		if len(fields) < 11 {
			continue
		}
		// COMMAND の先頭トークン（実行ファイルパス）の basename を取る。
		exe := filepath.Base(fields[10])
		var rss float64
		if _, err := fmt.Sscanf(fields[5], "%f", &rss); err != nil {
			continue
		}
		for _, name := range names {
			if matchesExe(exe, procNames[name]) {
				result[name] += rss
			}
		}
	}
	for name, kb := range result {
		result[name] = roundMB(kb / 1024)
	}
	return result
}

// processBasenames は unit 名から突き合わせる実行ファイル basename 候補を返す。
// 既知の unit名≠プロセス名（mariadb→mysqld 等）をここで吸収する。
func processBasenames(unit string) []string {
	switch unit {
	case "mariadb":
		return []string{"mariadbd", "mysqld", "mariadb"}
	case "mysql":
		return []string{"mysqld", "mariadbd", "mysql"}
	default:
		return []string{unit}
	}
}

// matchesExe は ps の実行ファイル basename が候補のいずれかに厳密一致するか返す。
// "nginx: worker process" のように COMMAND がコロン付きで来る場合に備え、コロン前で
// 切ったトークンとも比較する。
func matchesExe(exe string, candidates []string) bool {
	base := exe
	if idx := strings.IndexByte(base, ':'); idx >= 0 {
		base = base[:idx]
	}
	for _, c := range candidates {
		if exe == c || base == c {
			return true
		}
	}
	return false
}

// collectVersion はサービス名からバージョン文字列を取得する。
// name を実行ファイルとして引数渡しで起動する（シェル非経由）。取得できない場合は空文字。
func collectVersion(name string) string {
	type verCmd struct {
		bin  string
		args []string
	}
	candidates := []verCmd{
		{name, []string{"--version"}},
		{name, []string{"-v"}},
		{name, []string{"-V"}},
	}
	// postfix のみ専用コマンド
	if name == "postfix" {
		candidates = append([]verCmd{{"postconf", []string{"mail_version"}}}, candidates...)
	}

	for _, c := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, c.bin, c.args...).CombinedOutput()
		cancel()
		if err != nil && len(out) == 0 {
			continue
		}
		// 先頭行のみを対象にする（旧 head -1 相当）
		firstLine := string(out)
		if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
			firstLine = firstLine[:idx]
		}
		if m := versionRe.FindString(firstLine); m != "" {
			return m
		}
	}
	return ""
}

func roundMB(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}
