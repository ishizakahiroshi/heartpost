// updates パッケージは Linux 上の apt パッケージ更新状況を収集する。
// Monitor 側 UpdatesData と互換になるよう json タグを揃えて送信する。
//
// FreeBSD 等の非 Linux 環境では (nil, nil) を返し、レポートに含めない。
//
// no-shell 方針（C6: updates-reintroduces-bash-c）: 以前は runShell が bash -c で
// パイプライン（apt list | tail、ls | sort -V | tail | sed 等）を実行していたが、
// bash 不在/PATH 差で全項目が空になる単一障害点であり no-shell 方針に反するため、
// 各コマンドを引数渡しの CommandContext で実行し、tail/sort/sed 相当は Go で処理する。
package updates

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

func (c *Collector) Name() string { return "updates" }

// Result は Monitor 側 UpdatesData と一致する json タグを持つ。
// （UpdatesData の Unavailable / IsLocal は送信側では使わないので含めない。
//
//	受信側で必要なフィールドだけ unmarshal される。）
type Result struct {
	UpdateSvc      string   `json:"update_svc"`
	UpdateAuto     string   `json:"update_auto"`
	AutoEnabled    bool     `json:"auto_enabled"`
	UpdateCount    int      `json:"update_count"`
	UpdateList     []string `json:"update_list"`
	UpdateLog      string   `json:"update_log"`
	UpdateLast     string   `json:"update_last"`      // 最終インストール（/var/log/apt/history.log mtime）
	UpdateListLast string   `json:"update_list_last"` // 最終リスト更新（/var/lib/apt/periodic/update-success-stamp mtime）
	UbuntuVer      string   `json:"ubuntu_version"`
	KernelCurrent  string   `json:"kernel_current"`
	KernelLatest   string   `json:"kernel_latest"`
	KernelOutdated bool     `json:"kernel_outdated"`
	HeldCount      int      `json:"held_count"`
	HeldPackages   []string `json:"held_packages"`
}

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	if runtime.GOOS != "linux" {
		// FreeBSD（rental Agent 等）では apt が無いので送信しない。
		// Monitor 側で Unavailable=true として扱われる。
		return nil, nil
	}

	res := &Result{}

	// unattended-upgrades サービス状態
	res.UpdateSvc = strings.TrimSpace(run("systemctl", "is-active", "unattended-upgrades"))

	// auto update 設定値
	updateAuto := strings.TrimSpace(run("apt-config", "dump", "APT::Periodic::Unattended-Upgrade"))
	if updateAuto == "" {
		updateAuto = `APT::Periodic::Unattended-Upgrade "0";`
	}
	res.UpdateAuto = updateAuto

	// アップグレード可能パッケージ一覧（ヘッダ行を除く＝旧 tail -n +2 相当を Go で）
	listRaw := run("apt", "list", "--upgradable")
	if listRaw != "" {
		for i, line := range strings.Split(listRaw, "\n") {
			if i == 0 {
				continue // "Listing..." ヘッダ行
			}
			line = strings.TrimSpace(line)
			if line != "" {
				res.UpdateList = append(res.UpdateList, line)
			}
		}
	}
	res.UpdateCount = len(res.UpdateList)

	// unattended-upgrades ログ末尾 30行（旧 tail -30 相当を Go で）
	res.UpdateLog = tailFile("/var/log/unattended-upgrades/unattended-upgrades.log", 30)

	// 最終インストール時刻（history.log の mtime — install/upgrade 実行時のみ更新）
	res.UpdateLast = fileMtime("/var/log/apt/history.log")
	// 最終リスト更新時刻（apt-get update 成功で touch される stamp ファイル）
	res.UpdateListLast = fileMtime("/var/lib/apt/periodic/update-success-stamp")

	// Ubuntu バージョン
	ubuntuVer := strings.TrimSpace(run("lsb_release", "-ds"))
	if ubuntuVer == "" {
		ubuntuVer = readOSPrettyName()
	}
	res.UbuntuVer = ubuntuVer

	// 自動更新有効フラグ（Monitor 側ロジックと一致）
	res.AutoEnabled = res.UpdateSvc == "active" && strings.Contains(res.UpdateAuto, `"1"`)

	// カーネル情報
	current := strings.TrimSpace(run("uname", "-r"))
	latest := latestInstalledKernel()
	res.KernelCurrent = current
	res.KernelLatest = latest
	res.KernelOutdated = current != "" && latest != "" && current != latest

	// apt-mark hold で明示的に保留されたパッケージ一覧
	heldRaw := run("apt-mark", "showhold")
	if heldRaw != "" {
		for _, line := range strings.Split(heldRaw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				res.HeldPackages = append(res.HeldPackages, line)
			}
		}
	}
	res.HeldCount = len(res.HeldPackages)

	return res, nil
}

// run はコマンドを引数渡し（シェル非経由）で実行し標準出力を返す（失敗時は空文字）。
// apt list 等のネットワーク依存コマンドがハングしないよう 60s タイムアウトを付ける。
func run(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// tailFile は path の末尾 n 行を返す（旧 tail -N 相当の Go 実装）。
func tailFile(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	if n <= 0 {
		return ""
	}
	ring := make([]string, n)
	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256*1024), 1024*1024)
	for sc.Scan() {
		ring[count%n] = sc.Text()
		count++
	}
	if sc.Err() != nil {
		return ""
	}
	total := count
	if total > n {
		total = n
	}
	start := 0
	if count > n {
		start = count % n
	}
	out := make([]string, 0, total)
	for i := 0; i < total; i++ {
		out = append(out, ring[(start+i)%n])
	}
	return strings.Join(out, "\n")
}

// fileMtime は path の mtime を "YYYY-MM-DD HH:MM:SS" で返す（旧 stat -c '%y' 相当）。
func fileMtime(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fi.ModTime().Format("2006-01-02 15:04:05")
}

// latestInstalledKernel は /boot/vmlinuz-* の中で最新のカーネルバージョン文字列を返す
// （旧 `ls /boot/vmlinuz-* | sort -V | tail -1 | sed 's|/boot/vmlinuz-||'` の Go 実装）。
// filepath.Glob + version sort で bash 依存を排除する（C6: updates-reintroduces-bash-c）。
func latestInstalledKernel() string {
	matches, err := filepath.Glob("/boot/vmlinuz-*")
	if err != nil || len(matches) == 0 {
		return ""
	}
	versions := make([]string, 0, len(matches))
	for _, m := range matches {
		versions = append(versions, strings.TrimPrefix(filepath.Base(m), "vmlinuz-"))
	}
	sort.Slice(versions, func(i, j int) bool {
		return compareKernelVersion(versions[i], versions[j]) < 0
	})
	return versions[len(versions)-1]
}

// compareKernelVersion は sort -V 相当のバージョン比較を行う。
// '.' と '-' でトークンに分解し、数値トークンは数値比較、それ以外は文字列比較する。
// a<b なら負、a>b なら正、等しければ 0 を返す。
func compareKernelVersion(a, b string) int {
	ta := splitVersionTokens(a)
	tb := splitVersionTokens(b)
	n := len(ta)
	if len(tb) < n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		na, okA := parseUint(ta[i])
		nb, okB := parseUint(tb[i])
		if okA && okB {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if ta[i] != tb[i] {
			if ta[i] < tb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ta) < len(tb):
		return -1
	case len(ta) > len(tb):
		return 1
	default:
		return 0
	}
}

func splitVersionTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '-' || r == '+' || r == '~'
	})
}

func parseUint(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var v uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		v = v*10 + uint64(r-'0')
	}
	return v, true
}

// readOSPrettyName は /etc/os-release の PRETTY_NAME を返す（lsb_release が無い環境向け）
func readOSPrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		val := strings.TrimPrefix(line, "PRETTY_NAME=")
		val = strings.Trim(val, `"`)
		return val
	}
	return ""
}
