// backup パッケージはローカルバックアップファイル一覧と DB 容量を収集して Monitor に送る。
// バックアップモジュール有効時（collectors.jobs.backup = true）のみ動作する。
//
// 収集内容:
//   - ローカルバックアップ: database.backup_dir/*.sql.zst の ls -lt 結果
//   - Nextcloud DBダンプ: database.nc_backup_dir/*.sql.gz の ls -lt 結果（features.nextcloud=true のホストのみ）
//   - DB 容量: configured database.dsn から information_schema を参照
package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	sharedcollector "github.com/ishizakahiroshi/heartpost/collector"
	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

type Collector struct{}

func (c *Collector) Name() string     { return "backup" }
func (c *Collector) Interval() string { return "infra" }

// BackupFile はバックアップファイル1件
type BackupFile struct {
	Name string `json:"name"`
	Size string `json:"size"`
	Date string `json:"date"`
}

// DBInfo はDB別容量
type DBInfo struct {
	Name string `json:"name"`
	Size string `json:"size"` // MB数値文字列（単位なし）
}

// CollectResult は Monitor へ送るサマリー
type CollectResult struct {
	BackupFiles   []BackupFile `json:"backup_files"`
	NCBackupFiles []BackupFile `json:"nc_backup_files"` // Nextcloud DBダンプ一覧（nc-db-backup.sh の出力先）
	DBSize        string       `json:"db_size"`         // MB数値文字列（例: "28.2"）
	DBList        []DBInfo     `json:"db_list"`
}

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	db := cfg.Database
	backupDir := db.BackupDir
	if backupDir == "" {
		backupDir = "/var/backups/mariadb"
	}

	result := &CollectResult{}

	// ローカルバックアップ一覧
	if files, err := listBackupFilesWithSuffix(backupDir, ".sql.zst"); err == nil {
		result.BackupFiles = files
	}

	// Nextcloud DBダンプ一覧（features.nextcloud=true のホストのみ nc_backup_dir が設定される）
	if db.NCBackupDir != "" {
		if files, err := listBackupFilesWithSuffix(db.NCBackupDir, ".sql.gz"); err == nil {
			result.NCBackupFiles = files
		}
	}

	// DB 容量（DSN 未設定時はスキップ）
	if db.DSN != "" {
		size, list, err := getDBStats(db.DSN)
		if err == nil {
			result.DBSize = size
			result.DBList = list
		}
	} else {
		result.DBSize = "?"
	}

	return result, nil
}

func listBackupFilesWithSuffix(backupDir, suffix string) ([]BackupFile, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// os.ReadDir + DirEntry.Info() で取得する。ls -lt のテキストパース（スペース入り
	// ファイル名・ロケール・シンボリックリンクで崩れる）に依存しない。
	type fileInfo struct {
		name    string
		size    int64
		modTime time.Time
	}
	var infos []fileInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		infos = append(infos, fileInfo{name: e.Name(), size: fi.Size(), modTime: fi.ModTime()})
	}
	// mtime 降順（ls -lt 相当）
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].modTime.After(infos[j].modTime)
	})

	files := make([]BackupFile, 0, len(infos))
	for _, fi := range infos {
		files = append(files, BackupFile{
			Name: fi.name,
			Size: strconv.FormatInt(fi.size, 10),
			Date: fi.modTime.In(jst()).Format("2006-01-02 15:04:05"),
		})
	}
	return files, nil
}

func getDBStats(dsn string) (dbSizeMB string, dbList []DBInfo, err error) {
	dbUser, dbPass, dbSocket := parseMysqlDSN(dsn)
	if dbUser == "" {
		return "?", nil, fmt.Errorf("invalid DSN")
	}

	baseArgs := []string{"-u", dbUser, "--batch", "--skip-column-names"}
	if dbSocket != "" {
		baseArgs = append(baseArgs, "-S", dbSocket)
	}
	env := append(os.Environ(), "MYSQL_PWD="+dbPass)

	sizeQuery := "SELECT ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','sys')"
	if out, e := runMysql(env, append(append([]string{}, baseArgs...), "-e", sizeQuery)...); e == nil {
		if v := strings.TrimSpace(string(out)); v != "" && !strings.Contains(strings.ToUpper(v), "ERROR") {
			dbSizeMB = v
		}
	}
	if dbSizeMB == "" {
		dbSizeMB = "?"
	}

	listQuery := "SELECT table_schema, ROUND(SUM(data_length+index_length)/1024/1024,1) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','sys') GROUP BY table_schema ORDER BY SUM(data_length+index_length) DESC"
	if out, e := runMysql(env, append(append([]string{}, baseArgs...), "-e", listQuery)...); e == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if parts := strings.Split(line, "\t"); len(parts) == 2 {
				dbList = append(dbList, DBInfo{Name: parts[0], Size: parts[1]})
			}
		}
	}
	return
}

// runMysql は mysql クライアントを timeout 付きで実行する。MYSQL_PWD を含む env を
// 渡す必要があるため sharedcollector.RunWithTimeout（env 非対応）ではなく直接
// exec.CommandContext を使うが、DB ロックでのハングを防ぐ timeout は同じく付ける
// （C1: exec-no-timeout-blocks-loop）。
func runMysql(env []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mysql", args...)
	cmd.Env = env
	return cmd.Output()
}

// parseMysqlDSN は go-sql-driver DSN から user / password / socket を取得する
// 形式: user:pass@unix(/run/mysqld/mysqld.sock)/dbname?options
func parseMysqlDSN(dsn string) (user, pass, socket string) {
	parseUserPass := func(s string) (string, string) {
		idx := strings.Index(s, ":")
		if idx < 0 {
			return s, ""
		}
		return s[:idx], s[idx+1:]
	}

	if idx := strings.LastIndex(dsn, "@unix("); idx >= 0 {
		up := dsn[:idx]
		rest := dsn[idx+6:]
		if sockEnd := strings.Index(rest, ")"); sockEnd >= 0 {
			socket = rest[:sockEnd]
		}
		user, pass = parseUserPass(up)
		return
	}
	if idx := strings.LastIndex(dsn, "@tcp("); idx >= 0 {
		up := dsn[:idx]
		user, pass = parseUserPass(up)
		return
	}
	return
}

func jst() *time.Location {
	return sharedcollector.Location()
}
