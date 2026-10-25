// r2 パッケージは Cloudflare R2 のストレージメトリクスを収集して Monitor に送る。
// Cloudflare R2 モジュール有効時（collectors.jobs.cloudflare = true）のみ動作する。
//
// 収集方法:
//   - ストレージ容量: aws s3 ls --recursive --summarize（S3 互換 API）
//   - 月間操作回数: Cloudflare GraphQL Analytics API
package r2

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
	r2pkg "github.com/ishizakahiroshi/heartpost/r2"
)

type Collector struct{}

var commandOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func (c *Collector) Name() string     { return "cloudflare" }
func (c *Collector) Interval() string { return "infra" }

// BucketInfo はバケット別ストレージ情報
type BucketInfo struct {
	PayloadSize string `json:"payload_size"`
	ObjectCount string `json:"object_count"`
}

// StorageInfo はストレージ合計
type StorageInfo struct {
	PayloadSize string                `json:"payload_size"`
	ObjectCount string                `json:"object_count"`
	Buckets     map[string]BucketInfo `json:"buckets"`
}

// OperationsInfo は月間操作回数
type OperationsInfo struct {
	ClassA int    `json:"class_a"`
	ClassB int    `json:"class_b"`
	Month  string `json:"month"`
}

// CollectResult は Monitor へ送るサマリー
type CollectResult struct {
	Storage    *StorageInfo    `json:"storage,omitempty"`
	Operations *OperationsInfo `json:"operations,omitempty"`
}

// C3（r2-logic-duplicated-drift）: Class A/B のアクション分類は internal/r2 の正準実装が持つ。
// 本パッケージの collectOperations は internal/r2.CollectOperations へ委譲するため、
// ここでは accountID 正規化のみ保持する。
var reAccountID = regexp.MustCompile(`[^a-zA-Z0-9]`)

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	cf := cfg.Cloudflare
	if cf.AccountID == "" || cf.AccessKeyID == "" {
		return nil, nil
	}
	profile := cf.Profile
	if profile == "" {
		profile = "r2"
	}

	safeAccountID := reAccountID.ReplaceAllString(strings.TrimSpace(cf.AccountID), "")
	if safeAccountID == "" {
		return nil, nil
	}

	endpointURL := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", safeAccountID)
	result := &CollectResult{}

	// ストレージ容量収集
	if cf.Bucket != "" {
		storage, err := collectStorage(cf.Bucket, endpointURL, profile)
		if err == nil {
			result.Storage = storage
		}
	}

	// 月間操作回数（GraphQL）
	if cf.SecretAccessKey != "" {
		ops, err := collectOperations(safeAccountID, cf.SecretAccessKey)
		if err == nil {
			result.Operations = ops
		}
	}

	return result, nil
}

func collectStorage(bucket, endpointURL, profile string) (*StorageInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := commandOutput(ctx, "/usr/local/bin/aws", "s3", "ls",
		"s3://"+bucket, "--recursive", "--summarize",
		"--endpoint-url", endpointURL,
		"--profile", profile)
	if err != nil {
		return nil, fmt.Errorf("aws s3 ls: %w", err)
	}

	var totalSize, totalCount int64
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Total Objects:") {
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "Total Objects:")), "%d", &totalCount)
		} else if strings.HasPrefix(line, "Total Size:") {
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "Total Size:")), "%d", &totalSize)
		}
	}

	return &StorageInfo{
		PayloadSize: fmt.Sprintf("%d", totalSize),
		ObjectCount: fmt.Sprintf("%d", totalCount),
		Buckets: map[string]BucketInfo{
			bucket: {
				PayloadSize: fmt.Sprintf("%d", totalSize),
				ObjectCount: fmt.Sprintf("%d", totalCount),
			},
		},
	}, nil
}

// collectOperations は当月の R2 操作回数を取得する。
// C3（r2-logic-duplicated-drift）: GraphQL 取得ロジックは internal/r2 の正準実装
// CollectOperations に一本化し、ここはその委譲＋ローカル型への詰め替えのみとする。
func collectOperations(accountIDSafe, apiToken string) (*OperationsInfo, error) {
	ops, err := r2pkg.CollectOperations(accountIDSafe, apiToken)
	if err != nil {
		return nil, err
	}
	if ops == nil {
		return nil, nil
	}
	return &OperationsInfo{ClassA: ops.ClassA, ClassB: ops.ClassB, Month: ops.Month}, nil
}
