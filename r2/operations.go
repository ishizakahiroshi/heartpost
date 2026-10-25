// Package r2 provides shared Cloudflare R2 operation metrics.
package r2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const operationsTimeout = 15 * time.Second

type OperationsInfo struct {
	ClassA int    `json:"class_a"`
	ClassB int    `json:"class_b"`
	Month  string `json:"month"`
}

var classATypes = map[string]bool{
	"PutObject": true, "CopyObject": true, "DeleteObject": true,
	"DeleteObjects": true, "CreateMultipartUpload": true, "CompleteMultipartUpload": true,
	"UploadPart": true, "UploadPartCopy": true, "PutBucket": true,
	"ListMultipartUploads": true, "AbortMultipartUpload": true, "ListParts": true,
}
var classBTypes = map[string]bool{
	"GetObject": true, "HeadObject": true, "ListObjects": true,
	"ListObjectsV2": true, "ListBuckets": true, "HeadBucket": true,
	"GetBucketVersioning": true, "GetBucketLocation": true,
	"ReportUsageSummary": true,
}

// CollectOperations queries monthly operations; accountIDSafe must contain only ASCII letters and digits.
func CollectOperations(accountIDSafe, apiToken string) (*OperationsInfo, error) {
	now := time.Now().UTC()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	startOfNext := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	gqlQuery := fmt.Sprintf(
		`{ viewer { accounts(filter: {accountTag: "%s"}) { r2OperationsAdaptiveGroups(filter: {datetime_geq: "%s", datetime_lt: "%s"}, limit: 100) { dimensions { actionType } sum { requests } } } } }`,
		accountIDSafe,
		startOfMonth.Format(time.RFC3339),
		startOfNext.Format(time.RFC3339),
	)

	reqPayload, err := json.Marshal(map[string]string{"query": gqlQuery})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", bytes.NewReader(reqPayload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: operationsTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gqlResp struct {
		Data struct {
			Viewer struct {
				Accounts []struct {
					Ops []struct {
						Sum struct {
							Requests int `json:"requests"`
						} `json:"sum"`
						Dimensions struct {
							ActionType string `json:"actionType"`
						} `json:"dimensions"`
					} `json:"r2OperationsAdaptiveGroups"`
				} `json:"accounts"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5*1024*1024)).Decode(&gqlResp); err != nil {
		return nil, err
	}
	if len(gqlResp.Data.Viewer.Accounts) == 0 {
		return nil, fmt.Errorf("no accounts in response")
	}

	ops := &OperationsInfo{Month: now.Format("2006-01")}
	for _, row := range gqlResp.Data.Viewer.Accounts[0].Ops {
		at := row.Dimensions.ActionType
		cnt := row.Sum.Requests
		if classATypes[at] {
			ops.ClassA += cnt
		} else if classBTypes[at] {
			ops.ClassB += cnt
		}
	}
	return ops, nil
}
