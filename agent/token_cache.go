package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	license "github.com/ishizakahiroshi/heartpost/agentlicense"
)

const tokenRenewBefore = 5 * time.Minute

type TokenCache struct {
	Token     string `json:"token"`
	KID       string `json:"kid"`
	ExpiresAt string `json:"expires_at"` // RFC3339
	AgentID   string `json:"agent_id"`
}

func LoadTokenCache(path string) (*TokenCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cache TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("decode token cache: %w", err)
	}
	return &cache, nil
}

func (c *TokenCache) Valid(agentID string, verifier license.Verifier, now time.Time) (bool, error) {
	if c == nil {
		return false, nil
	}
	if c.AgentID != agentID || c.Token == "" {
		return false, nil
	}

	claims, err := verifier.VerifyToken(agentID, c.Token)
	if err != nil {
		return false, err
	}

	kid, err := license.ExtractKid(c.Token)
	if err != nil {
		return false, err
	}
	if c.KID != "" && c.KID != kid {
		return false, fmt.Errorf("cached kid mismatch")
	}

	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	if c.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, c.ExpiresAt)
		if err != nil {
			return false, fmt.Errorf("parse expires_at: %w", err)
		}
		expiresAt = parsed.UTC()
	}

	if now.Add(tokenRenewBefore).After(expiresAt) {
		return false, nil
	}
	return true, nil
}

func SaveTokenCache(path, agentID, token string, verifier license.Verifier) error {
	if token == "" {
		return ClearTokenCache(path)
	}

	claims, err := verifier.VerifyToken(agentID, token)
	if err != nil {
		return fmt.Errorf("verify token before cache: %w", err)
	}
	kid, err := license.ExtractKid(token)
	if err != nil {
		return fmt.Errorf("extract kid: %w", err)
	}

	cache := TokenCache{
		Token:     token,
		KID:       kid,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339),
		AgentID:   agentID,
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token cache: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("mkdir cache dir: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write token cache temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename token cache: %w", err)
	}
	return nil
}

func ClearTokenCache(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove token cache: %w", err)
	}
	return nil
}
