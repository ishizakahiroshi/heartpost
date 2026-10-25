package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

func (r *Runner) resolveToken(ctx context.Context, force bool) (string, error) {
	cfg := r.opts.License
	if cfg.CachePath != "" && !force {
		cache, err := LoadTokenCache(cfg.CachePath)
		if err == nil {
			valid, err := cache.Valid(r.opts.Identity.ID, cfg.Verifier, time.Now().UTC())
			if err == nil && valid {
				return cache.Token, nil
			}
			if err != nil {
				r.opts.Logger.Printf("WARN: token cache invalid: %v", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			r.opts.Logger.Printf("WARN: token cache read failed: %v", err)
		}
	}
	token, err := cfg.Verifier.VerifyWithMonitor(ctx, r.opts.Identity.ID, cfg.Key, cfg.PrimaryEndpoint)
	if err != nil {
		if cfg.OfflineFile != "" {
			if _, offlineErr := cfg.Verifier.VerifyOfflineLicense(r.opts.Identity.ID, cfg.OfflineFile); offlineErr != nil {
				return "", fmt.Errorf("license monitor verification failed: %v; license offline fallback failed: %v", err, offlineErr)
			}
		} else if !cfg.Relaxed {
			return "", fmt.Errorf("license monitor verification failed: %w", err)
		}
		if cfg.CachePath != "" {
			if clearErr := ClearTokenCache(cfg.CachePath); clearErr != nil {
				r.opts.Logger.Printf("WARN: token cache clear failed: %v", clearErr)
			}
		}
		return "", nil
	}
	if token != "" && cfg.CachePath != "" {
		if err := SaveTokenCache(cfg.CachePath, r.opts.Identity.ID, token, cfg.Verifier); err != nil {
			return "", fmt.Errorf("save token cache: %w", err)
		}
	}
	return token, nil
}

func (r *Runner) verify(ctx context.Context) (string, error) {
	cfg := r.opts.License
	if cfg == nil {
		return "", nil
	}
	if err := cfg.Verifier.Verify(r.opts.Identity.ID, cfg.Key); err != nil {
		return "", fmt.Errorf("license verification failed: %w", err)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, cfg.VerifyTimeout)
	defer cancel()
	token, err := r.resolveToken(verifyCtx, false)
	if err == nil {
		cfg.Verifier.SetCurrentToken(token)
	}
	return token, err
}
