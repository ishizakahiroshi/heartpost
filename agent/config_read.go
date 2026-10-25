package agent

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
	"path/filepath"
	"runtime"
)

type ConfigReadOptions struct {
	SecretsFileName         string
	CheckSecretsPermissions bool
}

// DecodeConfig decodes the main TOML and then its optional adjacent secrets file.
// The caller supplies its own schema, including product-specific extension fields.
func DecodeConfig(path string, dst any, opts ConfigReadOptions) ([]string, error) {
	if _, err := toml.DecodeFile(path, dst); err != nil {
		return nil, fmt.Errorf("%s decode failed: %w", filepath.Base(path), err)
	}
	name := opts.SecretsFileName
	if name == "" {
		name = secretsFileName
	}
	secret := filepath.Join(filepath.Dir(path), name)
	var warnings []string
	if info, err := os.Stat(secret); err == nil {
		if opts.CheckSecretsPermissions {
			warning, err := CheckSecretsPerm(secret, info.Mode(), runtime.GOOS)
			if err != nil {
				return nil, err
			}
			if warning != "" {
				warnings = append(warnings, warning)
			}
		}
		if _, err := toml.DecodeFile(secret, dst); err != nil {
			return nil, fmt.Errorf("%s decode failed: %w", name, err)
		}
	}
	return warnings, nil
}
