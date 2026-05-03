package store

import (
	"os"
	"path/filepath"
)

const (
	DirName             = ".opensecretmask"
	ConfigName          = "config.toml"
	SecretsName         = "secrets.json"
	MappingsName        = "mappings.json"
	AllowlistName       = "allowlist.json"
	AuditName           = "audit.log"
	LockName            = ".lock"
	CacheDirName        = "cache"
	RegisteredCacheName = "registered.aho"
)

// Root resolves ~/.opensecretmask. Override with $OPENSECRETMASK_HOME for tests.
func Root() (string, error) {
	if v := os.Getenv("OPENSECRETMASK_HOME"); v != "" {
		return v, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, DirName), nil
}

func Path(name string) (string, error) {
	r, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(r, name), nil
}
