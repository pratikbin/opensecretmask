package store

import (
	"encoding/json"
	"os"
)

type Allowlist struct {
	Values        []string `json:"values"`
	Patterns      []string `json:"patterns"`
	RulesDisabled []string `json:"rules_disabled"`
}

func LoadAllowlist(path string) (*Allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Allowlist{}, nil
		}
		return nil, err
	}
	a := &Allowlist{}
	if err := json.Unmarshal(b, a); err != nil {
		return nil, err
	}
	return a, nil
}

func SaveAllowlist(path string, a *Allowlist) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, b, 0o600)
}
