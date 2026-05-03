package store

import (
	"encoding/json"
	"os"
	"time"
)

type SecretEntry struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Source       string    `json:"source"`
	SourcePath   string    `json:"source_path,omitempty"`
	Rule         string    `json:"rule"`
	Value        string    `json:"value"`
	Masked       string    `json:"masked"`
	RegisteredAt time.Time `json:"registered_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

type Secrets struct {
	Version int           `json:"version"`
	Secrets []SecretEntry `json:"secrets"`
}

func LoadSecrets(path string) (*Secrets, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Secrets{Version: 1}, nil
		}
		return nil, err
	}
	s := &Secrets{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

func SaveSecrets(path string, s *Secrets) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, b, 0o600)
}

// Upsert replaces an entry by ID, otherwise appends. LastSeenAt set to now.
func (s *Secrets) Upsert(e SecretEntry) {
	e.LastSeenAt = time.Now().UTC()
	for i := range s.Secrets {
		if s.Secrets[i].ID == e.ID {
			s.Secrets[i] = e
			return
		}
	}
	s.Secrets = append(s.Secrets, e)
}

func (s *Secrets) FindByValue(v string) (*SecretEntry, bool) {
	for i := range s.Secrets {
		if s.Secrets[i].Value == v {
			return &s.Secrets[i], true
		}
	}
	return nil, false
}
