package store

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type AuditEvent struct {
	TS        time.Time `json:"ts"`
	SessionID string    `json:"session_id,omitempty"`
	Action    string    `json:"action"`
	Tool      string    `json:"tool,omitempty"`
	Event     string    `json:"event,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Mask      string    `json:"mask,omitempty"`
	Count     int       `json:"count,omitempty"`
	Src       string    `json:"src,omitempty"`
	Decision  string    `json:"decision,omitempty"`
	Direction string    `json:"direction,omitempty"`
	Policy    string    `json:"policy_applied,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type AuditWriter struct {
	path    string
	truncTo int
}

func NewAuditWriter(path string, truncTo int) *AuditWriter {
	return &AuditWriter{path: path, truncTo: truncTo}
}

// Append writes one NDJSON line. Lines must fit in PIPE_BUF (4096 bytes) so
// concurrent O_APPEND writes are atomic on POSIX.
func (a *AuditWriter) Append(ev AuditEvent) error {
	if a.truncTo > 0 && len(ev.Mask) > a.truncTo {
		ev.Mask = ev.Mask[:a.truncTo] + "…"
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line := append(b, '\n')
	if len(line) >= 4096 {
		return fmt.Errorf("audit event too large: %d bytes (PIPE_BUF=4096)", len(line))
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return err
	}
	return nil
}
