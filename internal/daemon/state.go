package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// PidFileName is the daemon record, relative to $OPENSECRETMASK_HOME.
	PidFileName = "proxy.pid"
	// LogName is the daemon's stdio log file, relative to $OPENSECRETMASK_HOME.
	LogName = "daemon.log"

	lockSuffix = ".lock"
	tmpSuffix  = ".tmp"
)

// Info is the on-disk record of a running 'osm proxy' daemon: where to reach
// it, and the configuration needed to reproduce it on respawn or restart.
// The JSON field names are a compatibility surface — a daemon started by an
// older binary must stay discoverable.
type Info struct {
	PID       int       `json:"pid"`
	ProxyAddr string    `json:"proxy_addr"`
	DashAddr  string    `json:"dash_addr"`
	StartedAt time.Time `json:"started_at"`

	// Spawn configuration — preserved so respawn and restart bring the daemon
	// back with the same providers, entropy, verbosity, and bind policy.
	Extra         []string `json:"extra,omitempty"`
	Entropy       bool     `json:"entropy,omitempty"`
	LogLevel      string   `json:"log_level,omitempty"`
	AllowExternal bool     `json:"allow_external,omitempty"`
}

func statePath(home string) string { return filepath.Join(home, PidFileName) }

// readState returns the recorded daemon. Absent, unparseable, and records
// missing the fields discovery depends on are all errors: callers treat any
// error as "no usable record".
func readState(home string) (*Info, error) {
	b, err := sys.readFile(statePath(home))
	if err != nil {
		return nil, err
	}
	var in Info
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("parse pidfile: %w", err)
	}
	if in.PID <= 0 || in.ProxyAddr == "" {
		return nil, errors.New("malformed pidfile")
	}
	return &in, nil
}

// Publish records a live daemon. Only the proxy process itself may call this:
// with --listen :0 it is the only party that knows the bound addresses. The
// write is atomic (temp file then rename) so a concurrent reader never sees a
// partial record.
func Publish(home string, in Info) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(home) + tmpSuffix
	if err := sys.writeFile(tmp, b, 0o600); err != nil {
		return err
	}
	return sys.rename(tmp, statePath(home))
}

// Unpublish removes the record. An absent record is success: callers use this
// as unconditional shutdown cleanup and as stale-record teardown.
func Unpublish(home string) error {
	err := sys.remove(statePath(home))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
