package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	pidFileName        = "proxy.pid"
	daemonLogName      = "daemon.log"
	daemonStartTimeout = 10 * time.Second
	daemonProbeTimeout = 500 * time.Millisecond
	daemonPollInterval = 100 * time.Millisecond
)

// pidInfo is the on-disk record of a running 'osm proxy' daemon. It is the
// single source of truth for 'osm run' to decide whether to reuse or respawn.
type pidInfo struct {
	PID       int       `json:"pid"`
	ProxyAddr string    `json:"proxy_addr"`
	DashAddr  string    `json:"dash_addr"`
	StartedAt time.Time `json:"started_at"`
	// Spawn config — preserved across 'osm restart' so a fresh binary
	// comes back up with the same providers / entropy / log level.
	Extra         []string `json:"extra,omitempty"`
	Entropy       bool     `json:"entropy,omitempty"`
	LogLevel      string   `json:"log_level,omitempty"`
	AllowExternal bool     `json:"allow_external,omitempty"`
}

type daemonOpts struct {
	extra         []string
	entropy       bool
	logLevel      string
	allowExternal bool
}

func pidFilePath(home string) string { return filepath.Join(home, pidFileName) }

func readPidFile(home string) (*pidInfo, error) {
	b, err := os.ReadFile(pidFilePath(home))
	if err != nil {
		return nil, err
	}
	var p pidInfo
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse pidfile: %w", err)
	}
	if p.PID <= 0 || p.ProxyAddr == "" {
		return nil, errors.New("malformed pidfile")
	}
	return &p, nil
}

func writePidFile(home string, p pidInfo) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := pidFilePath(home) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, pidFilePath(home))
}

func removePidFile(home string) error {
	err := os.Remove(pidFilePath(home))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// processAlive returns true if pid is a running process. Signal 0 is a no-op
// liveness probe: returns nil if the process exists and we can signal it.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// proxyReachable confirms the daemon's TCP listener is up. Guards against
// stale pidfiles whose PID is alive but belongs to an unrelated process
// (PID reuse after reboot) — that process won't be bound to ProxyAddr.
func proxyReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, daemonProbeTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func daemonHealthy(p *pidInfo) bool {
	return p != nil && processAlive(p.PID) && proxyReachable(p.ProxyAddr)
}

// ensureDaemon returns a live pidInfo, spawning a detached 'osm proxy' if
// none is healthy. Concurrent callers serialize via flock on proxy.pid.lock
// so a race between two 'osm run' invocations does not produce two daemons.
// osmKey is passed to the spawned daemon via $OSM_KEY so it can unlock the
// store without a terminal prompt.
func ensureDaemon(home, listen, dash, osmKey string, opts daemonOpts) (*pidInfo, bool, error) {
	if p, _ := readPidFile(home); daemonHealthy(p) {
		return p, false, nil
	}

	lockPath := pidFilePath(home) + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- lockfile path is internal
	if err != nil {
		return nil, false, fmt.Errorf("open daemon lockfile: %w", err)
	}
	defer func() { _ = lf.Close() }()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- fd uintptr fits in int on all supported platforms
		return nil, false, fmt.Errorf("flock daemon lockfile: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) }() // #nosec G115 -- fd uintptr fits in int on all supported platforms

	// Re-check after acquiring the lock — another caller may have spawned
	// the daemon while we were waiting.
	if p, _ := readPidFile(home); daemonHealthy(p) {
		return p, false, nil
	}
	_ = removePidFile(home)

	if err := spawnDaemon(home, listen, dash, osmKey, opts); err != nil {
		return nil, false, err
	}

	deadline := time.Now().Add(daemonStartTimeout)
	for time.Now().Before(deadline) {
		if p, err := readPidFile(home); err == nil && proxyReachable(p.ProxyAddr) {
			return p, true, nil
		}
		time.Sleep(daemonPollInterval)
	}
	return nil, false, fmt.Errorf("daemon did not become ready within %s — see %s",
		daemonStartTimeout, filepath.Join(home, daemonLogName))
}

// spawnDaemon fork-execs 'osm proxy' detached from the parent terminal:
// new session via Setsid so SIGHUP from the parent shell does not reach it,
// stdio redirected to a log file so the daemon survives parent exit.
func spawnDaemon(home, listen, dash, osmKey string, opts daemonOpts) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate osm binary: %w", err)
	}
	args := []string{"proxy", "--listen", listen, "--dashboard", dash, "--log-level", opts.logLevel}
	for _, p := range opts.extra {
		args = append(args, "--provider", p)
	}
	if opts.entropy {
		args = append(args, "--detect-entropy")
	}
	if opts.allowExternal {
		args = append(args, "--allow-external-bind")
	}
	logF, err := os.OpenFile(filepath.Join(home, daemonLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- daemon log path is internal (under $OPENSECRETMASK_HOME)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}
	cmd := exec.Command(self, args...) // #nosec G204 -- self is os.Executable, args are internal
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	env := os.Environ()
	if osmKey != "" {
		env = withEnv(env, map[string]string{keyEnv: osmKey})
	}
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		_ = logF.Close()
		return fmt.Errorf("spawn osm proxy: %w", err)
	}
	_ = cmd.Process.Release()
	_ = logF.Close()
	return nil
}
