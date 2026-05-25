// Package shell installs a posix-shell integration that wraps LLM agent
// CLIs (claude, codex, pi) with `osm run --`. Modelled on AikidoSec/safe-chain:
// rc files get one source line; the sourced script defines shell functions
// that take precedence over PATH lookup.
package shell

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

//go:embed scripts/init-posix.sh
var scripts embed.FS

const (
	scriptName    = "init-posix.sh"
	markerComment = "# opensecretmask shell integration"
	// maxRemoveLineLen guards teardown — refuse to delete suspicious long
	// lines that we did not write.
	maxRemoveLineLen = 200
)

// WrappedTools is the list of CLIs the embedded init script intercepts.
// Kept in sync with scripts/init-posix.sh.
var WrappedTools = []string{"claude", "codex", "pi"}

// sourcePattern matches the rc-file line osm install writes.
var sourcePattern = regexp.MustCompile(`^source\s+\S+init-posix\.sh\s+#\s*opensecretmask`)

// RcFile names an rc file we touched.
type RcFile struct {
	Shell string
	Path  string
}

// FileStatus reports whether a given rc file is wired up.
type FileStatus struct {
	RcFile
	Exists    bool
	Installed bool
}

func candidates() ([]RcFile, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	// macOS Terminal.app spawns bash as a login shell that reads ~/.bash_profile
	// and ignores ~/.bashrc, so cover both. ~/.profile is a fallback some
	// distros and login shells source.
	return []RcFile{
		{"zsh", filepath.Join(home, ".zshrc")},
		{"bash", filepath.Join(home, ".bashrc")},
		{"bash", filepath.Join(home, ".bash_profile")},
		{"sh", filepath.Join(home, ".profile")},
	}, nil
}

func existingTargets() ([]RcFile, error) {
	all, err := candidates()
	if err != nil {
		return nil, err
	}
	out := make([]RcFile, 0, len(all))
	for _, c := range all {
		if _, err := os.Stat(c.Path); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func scriptDest(osmHome string) string {
	return filepath.Join(osmHome, "scripts", scriptName)
}

func sourceLine(osmHome string) string {
	return fmt.Sprintf("source %s %s", scriptDest(osmHome), markerComment)
}

// Install copies the embedded init script to $osmHome/scripts and adds the
// source line to each existing rc file. Idempotent: previous osm source
// lines are stripped first.
func Install(osmHome string) ([]RcFile, error) {
	if err := writeScript(osmHome); err != nil {
		return nil, err
	}
	rcs, err := existingTargets()
	if err != nil {
		return nil, err
	}
	if len(rcs) == 0 {
		return nil, errors.New("no shell rc files found (~/.zshrc, ~/.bashrc) — create one and retry")
	}
	line := sourceLine(osmHome)
	updated := make([]RcFile, 0, len(rcs))
	for _, rc := range rcs {
		if err := backupOnce(rc.Path); err != nil {
			return updated, fmt.Errorf("backup %s: %w", rc.Path, err)
		}
		if err := removeMatchingLines(rc.Path, sourcePattern); err != nil {
			return updated, fmt.Errorf("strip %s: %w", rc.Path, err)
		}
		if err := appendLine(rc.Path, line); err != nil {
			return updated, fmt.Errorf("append %s: %w", rc.Path, err)
		}
		updated = append(updated, rc)
	}
	return updated, nil
}

// Uninstall removes the osm source line from any rc files that have one.
// Leaves the script file in $osmHome/scripts alone — `osm uninstall --purge`
// drops the whole home dir.
func Uninstall() ([]RcFile, error) {
	rcs, err := existingTargets()
	if err != nil {
		return nil, err
	}
	cleared := make([]RcFile, 0, len(rcs))
	for _, rc := range rcs {
		had, err := containsMatch(rc.Path, sourcePattern)
		if err != nil {
			return cleared, fmt.Errorf("scan %s: %w", rc.Path, err)
		}
		if !had {
			continue
		}
		if err := backupOnce(rc.Path); err != nil {
			return cleared, fmt.Errorf("backup %s: %w", rc.Path, err)
		}
		if err := removeMatchingLines(rc.Path, sourcePattern); err != nil {
			return cleared, fmt.Errorf("strip %s: %w", rc.Path, err)
		}
		cleared = append(cleared, rc)
	}
	return cleared, nil
}

// Status reports per-rc-file install state plus whether the script file is on disk.
func Status(osmHome string) ([]FileStatus, bool, error) {
	all, err := candidates()
	if err != nil {
		return nil, false, err
	}
	out := make([]FileStatus, 0, len(all))
	for _, c := range all {
		fs := FileStatus{RcFile: c}
		if _, err := os.Stat(c.Path); err == nil {
			fs.Exists = true
			fs.Installed, err = containsMatch(c.Path, sourcePattern)
			if err != nil {
				return nil, false, err
			}
		}
		out = append(out, fs)
	}
	_, err = os.Stat(scriptDest(osmHome))
	scriptPresent := err == nil
	return out, scriptPresent, nil
}

func writeScript(osmHome string) error {
	dir := filepath.Join(osmHome, "scripts")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	body, err := scripts.ReadFile("scripts/" + scriptName)
	if err != nil {
		return err
	}
	return os.WriteFile(scriptDest(osmHome), body, 0o600)
}

// backupOnce writes <path>.osm.bak only on the first call per file, so a
// pre-osm snapshot survives even when the user reinstalls.
func backupOnce(path string) error {
	bak := path + ".osm.bak"
	if _, err := os.Stat(bak); err == nil {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304,G703 -- path is a known rc file under the user's home
	if err != nil {
		return err
	}
	return os.WriteFile(bak, data, 0o600) // #nosec G304,G703 -- bak path derives from rc file under user's home
}

func containsMatch(path string, pat *regexp.Regexp) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304,G703 -- path is a known rc file under the user's home
	if err != nil {
		return false, err
	}
	if slices.ContainsFunc(splitLines(data), pat.MatchString) {
		return true, nil
	}
	return false, nil
}

func removeMatchingLines(path string, pat *regexp.Regexp) error {
	data, err := os.ReadFile(path) // #nosec G304,G703 -- path is a known rc file under the user's home
	if err != nil {
		return err
	}
	lines := splitLines(data)
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if shouldDrop(line, pat) {
			continue
		}
		kept = append(kept, line)
	}
	out := strings.Join(kept, "\n")
	// preserve trailing newline if present in the original
	if bytes.HasSuffix(data, []byte("\n")) && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0o600) // #nosec G304,G703 -- path is a known rc file under the user's home
}

func shouldDrop(line string, pat *regexp.Regexp) bool {
	if !pat.MatchString(line) {
		return false
	}
	// safe-chain guard: refuse to remove suspiciously long lines or any line
	// containing embedded newlines (would indicate a split bug, not our write).
	if len(line) > maxRemoveLineLen {
		return false
	}
	if strings.ContainsAny(line, "\n\r\u2028\u2029") {
		return false
	}
	return true
}

func appendLine(path, line string) error {
	data, err := os.ReadFile(path) // #nosec G304,G703 -- path is a known rc file under the user's home
	if err != nil {
		return err
	}
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		data = append(data, '\n')
	}
	data = append(data, []byte(line+"\n")...)
	return os.WriteFile(path, data, 0o600) // #nosec G304,G703 -- path is a known rc file under the user's home
}

func splitLines(data []byte) []string {
	// match safe-chain: split on LF, CR, LS, PS
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\u2028", "\n")
	s = strings.ReplaceAll(s, "\u2029", "\n")
	return strings.Split(s, "\n")
}
