package detector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type EnvEntry struct {
	Key        string
	Value      string
	SourcePath string
}

// FindEnvFiles walks from cwd up until .git/ or filesystem root, collecting
// files matching any of the configured patterns. Stops at git boundary if walkUpToGitRoot=true.
func FindEnvFiles(cwd string, patterns []string, walkUpToGitRoot bool) ([]string, error) {
	var found []string
	dir := cwd
	for {
		for _, pat := range patterns {
			matches, _ := filepath.Glob(filepath.Join(dir, pat))
			found = append(found, matches...)
		}
		if walkUpToGitRoot {
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return found, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return found, nil
		}
		dir = parent
	}
}

// ParseEnvFile returns KEY=VALUE entries. Honors `export KEY=VALUE`, ignores
// blank lines, comments. Values can be quoted "..." or '...'.
func ParseEnvFile(path string) ([]EnvEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []EnvEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out = append(out, EnvEntry{Key: k, Value: v, SourcePath: path})
	}
	return out, sc.Err()
}
