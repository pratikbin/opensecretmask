package shell

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ── pure helpers ────────────────────────────────────────────────────────────

func TestShouldDrop_MatchShort(t *testing.T) {
	t.Parallel()
	pat := regexp.MustCompile(`^source\s+\S+init-posix\.sh\s+#\s*opensecretmask`)
	line := "source /home/user/.osm/scripts/init-posix.sh # opensecretmask"
	if !shouldDrop(line, pat) {
		t.Error("expected shouldDrop=true for matching short line")
	}
}

func TestShouldDrop_NoMatch(t *testing.T) {
	t.Parallel()
	pat := regexp.MustCompile(`^source\s+\S+init-posix\.sh\s+#\s*opensecretmask`)
	line := "export PATH=$PATH:/usr/local/bin"
	if shouldDrop(line, pat) {
		t.Error("expected shouldDrop=false for non-matching line")
	}
}

func TestShouldDrop_TooLong(t *testing.T) {
	t.Parallel()
	pat := regexp.MustCompile(`opensecretmask`)
	// build a matching line longer than maxRemoveLineLen
	line := "source " + strings.Repeat("x", maxRemoveLineLen) + " # opensecretmask"
	if shouldDrop(line, pat) {
		t.Error("expected shouldDrop=false for oversized matching line")
	}
}

func TestShouldDrop_EmbeddedNewline(t *testing.T) {
	t.Parallel()
	pat := regexp.MustCompile(`opensecretmask`)
	// line that matches but contains embedded newline
	line := "source /tmp/init-posix.sh # opensecretmask\nrm -rf /"
	if shouldDrop(line, pat) {
		t.Error("expected shouldDrop=false for line with embedded newline")
	}
}

func TestShouldDrop_EmbeddedLineSeparator(t *testing.T) {
	t.Parallel()
	pat := regexp.MustCompile(`opensecretmask`)
	// Unicode line separator
	line := "source /tmp/init-posix.sh # opensecretmask evil"
	if shouldDrop(line, pat) {
		t.Error("expected shouldDrop=false for line with Unicode line separator")
	}
}

func TestSplitLines_CRLF(t *testing.T) {
	t.Parallel()
	data := []byte("a\r\nb\r\nc")
	got := splitLines(data)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("splitLines CRLF: got %v", got)
	}
}

func TestSplitLines_UnicodeSeparators(t *testing.T) {
	t.Parallel()
	data := []byte("a b c")
	got := splitLines(data)
	if len(got) != 3 {
		t.Errorf("splitLines Unicode separators: got %v", got)
	}
}

// ── file helpers ─────────────────────────────────────────────────────────────

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(data)
}

// ── containsMatch ────────────────────────────────────────────────────────────

func TestContainsMatch_Found(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, ".zshrc")
	writeFile(t, f, "export FOO=bar\nsource /osm/scripts/init-posix.sh # opensecretmask\nexport BAZ=qux\n")
	ok, err := containsMatch(f, sourcePattern)
	if err != nil {
		t.Fatalf("containsMatch: %v", err)
	}
	if !ok {
		t.Error("expected match=true")
	}
}

func TestContainsMatch_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, ".zshrc")
	writeFile(t, f, "export FOO=bar\n")
	ok, err := containsMatch(f, sourcePattern)
	if err != nil {
		t.Fatalf("containsMatch: %v", err)
	}
	if ok {
		t.Error("expected match=false")
	}
}

// ── removeMatchingLines ───────────────────────────────────────────────────────

func TestRemoveMatchingLines_RemovesLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, ".zshrc")
	writeFile(t, f, "export A=1\nsource /osm/scripts/init-posix.sh # opensecretmask\nexport B=2\n")
	if err := removeMatchingLines(f, sourcePattern); err != nil {
		t.Fatalf("removeMatchingLines: %v", err)
	}
	got := readFile(t, f)
	if strings.Contains(got, "opensecretmask") {
		t.Errorf("source line still present: %q", got)
	}
	if !strings.Contains(got, "export A=1") || !strings.Contains(got, "export B=2") {
		t.Errorf("other lines lost: %q", got)
	}
}

func TestRemoveMatchingLines_PreservesTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, ".zshrc")
	writeFile(t, f, "export A=1\nsource /osm/scripts/init-posix.sh # opensecretmask\n")
	if err := removeMatchingLines(f, sourcePattern); err != nil {
		t.Fatalf("removeMatchingLines: %v", err)
	}
	got := readFile(t, f)
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("trailing newline lost: %q", got)
	}
}

// ── backupOnce ────────────────────────────────────────────────────────────────

func TestBackupOnce_CreatesBackup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, ".zshrc")
	writeFile(t, f, "original content\n")
	if err := backupOnce(f); err != nil {
		t.Fatalf("backupOnce: %v", err)
	}
	bak := f + ".osm.bak"
	got := readFile(t, bak)
	if got != "original content\n" {
		t.Errorf("backup content mismatch: %q", got)
	}
}

func TestBackupOnce_NotOverwritten(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, ".zshrc")
	writeFile(t, f, "original content\n")
	bak := f + ".osm.bak"
	// create backup manually with known content
	writeFile(t, bak, "pre-existing backup\n")
	// rc file now has different content
	writeFile(t, f, "new content after install\n")
	// backupOnce must not overwrite existing bak
	if err := backupOnce(f); err != nil {
		t.Fatalf("backupOnce: %v", err)
	}
	got := readFile(t, bak)
	if got != "pre-existing backup\n" {
		t.Errorf("backup was overwritten: %q", got)
	}
}

// ── Install ───────────────────────────────────────────────────────────────────

func setupHome(t *testing.T, rcFiles map[string]string) (home, osmHome string) {
	t.Helper()
	home = t.TempDir()
	osmHome = t.TempDir()
	t.Setenv("HOME", home)
	for name, content := range rcFiles {
		writeFile(t, filepath.Join(home, name), content)
	}
	return home, osmHome
}

func TestInstall_WritesSourceLine(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	rcs, err := Install(osmHome)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(rcs) == 0 {
		t.Fatal("Install returned no rc files")
	}
	got := readFile(t, filepath.Join(home, ".zshrc"))
	if !strings.Contains(got, "init-posix.sh") {
		t.Errorf("source line not written: %q", got)
	}
	if !strings.Contains(got, markerComment) {
		t.Errorf("marker comment missing: %q", got)
	}
}

func TestInstall_Idempotent(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	got := readFile(t, filepath.Join(home, ".zshrc"))
	count := strings.Count(got, "init-posix.sh")
	if count != 1 {
		t.Errorf("source line duplicated after second install: count=%d, content=%q", count, got)
	}
}

func TestInstall_BackupCreatedOnce(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "original\n",
	})
	rc := filepath.Join(home, ".zshrc")
	bak := rc + ".osm.bak"
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	bakContent := readFile(t, bak)
	if bakContent != "original\n" {
		t.Errorf("backup has wrong content: %q", bakContent)
	}
	// second Install must not overwrite the backup
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	bakContent2 := readFile(t, bak)
	if bakContent2 != bakContent {
		t.Errorf("backup was overwritten on second install: %q", bakContent2)
	}
}

func TestInstall_NoRcFiles_Error(t *testing.T) {
	// empty home — no rc files exist
	_, osmHome := setupHome(t, map[string]string{})
	_, err := Install(osmHome)
	if err == nil {
		t.Error("expected error when no rc files exist")
	}
}

func TestInstall_WritesScript(t *testing.T) {
	_, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	scriptPath := filepath.Join(osmHome, "scripts", scriptName)
	if _, err := os.Stat(scriptPath); err != nil {
		t.Errorf("script not written: %v", err)
	}
}

func TestInstall_SourceLineNoEmbeddedNewlines(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got := readFile(t, filepath.Join(home, ".zshrc"))
	for line := range strings.SplitSeq(got, "\n") {
		if strings.Contains(line, "init-posix.sh") {
			if strings.ContainsAny(line, "\r  ") {
				t.Errorf("source line contains embedded newline-like char: %q", line)
			}
		}
	}
}

func TestInstall_MultipleRcFiles(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc":   "export Z=1\n",
		".bashrc":  "export B=1\n",
		".profile": "export P=1\n",
	})
	rcs, err := Install(osmHome)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(rcs) != 3 {
		t.Errorf("expected 3 rc files updated, got %d", len(rcs))
	}
	for _, name := range []string{".zshrc", ".bashrc", ".profile"} {
		got := readFile(t, filepath.Join(home, name))
		if !strings.Contains(got, "init-posix.sh") {
			t.Errorf("%s: source line missing", name)
		}
	}
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

func TestUninstall_RemovesSourceLine(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rcs, err := Uninstall()
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if len(rcs) == 0 {
		t.Fatal("Uninstall reported nothing cleared")
	}
	got := readFile(t, filepath.Join(home, ".zshrc"))
	if strings.Contains(got, "init-posix.sh") {
		t.Errorf("source line still present after uninstall: %q", got)
	}
}

func TestUninstall_PreservesOtherLines(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\nexport FOO=bar\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	got := readFile(t, filepath.Join(home, ".zshrc"))
	if !strings.Contains(got, "export PATH=$PATH") || !strings.Contains(got, "export FOO=bar") {
		t.Errorf("other lines lost after uninstall: %q", got)
	}
}

func TestUninstall_NotInstalled_NoError(t *testing.T) {
	setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	rcs, err := Uninstall()
	if err != nil {
		t.Fatalf("Uninstall on clean file: %v", err)
	}
	if len(rcs) != 0 {
		t.Errorf("expected 0 cleared, got %d", len(rcs))
	}
}

func TestUninstall_BackupCreated(t *testing.T) {
	home, osmHome := setupHome(t, map[string]string{
		".zshrc": "original\n",
	})
	rc := filepath.Join(home, ".zshrc")
	bak := rc + ".osm.bak"
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// remove backup to test uninstall creates its own backup if none exists yet
	_ = os.Remove(bak)
	// re-add source line manually to simulate fresh install w/o backup
	writeFile(t, rc, "original\nsource /osm/scripts/init-posix.sh # opensecretmask\n")
	if _, err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(bak); err != nil {
		t.Errorf("backup not created by Uninstall: %v", err)
	}
}

// ── Status ────────────────────────────────────────────────────────────────────

func TestStatus_Installed(t *testing.T) {
	_, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	statuses, scriptPresent, err := Status(osmHome)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !scriptPresent {
		t.Error("expected scriptPresent=true after Install")
	}
	var found bool
	for _, s := range statuses {
		if strings.HasSuffix(s.Path, ".zshrc") {
			if !s.Exists {
				t.Error(".zshrc: Exists should be true")
			}
			if !s.Installed {
				t.Error(".zshrc: Installed should be true")
			}
			found = true
		}
	}
	if !found {
		t.Error("Status did not include .zshrc entry")
	}
}

func TestStatus_NotInstalled(t *testing.T) {
	_, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	statuses, scriptPresent, err := Status(osmHome)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if scriptPresent {
		t.Error("expected scriptPresent=false before Install")
	}
	for _, s := range statuses {
		if strings.HasSuffix(s.Path, ".zshrc") {
			if !s.Exists {
				t.Error(".zshrc: Exists should be true")
			}
			if s.Installed {
				t.Error(".zshrc: Installed should be false before Install")
			}
		}
	}
}

func TestStatus_MissingRcFile(t *testing.T) {
	// home has no rc files at all
	_, osmHome := setupHome(t, map[string]string{})
	statuses, _, err := Status(osmHome)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, s := range statuses {
		if s.Exists {
			t.Errorf("no rc files created, but %s reports Exists=true", s.Path)
		}
		if s.Installed {
			t.Errorf("no rc files created, but %s reports Installed=true", s.Path)
		}
	}
}

func TestStatus_AfterUninstall(t *testing.T) {
	_, osmHome := setupHome(t, map[string]string{
		".zshrc": "export PATH=$PATH\n",
	})
	if _, err := Install(osmHome); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	statuses, _, err := Status(osmHome)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, s := range statuses {
		if strings.HasSuffix(s.Path, ".zshrc") && s.Installed {
			t.Error(".zshrc: Installed should be false after Uninstall")
		}
	}
}
