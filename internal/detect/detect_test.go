package detect

import "testing"

func newDetector(t *testing.T, cfg Config) *Detector {
	t.Helper()
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestAllRulesCompile(t *testing.T) {
	d := newDetector(t, Config{})
	if d.RuleCount() != len(builtinRules) {
		t.Fatalf("compiled %d rules, want %d", d.RuleCount(), len(builtinRules))
	}
	if d.RuleCount() < 40 {
		t.Fatalf("expected the full vendored rule set, got only %d", d.RuleCount())
	}
}

func TestScanFindsCredentials(t *testing.T) {
	d := newDetector(t, Config{})
	body := []byte(`{"content":"key sk-ant-api03-abcdef1234567890ABCDEF and ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`)
	want := map[string]string{
		"sk-ant-api03-abcdef1234567890ABCDEF":      "Anthropic API Key",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789": "GitHub Token",
	}
	got := d.Scan(body)
	if len(got) != len(want) {
		t.Fatalf("found %d secrets, want %d: %+v", len(got), len(want), got)
	}
	for _, f := range got {
		if want[f.Value] != f.Rule {
			t.Fatalf("value %q: rule %q, want %q", f.Value, f.Rule, want[f.Value])
		}
	}
}

func TestScanContextRuleCapturesSecretOnly(t *testing.T) {
	d := newDetector(t, Config{})
	got := d.Scan([]byte(`API_SECRET_KEY=s3cr3tValuePayload123`))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %+v", got)
	}
	if got[0].Value != "s3cr3tValuePayload123" {
		t.Fatalf("context rule should capture only the secret, got %q", got[0].Value)
	}
}

func TestLiteralPrefixLen(t *testing.T) {
	d := newDetector(t, Config{})
	if got := d.LiteralPrefixLen("sk-ant-api03-xxxxxxxxxx"); got != len("sk-ant-") {
		t.Fatalf("Anthropic key prefix len = %d, want %d", got, len("sk-ant-"))
	}
	if got := d.LiteralPrefixLen("just-some-plain-text"); got != 0 {
		t.Fatalf("non-credential prefix len = %d, want 0", got)
	}
}

func TestEntropyLayerToggle(t *testing.T) {
	body := []byte("token Xq7mK2pLz9wRt4vNc8bYf3hJd6sGa1e here")

	off := newDetector(t, Config{})
	if n := len(off.Scan(body)); n != 0 {
		t.Fatalf("entropy disabled but %d tokens flagged", n)
	}

	on := newDetector(t, Config{Entropy: true})
	got := on.Scan(body)
	if len(got) != 1 || got[0].Rule != "entropy" {
		t.Fatalf("entropy enabled: got %+v, want 1 entropy finding", got)
	}
}
