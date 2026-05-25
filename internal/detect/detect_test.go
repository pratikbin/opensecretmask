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
	var want int
	for _, p := range DefaultProviders() {
		want += len(p.Rules())
	}
	if d.RuleCount() != want {
		t.Fatalf("compiled %d rules, want %d", d.RuleCount(), want)
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

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func assertRuleFires(t *testing.T, d *Detector, body, rule string) {
	t.Helper()
	got := d.Scan([]byte(body))
	for _, f := range got {
		if f.Rule == rule {
			return
		}
	}
	t.Errorf("body %q: findings %+v missing rule %q", body, got, rule)
}

func TestLLMProviderMatches(t *testing.T) {
	d := newDetector(t, Config{})
	cases := []struct {
		body string
		rule string
	}{
		{`Authorization: Bearer pplx-` + repeat("a", 45), "Perplexity API Key"},
		{`{"k":"ABSK` + repeat("A", 110) + `"}`, "AWS Bedrock Long-Lived Key"},
		{`X-Bedrock: bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t`, "AWS Bedrock Short-Lived Key"},
	}
	for _, tc := range cases {
		assertRuleFires(t, d, tc.body, tc.rule)
	}
}

func TestGitProviderMatches(t *testing.T) {
	d := newDetector(t, Config{})
	cases := []struct {
		body string
		rule string
	}{
		{`glptt-` + repeat("a", 40), "GitLab Pipeline Trigger Token"},
		{`GR1348941` + repeat("a", 20), "GitLab Runner Registration Token"},
		{`glft-` + repeat("a", 20), "GitLab Feed Token"},
		{`glimt-` + repeat("a", 25), "GitLab Incoming Mail Token"},
		{`glagent-` + repeat("a", 50), "GitLab Kubernetes Agent Token"},
		{`glcbt-` + repeat("a", 30), "GitLab CI/CD Job Token"},
		{`gldt-` + repeat("a", 20), "GitLab Deploy Token"},
		{`glsoat-` + repeat("a", 30), "GitLab SCIM Token"},
	}
	for _, tc := range cases {
		assertRuleFires(t, d, tc.body, tc.rule)
	}
}

func TestChatProviderMatches(t *testing.T) {
	d := newDetector(t, Config{})
	cases := []struct {
		body string
		rule string
	}{
		{`{"t":"xoxe.xoxp-1-` + repeat("a", 50) + `"}`, "Slack Config Access Token"},
		{`xoxe-1-` + repeat("a", 50), "Slack Config Refresh Token"},
		{`https://hooks.slack.com/services/T01234567/B01234567/` + repeat("a", 24), "Slack Webhook URL"},
	}
	for _, tc := range cases {
		assertRuleFires(t, d, tc.body, tc.rule)
	}
}

func TestCloudProviderMatches(t *testing.T) {
	d := newDetector(t, Config{})
	cases := []struct {
		body string
		rule string
	}{
		{`AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L`, "Age Secret Key"},
		{`{"id":"LTAIabcdefghij0123456789"}`, "Alibaba Access Key ID"},
		{`hdr=AKCp` + repeat("a", 69), "Artifactory API Key"},
		{`cf:v1.0-abcdef0123456789abcdef01-` + repeat("a", 146), "Cloudflare Origin CA Key"},
		{`{"t":"dp.pt.` + repeat("a", 40) + `"}`, "Doppler Token"},
		{`x:dt0c01.` + repeat("A", 24) + `.` + repeat("A", 64), "Dynatrace API Token"},
		{`FLWSECK_TEST-` + repeat("a", 32) + `-X`, "Flutterwave Secret Key"},
		{`glc_` + repeat("a", 40), "Grafana Cloud API Token"},
		{`glsa_` + repeat("a", 32) + `_abcdef01`, "Grafana Service Account Token"},
		{`HRKU-AA` + repeat("a", 25), "Heroku API Key v2"},
		{`dckr_pat_` + repeat("a", 30), "Docker PAT"},
		{`nfp_` + repeat("a", 42), "Netlify Access Token"},
	}
	for _, tc := range cases {
		assertRuleFires(t, d, tc.body, tc.rule)
	}
}
