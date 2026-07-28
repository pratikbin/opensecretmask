package detect

import (
	"sync"
	"testing"
)

var sharedDetector = sync.OnceValue(func() *Detector {
	d, err := New(Config{}, DefaultProviders()...)
	if err != nil {
		panic("sharedDetector: " + err.Error())
	}
	return d
})

func newDetector(t *testing.T, cfg Config) *Detector {
	t.Helper()
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestAllRulesCompile(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
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
	t.Parallel()
	d := sharedDetector()
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
	t.Parallel()
	d := sharedDetector()
	got := d.Scan([]byte(`API_SECRET_KEY=s3cr3tValuePayload123`))
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %+v", got)
	}
	if got[0].Value != "s3cr3tValuePayload123" {
		t.Fatalf("context rule should capture only the secret, got %q", got[0].Value)
	}
}

func TestLiteralPrefixLen(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
	if got := d.LiteralPrefixLen("sk-ant-api03-xxxxxxxxxx"); got != len("sk-ant-") {
		t.Fatalf("Anthropic key prefix len = %d, want %d", got, len("sk-ant-"))
	}
	if got := d.LiteralPrefixLen("just-some-plain-text"); got != 0 {
		t.Fatalf("non-credential prefix len = %d, want 0", got)
	}
}

func TestEntropyLayerToggle(t *testing.T) {
	t.Parallel()
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
	for range n {
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
	t.Parallel()
	d := sharedDetector()
	cases := []struct {
		body string
		rule string
	}{
		{`Authorization: Bearer pplx-` + repeat("a", 45), "Perplexity API Key"},
		{`{"k":"ABSK` + repeat("A", 110) + `"}`, "AWS Bedrock Long-Lived Key"},
		{`X-Bedrock: bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t`, "AWS Bedrock Short-Lived Key"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

func TestDevtoolsProviderMatches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
	cases := []struct {
		body string
		rule string
	}{
		{`pscale_tkn_` + repeat("a", 40), "PlanetScale API Token"},
		{`pscale_oauth_` + repeat("a", 40), "PlanetScale OAuth Token"},
		{`pscale_pw_` + repeat("a", 40), "PlanetScale Password"},
		{`PMAK-` + repeat("a", 24) + `-` + repeat("b", 34), "Postman API Token"},
		{`pnu_` + repeat("a", 36), "Prefect API Token"},
		{`sgp_` + repeat("a", 40), "Sourcegraph Access Token"},
		{`tfp_` + repeat("a", 59), "Typeform API Token"},
		{`ico-` + repeat("a", 32), "Infracost API Token"},
		{`ops_eyJ` + repeat("a", 260), "1Password Service Account"},
		{`A3-ABCDEF-ABCDEFGHIJK-ABCDE-FGHIJ-KLMNO`, "1Password Secret Key"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

func TestCloudRound2Matches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
	cases := []struct {
		body string
		rule string
	}{
		{`xkeysib-` + repeat("a", 64) + `-` + repeat("A", 16), "Sendinblue API Token"},
		{`shpat_` + repeat("a", 32), "Shopify Access Token"},
		{`shpca_` + repeat("a", 32), "Shopify Custom Access Token"},
		{`shppa_` + repeat("a", 32), "Shopify Private App Access Token"},
		{`sq0atp-` + repeat("a", 30), "Square Access Token"},
		{`EAAA` + repeat("a", 30), "Square Access Token"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

func TestGitProviderMatches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
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
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

func TestChatProviderMatches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
	cases := []struct {
		body string
		rule string
	}{
		{`{"t":"xoxe.xoxp-1-` + repeat("a", 50) + `"}`, "Slack Config Access Token"},
		{`xoxe-1-` + repeat("a", 50), "Slack Config Refresh Token"},
		{`https://hooks.slack.com/services/T01234567/B01234567/` + repeat("a", 24), "Slack Webhook URL"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

// TestRound3Matches covers the round-3 gitleaks-derived rules spanning
// the llm, cloud, git and devtools providers. Each literal uses 'a'
// filler, valid across every charset (hex, base64url, alnum).
func TestRound3Matches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
	cases := []struct {
		body string
		rule string
	}{
		{`api_org_` + repeat("a", 34), "Hugging Face Organization API Token"},
		{`doo_v1_` + repeat("a", 64), "DigitalOcean OAuth Access Token"},
		{`dor_v1_` + repeat("a", 64), "DigitalOcean OAuth Refresh Token"},
		{`hvb.` + repeat("a", 138), "HashiCorp Vault Batch Token"},
		{`NRII-` + repeat("a", 32), "New Relic Insights Insert Key"},
		{`pul-` + repeat("a", 40), "Pulumi API Token"},
		{`sha256~` + repeat("a", 43), "OpenShift User Token"},
		{`shpss_` + repeat("a", 32), "Shopify Shared Secret"},
		{`tk-us-` + repeat("a", 48), "Scalingo API Token"},
		{`dnkey-` + repeat("a", 26) + `-` + repeat("a", 52), "Defined Networking API Token"},
		{`gloas-` + repeat("a", 64), "GitLab OIDC Application Secret"},
		{`glrt-` + repeat("a", 20), "GitLab Runner Authentication Token"},
		{`Cookie: _gitlab_session=` + repeat("a", 32), "GitLab Session Cookie"},
		{`p8e-` + repeat("a", 32), "Adobe Client Secret"},
		{`CLOJARS_` + repeat("a", 60), "Clojars API Token"},
		{`duffel_live_` + repeat("a", 43), "Duffel API Token"},
		{`fio-u-` + repeat("a", 64), "Frame.io API Token"},
		{`s-s4t2ud-` + repeat("a", 64), "Intra42 Client Secret"},
		{`rdme_` + repeat("a", 70), "Readme API Token"},
		{`rubygems_` + repeat("a", 48), "RubyGems API Token"},
		{`sntryu_` + repeat("a", 64), "Sentry User Token"},
		{`shippo_live_` + repeat("a", 40), "Shippo API Token"},
		{`sm_aat_` + repeat("a", 16), "SettleMint Application Access Token"},
		{`sm_pat_` + repeat("a", 16), "SettleMint Personal Access Token"},
		{`sm_sat_` + repeat("a", 16), "SettleMint Service Access Token"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

func TestCloudProviderMatches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
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
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}

// TestRound4Matches covers the round-4 rules derived from the trufflehog
// detector catalog and the local ~/workspace scan (OpenAI legacy, DeepSeek,
// Copperx and FC were observed live on disk).
func TestRound4Matches(t *testing.T) {
	t.Parallel()
	d := sharedDetector()
	cases := []struct {
		body string
		rule string
	}{
		{`lsv2_pt_` + repeat("a", 32) + `_` + repeat("a", 10), "LangSmith API Key"},
		{`nvapi-` + repeat("a", 64), "NVIDIA API Key"},
		{`sk-` + repeat("a", 20) + `T3BlbkFJ` + repeat("a", 20), "OpenAI API Key (legacy)"},
		{`rootly_` + repeat("a", 64), "Rootly API Token"},
		{`salad_cloud_` + repeat("a", 4) + `_` + repeat("a", 20), "SaladCloud API Key"},
		{`sbp_` + repeat("a", 40), "Supabase Personal Access Token"},
		{`sq0idp-` + repeat("a", 22), "Square OAuth Secret"},
		{`FLWSECK-` + repeat("a", 32) + `-X`, "Flutterwave Live Secret Key"},
		{`cmVmdGtu` + repeat("a", 56), "Artifactory Reference Token"},
		{`CCIPAT_` + repeat("a", 22) + `_` + repeat("a", 40), "CircleCI Personal Access Token"},
		{`CFPAT-` + repeat("a", 43), "Contentful Personal Access Token"},
		{`bkua_` + repeat("a", 40), "Buildkite User Access Token"},
		{`endr+` + repeat("a", 16), "Endor Labs API Key"},
		{`slk_` + repeat("a", 64), "Sourcegraph Cody Access Token"},
		{`shltm_` + repeat("a", 40), "Flexport API Token"},
		{`phx_` + repeat("a", 43), "PostHog Personal API Key"},
		{`BBFF-` + repeat("a", 30), "Ubidots Token"},
		{`pav1_` + repeat("a", 64), "Copperx API Key"},
		{`rh-api-` + repeat("a", 8) + `-` + repeat("a", 4) + `-` + repeat("a", 4) + `-` + repeat("a", 4) + `-` + repeat("a", 12), "Robinhood Crypto API Key"},
		{`ramp_sec_` + repeat("a", 48), "Ramp API Secret"},
		{`3MVG9` + repeat("a", 80), "Salesforce OAuth Token"},
		{`5AEP861` + repeat("a", 80), "Salesforce Refresh Token"},
		{`flb_live_` + repeat("a", 20), "Fleetbase API Key"},
		{`u-s4t2ud-` + repeat("a", 64), "Intra42 User Token"},
		{`pat-na1-` + repeat("a", 8) + `-` + repeat("a", 4) + `-` + repeat("a", 4) + `-` + repeat("a", 4) + `-` + repeat("a", 12), "HubSpot Private App Token"},
		{`skp_` + repeat("a", 32), "FC API Key"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			assertRuleFires(t, d, tc.body, tc.rule)
		})
	}
}
