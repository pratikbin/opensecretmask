package detect

import "regexp"

// gitRules cover GitLab token variants beyond the personal access
// token (glpat-) already in builtinRules. GitHub variants are already
// fully covered by the builtin gh[pousr]_ and github_pat_ rules.
var gitRules = []Rule{
	{"GitLab Pipeline Trigger Token", "critical", regexp.MustCompile(`glptt-[0-9a-f]{40}`), 0},
	{"GitLab Runner Registration Token", "critical", regexp.MustCompile(`GR1348941[0-9a-zA-Z_\-]{20}`), 0},
	{"GitLab Feed Token", "high", regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`), 0},
	{"GitLab Incoming Mail Token", "high", regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`), 0},
	{"GitLab Kubernetes Agent Token", "critical", regexp.MustCompile(`glagent-[0-9a-zA-Z_\-]{50}`), 0},
	{"GitLab CI/CD Job Token", "critical", regexp.MustCompile(`glcbt-[0-9a-zA-Z_\-]{20,}`), 0},
	{"GitLab Deploy Token", "critical", regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`), 0},
	{"GitLab SCIM Token", "critical", regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20,}`), 0},
	// Round-3 (gitleaks): OIDC application secret, runner authentication
	// token (GitLab 16.0+), and the session cookie value (group 1 keeps
	// the cookie name out of the mask).
	{"GitLab OIDC Application Secret", "critical", regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`), 0},
	{"GitLab Runner Authentication Token", "critical", regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`), 0},
	{"GitLab Session Cookie", "high", regexp.MustCompile(`_gitlab_session=([0-9a-z]{32})`), 1},
}

type gitProvider struct{}

func (gitProvider) Name() string  { return "git" }
func (gitProvider) Rules() []Rule { return gitRules }
