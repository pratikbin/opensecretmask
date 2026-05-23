package proxy

import "testing"

func TestPathScopedForMask(t *testing.T) {
	cases := map[string]bool{
		"/v1/messages":              true,
		"/v1/messages/count_tokens": true,
		"/v1/files":                 false,
		"/v1/models":                false,
		"/":                         false,
		"/v1/messages/foo":          false,
	}
	for p, want := range cases {
		if got := pathScopedForMask(p); got != want {
			t.Errorf("pathScopedForMask(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestPathScopedForUnmask(t *testing.T) {
	cases := map[string]bool{
		"/v1/messages":              true,
		"/v1/messages/count_tokens": false,
		"/v1/files":                 false,
		"/v1/models":                false,
	}
	for p, want := range cases {
		if got := pathScopedForUnmask(p); got != want {
			t.Errorf("pathScopedForUnmask(%q) = %v, want %v", p, got, want)
		}
	}
}
