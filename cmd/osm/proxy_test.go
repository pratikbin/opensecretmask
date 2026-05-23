package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestProxyCmd_HelpListsFlags(t *testing.T) {
	c := newProxyCmd()
	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetArgs([]string{"--help"})
	if err := c.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"--bind", "--upstream"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %s; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--auth-token") {
		t.Errorf("--auth-token should not exist in MVP; got:\n%s", out)
	}
}
