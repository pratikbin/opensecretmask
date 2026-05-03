package main

import (
	"bytes"
	"testing"
)

func BenchmarkHook_PostToolUseEmpty(b *testing.B) {
	dir := b.TempDir()
	b.Setenv("OPENSECRETMASK_HOME", dir)
	root := newRootCmd()
	root.SetArgs([]string{"init"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		b.Fatal(err)
	}
	stdin := `{"hook_event_name":"PostToolUse","tool_name":"Read","tool_response":{"content":"plain"}}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := newRootCmd()
		r.SetArgs([]string{"hook", "--harness=claudecode", "posttooluse"})
		r.SetIn(bytes.NewReader([]byte(stdin)))
		out := &bytes.Buffer{}
		r.SetOut(out)
		r.SetErr(out)
		if err := r.Execute(); err != nil {
			b.Fatal(err)
		}
	}
}
