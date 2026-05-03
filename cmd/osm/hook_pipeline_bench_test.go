package main

import (
	"bytes"
	"strings"
	"testing"
)

func BenchmarkHookPipeline_PostToolUse_MaskStripeKey(b *testing.B) {
	dir := b.TempDir()
	b.Setenv("OPENSECRETMASK_HOME", dir)
	root := newRootCmd()
	root.SetArgs([]string{"init"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		b.Fatal(err)
	}

	stdin := `{"hook_event_name":"PostToolUse","tool_name":"Read","session_id":"s1","tool_response":{"content":"line1\nbefore sk_live_4eC39HqLyjWDarjtT1zdp7dc after\nline3\nsk_live_4eC39HqLyjWDarjtT1zdp7dc again\n"}}`
	b.SetBytes(int64(len(stdin)))
	b.ReportAllocs()
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

func BenchmarkHookPipeline_PostToolUse_LargePayload(b *testing.B) {
	dir := b.TempDir()
	b.Setenv("OPENSECRETMASK_HOME", dir)
	root := newRootCmd()
	root.SetArgs([]string{"init"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		b.Fatal(err)
	}

	body := strings.Repeat("the quick brown fox sk_live_4eC39HqLyjWDarjtT1zdp7dc jumps ", 200)
	stdin := `{"hook_event_name":"PostToolUse","tool_name":"Read","session_id":"s1","tool_response":{"content":"` + body + `"}}`
	b.SetBytes(int64(len(stdin)))
	b.ReportAllocs()
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
