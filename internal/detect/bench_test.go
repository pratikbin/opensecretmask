package detect

import "testing"

// benchBody is a realistic LLM request payload carrying no credentials — the
// common case the literal-prefix gate accelerates.
func benchBody() []byte {
	const s = `{"model":"claude-opus","max_tokens":4096,"messages":[{"role":"user",` +
		`"content":"Explain how the Go scheduler handles preemption of long-running ` +
		`loops, why it matters for latency-sensitive services, and how GOMAXPROCS ` +
		`interacts with the netpoller under heavy concurrent request load."}]}`
	return []byte(s)
}

func BenchmarkScanNoSecret(b *testing.B) {
	d, err := New(Config{})
	if err != nil {
		b.Fatal(err)
	}
	body := benchBody()
	b.ReportAllocs()
	for b.Loop() {
		if f := d.Scan(body); len(f) != 0 {
			b.Fatalf("unexpected findings: %d", len(f))
		}
	}
}

