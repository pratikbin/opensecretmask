package detector

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func benchMask(_, _ string) (string, error) { return "[masked]", nil }

func BenchmarkScanner_Stream_1MB_NoSecrets(b *testing.B) {
	det := newFuzzDetector(b)
	rules := BuiltinRules()
	text := strings.Repeat("the quick brown fox jumps over the lazy dog ", 1024*1024/44+1)
	text = text[:1024*1024]
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(det, rules, 100*1024*1024, 1*1024*1024, benchMask)
		if err := s.Stream(strings.NewReader(text), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanner_Stream_1MB_With100Secrets(b *testing.B) {
	det := newFuzzDetector(b)
	rules := BuiltinRules()
	chunk := "lorem ipsum dolor sit amet sk_live_4eC39HqLyjWDarjtT1zdp7dc consectetur "
	text := strings.Repeat(chunk, 1024*1024/len(chunk)+1)
	text = text[:1024*1024]
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(det, rules, 100*1024*1024, 1*1024*1024, benchMask)
		if err := s.Stream(strings.NewReader(text), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanner_Stream_LargePEMContainer(b *testing.B) {
	det := newFuzzDetector(b)
	rules := BuiltinRules()
	body := strings.Repeat("MIICXAIBAAKBgQDfX1RAFWLqBQVqsCdYZ\n", 200)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----\n"
	text := "preamble\n" + pem + "trailer\n"
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := NewScanner(det, rules, 100*1024*1024, 1*1024*1024, benchMask)
		if err := s.Stream(strings.NewReader(text), bytes.NewBuffer(nil)); err != nil {
			b.Fatal(err)
		}
	}
}
