package detector

import (
	"strings"
	"testing"
)

func BenchmarkScan100KB(b *testing.B) {
	d := newFuzzDetector(b)
	text := strings.Repeat("lorem ipsum dolor sit amet sk_live_4eC39HqLyjWDarjtT1zdp7dc ", 1500)
	if len(text) < 100*1024 {
		text = strings.Repeat(text, 100*1024/len(text)+1)
	}
	text = text[:100*1024]
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(text)
	}
}

func BenchmarkScan1MB(b *testing.B) {
	d := newFuzzDetector(b)
	text := strings.Repeat("the quick brown fox jumps over the lazy dog ", 24000)
	if len(text) < 1024*1024 {
		text = strings.Repeat(text, 1024*1024/len(text)+1)
	}
	text = text[:1024*1024]
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(text)
	}
}
