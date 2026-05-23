package proxy

import (
	"fmt"
	"log/slog"
	"strings"
)

// goproxyLogger adapts goproxy's Printf-based Logger to slog. With Verbose off,
// goproxy emits only operational noise — client disconnects, upstream resets —
// which is benign for a local masking proxy, so every line lands at debug
// level: visible with --log-level=debug, silent otherwise.
type goproxyLogger struct {
	logger *slog.Logger
}

func (g goproxyLogger) Printf(format string, v ...any) {
	g.logger.Debug("goproxy: " + strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
}
