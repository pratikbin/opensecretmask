# opensecretmask

`osm` is a Go-based credential masking hook binary for AI coding agents. It intercepts tool I/O for claude-code, masks secrets before they reach the LLM, and unmasks them before tool execution.

See the design spec at [`docs/superpowers/specs/2026-05-02-opensecretmask-design.md`](docs/superpowers/specs/2026-05-02-opensecretmask-design.md).
