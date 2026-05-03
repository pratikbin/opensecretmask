package claudecode

import (
	"fmt"
	"strings"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"mvdan.cc/sh/v3/syntax"
)

type BashDecision string

const (
	BashSkip  BashDecision = "skip"
	BashDeny  BashDecision = "deny"
	BashAsk   BashDecision = "ask"
	BashAllow BashDecision = "allow"
)

type BashGate struct {
	cfg store.BashConfig
}

func NewBashGate(cfg store.BashConfig) *BashGate {
	return &BashGate{cfg: cfg}
}

// Classify decides ALLOW / ASK / DENY for a Bash command.
// `replacements` is the number of mask→real substitutions made on the command before
// classification. If 0, fast-path SKIP — no scanning required.
func (g *BashGate) Classify(cmd string, replacements int) (BashDecision, string) {
	if replacements == 0 {
		return BashSkip, ""
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	prog, err := parser.Parse(strings.NewReader(cmd), "cmd")
	if err != nil {
		return BashAsk, "parse error: " + err.Error()
	}
	dec, reason := g.walk(prog, cmd)
	if dec == "" {
		switch g.cfg.DefaultDecision {
		case "allow":
			return BashAllow, "default: allow"
		case "deny":
			return BashDeny, "default: deny"
		default:
			return BashAsk, "default: ask"
		}
	}
	return dec, reason
}

func (g *BashGate) walk(prog *syntax.File, fullCmd string) (BashDecision, string) {
	// Normalize quotes/punctuation to spaces so " curl " matches inside `bash -c 'curl ...'`.
	normalized := " " + strings.Map(func(r rune) rune {
		switch r {
		case '\'', '"', '`', '$', '(', ')', ';', '\n', '\t':
			return ' '
		}
		return r
	}, fullCmd) + " "

	// 1. /dev/tcp redirect targets → DENY.
	if strings.Contains(fullCmd, "/dev/tcp/") {
		return BashDeny, "writes to /dev/tcp/* (network egress)"
	}

	// 2. Egress blocklist substring scan over normalized padded string.
	for _, tok := range g.cfg.EgressBlocklist {
		needle := " " + tok + " "
		if strings.Contains(normalized, needle) {
			return BashDeny, "blocked: " + tok
		}
	}

	// 3. Walk AST for structural signals.
	var (
		decision BashDecision
		reason   string
		hasPipe  bool
		hasRedir bool
	)
	setIfEmpty := func(d BashDecision, why string) {
		if decision == "" {
			decision = d
			reason = why
		}
	}

	syntax.Walk(prog, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Subshell:
			if g.cfg.TreatSubshellAsDeny {
				setIfEmpty(BashDeny, "subshell")
			}
			return false
		case *syntax.CmdSubst:
			setIfEmpty(BashDeny, "command substitution")
			return false
		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				hasPipe = true
			}
		case *syntax.Redirect:
			hasRedir = true
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				return true
			}
			head := wordToString(n.Args[0])
			switch head {
			case "eval":
				setIfEmpty(BashDeny, "eval")
				return false
			case "source", ".":
				setIfEmpty(BashDeny, "source/. operator")
				return false
			}
		}
		return true
	})

	if decision == BashDeny {
		return decision, reason
	}

	// 4. Pipe / redirect signals.
	if hasPipe && g.cfg.TreatPipeAsAsk {
		setIfEmpty(BashAsk, "pipe present")
	}
	if hasRedir && g.cfg.TreatRedirectAsAsk {
		setIfEmpty(BashAsk, "redirect present")
	}

	// 5. If no structural signal, check local_allowlist against leading tokens.
	if decision == "" {
		fields := strings.Fields(strings.TrimSpace(fullCmd))
		maxN := len(fields)
		if maxN > 3 {
			maxN = 3
		}
		for n := maxN; n >= 1; n-- {
			candidate := strings.Join(fields[:n], " ")
			for _, allow := range g.cfg.LocalAllowlist {
				if candidate == allow {
					return BashAllow, "allowlisted: " + allow
				}
			}
		}
	}

	return decision, reason
}

// wordToString extracts a literal string from a syntax.Word (best-effort).
func wordToString(w *syntax.Word) string {
	var sb strings.Builder
	for _, p := range w.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			sb.WriteString(part.Value)
		default:
			sb.WriteString(fmt.Sprintf("<%T>", part))
		}
	}
	return sb.String()
}
