package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
	"github.com/pratikbin/opensecretmask/internal/core/engine"
	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/pratikbin/opensecretmask/internal/harness"
	"github.com/pratikbin/opensecretmask/internal/harness/claudecode"
	"github.com/spf13/cobra"
)

func newHookCmd() *cobra.Command {
	var harnessFlag string
	c := &cobra.Command{
		Use:   "hook EVENT",
		Short: "Run hook event handler (called by AI agent harnesses)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			event := args[0]
			// Re-entrancy guard: avoid recursion when osm calls itself.
			if os.Getenv("OSM_RUNNING") == "1" {
				_, _ = cmd.OutOrStdout().Write([]byte("{}"))
				return nil
			}
			_ = os.Setenv("OSM_RUNNING", "1")
			defer os.Unsetenv("OSM_RUNNING")

			adp := pickAdapter(harnessFlag)
			eng, perr := bootstrapEngine()
			if perr != nil {
				return emitPreconditionFailure(event, cmd.OutOrStdout(), perr)
			}
			req, raw, err := adp.ParseRequest(cmd.InOrStdin())
			if err != nil {
				return emitParseFailure(cmd.OutOrStdout(), err)
			}
			req.EventName = event

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			switch req.Direction {
			case harness.DirMask:
				return runMask(ctx, eng, adp, req, raw, cmd.OutOrStdout())
			case harness.DirUnmask:
				return runUnmask(ctx, eng, adp, req, raw, cmd.OutOrStdout())
			case harness.DirObserve:
				return runObserve(ctx, eng, adp, req, raw, cmd.OutOrStdout())
			}
			_, _ = cmd.OutOrStdout().Write([]byte("{}"))
			return nil
		},
	}
	c.Flags().StringVar(&harnessFlag, "harness", "claudecode", "harness adapter name")
	return c
}

func pickAdapter(_ string) harness.Adapter {
	// Only claudecode is wired in v1.
	return claudecode.New()
}

func bootstrapEngine() (*engine.Engine, error) {
	root, err := store.Root()
	if err != nil {
		return nil, err
	}
	cfg, err := store.LoadConfig(filepath.Join(root, store.ConfigName))
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	keyBytes, err := keymgr.LoadOrError(root)
	if err != nil {
		return nil, fmt.Errorf("install.key: %w", err)
	}
	hasher := keymgr.NewHasher(keyBytes)
	lock, err := store.OpenLock(root)
	if err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	allow, err := store.LoadAllowlist(filepath.Join(root, store.AllowlistName))
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	secs, err := store.LoadSecrets(filepath.Join(root, store.SecretsName))
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	rules := detector.BuiltinRules()
	al, err := detector.NewAllowlistSet(allow.Values, allow.Patterns, allow.RulesDisabled)
	if err != nil {
		return nil, err
	}
	ent := detector.NewEntropyScanner(cfg.Detector.Entropy.Threshold, cfg.Detector.Entropy.MinLength)
	regValues := make([]string, 0, len(secs.Secrets))
	for _, e := range secs.Secrets {
		regValues = append(regValues, e.Value)
	}
	det := detector.NewDetector(detector.NewRegisteredSet(regValues), rules, ent, al)
	au := store.NewAuditWriter(filepath.Join(root, store.AuditName), cfg.Audit.TruncateMaskTo)
	return &engine.Engine{
		Cfg: cfg, Hasher: hasher, Lock: lock, Detector: det,
		Audit: au, Root: root, Allowlist: allow, Rules: rules,
	}, nil
}

func runMask(ctx context.Context, eng *engine.Engine, adp harness.Adapter, req *harness.Request, raw json.RawMessage, w io.Writer) error {
	resp := &harness.Response{}
	for _, t := range req.Targets {
		masked, _, err := eng.MaskText(ctx, req.SessionID, req.Harness, t.Content)
		if err != nil {
			// fail-closed per cfg.Hooks.MaskOnError
			switch eng.Cfg.Hooks.MaskOnError {
			case "redact-all":
				resp.Modified = true
				resp.Targets = append(resp.Targets, harness.Target{Path: t.Path, Content: "[opensecretmask: redacted]"})
			default:
				resp.DenyReason = "opensecretmask: mask failed: " + err.Error()
				return adp.EmitResponse(w, raw, resp)
			}
			continue
		}
		if masked != t.Content {
			resp.Modified = true
		}
		resp.Targets = append(resp.Targets, harness.Target{Path: t.Path, Content: masked})
	}
	if !resp.Modified {
		_, err := w.Write([]byte("{}"))
		return err
	}
	return adp.EmitResponse(w, raw, resp)
}

func runUnmask(_ context.Context, eng *engine.Engine, adp harness.Adapter, req *harness.Request, raw json.RawMessage, w io.Writer) error {
	resp := &harness.Response{}
	totalReplacements := 0
	var lastBashCmd string
	for _, t := range req.Targets {
		out, n, err := eng.UnmaskText(t.Content)
		if err != nil {
			// fail-open: passthrough (write {}, don't modify)
			_, werr := w.Write([]byte("{}"))
			return werr
		}
		totalReplacements += n
		if out != t.Content {
			resp.Modified = true
		}
		if req.ToolName == "Bash" && len(t.Path) > 0 && t.Path[0] == "command" {
			lastBashCmd = out
		}
		resp.Targets = append(resp.Targets, harness.Target{Path: t.Path, Content: out})
	}
	if req.ToolName == "Bash" && lastBashCmd != "" {
		gate := claudecode.NewBashGate(eng.Cfg.Harness.Claudecode.Bash)
		dec, _ := gate.Classify(lastBashCmd, totalReplacements)
		if dec == claudecode.BashDeny {
			resp.DenyReason = "opensecretmask: bash egress denied"
			return adp.EmitResponse(w, raw, resp)
		}
	}
	if !resp.Modified {
		_, err := w.Write([]byte("{}"))
		return err
	}
	return adp.EmitResponse(w, raw, resp)
}

func runObserve(ctx context.Context, eng *engine.Engine, adp harness.Adapter, req *harness.Request, raw json.RawMessage, w io.Writer) error {
	resp := &harness.Response{}
	if req.EventName == "UserPromptSubmit" {
		for _, t := range req.Targets {
			hits := eng.Detector.Detect(t.Content)
			if len(hits) > 0 && eng.Cfg.Harness.Claudecode.WarnOnPrompt {
				resp.Notes = append(resp.Notes, fmt.Sprintf("opensecretmask: %d possible secret(s) in your prompt", len(hits)))
			}
		}
		return adp.EmitResponse(w, raw, resp)
	}
	if req.EventName == "SessionStart" {
		_, _ = eng.PreloadEnv(ctx, req.Cwd)
	}
	_, _ = w.Write([]byte("{}"))
	return nil
}

func emitPreconditionFailure(event string, w io.Writer, perr error) error {
	switch event {
	case "PostToolUse":
		_, _ = fmt.Fprintf(w, `{"decision":"block","reason":"opensecretmask: %s"}`, perr.Error())
	case "PreToolUse":
		out := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": fmt.Sprintf("opensecretmask: %s", perr.Error()),
			},
		}
		return json.NewEncoder(w).Encode(out)
	default:
		_, _ = w.Write([]byte("{}"))
	}
	return nil
}

func emitParseFailure(w io.Writer, _ error) error {
	_, _ = w.Write([]byte(`{"decision":"block","reason":"opensecretmask: malformed hook payload"}`))
	return nil
}
