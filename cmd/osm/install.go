package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/spf13/cobra"
)

const osmDescription = "opensecretmask"

type osmHookEntry struct {
	Event   string
	Matcher string
	Command string
}

func osmHooks() []osmHookEntry {
	return []osmHookEntry{
		{Event: "PostToolUse", Matcher: ".*", Command: "osm hook --harness=claudecode posttooluse"},
		{Event: "PreToolUse", Matcher: "Edit|Write|MultiEdit|Bash|NotebookEdit", Command: "osm hook --harness=claudecode pretooluse"},
		{Event: "UserPromptSubmit", Matcher: "", Command: "osm hook --harness=claudecode userpromptsubmit"},
		{Event: "SessionStart", Matcher: "", Command: "osm hook --harness=claudecode sessionstart"},
	}
}

type installOpts struct {
	global  bool
	project bool
	dryRun  bool
}

func newInstallCmd() *cobra.Command {
	var opts installOpts
	c := &cobra.Command{
		Use:   "install <harness>",
		Short: "Install hooks into a target harness (claude-code)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "claude-code" && args[0] != "claudecode" {
				return fmt.Errorf("unknown harness %q (only claude-code supported)", args[0])
			}
			path, err := resolveSettingsPath(opts)
			if err != nil {
				return err
			}
			settings, err := loadSettings(path)
			if err != nil {
				return err
			}
			updated := mergeOSMHooks(settings)
			if opts.dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "would write %s\n", path)
				out, _ := json.MarshalIndent(updated, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			data, err := json.MarshalIndent(updated, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
			if err := store.WriteAtomic(path, data, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "installed osm hooks to %s\n", path)
			return nil
		},
	}
	c.Flags().BoolVar(&opts.global, "global", false, "install to ~/.claude/settings.json")
	c.Flags().BoolVar(&opts.project, "project", false, "install to .claude/settings.json (default)")
	c.Flags().BoolVar(&opts.dryRun, "dry-run", false, "do not write, only print")
	return c
}

// resolveSettingsPath honors --global / --project flags. Default project.
func resolveSettingsPath(opts installOpts) (string, error) {
	if opts.global && opts.project {
		return "", fmt.Errorf("--global and --project are mutually exclusive")
	}
	if opts.global {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".claude", "settings.json"), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, ".claude", "settings.json"), nil
}

func loadSettings(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

// mergeOSMHooks idempotently inserts osm hook entries.
// Existing entries with description == "opensecretmask" get their command
// upgraded in place; user-owned entries are preserved untouched.
func mergeOSMHooks(settings map[string]any) map[string]any {
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	for _, h := range osmHooks() {
		entries, _ := hooks[h.Event].([]any)
		updated := false
		for _, en := range entries {
			m, ok := en.(map[string]any)
			if !ok {
				continue
			}
			hh, _ := m["hooks"].([]any)
			for j, sub := range hh {
				sm, ok := sub.(map[string]any)
				if !ok {
					continue
				}
				if sm["description"] == osmDescription {
					sm["command"] = h.Command
					hh[j] = sm
					updated = true
				}
			}
			if updated {
				m["hooks"] = hh
			}
		}
		if !updated {
			newEntry := map[string]any{
				"hooks": []any{
					map[string]any{
						"type":        "command",
						"command":     h.Command,
						"description": osmDescription,
					},
				},
			}
			if h.Matcher != "" {
				newEntry["matcher"] = h.Matcher
			}
			entries = append(entries, newEntry)
			hooks[h.Event] = entries
		}
	}
	return settings
}

func newUninstallCmd() *cobra.Command {
	var opts installOpts
	c := &cobra.Command{
		Use:   "uninstall <harness>",
		Short: "Remove osm hooks from a target harness (claude-code)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "claude-code" && args[0] != "claudecode" {
				return fmt.Errorf("unknown harness %q", args[0])
			}
			path, err := resolveSettingsPath(opts)
			if err != nil {
				return err
			}
			settings, err := loadSettings(path)
			if err != nil {
				return err
			}
			updated := removeOSMHooks(settings)
			if opts.dryRun {
				out, _ := json.MarshalIndent(updated, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}
			data, err := json.MarshalIndent(updated, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
			if err := store.WriteAtomic(path, data, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed osm hooks from %s\n", path)
			return nil
		},
	}
	c.Flags().BoolVar(&opts.global, "global", false, "uninstall from ~/.claude/settings.json")
	c.Flags().BoolVar(&opts.project, "project", false, "uninstall from .claude/settings.json (default)")
	c.Flags().BoolVar(&opts.dryRun, "dry-run", false, "do not write, only print")
	return c
}

// removeOSMHooks strips opensecretmask hook entries from settings.
// Empty matcher entries are dropped; empty event arrays are deleted.
func removeOSMHooks(settings map[string]any) map[string]any {
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		return settings
	}
	for event, raw := range hooks {
		entries, _ := raw.([]any)
		var newEntries []any
		for _, en := range entries {
			m, ok := en.(map[string]any)
			if !ok {
				newEntries = append(newEntries, en)
				continue
			}
			hh, _ := m["hooks"].([]any)
			var newHH []any
			for _, sub := range hh {
				sm, ok := sub.(map[string]any)
				if !ok {
					newHH = append(newHH, sub)
					continue
				}
				if sm["description"] == osmDescription {
					continue
				}
				newHH = append(newHH, sub)
			}
			if len(newHH) == 0 {
				continue
			}
			m["hooks"] = newHH
			newEntries = append(newEntries, m)
		}
		if len(newEntries) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = newEntries
		}
	}
	return settings
}
