package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/spf13/cobra"
)

type doctorReport struct {
	failures []string
}

func (r *doctorReport) check(out io.Writer, name string, ok bool, detail string) {
	if ok {
		fmt.Fprintf(out, "PASS  %s\n", name)
		return
	}
	fmt.Fprintf(out, "FAIL  %s: %s\n", name, detail)
	r.failures = append(r.failures, name)
}

func newDoctorCmd() *cobra.Command {
	var rebuildMappings, repairModes bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose installation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			root, err := store.Root()
			if err != nil {
				return err
			}

			rep := &doctorReport{}

			// 1. dir exists + mode
			st, derr := os.Stat(root)
			if derr != nil || !st.IsDir() {
				rep.check(out, "directory", false, fmt.Sprintf("cannot stat %s: %v", root, derr))
			} else {
				perm := st.Mode().Perm()
				ok := perm == 0o700
				if !ok && repairModes {
					if err := os.Chmod(root, 0o700); err == nil {
						ok = true
					}
				}
				rep.check(out, "directory mode 0700", ok, fmt.Sprintf("got %o", perm))
			}

			// 2. install.key
			keyPath := filepath.Join(root, keymgr.InstallKeyName)
			ks, kerr := os.Stat(keyPath)
			if kerr != nil {
				rep.check(out, "install.key exists", false, kerr.Error())
			} else {
				perm := ks.Mode().Perm()
				ok := perm == 0o600
				if !ok && repairModes {
					if err := os.Chmod(keyPath, 0o600); err == nil {
						ok = true
					}
				}
				rep.check(out, "install.key mode 0600", ok, fmt.Sprintf("got %o", perm))
				rep.check(out, "install.key length 32", ks.Size() == 32, fmt.Sprintf("got %d bytes", ks.Size()))
			}

			// 3. config.toml
			cfgPath := filepath.Join(root, store.ConfigName)
			cfg, cerr := store.LoadConfig(cfgPath)
			rep.check(out, "config.toml parse", cerr == nil, errString(cerr))
			if cfg != nil {
				rep.check(out, "config.toml validate", cfg.Validate() == nil, errString(cfg.Validate()))
			}

			// 4. secrets/mappings/allowlist parse
			secretsPath := filepath.Join(root, store.SecretsName)
			secs, serr := store.LoadSecrets(secretsPath)
			rep.check(out, "secrets.json parse", serr == nil, errString(serr))

			mappingsPath := filepath.Join(root, store.MappingsName)
			maps, merr := store.LoadMappings(mappingsPath)
			rep.check(out, "mappings.json parse", merr == nil, errString(merr))

			allowPath := filepath.Join(root, store.AllowlistName)
			_, aerr := store.LoadAllowlist(allowPath)
			rep.check(out, "allowlist.json parse", aerr == nil, errString(aerr))

			// 5. lock health
			lock, lerr := store.OpenLock(root)
			if lerr != nil {
				rep.check(out, "lock acquire", false, lerr.Error())
			} else {
				lockErr := lock.WithExclusive(1*time.Second, func() error { return nil })
				rep.check(out, "lock acquire", lockErr == nil, errString(lockErr))
			}

			// 6. mappings consistency
			if secs != nil && maps != nil {
				masked := make(map[string]string)
				for _, e := range secs.Secrets {
					masked[e.Masked] = e.Value
				}
				orphans := 0
				for k := range maps.ByMask {
					if _, ok := masked[k]; !ok {
						orphans++
					}
				}
				ok := orphans == 0
				if !ok && rebuildMappings {
					maps.ByMask = make(map[string]string, len(secs.Secrets))
					for _, e := range secs.Secrets {
						maps.ByMask[e.Masked] = e.Value
					}
					if err := store.SaveMappings(mappingsPath, maps); err == nil {
						ok = true
					}
				}
				rep.check(out, "mappings consistent", ok, fmt.Sprintf("%d orphan masks", orphans))
			}

			// 7. tmp cleanup
			cleanErr := store.CleanStaleTmp(root)
			rep.check(out, "stale .tmp cleanup", cleanErr == nil, errString(cleanErr))

			if len(rep.failures) > 0 && !rebuildMappings && !repairModes {
				return fmt.Errorf("%d check(s) failed: %v", len(rep.failures), rep.failures)
			}
			fmt.Fprintf(out, "doctor: %d failures (after repair where applicable)\n", len(rep.failures))
			return nil
		},
	}
	c.Flags().BoolVar(&rebuildMappings, "rebuild-mappings", false, "rebuild mappings.json from secrets.json")
	c.Flags().BoolVar(&repairModes, "repair-modes", false, "chmod files to expected modes")
	return c
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
