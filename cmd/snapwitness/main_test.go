package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buildwithme/snapwitness/internal/app"
	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/witnesstest"
)

// fakeRestic fakes `restic -r <repo> snapshots --json` by listing the files
// in <repo>/snapshots.
const fakeRestic = `#!/bin/sh
printf '['
sep=''
for f in "$2"/snapshots/*; do
  [ -f "$f" ] || continue
  printf '%s{"id":"%s","time":"2026-10-01T12:00:00Z","program_version":"restic 0.19.1"}' "$sep" "$(basename "$f")"
  sep=','
done
printf ']\n'
`

// snapwitness runs the CLI in-process, checks the exit code against want and
// returns stdout.
func snapwitness(t *testing.T, want int, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	if got := run(args, &stdout, &stderr); got != want {
		t.Fatalf(
			"snapwitness %s: got exit %d, want %d\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "),
			got,
			want,
			stdout.String(),
			stderr.String(),
		)
	}

	return stdout.String()
}

func TestRunUsage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.conf")
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no command", nil, app.ExitUsage},
		{"unknown command", []string{"backup"}, app.ExitUsage},
		{"unknown flag", []string{"audit", "-nope"}, app.ExitUsage},
		{"extra argument", []string{"record", "now"}, app.ExitUsage},
		{"init without flags", []string{"init"}, app.ExitUsage},
		{"witness without url", []string{"init", "-witness", "w1+00000000+key"}, app.ExitUsage},
		{"help", []string{"help"}, app.ExitOK},
		{"command help", []string{"audit", "-h"}, app.ExitOK},
		{"version", []string{"version"}, app.ExitOK},
		{"audit without config", []string{"audit", "-c", missing}, app.ExitError},
		{"record without config", []string{"record", "-c", missing}, app.ExitError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapwitness(t, tt.want, tt.args...)
		})
	}
}

// TestRunFlow goes through init, record and audit on the command line, with
// test witnesses and a fake restic.
func TestRunFlow(t *testing.T) {
	dir := t.TempDir()

	repo := filepath.Join(dir, "storage", "repo")
	if err := os.MkdirAll(filepath.Join(repo, "snapshots"), 0o750); err != nil {
		t.Fatal(err)
	}

	resticBin := filepath.Join(dir, "restic")
	if err := os.WriteFile(resticBin, []byte(fakeRestic), 0o700); err != nil {
		t.Fatal(err)
	}

	w1, w2 := witnesstest.New(t, "w1.test"), witnesstest.New(t, "w2.test")
	conf := filepath.Join(dir, "snapwitness.conf")

	out := snapwitness(
		t,
		app.ExitOK,
		"init",
		"-c",
		conf,
		"-name",
		"demo",
		"-repo",
		repo,
		"-log",
		filepath.Join(dir, "storage", "log"),
		"-witness",
		w1.VKey()+"="+w1.URL(),
		"-witness",
		w2.VKey()+"="+w2.URL(),
		"-quorum",
		"2",
	)
	if !strings.Contains(out, "witnessctl add-key") {
		t.Errorf("got init output %q, want the witness commands", out)
	}

	cfg, err := config.Load(conf)
	if err != nil {
		t.Fatal(err)
	}

	for _, w := range []*witnesstest.Witness{w1, w2} {
		if err := w.AddLog(cfg.Origin, cfg.LogKey); err != nil {
			t.Fatal(err)
		}
	}

	snapwitness(t, app.ExitUsage, "init", "-c", conf, "-name", "demo", "-repo", repo)
	snapwitness(
		t,
		app.ExitError,
		"init",
		"-c",
		conf,
		"-name",
		"demo",
		"-repo",
		repo,
		"-log",
		filepath.Join(dir, "storage", "log"),
		"-witness",
		w1.VKey()+"="+w1.URL(),
		"-quorum",
		"1",
	)
	snapwitness(t, app.ExitError, "audit", "-c", conf)

	data := []byte("first snapshot file, at least 32 bytes long")
	sum := sha256.Sum256(data)

	snap := filepath.Join(repo, "snapshots", hex.EncodeToString(sum[:]))
	if err := os.WriteFile(snap, data, 0o600); err != nil {
		t.Fatal(err)
	}

	snapwitness(t, app.ExitOK, "record", "-c", conf, "-restic", resticBin)
	out = snapwitness(t, app.ExitOK, "audit", "-c", conf)
	if !strings.Contains(out, "result: OK") {
		t.Errorf("got audit output\n%s\nwant result: OK", out)
	}

	var report app.Report
	if err := json.Unmarshal([]byte(snapwitness(t, app.ExitOK, "audit", "-c", conf, "-json")), &report); err != nil {
		t.Fatalf("decode the JSON report: %v", err)
	}

	if report.LogSize != 1 || report.Snapshots != 1 {
		t.Errorf("got log size %d and %d snapshots, want 1 and 1", report.LogSize, report.Snapshots)
	}

	if err := os.Remove(snap); err != nil {
		t.Fatal(err)
	}

	snapwitness(t, app.ExitAlarm, "audit", "-c", conf)
	// the alarm wins over the error from missing.conf
	snapwitness(t, app.ExitAlarm, "audit", "-c", conf, "-c", filepath.Join(dir, "missing.conf"))
	snapwitness(t, app.ExitAlarm, "record", "-c", conf, "-restic", resticBin)
	snapwitness(t, app.ExitOK, "record", "-c", conf, "-restic", resticBin, "-accept-removed")
	snapwitness(t, app.ExitOK, "audit", "-c", conf, "-offline")
}
