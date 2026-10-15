package app_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/buildwithme/snapwitness/internal/app"
	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/witnesstest"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func TestInit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	w := witnesstest.New(t, "w1.test")
	opts := app.InitOptions{
		Name:       "demo",
		ConfigPath: filepath.Join(dir, "snapwitness.conf"),
		Repo:       filepath.Join(dir, "repo"),
		LogDir:     filepath.Join(dir, "log"),
		Witnesses:  []config.Witness{{VKey: w.VKey(), URL: w.URL()}},
		Quorum:     1,
	}

	var out strings.Builder

	cfg, err := app.Init(opts, &out)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	if tag, ok := strings.CutPrefix(cfg.Origin, "snapwitness/demo/"); !ok || len(tag) != 16 {
		t.Errorf("got origin %q, want snapwitness/demo/ and 16 hex", cfg.Origin)
	}

	loaded, err := config.Load(opts.ConfigPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !reflect.DeepEqual(loaded, cfg) {
		t.Errorf("got loaded config %+v, want %+v", loaded, cfg)
	}

	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}

	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("got key file mode %o, want 600", mode)
	}

	for _, want := range []string{
		"witnessctl add-log -db <db> -origin " + cfg.Origin,
		"witnessctl add-key -db <db> -origin " + cfg.Origin + " -key " + cfg.LogKey,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("got output %q, want %q in it", out.String(), want)
		}
	}

	key := readFile(t, cfg.KeyFile)
	if _, err := app.Init(opts, io.Discard); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second init: got %v, want an error for the existing config", err)
	}

	if !bytes.Equal(readFile(t, cfg.KeyFile), key) {
		t.Error("second init changed the log key")
	}
}

func TestInitRejects(t *testing.T) {
	t.Parallel()
	w := witnesstest.New(t, "w1.test")
	good := config.Witness{VKey: w.VKey(), URL: w.URL()}
	tests := []struct {
		name   string
		change func(o *app.InitOptions)
	}{
		{"upper case name", func(o *app.InitOptions) { o.Name = "Demo" }},
		{"empty name", func(o *app.InitOptions) { o.Name = "" }},
		{"long name", func(o *app.InitOptions) { o.Name = strings.Repeat("a", 33) }},
		{"quorum 0", func(o *app.InitOptions) { o.Quorum = 0 }},
		{"quorum above witnesses", func(o *app.InitOptions) { o.Quorum = 2 }},
		{
			"bad witness key",
			func(o *app.InitOptions) { o.Witnesses = []config.Witness{{VKey: "w1+00000000+bad", URL: w.URL()}} },
		},
		{"log exists", func(o *app.InitOptions) {
			if err := wlog.Create(o.LogDir); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := app.InitOptions{
				Name:       "demo",
				ConfigPath: filepath.Join(dir, "snapwitness.conf"),
				Repo:       filepath.Join(dir, "repo"),
				LogDir:     filepath.Join(dir, "log"),
				Witnesses:  []config.Witness{good},
				Quorum:     1,
			}
			tt.change(&opts)

			if _, err := app.Init(opts, io.Discard); err == nil {
				t.Fatal("got no error, want init to refuse")
			}

			for _, name := range []string{"snapwitness.conf", "log.key"} {
				if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s: got %v, want no file left behind", name, err)
				}
			}
		})
	}
}

func TestReportExitCode(t *testing.T) {
	t.Parallel()

	with := func(err string, sevs ...app.Severity) *app.Report {
		r := &app.Report{Err: err}
		for _, s := range sevs {
			r.Add(s, "test", "message")
		}

		return r
	}
	tests := []struct {
		name string
		r    *app.Report
		want int
	}{
		{"nothing", with(""), app.ExitOK},
		{"info and warning", with("", app.Info, app.Warn), app.ExitOK},
		{"alarm", with("", app.Warn, app.Alarm), app.ExitAlarm},
		{"error", with("audit: timeout"), app.ExitError},
		{"alarm and error", with("audit: timeout", app.Alarm), app.ExitAlarm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.ExitCode(); got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestReportWrite(t *testing.T) {
	t.Parallel()

	r := &app.Report{
		Command:   "audit",
		Origin:    "snapwitness/demo/7c1e09d4b2a6f310",
		Witnesses: []app.WitnessStatus{{Name: "w1.test", Status: "conflict", Size: 5, Took: 2 * time.Millisecond}},
		Took:      41 * time.Millisecond,
	}
	r.Add(
		app.Alarm,
		"rollback",
		"witness w1.test has seen log size 5, the storage serves size 3",
		"likely: the storage was restored from an older copy",
	)
	r.Add(app.Warn, "unrecorded", "1 snapshots on the storage are not in the log")

	var text strings.Builder
	if err := r.WriteText(&text); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"snapwitness audit  origin=snapwitness/demo/7c1e09d4b2a6f310\n",
		"w1.test  conflict: has seen size 5  (2ms)\n",
		"ALARM rollback: witness w1.test has seen log size 5, the storage serves size 3\n      likely: the storage",
		"WARN unrecorded: ",
		"result: ALARM  (1 alarm, 1 warning, 41ms)\n",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("got text\n%s\nwant %q in it", text.String(), want)
		}
	}

	var b bytes.Buffer
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Command  string `json:"command"`
		Findings []struct {
			Severity string `json:"severity"`
			Kind     string `json:"kind"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", b.String(), err)
	}

	if got.Command != "audit" || len(got.Findings) != 2 || got.Findings[0].Severity != "ALARM" ||
		got.Findings[0].Kind != "rollback" {
		t.Errorf("got %+v, want the audit with the rollback alarm first", got)
	}

	if !strings.Contains(b.String(), "\n  \"command\"") {
		t.Errorf("got %s, want two-space indent", b.String())
	}
}
