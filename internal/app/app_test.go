package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/buildwithme/snapwitness/internal/app"
	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/restic"
	"github.com/buildwithme/snapwitness/internal/witness"
	"github.com/buildwithme/snapwitness/internal/witnesstest"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

// env is one repository with its log and witnesses. It also plays restic:
// its keyed view lists the snapshot files restic would read.
type env struct {
	t   *testing.T
	cfg *config.Config
	ws  []*witnesstest.Witness
	wc  *witness.Client
	ids []string // made by backup, oldest first
}

// newEnv runs init with n witnesses and the given quorum, and registers the
// log with each of them.
func newEnv(t *testing.T, n, quorum int) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, wc: &witness.Client{}}

	var cws []config.Witness

	for i := range n {
		w := witnesstest.New(t, fmt.Sprintf("w%d.test", i+1))
		e.ws = append(e.ws, w)
		cws = append(cws, config.Witness{VKey: w.VKey(), URL: w.URL()})
	}

	cfg, err := app.Init(app.InitOptions{
		Name:       "test",
		ConfigPath: filepath.Join(dir, "snapwitness.conf"),
		Repo:       filepath.Join(dir, "storage", "repo"),
		LogDir:     filepath.Join(dir, "storage", "log"),
		Witnesses:  cws,
		Quorum:     quorum,
	}, io.Discard)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	e.cfg = cfg
	for _, w := range e.ws {
		if err := w.AddLog(cfg.Origin, cfg.LogKey); err != nil {
			t.Fatalf("add log: %v", err)
		}
	}

	if err := os.MkdirAll(e.snapshots(), 0o750); err != nil {
		t.Fatal(err)
	}

	return e
}

func (e *env) snapshots() string { return filepath.Join(e.cfg.Repo, "snapshots") }

// Snapshots is the keyed view. It lists the snapshot files the way restic
// snapshots would with the password.
func (e *env) Snapshots(context.Context) ([]restic.Snapshot, error) {
	entries, err := os.ReadDir(e.snapshots())
	if err != nil {
		return nil, err
	}

	var snaps []restic.Snapshot

	for _, d := range entries {
		info, err := d.Info()
		if err != nil {
			return nil, err
		}

		snaps = append(snaps, restic.Snapshot{ID: d.Name(), Time: info.ModTime(), ProgramVersion: "restic 0.19.1"})
	}

	return snaps, nil
}

// backup writes a new snapshot file named after its SHA-256, like restic
// backup, and returns the ID.
func (e *env) backup() string {
	e.t.Helper()
	data := fmt.Appendf(nil, "snapshot %d %s", len(e.ids), rand.Text())
	if len(data) < restic.MinFileSize {
		e.t.Fatalf("snapshot of %d bytes, want at least %d", len(data), restic.MinFileSize)
	}

	id := hashName(data)
	writeFile(e.t, filepath.Join(e.snapshots(), id), data)
	e.ids = append(e.ids, id)

	return id
}

// remove deletes snapshot files, like restic forget would. Or an attacker.
func (e *env) remove(ids ...string) {
	e.t.Helper()

	for _, id := range ids {
		if err := os.Remove(filepath.Join(e.snapshots(), id)); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) record(opts app.RecordOptions) *app.Report {
	e.t.Helper()
	return app.Record(e.t.Context(), e.cfg, e, e.wc, opts)
}

func (e *env) audit(opts app.AuditOptions) *app.Report {
	e.t.Helper()
	return app.Audit(e.t.Context(), e.cfg, e.wc, opts)
}

func (e *env) backupAndRecord(n int) {
	e.t.Helper()

	for range n {
		e.backup()
		expect(e.t, "record", e.record(app.RecordOptions{}), app.ExitOK)
	}
}

func (e *env) setDown(down bool) {
	for _, w := range e.ws {
		w.SetDown(down)
	}
}

func (e *env) sizes() (logSize, checkpoint int64) {
	e.t.Helper()

	l, err := wlog.Open(e.cfg.LogDir)
	if err != nil {
		e.t.Fatal(err)
	}

	signed, err := l.ReadCheckpoint()
	if err != nil {
		e.t.Fatal(err)
	}

	body, _, _ := bytes.Cut(signed, []byte("\n\n"))

	c, err := wlog.ParseCheckpoint(append(body, '\n'))
	if err != nil {
		e.t.Fatal(err)
	}

	return l.Size(), c.Size
}

func (e *env) wantSizes(step string, logSize, checkpoint int64) {
	e.t.Helper()

	if l, c := e.sizes(); l != logSize || c != checkpoint {
		e.t.Errorf("%s: got log size %d and checkpoint %d, want %d and %d", step, l, c, logSize, checkpoint)
	}
}

// expect checks the exit code of r and its warnings and alarms. Findings are
// written like "ALARM rollback", in any order.
func expect(t *testing.T, step string, r *app.Report, code int, findings ...string) {
	t.Helper()

	var got []string

	for _, f := range r.Findings {
		if f.Severity >= app.Warn {
			got = append(got, f.Severity.String()+" "+f.Kind)
		}
	}

	slices.Sort(got)

	findings = slices.Sorted(slices.Values(findings))
	if r.ExitCode() != code || !slices.Equal(got, findings) {
		var b strings.Builder

		_ = r.WriteText(&b)
		t.Errorf(
			"%s: got exit %d with %q, want exit %d with %q\n%s",
			step,
			r.ExitCode(),
			got,
			code,
			findings,
			b.String(),
		)
	}
}

func finding(t *testing.T, r *app.Report, kind string) app.Finding {
	t.Helper()

	for _, f := range r.Findings {
		if f.Kind == kind {
			return f
		}
	}

	t.Fatalf("no %s finding in %+v", kind, r.Findings)

	return app.Finding{}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func hashName(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestAudit breaks a storage with three recorded backups, in a different way
// for each case, and checks what the audit says.
func TestAudit(t *testing.T) {
	later := func() time.Time { return time.Now().Add(27 * time.Hour) }
	tests := []struct {
		name   string
		damage func(e *env)
		opts   app.AuditOptions
		code   int
		want   []string
	}{
		{name: "clean", code: app.ExitOK},
		{name: "offline", opts: app.AuditOptions{Offline: true}, code: app.ExitOK},
		{
			name:   "delete",
			damage: func(e *env) { e.remove(e.ids[1]) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM deleted"},
		},
		{
			name:   "unapproved prune",
			damage: func(e *env) { e.remove(e.ids[:2]...) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM deleted"},
		},
		{
			// A snapshot deleted before any record saw it is the known gap
			name:   "known gap",
			damage: func(e *env) { e.remove(e.backup()) },
			code:   app.ExitOK,
		},
		{
			name:   "backup without record",
			damage: func(e *env) { e.backup() },
			code:   app.ExitOK,
			want:   []string{"WARN unrecorded"},
		},
		{
			name: "snapshot changed in place",
			damage: func(e *env) {
				writeFile(
					e.t,
					filepath.Join(e.snapshots(), e.ids[0]),
					[]byte("other bytes under the same snapshot name"),
				)
			},
			code: app.ExitAlarm,
			want: []string{"ALARM deleted", "ALARM tampered"},
		},
		{
			name:   "foreign file",
			damage: func(e *env) { writeFile(e.t, filepath.Join(e.snapshots(), "notes.txt"), []byte("hi")) },
			code:   app.ExitOK,
			want:   []string{"WARN foreign"},
		},
		{
			name: "file too short for restic",
			damage: func(e *env) {
				writeFile(e.t, filepath.Join(e.snapshots(), hashName([]byte("short"))), []byte("short"))
			},
			code: app.ExitOK,
			want: []string{"WARN foreign"},
		},
		{
			name:   "log gone",
			damage: func(e *env) { _ = os.RemoveAll(e.cfg.LogDir) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM deleted"},
		},
		{
			name:   "checkpoint gone",
			damage: func(e *env) { _ = os.Remove(filepath.Join(e.cfg.LogDir, wlog.CheckpointFile)) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM tampered"},
		},
		{
			name: "checkpoint changed",
			damage: func(e *env) {
				path := filepath.Join(e.cfg.LogDir, wlog.CheckpointFile)
				writeFile(e.t, path, bytes.Replace(readFile(e.t, path), []byte("\n3\n"), []byte("\n2\n"), 1))
			},
			code: app.ExitAlarm,
			want: []string{"ALARM tampered"},
		},
		{
			name: "entry changed",
			damage: func(e *env) {
				path := filepath.Join(e.cfg.LogDir, wlog.EntriesFile)
				b := readFile(e.t, path)
				b[4] = 'S'
				writeFile(e.t, path, b)
			},
			code: app.ExitAlarm,
			want: []string{"ALARM tampered"},
		},
		{
			name: "log truncated",
			damage: func(e *env) {
				path := filepath.Join(e.cfg.LogDir, wlog.EntriesFile)
				b := readFile(e.t, path)
				first := 4 + int(binary.BigEndian.Uint32(b))
				writeFile(e.t, path, b[:first])
			},
			code: app.ExitAlarm,
			want: []string{"ALARM tampered"},
		},
		{
			name: "stale",
			opts: app.AuditOptions{Now: later},
			code: app.ExitAlarm,
			want: []string{"ALARM stale", "ALARM stale"},
		},
		{
			name: "offline stale",
			opts: app.AuditOptions{Offline: true, Now: later},
			code: app.ExitAlarm,
			want: []string{"ALARM stale", "ALARM stale"},
		},
		{
			// The stored cosignatures still confirm the log
			name:   "witnesses down",
			damage: func(e *env) { e.setDown(true) },
			code:   app.ExitOK,
			want:   []string{"WARN witness", "WARN witness"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, 2, 2)
			e.backupAndRecord(3)

			if tt.damage != nil {
				tt.damage(e)
			}

			expect(t, "audit", e.audit(tt.opts), tt.code, tt.want...)
		})
	}
}

func TestRecordClean(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 3, 2)
	e.backupAndRecord(3)
	e.wantSizes("after 3 records", 3, 3)

	// A record without a new backup still appends one entry
	r := e.record(app.RecordOptions{})
	expect(t, "record without change", r, app.ExitOK)
	e.wantSizes("after a record without change", 4, 4)

	if r.Snapshots != 3 || r.LogSize != 4 {
		t.Errorf("got %d snapshots and log size %d, want 3 and 4", r.Snapshots, r.LogSize)
	}

	if !slices.ContainsFunc(r.Lines, func(l string) bool { return strings.Contains(l, "restic 0.19.1") }) {
		t.Errorf("got lines %q, want the restic version", r.Lines)
	}

	cosigned := 0

	for _, w := range e.ws {
		if w.Size(e.cfg.Origin) == 4 {
			cosigned++
		}
	}

	if cosigned < e.cfg.Quorum {
		t.Errorf("got %d witnesses at size 4, want at least %d", cosigned, e.cfg.Quorum)
	}

	expect(t, "audit", e.audit(app.AuditOptions{}), app.ExitOK)
}

func TestRecordRefusesRemoved(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.backupAndRecord(3)
	// restic forget --keep-last 1 without telling snapwitness
	e.remove(e.ids[0], e.ids[1])

	r := e.record(app.RecordOptions{})
	expect(t, "record", r, app.ExitAlarm, "ALARM deleted")
	details := strings.Join(finding(t, r, "deleted").Details, "\n")
	for _, want := range []string{e.ids[0], e.ids[1], "-accept-removed"} {
		if !strings.Contains(details, want) {
			t.Errorf("got details %q, want %q in them", details, want)
		}
	}

	e.wantSizes("after the refused record", 3, 3)
	expect(t, "audit", e.audit(app.AuditOptions{}), app.ExitAlarm, "ALARM deleted")

	expect(t, "record -accept-removed", e.record(app.RecordOptions{AcceptRemoved: true}), app.ExitOK)
	e.wantSizes("after the accepted record", 4, 4)
	expect(t, "audit after the accepted record", e.audit(app.AuditOptions{}), app.ExitOK)
}

type failingSource struct{}

func (failingSource) Snapshots(context.Context) ([]restic.Snapshot, error) {
	return nil, errors.New("restic: snapshots: exit code 1: wrong password")
}

func TestRecordErrors(t *testing.T) {
	t.Parallel()
	t.Run("restic fails", func(t *testing.T) {
		e := newEnv(t, 1, 1)

		r := app.Record(t.Context(), e.cfg, failingSource{}, e.wc, app.RecordOptions{})
		if r.ExitCode() != app.ExitError || !strings.Contains(r.Err, "wrong password") {
			t.Errorf(
				"got exit %d with error %q, want exit %d with the restic error",
				r.ExitCode(),
				r.Err,
				app.ExitError,
			)
		}
	})
	t.Run("other log key", func(t *testing.T) {
		e := newEnv(t, 1, 1)

		skey, _, err := note.GenerateKey(rand.Reader, e.cfg.Origin)
		if err != nil {
			t.Fatal(err)
		}

		writeFile(t, e.cfg.KeyFile, []byte(skey+"\n"))
		e.backup()
		r := e.record(app.RecordOptions{})
		if r.ExitCode() != app.ExitError || !strings.Contains(r.Err, "does not match") {
			t.Errorf("got exit %d with error %q, want exit %d with a key mismatch", r.ExitCode(), r.Err, app.ExitError)
		}
	})
	t.Run("audit before record", func(t *testing.T) {
		e := newEnv(t, 1, 1)

		r := e.audit(app.AuditOptions{})
		if r.ExitCode() != app.ExitError || !strings.Contains(r.Err, "run snapwitness record first") {
			t.Errorf("got exit %d with error %q, want exit %d", r.ExitCode(), r.Err, app.ExitError)
		}
	})
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
