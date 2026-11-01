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
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/buildwithme/snapwitness/internal/app"
	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/restic"
	"github.com/buildwithme/snapwitness/internal/state"
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

func (e *env) storage() string { return filepath.Dir(e.cfg.Repo) }

func (e *env) entries() string { return filepath.Join(e.cfg.LogDir, wlog.EntriesFile) }

func (e *env) checkpoint() string { return filepath.Join(e.cfg.LogDir, wlog.CheckpointFile) }

// appendFrames writes raw frames to the entries file and signs nothing, the
// way anyone with write access to the storage could.
func (e *env) appendFrames(entries ...[]byte) {
	e.t.Helper()

	f, err := os.OpenFile(e.entries(), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		e.t.Fatal(err)
	}

	for _, entry := range entries {
		if _, err := f.Write(binary.BigEndian.AppendUint32(nil, uint32(len(entry)))); err != nil {
			e.t.Fatal(err)
		}

		if _, err := f.Write(entry); err != nil {
			e.t.Fatal(err)
		}
	}

	if err := f.Close(); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) wantWitnesses(step string, size int64) {
	e.t.Helper()

	for _, w := range e.ws {
		if got := w.Size(e.cfg.Origin); got != size {
			e.t.Errorf("%s: witness %s: got size %d, want %d", step, w.Name(), got, size)
		}
	}
}

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

// save copies the whole storage (repo and log) and returns where the copy
// is.
func (e *env) save() string {
	e.t.Helper()
	dst := filepath.Join(e.t.TempDir(), "storage")
	if err := os.CopyFS(dst, os.DirFS(e.storage())); err != nil {
		e.t.Fatal(err)
	}

	return dst
}

func (e *env) restore(saved string) {
	e.t.Helper()

	if err := os.RemoveAll(e.storage()); err != nil {
		e.t.Fatal(err)
	}

	if err := os.CopyFS(e.storage(), os.DirFS(saved)); err != nil {
		e.t.Fatal(err)
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
	// witnesses cosign 10 minutes after this clock, more than the allowed skew
	earlier := func() time.Time { return time.Now().Add(-10 * time.Minute) }

	const escape = "notes\x1b[2J.txt"

	tests := []struct {
		name   string
		damage func(e *env)
		opts   app.AuditOptions
		code   int
		want   []string
		check  func(t *testing.T, e *env, r *app.Report)
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
			// A file name must not send terminal escape codes to the reader
			name:   "foreign file with an escape code",
			damage: func(e *env) { writeFile(e.t, filepath.Join(e.snapshots(), escape), []byte("hi")) },
			code:   app.ExitOK,
			want:   []string{"WARN foreign"},
			check: func(t *testing.T, _ *env, r *app.Report) {
				got := finding(t, r, "foreign").Details
				if want := []string{strconv.Quote(escape)}; !slices.Equal(got, want) {
					t.Errorf("got details %q, want %q", got, want)
				}

				var b strings.Builder
				if err := r.WriteText(&b); err != nil {
					t.Fatal(err)
				}

				if strings.Contains(b.String(), "\x1b") {
					t.Errorf("got an escape code in the text report:\n%q", b.String())
				}
			},
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
			damage: func(e *env) { _ = os.Remove(e.checkpoint()) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM deleted"},
		},
		{
			name: "log emptied and checkpoint gone",
			damage: func(e *env) {
				writeFile(e.t, e.entries(), nil)
				_ = os.Remove(e.checkpoint())
			},
			code: app.ExitAlarm,
			want: []string{"ALARM deleted"},
		},
		{
			name: "checkpoint changed",
			damage: func(e *env) {
				writeFile(
					e.t,
					e.checkpoint(),
					bytes.Replace(readFile(e.t, e.checkpoint()), []byte("\n3\n"), []byte("\n2\n"), 1),
				)
			},
			code: app.ExitAlarm,
			want: []string{"ALARM tampered"},
		},
		{
			name: "entry changed",
			damage: func(e *env) {
				b := readFile(e.t, e.entries())
				b[4] = 'S'
				writeFile(e.t, e.entries(), b)
			},
			code: app.ExitAlarm,
			want: []string{"ALARM tampered"},
		},
		{
			name: "log truncated",
			damage: func(e *env) {
				b := readFile(e.t, e.entries())
				first := 4 + int(binary.BigEndian.Uint32(b))
				writeFile(e.t, e.entries(), b[:first])
			},
			code: app.ExitAlarm,
			want: []string{"ALARM tampered"},
		},
		{
			name:   "torn frame",
			damage: func(e *env) { writeFile(e.t, e.entries(), append(readFile(e.t, e.entries()), 0, 0)) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM tampered"},
		},
		{
			name:   "entry past the checkpoint",
			damage: func(e *env) { e.appendFrames([]byte("not a state record")) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM tampered"},
		},
		{
			name:   "snapshots directory gone",
			damage: func(e *env) { _ = os.RemoveAll(e.snapshots()) },
			code:   app.ExitAlarm,
			want:   []string{"ALARM deleted"},
			check: func(t *testing.T, e *env, r *app.Report) {
				details := finding(t, r, "deleted").Details
				if len(details) != len(e.ids) {
					t.Fatalf("got details %q, want one per recorded snapshot", details)
				}

				for i, id := range slices.Sorted(slices.Values(e.ids)) {
					if !strings.Contains(details[i], id) {
						t.Errorf("got detail %q, want %s in it", details[i], id)
					}
				}
			},
		},
		{
			name: "cosignatures from the future",
			opts: app.AuditOptions{Now: earlier},
			code: app.ExitAlarm,
			want: []string{"ALARM stale", "WARN clock", "WARN clock"},
			check: func(t *testing.T, _ *env, r *app.Report) {
				var msgs []string

				for _, f := range r.Findings {
					if f.Kind == "clock" {
						msgs = append(msgs, f.Message)
					}
				}

				if len(msgs) != 2 || !strings.Contains(msgs[0], "w1.test") || !strings.Contains(msgs[1], "w2.test") {
					t.Errorf("got clock warnings %q, want one naming each witness", msgs)
				}
			},
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

			r := e.audit(tt.opts)
			expect(t, "audit", r, tt.code, tt.want...)

			if tt.check != nil {
				tt.check(t, e, r)
			}
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

// TestTailPastCheckpoint slips a record that removes a snapshot into the log,
// with no checkpoint. Record must not build on it, even with
// -accept-removed, and it must sign nothing.
func TestTailPastCheckpoint(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.backupAndRecord(3)
	slipped := &state.Record{
		Time:    time.Now().UTC().Truncate(time.Second),
		Tool:    "restic",
		Count:   2,
		Set:     state.SetHash(e.ids[1:]),
		Removed: []string{e.ids[0]},
	}

	before, err := os.Stat(e.entries())
	if err != nil {
		t.Fatal(err)
	}

	e.appendFrames(slipped.Marshal())
	e.remove(e.ids[0])

	r := e.record(app.RecordOptions{AcceptRemoved: true})
	expect(t, "record", r, app.ExitAlarm, "ALARM tampered")
	f := finding(t, r, "tampered")
	if !strings.Contains(f.Message, "1 log entry past the checkpoint") {
		t.Errorf("got message %q, want it to count the entry past the checkpoint", f.Message)
	}

	e.wantSizes("after the refused record", 4, 3)
	e.wantWitnesses("after the refused record", 3)
	a := e.audit(app.AuditOptions{})
	expect(t, "audit", a, app.ExitAlarm, "ALARM tampered", "ALARM deleted")

	// every witness is at size 3. Record and audit should both print the
	// command that cuts exactly the slipped frame
	p := "'" + e.entries() + "'"
	want := fmt.Sprintf("[ -f %s ] && [ ! -L %s ] && truncate -c -s %d %s", p, p, before.Size(), p)

	for _, rep := range []*app.Report{r, a} {
		if d := strings.Join(finding(t, rep, "tampered").Details, "\n"); !strings.Contains(d, want) {
			t.Errorf("%s: got details %q, want %q", rep.Command, d, want)
		}
	}

	// offline audit can't know what the witnesses saw
	offline := e.audit(app.AuditOptions{Offline: true})
	if d := strings.Join(finding(t, offline, "tampered").Details, "\n"); strings.Contains(d, "truncate") {
		t.Errorf("offline audit: got details %q, want no truncate command", d)
	}

	if err := os.Truncate(e.entries(), before.Size()); err != nil {
		t.Fatal(err)
	}

	expect(t, "record after the repair", e.record(app.RecordOptions{AcceptRemoved: true}), app.ExitOK)
	e.wantSizes("after the repair", 4, 4)
	expect(t, "audit after the repair", e.audit(app.AuditOptions{}), app.ExitOK)
}

// TestTailWitnessDown leaves one witness down with an entry past the
// checkpoint. The other one alone is a quorum, but we can't know if the down
// one cosigned the entry. Record and audit must say to wait.
func TestTailWitnessDown(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 1)
	e.backupAndRecord(3)
	e.appendFrames([]byte("junk frame"))
	e.ws[1].SetDown(true)

	for _, r := range []*app.Report{e.record(app.RecordOptions{}), e.audit(app.AuditOptions{})} {
		if r.ExitCode() != app.ExitAlarm {
			t.Errorf("%s: got exit %d, want %d", r.Command, r.ExitCode(), app.ExitAlarm)
		}

		d := strings.Join(finding(t, r, "tampered").Details, "\n")
		if strings.Contains(d, "truncate") || !strings.Contains(d, "do not drop them before") {
			t.Errorf("%s: got details %q, want advice to wait", r.Command, d)
		}
	}
}

// wantKeepAdvice wants the tail alarm of each report to say keep the
// entries. A witness that's ahead may have cosigned them.
func wantKeepAdvice(t *testing.T, reports ...*app.Report) {
	t.Helper()

	for _, r := range reports {
		d := strings.Join(finding(t, r, "tampered").Details, "\n")
		if strings.Contains(d, "truncate") || !strings.Contains(d, "do not drop them") {
			t.Errorf("%s: got details %q, want advice to keep the entries", r.Command, d)
		}
	}
}

func TestRollback(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.backupAndRecord(3)
	p3 := e.save()
	e.backupAndRecord(2)
	e.restore(p3)

	r := e.audit(app.AuditOptions{})
	expect(t, "audit", r, app.ExitAlarm, "ALARM rollback")
	f := finding(t, r, "rollback")
	for _, want := range []string{"w1.test", "w2.test", "size 5", "checkpoint is size 3"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("got message %q, want %q in it", f.Message, want)
		}
	}

	details := strings.Join(f.Details, "\n")
	for _, want := range []string{"restored from an older copy", "matches state #3"} {
		if !strings.Contains(details, want) {
			t.Errorf("got details %q, want %q in them", details, want)
		}
	}

	for _, w := range r.Witnesses {
		if w.Status != "conflict" || w.Size != 5 {
			t.Errorf("witness %s: got %s size %d, want conflict size 5", w.Name, w.Status, w.Size)
		}
	}

	expect(t, "record", e.record(app.RecordOptions{}), app.ExitAlarm, "ALARM rollback")
	e.wantSizes("after the refused record", 3, 3)
	e.wantWitnesses("after the refused record", 5)
}

// TestRollbackWithTail rolls the storage back but leaves the entries file at
// the size the witnesses have seen. That's still a rollback.
func TestRollbackWithTail(t *testing.T) {
	t.Parallel()
	t.Run("old checkpoint put back", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, 2, 2)
		e.backupAndRecord(3)
		cp3 := readFile(t, e.checkpoint())
		e.backupAndRecord(1)
		writeFile(t, e.checkpoint(), cp3)
		e.remove(e.ids[3])

		a := e.audit(app.AuditOptions{})
		expect(t, "audit", a, app.ExitAlarm, "ALARM rollback", "ALARM tampered")

		r := e.record(app.RecordOptions{})
		expect(t, "record", r, app.ExitAlarm, "ALARM rollback", "ALARM tampered")
		wantKeepAdvice(t, a, r)
		e.wantSizes("after the refused record", 4, 3)
		e.wantWitnesses("after the refused record", 4)
	})
	t.Run("old copy padded with junk", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, 2, 2)
		e.backupAndRecord(3)
		p3 := e.save()
		e.backupAndRecord(2)
		e.restore(p3)
		e.appendFrames([]byte("junk frame one"), []byte("junk frame two"))

		a := e.audit(app.AuditOptions{})
		expect(t, "audit", a, app.ExitAlarm, "ALARM rollback", "ALARM tampered")

		r := e.record(app.RecordOptions{})
		expect(t, "record", r, app.ExitAlarm, "ALARM rollback", "ALARM tampered")
		wantKeepAdvice(t, a, r)
		e.wantSizes("after the refused record", 5, 3)
		e.wantWitnesses("after the refused record", 5)
	})
}

// TestRollbackToGenesis empties the log and puts back the size 0 checkpoint
// from init. The witnesses are at 3, which makes it a rollback.
func TestRollbackToGenesis(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	genesis := readFile(t, e.checkpoint())
	e.backupAndRecord(3)
	writeFile(t, e.entries(), nil)
	writeFile(t, e.checkpoint(), genesis)

	expect(t, "audit", e.audit(app.AuditOptions{}), app.ExitAlarm, "ALARM rollback", "ALARM stale", "WARN unrecorded")
	expect(t, "record", e.record(app.RecordOptions{}), app.ExitAlarm, "ALARM rollback")
	e.wantSizes("after the refused record", 0, 0)
	e.wantWitnesses("after the refused record", 3)
}

// TestAuditTimeout cuts an audit short while one witness is slow. A rollback
// the fast witness proved before the timeout has to stay in the report.
func TestAuditTimeout(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.backupAndRecord(3)
	p3 := e.save()
	e.backupAndRecord(2)
	e.restore(p3)
	e.ws[1].SetDelay(time.Minute)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	r := app.Audit(ctx, e.cfg, e.wc, app.AuditOptions{})
	expect(t, "audit", r, app.ExitAlarm, "ALARM rollback")

	if !strings.Contains(r.Err, "deadline") {
		t.Errorf("got error %q, want the timeout", r.Err)
	}

	if msg := finding(t, r, "rollback").Message; !strings.Contains(msg, "witness w1.test has seen log size 5") {
		t.Errorf("got message %q, want the witness that answered", msg)
	}
}

func TestFork(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.backupAndRecord(2)
	p2 := e.save()
	e.backupAndRecord(1)

	// a different third record on the old copy, witnesses down. Record stores
	// its log-signed checkpoint before asking them, which means the log key
	// has now signed two histories of size 3
	e.restore(p2)
	e.setDown(true)
	e.backup()
	e.record(app.RecordOptions{})
	e.setDown(false)

	expect(t, "audit", e.audit(app.AuditOptions{}), app.ExitAlarm, "ALARM fork", "ALARM stale")
	expect(t, "record", e.record(app.RecordOptions{}), app.ExitAlarm, "ALARM fork")
	e.wantSizes("after the refused record", 3, 3)
}

// TestQuorumLoss records with one of two witnesses down. The checkpoint is
// stored anyway. Once the witness is back, an audit brings it up to date
// with no rollback alarm, whichever answer Collect sees first.
func TestQuorumLoss(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.backupAndRecord(3)
	e.ws[1].SetDown(true)
	e.backup()

	r := e.record(app.RecordOptions{})
	expect(t, "record", r, app.ExitAlarm, "ALARM quorum", "WARN witness")

	if msg := finding(t, r, "quorum").Message; !strings.Contains(msg, "the checkpoint is saved") {
		t.Errorf("got message %q, want it to say the checkpoint is saved", msg)
	}

	e.wantSizes("after the record without quorum", 4, 4)
	expect(t, "audit with a witness down", e.audit(app.AuditOptions{}), app.ExitAlarm, "ALARM stale", "WARN witness")

	e.ws[1].SetDown(false)
	expect(t, "audit", e.audit(app.AuditOptions{}), app.ExitOK)
	e.wantWitnesses("after the audit", 4)
	expect(t, "record again", e.record(app.RecordOptions{}), app.ExitOK)
	e.wantSizes("after the record with quorum", 5, 5)
	expect(t, "audit again", e.audit(app.AuditOptions{}), app.ExitOK)
}

func TestQuorumLossOnFirstRecord(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 2)
	e.ws[1].SetDown(true)
	e.backup()

	expect(t, "record", e.record(app.RecordOptions{}), app.ExitAlarm, "ALARM quorum", "WARN witness")
	e.wantSizes("after the first record", 1, 1)
	expect(t, "audit", e.audit(app.AuditOptions{}), app.ExitAlarm, "ALARM stale", "WARN witness")

	e.ws[1].SetDown(false)
	expect(t, "record again", e.record(app.RecordOptions{}), app.ExitOK)
	expect(t, "audit again", e.audit(app.AuditOptions{}), app.ExitOK)
}

// slowAfterList is the keyed view of e, and slows one witness once record has
// listed the snapshots. Only the cosign request after the append is slow.
type slowAfterList struct {
	*env
	slow *witnesstest.Witness
}

func (s slowAfterList) Snapshots(ctx context.Context) ([]restic.Snapshot, error) {
	s.slow.SetDelay(time.Minute)
	return s.env.Snapshots(ctx)
}

// cancelOnCut cancels the caller when a witness request gets cut, like an
// interrupt right after the quorum stop.
type cancelOnCut struct{ cancel context.CancelFunc }

func (c cancelOnCut) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if req.Context().Err() != nil {
		c.cancel()
	}

	return resp, err
}

// TestRecordInterrupted cancels a record right after the quorum cosigned.
// The cosignatures we got back must still be stored.
func TestRecordInterrupted(t *testing.T) {
	t.Parallel()
	e := newEnv(t, 2, 1)
	e.backupAndRecord(1)
	e.backup()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	wc := &witness.Client{HTTP: &http.Client{Transport: cancelOnCut{cancel}}}
	r := app.Record(ctx, e.cfg, slowAfterList{e, e.ws[1]}, wc, app.RecordOptions{})

	if ctx.Err() == nil {
		t.Fatal("got no interrupt, want the cut request to cancel the record")
	}

	expect(t, "record", r, app.ExitOK)
	e.wantSizes("after the interrupted record", 2, 2)

	logKey, err := e.cfg.LogVerifier()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := e.cfg.WitnessVerifiers()
	if err != nil {
		t.Fatal(err)
	}

	v, err := wlog.Verify(readFile(t, e.checkpoint()), logKey, keys)
	if err != nil {
		t.Fatal(err)
	}

	if len(v.Cosigs) != 1 || v.Cosigs[0].Name != "w1.test" {
		t.Errorf("got cosignatures %+v, want the one from w1.test", v.Cosigs)
	}
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

func TestAuditAll(t *testing.T) {
	t.Parallel()
	slow, fast := newEnv(t, 1, 1), newEnv(t, 1, 1)
	slow.backupAndRecord(1)
	fast.backupAndRecord(1)
	slow.ws[0].SetDelay(time.Minute)

	start := time.Now()
	cfgs := []*config.Config{slow.cfg, fast.cfg}
	reports := app.AuditAll(t.Context(), cfgs, &witness.Client{}, app.AuditOptions{}, 5*time.Second)

	if took := time.Since(start); took > 30*time.Second {
		t.Errorf("got %s, want the timeout to cut the slow audit", took)
	}

	if len(reports) != 2 || reports[0].Config != slow.cfg.Path || reports[1].Config != fast.cfg.Path {
		t.Fatalf("got %d reports, want 2 in the order of the configs", len(reports))
	}

	if r := reports[0]; r.ExitCode() != app.ExitError || !strings.Contains(r.Err, "deadline") {
		t.Errorf("slow: got exit %d with error %q, want exit %d after the timeout", r.ExitCode(), r.Err, app.ExitError)
	}

	expect(t, "fast", reports[1], app.ExitOK)
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

	logKey, err := cfg.LogVerifier()
	if err != nil {
		t.Fatal(err)
	}

	v, err := wlog.Verify(readFile(t, filepath.Join(cfg.LogDir, wlog.CheckpointFile)), logKey, nil)
	if err != nil {
		t.Fatalf("genesis checkpoint: %v", err)
	}

	if v.Size != 0 || len(readFile(t, filepath.Join(cfg.LogDir, wlog.EntriesFile))) != 0 {
		t.Errorf("got checkpoint size %d, want an empty log with a size 0 checkpoint", v.Size)
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
		change func(t *testing.T, o *app.InitOptions)
	}{
		{"upper case name", func(_ *testing.T, o *app.InitOptions) { o.Name = "Demo" }},
		{"empty name", func(_ *testing.T, o *app.InitOptions) { o.Name = "" }},
		{"long name", func(_ *testing.T, o *app.InitOptions) { o.Name = strings.Repeat("a", 33) }},
		{"quorum 0", func(_ *testing.T, o *app.InitOptions) { o.Quorum = 0 }},
		{"quorum above witnesses", func(_ *testing.T, o *app.InitOptions) { o.Quorum = 2 }},
		{"bad witness key", func(_ *testing.T, o *app.InitOptions) {
			o.Witnesses = []config.Witness{{VKey: "w1+00000000+bad", URL: w.URL()}}
		}},
		{"log exists", func(t *testing.T, o *app.InitOptions) {
			if err := wlog.Create(o.LogDir); err != nil {
				t.Fatal(err)
			}
		}},
		{"checkpoint left over", func(t *testing.T, o *app.InitOptions) {
			if err := os.MkdirAll(o.LogDir, 0o750); err != nil {
				t.Fatal(err)
			}

			writeFile(t, filepath.Join(o.LogDir, wlog.CheckpointFile), []byte("old"))
		}},
		{"key inside the log dir", func(_ *testing.T, o *app.InitOptions) {
			o.ConfigPath = filepath.Join(o.LogDir, "snapwitness.conf")
		}},
		{"key inside the repo", func(_ *testing.T, o *app.InitOptions) {
			o.ConfigPath = filepath.Join(o.Repo, "conf", "snapwitness.conf")
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
			tt.change(t, &opts)

			if _, err := app.Init(opts, io.Discard); err == nil {
				t.Fatal("got no error, want init to refuse")
			}

			for _, path := range []string{opts.ConfigPath, filepath.Join(filepath.Dir(opts.ConfigPath), "log.key")} {
				if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s: got %v, want no file left behind", path, err)
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

	if strings.Contains(b.String(), `"time"`) {
		t.Errorf("got %s, want no time for a witness without one", b.String())
	}

	var back app.Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatalf("decode into a report: %v", err)
	}

	if !reflect.DeepEqual(back.Findings, r.Findings) || back.ExitCode() != app.ExitAlarm {
		t.Errorf("got findings %+v, want %+v", back.Findings, r.Findings)
	}

	if err := json.Unmarshal([]byte(`{"findings":[{"severity":"LOUD"}]}`), &back); err == nil {
		t.Error("got no error for an unknown severity, want one")
	}
}
