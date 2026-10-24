package restic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeRestic writes a fake restic script. It saves its arguments to argsFile,
// one per line, then runs body.
func fakeRestic(t *testing.T, body string) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "restic")
	argsFile = filepath.Join(dir, "args")

	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > " + argsFile + "\n" + body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	return bin, argsFile
}

func hexID(n int) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(n))))
}

func TestSnapshots(t *testing.T) {
	a, b := hexID(1), hexID(2)
	if a < b {
		a, b = b, a
	}

	out := fmt.Sprintf(
		`[{"id":%q,"time":"2026-10-01T10:00:00.123+02:00","program_version":"restic 0.19.1","hostname":"h"},`+
			`{"id":%q,"time":"2026-10-01T11:00:00Z","program_version":"restic 0.19.1"}]`,
		a,
		b,
	)
	bin, argsFile := fakeRestic(t, "printf '%s' '"+out+"'")

	c := &CLI{Bin: bin, Repo: "/repo path", Env: []string{"RESTIC_PASSWORD=x"}}

	snaps, err := c.Snapshots(t.Context())
	if err != nil {
		t.Fatalf("snapshots: %v", err)
	}

	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(args), "-r\n/repo path\nsnapshots\n--json\n--no-lock\n"; got != want {
		t.Fatalf("args: got %q, want %q", got, want)
	}

	if len(snaps) != 2 || snaps[0].ID != b || snaps[1].ID != a {
		t.Fatalf("got %+v, want ids %s then %s", snaps, b, a)
	}

	if snaps[0].ProgramVersion != "restic 0.19.1" || snaps[0].Time.Hour() != 11 {
		t.Fatalf("got %+v, want version and time decoded", snaps[0])
	}
}

func TestSnapshotsEnv(t *testing.T) {
	bin, _ := fakeRestic(t, `printf '[{"id":"%s"}]' "$SNAP_ID"`)
	c := &CLI{Bin: bin, Repo: "r", Env: []string{"SNAP_ID=" + hexID(7)}}

	snaps, err := c.Snapshots(t.Context())
	if err != nil {
		t.Fatalf("snapshots: %v", err)
	}

	if len(snaps) != 1 || snaps[0].ID != hexID(7) {
		t.Fatalf("got %+v, want one snapshot %s from Env", snaps, hexID(7))
	}
}

func TestSnapshotsEmpty(t *testing.T) {
	bin, _ := fakeRestic(t, "echo '[]'")

	snaps, err := (&CLI{Bin: bin, Repo: "r"}).Snapshots(t.Context())
	if err != nil || len(snaps) != 0 {
		t.Fatalf("got %v, %v, want no snapshots and no error", snaps, err)
	}
}

func TestSnapshotsErrors(t *testing.T) {
	long := strings.Repeat("x", 3000)
	tests := []struct {
		name    string
		body    string
		wantErr string
		notErr  string
	}{
		{"bad id", `echo '[{"id":"ABC"}]'`, `bad snapshot id "ABC"`, ""},
		{"uppercase id", `echo '[{"id":"` + strings.ToUpper(hexID(1)) + `"}]'`, "bad snapshot id", ""},
		{"not json", "echo 'Fatal: nope'", "decode", ""},
		{
			"exit 1", "echo 'Fatal: wrong password or no key found' >&2; exit 1",
			`exit code 1: "Fatal: wrong password or no key found"`, "",
		},
		{
			"stderr tail",
			"printf 'HEAD%sTAIL' " + long + " >&2; exit 3",
			`exit code 3: "` + strings.Repeat("x", 2044) + `TAIL"`,
			"HEAD",
		},
		{
			"escape codes quoted",
			`printf 'Fatal: \033[31mred\n' >&2; exit 1`,
			`exit code 1: "Fatal: \x1b[31mred"`,
			"\x1b[",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, _ := fakeRestic(t, tt.body)

			_, err := (&CLI{Bin: bin, Repo: "r"}).Snapshots(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}

			if tt.notErr != "" && strings.Contains(err.Error(), tt.notErr) {
				t.Fatalf("got %v, want no %q (only the last 2 KiB of stderr)", err, tt.notErr)
			}
		})
	}
}

func TestSnapshotsCancel(t *testing.T) {
	bin, _ := fakeRestic(t, "echo 'started' >&2; exec sleep 30")
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)

	defer cancel()

	start := time.Now()

	_, err := (&CLI{Bin: bin, Repo: "r"}).Snapshots(ctx)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}

	if strings.Contains(err.Error(), "exit code") {
		t.Errorf("got %q, want the ctx error, not an exit code", err)
	}

	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("snapshots took %v after the deadline, want well under 3s", took)
	}
}

func TestSnapshotsMissingBinary(t *testing.T) {
	c := &CLI{Bin: filepath.Join(t.TempDir(), "nope"), Repo: "r"}
	if _, err := c.Snapshots(t.Context()); err == nil {
		t.Fatal("got nil, want error for a missing binary")
	}
}

func writeSnapshot(t testing.TB, dir string, content []byte) string {
	t.Helper()

	sum := sha256.Sum256(content)

	name := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o400); err != nil {
		t.Fatal(err)
	}

	return name
}

func TestList(t *testing.T) {
	repo := t.TempDir()

	dir := filepath.Join(repo, "snapshots")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var ids []string
	for i := range 20 {
		ids = append(ids, writeSnapshot(t, dir, []byte(fmt.Sprintf("snapshot %02d padded to at least 32 bytes", i))))
	}

	slices.Sort(ids)

	// The name claims one content while the file holds another
	mismatch := hexID(99)
	if err := os.WriteFile(
		filepath.Join(dir, mismatch),
		[]byte("swapped content, still 32 bytes or more"),
		0o400,
	); err != nil {
		t.Fatal(err)
	}

	foreign := "notes.txt"
	if err := os.WriteFile(filepath.Join(dir, foreign), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	short := writeSnapshot(t, dir, []byte("12345"))
	if err := os.Mkdir(filepath.Join(dir, hexID(100)), 0o755); err != nil {
		t.Fatal(err)
	}

	var bytes int64

	for _, id := range ids {
		info, err := os.Stat(filepath.Join(dir, id))
		if err != nil {
			t.Fatal(err)
		}

		bytes += info.Size()
	}

	bytes += int64(len("swapped content, still 32 bytes or more")) + 5 + 5

	for _, workers := range []int{0, 1, 4} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			l, err := List(t.Context(), repo, workers)
			if err != nil {
				t.Fatalf("list: %v", err)
			}

			if !reflect.DeepEqual(l.IDs, ids) {
				t.Errorf("ids: got %v, want %v", l.IDs, ids)
			}

			if !reflect.DeepEqual(l.Mismatch, []string{mismatch}) {
				t.Errorf("mismatch: got %v, want [%s]", l.Mismatch, mismatch)
			}

			if want := []string{hexID(100) + " (dir)", foreign}; !reflect.DeepEqual(l.Foreign, want) {
				t.Errorf("foreign: got %v, want %v", l.Foreign, want)
			}

			if !reflect.DeepEqual(l.TooShort, []string{short}) {
				t.Errorf("too short: got %v, want [%s]", l.TooShort, short)
			}

			if l.Files != 24 {
				t.Errorf("files: got %d, want 24", l.Files)
			}

			if l.Bytes != bytes {
				t.Errorf("bytes: got %d, want %d", l.Bytes, bytes)
			}
		})
	}
}

func TestListEmpty(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}

	l, err := List(t.Context(), repo, 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if l.IDs != nil || l.Files != 0 || l.Bytes != 0 {
		t.Fatalf("got %+v, want an empty listing", l)
	}
}

func TestListErrors(t *testing.T) {
	if _, err := List(t.Context(), t.TempDir(), 1); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing snapshots dir: got %v, want fs.ErrNotExist", err)
	}

	repo, dir := snapshotsDir(t)
	writeSnapshot(t, dir, []byte("one snapshot file of at least 32 bytes"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := List(ctx, repo, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: got %v, want context.Canceled", err)
	}
}

func snapshotsDir(t *testing.T) (repo, dir string) {
	t.Helper()
	repo = t.TempDir()

	dir = filepath.Join(repo, "snapshots")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	return repo, dir
}

func TestListNonRegular(t *testing.T) {
	repo, dir := snapshotsDir(t)
	snap := writeSnapshot(t, dir, []byte("a real snapshot file of at least 32 bytes"))

	outside := filepath.Join(repo, "outside")
	if err := os.WriteFile(outside, []byte("content somewhere else, 32 bytes or more"), 0o600); err != nil {
		t.Fatal(err)
	}

	link, fifo, sub := hexID(1), hexID(2), hexID(3)
	if err := os.Symlink(outside, filepath.Join(dir, link)); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	if err := syscall.Mkfifo(filepath.Join(dir, fifo), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
		t.Fatal(err)
	}

	// List runs in a goroutine: opening a fifo for reading blocks until
	// there's a writer
	type listed struct {
		l   *Listing
		err error
	}

	done := make(chan listed, 1)

	go func() {
		l, err := List(t.Context(), repo, 2)
		done <- listed{l, err}
	}()

	var got listed
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("list blocked on a non-regular entry")
	}

	if got.err != nil {
		t.Fatalf("list: %v", got.err)
	}

	want := []string{link + " (symlink)", fifo + " (fifo)", sub + " (dir)", "link (symlink)"}
	slices.Sort(want)

	if !reflect.DeepEqual(got.l.Foreign, want) {
		t.Errorf("foreign: got %v, want %v", got.l.Foreign, want)
	}

	if !reflect.DeepEqual(got.l.IDs, []string{snap}) || got.l.Mismatch != nil {
		t.Errorf("got ids %v, mismatch %v, want ids [%s] and no mismatch", got.l.IDs, got.l.Mismatch, snap)
	}

	if got.l.Files != 5 {
		t.Errorf("files: got %d, want 5", got.l.Files)
	}
}

func TestListOversized(t *testing.T) {
	repo, dir := snapshotsDir(t)
	big := hexID(1)

	path := filepath.Join(dir, big)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// sparse: no disk space, and still far too slow to hash in time
	if err := os.Truncate(path, 64<<30); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)

	defer cancel()

	l, err := List(ctx, repo, 1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if !reflect.DeepEqual(l.Mismatch, []string{big}) || l.IDs != nil {
		t.Errorf("got mismatch %v, ids %v, want mismatch [%s] and no ids", l.Mismatch, l.IDs, big)
	}

	if l.Bytes != 64<<30 {
		t.Errorf("bytes: got %d, want %d", l.Bytes, int64(64<<30))
	}
}

func TestListUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a file of mode 0")
	}

	repo, dir := snapshotsDir(t)
	ok := writeSnapshot(t, dir, []byte("a snapshot the lister can read, 32+ bytes"))

	bad := writeSnapshot(t, dir, []byte("a file the lister cannot open, 32+ bytes"))
	if err := os.Chmod(filepath.Join(dir, bad), 0o000); err != nil {
		t.Fatal(err)
	}

	l, err := List(t.Context(), repo, 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if !reflect.DeepEqual(l.Mismatch, []string{bad}) || !reflect.DeepEqual(l.IDs, []string{ok}) {
		t.Errorf("got mismatch %v, ids %v, want mismatch [%s], ids [%s]", l.Mismatch, l.IDs, bad, ok)
	}
}

func TestCheckFileVanished(t *testing.T) {
	r, err := checkFile(t.Context(), t.TempDir(), hexID(1))
	if err != nil || !r.gone {
		t.Fatalf("got %+v, %v, want gone and no error", r, err)
	}
}

// cancelAfter calls cancel once n bytes have been read through it.
type cancelAfter struct {
	r      io.Reader
	n      int64
	cancel context.CancelFunc
}

func (c *cancelAfter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.n -= int64(n); c.n <= 0 {
		c.cancel()
	}

	return n, err
}

func TestHashCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// A sparse 8 GiB file takes seconds to hash in full
	if err := os.Truncate(path, 8<<30); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:errcheck // read only
	defer f.Close()

	ctx, cancel := context.WithCancel(t.Context())

	defer cancel()

	start := time.Now()

	_, n, err := hash(ctx, &cancelAfter{r: f, n: 32 << 20, cancel: cancel})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}

	// hash must check ctx at least once per MiB
	if n > 33<<20 {
		t.Errorf("read %d bytes, want at most 1 MiB past the cancel at %d", n, 32<<20)
	}

	if took := time.Since(start); took > time.Second {
		t.Errorf("hash took %v, want well under 1s", took)
	}
}

func BenchmarkList(b *testing.B) {
	repo := b.TempDir()

	dir := filepath.Join(repo, "snapshots")
	if err := os.Mkdir(dir, 0o755); err != nil {
		b.Fatal(err)
	}

	for i := range 2000 {
		writeSnapshot(
			b,
			dir,
			[]byte(fmt.Sprintf("snapshot file %05d, about 500 bytes like restic %s", i, strings.Repeat("p", 450))),
		)
	}

	for _, workers := range []int{1, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			for b.Loop() {
				l, err := List(b.Context(), repo, workers)
				if err != nil {
					b.Fatal(err)
				}

				if len(l.IDs) != 2000 {
					b.Fatalf("got %d ids, want 2000", len(l.IDs))
				}
			}
		})
	}
}
