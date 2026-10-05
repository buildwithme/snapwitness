package restic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
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
			"exit code 1: Fatal: wrong password or no key found", "",
		},
		{
			"stderr tail",
			"printf 'HEAD%sTAIL' " + long + " >&2; exit 3",
			"exit code 3: " + strings.Repeat("x", 2044) + "TAIL",
			"HEAD",
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

			if !reflect.DeepEqual(l.Foreign, []string{foreign}) {
				t.Errorf("foreign: got %v, want [%s]", l.Foreign, foreign)
			}

			if !reflect.DeepEqual(l.TooShort, []string{short}) {
				t.Errorf("too short: got %v, want [%s]", l.TooShort, short)
			}

			if l.Files != 23 {
				t.Errorf("files: got %d, want 23", l.Files)
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
	if _, err := List(t.Context(), t.TempDir(), 1); err == nil {
		t.Fatal("missing snapshots dir: got nil, want error")
	}

	repo := t.TempDir()

	dir := filepath.Join(repo, "snapshots")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeSnapshot(t, dir, []byte("one snapshot file of at least 32 bytes"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := List(ctx, repo, 1); err == nil {
		t.Fatal("cancelled context: got nil, want error")
	}

	unreadable := writeSnapshot(t, dir, []byte("a file the lister cannot open, 32+ bytes"))
	if err := os.Chmod(filepath.Join(dir, unreadable), 0o000); err != nil {
		t.Fatal(err)
	}

	if os.Getuid() != 0 {
		if _, err := List(t.Context(), repo, 2); err == nil {
			t.Fatal("unreadable file: got nil, want error")
		}
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
