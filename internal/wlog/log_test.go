package wlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"
)

func newLog(t testing.TB, entries ...[]byte) *Log {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "log")
	if err := Create(dir); err != nil {
		t.Fatal(err)
	}

	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}

	return l
}

func testEntries(n int) [][]byte {
	out := make([][]byte, n)
	for i := range n {
		out[i] = fmt.Appendf(nil, "entry %d", i)
	}

	return out
}

func encodeFrame(entry []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(entry))), entry...)
}

// mth is the RFC 6962 Merkle tree hash, written out without tlog.
func mth(entries [][]byte) tlog.Hash {
	switch len(entries) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return sha256.Sum256(append([]byte{0}, entries[0]...))
	}

	k := 1
	for k*2 < len(entries) {
		k *= 2
	}

	left, right := mth(entries[:k]), mth(entries[k:])

	return sha256.Sum256(append(append([]byte{1}, left[:]...), right[:]...))
}

func TestAppendOpenRoundTrip(t *testing.T) {
	entries := append(testEntries(7), bytes.Repeat([]byte{0xff}, MaxEntrySize))
	l := newLog(t, entries...)

	re, err := Open(l.Dir())
	if err != nil {
		t.Fatal(err)
	}

	if got, want := re.Size(), int64(len(entries)); got != want {
		t.Fatalf("got size %d, want %d", got, want)
	}

	for i, e := range re.Entries(re.Size()) {
		if !bytes.Equal(e, entries[i]) {
			t.Errorf("entry %d: got %.20q, want %.20q", i, e, entries[i])
		}
	}

	for n := range l.Size() + 1 {
		got, err := re.Root(n)
		if err != nil {
			t.Fatal(err)
		}

		want, err := l.Root(n)
		if err != nil {
			t.Fatal(err)
		}

		if got != want {
			t.Errorf("root %d after reopen: got %v, want %v", n, got, want)
		}

		if ref := mth(entries[:n]); got != ref {
			t.Errorf("root %d: got %v, want RFC 6962 %v", n, got, ref)
		}
	}
}

func TestOffset(t *testing.T) {
	l := newLog(t)
	want := []int64{0}

	for _, e := range testEntries(3) {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}

		fi, err := os.Stat(filepath.Join(l.Dir(), EntriesFile))
		if err != nil {
			t.Fatal(err)
		}

		want = append(want, fi.Size())
	}

	// Audit and record call Offset on a log read back by Open
	re, err := Open(l.Dir())
	if err != nil {
		t.Fatal(err)
	}

	for n, w := range want {
		if got := l.Offset(int64(n)); got != w {
			t.Errorf("Offset(%d): got %d, want %d", n, got, w)
		}

		if got := re.Offset(int64(n)); got != w {
			t.Errorf("Offset(%d) after Open: got %d, want %d", n, got, w)
		}
	}
}

func TestEntriesCannotOverwrite(t *testing.T) {
	l := newLog(t, testEntries(3)...)

	re, err := Open(l.Dir())
	if err != nil {
		t.Fatal(err)
	}

	for _, lg := range []*Log{l, re} {
		grown := append(lg.Entries(1), []byte("x"))

		longer := append(lg.Entries(1)[0], 'x')
		if string(grown[1]) != "x" || string(longer) != "entry 0x" {
			t.Fatalf("got %q and %q", grown, longer)
		}

		if got := lg.Entries(2); string(got[0]) != "entry 0" || string(got[1]) != "entry 1" {
			t.Errorf("got %q, want entries 0 and 1 unchanged", got)
		}
	}
}

func TestCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "log")
	if _, err := Open(dir); !errors.Is(err, ErrNoLog) {
		t.Fatalf("open before create: got %v, want ErrNoLog", err)
	}

	if err := Create(dir); err != nil {
		t.Fatal(err)
	}

	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	if l.Size() != 0 {
		t.Errorf("got size %d, want 0", l.Size())
	}

	if err := l.Append([]byte("keep me")); err != nil {
		t.Fatal(err)
	}

	if err := Create(dir); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second create: got %v, want fs.ErrExist", err)
	}

	re, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	if re.Size() != 1 {
		t.Errorf("after second create: got size %d, want 1", re.Size())
	}
}

func TestOpenRejectsBadFrames(t *testing.T) {
	good := encodeFrame([]byte("ok"))
	over := binary.BigEndian.AppendUint32(nil, MaxEntrySize+1)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"torn header", append(slices.Clone(good), 0, 0), "torn frame header"},
		{"trailing byte", append(slices.Clone(good), 7), "torn frame header"},
		{"torn entry", append(slices.Clone(good), encodeFrame([]byte("cut off"))[:7]...), "torn entry"},
		{"zero length", append(slices.Clone(good), 0, 0, 0, 0), "empty entry"},
		{"oversized with body", append(slices.Clone(over), make([]byte, MaxEntrySize+1)...), "over the limit"},
		{"oversized without body", over, "over the limit"},
		{"max length", binary.BigEndian.AppendUint32(nil, math.MaxUint32), "over the limit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, EntriesFile), tt.data, 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := Open(dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error with %q", err, tt.want)
			}
		})
	}
}

func TestReadRejectsOtherFiles(t *testing.T) {
	// Each helper puts something other than a regular file at name in dir
	symlink := func(t *testing.T, dir, name string) {
		t.Helper()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, encodeFrame([]byte("elsewhere")), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	dangling := func(t *testing.T, dir, name string) {
		t.Helper()

		if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	fifo := func(t *testing.T, dir, name string) {
		t.Helper()

		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		file  string
		setup func(t *testing.T, dir, name string)
		want  string
	}{
		{"symlinked entries", EntriesFile, symlink, ""},
		{"dangling entries symlink", EntriesFile, dangling, ""},
		{"fifo entries", EntriesFile, fifo, "not a regular file"},
		{"symlinked checkpoint", CheckpointFile, symlink, ""},
		{"dangling checkpoint symlink", CheckpointFile, dangling, ""},
		{"fifo checkpoint", CheckpointFile, fifo, "not a regular file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.file == CheckpointFile {
				dir = newLog(t, []byte("entry")).Dir()
			}

			tt.setup(t, dir, tt.file)
			// read in a goroutine. If the open on the fifo blocks, the test
			// fails and doesn't hang
			done := make(chan error, 1)

			go func() {
				if tt.file == EntriesFile {
					_, err := Open(dir)
					done <- err

					return
				}

				l, err := Open(dir)
				if err == nil {
					_, err = l.ReadCheckpoint()
				}

				done <- err
			}()

			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("read blocked, want an error")
			}

			if err == nil || errors.Is(err, ErrNoLog) || errors.Is(err, ErrNoCheckpoint) {
				t.Fatalf("got %v, want a read error", err)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error with %q", err, tt.want)
			}
		})
	}
}

func TestReadRejectsOverCap(t *testing.T) {
	// sparse file, the test shouldn't write 256 MiB
	sized := func(t *testing.T, path string, size int64) {
		t.Helper()

		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatal(err)
		}

		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}

		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	sized(t, filepath.Join(dir, EntriesFile), maxEntriesSize+1)

	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "over 268435456 bytes") {
		t.Errorf("entries over the cap: got %v, want an over error", err)
	}

	l := newLog(t)
	path := filepath.Join(l.Dir(), CheckpointFile)
	sized(t, path, maxCheckpointSize)

	if b, err := l.ReadCheckpoint(); err != nil || len(b) != maxCheckpointSize {
		t.Errorf("checkpoint at the cap: got %d bytes and %v, want %d bytes", len(b), err, maxCheckpointSize)
	}

	sized(t, path, maxCheckpointSize+1)

	if _, err := l.ReadCheckpoint(); err == nil || !strings.Contains(err.Error(), "over 1048576 bytes") {
		t.Errorf("checkpoint over the cap: got %v, want an over error", err)
	}
}

func TestAppendRejects(t *testing.T) {
	tests := []struct {
		name  string
		entry []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"oversized", make([]byte, MaxEntrySize+1)},
	}
	l := newLog(t, []byte("first"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := l.Append(tt.entry); err == nil {
				t.Fatal("got nil error, want one")
			}

			if l.Size() != 1 {
				t.Errorf("got size %d, want 1", l.Size())
			}

			re, err := Open(l.Dir())
			if err != nil {
				t.Fatal(err)
			}

			if re.Size() != 1 {
				t.Errorf("reopen: got size %d, want 1", re.Size())
			}
		})
	}
}

func TestRootAndConsistency(t *testing.T) {
	const size = 20

	entries := testEntries(size)
	l := newLog(t, entries...)

	roots := make([]tlog.Hash, size+1)
	for n := range int64(size + 1) {
		r, err := l.Root(n)
		if err != nil {
			t.Fatal(err)
		}

		if want := mth(entries[:n]); r != want {
			t.Errorf("root %d: got %v, want %v", n, r, want)
		}

		roots[n] = r
	}

	if got, want := hex.EncodeToString(
		roots[0][:],
	), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Errorf("empty root: got %s, want %s", got, want)
	}

	for to := int64(2); to <= size; to++ {
		for from := int64(1); from < to; from++ {
			p, err := l.Consistency(from, to)
			if err != nil {
				t.Fatalf("consistency %d to %d: %v", from, to, err)
			}

			if err := tlog.CheckTree(p, to, roots[to], from, roots[from]); err != nil {
				t.Errorf("consistency %d to %d: %v", from, to, err)
			}
		}
	}

	for n := range int64(size + 1) {
		for _, from := range []int64{0, n} {
			p, err := l.Consistency(from, n)
			if err != nil || len(p) != 0 {
				t.Errorf("consistency %d to %d: got %d hashes and %v, want an empty proof", from, n, len(p), err)
			}
		}
	}

	bad := []struct{ from, to int64 }{{-1, 1}, {2, 1}, {0, size + 1}, {size + 1, size + 1}, {size, size + 1}}
	for _, b := range bad {
		if _, err := l.Consistency(b.from, b.to); err == nil {
			t.Errorf("consistency %d to %d: got nil error, want one", b.from, b.to)
		}
	}

	for _, n := range []int64{-1, size + 1} {
		if _, err := l.Root(n); err == nil {
			t.Errorf("root %d: got nil error, want one", n)
		}
	}
}

func TestCheckpointFile(t *testing.T) {
	l := newLog(t)
	if _, err := l.ReadCheckpoint(); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("got %v, want ErrNoCheckpoint", err)
	}

	for _, want := range []string{"first\n", "second\n"} {
		if err := l.WriteCheckpoint([]byte(want)); err != nil {
			t.Fatal(err)
		}

		got, err := l.ReadCheckpoint()
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	st, err := os.Stat(filepath.Join(l.Dir(), CheckpointFile))
	if err != nil {
		t.Fatal(err)
	}

	if got := st.Mode().Perm(); got != 0o644 {
		t.Errorf("got mode %v, want 0644", got)
	}

	assertFiles(t, l.Dir(), CheckpointFile, EntriesFile)
}

func TestWriteCheckpointRemovesTemp(t *testing.T) {
	l := newLog(t)
	// a file can't replace a non-empty directory; the rename fails
	if err := os.MkdirAll(filepath.Join(l.Dir(), CheckpointFile, "x"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := l.WriteCheckpoint([]byte("note\n")); err == nil {
		t.Fatal("got nil error, want one")
	}

	assertFiles(t, l.Dir(), CheckpointFile, EntriesFile)

	if _, err := l.ReadCheckpoint(); err == nil || errors.Is(err, ErrNoCheckpoint) {
		t.Errorf("read a directory: got %v, want a not a regular file error", err)
	}
}

func TestAppendRejectsSwappedEntries(t *testing.T) {
	// Write a copy of the entries file, the same size, at path
	copyTo := func(t *testing.T, dir, path string) {
		t.Helper()

		b, err := os.ReadFile(filepath.Join(dir, EntriesFile))
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, dir, target string) {
		t.Helper()

		if err := os.Remove(filepath.Join(dir, EntriesFile)); err != nil {
			t.Fatal(err)
		}

		if err := os.Symlink(target, filepath.Join(dir, EntriesFile)); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name string
		swap func(t *testing.T, dir, outside string)
		want string
	}{
		{"symlink to a file outside the dir", func(t *testing.T, dir, outside string) {
			copyTo(t, dir, outside)
			link(t, dir, outside)
		}, ""},
		{"symlink to a file in the dir", func(t *testing.T, dir, _ string) {
			copyTo(t, dir, filepath.Join(dir, "copy"))
			link(t, dir, "copy")
		}, "entries changed on the storage"},
		{"another regular file", func(t *testing.T, dir, _ string) {
			copyTo(t, dir, filepath.Join(dir, "copy"))

			if err := os.Rename(filepath.Join(dir, "copy"), filepath.Join(dir, EntriesFile)); err != nil {
				t.Fatal(err)
			}
		}, "entries changed on the storage"},
		{"grown on the storage", func(t *testing.T, dir, _ string) {
			f, err := os.OpenFile(filepath.Join(dir, EntriesFile), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := f.Write(encodeFrame([]byte("planted"))); err != nil {
				t.Fatal(err)
			}

			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}, "entries changed on the storage"},
		{"fifo", func(t *testing.T, dir, _ string) {
			if err := os.Remove(filepath.Join(dir, EntriesFile)); err != nil {
				t.Fatal(err)
			}

			if err := syscall.Mkfifo(filepath.Join(dir, EntriesFile), 0o644); err != nil {
				t.Fatal(err)
			}
		}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLog(t, []byte("first"))
			outside := filepath.Join(t.TempDir(), "outside")
			tt.swap(t, l.Dir(), outside)
			before := contents(t, l.Dir(), outside)
			// Append in a goroutine so a blocking open on the fifo fails the
			// test instead of hanging it
			done := make(chan error, 1)
			go func() { done <- l.Append([]byte("second")) }()

			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("append blocked, want an error")
			}

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want an error with %q", err, tt.want)
			}

			if l.Size() != 1 {
				t.Errorf("got size %d, want 1", l.Size())
			}

			if after := contents(t, l.Dir(), outside); !maps.Equal(after, before) {
				t.Errorf("got files %q after the append, want %q", after, before)
			}
		})
	}
}

func TestWritesRejectSwappedDir(t *testing.T) {
	l := newLog(t, []byte("first"))
	if err := l.WriteCheckpoint([]byte("old\n")); err != nil {
		t.Fatal(err)
	}

	// Move the log away and put a symlink to a dir outside the storage in its
	// place
	moved := l.Dir() + ".moved"
	if err := os.Rename(l.Dir(), moved); err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()

	b, err := os.ReadFile(filepath.Join(moved, EntriesFile))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(outside, EntriesFile), b, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(outside, l.Dir()); err != nil {
		t.Fatal(err)
	}

	before := contents(t, outside)

	const want = "changed on the storage"
	if err := l.WriteCheckpoint([]byte("new\n")); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("write checkpoint: got %v, want an error with %q", err, want)
	}

	if err := l.Append([]byte("second")); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("append: got %v, want an error with %q", err, want)
	}

	if after := contents(t, outside); !maps.Equal(after, before) {
		t.Errorf("got files %q outside, want %q", after, before)
	}

	if got := contents(t, moved)[filepath.Join(moved, CheckpointFile)]; got != "old\n" {
		t.Errorf("got checkpoint %q in the log, want %q", got, "old\n")
	}
}

func TestSymlinkedDir(t *testing.T) {
	target := newLog(t, []byte("first")).Dir()

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{link, link + "/"} {
		if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "is not a directory") {
			t.Errorf("open %s: got %v, want a not a directory error", dir, err)
		}
	}

	empty := t.TempDir()

	link = filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(empty, link); err != nil {
		t.Fatal(err)
	}

	if err := Create(link); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("create: got %v, want a not a directory error", err)
	}

	assertFiles(t, empty)
}

// contents maps path to bytes for every regular file in dir, plus the extra
// paths that are regular files.
func contents(t *testing.T, dir string, extra ...string) map[string]string {
	t.Helper()

	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	paths := slices.Clone(extra)
	for _, de := range des {
		paths = append(paths, filepath.Join(dir, de.Name()))
	}

	out := map[string]string{}

	for _, p := range paths {
		if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
			continue
		}

		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}

		out[p] = string(b)
	}

	return out
}

func assertFiles(t *testing.T, dir string, want ...string) {
	t.Helper()

	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, de := range des {
		got = append(got, de.Name())
	}

	if !slices.Equal(got, want) {
		t.Errorf("got files %q, want %q", got, want)
	}
}

func BenchmarkOpen(b *testing.B) {
	dir := b.TempDir()
	entry := bytes.Repeat([]byte{'x'}, 200)

	var data []byte

	for range 10_000 {
		data = append(data, encodeFrame(entry)...)
	}

	if err := os.WriteFile(filepath.Join(dir, EntriesFile), data, 0o644); err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if _, err := Open(dir); err != nil {
			b.Fatal(err)
		}
	}
}
