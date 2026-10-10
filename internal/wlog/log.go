// Package wlog keeps the append-only Merkle log of state records next to the
// backup repository, and reads, signs and verifies its checkpoints. The log
// lives on the same untrusted storage as the backup and can't stop a
// rewrite. It's the witnessed checkpoints that make a rewrite or a rollback
// visible.
package wlog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/mod/sumdb/tlog"
)

// Files inside the log directory and the largest entry the log accepts.
const (
	EntriesFile    = "entries"
	CheckpointFile = "checkpoint"
	MaxEntrySize   = 4 << 20
)

const (
	// frameHeader is the 4-byte big-endian length in front of every entry.
	frameHeader = 4
)

// ErrNoLog is returned by Open when the entries file is missing.
var ErrNoLog = errors.New("wlog: no log")

// Log is an append-only Merkle log kept in one directory next to the backup
// repository.
type Log struct {
	dir     string
	entries [][]byte
	hashes  []tlog.Hash // from tlog.StoredHashes, in storage order
}

// Create makes the log directory and an empty entries file. It fails if the
// entries file is already there and never truncates a log.
func Create(dir string) error {
	//nolint:gosec // the auditor may read the log as another user
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	//nolint:gosec // the log is public, the auditor may read it as another user
	f, err := os.OpenFile(filepath.Join(dir, EntriesFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	return nil
}

// Open reads every entry in dir and recomputes the RFC 6962 hashes in
// memory. We never take a hash from the storage. ErrNoLog means the entries
// file is missing; a torn or oversized frame is an error too.
func Open(dir string) (*Log, error) {
	data, err := readRegular(filepath.Join(dir, EntriesFile), 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoLog
	}

	if err != nil {
		return nil, fmt.Errorf("wlog: open: %w", err)
	}

	l := &Log{dir: dir}

	for off := 0; off < len(data); {
		// the file is untrusted and a torn write leaves a short tail. Check the
		// length against the limit and the bytes left first
		rest := data[off:]
		if len(rest) < frameHeader {
			return nil, fmt.Errorf("wlog: open: torn frame header at offset %d", off)
		}

		n := binary.BigEndian.Uint32(rest)
		switch {
		case n == 0:
			return nil, fmt.Errorf("wlog: open: empty entry at offset %d", off)
		case n > MaxEntrySize:
			return nil, fmt.Errorf("wlog: open: entry of %d bytes at offset %d is over the limit", n, off)
		case int(n) > len(rest)-frameHeader:
			return nil, fmt.Errorf(
				"wlog: open: torn entry at offset %d: want %d bytes, have %d",
				off,
				n,
				len(rest)-frameHeader,
			)
		}

		end := frameHeader + int(n)
		// three-index slice: a caller appending to the entry can't overwrite
		// the next one
		entry := rest[frameHeader:end:end]

		hs, err := tlog.StoredHashes(l.Size(), entry, l.reader())
		if err != nil {
			return nil, fmt.Errorf("wlog: open: %w", err)
		}

		l.entries = append(l.entries, entry)
		l.hashes = append(l.hashes, hs...)
		off += end
	}

	return l, nil
}

// Dir returns the log directory.
func (l *Log) Dir() string {
	return l.dir
}

// Size returns the number of entries in the log.
func (l *Log) Size() int64 {
	return int64(len(l.entries))
}

// Entries returns the first n entries.
func (l *Log) Entries(n int64) [][]byte {
	return l.entries[:n:n]
}

// Append writes one entry at the end of the log and syncs it to disk before
// it returns. That way a checkpoint only ever covers stored entries.
func (l *Log) Append(entry []byte) error {
	if len(entry) == 0 || len(entry) > MaxEntrySize {
		return fmt.Errorf("wlog: append: entry of %d bytes, want 1 to %d", len(entry), MaxEntrySize)
	}

	hs, err := tlog.StoredHashes(l.Size(), entry, l.reader())
	if err != nil {
		return fmt.Errorf("wlog: append: %w", err)
	}

	frame := make([]byte, frameHeader+len(entry))
	//nolint:gosec // len(entry) <= MaxEntrySize, checked above
	binary.BigEndian.PutUint32(frame, uint32(len(entry)))
	copy(frame[frameHeader:], entry)

	if err := appendFrame(filepath.Join(l.dir, EntriesFile), frame); err != nil {
		return fmt.Errorf("wlog: append: %w", err)
	}

	l.entries = append(l.entries, frame[frameHeader:])
	l.hashes = append(l.hashes, hs...)

	return nil
}

// Root returns the Merkle tree hash of the first n entries, 0 <= n <= Size.
// For n == 0 tlog.TreeHash gives the SHA-256 of the empty string, which is
// the root of the empty tree in RFC 6962.
func (l *Log) Root(n int64) (tlog.Hash, error) {
	if n < 0 || n > l.Size() {
		return tlog.Hash{}, fmt.Errorf("wlog: root: size %d not in 0 to %d", n, l.Size())
	}

	h, err := tlog.TreeHash(n, l.reader())
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("wlog: root: %w", err)
	}

	return h, nil
}

// Consistency returns the proof that the tree of size from is a prefix of the
// tree of size to. The proof is empty when from is 0 or equal to to.
func (l *Log) Consistency(from, to int64) ([]tlog.Hash, error) {
	if from < 0 || from > to || to > l.Size() {
		return nil, fmt.Errorf("wlog: consistency: sizes %d to %d not in a log of %d", from, to, l.Size())
	}

	if from == 0 || from == to {
		return nil, nil
	}

	p, err := tlog.ProveTree(to, from, l.reader())
	if err != nil {
		return nil, fmt.Errorf("wlog: consistency: %w", err)
	}

	return p, nil
}

// reader serves tlog the hashes rebuilt in memory.
func (l *Log) reader() tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, x := range indexes {
			if x < 0 || x >= int64(len(l.hashes)) {
				return nil, fmt.Errorf("wlog: stored hash %d of %d", x, len(l.hashes))
			}

			out[i] = l.hashes[x]
		}

		return out, nil
	})
}

// appendFrame writes one frame at the end of the entries file and syncs it.
// On failure it truncates the file back to its old size. A later append must
// not land behind a torn frame.
func appendFrame(path string, frame []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}

	st, err := f.Stat()
	if err == nil {
		if _, err = f.Write(frame); err == nil {
			err = f.Sync()
		}

		if err != nil {
			_ = f.Truncate(st.Size())
		}
	}

	if cerr := f.Close(); err == nil {
		err = cerr
	}

	return err
}

// readRegular reads a whole file, but only a regular one. A pipe or a device
// in its place could hang or flood the reader. With a limit above 0, larger
// files fail too.
func readRegular(path string, limit int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}

	if limit > 0 && st.Size() > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}

	return os.ReadFile(path)
}

// syncDir flushes the directory itself. Without it a new or renamed file
// may not survive a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}

	err = d.Sync()
	// some network mounts can't sync a directory, ignore that
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOTTY) {
		err = nil
	}

	if cerr := d.Close(); err == nil {
		err = cerr
	}

	return err
}
