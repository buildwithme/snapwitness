// Package wlog keeps the append-only Merkle log of state records next to the
// backup repository, and reads, signs and verifies its checkpoints. The log
// lives on the same untrusted storage as the backup and can't stop a
// rewrite. It's the witnessed checkpoints that make a rewrite or a rollback
// visible.
package wlog

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	// maxCheckpointSize bounds the checkpoint read back from the storage.
	maxCheckpointSize = 1 << 20
	// maxEntriesSize bounds the entries file, since Open keeps the whole log in
	// memory. With records of a few KiB, 256 MiB is years of daily backups.
	// TODO: stream the entries once logs get anywhere near that
	maxEntriesSize = 256 << 20
)

var (
	// ErrNoCheckpoint is returned by ReadCheckpoint when no checkpoint has been
	// written yet.
	ErrNoCheckpoint = errors.New("wlog: no checkpoint")
	// ErrNoLog is returned by Open when the entries file is missing.
	ErrNoLog = errors.New("wlog: no log")
)

// Log is an append-only Merkle log kept in one directory next to the backup
// repository.
type Log struct {
	dir     string
	dirInfo fs.FileInfo // what Open read; every write must go to this same dir
	file    fs.FileInfo
	stored  int64 // entries file size: read by Open plus written by Append
	entries [][]byte
	hashes  []tlog.Hash // from tlog.StoredHashes, in storage order
}

// Create makes the log directory and an empty entries file. It fails if the
// entries file is already there, or if dir is a symlink. It never truncates
// a log.
func Create(dir string) error {
	//nolint:gosec // the auditor may read the log as another user
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	info, err := lstatDir(dir)
	if err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	root, err := openRoot(dir, info)
	if err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	defer func() { _ = root.Close() }()

	f, err := root.OpenFile(EntriesFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	if err := syncDir(root); err != nil {
		return fmt.Errorf("wlog: create: %w", err)
	}

	return nil
}

// Open reads every entry in dir and recomputes the RFC 6962 hashes in
// memory. We never take a hash from the storage. ErrNoLog means the
// directory or the entries file is missing.
func Open(dir string) (*Log, error) {
	dirInfo, err := lstatDir(dir)

	var (
		data []byte
		file fs.FileInfo
	)

	if err == nil {
		data, file, err = readFile(filepath.Join(dir, EntriesFile), maxEntriesSize)
	}

	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoLog
	}

	if err != nil {
		return nil, fmt.Errorf("wlog: open: %w", err)
	}

	l := &Log{dir: dir, dirInfo: dirInfo, file: file, stored: int64(len(data))}
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

	if err := l.appendFrame(frame); err != nil {
		return fmt.Errorf("wlog: append: %w", err)
	}

	l.stored += int64(len(frame))
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

// ReadCheckpoint returns the stored signed checkpoint note, or
// ErrNoCheckpoint. A checkpoint over 1 MiB or one that isn't a regular file
// is an error.
func (l *Log) ReadCheckpoint() ([]byte, error) {
	b, _, err := readFile(filepath.Join(l.dir, CheckpointFile), maxCheckpointSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoCheckpoint
	}

	if err != nil {
		return nil, fmt.Errorf("wlog: read checkpoint: %w", err)
	}

	return b, nil
}

// WriteCheckpoint replaces the stored checkpoint with signed, by temp file
// and rename. After a crash there's either the old one or the new one. It
// only writes into the directory Open read: a symlink planted by the storage
// can't send the write somewhere else.
func (l *Log) WriteCheckpoint(signed []byte) error {
	root, err := openRoot(l.dir, l.dirInfo)
	if err != nil {
		return fmt.Errorf("wlog: write checkpoint: %w", err)
	}

	defer func() { _ = root.Close() }()
	// fresh random name, we don't want to reuse anything the storage put
	// there in advance
	tmp := CheckpointFile + ".tmp-" + rand.Text()

	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("wlog: write checkpoint: %w", err)
	}

	err = f.Chmod(0o644)
	if err == nil {
		_, err = f.Write(signed)
	}

	if err == nil {
		err = f.Sync()
	}

	if cerr := f.Close(); err == nil {
		err = cerr
	}

	if err == nil {
		err = root.Rename(tmp, CheckpointFile)
	}

	if err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("wlog: write checkpoint: %w", err)
	}

	if err := syncDir(root); err != nil {
		return fmt.Errorf("wlog: write checkpoint: %w", err)
	}

	return nil
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

// appendFrame appends one frame to the entries file and syncs it, but only
// while that file is still the one Open read. A frame written to a file the
// storage swapped in would get cosigned and never reach the log. A failed
// write is truncated away. A later append must not land behind a torn frame.
func (l *Log) appendFrame(frame []byte) error {
	root, err := openRoot(l.dir, l.dirInfo)
	if err != nil {
		return err
	}

	defer func() { _ = root.Close() }()
	// O_NONBLOCK: a fifo must not block the open, the Stat below rejects it
	f, err := root.OpenFile(EntriesFile, os.O_WRONLY|os.O_APPEND|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}

	st, err := f.Stat()
	if err == nil && (!st.Mode().IsRegular() || !os.SameFile(l.file, st) || st.Size() != l.stored) {
		err = errors.New("entries changed on the storage since it was read")
	}

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

// lstatDir fails unless dir is a directory itself. A symlink to one isn't
// enough.
func lstatDir(dir string) (fs.FileInfo, error) {
	// Drop a trailing slash, which would make Lstat follow a symlink
	st, err := os.Lstat(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}

	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	return st, nil
}

// openRoot opens dir as an os.Root and checks it's still the directory
// described by want. Files reached through the root can't escape it by a
// symlink. The check also catches a dir the storage swapped for a symlink
// since it was read.
func openRoot(dir string, want fs.FileInfo) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}

	st, err := root.Stat(".")
	if err == nil && !os.SameFile(want, st) {
		err = fmt.Errorf("log directory %s changed on the storage since it was read", dir)
	}

	if err != nil {
		_ = root.Close()
		return nil, err
	}

	return root, nil
}

// readFile reads a regular file of at most limit bytes through one handle,
// and returns it with the handle's info. It never follows a symlink or blocks
// on a fifo. All checks run on the handle: the storage can't swap the file
// between check and read.
func readFile(path string, limit int64) ([]byte, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}

	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}

	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}

	if st.Size() > limit {
		return nil, nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}

	// Read one byte past the limit to catch a file that grew after the Stat
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}

	if int64(len(b)) > limit {
		return nil, nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}

	return b, st, nil
}

// syncDir flushes the root directory itself. Without it a new or renamed
// file may not survive a crash.
func syncDir(root *os.Root) error {
	d, err := root.Open(".")
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
