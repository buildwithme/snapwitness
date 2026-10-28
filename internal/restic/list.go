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
	"runtime"
	"slices"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/buildwithme/snapwitness/internal/state"
)

// MinFileSize is the smallest size a real restic file can have.
const MinFileSize = 32 // 16-byte IV + 16-byte MAC

// Listing is what the storage shows in snapshots/, read without the password.
type Listing struct {
	IDs      []string // sorted: valid names whose SHA-256 matches the content
	Mismatch []string
	Foreign  []string // not 64 lowercase hex, or not a regular file
	TooShort []string
	Files    int
	Bytes    int64
}

// maxFileSize is the largest file List hashes. Real snapshot files are a few
// KiB; anything bigger counts as a mismatch and we don't even read it.
const maxFileSize = 16 << 20

// List re-hashes every file in <repoDir>/snapshots/, at most workers at a
// time (GOMAXPROCS when workers <= 0). restic names each file after the
// SHA-256 of its content. A file whose hash doesn't match its name was
// changed in place. Without a snapshots dir the error wraps fs.ErrNotExist.
func List(ctx context.Context, repoDir string, workers int) (*Listing, error) {
	dir := filepath.Join(repoDir, "snapshots")

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("restic: list: %w", err)
	}

	l := &Listing{}

	var names []string // valid IDs to hash, ascending since ReadDir sorts by name

	for _, e := range entries {
		switch {
		case !e.Type().IsRegular():
			l.Foreign = append(l.Foreign, fmt.Sprintf("%s (%s)", e.Name(), typeName(e.Type())))
		case state.ValidID(e.Name()):
			names = append(names, e.Name())
		default:
			info, err := e.Info()
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}

			if err == nil {
				l.Bytes += info.Size()
			}

			l.Foreign = append(l.Foreign, e.Name())
		}
	}

	results := make([]fileCheck, len(names))

	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	for i, name := range names {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}

			var err error

			results[i], err = checkFile(gctx, dir, name)

			return err
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("restic: list: %w", err)
	}

	for i, name := range names {
		r := results[i]
		l.Bytes += r.size

		switch {
		case r.gone:
		case r.foreign != "":
			l.Foreign = append(l.Foreign, fmt.Sprintf("%s (%s)", name, r.foreign))
		case !r.match:
			l.Mismatch = append(l.Mismatch, name)
		case r.size < MinFileSize:
			// keep these out of IDs. restic 0.19.1 panics on a 5-byte file
			// named by its own hash. That's never a real snapshot
			l.TooShort = append(l.TooShort, name)
		default:
			l.IDs = append(l.IDs, name)
		}
	}

	slices.Sort(l.Foreign)
	l.Files = len(l.IDs) + len(l.Mismatch) + len(l.Foreign) + len(l.TooShort)

	return l, nil
}

// fileCheck is what checkFile found for one valid name.
type fileCheck struct {
	gone    bool   // vanished since ReadDir
	foreign string // type name if it's no longer a regular file
	match   bool
	size    int64
}

// checkFile opens dir/name once, without following a symlink or blocking on
// a fifo. It hashes it only if the handle is a regular file of at most
// maxFileSize bytes. Only ctx errors come back: a file the storage made
// unreadable is just a mismatch, and the audit goes on.
func checkFile(ctx context.Context, dir, name string) (fileCheck, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return fileCheck{gone: true}, nil
	}

	if err != nil {
		return fileCheck{}, nil
	}

	//nolint:errcheck // read only, the read error is what counts
	defer f.Close()

	info, err := f.Stat()
	switch {
	case err != nil:
		return fileCheck{}, nil
	case !info.Mode().IsRegular():
		return fileCheck{foreign: typeName(info.Mode())}, nil
	case info.Size() > maxFileSize:
		return fileCheck{size: info.Size()}, nil
	}

	sum, n, err := hash(ctx, io.LimitReader(f, maxFileSize+1))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fileCheck{}, ctxErr
	}

	if err != nil || n > maxFileSize {
		return fileCheck{size: max(n, info.Size())}, nil
	}

	return fileCheck{match: hex.EncodeToString(sum) == name, size: n}, nil
}

// hash returns the SHA-256 of r and the number of bytes read. It stops with
// ctx.Err() once ctx is done. A deadline then also limits the time spent on
// one big file.
func hash(ctx context.Context, r io.Reader) ([]byte, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, ctxReader{ctx, r})

	return h.Sum(nil), n, err
}

// ctxReader reads at most 1 MiB per call and fails once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}

	return c.r.Read(p[:min(len(p), 1<<20)])
}

func typeName(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	default:
		return "irregular"
	}
}
