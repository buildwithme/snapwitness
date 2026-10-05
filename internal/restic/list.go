package restic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/buildwithme/snapwitness/internal/state"
)

// MinFileSize is the smallest size a real restic file can have.
const MinFileSize = 32 // 16-byte IV + 16-byte MAC

// Listing is what the storage shows in snapshots/, read without the password.
type Listing struct {
	IDs      []string // sorted: valid names whose SHA-256 matches the content
	Mismatch []string
	Foreign  []string // not 64 lowercase hex
	TooShort []string
	Files    int
	Bytes    int64
}

// List re-hashes every file in <repoDir>/snapshots/, at most workers at a
// time (GOMAXPROCS when workers <= 0). restic names each file after the
// SHA-256 of its content. A file whose hash doesn't match its name was
// changed in place. Non-regular entries are skipped and the first read
// error cancels the rest.
func List(ctx context.Context, repoDir string, workers int) (*Listing, error) {
	dir := filepath.Join(repoDir, "snapshots")

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("restic: list: %w", err)
	}

	l := &Listing{}

	var names []string // valid IDs to hash, ascending since ReadDir sorts by name

	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}

		l.Files++

		if state.ValidID(e.Name()) {
			names = append(names, e.Name())
			continue
		}

		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("restic: list: %w", err)
		}

		l.Foreign = append(l.Foreign, e.Name())
		l.Bytes += info.Size()
	}

	type result struct {
		match bool
		size  int64
	}

	results := make([]result, len(names))
	g, gctx := newGroup(ctx, workers)

	for i, name := range names {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return err
			}

			sum, n, err := hashFile(filepath.Join(dir, name))
			if err != nil {
				return err
			}

			results[i] = result{match: hex.EncodeToString(sum) == name, size: n}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("restic: list: %w", err)
	}

	// Catch a context canceled before any file was hashed
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("restic: list: %w", err)
	}

	for i, name := range names {
		r := results[i]
		l.Bytes += r.size

		switch {
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

	return l, nil
}

func hashFile(path string) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	//nolint:errcheck // read only, the read error is what counts
	defer f.Close()

	h := sha256.New()

	n, err := io.Copy(h, f)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}

	return h.Sum(nil), n, nil
}

// newGroup returns an errgroup limited to workers goroutines (GOMAXPROCS when
// workers <= 0). It cancels ctx on the first error.
func newGroup(ctx context.Context, workers int) (*errgroup.Group, context.Context) {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	return g, ctx
}
