package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

// InitOptions are the inputs of Init.
type InitOptions struct {
	Name       string // label inside the origin, [a-z0-9-]+
	ConfigPath string
	Repo       string
	LogDir     string
	Witnesses  []config.Witness
	Quorum     int
	MaxAge     time.Duration
}

var validName = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Init creates a log origin and key, the empty log and the config file. It
// won't overwrite any of them. On out it prints the origin, the log vkey, the
// paths and the commands to register the log with each witness.
func Init(opts InitOptions, out io.Writer) (*config.Config, error) {
	if !validName.MatchString(opts.Name) {
		return nil, fmt.Errorf("app: init: name %q: want 1 to 32 of a-z, 0-9 and -", opts.Name)
	}

	path, err := filepath.Abs(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	repo, err := filepath.Abs(opts.Repo)
	if err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	logDir, err := filepath.Abs(opts.LogDir)
	if err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	// random tag: two logs with the same name must never share an origin
	tag := make([]byte, 8)
	_, _ = rand.Read(tag)
	origin := "snapwitness/" + opts.Name + "/" + hex.EncodeToString(tag)

	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	ws := slices.Clone(opts.Witnesses)
	for i := range ws {
		if ws[i].Name == "" {
			ws[i].Name, _, _ = strings.Cut(ws[i].VKey, "+")
		}
	}

	maxAge := opts.MaxAge
	if maxAge == 0 {
		maxAge = config.DefaultMaxAge
	}

	cfg := &config.Config{
		Path:      path,
		Origin:    origin,
		Repo:      repo,
		LogDir:    logDir,
		LogKey:    vkey,
		KeyFile:   filepath.Join(filepath.Dir(path), "log.key"),
		Witnesses: ws,
		Quorum:    opts.Quorum,
		MaxAge:    maxAge,
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	// check all targets before we write anything. A refused init leaves
	// nothing behind
	entries := filepath.Join(logDir, wlog.EntriesFile)
	for _, p := range []string{path, cfg.KeyFile, entries} {
		_, err := os.Lstat(p)
		if err == nil {
			return nil, fmt.Errorf("app: init: %s: %w", p, fs.ErrExist)
		}

		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("app: init: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	if err := writeKey(cfg.KeyFile, skey); err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	if err := wlog.Create(logDir); err != nil {
		_ = os.Remove(cfg.KeyFile)
		return nil, fmt.Errorf("app: init: %w", err)
	}

	if err := config.Save(path, cfg); err != nil {
		_ = os.Remove(cfg.KeyFile)
		_ = os.Remove(entries)

		return nil, fmt.Errorf("app: init: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "created log %s\n", origin)
	fmt.Fprintf(&b, "  log key   %s\n", vkey)
	fmt.Fprintf(&b, "  config    %s\n", path)
	fmt.Fprintf(&b, "  key file  %s  (secret: record needs it, audit does not)\n", cfg.KeyFile)
	fmt.Fprintf(&b, "  repo      %s\n", repo)
	fmt.Fprintf(&b, "  log       %s\n", logDir)
	b.WriteString("\nregister the log with each witness (litewitness), then run snapwitness record:\n")

	for _, w := range ws {
		fmt.Fprintf(&b, "  %s  %s\n", w.Name, w.URL)
		fmt.Fprintf(&b, "    witnessctl add-log -db <db> -origin %s\n", origin)
		fmt.Fprintf(&b, "    witnessctl add-key -db <db> -origin %s -key %s\n", origin, vkey)
	}

	if _, err := io.WriteString(out, b.String()); err != nil {
		return nil, fmt.Errorf("app: init: %w", err)
	}

	return cfg, nil
}

// writeKey writes the private log key with mode 0600, never over an existing
// file.
func writeKey(path, skey string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	_, err = f.WriteString(skey + "\n")
	if err == nil {
		err = f.Sync()
	}

	if cerr := f.Close(); err == nil {
		err = cerr
	}

	if err != nil {
		_ = os.Remove(path)
	}

	return err
}
