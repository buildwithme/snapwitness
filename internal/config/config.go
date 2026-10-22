// Package config reads and writes the snapwitness config file: the trust
// anchor (log key, witnesses, quorum) and where the repository and the log
// live.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// Witness is one witness the log is checked against.
type Witness struct {
	Name string // key name, taken from VKey
	VKey string // note vkey: Ed25519 (0x01) or cosignature/v1 (0x04)
	URL  string // base URL; requests go to URL + "/add-checkpoint"
}

// Config is the trust anchor plus where the repository and the log are.
type Config struct {
	Path      string
	Origin    string // also the name of the log key
	Repo      string // local restic repository, absolute
	LogDir    string
	LogKey    string
	KeyFile   string // signing key, default <config dir>/log.key
	Witnesses []Witness
	Quorum    int           // witnesses that must cosign, 1..len(Witnesses)
	MaxAge    time.Duration // for the newest record and the quorum cosignatures
}

// DefaultMaxAge applies when the config has no maxage line. A daily backup
// gets two hours of slack.
const DefaultMaxAge = 26 * time.Hour

// ErrExists is what Save returns when the file is already there. It wraps
// fs.ErrExist.
var ErrExists = fmt.Errorf("config: %w", fs.ErrExist)

// Load reads and validates the config file at path. Relative paths in it
// resolve against the file's directory.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	c, err := parse(string(b), filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	c.Path = abs
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	return c, nil
}

func parse(text, dir string) (*Config, error) {
	c := &Config{}
	seen := map[string]bool{}

	for i, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val, _ := strings.Cut(line, " ")
		if val == "" {
			return nil, fmt.Errorf("line %d: %s: missing value", i+1, key)
		}

		if key != "witness" && seen[key] {
			return nil, fmt.Errorf("line %d: duplicate %s", i+1, key)
		}

		seen[key] = true

		var err error

		switch key {
		case "origin":
			c.Origin = val
		case "repo":
			c.Repo = resolve(dir, val)
		case "logdir":
			c.LogDir = resolve(dir, val)
		case "logkey":
			c.LogKey = val
		case "keyfile":
			c.KeyFile = resolve(dir, val)
		case "witness":
			vkey, addr, ok := strings.Cut(val, " ")
			if !ok || addr == "" || strings.Contains(addr, " ") {
				return nil, fmt.Errorf("line %d: witness: want <vkey> <url>", i+1)
			}

			name, _, _ := strings.Cut(vkey, "+")
			c.Witnesses = append(c.Witnesses, Witness{Name: name, VKey: vkey, URL: addr})
		case "quorum":
			c.Quorum, err = strconv.Atoi(val)
		case "maxage":
			c.MaxAge, err = time.ParseDuration(val)
		default:
			return nil, fmt.Errorf("line %d: unknown directive %q", i+1, key)
		}

		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", i+1, key, err)
		}
	}

	for _, key := range []string{"origin", "repo", "logdir", "logkey", "witness", "quorum"} {
		if !seen[key] {
			return nil, fmt.Errorf("missing %s", key)
		}
	}

	if !seen["keyfile"] {
		c.KeyFile = filepath.Join(dir, "log.key")
	}

	if !seen["maxage"] {
		c.MaxAge = DefaultMaxAge
	}

	return c, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}

	return filepath.Join(dir, p)
}

// Validate checks the origin, the log key, each witness key and URL, the
// quorum and the max age.
func (c *Config) Validate() error {
	if err := c.validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	return nil
}

// validate is Validate without the package prefix. Load puts the file name
// there instead.
func (c *Config) validate() error {
	if c.Origin == "" || strings.ContainsAny(c.Origin, " +") {
		return fmt.Errorf("origin %q: want no spaces or +", c.Origin)
	}

	for _, p := range []struct{ name, path string }{{"repo", c.Repo}, {"logdir", c.LogDir}} {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s %q: want an absolute path", p.name, p.path)
		}
	}

	if c.KeyFile != "" && !filepath.IsAbs(c.KeyFile) {
		return fmt.Errorf("keyfile %q: want an absolute path", c.KeyFile)
	}

	v, err := note.NewVerifier(c.LogKey)
	if err != nil {
		return fmt.Errorf("logkey: %w", err)
	}

	if v.Name() != c.Origin {
		return fmt.Errorf("logkey name %q, want origin %q", v.Name(), c.Origin)
	}

	if len(c.Witnesses) == 0 {
		return errors.New("no witness")
	}

	names := map[string]bool{}
	keys := map[string]string{} // public key -> witness name

	for _, w := range c.Witnesses {
		wv, err := fnote.NewVerifierForCosignatureV1(w.VKey)
		if err != nil {
			return fmt.Errorf("witness %s: %w", w.Name, err)
		}

		name := wv.Name()
		if names[name] {
			return fmt.Errorf("witness %s: duplicate name", name)
		}

		names[name] = true
		// the same key under two names would count twice toward the
		// quorum, since a cosignature doesn't cover the witness name
		key := publicKey(w.VKey)
		if other, ok := keys[key]; ok {
			return fmt.Errorf("witness %s: same key as witness %s", name, other)
		}

		keys[key] = name

		u, err := url.Parse(w.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("witness %s: url %q: want http or https", name, w.URL)
		}
	}

	if c.Quorum < 1 || c.Quorum > len(c.Witnesses) {
		return fmt.Errorf("quorum %d: want 1..%d", c.Quorum, len(c.Witnesses))
	}

	if c.MaxAge <= 0 {
		return fmt.Errorf("maxage %v: want more than 0", c.MaxAge)
	}

	return nil
}

// publicKey returns the raw key of a vkey, without the algorithm byte. That
// makes a plain Ed25519 vkey equal to its cosignature/v1 form.
func publicKey(vkey string) string {
	// Skip the name and the key hash; the base64 key may itself contain a +
	_, rest, _ := strings.Cut(vkey, "+")
	_, enc, _ := strings.Cut(rest, "+")

	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b) == 0 {
		return vkey
	}

	return string(b[1:])
}

// Marshal returns the config as text, one directive per line, always in the
// same order. Paths inside the config directory are written relative to it.
func (c *Config) Marshal() []byte {
	dir := ""
	if c.Path != "" {
		dir = filepath.Dir(c.Path)
	}

	var b strings.Builder
	b.WriteString("# snapwitness trust anchor, made by snapwitness init. Keep a copy next to your restic password.\n")
	fmt.Fprintf(&b, "origin %s\n", c.Origin)
	fmt.Fprintf(&b, "repo %s\n", relative(dir, c.Repo))
	fmt.Fprintf(&b, "logdir %s\n", relative(dir, c.LogDir))
	fmt.Fprintf(&b, "logkey %s\n", c.LogKey)
	// default key file stays implicit, a moved config dir still finds its key
	if c.KeyFile != "" && (dir == "" || c.KeyFile != filepath.Join(dir, "log.key")) {
		fmt.Fprintf(&b, "keyfile %s\n", relative(dir, c.KeyFile))
	}

	for _, w := range c.Witnesses {
		fmt.Fprintf(&b, "witness %s %s\n", w.VKey, w.URL)
	}

	fmt.Fprintf(&b, "quorum %d\n", c.Quorum)

	if c.MaxAge != 0 {
		fmt.Fprintf(&b, "maxage %s\n", c.MaxAge)
	}

	return []byte(b.String())
}

func relative(dir, p string) string {
	if dir == "" {
		return p
	}

	rel, err := filepath.Rel(dir, p)
	if err != nil || !filepath.IsLocal(rel) {
		return p
	}

	return rel
}

// Save writes c to a new file at path, mode 0644, with paths relative to its
// directory. It doesn't change c. The config is the trust anchor and Save
// never overwrites one: it returns ErrExists.
func Save(path string, c *Config) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("config: save: %w", err)
	}

	cp := *c
	cp.Path = abs
	//nolint:gosec // public keys and paths only; the auditor may read it as another user
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %s", ErrExists, path)
	}

	if err != nil {
		return fmt.Errorf("config: save: %w", err)
	}

	if _, err := f.Write(cp.Marshal()); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: save: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("config: save: %w", err)
	}

	return nil
}

// LogVerifier returns the verifier for the log signature on checkpoints.
func (c *Config) LogVerifier() (note.Verifier, error) {
	v, err := note.NewVerifier(c.LogKey)
	if err != nil {
		return nil, fmt.Errorf("config: logkey: %w", err)
	}

	return v, nil
}

// WitnessVerifiers returns one verifier per witness, in the order of
// Witnesses. A plain Ed25519 vkey is read as cosignature/v1, since witnesses
// send timestamped cosignatures back.
func (c *Config) WitnessVerifiers() ([]note.Verifier, error) {
	vs := make([]note.Verifier, 0, len(c.Witnesses))
	for _, w := range c.Witnesses {
		v, err := fnote.NewVerifierForCosignatureV1(w.VKey)
		if err != nil {
			return nil, fmt.Errorf("config: witness %s: %w", w.Name, err)
		}

		vs = append(vs, v)
	}

	return vs, nil
}
