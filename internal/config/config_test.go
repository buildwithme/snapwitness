package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

const origin = "snapwitness/demo/7c1e09d4b2a6f310"

func vkey(t *testing.T, name string) string {
	t.Helper()

	_, v, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}

	return v
}

func cosigKey(t *testing.T, name string) string {
	t.Helper()

	v, err := fnote.VKeyToCosignatureV1(vkey(t, name))
	if err != nil {
		t.Fatal(err)
	}

	return v
}

// testConfig returns a valid config whose paths live under dir.
func testConfig(t *testing.T, dir string) *Config {
	t.Helper()

	return &Config{
		Path:    filepath.Join(dir, "snapwitness.conf"),
		Origin:  origin,
		Repo:    filepath.Join(dir, "storage", "repo"),
		LogDir:  filepath.Join(dir, "storage", "log"),
		LogKey:  vkey(t, origin),
		KeyFile: filepath.Join(dir, "log.key"),
		Witnesses: []Witness{
			{Name: "witness-1.lw.example", VKey: cosigKey(t, "witness-1.lw.example"), URL: "http://127.0.0.1:7381"},
			{Name: "witness-2.lw.example", VKey: vkey(t, "witness-2.lw.example"), URL: "https://w2.example/base"},
		},
		Quorum: 2,
		MaxAge: DefaultMaxAge,
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := testConfig(t, dir)

	path := filepath.Join(dir, "snapwitness.conf")
	if err := Save(path, c); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode: got %v, want 0644", info.Mode().Perm())
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !reflect.DeepEqual(got, c) {
		t.Fatalf("got %+v, want %+v", got, c)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	text := string(b)
	for _, want := range []string{"\nrepo storage/repo\n", "\nlogdir storage/log\n", "\nquorum 2\n", "\nmaxage 26h0m0s\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("file: got %q, want it to contain %q", text, want)
		}
	}

	if strings.Contains(text, "keyfile") {
		t.Errorf("file: got %q, want no keyfile line for the default key file", text)
	}

	if !reflect.DeepEqual(got.Marshal(), b) {
		t.Fatalf("marshal after load: got %q, want %q", got.Marshal(), b)
	}
}

func TestSaveRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "snapwitness.conf")
	if err := os.WriteFile(path, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Save(path, testConfig(t, dir))
	if !errors.Is(err, ErrExists) || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want ErrExists and fs.ErrExist", err)
	}

	if got, want := err.Error(), "config: file already exists: "+path; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	b, _ := os.ReadFile(path)
	if string(b) != "keep me\n" {
		t.Fatalf("file changed: got %q", b)
	}
}

func TestMarshalPaths(t *testing.T) {
	dir := t.TempDir()
	c := testConfig(t, dir)
	other := t.TempDir()
	c.Repo = filepath.Join(other, "repo")
	c.KeyFile = filepath.Join(dir, "keys", "log.key")

	text := string(c.Marshal())
	if !strings.Contains(text, "\nrepo "+c.Repo+"\n") {
		t.Errorf("got %q, want an absolute repo path outside the config dir", text)
	}

	if !strings.Contains(text, "\nkeyfile keys/log.key\n") {
		t.Errorf("got %q, want a relative keyfile line", text)
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(t.TempDir(), "elsewhere")
	text := "# comment\n\norigin " + origin + "\nrepo ../repo\nlogdir " + abs + "\nlogkey " + vkey(t, origin) +
		"\nkeyfile k/log.key\nwitness " + vkey(t, "w1") + " http://127.0.0.1:1\nquorum 1\n"

	path := filepath.Join(dir, "sub", "c.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	checks := []struct{ name, got, want string }{
		{"path", c.Path, path},
		{"repo", c.Repo, filepath.Join(dir, "repo")},
		{"logdir", c.LogDir, abs},
		{"keyfile", c.KeyFile, filepath.Join(dir, "sub", "k", "log.key")},
		{"witness name", c.Witnesses[0].Name, "w1"},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("%s: got %q, want %q", ch.name, ch.got, ch.want)
		}
	}

	if c.MaxAge != DefaultMaxAge {
		t.Errorf("maxage: got %v, want %v", c.MaxAge, DefaultMaxAge)
	}
}

func TestLoadRejects(t *testing.T) {
	lk, wk := vkey(t, origin), vkey(t, "w1")
	good := "origin " + origin + "\nrepo r\nlogdir l\nlogkey " + lk + "\nwitness " + wk + " http://127.0.0.1:1\nquorum 1\n"
	tests := []struct {
		name    string
		text    string
		wantErr string
	}{
		{"unknown directive", good + "color blue\n", "unknown directive"},
		{"duplicate origin", good + "origin " + origin + "\n", "duplicate origin"},
		{"duplicate quorum", good + "quorum 1\n", "duplicate quorum"},
		{"missing origin", strings.Replace(good, "origin "+origin+"\n", "", 1), "missing origin"},
		{"missing repo", strings.Replace(good, "repo r\n", "", 1), "missing repo"},
		{"missing logdir", strings.Replace(good, "logdir l\n", "", 1), "missing logdir"},
		{"missing logkey", strings.Replace(good, "logkey "+lk+"\n", "", 1), "missing logkey"},
		{"missing witness", strings.Replace(good, "witness "+wk+" http://127.0.0.1:1\n", "", 1), "missing witness"},
		{"missing quorum", strings.Replace(good, "quorum 1\n", "", 1), "missing quorum"},
		{"missing value", good + "maxage\n", "missing value"},
		{"witness without url", good + "witness " + vkey(t, "w2") + "\n", "want <vkey> <url>"},
		{"quorum not a number", strings.Replace(good, "quorum 1", "quorum one", 1), "quorum"},
		{"bad maxage", good + "maxage 1 day\n", "maxage"},
		{"invalid after parse", strings.Replace(good, "quorum 1", "quorum 2", 1), "quorum 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.conf")
			if err := os.WriteFile(path, []byte(tt.text), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}

			assertOnePrefix(t, err)
		})
	}

	if _, err := Load(filepath.Join(t.TempDir(), "none.conf")); err == nil {
		t.Fatal("missing file: got nil, want error")
	}
}

func assertOnePrefix(t *testing.T, err error) {
	t.Helper()

	if msg := err.Error(); !strings.HasPrefix(msg, "config: ") || strings.Count(msg, "config: ") != 1 {
		t.Errorf("got %q, want one config: prefix", msg)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	if err := testConfig(t, dir).Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}

	// one Ed25519 key under two names, plain and as cosignature/v1
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sameKey := func(name string) string {
		v, err := note.NewEd25519VerifierKey(name, pub)
		if err != nil {
			t.Fatal(err)
		}

		return v
	}

	cosigSameKey, err := fnote.VKeyToCosignatureV1(sameKey("witness-2.lw.example"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		edit    func(c *Config)
		wantErr string
	}{
		{"empty origin", func(c *Config) { c.Origin = "" }, "origin"},
		{"origin with space", func(c *Config) { c.Origin = "a b" }, "origin"},
		{"origin with plus", func(c *Config) { c.Origin = "a+b" }, "origin"},
		{"relative repo", func(c *Config) { c.Repo = "repo" }, "repo"},
		{"relative logdir", func(c *Config) { c.LogDir = "log" }, "logdir"},
		{"relative keyfile", func(c *Config) { c.KeyFile = "log.key" }, "keyfile"},
		{"bad logkey", func(c *Config) { c.LogKey = "nonsense" }, "logkey"},
		{"logkey name differs", func(c *Config) { c.LogKey = vkey(t, "other") }, "want origin"},
		{"no witness", func(c *Config) { c.Witnesses = nil; c.Quorum = 0 }, "no witness"},
		{"bad witness key", func(c *Config) { c.Witnesses[0].VKey = "w+00000000+AAAA" }, "witness"},
		{
			"duplicate witness name",
			func(c *Config) { c.Witnesses[1].VKey = vkey(t, "witness-1.lw.example") },
			"duplicate",
		},
		{"same key under two names", func(c *Config) {
			c.Witnesses[0].VKey = sameKey("witness-1.lw.example")
			c.Witnesses[1].VKey = sameKey("witness-2.lw.example")
		}, "witness witness-2.lw.example: same key as witness witness-1.lw.example"},
		{"same key in both vkey forms", func(c *Config) {
			c.Witnesses[0].VKey = sameKey("witness-1.lw.example")
			c.Witnesses[1].VKey = cosigSameKey
		}, "same key as witness"},
		{"witness url scheme", func(c *Config) { c.Witnesses[0].URL = "ftp://127.0.0.1" }, "url"},
		{"witness url without host", func(c *Config) { c.Witnesses[0].URL = "http://" }, "url"},
		{"quorum zero", func(c *Config) { c.Quorum = 0 }, "quorum"},
		{"quorum above witnesses", func(c *Config) { c.Quorum = 3 }, "quorum"},
		{"maxage zero", func(c *Config) { c.MaxAge = 0 }, "maxage"},
		{"maxage negative", func(c *Config) { c.MaxAge = -time.Hour }, "maxage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testConfig(t, dir)
			tt.edit(c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}

			assertOnePrefix(t, err)
		})
	}
}

func TestVerifiers(t *testing.T) {
	c := testConfig(t, t.TempDir())

	lv, err := c.LogVerifier()
	if err != nil {
		t.Fatalf("log verifier: %v", err)
	}

	if lv.Name() != origin {
		t.Fatalf("log verifier name: got %q, want %q", lv.Name(), origin)
	}

	vs, err := c.WitnessVerifiers()
	if err != nil {
		t.Fatalf("witness verifiers: %v", err)
	}

	if len(vs) != 2 {
		t.Fatalf("got %d verifiers, want 2", len(vs))
	}

	for i, v := range vs {
		if v.Name() != c.Witnesses[i].Name {
			t.Errorf("verifier %d: got name %q, want %q", i, v.Name(), c.Witnesses[i].Name)
		}
	}

	// A plain Ed25519 vkey and its cosignature/v1 form verify the same
	// cosignatures
	plain := vkey(t, "w")

	cosig, err := fnote.VKeyToCosignatureV1(plain)
	if err != nil {
		t.Fatal(err)
	}

	a, err := (&Config{Witnesses: []Witness{{Name: "w", VKey: plain}}}).WitnessVerifiers()
	if err != nil {
		t.Fatal(err)
	}

	b, err := (&Config{Witnesses: []Witness{{Name: "w", VKey: cosig}}}).WitnessVerifiers()
	if err != nil {
		t.Fatal(err)
	}

	if a[0].KeyHash() != b[0].KeyHash() {
		t.Fatalf("key hash: got %08x, want %08x", a[0].KeyHash(), b[0].KeyHash())
	}
}
