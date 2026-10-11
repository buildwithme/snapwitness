package wlog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// sigPrefix starts every signature line of a signed note (C2SP signed-note).
const sigPrefix = "\u2014 "

// Checkpoint is a C2SP tlog-checkpoint body.
type Checkpoint struct {
	Origin string
	Size   int64
	Root   tlog.Hash
}

// Body returns the checkpoint text that gets signed: origin, size and the
// base64 root, one per line.
func (c Checkpoint) Body() []byte {
	return fmt.Appendf(nil, "%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:]))
}

// ParseCheckpoint reads a checkpoint body and rejects extra lines, bad base64,
// non-canonical numbers and negative sizes.
func ParseCheckpoint(body []byte) (Checkpoint, error) {
	lines := strings.Split(string(body), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return Checkpoint{}, errors.New(
			"wlog: parse checkpoint: want origin, size and root lines, each ending in a newline",
		)
	}

	origin, size, root := lines[0], lines[1], lines[2]
	if origin == "" {
		return Checkpoint{}, errors.New("wlog: parse checkpoint: empty origin")
	}

	// canonical text only. A checkpoint has exactly one body
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != size {
		return Checkpoint{}, fmt.Errorf("wlog: parse checkpoint: bad size %q", size)
	}

	h, err := base64.StdEncoding.DecodeString(root)
	if err != nil || len(h) != tlog.HashSize || base64.StdEncoding.EncodeToString(h) != root {
		return Checkpoint{}, fmt.Errorf("wlog: parse checkpoint: bad root %q", root)
	}

	c := Checkpoint{Origin: origin, Size: n}
	copy(c.Root[:], h)

	return c, nil
}

// Sign returns the signed note for c with the log signature only.
func Sign(c Checkpoint, s note.Signer) ([]byte, error) {
	if c.Origin != s.Name() {
		return nil, fmt.Errorf("wlog: sign: origin %q is not the key name %q", c.Origin, s.Name())
	}

	if c.Size < 0 {
		return nil, fmt.Errorf("wlog: sign: negative size %d", c.Size)
	}

	signed, err := note.Sign(&note.Note{Text: string(c.Body())}, s)
	if err != nil {
		return nil, fmt.Errorf("wlog: sign: %w", err)
	}

	return signed, nil
}

// Cosig is one verified witness cosignature.
type Cosig struct {
	Name string
	Time time.Time
	Line string // the whole signature line, no trailing newline
}

// Verified is a checkpoint whose log signature checked out.
type Verified struct {
	Checkpoint
	Signed []byte  // log signature only, ready to send to witnesses
	Cosigs []Cosig // from known witnesses, one each
}

// Verify opens a stored checkpoint note. The log signature must be valid and
// the origin must be the log key's name. It returns the valid cosignatures of
// the given witnesses, with timestamps, and ignores unknown keys. Like in
// note.Open, one bad signature from a known key fails the whole note.
func Verify(signed []byte, logKey note.Verifier, witnesses []note.Verifier) (*Verified, error) {
	known := note.VerifierList(append([]note.Verifier{logKey}, witnesses...)...)

	n, err := note.Open(signed, known)
	if err != nil {
		return nil, fmt.Errorf("wlog: verify: %w", err)
	}

	c, err := ParseCheckpoint([]byte(n.Text))
	if err != nil {
		return nil, fmt.Errorf("wlog: verify: %w", err)
	}

	if c.Origin != logKey.Name() {
		return nil, fmt.Errorf("wlog: verify: origin %q is not the log key name %q", c.Origin, logKey.Name())
	}

	v := &Verified{Checkpoint: c}
	// n.Sigs holds only the signatures note.Open verified, at most one per key
	for _, s := range n.Sigs {
		line := sigPrefix + s.Name + " " + s.Base64
		if s.Name == logKey.Name() && s.Hash == logKey.KeyHash() {
			v.Signed = []byte(n.Text + "\n" + line + "\n")
			continue
		}

		t, err := cosigTime(s)
		if err != nil {
			return nil, err
		}

		v.Cosigs = append(v.Cosigs, Cosig{Name: s.Name, Time: t, Line: line})
	}

	if v.Signed == nil {
		return nil, fmt.Errorf("wlog: verify: no signature from the log key %s", logKey.Name())
	}

	return v, nil
}

// Attach returns the log-signed note followed by the cosignature lines, sorted
// by witness name, with only the newest line for each witness.
func Attach(logSigned []byte, cosigs []Cosig) []byte {
	// newest line per witness. An older one could shadow it in note.Open
	newest := make(map[string]Cosig, len(cosigs))
	for _, c := range cosigs {
		if old, ok := newest[c.Name]; !ok || c.Time.After(old.Time) {
			newest[c.Name] = c
		}
	}

	out := slices.Clone(logSigned)
	for _, name := range slices.Sorted(maps.Keys(newest)) {
		out = append(out, newest[name].Line...)
		out = append(out, '\n')
	}

	return out
}

func cosigTime(s note.Signature) (time.Time, error) {
	t, err := fnote.CoSigV1Timestamp(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("wlog: cosignature %s: %w", s.Name, err)
	}

	return t.UTC(), nil
}
