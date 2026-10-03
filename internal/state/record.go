// Package state has the state record, the text entry appended to the log
// after each backup. Replaying those records rebuilds the snapshot set.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Header is the first line of every state record.
const Header = "snapwitness/v0 state"

// TimeFormat is the layout of the time line, always in UTC.
const TimeFormat = "2006-01-02T15:04:05Z"

// Record is one log entry: the snapshot set a client saw after a backup.
type Record struct {
	Time    time.Time // UTC, whole seconds
	Tool    string    // e.g. "restic 0.19.1"
	Count   int
	Set     [32]byte // SetHash of the set after this record
	Added   []string // sorted
	Removed []string // sorted
}

// Marshal returns the canonical text of r. The same record always gives the
// same bytes, and the log hash of an entry depends on its content only.
func (r *Record) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString(Header + "\n")
	b.WriteString("time " + r.Time.UTC().Format(TimeFormat) + "\n")
	b.WriteString("tool " + r.Tool + "\n")
	b.WriteString("count " + strconv.Itoa(r.Count) + "\n")
	b.WriteString("set " + hex.EncodeToString(r.Set[:]) + "\n")

	for _, id := range r.Added {
		b.WriteString("+ " + id + "\n")
	}

	for _, id := range r.Removed {
		b.WriteString("- " + id + "\n")
	}

	return b.Bytes()
}

// Parse reads a record and rejects anything Marshal wouldn't produce. Every
// record has exactly one valid encoding, and Parse(r.Marshal()) round-trips.
func Parse(b []byte) (*Record, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("state: parse: invalid utf-8")
	}

	s := string(b)
	if !strings.HasSuffix(s, "\n") {
		return nil, fmt.Errorf("state: parse: missing final newline")
	}

	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, l := range lines {
		if l == "" {
			return nil, fmt.Errorf("state: parse: line %d: empty line", i+1)
		}

		if strings.HasSuffix(l, " ") {
			return nil, fmt.Errorf("state: parse: line %d: trailing space", i+1)
		}
	}

	if len(lines) < 5 {
		return nil, fmt.Errorf("state: parse: %d lines, want at least 5", len(lines))
	}

	if lines[0] != Header {
		return nil, fmt.Errorf("state: parse: line 1: got header %q, want %q", lines[0], Header)
	}

	var r Record

	v, err := field(lines, 1, "time")
	if err != nil {
		return nil, err
	}

	t, err := time.Parse(TimeFormat, v)
	if err != nil || t.Format(TimeFormat) != v {
		return nil, fmt.Errorf("state: parse: line 2: bad time %q", v)
	}

	r.Time = t

	if r.Tool, err = field(lines, 2, "tool"); err != nil {
		return nil, err
	}

	if !validTool(r.Tool) {
		return nil, fmt.Errorf("state: parse: line 3: bad tool %q", r.Tool)
	}

	if v, err = field(lines, 3, "count"); err != nil {
		return nil, err
	}

	// check the round trip too: "+4", "04" and other spellings of 4 must fail
	if r.Count, err = strconv.Atoi(v); err != nil || r.Count < 0 || strconv.Itoa(r.Count) != v {
		return nil, fmt.Errorf("state: parse: line 4: bad count %q", v)
	}

	if v, err = field(lines, 4, "set"); err != nil {
		return nil, err
	}

	if !ValidID(v) {
		return nil, fmt.Errorf("state: parse: line 5: bad set hash %q", v)
	}

	if _, err := hex.Decode(r.Set[:], []byte(v)); err != nil {
		return nil, fmt.Errorf("state: parse: line 5: %w", err)
	}

	rest := lines[5:]
	for len(rest) > 0 && strings.HasPrefix(rest[0], "+ ") {
		r.Added = append(r.Added, rest[0][2:])
		rest = rest[1:]
	}

	for len(rest) > 0 && strings.HasPrefix(rest[0], "- ") {
		r.Removed = append(r.Removed, rest[0][2:])
		rest = rest[1:]
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("state: parse: line %d: unexpected %q", len(lines)-len(rest)+1, rest[0])
	}

	if err := checkIDs("added", r.Added); err != nil {
		return nil, err
	}

	if err := checkIDs("removed", r.Removed); err != nil {
		return nil, err
	}

	for _, id := range r.Added {
		if _, ok := slices.BinarySearch(r.Removed, id); ok {
			return nil, fmt.Errorf("state: parse: id %s both added and removed", id)
		}
	}

	return &r, nil
}

// field returns the value of lines[i], which must read "<key> <value>".
func field(lines []string, i int, key string) (string, error) {
	v, ok := strings.CutPrefix(lines[i], key+" ")
	if !ok || v == "" {
		return "", fmt.Errorf("state: parse: line %d: got %q, want %s", i+1, lines[i], key)
	}

	return v, nil
}

// validTool reports whether s is printable text that Marshal writes back as is.
func validTool(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}

	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
	}

	return true
}

// checkIDs checks that ids are valid snapshot IDs in strictly ascending order.
func checkIDs(what string, ids []string) error {
	for i, id := range ids {
		if !ValidID(id) {
			return fmt.Errorf("state: parse: %s: bad id %q", what, id)
		}

		if i > 0 && ids[i-1] >= id {
			return fmt.Errorf("state: parse: %s: %s out of order or duplicate", what, id)
		}
	}

	return nil
}

// SetHash returns the SHA-256 of the IDs in ascending order, each followed by
// a newline. It sorts a copy, ids stays as it is. The empty set hashes to the
// SHA-256 of the empty string.
func SetHash(ids []string) [32]byte {
	// sort first, the hash mustn't depend on the order restic or the storage
	// listed them in
	sorted := slices.Clone(ids)
	slices.Sort(sorted)

	return hashSorted(sorted)
}

// hashSorted is SetHash for ids already in ascending order.
func hashSorted(ids []string) [32]byte {
	h := sha256.New()

	var line []byte

	for _, id := range ids {
		line = append(append(line[:0], id...), '\n')
		h.Write(line)
	}

	var sum [32]byte
	h.Sum(sum[:0])

	return sum
}

// ValidID reports whether id is a restic snapshot ID: 64 lowercase hex
// characters.
func ValidID(id string) bool {
	if len(id) != 64 {
		return false
	}

	for i := range len(id) {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}
