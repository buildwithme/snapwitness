package state

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func id(n int) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(n))))
}

func testRecord() *Record {
	added := []string{id(1), id(2)}
	if added[0] > added[1] {
		added[0], added[1] = added[1], added[0]
	}

	return &Record{
		Time:  time.Date(2026, 10, 2, 14, 2, 11, 0, time.UTC),
		Tool:  "restic 0.19.1",
		Count: 2,
		Set:   SetHash(added),
		Added: added,
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	r := testRecord()
	r.Removed = []string{id(3)}
	b := r.Marshal()
	want := "snapwitness/v0 state\ntime 2026-10-02T14:02:11Z\ntool restic 0.19.1\ncount 2\nset " +
		fmt.Sprintf("%x", r.Set) + "\n+ " + r.Added[0] + "\n+ " + r.Added[1] + "\n- " + id(3) + "\n"

	if string(b) != want {
		t.Fatalf("got %q, want %q", b, want)
	}

	got, err := Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !reflect.DeepEqual(got, r) {
		t.Fatalf("got %+v, want %+v", got, r)
	}

	empty := &Record{Time: r.Time, Tool: "restic", Set: SetHash(nil)}

	got, err = Parse(empty.Marshal())
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}

	if !reflect.DeepEqual(got, empty) {
		t.Fatalf("got %+v, want %+v", got, empty)
	}
}

func TestParseRejects(t *testing.T) {
	r := testRecord()
	good := string(r.Marshal())
	a0, a1 := r.Added[0], r.Added[1]
	set := fmt.Sprintf("%x", r.Set)
	head := "snapwitness/v0 state\ntime 2026-10-02T14:02:11Z\ntool restic 0.19.1\ncount 2\nset " + set + "\n"

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"wrong header", strings.Replace(good, "v0 state", "v1 state", 1)},
		{"missing final newline", strings.TrimSuffix(good, "\n")},
		{"empty line", strings.Replace(good, "\ntool", "\n\ntool", 1)},
		{"trailing space", strings.Replace(good, "restic 0.19.1\n", "restic 0.19.1 \n", 1)},
		{"crlf", strings.ReplaceAll(good, "\n", "\r\n")},
		{"invalid utf-8", strings.Replace(good, "restic", "restic\xff", 1)},
		{"missing time", strings.Replace(good, "time 2026-10-02T14:02:11Z\n", "", 1)},
		{"unknown key", strings.Replace(good, "tool ", "prog ", 1)},
		{
			"keys swapped",
			strings.Replace(
				good,
				"time 2026-10-02T14:02:11Z\ntool restic 0.19.1\n",
				"tool restic 0.19.1\ntime 2026-10-02T14:02:11Z\n",
				1,
			),
		},
		{"time not utc", strings.Replace(good, "14:02:11Z", "14:02:11+02:00", 1)},
		{"time fraction", strings.Replace(good, "14:02:11Z", "14:02:11.5Z", 1)},
		{"time out of range", strings.Replace(good, "10-02", "10-32", 1)},
		{"empty tool", strings.Replace(good, "tool restic 0.19.1", "tool ", 1)},
		{"tool with tab", strings.Replace(good, "restic 0.19.1", "restic\t0.19.1", 1)},
		{"tool leading space", strings.Replace(good, "tool restic", "tool  restic", 1)},
		{"negative count", strings.Replace(good, "count 2", "count -2", 1)},
		{"count plus sign", strings.Replace(good, "count 2", "count +2", 1)},
		{"count leading zero", strings.Replace(good, "count 2", "count 02", 1)},
		{"count not a number", strings.Replace(good, "count 2", "count two", 1)},
		{"set uppercase hex", strings.Replace(good, set, strings.ToUpper(set), 1)},
		{"set short", strings.Replace(good, set, set[:62], 1)},
		{"set not hex", strings.Replace(good, set, "zz"+set[2:], 1)},
		{"added bad id", head + "+ " + a0[:63] + "\n"},
		{"added uppercase id", head + "+ " + strings.ToUpper(a0) + "\n"},
		{"added unsorted", head + "+ " + a1 + "\n+ " + a0 + "\n"},
		{"added duplicate", head + "+ " + a0 + "\n+ " + a0 + "\n"},
		{"removed unsorted", head + "- " + a1 + "\n- " + a0 + "\n"},
		{"removed duplicate", head + "- " + a0 + "\n- " + a0 + "\n"},
		{"added and removed", head + "+ " + a0 + "\n- " + a0 + "\n"},
		{"removed before added", head + "- " + a0 + "\n+ " + a1 + "\n"},
		{"unknown line after set", head + "* " + a0 + "\n"},
		{"plus without space", head + "+" + a0 + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r, err := Parse([]byte(tt.in)); err == nil {
				t.Fatalf("got %+v, want error", r)
			}
		})
	}
}

func TestSetHash(t *testing.T) {
	if got, want := SetHash(nil), sha256.Sum256(nil); got != want {
		t.Fatalf("empty: got %x, want %x", got, want)
	}

	ids := []string{id(2), id(1)}
	lo, hi := min(ids[0], ids[1]), max(ids[0], ids[1])

	want := sha256.Sum256([]byte(lo + "\n" + hi + "\n"))
	if got := SetHash(ids); got != want {
		t.Fatalf("got %x, want %x", got, want)
	}

	if ids[0] != id(2) {
		t.Fatalf("SetHash changed its input: got %s first, want %s", ids[0], id(2))
	}
}

func TestValidID(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{id(1), true},
		{strings.Repeat("0", 64), true},
		{strings.Repeat("0", 63), false},
		{strings.Repeat("0", 65), false},
		{strings.ToUpper(strings.Repeat("a", 64)), false},
		{strings.Repeat("g", 64), false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidID(tt.in); got != tt.want {
			t.Errorf("ValidID(%q): got %v, want %v", tt.in, got, tt.want)
		}
	}
}
