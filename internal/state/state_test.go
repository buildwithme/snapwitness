package state

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
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

// rec builds the record that changes the set have into have+added-removed.
func rec(have map[string]bool, added, removed []string) *Record {
	next := []string{}
	for k := range have {
		next = append(next, k)
	}

	next = append(next, added...)

	var kept []string

	for _, k := range next {
		drop := false
		for _, r := range removed {
			drop = drop || r == k
		}

		if !drop {
			kept = append(kept, k)
		}
	}

	return &Record{
		Time: time.Date(2026, 10, 2, 0, 0, len(have), 0, time.UTC), Tool: "restic",
		Count: len(kept), Set: SetHash(kept), Added: added, Removed: removed,
	}
}

func TestReplay(t *testing.T) {
	a, b, c := id(1), id(2), id(3)
	r0 := rec(map[string]bool{}, []string{a}, nil)
	r1 := rec(map[string]bool{a: true}, []string{b}, nil)
	r2 := rec(map[string]bool{a: true, b: true}, []string{c}, []string{a})
	r3 := rec(map[string]bool{b: true, c: true}, nil, nil)
	r3.Time = r3.Time.Add(time.Hour)

	s, err := Replay([][]byte{r0.Marshal(), r1.Marshal(), r2.Marshal(), r3.Marshal()})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if s.Size != 4 {
		t.Fatalf("size: got %d, want 4", s.Size)
	}

	want := []string{b, c}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}

	if got := s.Sorted(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sorted: got %v, want %v", got, want)
	}

	if got := s.IDs[c]; got.Index != 2 || !got.Time.Equal(r2.Time) {
		t.Fatalf("seen c: got %+v, want index 2 time %v", got, r2.Time)
	}

	if !reflect.DeepEqual(s.Last, r3) {
		t.Fatalf("last: got %+v, want %+v", s.Last, r3)
	}

	if len(s.History) != 4 || s.History[0] != r0.Set || s.History[3] != r3.Set {
		t.Fatalf("history: got %x", s.History)
	}

	if got := s.MatchIndex(r3.Set); got != 3 {
		t.Fatalf("match r3: got %d, want 3 (last of 2 and 3)", got)
	}

	if got := s.MatchIndex(r0.Set); got != 0 {
		t.Fatalf("match r0: got %d, want 0", got)
	}

	if got := s.MatchIndex(SetHash([]string{c})); got != -1 {
		t.Fatalf("match unknown: got %d, want -1", got)
	}

	empty, err := Replay(nil)
	if err != nil || empty.Size != 0 || empty.Last != nil || len(empty.IDs) != 0 {
		t.Fatalf("empty replay: got %+v, %v", empty, err)
	}
}

func TestReplayErrors(t *testing.T) {
	a, b := id(1), id(2)
	r0 := rec(map[string]bool{}, []string{a}, nil)
	one := map[string]bool{a: true}

	badCount := rec(one, []string{b}, nil)
	badCount.Count = 3
	badSet := rec(one, []string{b}, nil)
	badSet.Set = SetHash([]string{b})

	tests := []struct {
		name    string
		second  []byte
		wantErr string
	}{
		{"parse error", []byte("garbage\n"), "entry 1"},
		{"add known id", rec(one, []string{a}, nil).Marshal(), "record 1: adds known id"},
		{"remove unknown id", rec(one, nil, []string{b}).Marshal(), "record 1: removes unknown id"},
		{"count mismatch", badCount.Marshal(), "record 1: set has 2 ids, record says 3"},
		{"set mismatch", badSet.Marshal(), "record 1: set hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Replay([][]byte{r0.Marshal(), tt.second, r0.Marshal()})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestApply(t *testing.T) {
	a, b := id(1), id(2)

	s := NewState()
	if err := s.Apply(1, rec(map[string]bool{}, []string{a}, nil)); err == nil {
		t.Fatal("index 1 on empty state: got nil, want error")
	}

	if err := s.Apply(0, rec(map[string]bool{}, []string{a}, nil)); err != nil {
		t.Fatalf("apply 0: %v", err)
	}

	// A failed apply must leave the state as it was
	bad := rec(map[string]bool{a: true}, []string{b}, []string{a})
	bad.Count = 5

	if err := s.Apply(1, bad); err == nil {
		t.Fatal("bad count: got nil, want error")
	}

	if s.Size != 1 || len(s.IDs) != 1 || len(s.History) != 1 {
		t.Fatalf("state changed after failed apply: %+v", s)
	}

	if _, ok := s.IDs[a]; !ok {
		t.Fatal("state lost id a after failed apply")
	}
}

func TestDiff(t *testing.T) {
	a, b, c, d := id(1), id(2), id(3), id(4)
	have := map[string]Seen{a: {}, b: {}, c: {}}

	added, removed := Diff(have, []string{d, b, a})
	if !reflect.DeepEqual(added, []string{d}) {
		t.Fatalf("added: got %v, want [%s]", added, d)
	}

	if !reflect.DeepEqual(removed, []string{c}) {
		t.Fatalf("removed: got %v, want [%s]", removed, c)
	}

	added, removed = Diff(have, []string{c, b, a})
	if added != nil || removed != nil {
		t.Fatalf("same set: got %v %v, want nil, nil", added, removed)
	}

	added, removed = Diff(nil, []string{c, a, b})
	want := []string{a, b, c}
	slices.Sort(want)

	if !reflect.DeepEqual(added, want) || removed != nil {
		t.Fatalf("from empty: got %v %v, want %v nil", added, removed, want)
	}
}

func BenchmarkReplay(b *testing.B) {
	const n = 5000

	entries := make([][]byte, n)

	var ids []string

	for i := range n {
		ids = append(ids, id(i))
		r := &Record{
			Time:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour),
			Tool:  "restic 0.19.1",
			Count: len(ids),
			Set:   SetHash(ids),
			Added: []string{id(i)},
		}
		entries[i] = r.Marshal()
	}

	b.ResetTimer()

	for b.Loop() {
		if _, err := Replay(entries); err != nil {
			b.Fatal(err)
		}
	}
}
