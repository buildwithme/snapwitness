package state

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

// Seen is where an ID entered the log.
type Seen struct {
	Index int64
	Time  time.Time
}

// State is the snapshot set rebuilt from the log.
type State struct {
	IDs     map[string]Seen
	Size    int64
	Last    *Record    // nil before the first record
	History [][32]byte // set hash after record i
}

// NewState returns the empty state before the first record.
func NewState() *State {
	return &State{IDs: map[string]Seen{}}
}

// Apply applies record r at position index. Records come in order, added IDs
// must be new and removed ones known, and the result has to match the
// record's count and set hash. On error s stays as it was.
func (s *State) Apply(index int64, r *Record) error {
	_, err := s.apply(index, r, s.Sorted())
	return err
}

// apply is Apply with the current set passed in sorted, and it returns the
// new set sorted too. Replay carries it from record to record, which saves
// sorting the map each time.
func (s *State) apply(index int64, r *Record, cur []string) ([]string, error) {
	if index != s.Size {
		return nil, fmt.Errorf("state: record %d: out of order, want index %d", index, s.Size)
	}

	removed := make(map[string]bool, len(r.Removed))
	for _, id := range r.Removed {
		if _, ok := s.IDs[id]; !ok || removed[id] {
			return nil, fmt.Errorf("state: record %d: removes unknown id %s", index, id)
		}

		removed[id] = true
	}

	added := make(map[string]bool, len(r.Added))
	for _, id := range r.Added {
		if _, ok := s.IDs[id]; ok || added[id] {
			return nil, fmt.Errorf("state: record %d: adds known id %s", index, id)
		}

		added[id] = true
	}

	if n := len(s.IDs) + len(added) - len(removed); n != r.Count {
		return nil, fmt.Errorf("state: record %d: set has %d ids, record says %d", index, n, r.Count)
	}

	add := r.Added
	if !slices.IsSorted(add) {
		add = slices.Sorted(slices.Values(add))
	}

	// Merge the kept IDs with the added ones, both ascending
	next := make([]string, 0, r.Count)

	for _, id := range cur {
		if removed[id] {
			continue
		}

		for len(add) > 0 && add[0] < id {
			next = append(next, add[0])
			add = add[1:]
		}

		next = append(next, id)
	}

	next = append(next, add...)

	set := hashSorted(next)
	if set != r.Set {
		return nil, fmt.Errorf("state: record %d: set hash %x, record says %x", index, set, r.Set)
	}

	for id := range removed {
		delete(s.IDs, id)
	}

	for _, id := range r.Added {
		s.IDs[id] = Seen{Index: index, Time: r.Time}
	}

	s.History = append(s.History, set)
	s.Last = r
	s.Size = index + 1

	return next, nil
}

// Replay parses and applies the entries in order. An error names the index of
// the first bad entry.
func Replay(entries [][]byte) (*State, error) {
	s := NewState()

	var cur []string

	for i, e := range entries {
		r, err := Parse(e)
		if err != nil {
			return nil, fmt.Errorf("state: entry %d: %w", i, err)
		}

		if cur, err = s.apply(int64(i), r, cur); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Sorted returns the IDs in the current set in ascending order.
func (s *State) Sorted() []string {
	return slices.Sorted(maps.Keys(s.IDs))
}

// MatchIndex returns the last index whose set hash equals set, or -1. It tells
// which older state a rolled-back storage matches.
func (s *State) MatchIndex(set [32]byte) int64 {
	for i, v := range slices.Backward(s.History) {
		if v == set {
			return int64(i)
		}
	}

	return -1
}

// Diff compares the recorded set have with the IDs seen now. added is what's
// only in now, removed what's only in have, both sorted.
func Diff(have map[string]Seen, now []string) (added, removed []string) {
	inNow := make(map[string]bool, len(now))
	for _, id := range now {
		inNow[id] = true
		if _, ok := have[id]; !ok {
			added = append(added, id)
		}
	}

	for id := range have {
		if !inNow[id] {
			removed = append(removed, id)
		}
	}

	slices.Sort(added)
	added = slices.Compact(added)

	slices.Sort(removed)

	return added, removed
}
