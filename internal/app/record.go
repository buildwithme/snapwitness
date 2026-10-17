package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/sumdb/note"

	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/restic"
	"github.com/buildwithme/snapwitness/internal/state"
	"github.com/buildwithme/snapwitness/internal/witness"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

// SnapshotSource gives the keyed view of the repository (restic.CLI in
// production).
type SnapshotSource interface {
	Snapshots(ctx context.Context) ([]restic.Snapshot, error)
}

// RecordOptions are the inputs of Record.
type RecordOptions struct {
	AcceptRemoved bool
	Now           func() time.Time // time.Now when nil
}

// removedHint tells the user how to record a removal made on purpose.
//
// TODO: signed removals. -accept-removed takes everything for now.
const removedHint = "use -accept-removed only if you removed them on purpose; there is no admin key yet (see LIMITATIONS.md)"

// Record runs after each backup. It appends a state record and gets the new
// checkpoint cosigned by a quorum. It stops first if a witness has seen a
// larger log, or if snapshots were removed without AcceptRemoved. A record
// is appended even when nothing changed: each one is a witnessed observation.
func Record(
	ctx context.Context,
	cfg *config.Config,
	src SnapshotSource,
	wc *witness.Client,
	opts RecordOptions,
) *Report {
	start := time.Now()

	r := &Report{Command: "record", Config: cfg.Path, Origin: cfg.Origin}
	if err := record(ctx, cfg, src, wc, opts, r); err != nil {
		r.Err = err.Error()
	}

	r.Took = time.Since(start)

	return r
}

func record(
	ctx context.Context,
	cfg *config.Config,
	src SnapshotSource,
	wc *witness.Client,
	opts RecordOptions,
	r *Report,
) error {
	logKey, witnessKeys, ws, err := trust(cfg)
	if err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	signer, err := loadSigner(cfg, logKey)
	if err != nil {
		return err
	}

	l, err := wlog.Open(cfg.LogDir)
	if errors.Is(err, wlog.ErrNoLog) {
		r.Add(Alarm, "deleted", "the log is gone from the storage")
		return nil
	}

	if err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	var cp *wlog.Verified // nil before the first record

	var n int64 // the size it covers

	defer func() {
		r.LogSize = l.Size()
		r.line("log", "size %d, checkpoint %d", l.Size(), n)
	}()

	stored, err := l.ReadCheckpoint()
	switch {
	case errors.Is(err, wlog.ErrNoCheckpoint):
		// no checkpoint is only fine for an empty log. Deleting it can't be
		// allowed to reset what the witnesses have seen
		if l.Size() > 0 {
			r.Add(Alarm, "tampered", fmt.Sprintf("the log has %d entries but no checkpoint", l.Size()))
			return nil
		}
	case err != nil:
		return fmt.Errorf("app: record: %w", err)
	default:
		if cp = checkStored(r, l, stored, logKey, witnessKeys); cp == nil {
			return nil
		}

		n = cp.Size
	}

	// Probe the witnesses before we append. A new record must never build on
	// a rolled-back copy.
	if n > 0 {
		outs := wc.Collect(ctx, ws, witness.Request{Signed: cp.Signed, Size: n, OldSize: n, Proof: proofTo(l, n)}, 0)
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("app: record: %w", err)
		}

		r.Witnesses = statuses(outs, n)
		debugOutcomes("record probe", outs)
		vd := judge(r, outs, n, l.Size(), false)
		if vd.rollback || vd.fork {
			return nil
		}

		if len(vd.pending) > 0 {
			r.Add(Info, "pending", "a record run did not finish; this run completes it", vd.pending...)
		}
	}

	// replay everything, the unwitnessed tail too. The new record follows the
	// last entry
	st, err := state.Replay(l.Entries(l.Size()))
	if err != nil {
		r.Add(Alarm, "tampered", "the log records do not replay", err.Error())
		return nil
	}

	witnessed := st
	if n < l.Size() {
		if witnessed, err = state.Replay(l.Entries(n)); err != nil {
			r.Add(Alarm, "tampered", "the log records do not replay", err.Error())
			return nil
		}
	}

	snaps, err := src.Snapshots(ctx)
	if err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	ids := make([]string, 0, len(snaps))
	for _, s := range snaps {
		ids = append(ids, s.ID)
	}

	slices.Sort(ids)
	ids = slices.Compact(ids)
	added, removed := state.Diff(st.IDs, ids)
	r.Snapshots = len(ids)
	r.line("snapshots", "%d (+%d -%d)", len(ids), len(added), len(removed))

	// check removals against the witnessed state as well. An entry slipped
	// into the unwitnessed tail mustn't hide a deletion
	if gone := lost(ids, witnessed, st); len(gone) > 0 && !opts.AcceptRemoved {
		r.Add(
			Alarm,
			"deleted",
			plural(len(gone), "recorded snapshot")+" gone from the repository",
			append(gone, removedHint)...)

		return nil
	}

	tool := toolName(snaps)
	r.line("restic", "%s", tool)
	rec := &state.Record{
		Time:    clock(opts.Now)().UTC().Truncate(time.Second),
		Tool:    tool,
		Count:   len(ids),
		Set:     state.SetHash(ids),
		Added:   added,
		Removed: removed,
	}
	entry := rec.Marshal()
	// parse it back and apply it before it goes into an append-only log
	parsed, err := state.Parse(entry)
	if err == nil {
		err = st.Apply(st.Size, parsed)
	}

	if err != nil {
		return fmt.Errorf("app: record: new record: %w", err)
	}

	// store the entry before any witness sees a checkpoint that covers it
	if err := l.Append(entry); err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	size := l.Size()

	root, err := l.Root(size)
	if err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	signed, err := wlog.Sign(wlog.Checkpoint{Origin: cfg.Origin, Size: size, Root: root}, signer)
	if err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	outs := wc.Collect(
		ctx,
		ws,
		witness.Request{Signed: signed, Size: size, OldSize: n, Proof: proofTo(l, size)},
		cfg.Quorum,
	)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("app: record: entry %d is stored but not witnessed, run record again: %w", size-1, err)
	}

	r.Witnesses = statuses(outs, size)
	debugOutcomes("record", outs)
	judge(r, outs, size, size, true)
	cosigs := witness.Cosigned(outs)
	if len(cosigs) < cfg.Quorum {
		r.Add(
			Alarm,
			"quorum",
			fmt.Sprintf(
				"%d of %d witnesses cosigned size %d, quorum is %d; the record stays pending, run snapwitness record again",
				len(cosigs),
				len(ws),
				size,
				cfg.Quorum,
			),
		)
		// keep the old checkpoint. If there's none yet, store this one anyway:
		// the next run needs a signed size to start from, and audit reports the
		// missing quorum
		if cp != nil {
			return nil
		}
	}

	if err := l.WriteCheckpoint(wlog.Attach(signed, cosigs)); err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	n = size

	return nil
}

// loadSigner reads the signing key and checks it's the private half of the
// logkey in the config.
func loadSigner(cfg *config.Config, logKey note.Verifier) (note.Signer, error) {
	b, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("app: record: read log key: %w", err)
	}

	s, err := note.NewSigner(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("app: record: log key %s: %w", cfg.KeyFile, err)
	}

	if s.Name() != cfg.Origin || s.KeyHash() != logKey.KeyHash() {
		return nil, fmt.Errorf("app: record: log key %s does not match the logkey in %s", cfg.KeyFile, cfg.Path)
	}

	return s, nil
}

// lost lists "<time> <id>" for each ID of the states that isn't in ids,
// sorted by ID. The time is when the ID entered the log.
func lost(ids []string, states ...*state.State) []string {
	gone := map[string]state.Seen{}

	for _, s := range states {
		_, removed := state.Diff(s.IDs, ids)
		for _, id := range removed {
			gone[id] = s.IDs[id]
		}
	}

	out := make([]string, 0, len(gone))
	for _, id := range slices.Sorted(maps.Keys(gone)) {
		out = append(out, gone[id].Time.Format(state.TimeFormat)+" "+id)
	}

	return out
}

// toolName returns the program version of the newest snapshot, or plain
// "restic" when that's empty or not printable.
func toolName(snaps []restic.Snapshot) string {
	var newest restic.Snapshot
	for _, s := range snaps {
		if newest.ID == "" || s.Time.After(newest.Time) {
			newest = s
		}
	}

	v := strings.TrimSpace(newest.ProgramVersion)
	if v == "" || strings.IndexFunc(v, func(c rune) bool { return !unicode.IsPrint(c) }) >= 0 {
		return "restic"
	}

	return v
}
