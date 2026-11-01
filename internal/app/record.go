package app

import (
	"context"
	"fmt"
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
const removedHint = "use -accept-removed only if you removed them on purpose; there is no separate admin key for removals (see LIMITATIONS.md)"

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

	l, cp := readStored(r, cfg.LogDir, logKey, witnessKeys)
	if cp == nil {
		return nil
	}

	n := cp.Size

	defer func() {
		r.LogSize = l.Size()
		r.line("log", "size %d, checkpoint %d", l.Size(), n)
	}()

	// Probe the witnesses before we append. A new record must never build on
	// a rolled-back copy.
	outs := wc.Collect(ctx, ws, witness.Request{Signed: cp.Signed, Size: n, OldSize: n, Proof: proofTo(l, n)}, 0)
	r.Witnesses = statuses(outs, n)
	debugOutcomes("record probe", outs)

	warned := map[string]bool{}
	rollback, fork := judge(r, outs, n, ctx.Err(), warned)
	// Never sign entries past the checkpoint
	tampered := tail(r, l, n, rollback || fork, everyWitnessCosigned(ctx.Err(), outs, ws))
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	if rollback || fork || tampered {
		return nil
	}

	st, err := state.Replay(l.Entries(n))
	if err != nil {
		r.Add(Alarm, "tampered", "the log records do not replay", err.Error())
		return nil
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

	if len(removed) > 0 && !opts.AcceptRemoved {
		details := make([]string, 0, len(removed)+1)
		for _, id := range removed {
			details = append(details, st.IDs[id].Time.Format(state.TimeFormat)+" "+id)
		}

		r.Add(
			Alarm,
			"deleted",
			plural(len(removed), "recorded snapshot")+" gone from the repository",
			append(details, removedHint)...)

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

	// entry and log-signed checkpoint go to the storage before any witness
	// sees them. That way an honest storage always has the newest checkpoint
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

	if err := l.WriteCheckpoint(signed); err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	n = size

	outs = wc.Collect(
		ctx,
		ws,
		witness.Request{Signed: signed, Size: size, OldSize: cp.Size, Proof: proofTo(l, size)},
		cfg.Quorum,
	)
	r.Witnesses = statuses(outs, size)
	debugOutcomes("record", outs)
	judge(r, outs, size, ctx.Err(), warned)
	// Keep every cosignature that came back, even after an interrupt
	cosigs := witness.Cosigned(outs)
	if err := l.WriteCheckpoint(wlog.Attach(signed, cosigs)); err != nil {
		return fmt.Errorf("app: record: %w", err)
	}

	if len(cosigs) >= cfg.Quorum {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"app: record: checkpoint %d is saved with %d of %d cosignatures, run snapwitness record again: %w",
			size,
			len(cosigs),
			cfg.Quorum,
			err,
		)
	}

	r.Add(
		Alarm,
		"quorum",
		fmt.Sprintf(
			"%d of %d witnesses cosigned size %d, quorum is %d: the checkpoint is saved; run snapwitness record or audit again when the witnesses are back",
			len(cosigs),
			len(ws),
			size,
			cfg.Quorum,
		),
	)

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
