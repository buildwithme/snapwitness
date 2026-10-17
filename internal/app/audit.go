package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"

	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/restic"
	"github.com/buildwithme/snapwitness/internal/state"
	"github.com/buildwithme/snapwitness/internal/witness"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

// AuditOptions are the inputs of Audit and AuditAll.
type AuditOptions struct {
	Offline bool
	Workers int              // GOMAXPROCS when 0
	Now     func() time.Time // time.Now when nil
}

// Audit checks the storage against the log and the witnesses. It needs
// neither the restic password nor the log signing key.
func Audit(ctx context.Context, cfg *config.Config, wc *witness.Client, opts AuditOptions) *Report {
	start := time.Now()

	r := &Report{Command: "audit", Config: cfg.Path, Origin: cfg.Origin}
	if err := audit(ctx, cfg, wc, opts, r); err != nil {
		r.Err = err.Error()
	}

	r.Took = time.Since(start)

	return r
}

func audit(ctx context.Context, cfg *config.Config, wc *witness.Client, opts AuditOptions, r *Report) error {
	now := clock(opts.Now)()

	logKey, witnessKeys, ws, err := trust(cfg)
	if err != nil {
		return fmt.Errorf("app: audit: %w", err)
	}

	l, err := wlog.Open(cfg.LogDir)
	if errors.Is(err, wlog.ErrNoLog) {
		r.Add(Alarm, "deleted", "the log is gone from the storage")
		return nil
	}

	if err != nil {
		return fmt.Errorf("app: audit: %w", err)
	}

	r.LogSize = l.Size()
	cp, err := l.ReadCheckpoint()

	switch {
	case errors.Is(err, wlog.ErrNoCheckpoint) && l.Size() == 0:
		return errors.New("app: audit: no checkpoint yet, run snapwitness record first")
	case errors.Is(err, wlog.ErrNoCheckpoint):
		r.Add(Alarm, "tampered", fmt.Sprintf("the log has %d entries but no checkpoint", l.Size()))
		return nil
	case err != nil:
		return fmt.Errorf("app: audit: %w", err)
	}

	v := checkStored(r, l, cp, logKey, witnessKeys)
	if v == nil {
		return nil
	}

	n := v.Size

	st, err := state.Replay(l.Entries(n))
	if err != nil {
		r.Add(Alarm, "tampered", "the witnessed log records do not replay", err.Error())
		return nil
	}

	// re-hash the storage while the witnesses answer. The audit takes as long
	// as the slower of the two
	var (
		listing *restic.Listing
		g       errgroup.Group
	)
	g.Go(func() error {
		var err error

		listing, err = restic.List(ctx, cfg.Repo, opts.Workers)

		return err
	})

	var outs []witness.Outcome
	if !opts.Offline {
		outs = wc.Collect(ctx, ws, witness.Request{Signed: v.Signed, Size: n, OldSize: n, Proof: proofTo(l, n)}, 0)
	}

	listErr := g.Wait()
	// stop on a timeout or an interrupt, the answers so far can't be trusted
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("app: audit: %w", err)
	}

	if opts.Offline {
		r.Witnesses = stored(ws, v.Cosigs)
	} else {
		r.Witnesses = statuses(outs, n)
		debugOutcomes("audit", outs)

		if vd := judge(r, outs, n, l.Size(), true); len(vd.pending) > 0 {
			r.Add(Warn, "pending", "a record run did not finish; run snapwitness record again", vd.pending...)
		}
	}

	checkFresh(r, cfg, now, st, v.Cosigs, outs)

	if listErr != nil {
		r.line("log", "size %d, checkpoint %d, log key %08x", l.Size(), n, logKey.KeyHash())
		return fmt.Errorf("app: audit: %w", listErr)
	}

	slog.Debug("listed", "repo", cfg.Repo, "files", listing.Files, "bytes", listing.Bytes)
	r.Snapshots = len(listing.IDs)
	r.line(
		"repo",
		"%s  %d snapshots, %d files re-hashed",
		cfg.Repo,
		len(listing.IDs),
		listing.Files-len(listing.Foreign),
	)
	r.line("log", "size %d, checkpoint %d, log key %08x", l.Size(), n, logKey.KeyHash())
	compare(r, l, st, listing)

	return nil
}

// compare checks the replayed snapshot set against the files the storage
// serves.
func compare(r *Report, l *wlog.Log, st *state.State, listing *restic.Listing) {
	unrecorded, missing := state.Diff(st.IDs, listing.IDs)
	if len(missing) > 0 {
		details := make([]string, len(missing))
		for i, id := range missing {
			details[i] = fmt.Sprintf("missing %s recorded %s", id, st.IDs[id].Time.Format(state.TimeFormat))
		}

		r.Add(
			Alarm,
			"deleted",
			fmt.Sprintf("%d of %d recorded snapshots missing from the storage", len(missing), len(st.IDs)),
			details...)
	}

	if i := slices.IndexFunc(r.Findings, func(f Finding) bool { return f.Kind == "rollback" }); i >= 0 {
		details := []string{"likely: the storage was restored from an older copy"}
		if m := st.MatchIndex(state.SetHash(listing.IDs)); m >= 0 {
			details = append(details, fmt.Sprintf("the storage matches state #%d from %s", m+1, recordTime(l, m)))
		}

		r.Findings[i].Details = append(r.Findings[i].Details, details...)
	}

	if len(unrecorded) > 0 {
		r.Add(
			Warn,
			"unrecorded",
			plural(len(unrecorded), "snapshot")+" on the storage not in the log (a backup without record?)",
			unrecorded...)
	}

	if len(listing.Mismatch) > 0 {
		r.Add(
			Alarm,
			"tampered",
			plural(len(listing.Mismatch), "snapshot file")+" changed in place: the content does not match the name",
			listing.Mismatch...)
	}

	if foreign := slices.Concat(listing.Foreign, listing.TooShort); len(foreign) > 0 {
		r.Add(Warn, "foreign", plural(len(foreign), "file")+" in snapshots/ that restic would not read", foreign...)
	}
}

// checkFresh raises a stale alarm when fewer than a quorum of witnesses
// confirmed the log within MaxAge, or when there's no record that recent.
// Each witness counts with its newest cosignature, stored or fresh.
func checkFresh(
	r *Report,
	cfg *config.Config,
	now time.Time,
	st *state.State,
	stored []wlog.Cosig,
	outs []witness.Outcome,
) {
	newest := map[string]time.Time{}
	vouch := func(c wlog.Cosig) {
		if c.Time.After(newest[c.Name]) {
			newest[c.Name] = c.Time
		}
	}

	for _, c := range stored {
		vouch(c)
	}

	for _, o := range outs {
		if o.Cosig != nil {
			vouch(*o.Cosig)
		}
	}

	fresh := 0

	for _, t := range newest {
		if now.Sub(t) <= cfg.MaxAge {
			fresh++
		}
	}

	if fresh < cfg.Quorum {
		r.Add(
			Alarm,
			"stale",
			fmt.Sprintf(
				"%d of %d witnesses vouched for this log in the last %s, quorum is %d",
				fresh,
				len(cfg.Witnesses),
				cfg.MaxAge,
				cfg.Quorum,
			),
		)
	}

	switch {
	case st.Last == nil:
		r.Add(Alarm, "stale", "no state recorded yet")
	case now.Sub(st.Last.Time) > cfg.MaxAge:
		r.Add(
			Alarm,
			"stale",
			fmt.Sprintf(
				"no new state recorded for %s (last %s)",
				now.Sub(st.Last.Time).Round(time.Minute),
				st.Last.Time.Format(state.TimeFormat),
			),
		)
	}
}

func trust(cfg *config.Config) (note.Verifier, []note.Verifier, []witness.Witness, error) {
	logKey, err := cfg.LogVerifier()
	if err != nil {
		return nil, nil, nil, err
	}

	keys, err := cfg.WitnessVerifiers()
	if err != nil {
		return nil, nil, nil, err
	}

	ws := make([]witness.Witness, len(cfg.Witnesses))
	for i, w := range cfg.Witnesses {
		ws[i] = witness.Witness{Name: keys[i].Name(), URL: w.URL, Verifier: keys[i]}
	}

	return logKey, keys, ws, nil
}

// checkStored verifies the stored checkpoint and checks the storage still
// serves every entry it covers. On failure it raises a tampered alarm and
// returns nil.
func checkStored(r *Report, l *wlog.Log, cp []byte, logKey note.Verifier, witnessKeys []note.Verifier) *wlog.Verified {
	v, err := wlog.Verify(cp, logKey, witnessKeys)
	if err != nil {
		r.Add(Alarm, "tampered", "the checkpoint does not verify", err.Error())
		return nil
	}

	if v.Size > l.Size() {
		r.Add(
			Alarm,
			"tampered",
			fmt.Sprintf("log truncated: the checkpoint covers %d entries, the storage serves %d", v.Size, l.Size()),
		)

		return nil
	}

	root, err := l.Root(v.Size)
	if err != nil || root != v.Root {
		r.Add(Alarm, "tampered", fmt.Sprintf("the first %d log entries do not match the checkpoint root", v.Size))
		return nil
	}

	return v
}

// verdict is what the witnesses said about a checkpoint.
type verdict struct {
	rollback bool // a witness saw a bigger log than the storage serves
	fork     bool
	pending  []string // at a size the storage has but no stored checkpoint covers
}

// judge turns the witness answers for a checkpoint of size n into findings.
// served is how many entries the storage serves. Other witness errors only
// become warnings with warn set.
func judge(r *Report, outs []witness.Outcome, n, served int64, warn bool) verdict {
	var (
		vd            verdict
		ahead, forked []string
		seen          int64
	)

	for _, o := range outs {
		var conflict *witness.ConflictError
		switch {
		case o.Cosig != nil, errors.Is(o.Err, context.Canceled):
			// cosigned, or cut by the quorum stop: nothing to judge
		case errors.As(o.Err, &conflict) && conflict.Size > served:
			ahead = append(ahead, o.Witness)
			seen = max(seen, conflict.Size)
		case errors.As(o.Err, &conflict) && conflict.Size > n:
			vd.pending = append(vd.pending, fmt.Sprintf("witness %s has seen size %d", o.Witness, conflict.Size))
		case errors.Is(o.Err, witness.ErrInconsistent):
			forked = append(forked, o.Witness)
		case warn:
			r.Add(Warn, "witness", o.Err.Error())
		}
	}

	if len(ahead) > 0 {
		vd.rollback = true

		r.Add(
			Alarm,
			"rollback",
			fmt.Sprintf("%s seen log size %d, the storage serves size %d", who(ahead), seen, served),
		)
	}

	if len(forked) > 0 {
		vd.fork = true

		r.Add(Alarm, "fork", fmt.Sprintf("%s cosigned a different log at size %d", who(forked), n))
	}

	return vd
}

func who(names []string) string {
	if len(names) == 1 {
		return "witness " + names[0] + " has"
	}

	return "witnesses " + strings.Join(names, ", ") + " have"
}

func stored(ws []witness.Witness, cosigs []wlog.Cosig) []WitnessStatus {
	sts := make([]WitnessStatus, len(ws))
	for i, w := range ws {
		sts[i] = WitnessStatus{Name: w.Name, Status: "skipped"}
		for _, c := range cosigs {
			if c.Name == w.Name {
				sts[i].Time = c.Time
			}
		}
	}

	return sts
}

// proofTo gives Collect the consistency proof from any older size to size.
// Collect calls it from several goroutines. That's fine as long as nobody
// writes the log.
func proofTo(l *wlog.Log, size int64) func(int64) ([]tlog.Hash, error) {
	return func(from int64) ([]tlog.Hash, error) {
		return l.Consistency(from, size)
	}
}

func recordTime(l *wlog.Log, i int64) string {
	rec, err := state.Parse(l.Entries(i + 1)[i])
	if err != nil {
		return "an unreadable record"
	}

	return rec.Time.Format(state.TimeFormat)
}

func debugOutcomes(step string, outs []witness.Outcome) {
	for _, o := range outs {
		slog.Debug(step+": witness", "name", o.Witness, "cosigned", o.Cosig != nil, "took", o.Took, "err", o.Err)
	}
}

func clock(now func() time.Time) func() time.Time {
	if now == nil {
		return time.Now
	}

	return now
}
