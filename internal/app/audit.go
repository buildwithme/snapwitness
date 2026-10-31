package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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
// neither the restic password nor the log signing key. If ctx ends first it
// sets Err, but still judges the answers that came back. An alarm found
// before a timeout isn't lost.
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

	l, v := readStored(r, cfg.LogDir, logKey, witnessKeys)
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
	ctxErr := ctx.Err()

	var ahead bool

	if opts.Offline {
		r.Witnesses = stored(ws, v.Cosigs)
	} else {
		r.Witnesses = statuses(outs, n)
		debugOutcomes("audit", outs)
		rollback, fork := judge(r, outs, n, ctxErr, map[string]bool{})
		ahead = rollback || fork
	}

	tail(r, l, n, ahead, len(witness.Cosigned(outs)) == len(ws))
	checkFresh(r, cfg, now, st, v.Cosigs, outs)

	switch {
	case listErr == nil:
		slog.Debug("listed", "repo", cfg.Repo, "files", listing.Files, "bytes", listing.Bytes)
		r.Snapshots = len(listing.IDs)
		r.line(
			"repo",
			"%s  %d snapshots, %d files re-hashed",
			cfg.Repo,
			len(listing.IDs),
			listing.Files-len(listing.Foreign),
		)
		compare(r, l, st, listing)
	case ctxErr != nil:
		// listing was cut short, nothing to compare
	case errors.Is(listErr, fs.ErrNotExist):
		ids := st.Sorted()
		details := make([]string, len(ids))

		for i, id := range ids {
			details[i] = fmt.Sprintf("missing %s recorded %s", id, st.IDs[id].Time.Format(state.TimeFormat))
		}

		r.Add(Alarm, "deleted", "the snapshots directory is gone", details...)
	default:
		r.Add(Alarm, "tampered", "the snapshots directory cannot be read", fmt.Sprintf("%q", listErr.Error()))
	}

	r.line("log", "size %d, checkpoint %d, log key %08x", l.Size(), n, logKey.KeyHash())

	if ctxErr != nil {
		return fmt.Errorf("app: audit: %w", ctxErr)
	}

	if st.Last == nil {
		return errors.New("app: audit: no state recorded yet, run snapwitness record first")
	}

	return nil
}

// compare checks the replayed snapshot set against the files the storage
// serves. Names from the storage are quoted in the details. A file name
// could carry terminal escape codes into the report otherwise.
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
			quote(unrecorded)...)
	}

	if len(listing.Mismatch) > 0 {
		r.Add(
			Alarm,
			"tampered",
			plural(len(listing.Mismatch), "snapshot file")+" changed in place: the content does not match the name",
			quote(listing.Mismatch)...)
	}

	if foreign := slices.Concat(listing.Foreign, listing.TooShort); len(foreign) > 0 {
		r.Add(
			Warn,
			"foreign",
			plural(len(foreign), "file")+" in snapshots/ that restic would not read",
			quote(foreign)...)
	}
}

func quote(names []string) []string {
	out := make([]string, len(names))
	for i, s := range names {
		out[i] = strconv.Quote(s)
	}

	return out
}

// clockSkew is how far in the future a cosignature may be dated and still
// count. Enough for clocks that drift a little. A forged time far ahead would
// keep a log fresh forever.
const clockSkew = 5 * time.Minute

// checkFresh raises a stale alarm when fewer than a quorum of witnesses
// confirmed the log within MaxAge, or when there's no record that recent.
// Each witness counts with its newest cosignature, stored or fresh. One
// dated more than clockSkew ahead doesn't count.
func checkFresh(
	r *Report,
	cfg *config.Config,
	now time.Time,
	st *state.State,
	stored []wlog.Cosig,
	outs []witness.Outcome,
) {
	newest := map[string]time.Time{}
	future := map[string]time.Time{}
	vouch := func(c wlog.Cosig) {
		switch {
		case c.Time.After(now.Add(clockSkew)):
			future[c.Name] = c.Time
		case c.Time.After(newest[c.Name]):
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

	for _, name := range slices.Sorted(maps.Keys(future)) {
		t := future[name]
		r.Add(
			Warn,
			"clock",
			fmt.Sprintf(
				"witness %s cosigned at %s, %s in the future: check its clock and this one",
				name,
				t.Format(state.TimeFormat),
				t.Sub(now).Round(time.Second),
			),
		)
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

	if st.Last != nil && now.Sub(st.Last.Time) > cfg.MaxAge {
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

// AuditAll audits all configs in parallel, each with its own timeout (none
// if timeout <= 0), and returns the reports in the order of cfgs. A config
// that timed out gets a report with Err set.
func AuditAll(
	ctx context.Context,
	cfgs []*config.Config,
	wc *witness.Client,
	opts AuditOptions,
	timeout time.Duration,
) []*Report {
	reports := make([]*Report, len(cfgs))

	var wg sync.WaitGroup

	for i, cfg := range cfgs {
		wg.Go(func() {
			ctx := ctx

			if timeout > 0 {
				var cancel context.CancelFunc

				ctx, cancel = context.WithTimeout(ctx, timeout)

				defer cancel()
			}

			reports[i] = Audit(ctx, cfg, wc, opts)
		})
	}

	wg.Wait()

	return reports
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

// readStored opens the log and verifies the stored checkpoint. When either is
// gone, unreadable or doesn't verify, it raises an alarm and returns a nil
// checkpoint.
func readStored(r *Report, dir string, logKey note.Verifier, witnessKeys []note.Verifier) (*wlog.Log, *wlog.Verified) {
	l, err := wlog.Open(dir)
	switch {
	case errors.Is(err, wlog.ErrNoLog):
		r.Add(Alarm, "deleted", "the log is gone from the storage")
		return nil, nil
	case err != nil:
		r.Add(Alarm, "tampered", "the log cannot be read: "+err.Error())
		return nil, nil
	}

	r.LogSize = l.Size()
	cp, err := l.ReadCheckpoint()

	switch {
	case errors.Is(err, wlog.ErrNoCheckpoint):
		r.Add(Alarm, "deleted", "the checkpoint is gone from the storage")
		return l, nil
	case err != nil:
		r.Add(Alarm, "tampered", "the log cannot be read: "+err.Error())
		return l, nil
	}

	return l, checkStored(r, l, cp, logKey, witnessKeys)
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

// tail raises a tampered alarm and returns true when the log has entries past
// the checkpoint of size n. Nothing may build on those. We only show how to
// drop them when allCosigned is set and ahead isn't, otherwise a witness may
// have cosigned them.
func tail(r *Report, l *wlog.Log, n int64, ahead, allCosigned bool) bool {
	k := l.Size() - n
	if k <= 0 {
		return false
	}

	entries := fmt.Sprintf("%d log entries", k)
	if k == 1 {
		entries = "1 log entry"
	}

	var advice string

	switch {
	case ahead:
		advice = "do not drop them: a witness has seen a larger or different log, so they may be records it cosigned (see LIMITATIONS.md)"
	case !allCosigned:
		advice = "do not drop them before an audit where every witness answers and none has seen them (see LIMITATIONS.md)"
	default:
		p := shellQuote(filepath.Join(l.Dir(), wlog.EntriesFile))
		advice = fmt.Sprintf(
			"every witness is at size %d; if a second audit shows this alarm again, drop them by hand: [ -f %s ] && [ ! -L %s ] && truncate -c -s %d %s (see LIMITATIONS.md)",
			n,
			p,
			p,
			l.Offset(n),
			p,
		)
	}

	r.Add(
		Alarm,
		"tampered",
		entries+" past the checkpoint: the storage added them, or a record run stopped between its append and its checkpoint write",
		advice,
	)

	return true
}

// shellQuote quotes s as one word for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// judge turns the witness answers for a checkpoint of size n into findings.
// An honest storage always has the newest checkpoint. A witness that has seen
// a bigger log proves a rollback, one with a different tree a fork. Other
// errors give one warning per witness; warned tracks that across calls.
func judge(r *Report, outs []witness.Outcome, n int64, ctxErr error, warned map[string]bool) (rollback, fork bool) {
	var (
		ahead, forked []string
		seen          int64
	)

	for _, o := range outs {
		var conflict *witness.ConflictError
		switch {
		case o.Cosig != nil, errors.Is(o.Err, context.Canceled), ctxErr != nil && errors.Is(o.Err, ctxErr):
			// cosigned, or cut short: nothing to judge
		case errors.As(o.Err, &conflict) && conflict.Size > n:
			ahead = append(ahead, o.Witness)
			seen = max(seen, conflict.Size)
		case errors.Is(o.Err, witness.ErrInconsistent):
			forked = append(forked, o.Witness)
		case !warned[o.Witness]:
			warned[o.Witness] = true
			r.Add(Warn, "witness", o.Err.Error())
		}
	}

	if len(ahead) > 0 {
		r.Add(
			Alarm,
			"rollback",
			fmt.Sprintf("%s seen log size %d, the storage's checkpoint is size %d", who(ahead), seen, n),
		)
	}

	if len(forked) > 0 {
		r.Add(Alarm, "fork", fmt.Sprintf("%s cosigned a different log at size %d", who(forked), n))
	}

	return len(ahead) > 0, len(forked) > 0
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
