package witness

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/buildwithme/snapwitness/internal/wlog"
)

// Request is one checkpoint to be cosigned.
type Request struct {
	Signed  []byte // note with the log signature only
	Size    int64
	OldSize int64                                 // size the witnesses are expected to have
	Proof   func(from int64) ([]tlog.Hash, error) // consistency proof from `from` to Size
}

// Outcome is what one witness answered.
type Outcome struct {
	Witness string
	Cosig   *wlog.Cosig // nil unless the witness cosigned
	Err     error
	Took    time.Duration
}

// Collect asks all witnesses in ws in parallel and returns the outcomes in
// the order of ws. With stopAt > 0 it returns as soon as stopAt witnesses
// have cosigned or that can't happen anymore, and cancels the rest. With
// stopAt == 0 it waits for every answer, or for ctx.
func (c *Client) Collect(ctx context.Context, ws []Witness, req Request, stopAt int) []Outcome {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	type answer struct {
		i   int
		out Outcome
	}
	// one slot per witness. A late answer can't block once Collect has
	// returned
	answers := make(chan answer, len(ws))
	for i, w := range ws {
		go func() {
			t0 := time.Now()
			cosig, err := c.cosign(ctx, w, req)

			answers <- answer{i, Outcome{Witness: w.Name, Cosig: cosig, Err: err, Took: time.Since(t0)}}
		}()
	}

	outs := make([]Outcome, len(ws))
	answered := make([]bool, len(ws))
	cosigned, pending := 0, len(ws)

wait:
	for pending > 0 {
		// Stop once the quorum is met or can no longer be met
		if stopAt > 0 && (cosigned >= stopAt || cosigned+pending < stopAt) {
			break
		}

		select {
		case a := <-answers:
			outs[a.i], answered[a.i] = a.out, true
			pending--

			if a.out.Cosig != nil {
				cosigned++
			}
		case <-ctx.Done():
			break wait
		}
	}

	// witnesses still out were cut off, by the quorum stop or the caller's ctx
	why := ctx.Err()
	if why == nil {
		why = context.Canceled
	}

	for i, w := range ws {
		if !answered[i] {
			outs[i] = Outcome{Witness: w.Name, Err: fmt.Errorf("witness: %s: %w", w.Name, why), Took: time.Since(start)}
		}
	}

	return outs
}

// cosign asks w to cosign req from req.OldSize. A witness that lags, or
// already has this checkpoint, answers 409 with a size <= req.Size, and we
// ask it once more from that size. A larger size is returned as is.
func (c *Client) cosign(ctx context.Context, w Witness, req Request) (*wlog.Cosig, error) {
	cosig, err := c.addFrom(ctx, w, req, req.OldSize)

	var conflict *ConflictError

	if errors.As(err, &conflict) && conflict.Size <= req.Size && conflict.Size != req.OldSize {
		cosig, err = c.addFrom(ctx, w, req, conflict.Size)
	}

	if err != nil {
		return nil, err
	}

	return &cosig, nil
}

func (c *Client) addFrom(ctx context.Context, w Witness, req Request, old int64) (wlog.Cosig, error) {
	proof, err := req.Proof(old)
	if err != nil {
		return wlog.Cosig{}, fmt.Errorf("witness: %s: proof from %d: %w", w.Name, old, err)
	}

	return c.AddCheckpoint(ctx, w, old, proof, req.Signed)
}

// Cosigned returns the cosignatures of the outcomes that have one.
func Cosigned(outs []Outcome) []wlog.Cosig {
	var cosigs []wlog.Cosig

	for _, o := range outs {
		if o.Cosig != nil {
			cosigs = append(cosigs, *o.Cosig)
		}
	}

	return cosigs
}
