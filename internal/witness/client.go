// Package witness asks C2SP tlog-witness servers to cosign log checkpoints.
// Witnesses are asked in parallel, and a dead or slow one costs a single
// timeout overall.
package witness

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/buildwithme/snapwitness/internal/wlog"
)

// Witness is a witness endpoint and the key that must sign its cosignatures.
type Witness struct {
	Name     string
	URL      string
	Verifier note.Verifier
}

// ConflictError is a 409 answer: the witness has a different size for this log.
type ConflictError struct{ Size int64 }

// Error reports the conflict and the size the witness has.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("witness: conflict: witness has size %d", e.Size)
}

var (
	// ErrUnknownLog is a 404 answer: the witness does not know this log.
	ErrUnknownLog = errors.New("witness: unknown log")
	// ErrBadSignature is a 403 answer: the log signature did not verify.
	ErrBadSignature = errors.New("witness: bad log signature")
	// ErrInconsistent is a 422 answer: the consistency proof failed and the log
	// has forked from what the witness saw before.
	ErrInconsistent = errors.New("witness: inconsistent tree")
)

// Client speaks the C2SP tlog-witness protocol. The zero value uses
// http.DefaultClient.
type Client struct{ HTTP *http.Client }

// AddCheckpoint sends signed to w with the consistency proof from oldSize.
// The cosignature that comes back is checked against w.Verifier and the
// checkpoint body.
func (c *Client) AddCheckpoint(
	ctx context.Context,
	w Witness,
	oldSize int64,
	proof []tlog.Hash,
	signed []byte,
) (wlog.Cosig, error) {
	cosig, err := c.addCheckpoint(ctx, w, oldSize, proof, signed)
	if err != nil {
		return wlog.Cosig{}, fmt.Errorf("witness: %s: %w", w.Name, err)
	}

	return cosig, nil
}

// maxAnswer caps how many bytes of a witness answer are read.
const maxAnswer = 64 << 10

func (c *Client) addCheckpoint(
	ctx context.Context,
	w Witness,
	oldSize int64,
	proof []tlog.Hash,
	signed []byte,
) (wlog.Cosig, error) {
	var body bytes.Buffer
	fmt.Fprintf(&body, "old %d\n", oldSize)

	for _, h := range proof {
		body.WriteString(base64.StdEncoding.EncodeToString(h[:]))
		body.WriteByte('\n')
	}

	body.WriteByte('\n')
	body.Write(signed)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimSuffix(w.URL, "/")+"/add-checkpoint",
		&body,
	)
	if err != nil {
		return wlog.Cosig{}, err
	}

	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}

	resp, err := hc.Do(req)
	if err != nil {
		return wlog.Cosig{}, err
	}

	defer func() { _ = resp.Body.Close() }()

	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return wlog.Cosig{}, fmt.Errorf("read answer: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return openCosig(w, signed, answer)
	case http.StatusConflict:
		// witnesses don't agree on the content type. Any is fine if the body
		// is a size
		size, err := strconv.ParseInt(string(bytes.TrimSpace(answer)), 10, 64)
		if err != nil || size < 0 {
			return wlog.Cosig{}, fmt.Errorf(
				"409 without a size (content type %q): %q",
				resp.Header.Get("Content-Type"),
				excerpt(answer),
			)
		}

		return wlog.Cosig{}, &ConflictError{Size: size}
	case http.StatusNotFound:
		return wlog.Cosig{}, ErrUnknownLog
	case http.StatusForbidden:
		return wlog.Cosig{}, ErrBadSignature
	case http.StatusUnprocessableEntity:
		return wlog.Cosig{}, ErrInconsistent
	default:
		return wlog.Cosig{}, fmt.Errorf("status %d: %q", resp.StatusCode, excerpt(answer))
	}
}

// openCosig checks the signature lines of a 200 answer against the
// checkpoint body and returns the one made by w. note.Open only knows the
// witness key here. It skips the log signature in signed without checking
// it.
func openCosig(w Witness, signed, answer []byte) (wlog.Cosig, error) {
	n, err := note.Open(append(bytes.Clone(signed), answer...), note.VerifierList(w.Verifier))
	if err != nil {
		return wlog.Cosig{}, fmt.Errorf("bad cosignature: %w", err)
	}

	for _, s := range n.Sigs {
		if s.Name != w.Name || s.Hash != w.Verifier.KeyHash() {
			continue
		}

		t, err := fnote.CoSigV1Timestamp(s)
		if err != nil {
			return wlog.Cosig{}, fmt.Errorf("bad cosignature: %w", err)
		}

		return wlog.Cosig{Name: s.Name, Time: t.UTC(), Line: "\u2014 " + s.Name + " " + s.Base64}, nil
	}

	return wlog.Cosig{}, fmt.Errorf("no cosignature from %s", w.Name)
}

func excerpt(b []byte) []byte {
	b = bytes.TrimSpace(b)
	if len(b) > 200 {
		b = b[:200]
	}

	return b
}
