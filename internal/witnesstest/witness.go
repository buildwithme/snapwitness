// Package witnesstest runs an in-process C2SP tlog-witness on httptest. Tests
// use it to get witnesses that cosign, lag, conflict, go down or answer
// slowly.
package witnesstest

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Witness is an in-process C2SP tlog-witness for tests.
type Witness struct {
	srv      *httptest.Server
	name     string
	vkey     string
	signer   note.Signer
	verifier note.Verifier

	mu       sync.Mutex
	logs     map[string]*logState
	down     bool
	delay    time.Duration
	requests int
}

// logState is what the witness remembers about one log.
type logState struct {
	verifier note.Verifier
	size     int64
	root     tlog.Hash
}

// New starts a witness named name with a fresh key. The server is closed when
// the test ends.
func New(t testing.TB, name string) *Witness {
	t.Helper()

	skey, plain, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatalf("witnesstest: generate key: %v", err)
	}

	signer, err := fnote.NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatalf("witnesstest: signer: %v", err)
	}

	vkey, err := fnote.VKeyToCosignatureV1(plain)
	if err != nil {
		t.Fatalf("witnesstest: vkey: %v", err)
	}

	verifier, err := fnote.NewVerifierForCosignatureV1(vkey)
	if err != nil {
		t.Fatalf("witnesstest: verifier: %v", err)
	}

	w := &Witness{
		name:     name,
		vkey:     vkey,
		signer:   signer,
		verifier: verifier,
		logs:     map[string]*logState{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", w.addCheckpoint)
	w.srv = httptest.NewServer(mux)
	t.Cleanup(w.srv.Close)

	return w
}

// URL returns the base URL of the witness.
func (w *Witness) URL() string {
	return w.srv.URL
}

// Name returns the witness key name.
func (w *Witness) Name() string {
	return w.name
}

// VKey returns the witness verifier key in cosignature/v1 form.
func (w *Witness) VKey() string {
	return w.vkey
}

// Verifier returns the verifier for the witness cosignatures.
func (w *Witness) Verifier() note.Verifier {
	return w.verifier
}

// AddLog registers a log with its origin and log vkey, starting at size 0.
func (w *Witness) AddLog(origin, logVKey string) error {
	v, err := note.NewVerifier(logVKey)
	if err != nil {
		return fmt.Errorf("witnesstest: add log %s: %w", origin, err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, ok := w.logs[origin]; ok {
		return fmt.Errorf("witnesstest: add log %s: already added", origin)
	}

	w.logs[origin] = &logState{verifier: v}

	return nil
}

// Size returns the size the witness has for origin, or 0 for an unknown log.
func (w *Witness) Size(origin string) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	if l := w.logs[origin]; l != nil {
		return l.size
	}

	return 0
}

// SetDown makes the witness answer 503 to every request while down is true.
func (w *Witness) SetDown(down bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.down = down
}

// SetDelay makes the witness wait d before answering. The wait ends early when
// the request context is canceled.
func (w *Witness) SetDelay(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.delay = d
}

// Requests returns how many requests the witness has received.
func (w *Witness) Requests() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.requests
}

// addCheckpoint serves the C2SP tlog-witness add-checkpoint endpoint.
func (w *Witness) addCheckpoint(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	w.requests++
	down, delay := w.down, w.delay
	w.mu.Unlock()

	// read the body first. The server cancels r.Context() for a client that
	// went away only once the body is consumed
	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, 1<<20))
	if err != nil {
		http.Error(rw, "bad body", http.StatusBadRequest)
		return
	}

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}

	if down {
		http.Error(rw, "witness down", http.StatusServiceUnavailable)
		return
	}

	status, answer := w.add(body)
	if status == http.StatusConflict {
		rw.Header().Set("Content-Type", "text/x.tlog.size")
	} else {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}

	rw.WriteHeader(status)
	_, _ = rw.Write(answer)
}

// add checks one add-checkpoint request in the order the C2SP tlog-witness
// spec gives. It stores the new size and root, and returns the status and
// the body to answer with.
func (w *Witness) add(body []byte) (int, []byte) {
	old, proof, signed, err := parseRequest(body)
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error())
	}

	// Find the log by the origin line before verifying, as a real witness does
	origin, _, _ := bytes.Cut(signed, []byte("\n"))

	w.mu.Lock()
	defer w.mu.Unlock()

	l := w.logs[string(origin)]
	if l == nil {
		return http.StatusNotFound, []byte("unknown log")
	}

	n, err := note.Open(signed, note.VerifierList(l.verifier))
	if err != nil {
		var (
			unverified *note.UnverifiedNoteError
			invalid    *note.InvalidSignatureError
		)

		if errors.As(err, &unverified) || errors.As(err, &invalid) {
			return http.StatusForbidden, []byte("bad log signature")
		}

		return http.StatusBadRequest, []byte(err.Error())
	}

	size, root, err := parseCheckpoint(n.Text)
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error())
	}

	if old > size {
		return http.StatusBadRequest, fmt.Appendf(nil, "old size %d above checkpoint size %d", old, size)
	}

	if old != l.size {
		return http.StatusConflict, fmt.Appendf(nil, "%d\n", l.size)
	}

	// Accept any tree on top of size 0; CheckTree wants equal roots for equal
	// sizes
	if l.size > 0 {
		if err := tlog.CheckTree(proof, size, root, l.size, l.root); err != nil {
			return http.StatusUnprocessableEntity, []byte("bad consistency proof")
		}
	}

	cosigned, err := note.Sign(&note.Note{Text: n.Text}, w.signer)
	if err != nil {
		return http.StatusInternalServerError, []byte(err.Error())
	}

	l.size, l.root = size, root

	return http.StatusOK, cosigned[len(n.Text)+1:]
}

func parseRequest(body []byte) (int64, tlog.TreeProof, []byte, error) {
	line, rest, ok := bytes.Cut(body, []byte("\n"))

	text, found := strings.CutPrefix(string(line), "old ")
	if !ok || !found {
		return 0, nil, nil, errors.New("missing old line")
	}

	old, err := strconv.ParseInt(text, 10, 64)
	if err != nil || old < 0 {
		return 0, nil, nil, fmt.Errorf("bad old size %q", text)
	}

	var proof tlog.TreeProof

	for {
		line, rest, ok = bytes.Cut(rest, []byte("\n"))
		if !ok {
			return 0, nil, nil, errors.New("missing empty line before the note")
		}

		if len(line) == 0 {
			return old, proof, rest, nil
		}

		h, err := tlog.ParseHash(string(line))
		if err != nil {
			return 0, nil, nil, fmt.Errorf("bad proof line %q", line)
		}

		proof = append(proof, h)
	}
}

// parseCheckpoint reads size and root from a checkpoint body. Extension lines
// after the root are fine.
func parseCheckpoint(text string) (int64, tlog.Hash, error) {
	lines := strings.SplitN(text, "\n", 4)
	if len(lines) < 4 {
		return 0, tlog.Hash{}, errors.New("short checkpoint")
	}

	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 {
		return 0, tlog.Hash{}, fmt.Errorf("bad checkpoint size %q", lines[1])
	}

	root, err := tlog.ParseHash(lines[2])
	if err != nil {
		return 0, tlog.Hash{}, fmt.Errorf("bad checkpoint root %q", lines[2])
	}

	return size, root, nil
}
