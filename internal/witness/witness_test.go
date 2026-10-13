package witness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/buildwithme/snapwitness/internal/witnesstest"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

// testLog is an in-memory RFC 6962 tree (x/mod tlog), signed like the real
// log.
type testLog struct {
	origin string
	vkey   string
	signer note.Signer
	hashes []tlog.Hash
	size   int64
}

func newLogKey(t testing.TB) (note.Signer, string) {
	t.Helper()

	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/log")
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}

	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("log signer: %v", err)
	}

	return s, vkey
}

// newTestLog makes a log of n entries derived from tag. Same key with another
// tag gives you a fork.
func newTestLog(t testing.TB, signer note.Signer, vkey string, n int, tag string) *testLog {
	t.Helper()

	l := &testLog{origin: signer.Name(), vkey: vkey, signer: signer}
	for range n {
		hs, err := tlog.StoredHashes(l.size, fmt.Appendf(nil, "%s %d", tag, l.size), l)
		if err != nil {
			t.Fatalf("stored hashes: %v", err)
		}

		l.hashes = append(l.hashes, hs...)
		l.size++
	}

	return l
}

func (l *testLog) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 || x >= int64(len(l.hashes)) {
			return nil, fmt.Errorf("hash %d not stored", x)
		}

		out[i] = l.hashes[x]
	}

	return out, nil
}

// request returns a Request for the signed checkpoint at size, for witnesses
// expected to be at old.
func (l *testLog) request(t testing.TB, old, size int64) Request {
	t.Helper()

	root, err := tlog.TreeHash(size, l)
	if err != nil {
		t.Fatalf("tree hash %d: %v", size, err)
	}

	body := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size, base64.StdEncoding.EncodeToString(root[:]))

	signed, err := note.Sign(&note.Note{Text: body}, l.signer)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}

	return Request{
		Signed:  signed,
		Size:    size,
		OldSize: old,
		Proof: func(from int64) ([]tlog.Hash, error) {
			if from == 0 || from == size {
				return nil, nil
			}

			return tlog.ProveTree(size, from, l)
		},
	}
}

func newCosigKey(t testing.TB, name string) (note.Signer, note.Verifier) {
	t.Helper()

	skey, plain, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatalf("generate witness key: %v", err)
	}

	s, err := fnote.NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatalf("witness signer: %v", err)
	}

	vkey, err := fnote.VKeyToCosignatureV1(plain)
	if err != nil {
		t.Fatalf("witness vkey: %v", err)
	}

	v, err := fnote.NewVerifierForCosignatureV1(vkey)
	if err != nil {
		t.Fatalf("witness verifier: %v", err)
	}

	return s, v
}

// newWitness starts a test witness that knows l, or no log for a nil l. The
// client entry is built from the vkey like a config would do it.
func newWitness(t testing.TB, name string, l *testLog) (*witnesstest.Witness, Witness) {
	t.Helper()
	tw := witnesstest.New(t, name)
	if l != nil {
		if err := tw.AddLog(l.origin, l.vkey); err != nil {
			t.Fatalf("add log: %v", err)
		}
	}

	v, err := fnote.NewVerifierForCosignatureV1(tw.VKey())
	if err != nil {
		t.Fatalf("witness verifier: %v", err)
	}

	return tw, Witness{Name: tw.Name(), URL: tw.URL(), Verifier: v}
}

func advance(t testing.TB, c *Client, tw *witnesstest.Witness, w Witness, l *testLog, size int64) {
	t.Helper()
	req := l.request(t, tw.Size(l.origin), size)

	proof, err := req.Proof(req.OldSize)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	if _, err := c.AddCheckpoint(t.Context(), w, req.OldSize, proof, req.Signed); err != nil {
		t.Fatalf("advance %s to %d: %v", w.Name, size, err)
	}

	if got := tw.Size(l.origin); got != size {
		t.Fatalf("witness size: got %d, want %d", got, size)
	}
}

// slowWitness starts a witness that answers 503 after 5s. arrived is closed
// once it holds a request, and canceled is closed if that request's context
// ends first.
func slowWitness(t *testing.T) (w Witness, arrived, canceled <-chan struct{}) {
	t.Helper()

	in, done := make(chan struct{}), make(chan struct{})

	var inOnce, doneOnce sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Read the body so the server notices the client going away
		_, _ = io.Copy(io.Discard, r.Body)

		inOnce.Do(func() { close(in) })

		select {
		case <-r.Context().Done():
			doneOnce.Do(func() { close(done) })
		case <-time.After(5 * time.Second):
			http.Error(rw, "too late", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(srv.Close)
	_, v := newCosigKey(t, "slow")

	return Witness{Name: "slow", URL: srv.URL, Verifier: v}, in, done
}

// gatedTransport holds back every request not going to host until open is
// closed. That way the request to host is in flight before any other witness
// answers.
type gatedTransport struct {
	host string
	open <-chan struct{}
}

func (g gatedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != g.host {
		select {
		case <-g.open:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}

	return http.DefaultTransport.RoundTrip(r)
}

// checkCosig checks that c is a valid cosignature by w on signed, made no
// earlier than since.
func checkCosig(t *testing.T, w Witness, signed []byte, c *wlog.Cosig, since time.Time) {
	t.Helper()

	if c == nil {
		t.Fatalf("%s: no cosignature", w.Name)
	}

	if c.Name != w.Name {
		t.Errorf("cosig name: got %q, want %q", c.Name, w.Name)
	}

	if strings.Contains(c.Line, "\n") {
		t.Errorf("cosig line has a newline: %q", c.Line)
	}

	msg := append(bytes.Clone(signed), c.Line+"\n"...)
	if _, err := note.Open(msg, note.VerifierList(w.Verifier)); err != nil {
		t.Errorf("open with cosig line: %v", err)
	}

	// Cosignature timestamps have 1s resolution
	if c.Time.Before(since.Truncate(time.Second)) || c.Time.After(time.Now()) {
		t.Errorf("cosig time: got %v, want between %v and now", c.Time, since)
	}
}

func TestCollectCosign(t *testing.T) {
	tests := []struct {
		name string
		size int64
	}{
		{"empty log", 0},
		{"from size 0 to 5", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, vkey := newLogKey(t)
			l := newTestLog(t, signer, vkey, int(tt.size), "a")

			var (
				tws []*witnesstest.Witness
				ws  []Witness
			)

			for _, name := range []string{"w1", "w2", "w3"} {
				tw, w := newWitness(t, name, l)
				tws, ws = append(tws, tw), append(ws, w)
			}

			req := l.request(t, 0, tt.size)
			since := time.Now()

			outs := (&Client{}).Collect(t.Context(), ws, req, 0)

			if len(outs) != len(ws) {
				t.Fatalf("outcomes: got %d, want %d", len(outs), len(ws))
			}

			for i, o := range outs {
				if o.Witness != ws[i].Name {
					t.Errorf("outcome %d witness: got %q, want %q", i, o.Witness, ws[i].Name)
				}

				if o.Err != nil {
					t.Fatalf("%s: %v", o.Witness, o.Err)
				}

				checkCosig(t, ws[i], req.Signed, o.Cosig, since)

				if got := tws[i].Size(l.origin); got != tt.size {
					t.Errorf("%s size: got %d, want %d", o.Witness, got, tt.size)
				}
			}

			if got := len(Cosigned(outs)); got != 3 {
				t.Errorf("cosigned: got %d, want 3", got)
			}
		})
	}
}

func TestCollectConflict(t *testing.T) {
	tests := []struct {
		name         string
		at           int64 // size the witness has
		old, size    int64
		wantRequests int
		wantConflict int64 // 0 -> want a cosignature
	}{
		{"witness lags", 3, 5, 8, 2, 0},
		{"witness has this checkpoint", 8, 5, 8, 2, 0},
		{"witness behind the expected size of 0", 2, 0, 8, 2, 0},
		{"witness ahead", 8, 5, 6, 1, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			signer, vkey := newLogKey(t)
			l := newTestLog(t, signer, vkey, 8, "a")
			tw, w := newWitness(t, "w1", l)
			advance(t, c, tw, w, l, tt.at)
			before := tw.Requests()
			req := l.request(t, tt.old, tt.size)
			since := time.Now()

			outs := c.Collect(t.Context(), []Witness{w}, req, 0)

			if got := tw.Requests() - before; got != tt.wantRequests {
				t.Errorf("requests: got %d, want %d", got, tt.wantRequests)
			}

			o := outs[0]
			if tt.wantConflict == 0 {
				if o.Err != nil {
					t.Fatalf("got %v, want a cosignature", o.Err)
				}

				checkCosig(t, w, req.Signed, o.Cosig, since)

				if got := tw.Size(l.origin); got != tt.size {
					t.Errorf("witness size: got %d, want %d", got, tt.size)
				}

				return
			}

			var conflict *ConflictError
			if !errors.As(o.Err, &conflict) {
				t.Fatalf("got %v, want a *ConflictError", o.Err)
			}

			if conflict.Size != tt.wantConflict {
				t.Errorf("conflict size: got %d, want %d", conflict.Size, tt.wantConflict)
			}

			if o.Cosig != nil {
				t.Errorf("got a cosignature, want none")
			}
		})
	}
}

func TestCollectErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, c *Client) (Witness, Request)
		want  error // nil -> a plain error with the status code
	}{
		{"forked tree", func(t *testing.T, c *Client) (Witness, Request) {
			signer, vkey := newLogKey(t)
			a := newTestLog(t, signer, vkey, 5, "a")
			b := newTestLog(t, signer, vkey, 8, "b")
			tw, w := newWitness(t, "w1", a)
			advance(t, c, tw, w, a, 5)

			return w, b.request(t, 5, 8)
		}, ErrInconsistent},
		{"unknown origin", func(t *testing.T, _ *Client) (Witness, Request) {
			signer, vkey := newLogKey(t)
			l := newTestLog(t, signer, vkey, 3, "a")
			_, w := newWitness(t, "w1", nil)

			return w, l.request(t, 0, 3)
		}, ErrUnknownLog},
		{"wrong log key", func(t *testing.T, _ *Client) (Witness, Request) {
			signer, vkey := newLogKey(t)
			_, otherVKey := newLogKey(t)
			l := newTestLog(t, signer, vkey, 3, "a")

			tw, w := newWitness(t, "w1", nil)
			if err := tw.AddLog(l.origin, otherVKey); err != nil {
				t.Fatalf("add log: %v", err)
			}

			return w, l.request(t, 0, 3)
		}, ErrBadSignature},
		{"witness down", func(t *testing.T, _ *Client) (Witness, Request) {
			signer, vkey := newLogKey(t)
			l := newTestLog(t, signer, vkey, 3, "a")
			tw, w := newWitness(t, "w1", l)
			tw.SetDown(true)

			return w, l.request(t, 0, 3)
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}
			w, req := tt.setup(t, c)

			o := c.Collect(t.Context(), []Witness{w}, req, 0)[0]

			if o.Cosig != nil {
				t.Errorf("got a cosignature, want none")
			}

			if o.Err == nil {
				t.Fatalf("got no error, want one")
			}

			if !strings.Contains(o.Err.Error(), w.Name) {
				t.Errorf("error %q does not name the witness %s", o.Err, w.Name)
			}

			if tt.want != nil {
				if !errors.Is(o.Err, tt.want) {
					t.Errorf("got %v, want %v", o.Err, tt.want)
				}

				return
			}

			for _, sentinel := range []error{ErrUnknownLog, ErrBadSignature, ErrInconsistent} {
				if errors.Is(o.Err, sentinel) {
					t.Errorf("got %v, want a plain error", o.Err)
				}
			}

			if !strings.Contains(o.Err.Error(), "503") {
				t.Errorf("error %q does not carry the status 503", o.Err)
			}
		})
	}
}

func TestCollectStopAt(t *testing.T) {
	tests := []struct {
		name       string
		down       bool // the two quick witnesses answer 503
		wantSigned int
	}{
		{"quorum met", false, 2},
		{"quorum impossible", true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, vkey := newLogKey(t)
			l := newTestLog(t, signer, vkey, 4, "a")
			tw1, w1 := newWitness(t, "w1", l)
			tw2, w2 := newWitness(t, "w2", l)

			tw1.SetDown(tt.down)
			tw2.SetDown(tt.down)

			slow, arrived, canceled := slowWitness(t)
			ws := []Witness{w1, slow, w2}
			// Let w1 and w2 answer only once the slow witness holds its request
			c := &Client{
				HTTP: &http.Client{Transport: gatedTransport{strings.TrimPrefix(slow.URL, "http://"), arrived}},
			}
			start := time.Now()

			outs := c.Collect(t.Context(), ws, l.request(t, 0, 4), 2)

			if took := time.Since(start); took > time.Second {
				t.Errorf("collect took %v, want well under 1s", took)
			}

			if got := len(Cosigned(outs)); got != tt.wantSigned {
				t.Errorf("cosigned: got %d, want %d", got, tt.wantSigned)
			}

			if outs[1].Witness != "slow" || !errors.Is(outs[1].Err, context.Canceled) {
				t.Errorf("slow outcome: got %s %v, want slow and context.Canceled", outs[1].Witness, outs[1].Err)
			}

			select {
			case <-canceled:
			case <-time.After(2 * time.Second):
				t.Errorf("slow witness request was not canceled")
			}
		})
	}
}

func TestCollectContextDeadline(t *testing.T) {
	signer, vkey := newLogKey(t)
	l := newTestLog(t, signer, vkey, 4, "a")
	tw, w := newWitness(t, "w1", l)
	tw.SetDelay(5 * time.Second)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)

	defer cancel()

	start := time.Now()

	outs := (&Client{}).Collect(ctx, []Witness{w}, l.request(t, 0, 4), 0)

	if took := time.Since(start); took > time.Second {
		t.Errorf("collect took %v, want well under 1s", took)
	}

	if !errors.Is(outs[0].Err, context.DeadlineExceeded) {
		t.Errorf("got %v, want context.DeadlineExceeded", outs[0].Err)
	}

	if got := tw.Size(l.origin); got != 0 {
		t.Errorf("witness size: got %d, want 0", got)
	}
}

func TestAddCheckpointRequest(t *testing.T) {
	signer, vkey := newLogKey(t)
	l := newTestLog(t, signer, vkey, 7, "a")
	req := l.request(t, 3, 7)

	proof, err := req.Proof(3)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}

	var want bytes.Buffer
	want.WriteString("old 3\n")

	for _, h := range proof {
		want.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}

	want.WriteString("\n")
	want.Write(req.Signed)

	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/add-checkpoint" {
			t.Errorf("request: got %s %s, want POST /add-checkpoint", r.Method, r.URL.Path)
		}

		b, _ := io.ReadAll(r.Body)
		got <- b

		http.Error(rw, "", http.StatusUnprocessableEntity)
	}))

	defer srv.Close()

	_, v := newCosigKey(t, "w1")

	_, err = (&Client{}).AddCheckpoint(
		t.Context(),
		Witness{Name: "w1", URL: srv.URL + "/", Verifier: v},
		3,
		proof,
		req.Signed,
	)

	if !errors.Is(err, ErrInconsistent) {
		t.Errorf("got %v, want ErrInconsistent", err)
	}

	if b := <-got; !bytes.Equal(b, want.Bytes()) {
		t.Errorf("body: got %q, want %q", b, want.Bytes())
	}
}

func TestAddCheckpointAnswers(t *testing.T) {
	signer, vkey := newLogKey(t)
	l := newTestLog(t, signer, vkey, 2, "a")
	req := l.request(t, 0, 2)
	other, _ := newCosigKey(t, "w1")

	logV, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("log verifier: %v", err)
	}

	n, err := note.Open(req.Signed, note.VerifierList(logV))
	if err != nil {
		t.Fatalf("open checkpoint: %v", err)
	}

	foreign, err := note.Sign(&note.Note{Text: n.Text}, other)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	foreignLine := foreign[len(n.Text)+1:]

	tests := []struct {
		name        string
		status      int
		contentType string
		body        []byte
		wantSize    int64 // > 0 -> want a *ConflictError with this size
		wantErr     string
	}{
		{"409 with size type", http.StatusConflict, "text/x.tlog.size", []byte("7\n"), 7, ""},
		{"409 with plain type", http.StatusConflict, "text/plain", []byte("12"), 12, ""},
		{"409 without a number", http.StatusConflict, "text/plain", []byte("conflict"), 0, "409 without a size"},
		{"400", http.StatusBadRequest, "text/plain", []byte("old size above checkpoint size"), 0, "status 400"},
		{"200 empty", http.StatusOK, "text/plain", nil, 0, "bad cosignature"},
		{"200 signed by another key", http.StatusOK, "text/plain", foreignLine, 0, "bad cosignature"},
		{"200 garbage", http.StatusOK, "text/plain", []byte("not a signature\n"), 0, "bad cosignature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)

				rw.Header().Set("Content-Type", tt.contentType)
				rw.WriteHeader(tt.status)
				_, _ = rw.Write(tt.body)
			}))
			defer srv.Close()

			_, v := newCosigKey(t, "w1")

			_, err := (&Client{}).AddCheckpoint(
				t.Context(),
				Witness{Name: "w1", URL: srv.URL, Verifier: v},
				0,
				nil,
				req.Signed,
			)
			if err == nil {
				t.Fatalf("got no error, want one")
			}

			var conflict *ConflictError
			if tt.wantSize > 0 {
				if !errors.As(err, &conflict) || conflict.Size != tt.wantSize {
					t.Errorf("got %v, want a conflict at size %d", err, tt.wantSize)
				}

				return
			}

			if errors.As(err, &conflict) {
				t.Errorf("got %v, want no conflict", err)
			}

			if !strings.Contains(err.Error(), tt.wantErr) || !strings.HasPrefix(err.Error(), "witness: w1: ") {
				t.Errorf("got %q, want %q prefixed with the witness name", err, tt.wantErr)
			}
		})
	}
}

func TestCosigned(t *testing.T) {
	a := &wlog.Cosig{Name: "a", Line: "\u2014 a x"}
	c := &wlog.Cosig{Name: "c", Line: "\u2014 c x"}
	outs := []Outcome{
		{Witness: "a", Cosig: a},
		{Witness: "b", Err: errors.New("down")},
		{Witness: "c", Cosig: c},
	}

	got := Cosigned(outs)

	if len(got) != 2 || got[0] != *a || got[1] != *c {
		t.Errorf("got %v, want [%v %v]", got, *a, *c)
	}

	if got := Cosigned(nil); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func BenchmarkCollect(b *testing.B) {
	c := &Client{}
	signer, vkey := newLogKey(b)
	l := newTestLog(b, signer, vkey, 100, "a")

	var ws []Witness

	for _, name := range []string{"w1", "w2", "w3"} {
		tw, w := newWitness(b, name, l)
		advance(b, c, tw, w, l, 100)
		ws = append(ws, w)
	}

	// Re-cosign the size the witnesses already hold, with no proof and a fresh
	// timestamp each time
	req := l.request(b, 100, 100)

	for b.Loop() {
		outs := c.Collect(b.Context(), ws, req, 0)
		if got := len(Cosigned(outs)); got != len(ws) {
			b.Fatalf("cosigned: got %d, want %d: %v", got, len(ws), outs)
		}
	}
}
