package witness

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
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
