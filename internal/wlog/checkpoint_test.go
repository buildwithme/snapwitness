package wlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const testOrigin = "example.com/log"

func newLogKey(t testing.TB) (note.Signer, note.Verifier) {
	t.Helper()

	skey, vkey, err := note.GenerateKey(rand.Reader, testOrigin)
	if err != nil {
		t.Fatal(err)
	}

	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}

	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}

	return s, v
}

func newWitness(t testing.TB, name string) (note.Signer, note.Verifier) {
	t.Helper()

	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}

	s, err := fnote.NewSignerForCosignatureV1(skey)
	if err != nil {
		t.Fatal(err)
	}

	v, err := fnote.NewVerifierForCosignatureV1(vkey)
	if err != nil {
		t.Fatal(err)
	}

	return s, v
}

// fixedCosigner signs cosignature/v1 with a chosen timestamp, for tests that
// need two cosignatures from one witness at different times.
type fixedCosigner struct {
	name string
	hash uint32
	key  ed25519.PrivateKey
	at   time.Time
}

func (s fixedCosigner) Name() string    { return s.name }
func (s fixedCosigner) KeyHash() uint32 { return s.hash }

func (s fixedCosigner) Sign(msg []byte) ([]byte, error) {
	ts := uint64(s.at.Unix())
	m := fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", ts, msg)

	return append(binary.BigEndian.AppendUint64(nil, ts), ed25519.Sign(s.key, m)...), nil
}

// newFixedWitness returns a witness verifier and a function that makes its
// signer for a given time.
func newFixedWitness(t testing.TB, name string) (func(time.Time) note.Signer, note.Verifier) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	vkey, err := note.NewEd25519VerifierKey(name, pub)
	if err != nil {
		t.Fatal(err)
	}

	v, err := fnote.NewVerifierForCosignatureV1(vkey)
	if err != nil {
		t.Fatal(err)
	}

	return func(at time.Time) note.Signer { return fixedCosigner{name, v.KeyHash(), priv, at} }, v
}

// cosign returns the signature line of s over the checkpoint body, as a witness
// sends it.
func cosign(t testing.TB, c Checkpoint, s note.Signer) string {
	t.Helper()

	signed, err := note.Sign(&note.Note{Text: string(c.Body())}, s)
	if err != nil {
		t.Fatal(err)
	}

	_, sigs, _ := bytes.Cut(signed, []byte("\n\n"))

	return strings.TrimSuffix(string(sigs), "\n")
}

func withLines(signed []byte, lines ...string) []byte {
	out := bytes.Clone(signed)
	for _, l := range lines {
		out = append(out, l+"\n"...)
	}

	return out
}

func testCheckpoint() Checkpoint {
	return Checkpoint{Origin: testOrigin, Size: 5, Root: tlog.RecordHash([]byte("root"))}
}

func TestCheckpointBody(t *testing.T) {
	c := Checkpoint{Origin: testOrigin, Size: 3}

	want := testOrigin + "\n3\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	if got := string(c.Body()); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	tests := []Checkpoint{
		{Origin: testOrigin, Size: 0, Root: mth(nil)},
		testCheckpoint(),
		{Origin: "o", Size: math.MaxInt64, Root: tlog.RecordHash([]byte("x"))},
	}
	for _, c := range tests {
		t.Run(fmt.Sprint(c.Size), func(t *testing.T) {
			got, err := ParseCheckpoint(c.Body())
			if err != nil {
				t.Fatal(err)
			}

			if got != c {
				t.Errorf("got %+v, want %+v", got, c)
			}
		})
	}
}

func TestParseCheckpointRejects(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, tlog.HashSize))
	tests := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"extra line", "o\n1\n" + root + "\nextension\n"},
		{"missing final newline", "o\n1\n" + root},
		{"empty origin", "\n1\n" + root + "\n"},
		{"leading zero", "o\n007\n" + root + "\n"},
		{"negative size", "o\n-1\n" + root + "\n"},
		{"plus sign", "o\n+1\n" + root + "\n"},
		{"empty size", "o\n\n" + root + "\n"},
		{"size overflow", "o\n9223372036854775808\n" + root + "\n"},
		{"carriage return", "o\n1\r\n" + root + "\n"},
		{"bad base64", "o\n1\n!!!!\n"},
		{"short root", "o\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, tlog.HashSize-1)) + "\n"},
		{"long root", "o\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, tlog.HashSize+1)) + "\n"},
		{"unpadded root", "o\n1\n" + strings.TrimSuffix(root, "=") + "\n"},
		{"non-canonical root", "o\n1\n" + root[:42] + "B=\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if c, err := ParseCheckpoint([]byte(tt.body)); err == nil {
				t.Errorf("got %+v, want an error", c)
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	s, v := newLogKey(t)
	c := testCheckpoint()

	signed, err := Sign(c, s)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(signed, v, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got.Checkpoint != c {
		t.Errorf("got %+v, want %+v", got.Checkpoint, c)
	}

	if !bytes.Equal(got.Signed, signed) {
		t.Errorf("got signed %q, want %q", got.Signed, signed)
	}

	if len(got.Cosigs) != 0 {
		t.Errorf("got %d cosignatures, want 0", len(got.Cosigs))
	}
}

func TestSignRejects(t *testing.T) {
	s, _ := newLogKey(t)
	tests := []struct {
		name string
		c    Checkpoint
	}{
		{"other origin", Checkpoint{Origin: "other.example/log", Size: 1}},
		{"negative size", Checkpoint{Origin: testOrigin, Size: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Sign(tt.c, s); err == nil {
				t.Error("got nil error, want one")
			}
		})
	}
}

func TestVerifyCosigs(t *testing.T) {
	s, v := newLogKey(t)
	c := testCheckpoint()

	signed, err := Sign(c, s)
	if err != nil {
		t.Fatal(err)
	}

	before := time.Now().Truncate(time.Second)
	names := []string{"witness.a", "witness.b", "witness.c"}

	var (
		lines []string
		known []note.Verifier
	)

	for _, name := range names {
		ws, wv := newWitness(t, name)
		lines = append(lines, cosign(t, c, ws))
		known = append(known, wv)
	}

	after := time.Now()
	stranger, _ := newWitness(t, "witness.unknown")
	msg := withLines(signed, lines[0], cosign(t, c, stranger), lines[1], lines[2])

	got, err := Verify(msg, v, known)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Signed, signed) {
		t.Errorf("got signed %q, want %q", got.Signed, signed)
	}

	if len(got.Cosigs) != len(names) {
		t.Fatalf("got %d cosignatures, want %d", len(got.Cosigs), len(names))
	}

	for i, cs := range got.Cosigs {
		if cs.Name != names[i] || cs.Line != lines[i] {
			t.Errorf("cosignature %d: got %s %q, want %s %q", i, cs.Name, cs.Line, names[i], lines[i])
		}

		if cs.Time.Before(before) || cs.Time.After(after) || cs.Time.Location() != time.UTC {
			t.Errorf("cosignature %d: got time %v, want UTC between %v and %v", i, cs.Time, before, after)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	s, v := newLogKey(t)
	ws, wv := newWitness(t, "witness.a")
	impostor, _ := newLogKey(t)
	c := testCheckpoint()

	signed, err := Sign(c, s)
	if err != nil {
		t.Fatal(err)
	}

	signNote := func(text string, signers ...note.Signer) []byte {
		t.Helper()

		b, err := note.Sign(&note.Note{Text: text}, signers...)
		if err != nil {
			t.Fatal(err)
		}

		return b
	}
	other := c
	other.Origin = "other.example/log"
	moved := c
	moved.Size++

	tests := []struct {
		name   string
		signed []byte
		want   string
	}{
		{"wrong origin", signNote(string(other.Body()), s), "origin"},
		{"missing log signature", signNote(string(c.Body()), ws), "no signature from the log key"},
		{"tampered body", bytes.Replace(signed, []byte("\n5\n"), []byte("\n6\n"), 1), "invalid signature"},
		{"only unknown signatures", signNote(string(c.Body()), impostor), "no verifiable signatures"},
		{"bad cosignature", withLines(signed, cosign(t, moved, ws)), "invalid signature"},
		{"extension line", signNote(string(c.Body())+"ext\n", s), "parse checkpoint"},
		{"not a note", []byte("hello\n"), "malformed note"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.signed, v, []note.Verifier{wv})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error with %q", err, tt.want)
			}
		})
	}
}

func TestAttach(t *testing.T) {
	s, v := newLogKey(t)
	c := testCheckpoint()

	signed, err := Sign(c, s)
	if err != nil {
		t.Fatal(err)
	}

	signA, va := newFixedWitness(t, "witness.a")
	signB, vb := newFixedWitness(t, "witness.b")
	t1 := time.Unix(1_800_000_000, 0).UTC()
	t2 := t1.Add(time.Hour)
	oldA := Cosig{Name: "witness.a", Time: t1, Line: cosign(t, c, signA(t1))}
	newA := Cosig{Name: "witness.a", Time: t2, Line: cosign(t, c, signA(t2))}
	b := Cosig{Name: "witness.b", Time: t1, Line: cosign(t, c, signB(t1))}

	tests := []struct {
		name   string
		cosigs []Cosig
	}{
		{"old first", []Cosig{b, oldA, newA}},
		{"new first", []Cosig{newA, b, oldA}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keep := bytes.Clone(signed)
			out := Attach(signed, tt.cosigs)

			if !bytes.Equal(signed, keep) {
				t.Fatal("Attach changed its input")
			}

			if want := withLines(signed, newA.Line, b.Line); !bytes.Equal(out, want) {
				t.Errorf("got %q, want %q", out, want)
			}

			got, err := Verify(out, v, []note.Verifier{vb, va})
			if err != nil {
				t.Fatal(err)
			}

			want := []Cosig{newA, b}
			if len(got.Cosigs) != len(want) {
				t.Fatalf("got %d cosignatures, want %d", len(got.Cosigs), len(want))
			}

			for i, cs := range got.Cosigs {
				if cs.Name != want[i].Name || !cs.Time.Equal(want[i].Time) || cs.Line != want[i].Line {
					t.Errorf("cosignature %d: got %+v, want %+v", i, cs, want[i])
				}
			}

			if !bytes.Equal(got.Signed, signed) {
				t.Errorf("got signed %q, want %q", got.Signed, signed)
			}
		})
	}

	if got := Attach(signed, nil); !bytes.Equal(got, signed) {
		t.Errorf("no cosignatures: got %q, want %q", got, signed)
	}
}

func BenchmarkVerify(b *testing.B) {
	s, v := newLogKey(b)
	c := testCheckpoint()

	signed, err := Sign(c, s)
	if err != nil {
		b.Fatal(err)
	}

	var (
		lines []string
		known []note.Verifier
	)

	for i := range 3 {
		ws, wv := newWitness(b, fmt.Sprintf("witness.%d", i))
		lines = append(lines, cosign(b, c, ws))
		known = append(known, wv)
	}

	n := withLines(signed, lines...)
	for b.Loop() {
		if _, err := Verify(n, v, known); err != nil {
			b.Fatal(err)
		}
	}
}
