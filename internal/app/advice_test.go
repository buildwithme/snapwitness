package app

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/buildwithme/snapwitness/internal/witness"
	"github.com/buildwithme/snapwitness/internal/wlog"
)

func TestShellQuote(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"plain", "it's", "'", "a b", "$HOME", "`id`", "*", "tab\there", "line\nbreak"} {
		out, err := exec.Command("sh", "-c", "printf %s "+shellQuote(s)).Output()
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}

		if string(out) != s {
			t.Errorf("shellQuote(%q): sh gave back %q", s, out)
		}
	}
}

func TestEveryWitnessCosigned(t *testing.T) {
	t.Parallel()

	ws := make([]witness.Witness, 2)
	cosig := &wlog.Cosig{}
	both := []witness.Outcome{{Cosig: cosig}, {Cosig: cosig}}
	one := []witness.Outcome{{Cosig: cosig}, {Err: errors.New("down")}}
	tests := []struct {
		name   string
		ctxErr error
		outs   []witness.Outcome
		want   bool
	}{
		{"every witness cosigned", nil, both, true},
		{"cut short by the timeout", context.DeadlineExceeded, both, false},
		{"one witness down", nil, one, false},
		{"offline, no answers", nil, nil, false},
	}

	for _, tt := range tests {
		if got := everyWitnessCosigned(tt.ctxErr, tt.outs, ws); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
