package app

import (
	"os/exec"
	"testing"
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
