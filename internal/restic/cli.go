// Package restic reads a restic repository two ways. The keyed view runs the
// restic binary with the user's password. The keyless view is whatever the
// storage holds in snapshots/, and an auditor can read it without a
// password.
package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/buildwithme/snapwitness/internal/state"
)

// stderrTail is how many bytes from the end of restic's stderr an error keeps.
const stderrTail = 2 << 10

// Snapshot is the part of `restic snapshots --json` that SnapWitness uses.
type Snapshot struct {
	ID             string    `json:"id"`
	Time           time.Time `json:"time"`
	ProgramVersion string    `json:"program_version"`
}

// CLI runs the restic binary with the user's password environment.
type CLI struct {
	Bin  string // "restic" when empty
	Repo string
	Env  []string // appended to os.Environ()
}

// Snapshots runs `restic snapshots --json --no-lock` and returns the
// snapshots sorted by ID. Any invalid snapshot ID is an error.
func (c *CLI) Snapshots(ctx context.Context) ([]Snapshot, error) {
	bin := c.Bin
	if bin == "" {
		bin = "restic"
	}

	//nolint:gosec // G204: bin and repo are the user's own config, passed as separate args
	cmd := exec.CommandContext(ctx, bin, "-r", c.Repo, "snapshots", "--json", "--no-lock")
	cmd.Env = append(os.Environ(), c.Env...)
	// after a cancel kills restic a child may still hold the pipes open. Stop
	// waiting for them 5s later
	cmd.WaitDelay = 5 * time.Second

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("restic: snapshots: %w", ctxErr)
		}

		tail := stderr.Bytes()
		if len(tail) > stderrTail {
			tail = tail[len(tail)-stderrTail:]
		}

		msg := strings.TrimSpace(string(tail))

		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("restic: snapshots: exit code %d: %q", exitErr.ExitCode(), msg)
		}

		return nil, fmt.Errorf("restic: snapshots: %w", err)
	}

	var snaps []Snapshot
	if err := json.Unmarshal(stdout.Bytes(), &snaps); err != nil {
		return nil, fmt.Errorf("restic: snapshots: decode: %w", err)
	}

	for _, s := range snaps {
		if !state.ValidID(s.ID) {
			return nil, fmt.Errorf("restic: snapshots: bad snapshot id %q", s.ID)
		}
	}

	slices.SortFunc(snaps, func(a, b Snapshot) int { return strings.Compare(a.ID, b.ID) })

	return snaps, nil
}
