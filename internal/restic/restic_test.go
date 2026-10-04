package restic

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRestic writes a fake restic script. It saves its arguments to argsFile,
// one per line, then runs body.
func fakeRestic(t *testing.T, body string) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "restic")
	argsFile = filepath.Join(dir, "args")

	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > " + argsFile + "\n" + body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	return bin, argsFile
}

func hexID(n int) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(n))))
}

func TestSnapshots(t *testing.T) {
	a, b := hexID(1), hexID(2)
	if a < b {
		a, b = b, a
	}

	out := fmt.Sprintf(
		`[{"id":%q,"time":"2026-10-01T10:00:00.123+02:00","program_version":"restic 0.19.1","hostname":"h"},`+
			`{"id":%q,"time":"2026-10-01T11:00:00Z","program_version":"restic 0.19.1"}]`,
		a,
		b,
	)
	bin, argsFile := fakeRestic(t, "printf '%s' '"+out+"'")

	c := &CLI{Bin: bin, Repo: "/repo path", Env: []string{"RESTIC_PASSWORD=x"}}

	snaps, err := c.Snapshots(t.Context())
	if err != nil {
		t.Fatalf("snapshots: %v", err)
	}

	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(args), "-r\n/repo path\nsnapshots\n--json\n--no-lock\n"; got != want {
		t.Fatalf("args: got %q, want %q", got, want)
	}

	if len(snaps) != 2 || snaps[0].ID != b || snaps[1].ID != a {
		t.Fatalf("got %+v, want ids %s then %s", snaps, b, a)
	}

	if snaps[0].ProgramVersion != "restic 0.19.1" || snaps[0].Time.Hour() != 11 {
		t.Fatalf("got %+v, want version and time decoded", snaps[0])
	}
}

func TestSnapshotsEnv(t *testing.T) {
	bin, _ := fakeRestic(t, `printf '[{"id":"%s"}]' "$SNAP_ID"`)
	c := &CLI{Bin: bin, Repo: "r", Env: []string{"SNAP_ID=" + hexID(7)}}

	snaps, err := c.Snapshots(t.Context())
	if err != nil {
		t.Fatalf("snapshots: %v", err)
	}

	if len(snaps) != 1 || snaps[0].ID != hexID(7) {
		t.Fatalf("got %+v, want one snapshot %s from Env", snaps, hexID(7))
	}
}

func TestSnapshotsEmpty(t *testing.T) {
	bin, _ := fakeRestic(t, "echo '[]'")

	snaps, err := (&CLI{Bin: bin, Repo: "r"}).Snapshots(t.Context())
	if err != nil || len(snaps) != 0 {
		t.Fatalf("got %v, %v, want no snapshots and no error", snaps, err)
	}
}

func TestSnapshotsErrors(t *testing.T) {
	long := strings.Repeat("x", 3000)
	tests := []struct {
		name    string
		body    string
		wantErr string
		notErr  string
	}{
		{"bad id", `echo '[{"id":"ABC"}]'`, `bad snapshot id "ABC"`, ""},
		{"uppercase id", `echo '[{"id":"` + strings.ToUpper(hexID(1)) + `"}]'`, "bad snapshot id", ""},
		{"not json", "echo 'Fatal: nope'", "decode", ""},
		{
			"exit 1", "echo 'Fatal: wrong password or no key found' >&2; exit 1",
			"exit code 1: Fatal: wrong password or no key found", "",
		},
		{
			"stderr tail",
			"printf 'HEAD%sTAIL' " + long + " >&2; exit 3",
			"exit code 3: " + strings.Repeat("x", 2044) + "TAIL",
			"HEAD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, _ := fakeRestic(t, tt.body)

			_, err := (&CLI{Bin: bin, Repo: "r"}).Snapshots(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}

			if tt.notErr != "" && strings.Contains(err.Error(), tt.notErr) {
				t.Fatalf("got %v, want no %q (only the last 2 KiB of stderr)", err, tt.notErr)
			}
		})
	}
}

func TestSnapshotsMissingBinary(t *testing.T) {
	c := &CLI{Bin: filepath.Join(t.TempDir(), "nope"), Repo: "r"}
	if _, err := c.Snapshots(t.Context()); err == nil {
		t.Fatal("got nil, want error for a missing binary")
	}
}
