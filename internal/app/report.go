// Package app has the snapwitness commands. Init creates the trust anchor
// and the log, Record appends what restic shows after a backup and gets it
// witnessed, and Audit checks the storage against the log and the witnesses.
package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/buildwithme/snapwitness/internal/state"
)

// Severity is how bad a finding is.
type Severity int

// Severities from harmless to proof of a problem.
const (
	Info Severity = iota
	Warn
	Alarm
)

// String returns "INFO", "WARN" or "ALARM".
func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Alarm:
		return "ALARM"
	}

	return fmt.Sprintf("Severity(%d)", int(s))
}

// MarshalText writes the severity name. JSON reports say "ALARM" that way.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// Finding is one result line of a check.
type Finding struct {
	Severity Severity `json:"severity"`
	Kind     string   `json:"kind"` // deleted, rollback, fork, stale, tampered, unrecorded, foreign, witness, pending, quorum
	Message  string   `json:"message"`
	Details  []string `json:"details,omitempty"`
}

// WitnessStatus is one witness line in a report.
type WitnessStatus struct {
	Name   string        `json:"name"`
	Status string        `json:"status"` // "cosigned", "conflict", "unreachable", "error", "skipped"
	Size   int64         `json:"size,omitempty"`
	Time   time.Time     `json:"time"`
	Took   time.Duration `json:"took_ns,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// Report is the result of one record or audit run.
type Report struct {
	Command   string          `json:"command"` // "record" or "audit"
	Config    string          `json:"config"`
	Origin    string          `json:"origin"`
	LogSize   int64           `json:"log_size"`
	Snapshots int             `json:"snapshots"`
	Lines     []string        `json:"lines,omitempty"` // header facts, already formatted
	Witnesses []WitnessStatus `json:"witnesses,omitempty"`
	Findings  []Finding       `json:"findings,omitempty"`
	Took      time.Duration   `json:"took_ns"`
	Err       string          `json:"error,omitempty"` // the check could not finish
}

// Process exit codes. ExitAlarm means the check finished and found an alarm.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
	ExitAlarm = 3
)

// Add appends a finding to the report.
func (r *Report) Add(sev Severity, kind, msg string, details ...string) {
	r.Findings = append(r.Findings, Finding{Severity: sev, Kind: kind, Message: msg, Details: details})
}

// Worst returns the highest severity of the findings, Info if there are none.
func (r *Report) Worst() Severity {
	worst := Info
	for _, f := range r.Findings {
		worst = max(worst, f.Severity)
	}

	return worst
}

// ExitCode returns ExitAlarm when the report has an alarm, ExitError when the
// check couldn't finish, and ExitOK otherwise. The alarm wins over the error,
// here and across several audits: only an alarm proves a problem.
func (r *Report) ExitCode() int {
	switch {
	case r.Worst() == Alarm:
		return ExitAlarm
	case r.Err != "":
		return ExitError
	}

	return ExitOK
}

// WriteText writes the report for people: header facts and witness lines,
// then the findings and the result line.
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "snapwitness %s  origin=%s\n", r.Command, r.Origin)

	for _, l := range r.Lines {
		fmt.Fprintf(&b, "  %s\n", l)
	}

	for _, ws := range r.Witnesses {
		fmt.Fprintf(&b, "  %-10s %s  %s", "witness", ws.Name, ws.describe())

		if ws.Took > 0 {
			fmt.Fprintf(&b, "  (%s)", short(ws.Took))
		}

		b.WriteString("\n")
	}

	var alarms, warns int

	for _, f := range r.Findings {
		switch f.Severity {
		case Alarm:
			alarms++
		case Warn:
			warns++
		}

		fmt.Fprintf(&b, "%s %s: %s\n", f.Severity, f.Kind, f.Message)

		for _, d := range f.Details {
			fmt.Fprintf(&b, "      %s\n", d)
		}
	}

	if r.Err != "" {
		fmt.Fprintf(&b, "error: %s\n", r.Err)
	}

	fmt.Fprintf(
		&b,
		"result: %s  (%s, %s, %s)\n",
		r.result(),
		plural(alarms, "alarm"),
		plural(warns, "warning"),
		short(r.Took),
	)
	_, err := io.WriteString(w, b.String())

	return err
}

// WriteJSON writes the report as JSON with a two-space indent.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(r)
}

func (r *Report) result() string {
	switch r.ExitCode() {
	case ExitAlarm:
		return "ALARM"
	case ExitError:
		return "ERROR"
	}

	if r.Worst() == Warn {
		return "WARN"
	}

	return "OK"
}

func (ws WitnessStatus) describe() string {
	switch ws.Status {
	case "cosigned":
		return fmt.Sprintf("cosigned size %d at %s", ws.Size, ws.Time.Format(state.TimeFormat))
	case "conflict":
		return fmt.Sprintf("conflict: has seen size %d", ws.Size)
	case "skipped":
		if !ws.Time.IsZero() {
			return "skipped, last cosigned at " + ws.Time.Format(state.TimeFormat)
		}

		return "skipped"
	}

	return ws.Status + ": " + ws.Error
}

func short(d time.Duration) time.Duration {
	if d < time.Millisecond {
		return d.Round(time.Microsecond)
	}

	return d.Round(time.Millisecond)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}

	return fmt.Sprintf("%d %ss", n, word)
}
