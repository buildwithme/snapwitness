// Command snapwitness detects deleted, rolled-back or forked snapshot history
// in a restic repository, with a log on the same storage that independent
// witnesses cosign.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/buildwithme/snapwitness/internal/app"
	"github.com/buildwithme/snapwitness/internal/config"
	"github.com/buildwithme/snapwitness/internal/restic"
	"github.com/buildwithme/snapwitness/internal/witness"
)

// witnessTimeout limits one witness request. A dead witness would hang the
// run otherwise.
const witnessTimeout = 30 * time.Second

const usage = `usage:
  snapwitness init   -c snapwitness.conf -name NAME -repo DIR -log DIR -witness VKEY=URL [-witness ...] -quorum N [-maxage 26h]
  snapwitness record -c snapwitness.conf [-restic restic] [-accept-removed] [-json]
  snapwitness audit  [-c a.conf -c b.conf ...] [-offline] [-workers N] [-timeout 2m] [-json]
  snapwitness version

Add -v to any command for debug output on stderr.
Exit codes: 0 ok, 1 error, 2 usage, 3 alarm.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printf(stderr, "%s", usage)
		return app.ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	defer stop()

	switch cmd, args := args[0], args[1:]; cmd {
	case "init":
		return runInit(args, stdout, stderr)
	case "record":
		return runRecord(ctx, args, stdout, stderr)
	case "audit":
		return runAudit(ctx, args, stdout, stderr)
	case "version":
		printf(stdout, "snapwitness %s\n", version())
		return app.ExitOK
	case "help", "-h", "-help", "--help":
		printf(stdout, "%s", usage)
		return app.ExitOK
	default:
		printf(stderr, "snapwitness: unknown command %q\n%s", cmd, usage)
		return app.ExitUsage
	}
}

func runInit(args []string, stdout, stderr io.Writer) int {
	fs, verbose := newFlags("init", stderr)
	cfgPath := fs.String("c", "snapwitness.conf", "config file to create")
	name := fs.String("name", "", "label inside the log origin: a-z, 0-9 and -")
	repo := fs.String("repo", "", "restic repository `dir`")
	logDir := fs.String("log", "", "log `dir`, on the same storage as the repository")

	var ws witnessFlag
	fs.Var(&ws, "witness", "witness as `VKEY=URL`; repeat for each witness")
	quorum := fs.Int("quorum", 0, "witnesses that must cosign each record")
	maxAge := fs.Duration("maxage", config.DefaultMaxAge, "newest record and quorum cosignatures must be younger")

	if code, ok := parse(fs, verbose, args, stderr); !ok {
		return code
	}

	if *name == "" || *repo == "" || *logDir == "" || len(ws) == 0 || *quorum == 0 {
		printf(stderr, "snapwitness init: -name, -repo, -log, -witness and -quorum are required\n")
		return app.ExitUsage
	}

	_, err := app.Init(app.InitOptions{
		Name:       *name,
		ConfigPath: *cfgPath,
		Repo:       *repo,
		LogDir:     *logDir,
		Witnesses:  ws,
		Quorum:     *quorum,
		MaxAge:     *maxAge,
	}, stdout)
	if err != nil {
		printf(stderr, "snapwitness: %v\n", err)
		return app.ExitError
	}

	return app.ExitOK
}

func runRecord(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, verbose := newFlags("record", stderr)
	cfgPath := fs.String("c", "snapwitness.conf", "config file")
	bin := fs.String("restic", "", "restic binary (default $RESTIC_BIN, else restic)")
	accept := fs.Bool("accept-removed", false, "record removed snapshots as intended")
	asJSON := fs.Bool("json", false, "write the report as JSON")

	if code, ok := parse(fs, verbose, args, stderr); !ok {
		return code
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		printf(stderr, "snapwitness: %v\n", err)
		return app.ExitError
	}

	src := &restic.CLI{Bin: cmp.Or(*bin, os.Getenv("RESTIC_BIN"), "restic"), Repo: cfg.Repo}
	r := app.Record(ctx, cfg, src, newClient(), app.RecordOptions{AcceptRemoved: *accept})

	return max(r.ExitCode(), write(r, *asJSON, stdout, stderr))
}

func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, verbose := newFlags("audit", stderr)

	var cfgPaths listFlag
	fs.Var(&cfgPaths, "c", "config `file`; repeat to audit several (default snapwitness.conf)")
	offline := fs.Bool("offline", false, "do not ask the witnesses, check the stored cosignatures only")
	workers := fs.Int(
		"workers",
		0,
		"files re-hashed at once for each config; configs run in parallel (default GOMAXPROCS)",
	)
	timeout := fs.Duration("timeout", 2*time.Minute, "limit for each audit")
	asJSON := fs.Bool("json", false, "write the reports as JSON")

	if code, ok := parse(fs, verbose, args, stderr); !ok {
		return code
	}

	if len(cfgPaths) == 0 {
		cfgPaths = listFlag{"snapwitness.conf"}
	}

	// worst code wins: alarm (3), then error (1), then ok (0)
	code := app.ExitOK

	var cfgs []*config.Config

	for _, p := range cfgPaths {
		cfg, err := config.Load(p)
		if err != nil {
			printf(stderr, "snapwitness: %v\n", err)

			code = max(code, app.ExitError)

			continue
		}

		cfgs = append(cfgs, cfg)
	}

	opts := app.AuditOptions{Offline: *offline, Workers: *workers}
	for i, r := range app.AuditAll(ctx, cfgs, newClient(), opts, *timeout) {
		if i > 0 && !*asJSON {
			printf(stdout, "\n")
		}

		code = max(code, r.ExitCode(), write(r, *asJSON, stdout, stderr))
	}

	return code
}

func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *bool) {
	fs := flag.NewFlagSet("snapwitness "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	return fs, fs.Bool("v", false, "debug output on stderr")
}

// parse parses args and turns on debug logging for -v. It returns false when
// the command has to stop, with the exit code to use: 0 after -h, 2 on a
// usage error.
func parse(fs *flag.FlagSet, verbose *bool, args []string, stderr io.Writer) (int, bool) {
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return app.ExitOK, false
	}

	if err != nil {
		return app.ExitUsage, false
	}

	if fs.NArg() > 0 {
		printf(stderr, "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return app.ExitUsage, false
	}

	if *verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	return 0, true
}

func write(r *app.Report, asJSON bool, stdout, stderr io.Writer) int {
	var err error
	if asJSON {
		err = r.WriteJSON(stdout)
	} else {
		err = r.WriteText(stdout)
	}

	if err != nil {
		printf(stderr, "snapwitness: write report: %v\n", err)
		return app.ExitError
	}

	return app.ExitOK
}

func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func newClient() *witness.Client {
	return &witness.Client{HTTP: &http.Client{Timeout: witnessTimeout}}
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}

	return "(devel)"
}

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// witnessFlag collects -witness VKEY=URL values.
type witnessFlag []config.Witness

func (w *witnessFlag) String() string { return "" }

func (w *witnessFlag) Set(v string) error {
	// split at the = in front of the URL scheme. The vkey is base64 and can
	// end in = too
	i := strings.Index(v, "=http")
	if i <= 0 {
		return errors.New("want VKEY=URL with an http or https URL")
	}

	vkey := v[:i]
	name, _, _ := strings.Cut(vkey, "+")
	*w = append(*w, config.Witness{Name: name, VKey: vkey, URL: v[i+1:]})

	return nil
}
