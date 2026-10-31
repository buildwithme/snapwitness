#!/usr/bin/env bash
# SnapWitness demo: a real restic repository, two real litewitness processes
# and five cases (clean, delete, unapproved prune, known gap, rollback).
# Needs Go, ssh-agent, ssh-add, ssh-keygen, curl, perl (when bash has no
# EPOCHREALTIME), network access (to download litewitness and the Go toolchain
# it needs), and restic from $RESTIC_BIN or PATH.
# Exits non-zero when any case does not give the expected result.
set -euo pipefail

DEMO=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DEMO/.." && pwd)
BIN=$DEMO/.bin
WORK=$DEMO/.work
TORCHWOOD=v0.10.0
PORT1=7381
PORT2=7382

die() {
	echo "demo: $*" >&2
	exit 1
}

AGENT=''
LW1=''
LW2=''
cleanup() {
	# shellcheck disable=SC2086 # empty pids must vanish
	kill $LW1 $LW2 $AGENT 2>/dev/null || true
	# the witnesses keep writing into the work folder until they exit
	# shellcheck disable=SC2086
	[ -z "$LW1$LW2" ] || wait $LW1 $LW2 2>/dev/null || true
	if [ "${DEMO_CLEAN:-}" = 1 ]; then
		rm -rf "$WORK" "$BIN"
	fi
}
trap cleanup EXIT

for tool in go ssh-agent ssh-keygen ssh-add curl; do
	command -v "$tool" >/dev/null || die "$tool not found in PATH"
done
RESTIC=${RESTIC_BIN:-$(command -v restic || true)}
[ -n "$RESTIC" ] || die "restic not found: set RESTIC_BIN or put restic in PATH"
# we cd around below, so make it absolute
case $RESTIC in
*/*) RESTIC=$(cd "$(dirname "$RESTIC")" && pwd)/$(basename "$RESTIC") ;;
*) RESTIC=$(command -v "$RESTIC") ;;
esac
[ -x "$RESTIC" ] || die "restic at $RESTIC is not executable"

for port in $PORT1 $PORT2; do
	if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
		die "port $port is already in use, stop what listens there first"
	fi
done

now_ms() {
	if [ -n "${EPOCHREALTIME:-}" ]; then
		echo $((${EPOCHREALTIME/./} / 1000))
	else
		perl -MTime::HiRes=time -e 'printf "%d\n", time() * 1000'
	fi
}
START_MS=$(now_ms)

echo "== build"
mkdir -p "$BIN"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$BIN/snapwitness" ./cmd/snapwitness)
if [ ! -x "$BIN/litewitness" ] || [ ! -x "$BIN/witnessctl" ]; then
	# torchwood needs Go 1.27; GOTOOLCHAIN=auto downloads it
	GOBIN=$BIN GOTOOLCHAIN=auto go install \
		"filippo.io/torchwood/cmd/litewitness@$TORCHWOOD" \
		"filippo.io/torchwood/cmd/witnessctl@$TORCHWOOD"
fi
SW=$BIN/snapwitness
"$RESTIC" version
"$SW" version

rm -rf "$WORK"
mkdir -p "$WORK/lw"
# relative paths from here on: macOS limits unix socket paths to 104 bytes
cd "$WORK"

wait_for() { # what command...
	what=$1
	shift
	n=0
	until "$@" >/dev/null 2>&1; do
		n=$((n + 1))
		[ "$n" -lt 200 ] || die "timed out waiting for $what"
		sleep 0.05
	done
}

echo "== witnesses"
ssh-agent -D -a lw/agent.sock >/dev/null 2>&1 &
AGENT=$!
wait_for "ssh-agent socket" test -S lw/agent.sock
for i in 1 2; do
	ssh-keygen -q -t ed25519 -N "" -C "witness-$i" -f "lw/w$i"
	SSH_AUTH_SOCK=lw/agent.sock ssh-add -q "lw/w$i"
done

# Builds UNSET: one env -u per RESTIC_* variable, for the auditor and the
# witnesses. Callers run env themselves because $! of a function started in
# the background points at the subshell.
UNSET=()
restic_unset_args() {
	local v
	UNSET=(-u RESTIC_PASSWORD -u RESTIC_REPOSITORY -u RESTIC_PASSWORD_FILE)
	for v in $(compgen -e); do
		case $v in RESTIC_*) UNSET+=(-u "$v") ;; esac
	done
}

start_witness() { # index port
	fp=$(ssh-keygen -lf "lw/w$1.pub" | awk '{print $2}')
	restic_unset_args
	env "${UNSET[@]}" "$BIN/litewitness" -db "lw/w$1.db" -name "witness-$1.lw.example" -key "$fp" \
		-ssh-agent lw/agent.sock -listen "127.0.0.1:$2" 2>"lw/w$1.log" &
}
vkey_of() { # index
	wait_for "witness-$1 verifier key" grep -q 'verifier key' "lw/w$1.log"
	sed -n 's/.*verifier key.* vkey=\([^ ]*\).*/\1/p' "lw/w$1.log" | tr -d '"' | head -1
}
start_witnesses() {
	start_witness 1 $PORT1
	LW1=$!
	start_witness 2 $PORT2
	LW2=$!
	V1=$(vkey_of 1)
	V2=$(vkey_of 2)
	wait_for "witness-1 on port $PORT1" curl -s -o /dev/null "http://127.0.0.1:$PORT1/"
	wait_for "witness-2 on port $PORT2" curl -s -o /dev/null "http://127.0.0.1:$PORT2/"
}
stop_witnesses() {
	kill "$LW1" "$LW2"
	wait "$LW1" "$LW2" 2>/dev/null || true
	LW1=''
	LW2=''
	wait_for "port $PORT1 to close" port_closed $PORT1
	wait_for "port $PORT2 to close" port_closed $PORT2
}
port_closed() { ! curl -s -o /dev/null "http://127.0.0.1:$1/"; }
start_witnesses
echo "witness-1 $V1"
echo "witness-2 $V2"

# A demo value, not a real password
export RESTIC_PASSWORD=demo-only-password
export RESTIC_CACHE_DIR=$WORK/cache

echo "== init"
mkdir -p storage data
"$RESTIC" -r storage/repo init -q
"$SW" init -c snapwitness.conf -name demo -repo storage/repo -log storage/log \
	-witness "$V1=http://127.0.0.1:$PORT1" -witness "$V2=http://127.0.0.1:$PORT2" -quorum 2
ORIGIN=$(awk '$1 == "origin" {print $2}' snapwitness.conf)
LOGKEY=$(awk '$1 == "logkey" {print $2}' snapwitness.conf)
[ -n "$ORIGIN" ] && [ -n "$LOGKEY" ] || die "origin or logkey missing from snapwitness.conf"
for i in 1 2; do
	"$BIN/witnessctl" add-log -db "lw/w$i.db" -origin "$ORIGIN"
	"$BIN/witnessctl" add-key -db "lw/w$i.db" -origin "$ORIGIN" -key "$LOGKEY"
done
# Restart so both witnesses are sure to pick up the new log
stop_witnesses
start_witnesses
echo "--- snapwitness.conf"
cat snapwitness.conf

auditor() {
	restic_unset_args
	env "${UNSET[@]}" "$@"
}

ROWS=''
FAILED=0
OUT=''
# Run one checked command and print it with its output and time, then add a table row
step() { # case expected-exit command...
	label=$1
	want=$2
	shift 2
	echo "\$ $*"
	t0=$(now_ms)
	set +e
	OUT=$("$@" 2>&1)
	code=$?
	set -e
	t1=$(now_ms)
	printf '%s\n' "$OUT"
	echo "-> exit $code, want $want ($((t1 - t0)) ms)"
	got=$(printf '%s\n' "$OUT" | sed -n 's/^result: *\([A-Za-z]*\).*/\1/p' | tail -1)
	[ -n "$got" ] || got=-
	mark=''
	if [ "$code" != "$want" ]; then
		mark='  <- differs'
		FAILED=$((FAILED + 1))
	fi
	ROWS="$ROWS$(printf '%-34s %-10s %-8s %s%s' "$label" "$(meaning "$want")" "$got" "$code" "$mark")
"
}
meaning() {
	case $1 in
	0) echo "0 ok" ;;
	3) echo "3 alarm" ;;
	*) echo "$1" ;;
	esac
}

backup() { # n
	echo "backup $1 $(date -u +%FT%TZ)" >"data/file$1.txt"
	echo "\$ restic backup data"
	"$RESTIC" -r storage/repo backup data --host demo -q
}
record() { # case expected-exit
	step "$1" "$2" "$SW" record -c snapwitness.conf -restic "$RESTIC"
}
audit() { # case expected-exit
	step "$1" "$2" auditor "$SW" audit -c snapwitness.conf
}
restore_p3() {
	echo "\$ restore storage from P3"
	rm -rf storage
	cp -Rp p3 storage
}

echo
echo "== case 1: clean"
echo "RESTIC variables the auditor sees: $(auditor sh -c 'env | grep -c RESTIC || true')"
for n in 1 2 3; do
	backup "$n"
	record "1 clean: record $n" 0
done
audit "1 clean: audit" 0
cp -Rp storage p3

echo
echo "== case 2: delete"
set -- storage/repo/snapshots/*
echo "\$ rm $1"
rm -f "$1"
audit "2 delete: audit" 3
restore_p3
audit "2 delete: audit after restore" 0

echo
echo "== case 3: unapproved prune"
echo "\$ restic forget --keep-last 1"
"$RESTIC" -r storage/repo forget --keep-last 1 -q
audit "3 prune: audit" 3
record "3 prune: record" 3
restore_p3

echo
echo "== case 4: known gap"
ls storage/repo/snapshots >before.txt
backup 4
ls storage/repo/snapshots >after.txt
fresh=$(comm -13 before.txt after.txt)
[ -n "$fresh" ] || die "no new snapshot file after the backup"
echo "\$ rm storage/repo/snapshots/$fresh  (never recorded)"
rm -f "storage/repo/snapshots/$fresh"
audit "4 known gap: audit" 0
restore_p3

echo
echo "== case 5: rollback"
for n in 5 6; do
	backup "$n"
	record "5 rollback: record $n" 0
done
restore_p3
audit "5 rollback: audit" 3
if ! printf '%s\n' "$OUT" | grep -q 'ALARM rollback' || ! printf '%s\n' "$OUT" | grep -q 'seen'; then
	echo "-> the output does not name the witness conflict"
	ROWS="$ROWS$(printf '%-34s %-10s %-8s %s  <- differs' "5 rollback: names conflict" "yes" "no" "-")
"
	FAILED=$((FAILED + 1))
fi

echo
echo "== result ($((($(now_ms) - START_MS) / 1000)) s)"
printf '%-34s %-10s %-8s %s\n' case expected got exit
printf '%s' "$ROWS"
if [ "$FAILED" -gt 0 ]; then
	echo "$FAILED step(s) differ from what is expected"
	exit 1
fi
echo "all cases as expected"
