# SnapWitness

SnapWitness watches a restic repository that sits on storage you don't trust. It tells you when snapshots went missing, when the repository was rolled back, or when it shows two different histories. It only finds this afterwards, it can't prevent it.

This is a prototype. It works only with restic, and the repository has to be on a local path. The limits are in [LIMITATIONS.md](LIMITATIONS.md).

## The problem

Backup tools encrypt and authenticate your data. What they don't prove is that the set of snapshots you get back is complete and current.

Whoever controls the storage, the operator or anybody else, can:

- delete a snapshot,
- roll the whole repository back to an older state,
- show different snapshot lists to different clients (a "fork"),
- hide new snapshots (a "freeze").

restic's own design document says it directly: "Restic is not designed to detect this attack." ([design.rst](https://github.com/restic/restic/blob/master/doc/design.rst))

Append-only modes and S3 Object Lock help when the client gets hacked. Against a dishonest storage operator they don't help, and the client gets no proof of anything.

## Quick start

```sh
make demo
```

The demo runs five cases against real restic and two real witnesses (litewitness): a clean repository, a deleted snapshot, a prune nobody approved, a known gap and a rollback. You see every command with its output, and at the end a table with the results.

You need Go, `ssh-agent`, `ssh-add`, `ssh-keygen`, `curl`, restic (from `$RESTIC_BIN` or `PATH`) and `perl` if your bash has no `EPOCHREALTIME`. It also needs network access to download litewitness and the Go toolchain litewitness needs. The script is [demo/demo.sh](demo/demo.sh).

The files it makes stay in `demo/.work` and `demo/.bin` for you to look at. `DEMO_CLEAN=1 make demo` deletes them at the end.

## Commands

```text
snapwitness init   -c snapwitness.conf -name demo -repo DIR -log DIR -witness VKEY=URL [-witness ...] -quorum N [-maxage 26h]
snapwitness record -c snapwitness.conf [-restic restic] [-accept-removed] [-json]
snapwitness audit  [-c a.conf -c b.conf ...] [-offline] [-workers N] [-timeout 2m] [-json]
snapwitness version
```

- `init` creates the log key, the log and the config file. The config is the trust anchor: keep a copy of it next to your restic password.
- `record` runs after every backup. It reads the snapshot list (this needs the restic password), appends a state record to the log and asks the witnesses to cosign the new checkpoint.
- `audit` can run on any machine. It doesn't need the restic password or the log signing key. It compares what is on the storage with the log and with the witnesses.

Every command takes `-v` for debug output on stderr.

Exit codes: 0 ok, 1 error, 2 usage, 3 alarm.

## How it works

After each backup, `record` appends a state record to a Merkle log that is stored next to the repository. A record has the snapshot IDs added and removed since the previous one, and a hash of the whole set.

The log is signed with a key that stays on the client. Witnesses in other trust domains cosign every new log size and add a timestamp ([C2SP tlog-witness](https://c2sp.org/tlog-witness)). A witness won't cosign a checkpoint that doesn't fit with what it has seen before.

`audit` lists `snapshots/` on the storage without the password. It only needs the file names and a hash of each file. Then it replays the log and checks the witness cosignatures and how old they are.

If a snapshot is in the log but missing on the storage, you get an alarm. Same when the storage serves a smaller log than a witness has already seen.

The details, formats and diagrams are in [docs/design.md](docs/design.md).

## Limits

A snapshot that was deleted before it was ever recorded is invisible to SnapWitness. It trusts the first config you give it, and there's no separate key for authorised removals. [LIMITATIONS.md](LIMITATIONS.md) has the full list.

## Security

Please report vulnerabilities privately. [SECURITY.md](SECURITY.md) explains how.

## License

Apache-2.0. See [LICENSE](LICENSE).
