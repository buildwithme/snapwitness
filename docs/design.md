# Design

This page is about how the prototype works and why, and about the formats it writes.

In short: after each backup the client appends a state record to a Merkle log. The log is kept next to the repository, on the same storage that isn't trusted. Witnesses in other trust domains cosign each new log size and add a timestamp. Later an auditor without the restic password compares the storage listing, the log and the witnesses, and finds out when the repository lost snapshots, was rolled back or shows two histories.

## Components

- `init` runs once on the client. It creates the log key, the log and the config file, and writes a log-signed checkpoint of size 0.
- `record` runs on the client after each backup. It reads the snapshot list with the restic password, appends a state record and saves a log-signed checkpoint. Only after that it collects the witness cosignatures.
- `audit` runs on any host and needs neither the password nor the log key. It lists `snapshots/` on the storage, replays the log and checks the checkpoint and the witnesses.

The log is two files in `logdir`, next to the repository: `entries`, which is append-only, and `checkpoint` with the newest signed note. The witnesses live in other trust domains. They cosign a checkpoint and add a timestamp, but only if it's consistent with what they saw before.

The client and the auditor share the config. It's the trust anchor and holds the origin, the log public key, the witness keys and URLs, the quorum and the maximum age.

In the code, `internal/config` reads and writes the config file and `internal/state` has the record format and the replay. `internal/wlog` is the log with its checkpoints and cosignatures, `internal/witness` the witness client and the parallel collection, and `internal/restic` the keyed reader and the keyless lister. `internal/app` puts it all together: init, record, audit and the reports.

```mermaid
flowchart LR
    subgraph Client
        R[snapwitness record]
        K[(log.key)]
    end
    subgraph Storage["Storage (not trusted)"]
        REPO["restic repo<br/>snapshots/ ..."]
        LOG["log<br/>entries + checkpoint"]
    end
    subgraph Witnesses["Witnesses (other trust domains)"]
        W1[witness 1]
        W2[witness 2]
    end
    subgraph Auditor["Auditor (no password, no log key)"]
        A[snapwitness audit]
        C[(config)]
    end
    R -->|reads snapshot list| REPO
    R -->|append entry, write checkpoint| LOG
    K -.signs.-> R
    R -->|add-checkpoint| W1
    R -->|add-checkpoint| W2
    A -->|list snapshots/| REPO
    A -->|read| LOG
    A -->|add-checkpoint, old = N| W1
    A -->|add-checkpoint, old = N| W2
    C -.trust anchor.-> A
```

## State record

Each `record` run writes one record. The format is deterministic ASCII text with `\n` line endings:

```text
snapwitness/v0 state
time 2026-10-02T14:02:11Z
tool restic 0.19.1
count 4
set 6d1f0c9a...(64 hex)
+ 9a7f03be...(64 hex)
- 1c22d0e8...(64 hex)
```

- The header comes first, then `time`, `tool`, `count`, `set`, the sorted `+ id` lines and the sorted `- id` lines. The text ends with a newline. There are no trailing spaces and no empty lines.
- `count` is the number of snapshots after this record. `set` is the SHA-256 of `id + "\n"` for every snapshot ID in ascending order. For an empty set it's the hash of empty input.
- `+` lines are the IDs added since the previous record, `-` lines the IDs that were removed.
- The parser refuses anything the writer wouldn't produce. Replay goes through the records in order and checks each one: added IDs must have been absent, removed IDs present, and the count and the set hash have to match. When something fails, the error names the first bad index.
- Every run writes a record, also when nothing changed.

## Log and checkpoint

`entries` keeps each record as a frame: a 4-byte big-endian length, then the record bytes. The file is only ever appended to, and every frame gets an `fsync`. The Merkle tree is the RFC 6962 tree over the records. It's rebuilt in memory every time the log is opened.

`checkpoint` holds the newest signed note. The body is a [C2SP tlog-checkpoint](https://c2sp.org/tlog-checkpoint):

```text
<origin>
<size>
<base64 root hash>
```

The log signs this body, and each witness adds one cosignature line ([C2SP tlog-cosignature](https://c2sp.org/tlog-cosignature)) with its name, a key hash and a timestamp:

```text
— <log name> <base64 signature>
— <witness name> <base64 signature>
```

To replace the file, `record` writes a temporary file, syncs it, renames it and syncs the directory. After a crash you have the old checkpoint or the new one, nothing in between.

`init` already writes a log-signed checkpoint of size 0 (the empty tree). Every log that was set up has one, and a missing checkpoint means the storage lost it.

The stored checkpoint is always the newest one the log signed, because `record` writes it before any witness sees it. On an honest storage no witness can be ahead of it. When a witness has seen a bigger size, that's a `rollback`.

Both files are opened once with `O_NOFOLLOW`, checked to be regular files and read through that same handle. `entries` can be up to 256 MiB and `checkpoint` up to 1 MiB. A file that fails one of these checks, or ends in a torn frame, is reported as `tampered`.

## Witness protocol

Both `record` and `audit` talk to the witnesses with `add-checkpoint` from [C2SP tlog-witness](https://c2sp.org/tlog-witness):

```text
POST <URL>/add-checkpoint
old <old size>
<base64 hash>        (zero or more lines: consistency proof from old size)
<empty line>
<signed checkpoint note>
```

A 200 answer has one or more cosignature lines. With 409 the witness says it has seen a different size and puts that size in the body; the client may retry with that size and a proof. 404 means the witness doesn't know this log, 403 is a bad log signature and 400 a bad request. 422 means the consistency proof doesn't match what the witness saw: the history forked.

What the client does with the answers:

- All witnesses are asked in parallel, one goroutine each. A dead witness costs one timeout, and the timeouts don't add up.
- A 409 with a different size that isn't larger than the checkpoint gets one retry, with that size and the matching proof. Here the witness is just behind, for example because an earlier run stopped before it got to this witness.
- A 409 with a size larger than the checkpoint is never retried. That answer is the evidence of a rollback.
- A 200 answer is parsed strictly. Every line has to be a note signature line ending in a newline; one blank line or anything else and the whole answer is rejected. Each cosignature is checked on its own against the exact checkpoint body that was sent, which means an answer can't move the boundary between the text and the signatures. Lines with other names or keys are skipped. The first valid cosignature from the expected witness is the one used.
- `record` stops once `quorum` witnesses have cosigned and cancels the others.

## Record flow

`record` goes through these steps:

1. Open the log, verify the checkpoint and check the root of the first N entries.
   A missing checkpoint raises `deleted`. More than N entries raise `tampered`, and the entries past the checkpoint are never signed.
2. Send the same checkpoint to the witnesses again, with `old = N`, also when N is 0. This is the rollback probe: a witness either cosigns it or answers with a conflict and a larger size.
   A larger size or a fork raises `rollback` or `fork`, and nothing is written.
3. Run `restic snapshots --json` with the password and diff the list against the replay of the first N entries.
4. If a snapshot was removed and `-accept-removed` isn't given, raise `deleted` and append nothing.
5. Otherwise append record N+1 and sign checkpoint N+1.
   Save this checkpoint right away, with only the log signature on it.
6. Ask the witnesses with `add-checkpoint`, sending `old = N` and the proof.
   Then write the checkpoint again, now with the log and witness lines. Fewer than `quorum` cosignatures raise `quorum`, but the checkpoint stays saved.

N is always the checkpoint size, and `record` replays only those first N entries. If there are more, either the storage added them or an earlier run stopped between its append and its checkpoint write. In both cases no witness has seen them. They raise an alarm and are never signed.

The newest checkpoint is kept also without a quorum. The `quorum` alarm says it's saved, and once the witnesses are back you can run `record` or `audit` again. If the run is cancelled after the quorum was reached, the cosignatures collected so far are kept. Any witness error other than a conflict ends up as a `witness` warning in the report.

## Audit flow

```mermaid
flowchart TD
    A[open log and checkpoint] -->|log or checkpoint missing| X1[ALARM deleted]
    A -->|unreadable: torn frame, not a regular file, too big| X2[ALARM tampered]
    A --> C[verify signatures, origin, size, root of first N entries]
    C -->|fails| X2
    C -->|more than N entries| X2
    C --> D[ask witnesses with old = N, unless -offline<br/>in parallel with: replay first N entries, hash files in snapshots/]
    D -->|witness has larger size| X3[ALARM rollback]
    D -->|proof does not fit| X4[ALARM fork]
    D --> F{fewer than quorum witnesses<br/>newer than maxage,<br/>or newest record too old?}
    F -->|yes| X5[ALARM stale]
    F --> L{listing of snapshots/}
    L -->|directory gone| X1
    L -->|other error| X2
    L --> G{expected vs observed IDs}
    G -->|expected but missing| X6[ALARM deleted]
    G -->|file hash differs, too big, not regular| X2
    G -->|observed but not expected| W2[WARN unrecorded]
    G -->|odd file names, too short| W3[WARN foreign]
    G -->|same| OK[OK, exit 0]
```

If the observed set is the same as the set of an older record, the rollback report names that record (`the storage matches state #i from <time>`).

Damaged storage raises an alarm. That covers a torn frame, a file in `snapshots/` that isn't regular or is over 16 MiB, an unreadable log and a missing `snapshots/` directory. A timeout is an error, but every alarm found until then stays in the report, and the witness answers that did arrive still count. File names that come from the storage are quoted in reports, which keeps terminal escape codes out.

The `clock` warning names the witness whose cosignature is too far in the future.

You can audit several repositories in one go by repeating `-c`. Each config gets its own audit and its own timeout. `-workers` counts per config, and several configs multiply the hashing work. The exit code is 3 if any audit raised an alarm, otherwise 1 if any failed with an error, and 0 if neither happened.

The listing only opens regular files and doesn't follow symlinks. Anything else shows up with its type, like `name (symlink)`. It hashes at most 16 MiB per snapshot file. Real restic snapshot files are just a few KiB.

## Findings

| Finding | Level | Meaning |
|---|---|---|
| `deleted` | alarm | A snapshot in the log is not on the storage, or the log, the checkpoint or the `snapshots/` directory is gone. In `record`, a snapshot disappeared since the last record and `-accept-removed` was not given |
| `rollback` | alarm | A witness has seen a larger log than the storage serves. The storage was probably restored from an older copy |
| `fork` | alarm | A witness holds a history that is not consistent with this log |
| `tampered` | alarm | The log or checkpoint does not verify or cannot be read, the log was truncated, the log has entries past the checkpoint, or a snapshot file does not hash to its name or is not a regular file |
| `stale` | alarm | Too few witnesses cosigned within `maxage`, or no new state was recorded in that time |
| `quorum` | alarm | `record` could not get enough cosignatures. The checkpoint is still saved |
| `unrecorded` | warning | A snapshot is on the storage but not in the log (a backup without `record`) |
| `foreign` | warning | Files in `snapshots/` whose names are not snapshot IDs, or that are too short to be a snapshot |
| `witness` | warning | A witness could not be reached or gave an unusable answer |
| `clock` | warning | A witness cosignature is dated more than 5 minutes in the future, so it does not count as fresh |

## Threats

| Attack by the storage operator | Detected? |
|---|---|
| Delete a snapshot after it was recorded | Yes (`deleted`) |
| Delete the log or the checkpoint, truncate or damage the log | Yes (`deleted`, `tampered`) |
| Add log entries the client never wrote | Yes (`tampered`), and `record` never signs them |
| Roll the repository and the log back to an older copy | Yes, once a witness has seen the newer log (`rollback`). An `-offline` audit sees it only after `maxage` (`stale`) |
| Show different histories to different clients | Yes, if both reach the same witnesses (`fork`) |
| Freeze: hide new snapshots and serve the old state | Yes, after `maxage` (`stale`) |
| Change a snapshot file | Yes (`tampered`) |
| Delete a snapshot before its first record | No |
| Collusion of the operator with enough witnesses | No |
| Attacker who has the client, the restic password and the log key | No |
| Prevent any of the above | No, the tool only detects |

## Decisions

I didn't want to run a server for this. The log is a plain file next to the repository and there's nothing extra to operate. The storage isn't trusted anyway, and every claim in it is checked against the log key and the witnesses.

The log is hand-written. Tessera felt like too much for this, the MVP only needs an append-only list of a few thousand records with proofs, and `golang.org/x/mod/sumdb/tlog` gives the RFC 6962 hashes and proofs without an extra dependency.

The witnesses are in the design from the start. A signed log on the same storage proves nothing against a rollback, because the operator can restore the log together with the repository. Only the witnesses remember the newest size.

`record` saves the log-signed checkpoint before it asks any witness. This keeps the rule simple: a witness that is ahead always means a rollback. The price is a manual repair when a crash hits between the append and the checkpoint write (see [LIMITATIONS.md](../LIMITATIONS.md)).

Every run appends a record, even with no change. Such a record still proves the state at that time, and `stale` depends on it.

The audit doesn't need the password. restic names each file in `snapshots/` after the SHA-256 of its contents, which lets the auditor list the snapshot IDs and check every one by hashing its file. restic 0.19.1 panics on a very short file whose name is its hash. Those files are reported as `foreign` and never given to restic.

I kept the dependencies few: `golang.org/x/mod`, `golang.org/x/sync` and `github.com/transparency-dev/formats` for the cosignature format. Everything else is the standard library.

One config file is the trust anchor. `init` writes the origin, the log public key, the witness keys and the quorum into it, and an auditor with a copy needs nothing else.

## Limits

The known limits are in [LIMITATIONS.md](../LIMITATIONS.md).
