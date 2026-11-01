# Limitations

SnapWitness is a prototype. It only detects problems, it doesn't stop or repair anything, and you learn about a deleted snapshot or a rolled-back repository at the next audit. Please read the rest of this list before you rely on it.

- What never got into the log can't be checked. That's a snapshot deleted before any `record` saw it, and also a backup that was never recorded. The audit warns `unrecorded` about such a snapshot only while its file is still there, which is why `record` should run right after every backup.
- The config file is trusted on first use. It's the trust anchor (origin, log key, witness keys, quorum), and if somebody hands you a different one on the first run, you audit the wrong thing. Its copy belongs next to your restic password, off the storage. The witnesses are trusted as a group too: a storage operator who controls at least `quorum` of them, or every witness you ask, can hide a rollback.
- I assume one writer per log. Nothing locks two `record` runs against each other, and two writers make two histories; a witness will refuse one of them.
  An audit that runs while `record` is writing can show a false rollback alarm or entries past the checkpoint. Run it again before you act on either.
- Crashes aren't repaired automatically. A crash inside `record` can leave entries past the checkpoint or a torn last frame, both `tampered`. Copy the log first. The alarm prints a guarded `truncate` command only when every witness cosigned the checkpoint size; if a witness has seen more, keep the entries. For a torn frame it gives the offset to truncate `entries` to.
- Freshness checks rely on the witness timestamps. An `-offline` audit doesn't ask the witnesses at all, and it sees a rollback only after `maxage`, once the cosignatures it has are too old. The witness clocks are also trusted: a cosignature dated more than 5 minutes in the future is ignored with a `clock` warning, but a witness whose clock is wrong by less than that is believed.
- Only Linux and macOS are supported. The audit opens files with `O_NOFOLLOW` and `O_NONBLOCK`, and Windows has neither.
- It's restic only. The auditor reads `snapshots/` from a local path, for example a mounted or synced copy, and can't read remote backends directly.
- `record -accept-removed` is just a placeholder: it accepts every removal since the last record. There's no separate admin key and no signed "this removal is on purpose" entry. When a snapshot goes away, a `forget` or `prune` you didn't run looks the same as one you did.
- The time in a state record comes from the client's clock. For freshness the audit uses the witness timestamps, because they are the only times that come from someone else.
- A witness has to know the log (origin and log key) before it cosigns anything. `init` prints the litewitness commands to register it. If a witness loses its database, the history it held is gone and the log has to be registered again.
- Opening the log reads and hashes all of it in memory. Thousands of records are fine, millions would be too much. Log and witness signatures are Ed25519 only; post-quantum signatures (ML-DSA) aren't supported.
