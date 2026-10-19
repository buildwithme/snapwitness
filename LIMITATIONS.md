# Limitations

SnapWitness is a prototype. It only detects problems, it doesn't stop or repair anything, and you learn about a deleted snapshot or a rolled-back repository at the next audit. Please read the rest of this list before you rely on it.

- What never got into the log can't be checked. That's a snapshot deleted before any `record` saw it, and also a backup that was never recorded. The audit warns `unrecorded` about such a snapshot only while its file is still there, which is why `record` should run right after every backup.
- The config file is trusted on first use. It's the trust anchor (origin, log key, witness keys, quorum), and if somebody hands you a different one on the first run, you audit the wrong thing. Its copy belongs next to your restic password, off the storage. The witnesses are trusted as a group too: a storage operator who controls at least `quorum` of them, or every witness you ask, can hide a rollback.
- I assume one writer per log. Nothing locks two `record` runs against each other, and two writers make two histories; a witness will refuse one of them.
- It's restic only. The auditor reads `snapshots/` from a local path, for example a mounted or synced copy, and can't read remote backends directly yet.
- `record -accept-removed` is just a placeholder: it accepts every removal since the last record. There's no separate admin key yet and no signed "this removal is on purpose" entry. When a snapshot goes away, a `forget` or `prune` you didn't run looks the same as one you did.
- The time in a state record comes from the client's clock. For freshness the audit uses the witness timestamps, because they are the only times that come from someone else.
- A witness has to know the log (origin and log key) before it cosigns anything. `init` prints the litewitness commands to register it. If a witness loses its database, the history it held is gone and the log has to be registered again.
- Opening the log reads and hashes all of it in memory. Thousands of records are fine, millions would be too much. Signatures are Ed25519 only, and post-quantum ML-DSA isn't supported yet.
