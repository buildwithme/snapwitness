# Security policy

Please report security problems privately on GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Don't open a public issue for it.

Tell me what you found, how to reproduce it, and the version or commit. I work on this in my spare time and can't promise a response time, but I'll answer as soon as I've read your report.

I especially want to hear about:

- `audit` staying quiet while a recorded snapshot is missing, the storage was rolled back or the history forked
- `record` or `audit` accepting a forged checkpoint, cosignature or witness answer
- a crash, a hang or unbounded memory use in the state record, log or checkpoint parsers
- a flaw in how the log key or the config is created, stored or read

The attacks in [LIMITATIONS.md](LIMITATIONS.md) are known, for example a snapshot deleted before its first record or witnesses that collude with the storage operator. Problems in restic, litewitness or other tools belong to those projects, please report them there.

The demo script uses a fixed test password on purpose.
