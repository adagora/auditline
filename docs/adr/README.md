# Architecture decision records

## Policy
Write an ADR only for a non-trivial architectural decision. It qualifies if it is hard to reverse, affects module boundaries, data formats, security posture or external contracts, or a reasonable engineer would challenge it.

Not an ADR: bug fixes, flag tweaks, naming, dependency bumps, tuning. Put those in the commit message.

Format: Nygard (Status, Context, Decision, Consequences), at most ~40 lines, file `NNNN-kebab-title.md`. Accepted ADRs are never edited except their status. To change a decision, write a new ADR that supersedes the old one and mark the old one `Superseded by NNNN`.
