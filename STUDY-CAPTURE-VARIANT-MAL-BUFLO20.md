# MAL BuFLO 20 ms capture source snapshot

This branch preserves the source snapshot used to build the MAL BuFLO 20 ms
client. The study's final MAL timing map identifies 283 `relaxed_20ms`
sessions with client SHA-256
`63e65f88eda67a04038e08f41497de1eab6766291b9aa42ca1e1764cff8ca95c`.
The separately preserved build output has the same hash. This evidence binds
the recorded client identity to those sessions; it is not an independent proof
of defense fidelity or of which instructions were executed for each packet.

The source used for the build was an exported directory without Git metadata.
This branch overlays its source files on capture-used Native revision
`b77d46df18565a46f494fca0e1fa5a4c37e4dd63` so the changes can be inspected in
Git. **The parent is an integration baseline, not a proven historical ancestor.**
The build export omitted 55 files found in that parent, mostly CI, documentation
and unused test or support files. Those absent files are retained here; this
branch is therefore a reconstruction, not a byte-for-byte representation of
the exported directory. The exact export and its inventory are held in the
private study evidence archive.

This variant's changes extend beyond the 20 ms timing parameter. Do not assume
that it is interchangeable with the earlier Native 01e or b77 clients, apply
its validation rules retroactively to historical receipts, or identify this
branch's Git commit as the original capture-time commit.
