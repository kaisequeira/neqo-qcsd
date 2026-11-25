# Capture-used Native versions

The production source at this integration point is the capture-observed Native
`b77d46df18565a46f494fca0e1fa5a4c37e4dd63` tree. It follows the former main
`d2c4ec0e7dcc358fb0915d7b09c9a9b91715da8c`. The historical
`01e226fb43000691acbda57feb338855b26e66ca` and reconstructed 20 ms variant
are also reachable through this integration commit's parents. Keeping their Git
history does not mean that either variant's differing behavior has been applied
to the default source tree.

## 20 ms MAL BuFLO

The final study timing map records 283 `relaxed_20ms` sessions associated with
client SHA-256 `63e65f88eda67a04038e08f41497de1eab6766291b9aa42ca1e1764cff8ca95c`.
The preserved client binary has the same digest. The source directory used to
build it had no Git metadata, so its exact historical commit and ancestry are
not known.

The `mal-buflo-20ms-20261124.patch` file contains the source differences from
the b77 integration baseline to the [documented reconstruction](https://github.com/kaisequeira/neqo-qcsd/tree/study-capture/mal-buflo-20ms-20261124).
The b77 parent was chosen as an integration baseline, **not proven to be an
ancestor of the capture-time export**. The export lacked 55 files from b77,
mostly CI, documentation and unreferenced test or support files; those files
are retained in the reconstruction. The independent private study archive
preserves the original exported files and their inventory. Consult it for
byte-exact evidence rather than treating the reconstruction as the original
Git commit. A build or hash match does not establish defense fidelity.

To inspect or use this reconstruction, start from a clean checkout of b77 and
apply the patch from this directory; verify the resulting files against the
private export inventory before relying on them for reproduction. The branch
README records the same distinction.

## Earlier 64 ms feedback

The historical 01e implementation has a separate 64 ms socket-schema-2
predicate that the b77 aggregate paths do not explicitly repeat. Both versions
remain in history, but this integration does not silently change b77's
acceptance policy or retroactively re-evaluate historical receipts. A complete
version-bound aggregate and Linux helper comparison remains a separate
validation task.

## Linux checks, 25 November 2026

In an isolated aarch64 Linux container using Rust 1.90 and the recorded d428
builder image, `cargo test --locked --offline -p neqo-csdef` at b77 passed 625
tests. Five focused `neqo-bin` tests passed: the two `layered_feedback` tests,
the observed-Poki scheduler-feedback test, the timestamp-inventory-bounds test,
and `buflo_cadence64_kernel_receipts_keep_outgoing_guard_and_half_open_incoming_bound`.
These checks do not prove the behavior of every capture or resolve the 01e/b77
schema distinction in the aggregate path.

The same `neqo-csdef` test command on the reconstructed 20 ms source at
`25a9c572c33e0cdf6179ccd67ec47de190b12b8b` passed 622 of 625 tests. A
separate run against a copy of the capture-time source export, excluding build
outputs and logs, produced the same result. In both runs these three failed:

- `buflo_cadence64_ack_start_preserves_real_suppressed_identity_holes`
- `rbing_b815_closure_stops_fresh_incoming_before_materialization`
- `rbing_owned_data_continuation_rejects_known_subcell_chaff_body_tail`

Those results concern the checked sources in that test environment; they are
not a determination that individual historical captures were invalid. Test
logs and the exact exported source are retained in the private study archive.
