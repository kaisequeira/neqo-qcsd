# QCSD migration to Neqo 0.30.0

## Provenance

This branch is based on Mozilla Neqo v0.30.0, commit
`8a04d065c2d35c8e8fd804f91c7081ab6bb60b89`. The behavioral source is
`jpcsmith/neqo-qcsd` tag `usenixsecurity22-v1`, commit
`39e293fb384dd341156eedd1e4b833d24904b1f6`. Its exact pre-QCSD Neqo parent is
`222bab99ee107f68101fab192c3903a15e22111a`.

The paper authority is Jean-Pierre Smith, Luca Dolfi, Prateek Mittal, and
Adrian Perrig, “QCSD: A QUIC Client-Side Website-Fingerprinting Defence
Framework,” *31st USENIX Security Symposium*, 2022. The local research copy
used during the port was `QCSD.pdf`; the publication page is
<https://www.usenix.org/conference/usenixsecurity22/presentation/smith>.

The migrated work remains dual-licensed under MIT or Apache-2.0, matching
Neqo. Ported files retain the standard dual-license header. Credit for the
published QCSD behavior belongs to its authors and contributors.

## Persistent source layout

The migration was performed with three sibling repositories:

- `neqo-qcsd/`: `kaisequeira/neqo-qcsd`, branch `qcsd-migration`.
- `legacy-neqo-qcsd/`: published QCSD at `39e293fb`.
- `legacy-neqo-2020/`: the exact parent at `222bab99`.

The parent commit is no longer reachable from Mozilla’s rewritten public
history, so the third checkout obtains that object from the published QCSD
repository while retaining `mozilla/neqo` as `origin`.

## Architecture

`neqo-qcsd` is transport-independent and does not depend on
`neqo-transport`. Its public boundary uses `QcsdEndpointId` and
`QcsdStreamId`; only the HTTP/3 adapter converts to current Neqo `StreamId`.
It contains:

- Static signed-CSV playback;
- deterministic seeded FRONT schedule generation;
- Tamaraw bidirectional constant-rate shaping and modulo completion;
- shared round-robin endpoint scheduling;
- versioned configuration and resource manifests plus legacy importers;
- dependency-aware chaff selection with exact-origin endpoint routing;
- explicit observations, actions, retry/drop policy, tail wait, and misses.

The `qcsd` features in `neqo-transport` and `neqo-http3` provide the narrow
adapter. Controlled receive streams use absolute `MAX_STREAM_DATA` values and
do not auto-grow or auto-tune. Outgoing scheduled 1-RTT packets carry normal
frames first, then `PING` and `PADDING` to reach an exact UDP-payload target.
Queued targets force one output datagram rather than GSO batching. QUIC
encryption state, congestion control, path validation, mandatory control
traffic, and the active path MTU remain authoritative.

`neqo-qcsd-client` uses a Tokio current-thread runtime. One loop owns the
controller and all origin connections, routes actions in stable endpoint
order, and therefore needs neither worker threads nor shared mutexes. The loop
combines Neqo's transport callback, the controller's next monotonic deadline,
and the configured control interval so due slots are processed without busy
polling or delaying transport timers.

## Intentional divergences

- Legacy raw `u64` stream IDs are confined to import/adapter boundaries.
- Durations are stored as integer microseconds. The new FRONT implementation
  uses an internal SplitMix64 generator so dependency upgrades cannot alter a
  seed’s schedule. Statistical FRONT behavior and defaults are preserved;
  exact old RNG traces should be imported as Static CSV schedules.
- Packet sizes always mean UDP payload bytes. Values below the safe minimum or
  above the active path MTU are rejected rather than clamped.
- Baseline (`kind = "none"`) uses Neqo’s normal receive windows. Shaped
  connections advertise the configured initial receive allowance (16 bytes in
  the published profile) before the handshake, because QUIC cannot revoke
  transport-parameter credit after advertising it.
- FRONT leaves application streams on automatic receive/send behavior and
  manually controls chaff receive credit. After opening a FRONT application
  stream, the adapter explicitly restores its configured automatic receive
  window (1 MiB in the checked-in profiles). Tamaraw and non-padding Static
  runs control application and chaff streams.
- Chaff is HTTPS GET-only, exactly same-origin, uses
  `Accept-Encoding: identity`, and strips conditional and range headers.
  Redirect targets are never promoted into the manifest automatically.
- The old clients and notebooks were not copied. The modern runner reproduces
  their required inputs and records machine-readable measurements.

The legacy TOML importer maps the published `[flow_shaper]` values into the
versioned schema, including millisecond-to-microsecond conversion and
`rx_stream_data_window` to `automatic_receive_window`. A
`[front_defence]` section selects FRONT, but its embedded seed is replaced by
the runner's required explicit seed. The legacy schema did not encode Static
or Tamaraw selection, so an importer cannot infer either defense. The obsolete
`local_md` and `use_empty_resources` switches are accepted for compatibility
but have no modern effect.

## Runner

Probe resources with HEAD and a bounded GET fallback:

```shell
cargo run --locked -p neqo-bin --features qcsd --bin neqo-qcsd-client -- \
  probe --output manifest.json --max-bytes 1048576 \
  https://example.com/ https://example.com/style.css
```

Run an explicit configuration:

```shell
cargo run --locked -p neqo-bin --features qcsd --bin neqo-qcsd-client -- \
  run --config qcsd-presets/published-front.toml \
  --manifest manifest.json --seed 42 --output-dir results/front-42 \
  --max-response-bytes 16777216 https://example.com/
```

`--preset published-front`, `--preset published-tamaraw`, and
`--preset conservative-live` expand into the same resolved values recorded in
`run.json`. Static schedules use an explicit config and CSV because the
published experiments intentionally supplied a trace rather than one universal
schedule.

Each run writes:

- `run.json`: source commits, fully resolved config, seed, URLs, endpoints,
  ALPN, timestamps, completion state, response status/bytes/SHA-256;
- `packets.csv`: direction, monotonic time, connection, observed UDP length,
  scheduled target, and satisfaction;
- `events.csv`: observations/actions, receive releases, chaff lifecycle,
  failures, and explicit miss reasons;
- `qlog/`: one Neqo qlog per endpoint.

The runner bounds application bodies with `--max-response-bytes`. Live runs
should use a probed same-origin manifest and the conservative preset. Public
endpoint availability and UDP reachability are release-gate observations, not
deterministic CI assertions.

## Legacy test audit

On the current compiler, the unmodified published tag first fails compilation
because its crates deny warnings that are now emitted for obsolete attributes
and lifetime spelling. With `RUSTFLAGS='--cap-lints warn'`, the
`neqo-csdef` library executes 80 tests: 74 pass and six fail:

- `chaff_stream::tests::throttled::test_data_sent`;
- `chaff_stream::tests::throttled::test_data_sent_desync`;
- `chaff_stream::tests::throttled::test_data_sent_no_budget`;
- `flow_shaper::tests::process_timer_pulls_and_pushes_multiple`;
- `flow_shaper::tests::process_timer_should_not_block`;
- `dependency_tracker::tests::from_json`.

The first three assert stale throttled-send bookkeeping (two expected panics no
longer occur). The next two expect `SendPaddingFrames` although the published
implementation emits `SendPacketOfSize`. The final test depends on a missing
fixture file. These are recorded as stale test/fixture findings, not copied as
desired behavior. The 74 passing cases seeded the modern core regression
corpus; focused modern tests additionally cover deterministic FRONT, Static and
Tamaraw sequences, imports, dependencies, round robin, manual flow control,
and exact datagram targets.

## Verification

Run the focused checks with an NSS setup supported by upstream Neqo:

```shell
cargo test --locked -p neqo-qcsd
cargo clippy --locked -p neqo-qcsd --all-targets -- -D warnings
cargo check --locked -p neqo-transport
cargo check --locked -p neqo-transport --features qcsd
cargo check --locked -p neqo-http3
cargo check --locked -p neqo-http3 --features qcsd
cargo clippy --locked -p neqo-bin --features qcsd \
  --bin neqo-qcsd-client -- -D warnings
```

The dedicated workflow also checks default Neqo and QCSD feature builds
separately. Local test linking requires a compatible system NSS or the
`NSS_DIR`/dynamic-library setup described in the root README.

### Verification snapshot (2026-07-16)

- All 18 `neqo-qcsd` unit tests pass, and strict all-target core clippy is
  clean.
- All 856 QCSD-enabled `neqo-transport` library tests pass, including six new
  focused tests covering manual credit, restoring automatic credit, exact
  900/1000/1200-byte UDP payloads, unsafe size rejection, and leaving
  handshake output unshaped.
- Default and `qcsd` feature checks pass independently for transport and
  HTTP/3. The full QCSD-enabled HTTP/3 library suite passes 391 tests with one
  pre-existing ignored test; default `neqo-bin` checks and strict QCSD-runner
  clippy also pass.
- Against an unmodified local Neqo HTTP/3 server, fresh baseline and
  conservative FRONT runs both completed with status 200 and identical body
  SHA-256
  `8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1`.
  All three scheduled outgoing FRONT datagrams were exactly 1200 bytes and
  recorded as satisfied. Incoming misses were recorded explicitly because the
  deliberately minimal server exposed only a one-byte chaff resource.

On the ARM64 verification host, upstream `nss-rs` built its assembly wrapper
archive but did not add that archive to the test link command. Focused linked
tests and smoke binaries were therefore run with an extra native search path
and `-l static=aarch64-gcm-wrap_c_lib`. Compile-only checks need no workaround,
and the x86-64 GitHub workflow uses Mozilla's supported NSS setup.

Public HTTP/3 endpoint tests remain a timestamped release gate rather than a
claim made by this local snapshot. Run `probe`, baseline, and the bounded
conservative preset immediately before a research release; record reachability
or endpoint failures alongside the resulting artifacts.

## Out of scope

This remains client-only. Reserved HTTP/3 frames, `MAX_STREAMS` manipulation,
multipath defenses, the 2022 classifier/notebooks, and exact reproduction of
old Internet performance measurements are future work.
