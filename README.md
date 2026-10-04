# Neqo, an Implementation of QUIC in Rust

![neqo logo](https://github.com/mozilla/neqo/raw/main/neqo.png "neqo logo")

Neqo is the QUIC implementation used by Mozilla in Firefox and other products.
It is written in Rust and provides a library for QUIC transport, HTTP/3, and
QPACK. The TLS security backend is the Mozilla NSS library, which is also used
by Firefox.

Neqo is designed to be used in Firefox, but it can also be used
standalone. We include command line tools for testing and debugging, such as
`neqo-client` and `neqo-server`, which can be used to test HTTP/3 servers
and clients.

**Note: The neqo server functionality is experimental**, since
it is not in production use at Mozilla, and it is not as mature as the
client functionality. It is intended to be standards-compliant when
interoperating with a compliant client, but it may not implement all
optional protocol features, and it may not handle all edge cases.
It is also not optimized for performance or resource usage, and
while it implements many of the necessary features for a server,
it does not include configuration of a number of options that
are suited to a live deployment.
**Do not use the neqo server code in production.**

To build Neqo:

```shell
cargo build
```

This will use a system-installed [NSS][NSS] library if it is new enough. (See "Build with separate NSS/NSPR" below if NSS is not installed or it is deemed too old.)

To run test HTTP/3 programs (`neqo-client` and `neqo-server`):

```shell
./target/debug/neqo-server '[::]:12345'
./target/debug/neqo-client 'https://[::]:12345/'
```

## QCSD research client

This fork contains a feature-gated migration of the published client-side QCSD
framework to Mozilla Neqo 0.30.0. It adds no server requirements and leaves
normal Neqo builds unchanged until the `qcsd` feature is enabled. The
transport-independent client-side defence library is `neqo-csdef`; the narrow
Neqo transport/HTTP/3 integration feature remains named `qcsd`, and
`neqo-qcsd-client` is the dedicated current-thread research runner.

### Provenance

The base is Mozilla Neqo v0.30.0 commit
`8a04d065c2d35c8e8fd804f91c7081ab6bb60b89`. Behavioral authority comes from
`jpcsmith/neqo-qcsd` tag `usenixsecurity22-v1` commit
`39e293fb384dd341156eedd1e4b833d24904b1f6`, whose exact pre-QCSD parent was
`222bab99ee107f68101fab192c3903a15e22111a`. The accompanying publication is
Jean-Pierre Smith, Luca Dolfi, Prateek Mittal, and Adrian Perrig,
“[QCSD: A QUIC Client-Side Website-Fingerprinting Defence
Framework](https://www.usenix.org/conference/usenixsecurity22/presentation/smith),”
*31st USENIX Security Symposium*, 2022. Migrated code retains Neqo's dual
MIT/Apache-2.0 licensing and the published authors' behavioral credit.

### Architecture

`neqo-csdef` has no Neqo dependency. Its focused modules retain the published
responsibility boundaries while using a closed-loop, typed observation/action
seam:

- `defense/` implements the seven runner selections: None, Static,
  deterministic FRONT, Tamaraw, Traffic Morphing, WTF-PAD, and directed
  Walkie-Talkie. Independent incoming/outgoing round-robin scheduling maps
  defense events onto live endpoints.
- `rng.rs` and `distribution.rs` provide domain-separated deterministic
  sampling, validated morphing matrices, and token histograms without
  introducing a Neqo dependency. Reactive defenses own their runtime state
  machines directly.
- `stream/` implements the Figure-7 receive state machine and one-pass
  per-endpoint receive-capacity allocation.
- `controller/` is the single-owner replacement for `FlowShaper`; it composes
  control-interval buckets, receive backlog, chaff replenishment, closed-loop
  defense signals, slot accounting, and tail completion without
  `Rc<RefCell<_>>`, worker threads, or mutex-protected shared defenses.
- `event/` exposes typed observations/actions with stable endpoint, stream,
  slot, and chaff-request IDs. `chaff_manager.rs` and
  `dependency_tracker.rs` provide repeated-resource low-watermark chaff and
  deterministic application graph dispatch.

Every defense receives wire activity, aggregate receive capacity, terminal
slot outcomes, and application completion on the same defense-relative clock.
Signals buffered since the preceding poll are ordered and delivered before the
defense may emit another due event. Handshake datagrams remain outside the
defense trace, while `packets.csv` retains its process-relative clock for
capture correlation.

Reactive adaptations consume an additive, causally classified datagram view.
The independent raw datagram observation remains unchanged for capture
reconciliation and non-reactive defenses. After packet construction or
decryption, the transport marks a datagram as defense cover only when every
relevant frame has positive provenance: a scheduled cover packet, registered
reviewed-chaff STREAM or flow-control state, or ACK ranges that exclusively
acknowledge already classified cover packets. Mixed, unknown, and
natural-control evidence fails closed to natural traffic. Traffic Morphing and
WTF-PAD therefore cannot recursively react to controller-induced traffic;
their diagnostics record the number of causally suppressed cover datagrams.
This is exact transport provenance for the classification decision, not a
claim that a passive capture can recover encrypted frame identities or exact
server packet-to-HTTP-body attribution.

The feature-gated Neqo adapter gives controlled streams absolute
`MAX_STREAM_DATA` credit and disables receive-window auto-growth only for those
streams. Scheduled 1-RTT output uses application frames before chaff, then
`PING` and `PADDING` to reach the exact UDP-payload target. Packet protection,
path validation, congestion control, pacing, mandatory frames, and path MTU
remain authoritative; unsafe or late slots receive one explicit miss reason.

### Prospective BuFLO V12 preparation reserve

The historical BuFLO kernel schema 11 remains the default. A new, explicit
prepared Source flag opts in to schema 12:

```json
"buflo_kernel_preparation_policy": "rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1"
```

This flag requires the existing `rapid-v5-half-period-10000us-ack-start-v2`
incoming policy, approved origins, variable primary document and completed
terminal HTTP response policies, fixed 1200-byte/20-ms BuFLO settings, and the
actual ETF scheduler contract. It has no effect on another defense. It is a
prospective client adaptation and makes no paper equivalence or scientific
credit claim by itself.

For a rolling outgoing cell, selection and a fresh CLOCK_TAI dispatch
confirmation must finish strictly before release + 4 ms. This leaves a 1 ms
reserve before the original, unchanged release + 5 ms physical deadline.
Tick zero still requires selection, staging and dispatch before release.
Nominal admission remains release − 10 ms and nominal selection release − 5 ms.
Every preparation deadline is recorded in schema-2 wait/failure entries under
a schema-3 protected-wait receipt; raw kernel schema 12 and outer runner schema
21 carry the exact opt-in marker and their distinct semantics.

This addresses a measured sample gap at slot 938: the next CLOCK_TAI reading
was 1.417690 ms after release, with 3.582310 ms left before the original
physical deadline. The gap does not establish whether descheduling or a clock
step caused it. A schema-11 attempt still fails under its original rules and
is never relabelled as successful.

Actual construction lateness is retained and must be below 5000 us for this
opt-in path. Application STREAM data, retransmissions, control bytes, exact
slot identity and full wire accounting retain their existing ownership. A
prepared application datagram is never converted into a padding omission.
Preparation alone gives no successful-send credit. Any preparation, enqueue,
clock, helper, kernel TX or post-veth failure stays an explicit failed attempt.
There is no omission allowance or catch-up send.

The enqueue cutoff and exact physical TX/post-veth window remain half-open at
release + 5 ms. SCM_TXTIME remains release + 10 ms, ETF delta remains 10 ms,
and deadline mode/offload remain disabled. Incoming credit keeps its existing
10 ms ACK-start contract. Generic EDF and other defenses are unchanged.

A delayed Python UDP/ETF probe demonstrated enqueue at +1.571969 ms, kernel TX
at at most +1.679667 ms and post-veth observation at at most +1.699866 ms, with
matching 1200 bytes and no TXTIME errors. That proves the measured UDP/kernel
path only. Native compilation, focused QUIC regressions, a fresh Source-bound
runtime and the original failing-seed full-graph repeat are still required
before this policy can authorize capture.

### Prospective fixed BuFLO 200-second event budget

Larger complete resource graphs need more than the historical 6000 incoming
cells (7,200,000 scheduled receive bytes shared across all origins). A separate
explicit parameter flag permits one fixed larger budget:

```json
{
  "schema_version": 1,
  "interval_us": 20000,
  "minimum_duration_us": 10000000,
  "packet_size": 1200,
  "max_events": 10000,
  "implementation_scope": "client_only_quic",
  "paper_equivalent": false,
  "duration_budget_policy": "rapid-v6-fixed-200s-duration-budget-v1"
}
```

The public `BufloDurationBudgetPolicy::RapidV6Fixed200Seconds` accepts only that
fixed combination. Omitting the optional parameter retains the existing
120-second validation bound and exact historical serialized key set. Unknown
policies, arbitrary duration values, changed fixed settings, and overflowing
duration arithmetic are rejected. Recorded `defense_parameters.buflo_duration_budget`
retains the actual explicit policy; it is never inferred from a timeout.

The unchanged 20-ms cadence permits at most 10000 cells in each direction over
a 200-second budget. It offers 12,000,000 incoming scheduled receive bytes
across the whole graph; origins do not multiply that capacity. The application
may finish earlier after the existing minimum duration and terminal conditions.
Exhausting the event guard before normal completion remains a typed failure.
Cell size, the kernel V12 marker/raw/outer schemas, release − 10-ms admission,
release − 5-ms selection, release + 4-ms preparation cutoff, release + 5-ms
physical deadline, 10-ms incoming window, ETF delta/SCM_TXTIME, clock checks,
application bytes, other defenses and omission rules are unchanged.

Matching prospective Lab settings must apply a 240-second native timeout and
300-second recorder duration only to BuFLO, bind this fresh traffic receipt,
and verify a fresh per-mode canary. For a future common 50-site cohort, use one
prospectively declared total baseline body threshold of at most 10,000,000
bytes per complete graph. The remaining scheduled capacity is conservative
headroom for framing, chaff and ACK-start delay; it does not guarantee a
successful defense canary or stable later responses. The 16-MiB per-response
cap does not imply this total graph-size condition. Existing admissions,
complete graphs and failed attempts must remain intact and must not be
retroactively marked rejected by the future threshold. Authoring and HOST
fixtures give no compilation, physical-send or formal-trace credit.

For application streams, the runner seeds Figure-7's known-capacity floor from
the workload resource's effective length, capped by the run's response limit.
This keeps shaped receive credit available to a reviewed response even when the
server omits `Content-Length`; response headers, DATA frames, and blocked
signals can still extend the floor. Chaff streams continue to use the
controller's resource estimate.
Defense-scheduled receive credit is tracked as exact absolute STREAM-offset
ranges. The transport's initial allowance is excluded. Observed STREAM bytes
reduce an incoming defense's desired byte budget, while only their exact
overlap with scheduled ranges reduces credit still in flight. Unused ranges
retire when their stream or endpoint closes; only that retired amount becomes
eligible for a retry. Advertising `MAX_STREAM_DATA` never counts as received
traffic. A bounded parser-liveness lease remains slotless at the transport
boundary. When it is provisionally backed by an existing scheduled slot, the
controller includes that owner as runner trace metadata so the slot's action
time is the lease-issuance time; an unowned lease includes no slot metadata.

Walkie-Talkie is the one defence whose effective initial request-stream receive
limit is zero. The same zero is installed in the client transport parameter,
the controller `ReceiveState`, and `ConfigureManualReceive`; all other modes
retain the resolved shared value (16 bytes in the checked-in profiles). Thus an
outgoing Walkie-Talkie turn admits no response HEADERS or DATA, and an incoming
cell grants exactly its raw-offset byte budget without an implicit allowance
per stream.
Run-level timeouts terminalize pending slots as `DeadlineExpired`, other
runner failures use `RunAborted`, and `EndpointClosed` is reserved for an
unavailable or closed endpoint.
The runner derives one PMTUD policy from the resolved maximum UDP-payload size
and the peer address family, and applies it identically to None and every
defense. The ceiling constrains every locally built datagram in the Initial,
Handshake, and Application Data packet-number spaces. The peer's advertised
maximum immediately caps the effective PLPMTU instead of waiting for a later
search-table transition. A ceiling that fits the fixed initial path payload,
including the 1200-byte live profile, disables client probing so probe
datagrams cannot fall outside the configured matrix domain. The published
1450-byte profile and larger custom ceilings retain PMTUD. QCSD endpoints use
the direct-capture UDP bind path, which clears Linux/Android `UDP_GRO` after
the normal socket setup so one kernel receive record cannot merge several
QUIC datagrams. Ordinary non-QCSD client and server binds retain their normal
socket behavior.

FRONT is a chaff-only defense: its scheduled datagrams never consume ordinary
application or chaff `STREAM` data, and application transmission remains
otherwise automatic. Tamaraw shapes application and chaff in both directions,
prioritizing application data within each available slot and padding each
direction to the published modulo completion rule. Their generators reproduce
the published algorithms and control semantics; deterministic equality is
defined against this implementation's pinned generator, not the historical
`rand` crate's seed-to-sample mapping.

### Prospective FRONT V4 preparation reserve

The source-bound policy
`rapid-v5-front-bounded-outgoing-padding-omission-10pct-window-10000us-reserve-1000us-v4`
addresses a local construction-to-send race. In a four-seed diagnostic of V3,
two attempts aborted before the socket call, 3,765 ns and 8,419 ns after their
padding deadlines. Two other attempts completed all 260 resources across four
origins. Those failed attempts remain failed V3 evidence. Their existing
traces do not retain the rejected prepared datagram, so its exact coalesced
composition cannot be inferred from nearby packets.

V3 decides eligibility before building and encrypting a packet, then checks
the clock again before the socket call. Starting construction immediately
before the deadline can consume the remaining time. V4 reserves a full
millisecond before that unchanged physical deadline:

| Boundary, relative to the padding target | V4 behavior |
| --- | --- |
| Before release | Padding target remains ineligible. |
| Release through less than 9 ms | Padding construction is eligible. |
| At or after 9 ms | Unbuilt padding target expires; ordinary application and control work remains eligible. |
| Before 10 ms | An already built target may reach the socket. |
| At or after 10 ms | Physical target handoff remains a hard failure. |

The adapter's construction deadline is exactly 1,000 microseconds earlier than
the original socket deadline. Existing upward release and downward deadline
rounding is retained; actual relative windows can be one microsecond shorter.
The output operation takes a fresh monotonic sample immediately before
construction so prior controller, trace or HTTP work cannot leave it using a
stale eligibility time. A target first registered during its reserved tail is
recorded as an unbuilt omission without reaching transport.

Expiration occurs before transport selects or encrypts frames. It does not
cancel, consume or discard application STREAM, retransmission, reviewed-chaff
STREAM or mandatory control work. That work can produce an ordinary datagram
in the same output operation. FRONT targets remain 1,200-byte chaff-only
targets; the original outgoing and incoming generators are unchanged.

The run records a schema-4 policy marker with the 9,000-microsecond
construction window, the 1,000-microsecond reserve and the original
10,000-microsecond physical window. Each target registration also records
`front_padding_preparation_window`: the shortened transport action and both
absolute deadlines. `DeadlineExpired` refers to the recorded construction
deadline for an unbuilt V4 outgoing target. The existing 10% bound on
outgoing pure-padding omissions remains; V4 does not authorize omissions of
realized application or control bytes, or waive incoming completion.

The reserve is not a real-time guarantee. If an operation still exceeds its
physical deadline, it fails. A pre-handoff failure records
`front_prepared_output_failure` with the built datagram hash, exact byte
composition, preparation and observation timestamps, target identity and
socket deadline. It does not create a physical packet or satisfied-slot
receipt. A syscall that succeeds too late retains its actual physical packet
and slot evidence before the run fails. Neither case can become an accepted
pure-padding omission.

V4 requires its exact marker in the authenticated prepared workload and the
unchanged research1200 FRONT parameters. It is inert for other modes and does
not change V1–V3 behavior, generic deadline/clock guards, incoming credit,
congestion decisions or the complete application resource graph. Lab-side
policy validation and a prospective study amendment must recognize V4 before
new formal traces can use it; old policy markers and receipts are preserved.

Traffic Morphing pads each natural client-egress 1-RTT datagram in place after
normal frame selection. Its workload-bound padding-only matrix never selects a
smaller target. The runner requires `--workload-id` and rejects missing or
duplicate source profiles. The runner installs every origin's morpher
atomically after all QUIC connections are established and immediately before
starting the defence clock; the direct observer still retains the earlier
handshake and bootstrap traffic. Before a random draw, optional STREAM
selection is limited to source rows whose reachable targets fit current pacing
and congestion capacity; otherwise optional data waits. Necessary control-only
packets carry a typed, fidelity-invalidating bypass reason. Incoming
realization is a separate aggregate QCSD adapter using receiver credit and
observed reviewed-chaff bytes. Receive-credit requests are byte amounts, not
UDP payload targets, so a final residual smaller than the minimum shaped
datagram remains valid and is requested exactly. Unresolved deficits remain
explicit shortfall.
WTF-PAD is a time-reactive chaff-only adaptive-padding state machine driven by
validated finite token histograms and an explicit event guard. Incoming
reviewed-chaff `BytesRead` aggregates repay desired events FIFO. Each event's
size and lag diagnostics use its largest single causal aggregate contribution,
so fragmented repayment remains visible without claiming unavailable
server-datagram boundaries. Directed Walkie-Talkie selects exactly one
workload-bound symmetric pair mould from a precomputed profile bundle in
`ChaffAndShape` mode. It enforces global
half-duplex application batches, advances an incoming turn only after both the
global application batch has terminated and its response-byte budget was
actually observed, and holds each later outgoing mould turn until the runner
has opened that batch's globally ready requests. This prevents cover slots from
being consumed before application STREAM bytes exist. Missed outgoing slots
are retried under the runner's whole-run timeout. A stalled turn aborts the
run; elapsed time is never treated as successful realization. After a causal
batch completion and terminalization
of its existing incoming slots, an underfilled pre-advertised response
allowance can create an exact residual receive-credit request. Missed request
opportunities remain retryable, later batches can create fresh opportunities,
and neither credit nor a successfully emitted request advances the mould;
only observed application or reviewed-chaff bytes do. A decoy-only mould
suffix after the selected
workload's terminal batch remains chaff-only and cannot reopen the application
gate. Diagnostics bind expected, observed, completed, and overflow application
batch counts; fidelity requires equality with no overflow. Mandatory ACK, path,
and connection-control frames remain transport-owned, so physical wire rows
can contain a control datagram during an incoming turn even though no outgoing
defense or application `STREAM` slot is released. Typed STREAM-transmission
observations make any application crossing a fidelity failure. A shared
per-run observation clock adds production nanoseconds and a total-order
sequence before endpoint queues are drained; the external Walkie-Talkie bundle
producer requires that causal evidence so multi-origin burst transitions
cannot depend on polling order. These are QCSD
adaptations over QUIC datagrams and client-side receive-credit pulls; they are
not byte-for-byte ports of the original Tor implementations.

The Walkie-Talkie bundle declares
`http3-request-stream-offset.bytes`. Outgoing natural cells are fitted from
unique raw application request-STREAM offset ranges actually transmitted.
Incoming natural cells count raw offsets consumed by the HTTP/3 request-stream
reader, including response HEADERS and frame headers, DATA, trailers, and other
framing—not only body bytes. Envelope construction and symmetric pairing align
global batch (k) only with batch (k), zero-extend components within that
batch, and record common `molded_batch_ends`. Selected-side `batch_ends` retain
the expected application-batch count; unmatched common batches are chaff-only.
The completing incoming read is delivered to the defence before its final
credit-consumption signal can advance the mould. Direct encrypted PCAP is the
independent timing/direction/frame-size evidence and cannot assign these raw
offsets to individual server packets.

For reactive defenses, seeded reproducibility is conditional on the same
ordered defense-signal transcript. Full-controller golden replays for Traffic
Morphing, WTF-PAD, and Walkie-Talkie drive an identical transcript twice and
compare typed actions, slots, terminal outcomes, and diagnostics exactly.
Independent live QUIC connections are not treated as identical inputs because
transport packetization, ACK timing, endpoint interleaving, and available
receive credit can change their causally classified datagram, STREAM-payload,
and realization observations.

Intentional modernizations include typed IDs, integer microsecond durations, a
pinned SplitMix64 FRONT generator, explicit UDP-payload sizes, same-origin
credential-free chaff with frozen safe request headers, and current Neqo stream keep-alives.
Exact historical RNG traces can be imported as Static CSV schedules. Schedule
CSV and dependency JSON inputs remain readable, but the obsolete profile-v1
TOML surface, clients, notebooks, worker threads, and direct core-to-Neqo
coupling were not restored.

### Profiles and runner

Complete built-in profiles live in `neqo-csdef/profiles/`. The `published`
profile captures the published source tag's defaults; it is not a claim that
one parameter set represents every experiment in the paper. The runner resolves
the selected profile and defense into the full configuration stored with every
run. Embedded profiles require the complete version-two profile schema;
resolved standalone `QcsdConfig` files must explicitly declare version two.
The removed profile-v1 `[flow_shaper]`/`[front_defence]` format is not
callable. All three adaptive defense-parameter JSON envelopes require their
strict version-two schemas. Explicit version-two configuration files remain
available for custom research defenses.
Static and the three parameterized defenses take a separate, content-hashed
input:

| Defense | Runner input | Parameter content |
|---|---|---|
| Static | `--schedule PATH --static-mode MODE` | signed legacy-compatible CSV schedule |
| Traffic Morphing | `--morphing-matrix PATH --workload-id ID` | workload-bound source-to-decoy bidirectional matrix bundle |
| WTF-PAD | `--wtf-pad-histograms PATH` | bidirectional burst/gap token histograms |
| Walkie-Talkie | `--walkie-talkie-molded PATH --workload-id ID` | one-to-one symmetric workload-bound pair-mould bundle |

The parameter flag for the selected defense is required and foreign defense
flags are rejected. Relative parameter paths in an explicit TOML
configuration resolve from that configuration's directory. The runner records
the selected file's path, kind, and raw SHA-256 digest in
`run.json.defense_parameters`; terminal defense counters such as morphing
realization error, WTF-PAD guard activation, and Walkie-Talkie target/observed
cells, application-batch expected/observed/overflow, mould overflow, shortfall,
chaff bytes, and control-only crossings are written under
`run.json.defense_diagnostics`.

Build the runner and inspect the current command surface with:

```shell
cargo build --locked -p neqo-bin --features qcsd --bin neqo-qcsd-client
target/debug/neqo-qcsd-client run --help
```

`probe --input-manifest` enriches browser-discovered graphs without discarding
IDs, dependencies, resource types, or safe headers.
Application requests replay the exact safe headers frozen in the manifest;
`as-defined` and `half-duplex` change request scheduling, not those headers.
Stored credentials and HTTP/3-invalid connection fields are rejected. Chaff
always remains same-origin GET-only and replays the same frozen safe headers,
including `Accept-Encoding`, while stripping credentials, ranges, conditions,
connection-specific fields, and promoted cross-origin redirects.

### Validation

Regression tests cover controller schedules, stream-state transitions, chaff
and dependency handling, shared endpoints, explicit transport misses,
application-before-chaff transmission, default-feature inertness, response
parity, and outgoing datagram correlation.

Run the focused local checks with a compatible NSS setup:

```shell
cargo test --locked -p neqo-csdef
cargo clippy --locked -p neqo-csdef --all-targets -- -D warnings
cargo doc --locked -p neqo-csdef --no-deps
cargo check --locked -p neqo-transport
cargo check --locked -p neqo-transport --features qcsd
cargo clippy --locked -p neqo-transport --features qcsd --lib -- -D warnings
cargo test --locked -p neqo-transport --features qcsd --lib
cargo check --locked -p neqo-http3
cargo check --locked -p neqo-http3 --features qcsd
cargo clippy --locked -p neqo-http3 --features qcsd --lib -- -D warnings
cargo test --locked -p neqo-http3 --features qcsd --lib
cargo check --locked -p neqo-bin
cargo test --locked -p neqo-bin --features qcsd --lib
cargo clippy --locked -p neqo-bin --features qcsd \
  --bin neqo-qcsd-client -- -D warnings
cargo build --locked -p neqo-bin --features qcsd \
  --bin neqo-qcsd-client
```

The companion
[`neqo-qcsd-lab`](https://github.com/kaisequeira/neqo-qcsd-lab) repository pins
this fork as a submodule and supplies Docker-only live workload discovery,
bounded PCAPNG capture, deterministic campaigns, drift detection, and
paper-style PDF visualization. It validates prepared defence-parameter bundles
and their sealed train evidence, but deliberately leaves fitting and parameter
generation outside the collection environment. Its bounded acceptance campaign
exercises all seven selections. The focused QCSD workflow validates pushes to
`main` and pull requests; canonical live acceptance runs explicitly through
the Docker lab.

## Build with separate NSS/NSPR

1. Clone [NSS][NSS] and [NSPR][NSPR] into the same directory and export an environment variable called `NSS_DIR` pointing to NSS.
   For example if you have a folder `$HOME/neqo-dependencies` and cloned NSS and NSPR into it you'd set `NSS_DIR=$HOME/neqo-dependencies/nss`.

2. If you did not already compile NSS separately, you need to have [Mercurial (hg)][HG] installed.
   NSS builds require [GYP][GYP] and [Ninja][NINJA] to be installed.

3. Run `cargo build` in your `neqo` checkout. The prior steps enable `cargo build` to use the existing NSS build or build it from the existing checkout if it hasn't been built yet.

4. Now that NSS has been built you need to set another environment variable to be able to actually do anything that depends on NSS.
   - For Linux:

     ```shell
     export LD_LIBRARY_PATH="$(find $NSS_DIR/.. -name libssl3.so -print | head -1 | xargs dirname | xargs realpath)"
     ```

   - For macOS:

     ```shell
     export DYLD_LIBRARY_PATH="$(find $NSS_DIR/.. -name libssl3.dylib -print | head -1 | xargs dirname | xargs realpath)"
     ```

5. (optional) After having an NSS build you can set the `NSS_PREBUILT=1` environment variable to skip building NSS again on future `cargo build` invocations.

## Debugging Neqo

### QUIC logging

Enable generation of [QLOG][QLOG] logs with:

```shell
target/debug/neqo-server '[::]:12345' --qlog-dir .
target/debug/neqo-client 'https://[::]:12345/' --qlog-dir .
```

You can of course specify a different directory for the QLOG files.
You can upload QLOG files to [qvis][QVIS] to visualize the flows.

To export QLOG files for [Neqo Simulator](./test-fixture/src/sim) runs, set the
environment variable `QLOGDIR`. For example:

```shell
QLOGDIR=/tmp/qlog cargo bench --bench min_bandwidth --features bench
```

### Using `SSLKEYLOGFILE` to decrypt Wireshark logs

You can export TLS keys by setting the `SSLKEYLOGFILE` environment variable
to a filename to instruct NSS to dump keys in the
[standard format](https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/)
to enable decryption by [Wireshark](https://wiki.wireshark.org/TLS) and other tools.

### Using RUST_LOG effectively

As documented in the [env_logger documentation](https://docs.rs/env_logger/),
the `RUST_LOG` environment variable can be used to selectively enable log messages
from Rust code. This works for Neqo's command line tools, as well as for when Neqo is
incorporated into Gecko, although [Gecko needs to be built in debug mode](https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/Configuring_Build_Options).

Some examples:

1. ```shell
   RUST_LOG=neqo_transport::dump ./mach run
   ```

   lists sent and received QUIC packets and their frames' contents only.

1. ```shell
   RUST_LOG=neqo_transport=debug,neqo_http3=trace,info ./mach run
   ```

   sets a `debug` log level for `transport`, `trace` level for `http3`, and `info` log
   level for all other Rust crates, both Neqo and others used by Gecko.

1. ```shell
   RUST_LOG=neqo=trace,error ./mach run
   ```

   sets `trace` level for all modules starting with `neqo`, and sets `error` as minimum log level for other unrelated Rust log messages.

### Trying in-development Neqo code in Gecko

In a checked-out copy of Gecko source, set `[patches.*]` values for the
Neqo crates to local versions in the root `Cargo.toml`. For example, if Neqo
was checked out to `/home/alice/git/neqo`, add the following lines to the root
`Cargo.toml`.

```toml
[patch."https://github.com/mozilla/neqo"]
neqo-bin = { path = "/home/alice/git/neqo/neqo-bin" }
neqo-common = { path = "/home/alice/git/neqo/neqo-common" }
neqo-http3 = { path = "/home/alice/git/neqo/neqo-http3" }
neqo-qpack = { path = "/home/alice/git/neqo/neqo-qpack" }
neqo-transport = { path = "/home/alice/git/neqo/neqo-transport" }
neqo-udp = { path = "/home/alice/git/neqo/neqo-udp" }
```

Then run the following:

```shell
./mach vendor rust
```

Compile Gecko as usual with

```shell
./mach build
```

Note: Using newer Neqo code with Gecko may also require changes (likely to `neqo_glue`) if
something has changed.

### Connect with Firefox to local neqo-server

1. Run `neqo-server` via `cargo run --bin neqo-server -- 'localhost:12345'`.
2. On Firefox, set `about:config` preferences:
   - `network.http.http3.alt-svc-mapping-for-testing` to `localhost;h3=":12345"`
   - `network.http.http3.disable_when_third_party_roots_found` to `false`
3. Optionally enable logging via `about:logging` or profiling via <https://profiler.firefox.com/>.
4. Navigate to <https://localhost:12345> and accept the self-signed certificate.

## Releasing Neqo and landing it in Firefox

Neqo follows [semantic versioning](https://semver.org/). While the version is
still below `1.0`, a **minor** bump (`0.X.0`) signals a breaking change and a
**patch** bump (`0.X.Y`) is reserved for backwards-compatible fixes.

### Minor release (e.g. `v0.26.0` → `v0.27.0`)

1. Bump the workspace version in [`Cargo.toml`](./Cargo.toml). Commit the
   resulting `Cargo.toml` and `Cargo.lock` change and open a pull request
   against `main`.
2. Merge the pull request.
3. Create the `vX.Y.Z` git tag pointing at the **merged** commit on `main` and
   push it.
4. Publish a [GitHub release](https://github.com/mozilla/neqo/releases) for the
   new tag.
5. File a Bugzilla bug under *Core :: Networking* titled `Update neqo to
   vX.Y.Z` (see [bug 2030978](https://bugzilla.mozilla.org/show_bug.cgi?id=2030978)
   for an example).
6. In a [`firefox`](https://github.com/mozilla-firefox/firefox) checkout, bump
   the `neqo-*` dependency versions in
   [`netwerk/socket/neqo_glue/Cargo.toml`](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/socket/neqo_glue/Cargo.toml)
   and
   [`netwerk/test/http3server/Cargo.toml`](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/test/http3server/Cargo.toml)
   (see [Phabricator D293565](https://phabricator.services.mozilla.com/D293565)
   for an example).
7. Run `./mach -v vendor rust --force --ignore-modified`.
8. Run `./mach cargo vet` and obtain the necessary supply-chain audits.
9. Submit the change to Phabricator referencing the Bugzilla bug.

### Patch release (e.g. `v0.26.0` → `v0.26.1`)

Patch releases ship from a long-lived release branch so that `main` can keep
moving with breaking changes.

1. If it doesn't exist yet, create the `vX.Y` branch on GitHub off the
   `vX.Y.0` tag (e.g. the
   [`v0.26`](https://github.com/mozilla/neqo/tree/v0.26) branch was cut from
   `v0.26.0`). Backport the fixes onto that branch.
2. From the `vX.Y` branch, open a pull request that bumps the version to
   `vX.Y.Z` in [`Cargo.toml`](./Cargo.toml) and targets `vX.Y` (not `main`).
3. Follow steps 2–9 of the minor release flow, tagging and releasing off the
   `vX.Y` branch instead of `main`. See
   [bug 2034178](https://bugzilla.mozilla.org/show_bug.cgi?id=2034178) and
   [Phabricator D296371](https://phabricator.services.mozilla.com/D296371) for
   an example.

[NSS]: https://hg.mozilla.org/projects/nss
[NSPR]: https://hg.mozilla.org/projects/nspr
[GYP]: https://github.com/nodejs/gyp-next
[HG]: https://www.mercurial-scm.org/
[NINJA]: https://ninja-build.org/
[QLOG]: https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/
[QVIS]: https://qvis.quictools.info/
