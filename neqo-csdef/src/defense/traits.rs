// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize};

use super::Capacity;
use crate::{Direction, MissedSlotReason, Packet, QcsdDatagramClass, TrafficMorphingOutcome};

/// Whether a defense adds cover traffic or regulates the whole application.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseMode {
    /// Application traffic remains automatic; scheduled capacity is chaff-only.
    ChaffOnly,
    /// Application and chaff traffic are shaped toward the schedule.
    ChaffAndShape,
}

/// How a previously emitted event resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventOutcome {
    /// The adapter realised `observed` bytes for the event.
    ///
    /// For outgoing events this is the UDP datagram size. For incoming events
    /// it is the amount of receive credit whose absolute limit was encoded.
    Satisfied { observed: u16 },
    /// The adapter could not realise the event.
    Missed(MissedSlotReason),
}

/// What a defense may learn about the connection it is shaping.
///
/// This deliberately contains no endpoint, stream, or Neqo concepts. Raw wire
/// observations include all post-handshake datagrams and remain available to
/// non-reactive defenses. Reactive chaff-only defenses use the causally
/// classified view so only transport-proven defense feedback is suppressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalKind {
    /// A UDP datagram crossed the wire, aggregated across all endpoints.
    Wire { direction: Direction, length: u16 },
    /// The post-decryption/build causal class of a UDP datagram.
    ///
    /// This is additive to [`Self::Wire`]. Mixed or unknown evidence is
    /// classified as natural by the transport adapter.
    ClassifiedWire {
        direction: Direction,
        length: u16,
        class: QcsdDatagramClass,
    },
    /// Application or reviewed-chaff request-stream offsets were transmitted
    /// or consumed.
    ///
    /// Incoming values are raw offsets advanced by HTTP/3, including frame
    /// headers, HEADERS blocks, DATA, and trailers. Unlike receive-credit
    /// actions, these bytes were actually observed; they are not body-only or
    /// attributable to one server datagram.
    PayloadBytes {
        direction: Direction,
        bytes: u64,
        /// Whether the bytes belong to an explicitly reviewed chaff stream.
        cover: bool,
    },
    /// Exact overlap between consumed raw STREAM offsets and previously
    /// advertised defense-scheduled receive-credit ranges.
    ///
    /// This is an internal credit-ledger signal, not a claim about payload
    /// provenance. It excludes bytes admitted by the initial stream allowance.
    ReceiveCreditConsumed { bytes: u64 },
    /// Previously advertised scheduled receive-credit offsets that can no
    /// longer produce payload because their stream closed before consumption.
    ///
    /// Initial transport allowance is excluded. A client-only incoming adapter
    /// can retry these bytes without confusing `MAX_STREAM_DATA` with observed
    /// application or reviewed-chaff payload.
    ReceiveCreditRetired { bytes: u64 },
    /// Releasable receive capacity aggregated across all endpoints.
    Capacity(Capacity),
    /// A previously emitted event reached a terminal outcome.
    Resolved {
        packet: Packet,
        outcome: EventOutcome,
    },
    /// Outcome of the transport's same-datagram Traffic Morphing hook.
    ///
    /// A bypass always carries a typed reason. The source packet has already
    /// crossed the wire in either case.
    TrafficMorphingEgress {
        source: u16,
        outcome: TrafficMorphingOutcome,
    },
    /// The runner opened one global application request batch.
    ApplicationBatchStarted,
    /// Every application stream in the current global batch terminated.
    ApplicationBatchCompleted,
    /// Every application request has completed.
    ApplicationComplete,
}

/// One timestamped observation delivered to a defense.
///
/// `at` uses the same defense-start clock as the `elapsed` argument of
/// [`Defense::next_event`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefenseSignal {
    /// Time relative to defense start.
    pub at: Duration,
    /// Observation payload.
    pub kind: SignalKind,
}

/// Per-mould Walkie-Talkie realization recorded in the terminal run artifact.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct WalkieTalkieBurstDiagnostics {
    /// Zero-based mould pair index.
    pub index: usize,
    /// Configured client-to-server fixed cells.
    pub target_outgoing_cells: u64,
    /// Configured server-to-client fixed cells.
    pub target_incoming_cells: u64,
    /// Client-to-server fixed-cell events actually realized.
    pub observed_outgoing_cells: u64,
    /// Fixed-cell equivalents of response STREAM bytes observed in this turn.
    pub observed_incoming_cells: u64,
}

/// Defense-specific counters recorded with the terminal run artifact.
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct DefenseDiagnostics {
    /// Number of natural client datagrams transformed in place.
    pub morphing_egress_packets: u64,
    /// Natural UDP-payload bytes presented to the egress transformer.
    pub morphing_egress_source_bytes: u64,
    /// Resulting UDP-payload bytes after same-datagram padding.
    pub morphing_egress_target_bytes: u64,
    /// Egress datagrams that could not be transformed under the declared policy.
    pub morphing_egress_bypasses: u64,
    /// Bypasses caused by a pacing-limited ACK/control transmission.
    pub morphing_egress_pacing_bypasses: u64,
    /// Bypasses caused by a congestion-limited ACK/control transmission.
    pub morphing_egress_congestion_bypasses: u64,
    /// Bypasses caused by a coalesced mandatory-control packet.
    pub morphing_egress_coalesced_bypasses: u64,
    /// Bypasses whose natural packet size was outside the QCSD size domain.
    pub morphing_egress_invalid_size_bypasses: u64,
    /// Bypasses caused by an unexpected failure to select a validated target.
    pub morphing_egress_target_selection_bypasses: u64,
    /// L1 distance in parts per million between observed egress target sizes
    /// and the configured outgoing target distribution.
    pub morphing_egress_target_l1_ppm: u64,
    /// Incoming target bytes requested through the QCSD realization adapter.
    pub morphing_ingress_requested_bytes: u64,
    /// Requested incoming cover bytes actually consumed from reviewed chaff streams.
    pub morphing_ingress_received_bytes: u64,
    /// Incoming target deficit left unrealized at the configured bound or tail.
    pub morphing_ingress_shortfall_bytes: u64,
    /// L1 distance in parts per million between observed incoming datagram
    /// sizes and the configured incoming target distribution.
    pub morphing_ingress_target_l1_ppm: u64,
    /// Number of padding events emitted by WTF-PAD.
    pub padding_events: u64,
    /// Whether WTF-PAD stopped at its configured event guard.
    pub padding_event_guard_triggered: bool,
    /// Desired incoming cover bytes emitted by the WTF-PAD automaton.
    pub wtf_pad_incoming_desired_bytes: u64,
    /// Total receive-credit bytes encoded for desired incoming events,
    /// including exact retries after unused scheduled offsets retire.
    pub wtf_pad_incoming_requested_bytes: u64,
    /// Desired incoming bytes satisfied by observed response payload.
    pub wtf_pad_incoming_received_bytes: u64,
    /// Desired incoming bytes that have not been observed.
    pub wtf_pad_incoming_shortfall_bytes: u64,
    /// Sum, over desired events, of the absolute error between the desired
    /// size and its largest single causally attributed HTTP/3 read aggregate.
    ///
    /// This is an aggregate-fragmentation metric, not a reconstructed
    /// server-datagram-size metric.
    pub wtf_pad_incoming_size_error_bytes: u64,
    /// Desired incoming events with at least one attributed read aggregate.
    pub wtf_pad_incoming_observed_events: u64,
    /// Sum of desired-to-representative-aggregate lag in microseconds.
    pub wtf_pad_incoming_lag_us_total: u64,
    /// Maximum desired-to-representative-aggregate lag in microseconds.
    pub wtf_pad_incoming_lag_us_max: u64,
    /// WTF-PAD transitions from the silent state into burst mode.
    pub wtf_pad_silent_to_burst: u64,
    /// WTF-PAD transitions from burst mode into a synthetic gap.
    pub wtf_pad_burst_to_gap: u64,
    /// WTF-PAD transitions from a synthetic gap back into burst mode.
    pub wtf_pad_gap_to_burst: u64,
    /// WTF-PAD transitions from burst mode back to silence.
    pub wtf_pad_burst_to_silent: u64,
    /// Walkie-Talkie outgoing events retried after a missed slot.
    pub retried_outgoing_events: u64,
    /// Outgoing fixed cells in the selected Walkie-Talkie pair mould.
    pub walkie_talkie_target_outgoing_cells: u64,
    /// Incoming fixed cells in the selected Walkie-Talkie pair mould.
    pub walkie_talkie_target_incoming_cells: u64,
    /// Outgoing fixed-cell events actually realized by the transport.
    pub walkie_talkie_observed_outgoing_cells: u64,
    /// Incoming fixed-cell equivalents observed as response payload.
    pub walkie_talkie_observed_incoming_cells: u64,
    /// Outgoing mould cells not realized at terminalization.
    pub walkie_talkie_outgoing_shortfall_cells: u64,
    /// Incoming mould cells not realized at terminalization.
    pub walkie_talkie_incoming_shortfall_cells: u64,
    /// Outgoing cell equivalents beyond the selected mould.
    pub walkie_talkie_outgoing_overflow_cells: u64,
    /// Incoming cell equivalents beyond the selected mould.
    pub walkie_talkie_incoming_overflow_cells: u64,
    /// Incoming Walkie-Talkie mold bytes not realized when a run aborts.
    pub walkie_talkie_incoming_shortfall_bytes: u64,
    /// Incoming response bytes attributed to reviewed chaff realization.
    pub walkie_talkie_incoming_chaff_bytes: u64,
    /// L1 distance between target and observed direction-level cell counts.
    pub walkie_talkie_target_observed_cell_l1: u64,
    /// Cell-count L1 distance over the molded outgoing/incoming burst budgets.
    pub walkie_talkie_target_observed_burst_l1: u64,
    /// Necessary ACK/path/control-only packets observed across application turns.
    pub walkie_talkie_control_only_crossings: u64,
    /// Application request-stream offsets observed across the opposite turn.
    pub walkie_talkie_application_stream_crossing_bytes: u64,
    /// Unique client-to-server application request-stream offset bytes.
    pub walkie_talkie_natural_outgoing_bytes: u64,
    /// Raw application request-stream offset bytes consumed by HTTP/3.
    pub walkie_talkie_natural_incoming_bytes: u64,
    /// Evaluation fixed cells above the selected workload's training envelope.
    pub walkie_talkie_source_envelope_overflow_cells: u64,
    /// Target and observed fixed-cell counts for every individual mould pair.
    pub walkie_talkie_burst_realization: Vec<WalkieTalkieBurstDiagnostics>,
    /// Application batches in the selected workload's sealed training envelope.
    pub walkie_talkie_expected_application_batches: u64,
    /// Application batches actually opened during this evaluation visit.
    pub walkie_talkie_observed_application_batches: u64,
    /// Observed application batches beyond the selected training envelope.
    pub walkie_talkie_application_batch_overflow: u64,
    /// Global application batches whose streams all terminated.
    pub walkie_talkie_application_batches_completed: u64,
    /// Invalid duplicate or unmatched application-batch lifecycle signals.
    pub walkie_talkie_batch_lifecycle_errors: u64,
    /// Whether terminalization occurred with an application batch still active.
    pub walkie_talkie_application_batch_active: bool,
    /// Cover-traffic wire observations suppressed to avoid self-feedback.
    pub suppressed_cover_feedback: u64,
}

/// Stateful generator for a QCSD packet schedule.
///
/// A defense describes *what* should happen. Endpoint selection,
/// flow-control releases, and packet construction remain controller/adapter
/// responsibilities.
///
/// # Contract
///
/// For each poll, the controller delivers all observations buffered since the
/// previous poll through [`Self::observe`] in non-decreasing timestamp order
/// before calling [`Self::next_event`]. It then calls `next_event` repeatedly
/// until it returns `None`.
///
/// A defense must emit only events that are already due. Pending internal
/// decisions may be cancelled before their deadline; emitted events cannot be
/// retracted. Returned events must be non-decreasing in timestamp.
pub trait Defense: Debug {
    /// Consume one observation.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "signals are Copy values deliberately passed through the single-owner reducer"
    )]
    fn observe(&mut self, signal: DefenseSignal);
    /// Observe application request-stream offset bytes independently of shaped cells.
    ///
    /// The controller deduplicates client-egress STREAM ranges before calling
    /// this hook. Incoming values are the raw offsets HTTP/3 consumes, including
    /// framing and content; they are already unique. Defenses that do not
    /// compare natural traffic with a frozen training envelope can ignore this
    /// observation.
    fn observe_application_bytes(&mut self, _at: Duration, _direction: Direction, _bytes: u64) {}
    /// Return the next event at or before `elapsed`.
    fn next_event(&mut self, elapsed: Duration) -> Option<Packet>;
    /// Time of the next event relative to defense start.
    fn next_event_at(&self) -> Option<Duration>;
    /// Whether no events remain.
    fn is_complete(&self) -> bool;
    /// Whether no outgoing events remain.
    fn is_outgoing_complete(&self) -> bool;
    /// Whether normal-priority chaff STREAM data may leave without a slot.
    ///
    /// Most finite schedules release chaff once no outgoing events remain so
    /// an incoming-only tail can finish. A strict half-duplex defense may keep
    /// application and chaff STREAM data gated until its full sequence ends.
    /// Mandatory QUIC ACK, path, and control frames remain transport-owned.
    fn can_release_chaff_send_shaping(&self) -> bool {
        self.is_outgoing_complete()
    }
    /// Whether the runner may open the next global application request batch.
    ///
    /// Most defenses do not regulate application batch creation. Strict
    /// half-duplex defenses override this to couple dispatch to an outgoing
    /// turn whose preceding byte budget and application batch both ended.
    fn can_start_application_batch(&self) -> bool {
        true
    }
    /// How application traffic participates in the schedule.
    fn mode(&self) -> DefenseMode;
    /// Defense-specific counters for reproducibility and failure auditing.
    fn diagnostics(&self) -> DefenseDiagnostics {
        DefenseDiagnostics::default()
    }
}
