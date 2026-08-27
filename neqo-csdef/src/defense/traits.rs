// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize};

use super::Capacity;
use crate::{
    Direction, MissedSlotReason, Packet, QcsdChaffCancellationReason, QcsdCongestionReason,
    QcsdDatagramClass, QcsdSendPolicy, QcsdSlotComposition, QcsdSlotId, TrafficMorphingOutcome,
};

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
    /// it is the scheduled receive-credit amount whose tagged raw stream
    /// offsets were consumed.
    Satisfied { observed: u16 },
    /// The adapter could not realise the event.
    Missed(MissedSlotReason),
    /// Complete congestion-sensitive target with byte-level composition.
    FullySatisfied { composition: QcsdSlotComposition },
    /// Smaller target legally selected from congestion-controller capacity.
    PartiallySatisfied {
        composition: QcsdSlotComposition,
        reason: QcsdCongestionReason,
    },
    /// No defense-owned datagram was legal at the one-shot attempt boundary.
    Suppressed {
        composition: QcsdSlotComposition,
        reason: QcsdCongestionReason,
    },
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
    /// One complete incoming event was handed to the shared receive-credit
    /// controller.
    ///
    /// This is deliberately distinct from [`Self::Resolved`]: requesting
    /// receive credit does not prove that the peer produced the scheduled
    /// bytes. The terminal outcome arrives only after consumption or an
    /// explicit impossibility/retirement failure.
    ReceiveCreditRequested { packet: Packet },
    /// A candidate defense's incoming event received its controller slot.
    ///
    /// This slot-bearing signal is opt-in and does not replace the established
    /// [`Self::ReceiveCreditRequested`] observation delivered to legacy
    /// defenses. It lets a client-only defense keep local advertisement and
    /// eventual peer-consumption outcomes causally distinct.
    IncomingCreditScheduled { slot: QcsdSlotId, packet: Packet },
    /// Every receive-limit action belonging to one incoming event was encoded
    /// on the local wire.
    ///
    /// This is the local opportunity realization boundary. It deliberately
    /// does not imply that the peer produced or the client consumed any of the
    /// scheduled response bytes.
    IncomingCreditAdvertised { slot: QcsdSlotId, packet: Packet },
    /// Exact consumed raw STREAM offsets attributed to defense-owned work.
    ///
    /// This includes overlap with previously advertised scheduled ranges and
    /// actual parser-lease bytes debited against an existing same-stream
    /// scheduling claim. Merely encoding a parser lease cannot consume work;
    /// unowned lease bytes and the initial stream allowance are excluded. This
    /// is an internal credit-ledger signal, not a payload-provenance claim.
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
    /// Whether any client STREAM frame remains pending across all endpoints.
    EgressBacklog { pending: bool },
    /// A previously emitted event reached a terminal outcome.
    Resolved {
        packet: Packet,
        outcome: EventOutcome,
    },
    /// Terminal incoming-credit result for a defense that opted into the split
    /// local-advertisement/peer-consumption lifecycle.
    IncomingCreditResolved {
        slot: QcsdSlotId,
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

/// Allocation contract attached to one causal Walkie-Talkie receive
/// continuation event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverContinuationDisposition {
    /// Exact size of the whole continuation cell.
    pub cell_bytes: u64,
    /// Maximum advertised raw prefix that may still count as pristine for the
    /// prepared receiver-liveness contract.
    pub parser_ceiling_bytes: u64,
}

/// Capacity visible to a defense after controller-private reservations have
/// been removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityAdjustment {
    /// Exact chaff response capacity protected from ordinary allocation.
    pub reserved_chaff_bytes: u64,
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

/// One versioned `CS-BuFLO` rate-estimator decision.
///
/// The live client-only adaptation deliberately advances its byte boundary on
/// real-bearing traffic, while the pinned bilateral author prototype advances
/// on every transmitted real-or-junk write.  Keeping every decision in the
/// terminal artifact makes that translation auditable instead of inferring it
/// from only the final interval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CsBufloRateTransitionDiagnostics {
    /// Transition-record schema, versioned independently of run/config schemas.
    pub schema_version: u32,
    /// `outgoing` or `incoming` at the client observation boundary.
    pub direction: &'static str,
    /// Defense-relative time at which the byte boundary was processed.
    pub at_us: u64,
    /// Doubling boundary which triggered this decision.
    pub boundary_bytes: u64,
    /// Live real-bearing byte counter at the decision.
    pub real_bearing_bytes: u64,
    /// Eligible direction-specific timing samples before the window was cleared.
    pub eligible_samples: u64,
    /// Upper median, or null when the current rate had to be retained.
    pub median_interval_us: Option<u64>,
    /// Interval in force before the decision.
    pub previous_interval_us: u64,
    /// Floored, clamped interval selected by the decision.
    pub resulting_interval_us: u64,
    /// Whether no eligible sample existed and the prior interval was retained.
    pub retained_current_interval: bool,
}

/// Defense-specific counters recorded with the terminal run artifact.
#[derive(Debug, Default, Eq, PartialEq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the terminal artifact intentionally flattens independent fidelity predicates"
)]
pub struct DefenseDiagnostics {
    /// Incoming schedule bytes handed to the shared receive-credit adapter.
    pub scheduled_incoming_requested_bytes: u64,
    /// Scheduled receive-credit bytes currently or terminally attributed to
    /// locally encoded offsets. Retried parser ownership is de-attributed
    /// before replacement credit is encoded, so this is not a cumulative wire
    /// byte counter.
    pub scheduled_incoming_advertised_bytes: u64,
    /// Scheduled receive-credit offsets actually consumed as response bytes.
    pub scheduled_incoming_consumed_bytes: u64,
    /// Scheduled offsets made impossible by an adapter failure or retirement.
    pub scheduled_incoming_retired_bytes: u64,
    /// Requested bytes that are neither consumed nor terminally retired.
    pub scheduled_incoming_unresolved_bytes: u64,
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
    /// Informational L1 distance between the aggregate incoming wire mixture
    /// (natural plus cover) and the configured incoming target distribution.
    ///
    /// The client-only ingress adapter realizes byte deficits on later chaff;
    /// this is not a same-datagram Traffic Morphing fidelity claim.
    pub morphing_ingress_wire_mixture_l1_ppm: u64,
    /// Number of padding events emitted by WTF-PAD.
    pub padding_events: u64,
    /// Whether WTF-PAD stopped at its configured event guard.
    pub padding_event_guard_triggered: bool,
    /// Desired incoming cover bytes emitted by the WTF-PAD automaton.
    pub wtf_pad_incoming_desired_bytes: u64,
    /// Total receive-credit bytes requested for desired incoming events,
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
    /// Whether `BuFLO` claims wire-equivalence to the original cooperating TCP design.
    pub buflo_paper_equivalent: bool,
    /// Whether `BuFLO` used only the client-side QCSD approximation.
    pub buflo_client_only: bool,
    /// `BuFLO` client-egress cells emitted into the controller.
    pub buflo_scheduled_outgoing_cells: u64,
    /// `BuFLO` incoming receive-credit cells emitted into the controller.
    pub buflo_scheduled_incoming_cells: u64,
    /// Exact-size `BuFLO` client-egress cells realized by transport.
    pub buflo_full_outgoing_cells: u64,
    /// Congestion-limited partial `BuFLO` client-egress cells (always an error).
    pub buflo_partial_outgoing_cells: u64,
    /// Suppressed `BuFLO` client-egress cells (always an error).
    pub buflo_suppressed_outgoing_cells: u64,
    /// Non-congestion `BuFLO` client-egress realization failures.
    pub buflo_missed_outgoing_cells: u64,
    /// Incoming `BuFLO` receive-credit cells that terminalized unsuccessfully.
    pub buflo_missed_incoming_cells: u64,
    /// Outgoing cells emitted at least one full rho interval after their target time.
    pub buflo_catch_up_outgoing_cells: u64,
    /// Incoming cells emitted at least one full rho interval after their target time.
    pub buflo_catch_up_incoming_cells: u64,
    /// Emitted outgoing cells that have not terminalized.
    pub buflo_outgoing_unresolved_cells: u64,
    /// Emitted incoming cells that have not terminalized.
    pub buflo_incoming_unresolved_cells: u64,
    /// Latest aggregate client STREAM backlog state.
    pub buflo_egress_backlog_pending: bool,
    /// Whether the application-complete signal was observed.
    pub buflo_application_complete: bool,
    /// Pending reviewed-chaff requests discarded at an ineligible terminal sub-cell tail.
    pub buflo_terminal_subcell_pending_request_cancellations: u64,
    /// Open reviewed-chaff streams canceled at an ineligible terminal sub-cell tail.
    pub buflo_terminal_subcell_stream_cancellations: u64,
    /// Exact raw receive capacity left across the canceled sub-cell tail streams.
    pub buflo_terminal_subcell_exact_capacity_bytes_cancelled: u64,
    /// Whether the first eligible post-tau sub-cell terminal boundary latched.
    pub buflo_terminal_subcell_latched: bool,
    /// Controller elapsed time at the terminal sub-cell latch.
    pub buflo_terminal_subcell_latched_at_us: u64,
    /// Open reviewed-chaff streams present at the terminal sub-cell latch.
    pub buflo_terminal_subcell_open_streams_at_latch: u64,
    /// Parser-lease bytes still live at the terminal sub-cell latch (must be zero).
    pub buflo_terminal_subcell_parser_lease_bytes_at_latch: u64,
    /// Pending parser boundaries across all roles at the terminal sub-cell latch.
    /// Nonzero values are permitted only for reviewed chaff streams canceled
    /// by the typed terminal-tail transition.
    pub buflo_terminal_subcell_pending_parser_boundaries_at_latch: u64,
    /// Pending application parser boundaries at the terminal sub-cell latch
    /// (must be zero; application parsing is never cancellable defense work).
    pub buflo_terminal_subcell_pending_application_parser_boundaries_at_latch: u64,
    /// Whether the configured minimum duration was reached.
    pub buflo_minimum_duration_reached: bool,
    /// Whether the QCSD-only `BuFLO` event guard stopped the schedule.
    pub buflo_event_guard_triggered: bool,
    /// Whether `CS-BuFLO` claims wire-equivalence to the cooperating TCP design.
    pub cs_buflo_paper_equivalent: bool,
    /// Whether `CS-BuFLO` used only the client-side QCSD approximation.
    pub cs_buflo_client_only: bool,
    /// True for the CPSP payload-padding ablation.
    pub cs_buflo_payload_padding: bool,
    /// True for the CTSP total-padding variant.
    pub cs_buflo_total_padding: bool,
    /// `CS-BuFLO` client-egress cells emitted into the controller.
    pub cs_buflo_scheduled_outgoing_cells: u64,
    /// `CS-BuFLO` incoming receive-credit cells emitted into the controller.
    pub cs_buflo_scheduled_incoming_cells: u64,
    /// Full-size congestion-sensitive egress attempts.
    pub cs_buflo_full_outgoing_cells: u64,
    /// Smaller congestion-limited egress attempts that crossed the wire.
    pub cs_buflo_partial_outgoing_cells: u64,
    /// Congestion-sensitive attempts that emitted no defense-owned datagram.
    pub cs_buflo_suppressed_outgoing_cells: u64,
    /// Outgoing cells that failed for a non-congestion adapter reason.
    pub cs_buflo_missed_outgoing_cells: u64,
    /// Incoming receive-credit attempts that terminalized unsuccessfully.
    pub cs_buflo_missed_incoming_cells: u64,
    /// Sum of desired UDP bytes over terminal `CS-BuFLO` egress attempts.
    pub cs_buflo_desired_udp_bytes: u64,
    /// Sum of realized UDP bytes over terminal `CS-BuFLO` egress attempts.
    pub cs_buflo_realized_udp_bytes: u64,
    /// Application STREAM bytes carried by realized `CS-BuFLO` datagrams.
    pub cs_buflo_application_stream_bytes: u64,
    /// Retransmitted application or reviewed-chaff STREAM bytes in realized attempts.
    pub cs_buflo_retransmission_stream_bytes: u64,
    /// Fresh reviewed-chaff STREAM bytes carried by realized `CS-BuFLO` datagrams.
    pub cs_buflo_chaff_stream_bytes: u64,
    /// Defense-owned scheduled PING and `MAX_STREAM_DATA` bytes.
    pub cs_buflo_defense_control_bytes: u64,
    /// QUIC PADDING bytes carried by realized `CS-BuFLO` datagrams.
    pub cs_buflo_quic_padding_bytes: u64,
    /// Remaining headers, authentication, ACK, and other QUIC bytes.
    pub cs_buflo_other_quic_bytes: u64,
    /// Sum of release-to-attempt delay over realized egress attempts.
    pub cs_buflo_lateness_us_total: u64,
    /// Largest release-to-attempt delay.
    pub cs_buflo_lateness_us_max: u64,
    /// Unique natural request STREAM bytes observed by the controller.
    pub cs_buflo_natural_outgoing_bytes: u64,
    /// Raw response request-stream offsets consumed by HTTP/3.
    pub cs_buflo_natural_incoming_bytes: u64,
    /// Reviewed-chaff STREAM bytes transmitted in the outgoing direction.
    pub cs_buflo_cover_outgoing_bytes: u64,
    /// Reviewed-chaff response STREAM bytes consumed by the client.
    pub cs_buflo_cover_incoming_bytes: u64,
    /// Incoming scheduled-credit bytes terminally observed by the client-only adapter.
    pub cs_buflo_realized_incoming_credit_bytes: u64,
    /// Frozen outgoing natural-byte input to the padding-target calculation.
    pub cs_buflo_outgoing_padding_basis_natural_bytes: u64,
    /// Frozen incoming natural-byte input to the padding-target calculation.
    pub cs_buflo_incoming_padding_basis_natural_bytes: u64,
    /// Frozen outgoing cover-byte input to the padding-target calculation.
    pub cs_buflo_outgoing_padding_basis_cover_bytes: u64,
    /// Frozen incoming cover-byte input to the padding-target calculation.
    pub cs_buflo_incoming_padding_basis_cover_bytes: u64,
    /// Frozen outgoing realized-UDP input to CTSP's total-padding calculation.
    pub cs_buflo_outgoing_padding_basis_total_bytes: u64,
    /// Frozen incoming realized-credit approximation (payload mode is mandatory).
    pub cs_buflo_incoming_padding_basis_total_bytes: u64,
    /// Live early-termination mapping identifier.
    pub cs_buflo_early_termination_semantics: &'static str,
    /// Version of the client-only stop-then-drain early-termination translation.
    pub cs_buflo_early_termination_translation_version: u32,
    /// Client-only policy used to stop new opportunities and drain advertised credit.
    pub cs_buflo_termination_stop_policy: &'static str,
    /// Source-study socket write size retained only as comparison metadata.
    pub cs_buflo_reference_tcp_write_size_bytes: u64,
    /// Source-study nominal IPv4/TCP packet size retained only as metadata.
    pub cs_buflo_reference_nominal_tcp_packet_size_bytes: u64,
    /// Configured live QUIC UDP-payload target.
    pub cs_buflo_runtime_udp_packet_size_bytes: u64,
    /// Client-egress observed UDP bytes used by the crossing predicate.
    pub cs_buflo_outgoing_termination_accounted_bytes: u64,
    /// Client-ingress realized-credit bytes used by the crossing approximation.
    pub cs_buflo_incoming_termination_accounted_bytes: u64,
    /// Actual observed UDP increment of the latest realized egress opportunity.
    pub cs_buflo_outgoing_last_termination_increment_bytes: u64,
    /// Actual realized-credit increment of the latest ingress opportunity.
    pub cs_buflo_incoming_last_termination_increment_bytes: u64,
    /// Whether the latest realized egress increment crossed a power-of-two boundary.
    pub cs_buflo_outgoing_power_of_two_crossed: bool,
    /// Whether the latest ingress-credit increment crossed a power-of-two boundary.
    pub cs_buflo_incoming_power_of_two_crossed: bool,
    /// Whether outgoing opportunities have entered the terminal drain phase.
    pub cs_buflo_outgoing_termination_stop_latched: bool,
    /// Whether incoming opportunities have entered the terminal drain phase.
    pub cs_buflo_incoming_termination_stop_latched: bool,
    /// Outgoing reason which initiated terminal drain, or empty before a latch.
    pub cs_buflo_outgoing_termination_stop_reason: &'static str,
    /// Incoming reason which initiated terminal drain, or empty before a latch.
    pub cs_buflo_incoming_termination_stop_reason: &'static str,
    /// Outgoing phase in which terminal drain began, or empty before a latch.
    pub cs_buflo_outgoing_termination_stop_phase: &'static str,
    /// Incoming phase in which terminal drain began, or empty before a latch.
    pub cs_buflo_incoming_termination_stop_phase: &'static str,
    /// Outgoing controller elapsed time at the terminal-drain latch.
    pub cs_buflo_outgoing_termination_stop_latched_at_us: u64,
    /// Incoming controller elapsed time at the terminal-drain latch.
    pub cs_buflo_incoming_termination_stop_latched_at_us: u64,
    /// Outgoing opportunities scheduled when terminal drain began.
    pub cs_buflo_outgoing_termination_stop_scheduled_cells_at_stop: u64,
    /// Incoming opportunities scheduled when terminal drain began.
    pub cs_buflo_incoming_termination_stop_scheduled_cells_at_stop: u64,
    /// Outgoing opportunities terminal when terminal drain began.
    pub cs_buflo_outgoing_termination_stop_terminal_cells_at_stop: u64,
    /// Incoming opportunities terminal when terminal drain began.
    pub cs_buflo_incoming_termination_stop_terminal_cells_at_stop: u64,
    /// Outgoing padding-policy progress at the terminal-drain latch.
    pub cs_buflo_outgoing_termination_stop_progress_bytes_at_stop: u64,
    /// Incoming padding-policy progress at the terminal-drain latch.
    pub cs_buflo_incoming_termination_stop_progress_bytes_at_stop: u64,
    /// Outgoing frozen padding target at the terminal-drain latch.
    pub cs_buflo_outgoing_termination_stop_padding_target_bytes_at_stop: u64,
    /// Incoming frozen padding target at the terminal-drain latch.
    pub cs_buflo_incoming_termination_stop_padding_target_bytes_at_stop: u64,
    /// Outgoing accounted-byte total at the crossing that initiated terminal drain.
    pub cs_buflo_outgoing_termination_stop_crossing_total_bytes: u64,
    /// Incoming accounted-byte total at the crossing that initiated terminal drain.
    pub cs_buflo_incoming_termination_stop_crossing_total_bytes: u64,
    /// Outgoing observed increment that crossed the terminal-drain boundary.
    pub cs_buflo_outgoing_termination_stop_crossing_increment_bytes: u64,
    /// Incoming observed increment that crossed the terminal-drain boundary.
    pub cs_buflo_incoming_termination_stop_crossing_increment_bytes: u64,
    /// Number of outgoing provisional stop receipts invalidated before final termination.
    pub cs_buflo_outgoing_termination_stop_provisional_invalidation_count: u64,
    /// Number of incoming provisional stop receipts invalidated before final termination.
    pub cs_buflo_incoming_termination_stop_provisional_invalidation_count: u64,
    /// Fresh outgoing application STREAM bytes used by the adaptive boundary.
    pub cs_buflo_real_bearing_outgoing_bytes: u64,
    /// Client-only incoming real-bearing byte approximation.
    pub cs_buflo_real_bearing_incoming_bytes: u64,
    /// Frozen outgoing CPSP/CTSP completion target.
    pub cs_buflo_outgoing_padding_target_bytes: u64,
    /// Frozen client-only incoming completion target.
    pub cs_buflo_incoming_padding_target_bytes: u64,
    /// Current client-egress adaptive interval.
    pub cs_buflo_outgoing_interval_us: u64,
    /// Current client-ingress approximation interval.
    pub cs_buflo_incoming_interval_us: u64,
    /// Completed outgoing power-of-two rate adaptations.
    pub cs_buflo_outgoing_rate_adaptations: u64,
    /// Completed incoming approximation rate adaptations.
    pub cs_buflo_incoming_rate_adaptations: u64,
    /// Version of the live-vs-author rate-boundary translation contract.
    pub cs_buflo_rate_boundary_translation_version: u32,
    /// Live counter used to trigger rate decisions.
    pub cs_buflo_rate_boundary_counter_semantics: &'static str,
    /// Counter used by the pinned bilateral author implementation.
    pub cs_buflo_author_rate_boundary_counter_semantics: &'static str,
    /// Every rate-estimator decision in causal order.
    pub cs_buflo_rate_transitions: Vec<CsBufloRateTransitionDiagnostics>,
    /// Outgoing opportunities armed after the adaptive interval reached its configured minimum.
    pub cs_buflo_outgoing_minimum_interval_opportunities: u64,
    /// Incoming opportunities armed after the adaptive interval reached its configured minimum.
    pub cs_buflo_incoming_minimum_interval_opportunities: u64,
    /// Incoming minimum-interval opportunities fully advertised on the local wire.
    pub cs_buflo_incoming_minimum_interval_local_realized: u64,
    /// Terminal outgoing opportunities that were armed at the configured minimum interval.
    pub cs_buflo_outgoing_minimum_interval_terminal: u64,
    /// Terminal incoming opportunities that were armed at the configured minimum interval.
    pub cs_buflo_incoming_minimum_interval_terminal: u64,
    /// Full outgoing datagrams among opportunities armed at the configured minimum interval.
    pub cs_buflo_outgoing_minimum_interval_full: u64,
    /// Fully consumed incoming credits armed at the configured minimum interval.
    pub cs_buflo_incoming_minimum_interval_full: u64,
    /// Incoming opportunities fully advertised on the local wire.
    pub cs_buflo_incoming_local_realized_cells: u64,
    /// Next outgoing real-bearing byte boundary.
    pub cs_buflo_next_outgoing_adaptation_boundary_bytes: u64,
    /// Next incoming approximation byte boundary.
    pub cs_buflo_next_incoming_adaptation_boundary_bytes: u64,
    /// Eligible outgoing IAT samples retained after the latest separator/adaptation.
    pub cs_buflo_outgoing_estimator_samples: u64,
    /// Eligible incoming IAT samples retained after the latest separator/adaptation.
    pub cs_buflo_incoming_estimator_samples: u64,
    /// Emitted outgoing cells that have not terminalized.
    pub cs_buflo_outgoing_unresolved_cells: u64,
    /// Emitted incoming cells that have not terminalized.
    pub cs_buflo_incoming_unresolved_cells: u64,
    /// Latest aggregate client STREAM backlog state.
    pub cs_buflo_egress_backlog_pending: bool,
    /// Whether the application-complete signal was observed.
    pub cs_buflo_application_complete: bool,
    /// Whether the required quiet period was reached.
    pub cs_buflo_quiet_time_reached: bool,
    /// Whether CS-BuFLO irreversibly entered its client-local termination state.
    pub cs_buflo_local_termination_latched: bool,
    /// Monotonic microsecond at which client-local termination irreversibly latched.
    pub cs_buflo_local_et_latched_at_us: u64,
    /// Real outgoing application bytes observed after local termination.
    pub cs_buflo_post_local_et_natural_outgoing_bytes: u64,
    /// Real incoming application bytes observed after local termination.
    pub cs_buflo_post_local_et_natural_incoming_bytes: u64,
    /// Queued chaff requests discarded at the local termination boundary.
    pub cs_buflo_local_et_pending_request_cancellations: u64,
    /// Open chaff request streams explicitly canceled at the local termination boundary.
    pub cs_buflo_local_et_stream_cancellations: u64,
    /// Whether local early termination latched before the client onLoad analogue.
    pub cs_buflo_local_et_before_application_complete: bool,
    /// Open application receive streams handed back to ordinary Neqo flow control.
    pub cs_buflo_local_et_application_receive_streams_handed_off: u64,
    /// Retained application parser boundaries transferred to ordinary Neqo flow control.
    pub cs_buflo_local_et_application_parser_boundaries_handed_off: u64,
    /// Remaining advertised unowned parser-lease bytes transferred at local termination.
    pub cs_buflo_local_et_application_parser_lease_bytes_handed_off: u64,
    /// Live endpoints whose application send shaping was released by a pre-onLoad handoff.
    /// Post-onLoad retransmission cleanup is deliberately excluded.
    pub cs_buflo_local_et_application_send_endpoints_released: u64,
    /// Whether the QCSD-only `CS-BuFLO` event guard stopped the schedule.
    pub cs_buflo_event_guard_triggered: bool,
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
    /// Pure preview of the next deterministic outgoing event which may be
    /// staged before release and retracted before it is emitted.
    ///
    /// The preview must remain identical until either [`Self::next_event`]
    /// returns it or the defense becomes terminal. Previewing must not advance
    /// schedule state or diagnostics.
    fn next_outgoing_prearm(&self) -> Option<Packet> {
        None
    }
    /// Snapshot a fixed schedule whose outgoing targets may be staged before release.
    ///
    /// Returning `None` preserves ordinary due-time generation. Implementations
    /// opting in must return the exact global order subsequently produced by
    /// [`Self::next_event`]. The controller keeps future incoming events private
    /// until their timestamps are due.
    fn fixed_schedule_snapshot(&self) -> Option<Vec<Packet>> {
        None
    }
    /// Whether the most recently returned incoming event must be assigned
    /// whole to one pristine controlled chaff stream.
    ///
    /// The controller queries this immediately after [`Self::next_event`].
    /// Ordinary receive events may be fragmented across streams and may use
    /// bounded claims. A receiver-continuation event uses neither behavior:
    /// the controller holds it until one pristine chaff stream has exact
    /// capacity for the complete cell.
    fn last_incoming_event_receiver_continuation(&self) -> Option<ReceiverContinuationDisposition> {
        None
    }
    /// Whether the current incoming component still requires a dedicated
    /// receiver-continuation stream. The controller queries this before base
    /// allocation so the candidate cannot be consumed before the held event is
    /// emitted.
    fn pending_receiver_continuation(&self) -> Option<ReceiverContinuationDisposition> {
        None
    }
    /// Whether a causally tagged receiver-continuation event must remain
    /// queued until its pristine peer-acknowledged stream precondition exists.
    ///
    /// This is an explicit exception to the generic drop-unsatisfied switch,
    /// used only by the established Walkie-Talkie continuation protocol. It
    /// does not weaken exact-window BuFLO/CS-BuFLO incoming opportunities.
    fn retain_causal_incoming_until_ready(&self) -> bool {
        false
    }
    /// Whether the controller must provision one initial chaff-request batch
    /// to its configured stream limit before due outgoing targets are
    /// dispatched, then permanently disable application-level replenishment.
    ///
    /// Transport retransmission of that initial batch remains transport-owned.
    /// Defenses returning `false` retain the ordinary low-watermark replenisher.
    fn preprovision_chaff_once_to_stream_limit(&self) -> bool {
        false
    }
    /// Whether ordinary base allocation may use only peer-ACK-activated chaff.
    /// Application streams and other defenses retain their existing behavior.
    fn base_chaff_requires_peer_acknowledgment(&self) -> bool {
        false
    }
    /// Number of distinct pristine activated streams that must be protected
    /// for every nonzero incoming component remaining in the fixed schedule.
    fn receiver_continuation_reserve_horizon(&self) -> usize {
        0
    }
    /// Maximum reserve horizon across the complete fixed schedule.
    fn max_receiver_continuation_reserve_horizon(&self) -> usize {
        0
    }
    /// Exact continuation-cell size used for static controller preflight.
    fn receiver_continuation_cell_bytes(&self) -> Option<u64> {
        None
    }
    /// Observe controller-private capacity withheld from ordinary scheduling.
    fn observe_capacity_adjustment(&mut self, _adjustment: CapacityAdjustment) {}
    /// Time of the next event relative to defense start.
    fn next_event_at(&self) -> Option<Duration>;
    /// Whether no events remain.
    fn is_complete(&self) -> bool;
    /// Whether this defense can prove that it will never emit another
    /// incoming event.
    ///
    /// Dynamic defenses conservatively inherit whole-schedule completion.
    /// Fixed schedules may report this earlier while outgoing events remain.
    fn is_incoming_complete(&self) -> bool {
        self.is_complete()
    }
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
    /// Describe an unrecoverable defense realization failure.
    ///
    /// The controller and runner use this prompt to abort immediately after
    /// reducing the observation that made further realization impossible.
    /// Finite schedule completion is not a failure and returns `None`.
    fn terminal_failure(&self) -> Option<&'static str> {
        None
    }
    /// How application traffic participates in the schedule.
    fn mode(&self) -> DefenseMode;
    /// Transport realization policy for outgoing schedule events.
    fn outgoing_send_policy(&self) -> QcsdSendPolicy {
        QcsdSendPolicy::Exact
    }
    /// Whether each incoming credit opportunity must be allocated as one exact
    /// action inside its single controller window without fragmentation or retry.
    ///
    /// Legacy and burst-molding defenses retain their established retry
    /// semantics. Constant-rate `BuFLO` variants override this because carrying
    /// a residual allocation into a later cadence would falsely report one
    /// exact cell. Peer consumption can occur after the window and remains
    /// separately accounted because a client-only adapter has no authority
    /// over server packet timing.
    fn incoming_slot_must_resolve_in_window(&self) -> bool {
        false
    }
    /// Whether incoming events use slot-bearing local-advertisement and
    /// eventual-consumption signals.
    ///
    /// This remains disabled by default so established defenses retain their
    /// exact observation stream and terminal behavior.
    fn split_incoming_credit_lifecycle(&self) -> bool {
        false
    }
    /// Whether terminal completion must wait for candidate-defense chaff
    /// requests to leave both the controller queue and chaff manager.
    ///
    /// This is scoped to the new constant-rate client-only adaptations so the
    /// established seven runtime identities retain their prior lifecycle.
    fn requires_terminal_chaff_drain(&self) -> bool {
        false
    }
    /// Whether the controller may open another reviewed-chaff request.
    ///
    /// Existing defenses retain the low-watermark replenisher. A defense that
    /// enters a natural terminal drain can close replenishment while keeping
    /// already-open and pending chaff in its backlog until those streams end.
    fn accepts_new_chaff_requests(&self) -> bool {
        true
    }
    /// Exact chaff receive capacity required for one more terminal-drain
    /// schedule event.
    ///
    /// When replenishment has closed, an open reviewed-chaff stream is useful
    /// to the defense schedule only while it can carry another whole incoming
    /// event. Returning a byte floor lets the controller stop at that first
    /// ineligible boundary. The defense must then expose a typed terminal
    /// cancellation reason or otherwise keep the stream open as a completion
    /// barrier. `None` retains the historical open-stream backlog rule.
    fn terminal_chaff_backlog_cell_bytes(&self) -> Option<u64> {
        None
    }
    /// Typed local reason attached to any terminal reviewed-chaff cleanup.
    fn terminal_chaff_cancellation_reason(&self) -> Option<QcsdChaffCancellationReason> {
        None
    }
    /// Whether outgoing reviewed-chaff STREAM payload is counted once per
    /// unique stream offset instead of once per wire transmission.
    ///
    /// CS-BuFLO's payload-padding counter models bytes handed to the socket;
    /// retransmission of an already-counted offset must therefore not advance
    /// its CPSP target. Other defenses retain their historical wire-observation
    /// semantics.
    fn deduplicate_chaff_payload_offsets(&self) -> bool {
        false
    }
    /// Whether unique application/chaff offset provenance survives response
    /// completion until endpoint teardown. CS-BuFLO needs this because a
    /// request retransmission can occur after its response stream finishes and
    /// must not re-enter either payload-padding basis.
    fn retain_stream_offset_provenance_after_close(&self) -> bool {
        false
    }
    /// Defense-specific counters for reproducibility and failure auditing.
    fn diagnostics(&self) -> DefenseDiagnostics {
        DefenseDiagnostics::default()
    }
}
