// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Typed QCSD trace output and scheduled-slot accounting.

#![expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the parent runner constructs these private-module trace records directly"
)]

use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write as _},
    path::Path,
    time::Instant,
};

use neqo_csdef::{
    Direction, EventOutcome, IncomingTerminalProcessWitness, MissedSlotReason, Packet,
    QcsdCongestionReason, QcsdController, QcsdEndpointId, QcsdObservation, QcsdSendPolicy,
    QcsdSlotComposition, QcsdSlotId, QcsdSlotOutcome, QcsdStreamId, TimestampedQcsdObservation,
};
use serde::Serialize;
use serde_json::Value;

use super::Error;

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingSlot {
    pub(super) endpoint: QcsdEndpointId,
    pub(super) packet: Packet,
    /// First adapter action issued for this logical scheduled slot.
    pub(super) action_time_us: u64,
    /// First whole-slot local-realisation boundary, once all original
    /// fan-out children have advertised their credit.
    pub(super) credit_advertised_at_us: Option<u64>,
    /// Latest original fan-out advertisement while that whole-slot boundary
    /// remains incomplete.  This becomes `credit_advertised_at_us` exactly
    /// once, when the controller first reports local realisation.
    credit_advertisement_candidate_at_us: Option<u64>,
}

pub(super) struct PacketTraceRow<'a> {
    pub(super) now: Instant,
    pub(super) endpoint: QcsdEndpointId,
    pub(super) direction: &'a str,
    pub(super) observed: usize,
    pub(super) scheduled: Option<u16>,
    pub(super) satisfaction: &'a str,
    pub(super) slot: Option<QcsdSlotId>,
    pub(super) qcsd: QcsdTraceColumns,
}

pub(super) struct ScheduleTraceRow<'a> {
    /// Terminal-event time used only when the slot had no registered action.
    pub(super) action_time_us: u64,
    pub(super) endpoint: Option<QcsdEndpointId>,
    pub(super) packet: Packet,
    pub(super) satisfaction: &'a str,
    pub(super) observed: Option<usize>,
    pub(super) miss_reason: &'a str,
    pub(super) slot: QcsdSlotId,
    pub(super) qcsd: QcsdTraceColumns,
    /// Exact controller terminal-resolution time relative to defense start.
    ///
    /// This is not an adapter-production, packet-emission, or trace-write
    /// timestamp. Every current runner schedule row must carry the exact
    /// `Duration at` used by the controller's terminal slot transition.
    pub(super) terminal_defense_elapsed_us: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScheduleTerminalSemantics {
    /// A scheduled opportunity reached its ordinary terminal boundary.
    OpportunityResolution,
    /// Run/endpoint teardown or typed adapter rejection explicitly cancelled
    /// a target that was still in the future. The typed missed reason remains
    /// in the historical `miss_reason` column; target and terminal timestamps
    /// prove chronology.
    FutureCancellation(MissedSlotReason),
}

/// Versioned nullable extension shared by packets/events/schedule traces.
///
/// The historical columns remain an exact prefix; absent metadata serializes
/// as empty fields so old prefix readers continue to work.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct QcsdTraceColumns {
    schema_version: Option<u8>,
    send_policy: Option<&'static str>,
    desired_udp_bytes: Option<u16>,
    observed_udp_bytes: Option<u16>,
    application_stream_bytes: Option<u16>,
    retransmission_stream_bytes: Option<u16>,
    chaff_stream_bytes: Option<u16>,
    defense_control_bytes: Option<u16>,
    quic_padding_bytes: Option<u16>,
    other_quic_bytes: Option<u16>,
    lateness_us: Option<u64>,
    congestion_reason: Option<&'static str>,
    credit_advertised_at_us: Option<u64>,
    credit_advertisement_delay_us: Option<u64>,
    /// Terminal reconciliation time for a fully consumed incoming credit.
    ///
    /// This is deliberately later and semantically distinct from the local
    /// `MAX_STREAM_DATA` advertisement boundary. It does not claim a server
    /// packet timestamp or server-side padding-complete signal.
    credit_consumed_at_us: Option<u64>,
    credit_consumption_delay_us: Option<u64>,
    /// Exact controller terminal-resolution time on the defense clock.
    /// Populated only for schedule rows; packet and event rows retain a blank
    /// nullable suffix for schema compatibility.
    terminal_defense_elapsed_us: Option<u64>,
}

impl QcsdTraceColumns {
    pub(super) const fn exact(desired_udp_bytes: u16, observed_udp_bytes: Option<u16>) -> Self {
        Self {
            schema_version: Some(1),
            send_policy: Some("exact"),
            desired_udp_bytes: Some(desired_udp_bytes),
            observed_udp_bytes,
            application_stream_bytes: None,
            retransmission_stream_bytes: None,
            chaff_stream_bytes: None,
            defense_control_bytes: None,
            quic_padding_bytes: None,
            other_quic_bytes: None,
            lateness_us: None,
            congestion_reason: None,
            credit_advertised_at_us: None,
            credit_advertisement_delay_us: None,
            credit_consumed_at_us: None,
            credit_consumption_delay_us: None,
            terminal_defense_elapsed_us: None,
        }
    }

    pub(super) const fn from_outcome(_packet: Packet, outcome: QcsdSlotOutcome) -> Self {
        match outcome {
            QcsdSlotOutcome::Full { composition } => Self::composition(composition, None),
            QcsdSlotOutcome::Partial {
                composition,
                reason,
            }
            | QcsdSlotOutcome::Suppressed {
                composition,
                reason,
            } => Self::composition(composition, Some(reason)),
        }
    }

    /// Attach the transport's packet-builder composition to a raw packet row.
    ///
    /// Scheduled rows retain their exact/congestion-sensitive policy and
    /// reason. Unscheduled maintenance and local-ET control packets are
    /// labelled explicitly instead of receiving an empty composition suffix.
    pub(super) fn with_built_composition(mut self, composition: QcsdSlotComposition) -> Self {
        self.schema_version = Some(2);
        self.send_policy = Some(self.send_policy.unwrap_or("unscheduled"));
        self.desired_udp_bytes = Some(composition.desired_udp_bytes);
        self.observed_udp_bytes = Some(composition.observed_udp_bytes);
        self.application_stream_bytes = Some(composition.application_stream_bytes);
        self.retransmission_stream_bytes = Some(composition.retransmission_stream_bytes);
        self.chaff_stream_bytes = Some(composition.chaff_stream_bytes);
        self.defense_control_bytes = Some(composition.defense_control_bytes);
        self.quic_padding_bytes = Some(composition.quic_padding_bytes);
        self.other_quic_bytes = Some(composition.other_quic_bytes);
        self.lateness_us = Some(composition.lateness_us);
        self
    }

    const fn composition(
        composition: QcsdSlotComposition,
        reason: Option<QcsdCongestionReason>,
    ) -> Self {
        Self {
            schema_version: Some(1),
            send_policy: Some("congestion_sensitive"),
            desired_udp_bytes: Some(composition.desired_udp_bytes),
            observed_udp_bytes: Some(composition.observed_udp_bytes),
            application_stream_bytes: Some(composition.application_stream_bytes),
            retransmission_stream_bytes: Some(composition.retransmission_stream_bytes),
            chaff_stream_bytes: Some(composition.chaff_stream_bytes),
            defense_control_bytes: Some(composition.defense_control_bytes),
            quic_padding_bytes: Some(composition.quic_padding_bytes),
            other_quic_bytes: Some(composition.other_quic_bytes),
            lateness_us: Some(composition.lateness_us),
            congestion_reason: match reason {
                Some(reason) => Some(congestion_reason(reason)),
                None => None,
            },
            credit_advertised_at_us: None,
            credit_advertisement_delay_us: None,
            credit_consumed_at_us: None,
            credit_consumption_delay_us: None,
            terminal_defense_elapsed_us: None,
        }
    }

    fn from_observation(
        observation: &QcsdObservation,
        terminal_slots: &HashMap<QcsdSlotId, Packet>,
    ) -> Self {
        match observation {
            QcsdObservation::SlotResolved {
                packet, outcome, ..
            } => Self::from_outcome(*packet, *outcome),
            QcsdObservation::SlotSatisfied {
                slot,
                observed_size,
                ..
            } => terminal_slots
                .get(slot)
                .map_or_else(Self::default, |packet| {
                    Self::exact(packet.length(), Some(*observed_size))
                }),
            _ => Self::default(),
        }
    }

    fn from_serialized_event(details: &Value) -> Self {
        if details.get("type").and_then(Value::as_str) != Some("send_packet") {
            return Self::default();
        }
        let policy = match details.get("send_policy").and_then(Value::as_str) {
            Some("congestion_sensitive") => QcsdSendPolicy::CongestionSensitive,
            _ => QcsdSendPolicy::Exact,
        };
        let desired = details
            .get("packet")
            .and_then(|packet| packet.get("length"))
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok());
        Self {
            schema_version: Some(1),
            send_policy: Some(match policy {
                QcsdSendPolicy::Exact => "exact",
                QcsdSendPolicy::CongestionSensitive => "congestion_sensitive",
            }),
            desired_udp_bytes: desired,
            ..Self::default()
        }
    }

    fn csv_suffix(self) -> String {
        fn number<T: ToString>(value: Option<T>) -> String {
            value.map_or_else(String::new, |value| value.to_string())
        }
        [
            number(self.schema_version),
            self.send_policy.unwrap_or_default().into(),
            number(self.desired_udp_bytes),
            number(self.observed_udp_bytes),
            number(self.application_stream_bytes),
            number(self.retransmission_stream_bytes),
            number(self.chaff_stream_bytes),
            number(self.defense_control_bytes),
            number(self.quic_padding_bytes),
            number(self.other_quic_bytes),
            number(self.lateness_us),
            self.congestion_reason.unwrap_or_default().into(),
            number(self.credit_advertised_at_us),
            number(self.credit_advertisement_delay_us),
            number(self.credit_consumed_at_us),
            number(self.credit_consumption_delay_us),
            number(self.terminal_defense_elapsed_us),
        ]
        .join(",")
    }
}

const fn congestion_reason(reason: QcsdCongestionReason) -> &'static str {
    match reason {
        QcsdCongestionReason::PacingLimited => "pacing_limited",
        QcsdCongestionReason::CongestionLimited => "congestion_limited",
    }
}

#[derive(Clone, Copy)]
enum BacklogTraceKind {
    Stream,
    Aggregate,
}

// Only the two fixed bool/u64 backlog records at the unattributed,
// controller-less runner snapshot boundary may postpone rendering.
// They still retain every original production and insertion identity.
#[derive(Clone, Copy)]
struct DeferredBacklogTraceDetails {
    kind: BacklogTraceKind,
    pending: bool,
    produced_monotonic_ns: u64,
    production_sequence: u64,
}

impl DeferredBacklogTraceDetails {
    fn from_record(record: &TimestampedQcsdObservation) -> Option<Self> {
        let (kind, pending) = match record.observation() {
            QcsdObservation::EgressStreamBacklog { pending } => {
                (BacklogTraceKind::Stream, *pending)
            }
            QcsdObservation::EgressBacklog { pending } => {
                (BacklogTraceKind::Aggregate, *pending)
            }
            _ => return None,
        };
        Some(Self {
            kind,
            pending,
            produced_monotonic_ns: record.produced_monotonic_ns(),
            production_sequence: record.sequence(),
        })
    }

    fn render(self) -> Result<String, Error> {
        let observation = match self.kind {
            BacklogTraceKind::Stream => QcsdObservation::EgressStreamBacklog {
                pending: self.pending,
            },
            BacklogTraceKind::Aggregate => QcsdObservation::EgressBacklog {
                pending: self.pending,
            },
        };
        observation_trace_details(
            &observation,
            self.produced_monotonic_ns,
            self.production_sequence,
        )
    }
}

// Original observation serializer and CSV quote escaping, shared by
// immediate records and terminal rendering of fixed backlog records.
fn observation_trace_details(
    observation: &QcsdObservation,
    produced_monotonic_ns: u64,
    production_sequence: u64,
) -> Result<String, Error> {
    let mut details = serde_json::to_value(observation)?;
    let Value::Object(fields) = &mut details else {
        return Err(Error::SlotInvariant(
            "serialized QCSD observation was not an object".into(),
        ));
    };
    fields.insert(
        "production_monotonic_ns".into(),
        Value::from(produced_monotonic_ns),
    );
    fields.insert("production_sequence".into(), Value::from(production_sequence));
    Ok(serde_json::to_string(&details)?.replace('"', "\"\""))
}

struct EventTraceRow {
    monotonic_ns: u64,
    production_sequence: Option<u64>,
    insertion_sequence: u64,
    connection: String,
    event: String,
    outcome: String,
    details: String,
    deferred_backlog_details: Option<DeferredBacklogTraceDetails>,
    qcsd: QcsdTraceColumns,
}

#[derive(Clone, Copy)]
struct PhysicalReceiveAdvertisement {
    absolute_limit: u64,
    handoff_ns: u64,
    production_ns: u64,
    production_sequence: u64,
}

pub(super) struct TraceFiles {
    packets: BufWriter<File>,
    events: BufWriter<File>,
    schedule: BufWriter<File>,
    start: Instant,
    event_rows: Vec<EventTraceRow>,
    /// Engineering-only allocation accounting. Disabled unless explicitly
    /// requested; never changes an event, controller action or trace row.
    trace_growth_diagnostics: bool,
    event_string_capacity_bytes: usize,
    next_event_sequence: u64,
    events_flushed: bool,
    pending_slots: HashMap<QcsdSlotId, PendingSlot>,
    incoming_target_limits: HashMap<QcsdSlotId, HashMap<(QcsdEndpointId, QcsdStreamId), u64>>,
    /// First successful physical coverage of each advancing receive frontier.
    /// Retain closed streams: legacy parser bytes can change scheduling owner
    /// later, but their original handoff cannot move to that later reduction.
    physical_receive_advertisements:
        HashMap<(QcsdEndpointId, QcsdStreamId), Vec<PhysicalReceiveAdvertisement>>,
    terminal_slots: HashMap<QcsdSlotId, Packet>,
    cs_incoming_process_witnesses_required: bool,
    cs_incoming_process_witnesses: HashMap<QcsdSlotId, IncomingTerminalProcessWitness>,
    buflo_fin_defense_origin_ns: Option<u64>,
    buflo_fin_raw_frontiers: HashMap<(QcsdEndpointId, QcsdStreamId), (u64, u64, u64)>,
    buflo_fin_peer_reads: HashMap<(QcsdEndpointId, QcsdStreamId), (u64, u64, u64, u64, u64, u64)>,
    buflo_fin_release_proofs: HashMap<u64, Value>,
    buflo_fin_replacement_counts: HashMap<u64, usize>,
    buflo_fin_consumed_slots: HashMap<QcsdSlotId, ()>,
    buflo_fin_pre_advertisements: HashMap<u64, Vec<(QcsdSlotId, Packet, u64, u64, u64, u64)>>,
}

impl TraceFiles {
    pub(super) fn new(output_dir: &Path, start: Instant) -> Result<Self, Error> {
        // Keep sustained 120-second constant-rate traces off the filesystem
        // hot path; candidate evidence is flushed explicitly before run.json.
        const TRACE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
        let mut packets = BufWriter::with_capacity(
            TRACE_BUFFER_BYTES,
            File::create(output_dir.join("packets.csv"))?,
        );
        writeln!(
            packets,
            "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction,slot_id,qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,congestion_reason,credit_advertised_at_us,credit_advertisement_delay_us,credit_consumed_at_us,credit_consumption_delay_us,terminal_defense_elapsed_us"
        )?;
        let mut events = BufWriter::with_capacity(
            TRACE_BUFFER_BYTES,
            File::create(output_dir.join("events.csv"))?,
        );
        writeln!(
            events,
            "monotonic_us,connection,event,outcome,details,qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,congestion_reason,credit_advertised_at_us,credit_advertisement_delay_us,credit_consumed_at_us,credit_consumption_delay_us,terminal_defense_elapsed_us"
        )?;
        let mut schedule = BufWriter::with_capacity(
            TRACE_BUFFER_BYTES,
            File::create(output_dir.join("schedule.csv"))?,
        );
        writeln!(
            schedule,
            "target_time_us,direction,size,connection,action_time_us,satisfaction,observed_size,miss_reason,slot_id,qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,congestion_reason,credit_advertised_at_us,credit_advertisement_delay_us,credit_consumed_at_us,credit_consumption_delay_us,terminal_defense_elapsed_us"
        )?;
        Ok(Self {
            packets,
            events,
            schedule,
            start,
            event_rows: Vec::new(),
            trace_growth_diagnostics: std::env::var_os("QCSD_TRACE_GROWTH_DIAGNOSTICS")
                .is_some_and(|value| value == "1"),
            event_string_capacity_bytes: 0,
            next_event_sequence: 0,
            events_flushed: false,
            pending_slots: HashMap::new(),
            incoming_target_limits: HashMap::new(),
            physical_receive_advertisements: HashMap::new(),
            terminal_slots: HashMap::new(),
            cs_incoming_process_witnesses_required: false,
            cs_incoming_process_witnesses: HashMap::new(),
            buflo_fin_defense_origin_ns: None,
            buflo_fin_raw_frontiers: HashMap::new(),
            buflo_fin_peer_reads: HashMap::new(),
            buflo_fin_release_proofs: HashMap::new(),
            buflo_fin_replacement_counts: HashMap::new(),
            buflo_fin_consumed_slots: HashMap::new(),
            buflo_fin_pre_advertisements: HashMap::new(),
        })
    }

    /// Hardwired by execute_run_inner for CS; no public flag or policy input.
    pub(super) fn require_cs_incoming_process_witnesses(&mut self) {
        self.cs_incoming_process_witnesses_required = true;
    }

    /// Bind the opaque controller-issued clock witness to the original trace
    /// owner before its independently timestamped, later action is serialized.
    pub(super) fn bind_cs_incoming_process_witness(
        &mut self,
        controller: &QcsdController,
        action: &neqo_csdef::QcsdAction,
        serialized_at: Instant,
    ) -> Result<(), Error> {
        if !self.cs_incoming_process_witnesses_required {
            return Ok(());
        }
        let neqo_csdef::QcsdAction::SlotSatisfied {
            endpoint,
            packet,
            slot,
        } = action
        else {
            return Ok(());
        };
        if packet.direction() != Direction::Incoming {
            return Ok(());
        }
        let witness = controller
            .incoming_terminal_process_witness(*slot)
            .ok_or_else(|| {
                Error::SlotInvariant(format!(
                    "incoming slot {} lacks an owned process-clock witness",
                    slot.0
                ))
            })?;
        let pending = self.pending_slots.get(slot).ok_or_else(|| {
            Error::SlotInvariant(format!(
                "incoming slot {} has no original trace owner",
                slot.0
            ))
        })?;
        let correct_outcome = matches!(witness.outcome(), EventOutcome::Satisfied { observed }
            if observed == packet.length());
        if witness.slot() != *slot
            || witness.packet() != *packet
            || pending.packet != *packet
            || self.pending_slot_endpoint(*slot) != *endpoint
            || witness.endpoint() != *endpoint
            || !correct_outcome
            || controller.terminal_slot_resolution_at(*slot) != Some(witness.terminal_at())
            || self.terminal_slots.contains_key(slot)
            || self.cs_incoming_process_witnesses.contains_key(slot)
            || witness.captured_at() < self.start
            || witness.captured_at() > serialized_at
        {
            return Err(Error::SlotInvariant(format!(
                "incoming slot {} process-clock witness identity/order differs",
                slot.0
            )));
        }
        let consumed_at_us = self.elapsed_us(witness.captured_at());
        if pending
            .credit_advertised_at_us
            .is_none_or(|advertised| consumed_at_us < advertised)
        {
            return Err(Error::SlotInvariant(format!(
                "incoming slot {} process-clock witness predates its advertisement",
                slot.0
            )));
        }
        let captured_ns = u64::try_from(
            witness.captured_at().duration_since(self.start).as_nanos(),
        )
        .map_err(|_| Error::SlotInvariant("incoming process-clock witness overflow".into()))?;
        let serialized_ns = u64::try_from(serialized_at.duration_since(self.start).as_nanos())
            .map_err(|_| {
                Error::SlotInvariant("incoming action serialization clock overflow".into())
            })?;
        self.event(serialized_at, *endpoint, "incoming_terminal_process_clock", "owned_resolution", &serde_json::json!({
            "schema_version": 1,
            "source": "native-owned-incoming-terminal-process-clock-v1",
            "slot": slot.0, "packet": packet, "endpoint": endpoint.map(|value| value.0),
            "captured_process_monotonic_ns": captured_ns,
            "serialized_process_monotonic_ns": serialized_ns,
            "controller_terminal_defense_elapsed_us": u64::try_from(witness.terminal_at().as_micros()).unwrap_or(u64::MAX),
            "observed_consumed_bytes": packet.length(),
        }))?;
        self.cs_incoming_process_witnesses.insert(*slot, witness);
        Ok(())
    }

    /// Bind the actual activation Instant, never a controller reduction delta.
    pub(super) fn bind_buflo_fin_permission_defense_start(
        &mut self,
        start: Instant,
    ) -> Result<(), Error> {
        let origin_ns = self.elapsed_ns(start);
        if self
            .buflo_fin_defense_origin_ns
            .is_some_and(|old| old != origin_ns)
        {
            return Err(Error::SlotInvariant(
                "FIN permission defense origin changed".into(),
            ));
        }
        self.buflo_fin_defense_origin_ns = Some(origin_ns);
        Ok(())
    }

    /// Capture live owner identity before the controller removes pending
    /// ranges. The post-reduction proof cannot manufacture this snapshot.
    pub(super) fn prepare_buflo_fin_permission_observation(
        &mut self,
        controller: &QcsdController,
        record: &TimestampedQcsdObservation,
    ) -> Result<(), Error> {
        if let QcsdObservation::ReceiveLimitAdvertised {
            endpoint,
            stream,
            absolute_limit,
            slot,
        } = record.observation()
            && controller.buflo_permission_accounting().is_some()
        {
            let owners = controller.pending_buflo_fin_permission_replacements(
                *endpoint,
                *stream,
                *absolute_limit,
                *slot,
            );
            if !owners.is_empty()
                && self
                    .buflo_fin_pre_advertisements
                    .insert(record.sequence(), owners)
                    .is_some()
            {
                return Err(Error::SlotInvariant(
                    "FIN permission pre-reduction observation replayed".into(),
                ));
            }
        }
        Ok(())
    }

    /// Explicitly synthetic metadata-only test seam. No transport proof,
    /// receive permission, raw capture, controller state or runtime is created.
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "test premises remain explicit and separate from runtime authority"
    )]
    pub(super) fn test_buflo_fin_permission_snapshot(
        &mut self,
        accounting: &neqo_csdef::BufloPermissionAccounting,
        witnesses: &HashMap<QcsdSlotId, neqo_csdef::IncomingCreditRealizationWitness>,
        owners: Vec<(QcsdSlotId, Packet, u64, u64, u64, u64)>,
        advertisements: Vec<(QcsdEndpointId, QcsdStreamId, u64, Instant, u64, u64)>,
        record: &TimestampedQcsdObservation,
        handoff: Option<Instant>,
    ) -> Result<(), Error> {
        if !owners.is_empty()
            && self
                .buflo_fin_pre_advertisements
                .insert(record.sequence(), owners)
                .is_some()
        {
            return Err(Error::SlotInvariant(
                "synthetic pre-owner fixture repeated a sequence".into(),
            ));
        }
        for (endpoint, stream, absolute_limit, at, production_ns, production_sequence) in
            advertisements
        {
            let handoff_ns = self.elapsed_ns(at);
            self.physical_receive_advertisements
                .entry((endpoint, stream))
                .or_default()
                .push(PhysicalReceiveAdvertisement {
                    absolute_limit,
                    handoff_ns,
                    production_ns,
                    production_sequence,
                });
        }
        self.reconcile_buflo_fin_permission_snapshot(accounting, witnesses, record, handoff)
    }

    pub(super) fn buflo_fin_permission_physical_summary(&self) -> Value {
        serde_json::json!({
            "schema_version": 1,
            "policy": "buflo-retained-owned-parser-demand-genuine-fin-permission-release-v1",
            "defense_start_monotonic_ns": self.buflo_fin_defense_origin_ns,
            "genuine_fin_release_records": self.buflo_fin_release_proofs.len(),
            "replacement_advertisement_partitions": self.buflo_fin_replacement_counts.values().sum::<usize>(),
            "timely_handoff_eventually_consumed_1200_slots": self.buflo_fin_consumed_slots.len(),
            "wire_datagram_constant_size_claim": false,
            "permission_is_received_data": false,
        })
    }

    /// Separate append-only proof for the prospective policy. In particular,
    /// the old first-advertisement latch cannot authenticate a replacement.
    #[expect(
        clippy::too_many_lines,
        reason = "the prospective release proof keeps every causal join explicit"
    )]
    fn reconcile_buflo_fin_permission(
        &mut self,
        controller: &QcsdController,
        record: &TimestampedQcsdObservation,
        handoff: Option<Instant>,
    ) -> Result<(), Error> {
        let Some(accounting) = controller.buflo_permission_accounting() else {
            return Ok(());
        };
        let witnesses: HashMap<_, _> =
            if matches!(record.observation(), QcsdObservation::BytesRead { .. }) {
                accounting
                    .releases
                    .iter()
                    .filter_map(|release| {
                        controller
                            .incoming_credit_realization_witness(release.slot)
                            .cloned()
                            .map(|witness| (release.slot, witness))
                    })
                    .collect()
            } else {
                HashMap::new()
            };
        self.reconcile_buflo_fin_permission_snapshot(&accounting, &witnesses, record, handoff)
    }

    /// The runtime wrapper supplies only genuine immutable controller snapshots.
    /// Factoring the checked reducer permits explicitly synthetic metadata tests
    /// without minting a transport witness or reaching csdef-private ledgers.
    #[expect(
        clippy::too_many_lines,
        reason = "the prospective release proof keeps every causal join explicit"
    )]
    fn reconcile_buflo_fin_permission_snapshot(
        &mut self,
        accounting: &neqo_csdef::BufloPermissionAccounting,
        witnesses: &HashMap<QcsdSlotId, neqo_csdef::IncomingCreditRealizationWitness>,
        record: &TimestampedQcsdObservation,
        handoff: Option<Instant>,
    ) -> Result<(), Error> {
        let fail = |message: &str| Error::SlotInvariant(format!("FIN permission proof: {message}"));
        let sequence = record.sequence();
        let produced_ns = record.produced_monotonic_ns();
        let pre_owners = self
            .buflo_fin_pre_advertisements
            .remove(&sequence)
            .unwrap_or_default();
        let mut replacement_partitions = Vec::new();
        match record.observation() {
            QcsdObservation::StreamOpened {
                endpoint, stream, ..
            } => {
                if self
                    .buflo_fin_raw_frontiers
                    .insert((*endpoint, *stream), (0, sequence, produced_ns))
                    .is_some()
                {
                    return Err(fail("request stream lifecycle was reused"));
                }
            }
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes,
            } => {
                let raw = self
                    .buflo_fin_raw_frontiers
                    .get_mut(&(*endpoint, *stream))
                    .ok_or_else(|| fail("raw read lacks opened stream"))?;
                if sequence <= raw.1 || produced_ns < raw.2 {
                    return Err(fail("raw read order regressed"));
                }
                raw.0 = raw
                    .0
                    .checked_add(*bytes)
                    .ok_or_else(|| fail("raw read overflow"))?;
                raw.1 = sequence;
                raw.2 = produced_ns;
                self.buflo_fin_peer_reads.remove(&(*endpoint, *stream));
            }
            QcsdObservation::PeerFinRead {
                endpoint,
                stream,
                final_size,
                encoded_receive_limit,
                manual_receive_limit,
                bytes_received,
                bytes_read,
                buffered_bytes,
            } => {
                let raw = self
                    .buflo_fin_raw_frontiers
                    .get(&(*endpoint, *stream))
                    .ok_or_else(|| fail("FIN read lacks opened stream"))?;
                if raw.0 != *final_size
                    || *bytes_read != *final_size
                    || *bytes_received != *final_size
                    || *buffered_bytes != 0
                    || encoded_receive_limit != manual_receive_limit
                    || *encoded_receive_limit < *final_size
                    || sequence <= raw.1
                    || produced_ns < raw.2
                    || self
                        .buflo_fin_peer_reads
                        .contains_key(&(*endpoint, *stream))
                {
                    return Err(fail(
                        "FIN read is stale, replayed, or differs from actual raw frontier",
                    ));
                }
                self.buflo_fin_peer_reads.insert(
                    (*endpoint, *stream),
                    (
                        *final_size,
                        *encoded_receive_limit,
                        sequence,
                        produced_ns,
                        raw.1,
                        raw.2,
                    ),
                );
            }
            _ => {}
        }
        for release in &accounting.releases {
            if self
                .buflo_fin_release_proofs
                .contains_key(&release.release_index)
            {
                continue;
            }
            if release.release_index
                != u64::try_from(self.buflo_fin_release_proofs.len()).unwrap_or(u64::MAX)
                || !matches!(record.observation(), QcsdObservation::StreamFinished { endpoint, stream, finish: neqo_csdef::QcsdStreamFinish::Fin }
                    if *endpoint == release.endpoint && *stream == release.stream)
            {
                return Err(fail("new release lacks its exact ordered FIN observation"));
            }
            let origin = self
                .buflo_fin_defense_origin_ns
                .ok_or_else(|| fail("actual defense start is unbound"))?;
            let target_ns = origin
                .checked_add(
                    release
                        .target_us
                        .checked_mul(1_000)
                        .ok_or_else(|| fail("target overflow"))?,
                )
                .ok_or_else(|| fail("target origin overflow"))?;
            let deadline_ns = origin
                .checked_add(
                    release
                        .deadline_us
                        .checked_mul(1_000)
                        .ok_or_else(|| fail("deadline overflow"))?,
                )
                .ok_or_else(|| fail("deadline origin overflow"))?;
            let proof = self
                .buflo_fin_peer_reads
                .get(&(release.endpoint, release.stream))
                .copied()
                .ok_or_else(|| fail("release lacks genuine raw-read FIN producer record"))?;
            if proof.0 != release.final_size
                || release.start != release.final_size
                || release.end != proof.1
                || release.start >= release.end
                || release.deadline_us.checked_sub(release.target_us) != Some(32_000)
                || release.fin_at_us < release.target_us
                || release.fin_at_us >= release.deadline_us
                || sequence <= proof.2
                || produced_ns < proof.3
                || produced_ns < target_ns
                || produced_ns >= deadline_ns
            {
                return Err(fail(
                    "release frontier, clock, or FIN producer order differs",
                ));
            }
            let original = self
                .physical_receive_advertisements
                .get(&(release.endpoint, release.stream))
                .and_then(|ads| {
                    ads.iter()
                        .rev()
                        .find(|ad| ad.production_sequence < proof.2)
                        .filter(|ad| {
                            ad.absolute_limit == proof.1
                                && ad.production_ns <= ad.handoff_ns
                                && ad.handoff_ns >= target_ns
                                && ad.handoff_ns < deadline_ns
                                && ad.handoff_ns <= proof.3
                        })
                })
                .copied()
                .ok_or_else(|| fail("released MAX lacks original physical coverage"))?;
            let details = serde_json::json!({
                "schema_version": 1, "policy": accounting.policy,
                "release": release, "defense_start_monotonic_ns": origin,
                "target_monotonic_ns": target_ns, "exclusive_deadline_monotonic_ns": deadline_ns,
                "last_raw_read_production_sequence": proof.4, "last_raw_read_production_monotonic_ns": proof.5,
                "peer_fin_read_production_sequence": proof.2, "peer_fin_read_production_monotonic_ns": proof.3,
                "stream_fin_production_sequence": sequence, "stream_fin_production_monotonic_ns": produced_ns,
                "original_max_production_sequence": original.production_sequence,
                "original_max_production_monotonic_ns": original.production_ns,
                "original_max_physical_handoff_monotonic_ns": original.handoff_ns,
            });
            self.event(
                Instant::now(),
                Some(release.endpoint),
                "buflo_fin_permission_release",
                "proved",
                &details,
            )?;
            self.buflo_fin_release_proofs
                .insert(release.release_index, details);
        }
        for release in &accounting.releases {
            let done = self
                .buflo_fin_replacement_counts
                .get(&release.release_index)
                .copied()
                .unwrap_or(0);
            if done > release.replacements.len() {
                return Err(fail("replacement history shrank"));
            }
            for (index, replacement) in release.replacements.iter().enumerate().skip(done) {
                let (endpoint, stream, start, end, reduced_at_us) = *replacement;
                let prior = self
                    .buflo_fin_release_proofs
                    .get(&release.release_index)
                    .ok_or_else(|| fail("replacement precedes proved release"))?;
                let fin_sequence = prior["stream_fin_production_sequence"]
                    .as_u64()
                    .ok_or_else(|| fail("missing FIN sequence"))?;
                let fin_ns = prior["stream_fin_production_monotonic_ns"]
                    .as_u64()
                    .ok_or_else(|| fail("missing FIN clock"))?;
                let target_ns = prior["target_monotonic_ns"]
                    .as_u64()
                    .ok_or_else(|| fail("missing target clock"))?;
                let deadline_ns = prior["exclusive_deadline_monotonic_ns"]
                    .as_u64()
                    .ok_or_else(|| fail("missing deadline clock"))?;
                let handoff_ns = handoff
                    .map(|value| self.elapsed_ns(value))
                    .ok_or_else(|| fail("replacement lacks socket handoff"))?;
                if !matches!(record.observation(), QcsdObservation::ReceiveLimitAdvertised { endpoint: actual_endpoint, stream: actual_stream, absolute_limit, .. }
                    if *actual_endpoint == endpoint && *actual_stream == stream && *absolute_limit >= end)
                    || endpoint != release.endpoint
                    || start >= end
                    || sequence <= fin_sequence
                    || produced_ns < fin_ns
                    || produced_ns > handoff_ns
                    || handoff_ns < target_ns
                    || handoff_ns >= deadline_ns
                    || reduced_at_us < release.fin_at_us
                    || reduced_at_us >= release.deadline_us
                {
                    return Err(fail(
                        "replacement is stale, cross-stream, or outside the original physical window",
                    ));
                }
                let owner = pre_owners
                    .iter()
                    .find(|owner| {
                        owner.0 == release.slot
                            && owner.1.direction() == Direction::Incoming
                            && owner.1.length() == 1_200
                            && owner.1.timestamp_us() == release.target_us
                            && owner.2 <= start
                            && end <= owner.3
                            && owner.4 <= start
                            && end <= owner.5
                    })
                    .ok_or_else(|| {
                        fail("replacement lacks exact pre-reduction pending owner/range")
                    })?;
                let advancing = self
                    .physical_receive_advertisements
                    .get(&(endpoint, stream))
                    .is_some_and(|ads| {
                        let previous = ads
                            .len()
                            .checked_sub(2)
                            .map(|index| ads[index].absolute_limit);
                        previous.is_none_or(|limit| limit == owner.4 && limit <= start)
                            && ads.last().is_some_and(|ad| {
                                ad.production_sequence == sequence
                                    && ad.production_ns == produced_ns
                                    && ad.handoff_ns == handoff_ns
                                    && ad.absolute_limit > owner.4
                                    && ad.absolute_limit >= end
                            })
                    });
                if !advancing {
                    return Err(fail(
                        "replacement does not advance the actual physical MAX history",
                    ));
                }
                replacement_partitions.push((release.slot, start, end));
                let prior_bytes: u64 = release.replacements[..=index]
                    .iter()
                    .map(|r| r.3 - r.2)
                    .sum();
                if prior_bytes > release.end - release.start {
                    return Err(fail("replacement exceeds the proved released extent"));
                }
                self.event(Instant::now(), Some(endpoint), "buflo_fin_permission_replacement", "physically_handed_off",
                    &serde_json::json!({"schema_version":1, "policy":accounting.policy,
                        "release_index":release.release_index, "replacement_index":index,
                        "slot":release.slot.0, "endpoint":endpoint.0, "stream":stream.0, "start":start, "end":end,
                        "production_sequence":sequence, "production_monotonic_ns":produced_ns,
                        "physical_handoff_monotonic_ns":handoff_ns, "controller_reduction_defense_elapsed_us":reduced_at_us,
                        "original_target_monotonic_ns":target_ns, "original_exclusive_deadline_monotonic_ns":deadline_ns,
                        "pre_reduction_owner_start":owner.2,"pre_reduction_owner_end":owner.3,
                        "pre_reduction_advertised_limit":owner.4,"pre_reduction_requested_limit":owner.5}))?;
                self.buflo_fin_replacement_counts
                    .insert(release.release_index, index + 1);
            }
        }
        for owner in pre_owners {
            let mut partitions: Vec<_> = replacement_partitions
                .iter()
                .filter(|p| p.0 == owner.0 && owner.2 <= p.1 && p.2 <= owner.3)
                .copied()
                .collect();
            partitions.sort_unstable_by_key(|p| (p.1, p.2));
            let mut next = owner.2;
            for partition in partitions {
                if partition.1 != next || partition.2 <= partition.1 {
                    return Err(fail(
                        "replacement partition overlaps or leaves an owner gap",
                    ));
                }
                next = partition.2;
            }
            if next != owner.3 {
                return Err(fail(
                    "pending owner was not fully represented by replacement proofs",
                ));
            }
        }
        if matches!(record.observation(), QcsdObservation::BytesRead { .. }) {
            let mut slots: Vec<_> = accounting.releases.iter().map(|r| r.slot).collect();
            slots.sort_unstable();
            slots.dedup();
            for slot in slots {
                if self.buflo_fin_consumed_slots.contains_key(&slot) {
                    continue;
                }
                let Some(witness) = witnesses.get(&slot) else {
                    continue;
                };
                let releases: Vec<_> = accounting
                    .releases
                    .iter()
                    .filter(|r| r.slot == slot)
                    .collect();
                let first = releases[0];
                let origin = self
                    .buflo_fin_defense_origin_ns
                    .ok_or_else(|| fail("consumption lacks actual defense origin"))?;
                let target_ns = origin
                    .checked_add(
                        first
                            .target_us
                            .checked_mul(1_000)
                            .ok_or_else(|| fail("target overflow"))?,
                    )
                    .ok_or_else(|| fail("target overflow"))?;
                let deadline_ns = origin
                    .checked_add(
                        first
                            .deadline_us
                            .checked_mul(1_000)
                            .ok_or_else(|| fail("deadline overflow"))?,
                    )
                    .ok_or_else(|| fail("deadline overflow"))?;
                let mut ranges = witness.ranges.clone();
                ranges.sort_unstable_by_key(|r| (r.endpoint, r.stream, r.start, r.end));
                let bytes = ranges
                    .iter()
                    .try_fold(0_u64, |sum, r| sum.checked_add(r.end.checked_sub(r.start)?));
                if witness.packet.direction() != Direction::Incoming
                    || witness.packet.length() != 1_200
                    || witness.requested != 1_200
                    || witness.advertised != 1_200
                    || witness.consumed != 1_200
                    || witness.retired != 0
                    || !witness.locally_realized
                    || bytes != Some(1_200)
                    || witness.packet.timestamp_us() != first.target_us
                    || ranges.windows(2).any(|p| {
                        p[0].endpoint == p[1].endpoint
                            && p[0].stream == p[1].stream
                            && p[0].end > p[1].start
                    })
                    || releases.iter().any(|r| {
                        r.target_us != first.target_us
                            || r.deadline_us != first.deadline_us
                            || r.replacements.iter().map(|p| p.3 - p.2).sum::<u64>()
                                != r.end - r.start
                            || self
                                .buflo_fin_replacement_counts
                                .get(&r.release_index)
                                .copied()
                                .unwrap_or(0)
                                != r.replacements.len()
                    })
                {
                    return Err(fail(
                        "same-cell eventual consumption is incomplete or retired",
                    ));
                }
                let mut physical = Vec::new();
                for range in ranges {
                    if range.start >= range.end {
                        return Err(fail("empty consumed range"));
                    }
                    let advertisement = self
                        .physical_receive_advertisements
                        .get(&(range.endpoint, range.stream))
                        .and_then(|ads| {
                            ads.iter().find(|ad| {
                                ad.absolute_limit >= range.end
                                    && ad.production_ns <= ad.handoff_ns
                                    && ad.handoff_ns >= target_ns
                                    && ad.handoff_ns < deadline_ns
                                    && ad.handoff_ns <= produced_ns
                            })
                        })
                        .ok_or_else(|| {
                            fail("actual consumed range lacks same-window physical permission")
                        })?;
                    physical.push(serde_json::json!({"endpoint":range.endpoint.0,"stream":range.stream.0,
                        "start":range.start,"end":range.end,"production_sequence":advertisement.production_sequence,
                        "production_monotonic_ns":advertisement.production_ns,"physical_handoff_monotonic_ns":advertisement.handoff_ns}));
                }
                self.event(Instant::now(), Some(first.endpoint), "buflo_fin_permission_cell_realization", "full_1200_actual_raw_consumed",
                    &serde_json::json!({"schema_version":1,"policy":accounting.policy,"slot":slot.0,
                        "requested_bytes":1200,"effective_advertised_bytes":1200,"consumed_bytes":1200,"retired_bytes":0,
                        "original_target_monotonic_ns":target_ns,"original_exclusive_deadline_monotonic_ns":deadline_ns,
                        "final_read_production_sequence":sequence,"final_read_production_monotonic_ns":produced_ns,
                        "ranges":physical,"gross_permission_is_not_data":true}))?;
                self.buflo_fin_consumed_slots.insert(slot, ());
            }
        }
        if let QcsdObservation::StreamFinished {
            endpoint, stream, ..
        } = record.observation()
        {
            self.buflo_fin_peer_reads.remove(&(*endpoint, *stream));
        }
        Ok(())
    }

    pub(super) fn elapsed_us(&self, now: Instant) -> u64 {
        u64::try_from(now.duration_since(self.start).as_micros()).unwrap_or(u64::MAX)
    }

    fn elapsed_ns(&self, now: Instant) -> u64 {
        u64::try_from(
            now.checked_duration_since(self.start)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX)
    }

    pub(super) fn packet(&mut self, row: &PacketTraceRow<'_>) -> Result<(), Error> {
        writeln!(
            self.packets,
            "{},{},{},{},{},{},{},{}",
            row.direction,
            self.elapsed_us(row.now),
            row.endpoint.0,
            row.observed,
            row.scheduled
                .map_or_else(String::new, |value| value.to_string()),
            row.satisfaction,
            row.slot
                .map_or_else(String::new, |value| value.0.to_string()),
            row.qcsd.csv_suffix(),
        )?;
        Ok(())
    }

    pub(super) fn register_slot(
        &mut self,
        now: Instant,
        endpoint: QcsdEndpointId,
        packet: Packet,
        slot: QcsdSlotId,
    ) -> Result<(), Error> {
        if packet.direction() != Direction::Outgoing {
            return Err(Error::SlotInvariant(format!(
                "incoming slot {} was registered without a receive-credit target",
                slot.0
            )));
        }
        if self.terminal_slots.contains_key(&slot) {
            return Err(Error::SlotInvariant(format!(
                "slot {} was registered after reaching a terminal state",
                slot.0
            )));
        }
        if self.pending_slots.contains_key(&slot) {
            return Err(Error::SlotInvariant(format!(
                "slot {} was registered in more than one action batch",
                slot.0
            )));
        }
        let action_time_us = self.elapsed_us(now);
        self.pending_slots.insert(
            slot,
            PendingSlot {
                endpoint,
                packet,
                action_time_us,
                credit_advertised_at_us: None,
                credit_advertisement_candidate_at_us: None,
            },
        );
        Ok(())
    }

    pub(super) fn register_incoming_action(
        &mut self,
        now: Instant,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        packet: Packet,
        slot: QcsdSlotId,
    ) -> Result<(), Error> {
        if self.terminal_slots.contains_key(&slot) {
            return Err(Error::SlotInvariant(format!(
                "incoming slot {} was registered after reaching a terminal state",
                slot.0
            )));
        }
        if packet.direction() != Direction::Incoming {
            return Err(Error::SlotInvariant(format!(
                "outgoing slot {} was reused as incoming receive credit",
                slot.0
            )));
        }

        if let Some(existing) = self.pending_slots.get(&slot)
            && existing.packet != packet
        {
            return Err(Error::SlotInvariant(format!(
                "slot {} was reused for a different action",
                slot.0
            )));
        }

        let target = (endpoint, stream);
        if let Some(previous_limit) = self
            .incoming_target_limits
            .get(&slot)
            .and_then(|targets| targets.get(&target))
            && absolute_limit <= *previous_limit
        {
            return Err(Error::SlotInvariant(format!(
                "incoming slot {} target {}:{} receive limit {absolute_limit} did not strictly increase from {previous_limit}",
                slot.0, endpoint.0, stream.0
            )));
        }

        if let Some(existing) = self.pending_slots.get_mut(&slot) {
            // One logical incoming slot can continue on the same stream, fan
            // out over several streams, or move to another endpoint after
            // returned receive credit. Keep its first action time while the
            // controller incrementally realizes that one scheduled packet.
            existing.endpoint = endpoint;
        } else {
            let action_time_us = self.elapsed_us(now);
            self.pending_slots.insert(
                slot,
                PendingSlot {
                    endpoint,
                    packet,
                    action_time_us,
                    credit_advertised_at_us: None,
                    credit_advertisement_candidate_at_us: None,
                },
            );
        }
        self.incoming_target_limits
            .entry(slot)
            .or_default()
            .insert(target, absolute_limit);
        Ok(())
    }

    pub(super) fn pending_slots(&self) -> Vec<(QcsdSlotId, PendingSlot)> {
        let mut pending: Vec<_> = self
            .pending_slots
            .iter()
            .map(|(slot, record)| (*slot, *record))
            .collect();
        pending.sort_unstable_by_key(|(slot, _)| *slot);
        pending
    }

    /// Endpoint attribution for one logical pending slot.
    ///
    /// Incoming receive credit may fan out across streams and connections.
    /// The raw transport observation still has one physical carrier, while
    /// the schedule row represents the logical slot and therefore has no
    /// connection attribution when more than one endpoint owns a child.
    pub(super) fn pending_slot_endpoint(&self, slot: QcsdSlotId) -> Option<QcsdEndpointId> {
        let pending = self.pending_slots.get(&slot)?;
        let Some(targets) = self.incoming_target_limits.get(&slot) else {
            return Some(pending.endpoint);
        };
        let mut endpoints = targets.keys().map(|(endpoint, _)| *endpoint);
        let first = endpoints.next().unwrap_or(pending.endpoint);
        endpoints.all(|endpoint| endpoint == first).then_some(first)
    }

    pub(super) fn is_slot_pending(&self, slot: QcsdSlotId) -> bool {
        self.pending_slots.contains_key(&slot)
    }

    pub(super) fn is_slot_terminal(&self, slot: QcsdSlotId) -> bool {
        self.terminal_slots.contains_key(&slot)
    }

    pub(super) fn ensure_no_pending_slots(&self) -> Result<(), Error> {
        if self.pending_slots.is_empty() && self.cs_incoming_process_witnesses.is_empty() {
            Ok(())
        } else {
            let slots = self
                .pending_slots()
                .into_iter()
                .map(|(slot, _)| slot.0.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            Err(Error::SlotInvariant(format!(
                "run completed with unterminated slots: {slots}"
            )))
        }
    }

    pub(super) fn event(
        &mut self,
        now: Instant,
        endpoint: Option<QcsdEndpointId>,
        event: &str,
        outcome: &str,
        details: &impl Serialize,
    ) -> Result<(), Error> {
        let details_value = serde_json::to_value(details)?;
        let qcsd = QcsdTraceColumns::from_serialized_event(&details_value);
        let details = serde_json::to_string(&details_value)?.replace('"', "\"\"");
        self.push_event(EventTraceRow {
            monotonic_ns: self.elapsed_ns(now),
            production_sequence: None,
            insertion_sequence: self.next_event_sequence,
            connection: endpoint.map_or_else(String::new, |value| value.0.to_string()),
            event: event.into(),
            outcome: outcome.into(),
            details,
            deferred_backlog_details: None,
            qcsd,
        })
    }

    pub(super) fn observation(
        &mut self,
        endpoint: Option<QcsdEndpointId>,
        record: &TimestampedQcsdObservation,
    ) -> Result<(), Error> {
        self.observation_with_controller(endpoint, record, None, None)
    }

    /// Persist an adapter observation after the controller has reduced it.
    ///
    /// A `ReceiveLimitAdvertised` observation is only a whole-slot local
    /// realisation after every original fan-out child has been advertised.
    /// The controller is the sole owner of that logical ledger, and the
    /// successful socket handoff is the physical boundary, so only this
    /// causally ordered path may freeze the runtime receipt timestamp.
    pub(super) fn observation_after_controller(
        &mut self,
        endpoint: Option<QcsdEndpointId>,
        record: &TimestampedQcsdObservation,
        controller: &QcsdController,
        receive_credit_handoff_at: Option<Instant>,
    ) -> Result<(), Error> {
        self.observation_with_controller(
            endpoint,
            record,
            Some(controller),
            receive_credit_handoff_at,
        )
    }

    fn observation_with_controller(
        &mut self,
        endpoint: Option<QcsdEndpointId>,
        record: &TimestampedQcsdObservation,
        controller: Option<&QcsdController>,
        receive_credit_handoff_at: Option<Instant>,
    ) -> Result<(), Error> {
        let mut qcsd =
            QcsdTraceColumns::from_observation(record.observation(), &self.terminal_slots);
        if let QcsdObservation::ReceiveLimitAdvertised {
            endpoint,
            stream,
            absolute_limit,
            slot,
        } = record.observation()
        {
            let advertised_at_us = match (controller, receive_credit_handoff_at) {
                (Some(_), Some(handoff_at)) => self.elapsed_us(handoff_at),
                (Some(_), None) => {
                    return Err(Error::SlotInvariant(
                        "runtime receive-credit advertisement lacked a successful socket-handoff timestamp"
                            .into(),
                    ));
                }
                // Isolated trace tests and historical generic callers have no
                // runtime controller/handoff boundary. Production adapter
                // observations always use the fail-closed branch above.
                (None, _) => record.produced_monotonic_ns() / 1_000,
            };
            if controller.is_some() {
                let handoff_ns = self
                    .elapsed_ns(receive_credit_handoff_at.expect("runtime handoff checked above"));
                let advertisements = self
                    .physical_receive_advertisements
                    .entry((*endpoint, *stream))
                    .or_default();
                if advertisements
                    .last()
                    .is_none_or(|previous| previous.absolute_limit < *absolute_limit)
                {
                    advertisements.push(PhysicalReceiveAdvertisement {
                        absolute_limit: *absolute_limit,
                        handoff_ns,
                        production_ns: record.produced_monotonic_ns(),
                        production_sequence: record.sequence(),
                    });
                }
            }
            let slots = self.advertised_credit_slots(*endpoint, *stream, *absolute_limit, *slot);
            let mut newly_frozen_slots = Vec::new();
            for slot in &slots {
                let pending = self.pending_slots.get_mut(slot).ok_or_else(|| {
                    Error::SlotInvariant(format!(
                        "receive-credit advertisement targeted unknown slot {}",
                        slot.0
                    ))
                })?;
                match controller {
                    Some(controller) => {
                        if pending.credit_advertised_at_us.is_none() {
                            pending.credit_advertisement_candidate_at_us = Some(
                                pending
                                    .credit_advertisement_candidate_at_us
                                    .map_or(advertised_at_us, |previous| {
                                        previous.max(advertised_at_us)
                                    }),
                            );
                            if controller.incoming_slot_is_locally_realized(*slot) {
                                pending.credit_advertised_at_us =
                                    pending.credit_advertisement_candidate_at_us;
                                newly_frozen_slots.push(*slot);
                            }
                        }
                    }
                    // This compatibility path serves isolated trace-file tests
                    // and historical generic callers that do not own a
                    // controller.  All runtime adapter observations use the
                    // ordered controller-aware path above.
                    None => {
                        pending.credit_advertised_at_us = Some(
                            pending
                                .credit_advertised_at_us
                                .map_or(advertised_at_us, |previous| {
                                    previous.max(advertised_at_us)
                                }),
                        );
                    }
                }
            }
            // An explicitly attributed scheduled release retains honest
            // scalar event provenance even when the same physical frame also
            // covers preceding parser-owned capacity. For a slotless runtime
            // advertisement, only a newly frozen whole-slot boundary can own
            // the scalar receipt. Already-realized but unconsumed owners must
            // retain their earlier timestamps without making that new receipt
            // ambiguous. Multiple new owners remain unrepresented by a scalar.
            // Controller-less historical callers retain their prior coverage
            // rule. Every covered schedule row keeps its own frozen boundary.
            let scalar_candidates = if controller.is_some() {
                &newly_frozen_slots
            } else {
                &slots
            };
            let scalar_slot = (*slot).or(match scalar_candidates.as_slice() {
                [only] => Some(*only),
                _ => None,
            });
            // An unfinished explicit fan-out has no whole-slot scalar receipt.
            // Preserve its observation with the nullable extension still empty.
            if let Some(scalar_slot) = scalar_slot
                && self.pending_slots[&scalar_slot]
                    .credit_advertised_at_us
                    .is_some()
            {
                let pending = &self.pending_slots[&scalar_slot];
                qcsd.schema_version = Some(2);
                qcsd.credit_advertised_at_us = pending.credit_advertised_at_us;
                qcsd.credit_advertisement_delay_us = pending
                    .credit_advertised_at_us
                    .map(|advertised| advertised.saturating_sub(pending.action_time_us));
            }
        }
        let deferred_backlog_details = if endpoint.is_none() && controller.is_none() {
            DeferredBacklogTraceDetails::from_record(record)
        } else {
            None
        };
        let details = if deferred_backlog_details.is_some() {
            String::new()
        } else {
            observation_trace_details(
                record.observation(),
                record.produced_monotonic_ns(),
                record.sequence(),
            )?
        };
        self.push_event(EventTraceRow {
            monotonic_ns: record.produced_monotonic_ns(),
            production_sequence: Some(record.sequence()),
            insertion_sequence: self.next_event_sequence,
            connection: endpoint.map_or_else(String::new, |value| value.0.to_string()),
            event: "observation".into(),
            outcome: "recorded".into(),
            details,
            deferred_backlog_details,
            qcsd,
        })?;
        if let Some(controller) = controller
            && matches!(record.observation(), QcsdObservation::BytesRead { .. })
        {
            self.reconcile_consumed_incoming_realizations(controller, record)?;
        }
        if let Some(controller) = controller {
            self.reconcile_buflo_fin_permission(controller, record, receive_credit_handoff_at)?;
        }
        Ok(())
    }

    /// A legacy parser claim can become fully advertised only when its raw
    /// bytes acquire scheduling ownership during consumption. The controller
    /// snapshots that terminal ledger before removing it. Join every consumed
    /// interval to actual successful transport coverage; no candidate or
    /// terminal/reduction timestamp can substitute for a missing handoff.
    fn reconcile_consumed_incoming_realizations(
        &mut self,
        controller: &QcsdController,
        record: &TimestampedQcsdObservation,
    ) -> Result<(), Error> {
        let slots: Vec<_> = controller
            .incoming_credit_realization_slots()
            .filter(|slot| {
                self.pending_slots
                    .get(slot)
                    .is_some_and(|pending| pending.credit_advertised_at_us.is_none())
                    && controller
                        .incoming_credit_realization_witness(*slot)
                        .is_some_and(|witness| witness.retired == 0)
            })
            .collect();
        for slot in slots {
            let witness = controller
                .incoming_credit_realization_witness(slot)
                .expect("selected immutable witness");
            let pending = &self.pending_slots[&slot];
            let mut ranges = witness.ranges.clone();
            ranges.sort_unstable_by_key(|range| {
                (range.endpoint, range.stream, range.start, range.end)
            });
            let covered_bytes = ranges.iter().try_fold(0_u64, |total, range| {
                total.checked_add(range.end.checked_sub(range.start)?)
            });
            let overlapping = ranges.windows(2).any(|pair| {
                pair[0].endpoint == pair[1].endpoint
                    && pair[0].stream == pair[1].stream
                    && pair[0].end > pair[1].start
            });
            if witness.packet != pending.packet
                || witness.requested != u64::from(pending.packet.length())
                || witness.advertised != witness.requested
                || witness.consumed != witness.requested
                || witness.retired != 0
                || !witness.locally_realized
                || covered_bytes != Some(witness.requested)
                || overlapping
                || ranges.iter().any(|range| range.start >= range.end)
                || !ranges.iter().any(|range| range.reclassified_parser)
            {
                return Err(Error::SlotInvariant(format!(
                    "incoming slot {} has an incomplete consumed-realization witness",
                    slot.0
                )));
            }
            let mut advertised_ns = 0;
            let mut physical_ranges = Vec::new();
            for range in ranges {
                let advertisement = self
                    .physical_receive_advertisements
                    .get(&(range.endpoint, range.stream))
                    .and_then(|advertisements| {
                        advertisements.iter().find(|advertisement| {
                            advertisement.absolute_limit >= range.end
                                && advertisement.production_ns <= advertisement.handoff_ns
                                && advertisement.handoff_ns <= record.produced_monotonic_ns()
                        })
                    })
                    .ok_or_else(|| {
                        Error::SlotInvariant(format!(
                            "incoming slot {} consumed range {}:{}:{}..{} lacks original physical handoff coverage",
                            slot.0, range.endpoint.0, range.stream.0, range.start, range.end
                        ))
                    })?;
                advertised_ns = advertised_ns.max(advertisement.handoff_ns);
                physical_ranges.push(serde_json::json!({
                    "endpoint": range.endpoint.0,
                    "stream": range.stream.0,
                    "start": range.start,
                    "end": range.end,
                    "reclassified_parser": range.reclassified_parser,
                    "absolute_limit": advertisement.absolute_limit,
                    "production_sequence": advertisement.production_sequence,
                    "production_monotonic_ns": advertisement.production_ns,
                    "physical_handoff_monotonic_ns": advertisement.handoff_ns,
                }));
            }
            let advertised_at_us = advertised_ns / 1_000;
            if advertised_at_us < pending.action_time_us {
                return Err(Error::SlotInvariant(format!(
                    "incoming slot {} physical realization precedes its scheduled action",
                    slot.0
                )));
            }
            let endpoint = pending.endpoint;
            let reduced_at = Instant::now();
            self.event(
                reduced_at,
                Some(endpoint),
                "incoming_credit_realization",
                "reconciled",
                &serde_json::json!({
                    "schema_version": 1,
                    "source": "native-controller-consumed-physical-receive-ranges-v1",
                    "slot": slot.0,
                    "requested_bytes": witness.requested,
                    "advertised_bytes": witness.advertised,
                    "consumed_bytes": witness.consumed,
                    "retired_bytes": witness.retired,
                    "reconciliation_observation_production_sequence": record.sequence(),
                    "reconciliation_observation_production_monotonic_ns": record.produced_monotonic_ns(),
                    "controller_terminal_defense_elapsed_us": u64::try_from(witness.terminal_at.as_micros()).unwrap_or(u64::MAX),
                    "reduction_monotonic_ns": self.elapsed_ns(reduced_at),
                    "credit_advertised_at_us": advertised_at_us,
                    "ranges": physical_ranges,
                }),
            )?;
            self.pending_slots
                .get_mut(&slot)
                .expect("pending realization retained")
                .credit_advertised_at_us = Some(advertised_at_us);
        }
        Ok(())
    }

    /// Resolve every logical incoming slot whose registered physical target
    /// is covered by one on-wire `MAX_STREAM_DATA` advertisement. A frame may
    /// carry one explicit scheduled release while also covering preceding
    /// parser-owned capacity, so the explicit identity is additive rather
    /// than an alternative to reverse target attribution.
    fn advertised_credit_slots(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        explicit_slot: Option<QcsdSlotId>,
    ) -> Vec<QcsdSlotId> {
        let mut slots: Vec<_> = self
            .incoming_target_limits
            .iter()
            .filter_map(|(slot, targets)| {
                targets
                    .get(&(endpoint, stream))
                    .is_some_and(|target| *target <= absolute_limit)
                    .then_some(*slot)
            })
            .collect();
        if let Some(slot) = explicit_slot {
            slots.push(slot);
        }
        slots.sort_unstable();
        slots.dedup();
        slots
    }

    fn push_event(&mut self, row: EventTraceRow) -> Result<(), Error> {
        if self.events_flushed {
            return Err(Error::SlotInvariant(
                "attempted to record an event after events.csv was finalized".into(),
            ));
        }
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
        if self.trace_growth_diagnostics {
            let string_bytes = row
                .connection
                .capacity()
                .saturating_add(row.event.capacity())
                .saturating_add(row.outcome.capacity())
                .saturating_add(row.details.capacity());
            self.event_string_capacity_bytes = self
                .event_string_capacity_bytes
                .saturating_add(string_bytes);
        }
        self.event_rows.push(row);
        if self.trace_growth_diagnostics
            && self.event_rows.len() >= 1_024
            && self.event_rows.len().is_power_of_two()
        {
            self.report_trace_growth();
        }
        Ok(())
    }

    /// Attribute retained allocations without scanning all prior events or
    /// adding synthetic observations to the scientific trace. These figures
    /// omit allocator overhead and map allocations; they are not process RSS.
    fn report_trace_growth(&self) {
        let row_storage_bytes = self
            .event_rows
            .capacity()
            .saturating_mul(std::mem::size_of::<EventTraceRow>());
        let report = serde_json::json!({
            "record_type": "qcsd-engineering-trace-allocation-growth-v1",
            "monotonic_ns": self.elapsed_ns(Instant::now()),
            "event_rows": self.event_rows.len(),
            "event_row_capacity": self.event_rows.capacity(),
            "event_row_size_bytes": std::mem::size_of::<EventTraceRow>(),
            "event_row_storage_bytes": row_storage_bytes,
            "event_owned_string_capacity_bytes": self.event_string_capacity_bytes,
            "accounted_event_allocation_bytes": row_storage_bytes
                .saturating_add(self.event_string_capacity_bytes),
            "csv_writer_capacity_bytes": self.packets.capacity()
                .saturating_add(self.events.capacity())
                .saturating_add(self.schedule.capacity()),
            "pending_slots": self.pending_slots.len(),
            "incoming_target_limits": self.incoming_target_limits.len(),
            "physical_receive_advertisement_streams": self.physical_receive_advertisements.len(),
            "terminal_slots": self.terminal_slots.len(),
            "cs_incoming_process_witnesses": self.cs_incoming_process_witnesses.len(),
            "buflo_fin_raw_frontiers": self.buflo_fin_raw_frontiers.len(),
            "buflo_fin_peer_reads": self.buflo_fin_peer_reads.len(),
            "buflo_fin_release_proofs": self.buflo_fin_release_proofs.len(),
            "buflo_fin_pre_advertisement_slots": self.buflo_fin_pre_advertisements.len(),
            "scientific_credit_added": 0,
        });
        // Diagnostic output failure must not change the run's verdict.
        drop(writeln!(std::io::stderr(), "QCSD_TRACE_GROWTH {report}"));
    }

    pub(super) fn flush_events(&mut self) -> Result<(), Error> {
        if self.events_flushed {
            return Ok(());
        }
        self.event_rows.sort_by(|left, right| {
            left.monotonic_ns.cmp(&right.monotonic_ns).then_with(|| {
                match (left.production_sequence, right.production_sequence) {
                    (Some(left), Some(right)) => left.cmp(&right),
                    _ => left.insertion_sequence.cmp(&right.insertion_sequence),
                }
            })
        });
        for row in self.event_rows.drain(..) {
            let details = match row.deferred_backlog_details {
                Some(backlog) => backlog.render()?,
                None => row.details,
            };
            writeln!(
                self.events,
                "{},{},{},{},\"{}\",{}",
                row.monotonic_ns / 1_000,
                row.connection,
                row.event,
                row.outcome,
                details,
                row.qcsd.csv_suffix(),
            )?;
        }
        self.event_string_capacity_bytes = 0;
        self.events.flush()?;
        self.packets.flush()?;
        self.schedule.flush()?;
        self.events_flushed = true;
        Ok(())
    }

    pub(super) fn schedule(&mut self, row: &ScheduleTraceRow<'_>) -> Result<(), Error> {
        self.schedule_with_semantics(row, ScheduleTerminalSemantics::OpportunityResolution)
    }

    /// Record an explicitly cancelled not-yet-due slot.
    ///
    /// This narrow path preserves abnormal-run evidence without weakening the
    /// ordinary controller-clock invariant enforced by [`Self::schedule`].
    /// The caller supplies the typed cancellation reason, which must agree
    /// with the row and may only identify run/endpoint teardown or a typed
    /// adapter rejection while installing the future target.
    pub(super) fn schedule_future_cancellation(
        &mut self,
        row: &ScheduleTraceRow<'_>,
        reason: MissedSlotReason,
    ) -> Result<(), Error> {
        self.schedule_with_semantics(row, ScheduleTerminalSemantics::FutureCancellation(reason))
    }

    fn schedule_with_semantics(
        &mut self,
        row: &ScheduleTraceRow<'_>,
        semantics: ScheduleTerminalSemantics,
    ) -> Result<(), Error> {
        let target_time_us = row.packet.timestamp_us();
        match semantics {
            ScheduleTerminalSemantics::OpportunityResolution => {
                if row.terminal_defense_elapsed_us < target_time_us {
                    return Err(Error::SlotInvariant(format!(
                        "slot {} terminal defense time {}us predates target {target_time_us}us",
                        row.slot.0, row.terminal_defense_elapsed_us
                    )));
                }
            }
            ScheduleTerminalSemantics::FutureCancellation(reason) => {
                if row.terminal_defense_elapsed_us >= target_time_us {
                    return Err(Error::SlotInvariant(format!(
                        "slot {} future cancellation time {}us did not predate target {target_time_us}us",
                        row.slot.0, row.terminal_defense_elapsed_us
                    )));
                }
                if !matches!(
                    reason,
                    MissedSlotReason::EndpointClosed
                        | MissedSlotReason::DeadlineExpired
                        | MissedSlotReason::KeysUnavailable
                        | MissedSlotReason::PathMtu
                        | MissedSlotReason::RunAborted
                ) {
                    return Err(Error::SlotInvariant(format!(
                        "slot {} used invalid future-cancellation reason {reason:?}",
                        row.slot.0
                    )));
                }
                let expected_reason = format!("{reason:?}");
                if row.satisfaction != "missed" || row.miss_reason != expected_reason {
                    return Err(Error::SlotInvariant(format!(
                        "slot {} future cancellation must be a matching typed miss ({reason:?})",
                        row.slot.0
                    )));
                }
            }
        }
        let terminal_time_us = row.action_time_us;
        let mut action_time_us = row.action_time_us;
        let endpoint = row.endpoint;
        let packet = row.packet;
        let slot = row.slot;
        if let Some(terminal_packet) = self.terminal_slots.get(&slot) {
            let detail = if *terminal_packet == packet {
                "reached more than one terminal state"
            } else {
                "was reused for a different terminal packet"
            };
            return Err(Error::SlotInvariant(format!("slot {} {detail}", slot.0)));
        }
        let mut qcsd = row.qcsd;
        let consumed_at_us = if self.cs_incoming_process_witnesses_required
            && packet.direction() == Direction::Incoming
            && matches!(row.satisfaction, "satisfied" | "full")
        {
            let witness = self
                .cs_incoming_process_witnesses
                .get(&slot)
                .ok_or_else(|| {
                    Error::SlotInvariant(format!(
                        "incoming slot {} terminal trace lacks its process-clock witness",
                        slot.0
                    ))
                })?;
            if witness.packet() != packet
                || witness.slot() != slot
                || u64::try_from(witness.terminal_at().as_micros()).unwrap_or(u64::MAX)
                    != row.terminal_defense_elapsed_us
                || self.pending_slot_endpoint(slot) != row.endpoint
            {
                return Err(Error::SlotInvariant(format!(
                    "incoming slot {} terminal trace changed process-clock ownership",
                    slot.0
                )));
            }
            self.elapsed_us(witness.captured_at())
        } else {
            terminal_time_us
        };
        if let Some(pending) = self.pending_slots.get(&slot) {
            if pending.packet != packet {
                return Err(Error::SlotInvariant(format!(
                    "slot {} terminated with a different packet",
                    slot.0
                )));
            }
            action_time_us = pending.action_time_us;
            if packet.direction() == Direction::Incoming {
                qcsd.schema_version = Some(2);
                qcsd.credit_advertised_at_us = pending.credit_advertised_at_us;
                qcsd.credit_advertisement_delay_us = pending
                    .credit_advertised_at_us
                    .map(|advertised| advertised.saturating_sub(pending.action_time_us));
                if row.satisfaction == "satisfied" || row.satisfaction == "full" {
                    qcsd.credit_consumed_at_us = Some(consumed_at_us);
                    qcsd.credit_consumption_delay_us =
                        Some(consumed_at_us.saturating_sub(pending.action_time_us));
                }
            }
        }
        // Schedule schema three binds every terminal row directly to the
        // controller's defense-relative resolution time. This supersedes the
        // schema-one/two outcome identity while preserving every older field.
        qcsd.schema_version = Some(3);
        qcsd.terminal_defense_elapsed_us = Some(row.terminal_defense_elapsed_us);
        self.cs_incoming_process_witnesses.remove(&slot);
        self.pending_slots.remove(&slot);
        self.incoming_target_limits.remove(&slot);
        self.terminal_slots.insert(slot, packet);
        writeln!(
            self.schedule,
            "{},{},{},{},{action_time_us},{},{},{},{},{}",
            packet.timestamp_us(),
            match packet.direction() {
                Direction::Outgoing => "outgoing",
                Direction::Incoming => "incoming",
            },
            packet.length(),
            endpoint.map_or_else(String::new, |value| value.0.to_string()),
            row.satisfaction,
            row.observed
                .map_or_else(String::new, |value| value.to_string()),
            row.miss_reason,
            slot.0,
            qcsd.csv_suffix(),
        )?;
        Ok(())
    }
}

impl Drop for TraceFiles {
    fn drop(&mut self) {
        drop(self.flush_events());
    }
}

#[cfg(test)]
mod incoming_realization_tests {
    use std::{
        fs,
        io::Write as _,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use neqo_csdef::{
        QcsdAction, QcsdConfig, QcsdObservationClock, QcsdRequestRole, QcsdStreamFinish, Resource,
        ResourceManifest, StaticSchedule, Trace,
    };

    use super::*;

    struct Fixture {
        controller: QcsdController,
        traces: TraceFiles,
        clock: QcsdObservationClock,
        start: Instant,
        output: PathBuf,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        slot: QcsdSlotId,
        packet: Packet,
        time_us: u64,
        last_handoff_us: u64,
    }

    impl Fixture {
        fn new(explicit_bytes: u64) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let output = std::env::temp_dir().join(format!(
                "qcsd-incoming-realization-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&output).expect("fresh trace directory");
            let start = Instant::now();
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(4);
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("cell");
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: 1,
                    max_stream_data_excess: 1_000,
                    ..QcsdConfig::default()
                },
                None,
                Box::new(StaticSchedule::new(Trace::new([packet]), false)),
            )
            .expect("controller");
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: "https://example.com".into(),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(explicit_bytes + 1),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller.poll(Duration::ZERO);
            let action = controller
                .drain_actions()
                .find(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
                .expect("actual partial scheduled release");
            let QcsdAction::IncreaseReceiveLimit {
                absolute_limit,
                slot,
                ..
            } = action
            else {
                unreachable!();
            };
            assert_eq!(absolute_limit, explicit_bytes + 1);
            let mut traces = TraceFiles::new(&output, start).expect("traces");
            traces
                .register_incoming_action(
                    start + Duration::from_micros(1),
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                )
                .expect("register actual scheduled action");
            let mut fixture = Self {
                controller,
                traces,
                clock: QcsdObservationClock::new(start),
                start,
                output,
                endpoint,
                stream,
                slot,
                packet,
                time_us: 1,
                last_handoff_us: 0,
            };
            fixture
                .advertise(absolute_limit, Some(slot), true)
                .expect("partial advertisement");
            fixture
                .read(explicit_bytes + 1)
                .expect("consume original exact offsets");
            assert!(!fixture.controller.incoming_slot_is_locally_realized(slot));
            fixture
        }

        fn record(&mut self, observation: QcsdObservation) -> TimestampedQcsdObservation {
            self.time_us += 1;
            self.clock.record_at(
                observation,
                self.start + Duration::from_micros(self.time_us),
            )
        }

        fn advertise(
            &mut self,
            absolute_limit: u64,
            slot: Option<QcsdSlotId>,
            retain_physical: bool,
        ) -> Result<(), Error> {
            let record = self.record(QcsdObservation::ReceiveLimitAdvertised {
                endpoint: self.endpoint,
                stream: self.stream,
                absolute_limit,
                slot,
            });
            self.time_us += 1;
            self.last_handoff_us = self.time_us;
            self.controller.observe(
                record.observation().clone(),
                Duration::from_micros(self.time_us),
            );
            if retain_physical {
                self.traces.observation_after_controller(
                    Some(self.endpoint),
                    &record,
                    &self.controller,
                    Some(self.start + Duration::from_micros(self.time_us)),
                )?;
            }
            Ok(())
        }

        fn lease(&mut self, retain_physical: bool) -> (u64, u64) {
            let record = self.record(QcsdObservation::HeaderProgress {
                endpoint: self.endpoint,
                stream: self.stream,
                min_remaining: 0,
                awaiting_data_frame: true,
            });
            self.controller.observe(
                record.observation().clone(),
                Duration::from_micros(self.time_us),
            );
            self.traces
                .observation_after_controller(Some(self.endpoint), &record, &self.controller, None)
                .expect("typed boundary observation");
            let (absolute_limit, increase) = self
                .controller
                .drain_actions()
                .find_map(|action| {
                    if let QcsdAction::LeaseParserReceive {
                        absolute_limit,
                        increase,
                        owner,
                        ..
                    } = action
                    {
                        assert!(owner.is_none(), "legacy unowned parser lease");
                        Some((absolute_limit, increase))
                    } else {
                        None
                    }
                })
                .expect("actual parser lease");
            self.advertise(absolute_limit, None, retain_physical)
                .expect("actual parser advertisement");
            (absolute_limit, increase)
        }

        fn read(&mut self, bytes: u64) -> Result<(), Error> {
            let record = self.record(QcsdObservation::BytesRead {
                endpoint: self.endpoint,
                stream: self.stream,
                bytes,
            });
            self.controller.observe(
                record.observation().clone(),
                Duration::from_micros(self.time_us),
            );
            self.traces.observation_after_controller(
                Some(self.endpoint),
                &record,
                &self.controller,
                None,
            )
        }

        fn consume_parser_remainder(
            &mut self,
            mut remaining: u64,
            retain_last: bool,
        ) -> Result<(), Error> {
            while remaining > 0 {
                let (_, increase) = self.lease(remaining > 16 || retain_last);
                let bytes = remaining.min(increase);
                self.read(bytes)?;
                remaining -= bytes;
            }
            Ok(())
        }

        fn terminal(&mut self) -> Result<(), Error> {
            let terminal = self.controller.drain_actions().find(|action| {
                matches!(action, QcsdAction::SlotSatisfied { slot, .. } if *slot == self.slot)
            }).expect("controller-issued full terminal action");
            assert!(matches!(terminal, QcsdAction::SlotSatisfied { .. }));
            self.write_terminal()
        }

        fn write_terminal(&mut self) -> Result<(), Error> {
            self.traces.schedule(&ScheduleTraceRow {
                action_time_us: self.time_us + 7,
                endpoint: Some(self.endpoint),
                packet: self.packet,
                satisfaction: "satisfied",
                observed: Some(1_200),
                miss_reason: "",
                slot: self.slot,
                qcsd: QcsdTraceColumns::exact(1_200, Some(1_200)),
                terminal_defense_elapsed_us: self.time_us,
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.output);
        }
    }

    #[test]
    fn incoming_realization_trace_reclassifies_491_and_534_byte_splits_after_last_advertisement() {
        for explicit in [993, 1_179] {
            let mut fixture = Fixture::new(explicit);
            fixture
                .consume_parser_remainder(1_200 - explicit, true)
                .expect("full raw consumption");
            assert!(
                !fixture
                    .controller
                    .incoming_slot_is_locally_realized(fixture.slot),
                "the completed live ledger has been removed"
            );
            let witness = fixture
                .controller
                .incoming_credit_realization_witness(fixture.slot)
                .expect("immutable terminal ownership witness");
            assert_eq!(
                (
                    witness.requested,
                    witness.advertised,
                    witness.consumed,
                    witness.retired
                ),
                (1_200, 1_200, 1_200, 0)
            );
            assert_eq!(
                witness
                    .ranges
                    .iter()
                    .filter(|range| range.reclassified_parser)
                    .map(|range| range.end - range.start)
                    .sum::<u64>(),
                1_200 - explicit
            );
            assert_eq!(
                fixture.traces.pending_slots[&fixture.slot].credit_advertised_at_us,
                Some(fixture.last_handoff_us)
            );
            assert!(fixture.last_handoff_us < fixture.time_us);
            fixture.terminal().expect("full terminal schedule");
            assert!(
                fixture.write_terminal().is_err(),
                "one terminal action cannot be reused"
            );
            fixture
                .traces
                .schedule
                .flush()
                .expect("flush schedule bytes");
            fixture
                .traces
                .flush_events()
                .expect("flush raw event bytes");
            let schedule =
                fs::read_to_string(fixture.output.join("schedule.csv")).expect("schedule");
            let fields: Vec<_> = schedule
                .lines()
                .nth(1)
                .expect("one terminal row")
                .split(',')
                .collect();
            assert_eq!(schedule.lines().count(), 2);
            assert_eq!(fields[21], fixture.last_handoff_us.to_string());
            assert_eq!(fields[22], (fixture.last_handoff_us - 1).to_string());
            assert_eq!(fields[23], (fixture.time_us + 7).to_string());
            assert_eq!(fields[25], fixture.time_us.to_string());
            let events = fs::read_to_string(fixture.output.join("events.csv")).expect("events");
            assert_eq!(
                events
                    .lines()
                    .filter(|line| line.contains("incoming_credit_realization"))
                    .count(),
                1
            );
            assert!(events.contains("native-controller-consumed-physical-receive-ranges-v1"));
            assert!(events.contains("physical_handoff_monotonic_ns"));
        }
    }

    #[test]
    fn incoming_realization_trace_rejects_missing_original_parser_handoff_coverage() {
        let mut fixture = Fixture::new(1_179);
        assert!(matches!(fixture.consume_parser_remainder(21, false),
            Err(Error::SlotInvariant(message)) if message.contains("lacks original physical handoff coverage")));
        assert_eq!(
            fixture.traces.pending_slots[&fixture.slot].credit_advertised_at_us,
            None
        );
    }

    #[test]
    fn incoming_realization_trace_rejects_no_handoff_and_future_coverage() {
        for future in [false, true] {
            let mut fixture = Fixture::new(1_184);
            let (limit, _) = fixture.lease(false);
            let record = fixture.record(QcsdObservation::ReceiveLimitAdvertised {
                endpoint: fixture.endpoint,
                stream: fixture.stream,
                absolute_limit: limit,
                slot: None,
            });
            let handoff =
                future.then_some(fixture.start + Duration::from_micros(fixture.time_us + 100));
            let result = fixture.traces.observation_after_controller(
                Some(fixture.endpoint),
                &record,
                &fixture.controller,
                handoff,
            );
            assert_eq!(result.is_ok(), future);
            assert!(fixture.read(16).is_err());
            assert_eq!(
                fixture.traces.pending_slots[&fixture.slot].credit_advertised_at_us,
                None
            );
        }
    }

    /// Mechanism fixture, not a successful workload or a replacement FRONT
    /// acceptance oracle. The fixed event list preserves FRONT's ChaffOnly
    /// allocation and non-exact incoming lifecycle without random sampling.
    struct FrontFixture {
        controller: QcsdController,
        traces: TraceFiles,
        clock: QcsdObservationClock,
        start: Instant,
        output: PathBuf,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        packet: Packet,
        first_action_us: u64,
    }

    impl FrontFixture {
        fn new(body_bytes: u64, packets: usize) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let output = std::env::temp_dir().join(format!(
                "qcsd-front-continuation-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&output).expect("fresh FRONT trace directory");
            let start = Instant::now();
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(80);
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("cell");
            let resource = |id, bytes| Resource {
                id,
                url: format!("https://example.com/chaff-{id}"),
                kind: "Image".into(),
                content_length: Some(bytes),
                data_length: bytes,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            };
            // A future event keeps this a middle-of-flight opportunity, as
            // in the retained slot855 case; it is never polled by these tests.
            let sentinel = Packet::new(Duration::from_secs(10), Direction::Incoming, 1_200)
                .expect("future event");
            let schedule = Trace::new(std::iter::repeat_n(packet, packets).chain([sentinel]));
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: 16,
                    max_stream_data_excess: 1_000,
                    ..QcsdConfig::front_v5_light_configuration()
                },
                Some(ResourceManifest {
                    resources: vec![resource(1, body_bytes), resource(2, 5_000)],
                }),
                Box::new(StaticSchedule::new(schedule, true)),
            )
            .expect("FRONT ChaffOnly controller");
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: "https://example.com".into(),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Chaff {
                        resource_id: 1,
                        request_id: None,
                    },
                    expected_response_length: Some(body_bytes),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller.poll(Duration::ZERO);
            Self {
                controller,
                traces: TraceFiles::new(&output, start).expect("FRONT traces"),
                clock: QcsdObservationClock::new(start),
                start,
                output,
                endpoint,
                stream,
                packet,
                first_action_us: 1,
            }
        }

        fn receive_actions(&mut self, at_us: u64) -> Vec<(QcsdSlotId, u64)> {
            let actions: Vec<_> = self.controller.drain_actions().collect();
            actions
                .into_iter()
                .filter_map(|action| {
                    let QcsdAction::IncreaseReceiveLimit {
                        endpoint,
                        stream,
                        absolute_limit,
                        packet,
                        slot,
                    } = action
                    else {
                        return None;
                    };
                    assert_eq!(packet, self.packet, "continuation retains original target");
                    assert_eq!(endpoint, self.endpoint);
                    assert_eq!(stream, self.stream);
                    self.traces
                        .register_incoming_action(
                            self.start + Duration::from_micros(at_us),
                            endpoint,
                            stream,
                            absolute_limit,
                            packet,
                            slot,
                        )
                        .expect("actual controller action owns the trace target");
                    Some((slot, absolute_limit))
                })
                .collect()
        }

        fn observe(&mut self, observation: QcsdObservation, at_us: u64) {
            let record = self
                .clock
                .record_at(observation, self.start + Duration::from_micros(at_us));
            self.controller
                .observe(record.observation().clone(), Duration::from_micros(at_us));
            self.traces
                .observation_after_controller(Some(self.endpoint), &record, &self.controller, None)
                .expect("actual non-advertisement observation");
        }

        fn advertise(&mut self, slot: QcsdSlotId, limit: u64, produced_us: u64, handoff_us: u64) {
            let record = self.clock.record_at(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint: self.endpoint,
                    stream: self.stream,
                    absolute_limit: limit,
                    slot: Some(slot),
                },
                self.start + Duration::from_micros(produced_us),
            );
            self.controller.observe(
                record.observation().clone(),
                Duration::from_micros(handoff_us),
            );
            self.traces
                .observation_after_controller(
                    Some(self.endpoint),
                    &record,
                    &self.controller,
                    Some(self.start + Duration::from_micros(handoff_us)),
                )
                .expect("original production plus successful physical boundary");
        }

        fn read(&mut self, bytes: u64, at_us: u64) {
            self.observe(
                QcsdObservation::BytesRead {
                    endpoint: self.endpoint,
                    stream: self.stream,
                    bytes,
                },
                at_us,
            );
        }

        fn assert_original_action(&self, slot: QcsdSlotId) {
            let pending = &self.traces.pending_slots[&slot];
            assert_eq!(pending.packet, self.packet);
            assert_eq!(pending.action_time_us, self.first_action_us);
        }
    }

    impl Drop for FrontFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.output);
        }
    }

    #[test]
    fn front_partial_1200_byte_owner_retains_first_action_through_late_headers_and_fin() {
        let mut f = FrontFixture::new(600, 1);
        let actions = f.receive_actions(1);
        assert_eq!(actions.len(), 1);
        let (slot, limit) = actions[0];
        assert_eq!(limit, 600, "584 controlled bytes plus16 initial bytes");
        f.advertise(slot, limit, 2, 3);
        f.read(600, 4);
        assert!(!f.controller.incoming_slot_is_locally_realized(slot));
        assert_eq!(f.traces.pending_slots[&slot].credit_advertised_at_us, None);

        f.observe(
            QcsdObservation::ResponseHeaders {
                endpoint: f.endpoint,
                stream: f.stream,
                status: Some(200),
                content_length: Some(600),
                frame_bytes: 251,
            },
            1_000_000,
        );
        let headers = f.receive_actions(1_000_001);
        assert_eq!(
            headers,
            [(slot, 851)],
            "new framing continues the same owner"
        );
        f.advertise(slot, 851, 1_000_002, 1_000_003);
        f.read(251, 1_000_004);
        f.assert_original_action(slot);
        assert!(!f.controller.incoming_slot_is_locally_realized(slot));

        f.observe(
            QcsdObservation::StreamFinished {
                endpoint: f.endpoint,
                stream: f.stream,
                finish: QcsdStreamFinish::Fin,
            },
            1_100_000,
        );
        f.stream = QcsdStreamId(84);
        f.observe(
            QcsdObservation::StreamOpened {
                endpoint: f.endpoint,
                stream: f.stream,
                role: QcsdRequestRole::Chaff {
                    resource_id: 2,
                    request_id: None,
                },
                expected_response_length: Some(5_000),
            },
            1_100_001,
        );
        f.controller.poll(Duration::from_micros(1_100_002));
        let continued = f.receive_actions(1_100_003);
        assert_eq!(
            continued,
            [(slot, 381)],
            "FIN returns only365 remaining owner bytes"
        );
        f.advertise(slot, 381, 1_400_000, 1_400_001);
        f.assert_original_action(slot);
        assert!(f.controller.incoming_slot_is_locally_realized(slot));
        assert_eq!(
            f.traces.pending_slots[&slot].credit_advertised_at_us,
            Some(1_400_001)
        );
        assert_eq!(
            f.controller
                .defense_diagnostics()
                .scheduled_incoming_requested_bytes,
            1_200
        );
        assert_eq!(
            f.controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            1_200
        );
        f.read(381, 1_400_002);
        assert!(f.controller.drain_actions().any(|action| matches!(action,
            QcsdAction::SlotSatisfied { slot: actual, .. } if actual == slot)));
        f.traces
            .schedule(&ScheduleTraceRow {
                action_time_us: 1_400_003,
                endpoint: Some(f.endpoint),
                packet: f.packet,
                satisfaction: "satisfied",
                observed: Some(1_200),
                miss_reason: "",
                slot,
                qcsd: QcsdTraceColumns::exact(1_200, Some(1_200)),
                terminal_defense_elapsed_us: 1_400_002,
            })
            .expect("legacy complete terminal row retains its late whole-slot boundary");
        f.traces.schedule.flush().expect("schedule fixture bytes");
        let csv = fs::read_to_string(f.output.join("schedule.csv")).expect("schedule fixture");
        let row: Vec<_> = csv
            .lines()
            .nth(1)
            .expect("terminal row")
            .split(',')
            .collect();
        assert_eq!(
            row[21], "1400001",
            "neither first carrier nor production substitutes for physical whole-slot time"
        );
        assert_eq!(
            row[22], "1400000",
            "legacy scalar delay retains the first1us action"
        );
        assert_eq!(row[0], "0", "nominal scheduled target remains zero");
    }

    #[test]
    fn front_two_original_owners_can_share_one_late_physical_carrier_without_renumbering() {
        let mut f = FrontFixture::new(5_000, 2);
        let actions = f.receive_actions(1);
        assert_eq!(actions.len(), 2);
        assert_ne!(actions[0].0, actions[1].0);
        assert_eq!((actions[0].1, actions[1].1), (1_216, 2_416));
        for (index, (slot, _)) in actions.iter().enumerate() {
            // Transport coalescing may encode the highest absolute frontier
            // while retaining one production record per accepted owner.
            f.advertise(
                *slot,
                2_416,
                70_000 + u64::try_from(index).expect("small index"),
                70_100,
            );
            f.assert_original_action(*slot);
            assert!(f.controller.incoming_slot_is_locally_realized(*slot));
            assert_eq!(
                f.traces.pending_slots[slot].credit_advertised_at_us,
                Some(70_100)
            );
        }
        let diagnostics = f.controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 2_400);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 2_400);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
    }

    impl FrontFixture {
        /// Exercise the shared trace producer with one original transport
        /// observation and a separately supplied successful physical boundary.
        /// This is a trace mechanism fixture, not a CS-BuFLO workload oracle.
        fn advertise_with_identity(
            &mut self,
            slot: Option<QcsdSlotId>,
            limit: u64,
            produced_us: u64,
            handoff_us: Option<u64>,
        ) -> Result<TimestampedQcsdObservation, Error> {
            let record = self.clock.record_at(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint: self.endpoint,
                    stream: self.stream,
                    absolute_limit: limit,
                    slot,
                },
                self.start + Duration::from_micros(produced_us),
            );
            self.controller.observe(
                record.observation().clone(),
                Duration::from_micros(handoff_us.unwrap_or(produced_us)),
            );
            self.traces.observation_after_controller(
                Some(self.endpoint),
                &record,
                &self.controller,
                handoff_us.map(|at| self.start + Duration::from_micros(at)),
            )?;
            Ok(record)
        }
    }

    #[test]
    fn incoming_scalar_receipt_uses_unique_newly_frozen_owner() {
        let mut f = FrontFixture::new(5_000, 2);
        let actions: Vec<_> = f
            .controller
            .drain_actions()
            .filter_map(|action| {
                let QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                } = action
                else {
                    return None;
                };
                Some((endpoint, stream, absolute_limit, packet, slot))
            })
            .collect();
        assert_eq!(actions.len(), 2, "two genuine controller owners");
        let (endpoint, stream, old_limit, old_packet, old_slot) = actions[0];
        let (new_endpoint, new_stream, new_limit, new_packet, new_slot) = actions[1];
        assert_ne!(old_slot, new_slot);
        assert_eq!((new_endpoint, new_stream), (endpoint, stream));
        f.traces
            .register_incoming_action(
                f.start + Duration::from_micros(76_708),
                endpoint,
                stream,
                old_limit,
                old_packet,
                old_slot,
            )
            .expect("register first genuine action");
        f.advertise(old_slot, old_limit, 76_726, 76_750);
        assert!(f.controller.incoming_slot_is_locally_realized(old_slot));
        assert!(
            f.traces.is_slot_pending(old_slot),
            "advertised is not consumed"
        );

        f.traces
            .register_incoming_action(
                f.start + Duration::from_micros(90_961),
                new_endpoint,
                new_stream,
                new_limit,
                new_packet,
                new_slot,
            )
            .expect("register later genuine action");
        assert_eq!(
            f.traces
                .advertised_credit_slots(endpoint, stream, new_limit, None),
            vec![old_slot, new_slot],
            "the new frame still reverse-covers both original owners",
        );
        let record = f
            .advertise_with_identity(None, new_limit, 90_981, Some(91_004))
            .expect("one actual slotless observation and successful handoff");
        assert!(matches!(
            record.observation(),
            QcsdObservation::ReceiveLimitAdvertised { slot: None, .. }
        ));
        let rows: Vec<_> = f
            .traces
            .event_rows
            .iter()
            .filter(|row| row.production_sequence == Some(record.sequence()))
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "never duplicate the original observation identity"
        );
        let row = rows[0];
        assert_eq!(row.monotonic_ns, record.produced_monotonic_ns());
        let detail: Value = serde_json::from_str(&row.details.replace("\"\"", "\""))
            .expect("original observation JSON after CSV escaping");
        assert_eq!(detail["slot"], Value::Null);
        assert_eq!(detail["absolute_limit"], new_limit);
        assert_eq!(detail["production_sequence"], record.sequence());
        assert_eq!(
            detail["production_monotonic_ns"],
            record.produced_monotonic_ns()
        );
        assert_eq!(row.qcsd.schema_version, Some(2));
        assert_eq!(row.qcsd.credit_advertised_at_us, Some(91_004));
        assert_eq!(row.qcsd.credit_advertisement_delay_us, Some(43));
        assert_eq!(
            f.traces.pending_slots[&old_slot].credit_advertised_at_us,
            Some(76_750)
        );
        assert_eq!(
            f.traces.pending_slots[&new_slot].credit_advertised_at_us,
            Some(91_004)
        );
        assert!(f.controller.incoming_slot_is_locally_realized(new_slot));
        assert_eq!(f.traces.pending_slots[&old_slot].action_time_us, 76_708);
        assert_eq!(f.traces.pending_slots[&new_slot].action_time_us, 90_961);
        assert_eq!(
            f.traces
                .advertised_credit_slots(endpoint, stream, new_limit, None),
            vec![old_slot, new_slot],
            "scalar attribution must not remove reverse ownership"
        );
        assert_eq!(
            f.controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            2_400
        );
        assert_eq!(
            f.controller
                .defense_diagnostics()
                .scheduled_incoming_consumed_bytes,
            0
        );
    }

    #[test]
    fn incoming_scalar_receipt_preserves_explicit_owner_and_controllerless_compatibility() {
        let mut f = FrontFixture::new(5_000, 2);
        let actions = f.receive_actions(1);
        let (old_slot, old_limit) = actions[0];
        let (new_slot, new_limit) = actions[1];
        f.advertise(old_slot, old_limit, 2, 3);
        let record = f
            .advertise_with_identity(Some(old_slot), new_limit, 4, Some(5))
            .expect("explicit identity retains priority over reverse coverage");
        let row = f
            .traces
            .event_rows
            .iter()
            .find(|row| row.production_sequence == Some(record.sequence()))
            .expect("explicit event");
        assert_eq!(row.qcsd.credit_advertised_at_us, Some(3));
        assert_eq!(row.qcsd.credit_advertisement_delay_us, Some(2));
        assert_eq!(
            f.traces.pending_slots[&old_slot].credit_advertised_at_us,
            Some(3)
        );
        assert_eq!(
            f.traces.pending_slots[&new_slot].credit_advertised_at_us, None,
            "an explicit earlier owner cannot realize an unresolved later owner"
        );

        let mut historical = FrontFixture::new(5_000, 1);
        let (slot, limit) = historical.receive_actions(1)[0];
        let original = historical.clock.record_at(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint: historical.endpoint,
                stream: historical.stream,
                absolute_limit: limit,
                slot: None,
            },
            historical.start + Duration::from_micros(2),
        );
        historical
            .traces
            .observation(Some(historical.endpoint), &original)
            .expect("historical controller-less singleton attribution");
        let row = historical
            .traces
            .event_rows
            .last()
            .expect("historical event");
        assert_eq!(row.qcsd.schema_version, Some(2));
        assert_eq!(row.qcsd.credit_advertised_at_us, Some(2));
        assert_eq!(row.qcsd.credit_advertisement_delay_us, Some(1));
        assert_eq!(
            historical.traces.pending_slots[&slot].credit_advertised_at_us,
            Some(2)
        );
    }

    #[test]
    fn incoming_scalar_receipt_refuses_multiple_new_owners_and_repeated_slotless_claims() {
        let mut f = FrontFixture::new(5_000, 2);
        let actions = f.receive_actions(1);
        let record = f
            .advertise_with_identity(None, actions[1].1, 2, Some(3))
            .expect("physical coverage remains valid without an arbitrary scalar owner");
        let row = f
            .traces
            .event_rows
            .iter()
            .find(|row| row.production_sequence == Some(record.sequence()))
            .expect("shared event");
        assert_eq!(row.qcsd.schema_version, None);
        assert_eq!(row.qcsd.credit_advertised_at_us, None);
        assert_eq!(row.qcsd.credit_advertisement_delay_us, None);
        for (slot, _) in &actions {
            assert!(f.controller.incoming_slot_is_locally_realized(*slot));
            assert_eq!(
                f.traces.pending_slots[slot].credit_advertised_at_us,
                Some(3)
            );
        }
        let repeated = f
            .advertise_with_identity(None, actions[1].1, 4, Some(5))
            .expect("repeat keeps original per-owner times");
        let rows: Vec<_> = f
            .traces
            .event_rows
            .iter()
            .filter(|row| row.production_sequence == Some(repeated.sequence()))
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].qcsd.schema_version, None);
        assert_eq!(rows[0].qcsd.credit_advertised_at_us, None);
        for (slot, _) in &actions {
            assert_eq!(
                f.traces.pending_slots[slot].credit_advertised_at_us,
                Some(3)
            );
        }

        let mut singleton = FrontFixture::new(5_000, 1);
        let (slot, limit) = singleton.receive_actions(1)[0];
        singleton
            .advertise_with_identity(None, limit, 2, Some(3))
            .expect("first singleton handoff freezes its boundary");
        let repeat = singleton
            .advertise_with_identity(None, limit, 4, Some(5))
            .expect("repeating one old owner is not a new physical realization");
        let row = singleton
            .traces
            .event_rows
            .iter()
            .find(|row| row.production_sequence == Some(repeat.sequence()))
            .expect("one original repeated singleton event");
        assert_eq!(row.qcsd.schema_version, None);
        assert_eq!(row.qcsd.credit_advertised_at_us, None);
        assert_eq!(
            singleton.traces.pending_slots[&slot].credit_advertised_at_us,
            Some(3)
        );
    }

    #[test]
    fn incoming_scalar_receipt_refuses_unresolved_fanout_and_missing_handoff() {
        let mut partial = FrontFixture::new(600, 1);
        let (slot, limit) = partial.receive_actions(1)[0];
        let record = partial
            .advertise_with_identity(None, limit, 2, Some(3))
            .expect("partial physical coverage remains an incomplete candidate");
        assert!(!partial.controller.incoming_slot_is_locally_realized(slot));
        assert_eq!(
            partial.traces.pending_slots[&slot].credit_advertised_at_us,
            None
        );
        let row = partial
            .traces
            .event_rows
            .iter()
            .find(|row| row.production_sequence == Some(record.sequence()))
            .expect("partial event");
        assert_eq!(row.qcsd.schema_version, None);
        assert_eq!(row.qcsd.credit_advertised_at_us, None);

        let mut missing = FrontFixture::new(5_000, 1);
        let (slot, limit) = missing.receive_actions(1)[0];
        assert!(
            matches!(missing.advertise_with_identity(None, limit, 2, None),
            Err(Error::SlotInvariant(message)) if message.contains("lacked a successful socket-handoff"))
        );
        assert_eq!(
            missing.traces.pending_slots[&slot].credit_advertised_at_us,
            None
        );
        assert!(missing.traces.physical_receive_advertisements.is_empty());
        assert!(
            missing.traces.event_rows.is_empty(),
            "missing handoff cannot publish an observation"
        );
    }
}

#[cfg(test)]
mod incoming_terminal_process_clock_tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use neqo_csdef::{
        CsBufloConfig, DefenseConfig, QcsdAction, QcsdConfig, QcsdObservationClock,
        QcsdRequestRole, StaticSchedule, Trace,
    };

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct OwnedFixture {
        controller: QcsdController,
        traces: TraceFiles,
        path: std::path::PathBuf,
        endpoint: QcsdEndpointId,
        slot: QcsdSlotId,
        packet: Packet,
    }
    impl OwnedFixture {
        fn new(consumed: u64) -> Self {
            let start = Instant::now();
            let path = std::env::temp_dir().join(format!(
                "neqo-native136-owned-process-clock-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("fresh fixture");
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).expect("owned600");
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    max_udp_payload_size: 1200,
                    initial_max_stream_data: 1,
                    defense: DefenseConfig::CsBuflo(CsBufloConfig {
                        parameters: "fixture-only.json".into(),
                    }),
                    ..QcsdConfig::default()
                },
                None,
                Box::new(StaticSchedule::new(Trace::new([packet]), false)),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(0);
            let stream = QcsdStreamId(4);
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: "https://clock.example".into(),
                    max_udp_payload_size: 1200,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: None,
                },
                Duration::ZERO,
            );
            // The original one-byte initial window is not scheduled credit.
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 1,
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller.poll(Duration::ZERO);
            let action = controller
                .drain_actions()
                .find(|a| matches!(a, QcsdAction::IncreaseReceiveLimit { .. }))
                .expect("original owned receive action");
            let QcsdAction::IncreaseReceiveLimit {
                slot,
                absolute_limit,
                packet: actual,
                ..
            } = action
            else {
                unreachable!()
            };
            assert_eq!(actual, packet);
            let mut traces = TraceFiles::new(&path, start).expect("traces");
            traces.require_cs_incoming_process_witnesses();
            let advertised = Instant::now();
            traces
                .register_incoming_action(
                    advertised,
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                )
                .expect("register owner");
            let clock = QcsdObservationClock::new(start);
            let record = clock.record_at(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                advertised,
            );
            controller.observe(
                record.observation().clone(),
                advertised.duration_since(start),
            );
            traces
                .observation_after_controller(
                    Some(endpoint),
                    &record,
                    &controller,
                    Some(advertised),
                )
                .expect("original physical advertisement");
            for bytes in [1, 1, 1, consumed - 3] {
                let at = Instant::now().duration_since(start);
                controller.observe(
                    QcsdObservation::BytesRead {
                        endpoint,
                        stream,
                        bytes,
                    },
                    at,
                );
            }
            Self {
                controller,
                traces,
                path,
                endpoint,
                slot,
                packet,
            }
        }
        fn action(&self) -> QcsdAction {
            QcsdAction::SlotSatisfied {
                endpoint: Some(self.endpoint),
                packet: self.packet,
                slot: self.slot,
            }
        }
        fn row(&self, serialized_at: Instant) -> ScheduleTraceRow<'static> {
            ScheduleTraceRow {
                action_time_us: self.traces.elapsed_us(serialized_at),
                endpoint: Some(self.endpoint),
                packet: self.packet,
                satisfaction: "satisfied",
                observed: None,
                miss_reason: "",
                slot: self.slot,
                qcsd: QcsdTraceColumns::exact(600, None),
                terminal_defense_elapsed_us: u64::try_from(
                    self.controller
                        .terminal_slot_resolution_at(self.slot)
                        .expect("real controller resolution")
                        .as_micros(),
                )
                .expect("bounded"),
            }
        }
    }
    impl Drop for OwnedFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn queued_serialization_10127us_keeps_independent_consumption_clock() {
        let mut f = OwnedFixture::new(600);
        let witness = f
            .controller
            .incoming_terminal_process_witness(f.slot)
            .expect("actual owned600 witness");
        let serialized = witness.captured_at() + Duration::from_micros(10127);
        let action = f.action();
        f.traces
            .bind_cs_incoming_process_witness(&f.controller, &action, serialized)
            .expect("bind independent witness");
        let row = f.row(serialized);
        f.traces.schedule(&row).expect("saved schedule");
        f.traces.schedule.flush().expect("schedule flush");
        let text = fs::read_to_string(f.path.join("schedule.csv")).expect("raw schedule");
        let mut lines = text.lines();
        let headers: Vec<_> = lines.next().expect("headers").split(',').collect();
        let values: Vec<_> = lines.next().expect("one terminal").split(',').collect();
        let field = |name| {
            values[headers.iter().position(|v| *v == name).expect("column")]
                .parse::<u64>()
                .expect("integer")
        };
        let consumed = field("credit_consumed_at_us");
        assert_eq!(consumed, f.traces.elapsed_us(witness.captured_at()));
        let serialized_us = f.traces.elapsed_us(serialized);
        assert_eq!(serialized_us - consumed, 10127);
        // Original h controller-action bound remains 10000us. Only the genuine
        // earlier clock witness passes; late serialization is still exposed.
        assert!(consumed >= row.terminal_defense_elapsed_us);
        assert!(consumed - row.terminal_defense_elapsed_us <= 10000);
        assert!(serialized_us - row.terminal_defense_elapsed_us > 10000);
        let event = f
            .traces
            .event_rows
            .iter()
            .find(|r| r.event == "incoming_terminal_process_clock")
            .expect("separate serialization event");
        assert_eq!(
            event.monotonic_ns,
            u64::try_from(serialized.duration_since(f.traces.start).as_nanos()).expect("bounded")
        );
        assert!(f.traces.cs_incoming_process_witnesses.is_empty());
    }

    #[test]
    fn incomplete_credit_cannot_supply_process_clock_witness() {
        let mut f = OwnedFixture::new(599);
        assert!(
            f.controller
                .incoming_terminal_process_witness(f.slot)
                .is_none()
        );
        let action = f.action();
        assert!(
            f.traces
                .bind_cs_incoming_process_witness(&f.controller, &action, Instant::now())
                .is_err()
        );
    }

    #[test]
    fn wrong_slot_packet_or_owner_is_rejected() {
        for bad in 0..3 {
            let mut f = OwnedFixture::new(600);
            let witness = f
                .controller
                .incoming_terminal_process_witness(f.slot)
                .expect("witness");
            let action = QcsdAction::SlotSatisfied {
                endpoint: Some(if bad == 0 {
                    QcsdEndpointId(9)
                } else {
                    f.endpoint
                }),
                packet: if bad == 1 {
                    Packet::new(Duration::from_micros(1), Direction::Incoming, 600)
                        .expect("different target")
                } else {
                    f.packet
                },
                slot: if bad == 2 {
                    QcsdSlotId(f.slot.0 + 1)
                } else {
                    f.slot
                },
            };
            assert!(
                f.traces
                    .bind_cs_incoming_process_witness(
                        &f.controller,
                        &action,
                        witness.captured_at() + Duration::from_micros(10127)
                    )
                    .is_err()
            );
            assert!(f.traces.cs_incoming_process_witnesses.is_empty());
        }
    }

    #[test]
    fn duplicate_or_backwards_serialization_is_rejected() {
        let mut f = OwnedFixture::new(600);
        let witness = f
            .controller
            .incoming_terminal_process_witness(f.slot)
            .expect("witness");
        let action = f.action();
        assert!(
            f.traces
                .bind_cs_incoming_process_witness(
                    &f.controller,
                    &action,
                    witness.captured_at() - Duration::from_nanos(1)
                )
                .is_err()
        );
        let serialized = witness.captured_at() + Duration::from_micros(10127);
        f.traces
            .bind_cs_incoming_process_witness(&f.controller, &action, serialized)
            .expect("first exact bind");
        assert!(
            f.traces
                .bind_cs_incoming_process_witness(&f.controller, &action, serialized)
                .is_err()
        );
    }

    #[test]
    fn schedule_cannot_substitute_clock_or_omit_witness() {
        for missing in [false, true] {
            let mut f = OwnedFixture::new(600);
            let witness = f
                .controller
                .incoming_terminal_process_witness(f.slot)
                .expect("witness");
            let serialized = witness.captured_at() + Duration::from_micros(10127);
            let action = f.action();
            if !missing {
                f.traces
                    .bind_cs_incoming_process_witness(&f.controller, &action, serialized)
                    .expect("bind");
            }
            let mut row = f.row(serialized);
            if !missing {
                row.terminal_defense_elapsed_us += 1;
            }
            assert!(f.traces.schedule(&row).is_err());
        }
    }
}

#[cfg(test)]
mod fixed_backlog_trace_deferral_tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use neqo_csdef::{QcsdConfig, QcsdObservationClock, StaticSchedule, Trace};

    use super::*;

    struct Fixture {
        output: PathBuf,
        traces: TraceFiles,
    }

    impl Fixture {
        fn new(start: Instant) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let output = std::env::temp_dir().join(format!(
                "qcsd-fixed-backlog-trace-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&output).expect("fresh trace directory");
            let traces = TraceFiles::new(&output, start).expect("original trace files");
            Self { output, traces }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.output);
        }
    }

    // Complete original immediate serializer, retained independently as
    // the reference for the new terminal-render boundary.
    fn original_details(record: &TimestampedQcsdObservation) -> Result<String, Error> {
        let mut details = serde_json::to_value(record.observation())?;
        let Value::Object(fields) = &mut details else {
            return Err(Error::SlotInvariant(
                "serialized QCSD observation was not an object".into(),
            ));
        };
        fields.insert(
            "production_monotonic_ns".into(),
            Value::from(record.produced_monotonic_ns()),
        );
        fields.insert("production_sequence".into(), Value::from(record.sequence()));
        Ok(serde_json::to_string(&details)?.replace('"', "\"\""))
    }

    fn observation(index: usize) -> QcsdObservation {
        match index % 5 {
            0 => QcsdObservation::EgressStreamBacklog { pending: false },
            1 => QcsdObservation::EgressStreamBacklog { pending: true },
            2 => QcsdObservation::EgressBacklog { pending: false },
            3 => QcsdObservation::EgressBacklog { pending: true },
            _ => QcsdObservation::ApplicationComplete,
        }
    }

    #[test]
    fn fixed_backlog_terminal_render_preserves_complete_original_csv_bytes() {
        let start = Instant::now();
        let clock = QcsdObservationClock::new(start);
        let mut actual = Fixture::new(start);
        let mut original = Fixture::new(start);
        for index in 0..320 {
            // Deliberately out-of-order production times and same-time
            // mixed observation/action rows retain the original tie rules.
            let at = start
                + Duration::from_nanos(
                    u64::try_from((index / 2) % 11).expect("bounded") * 1_000,
                );
            let record = clock.record_at(observation(index), at);
            actual
                .traces
                .observation(None, &record)
                .expect("true unattributed observation path");
            original
                .traces
                .push_event(EventTraceRow {
                    monotonic_ns: record.produced_monotonic_ns(),
                    production_sequence: Some(record.sequence()),
                    insertion_sequence: original.traces.next_event_sequence,
                    connection: String::new(),
                    event: "observation".into(),
                    outcome: "recorded".into(),
                    details: original_details(&record).expect("original serde"),
                    deferred_backlog_details: None,
                    qcsd: QcsdTraceColumns::default(),
                })
                .expect("original fully rendered row");
            let saved = actual.traces.event_rows.last().expect("saved row");
            assert_eq!(saved.monotonic_ns, record.produced_monotonic_ns());
            assert_eq!(saved.production_sequence, Some(record.sequence()));
            if index % 5 < 4 {
                assert!(saved.details.is_empty(), "no live JSON/quote-copy");
                let deferred = saved.deferred_backlog_details.expect("typed fixed snapshot");
                assert_eq!(
                    deferred.produced_monotonic_ns,
                    record.produced_monotonic_ns(),
                );
                assert_eq!(deferred.production_sequence, record.sequence());
            } else {
                assert!(saved.deferred_backlog_details.is_none());
                assert_eq!(saved.details, original_details(&record).expect("reference"));
            }
            if index % 3 == 0 {
                let details = serde_json::json!({"index": index, "quoted": "\"value\""});
                for traces in [&mut actual.traces, &mut original.traces] {
                    traces
                        .event(at, None, "action", "fixture", &details)
                        .expect("unchanged generic event path");
                }
            }
        }
        assert_eq!(actual.traces.next_event_sequence, original.traces.next_event_sequence);
        assert_eq!(
            actual.traces.event_rows.iter().filter(|row| row.deferred_backlog_details.is_some()).count(),
            256,
        );
        actual.traces.flush_events().expect("terminal deferred render");
        original.traces.flush_events().expect("original reference render");
        assert_eq!(
            fs::read(actual.output.join("events.csv")).expect("whole actual CSV"),
            fs::read(original.output.join("events.csv")).expect("whole original CSV"),
        );
        let closed_bytes = fs::read(actual.output.join("events.csv")).expect("whole CSV");
        actual.traces.flush_events().expect("original idempotent finalization");
        let later = clock.record_at(observation(0), start + Duration::from_micros(20));
        assert!(actual.traces.observation(None, &later).is_err());
        assert_eq!(
            fs::read(actual.output.join("events.csv")).expect("unchanged whole CSV"),
            closed_bytes,
        );
    }

    #[test]
    fn fixed_backlog_deferral_is_exact_scope_and_primitive_render_only() {
        let start = Instant::now();
        let clock = QcsdObservationClock::new(start);
        let mut f = Fixture::new(start);
        let controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::new(Vec::<Packet>::new()), false)),
        )
        .expect("original pure static controller");
        for index in 0..4 {
            let record = clock.record_at(observation(index), start);
            f.traces
                .observation(Some(QcsdEndpointId(1)), &record)
                .expect("attributed path remains immediate");
            assert!(
                f.traces.event_rows.last().expect("row").deferred_backlog_details.is_none()
            );
            assert_eq!(
                f.traces.event_rows.last().expect("row").details,
                original_details(&record).expect("original reference"),
            );
            f.traces
                .observation_after_controller(None, &record, &controller, None)
                .expect("controller-aware path remains immediate");
            assert!(
                f.traces.event_rows.last().expect("row").deferred_backlog_details.is_none()
            );
            assert_eq!(
                f.traces.event_rows.last().expect("row").details,
                original_details(&record).expect("original reference"),
            );
        }
        let other = clock.record_at(QcsdObservation::ApplicationComplete, start);
        assert!(DeferredBacklogTraceDetails::from_record(&other).is_none());
        f.traces.observation(None, &other).expect("other variant is immediate");
        assert!(f.traces.event_rows.last().expect("row").deferred_backlog_details.is_none());

        // Fixed bool/u64 data has no custom/fallible value to validate later.
        // Exercise both kinds, both bools, zero and maximum unsigned fields
        // through the same original serializer/escaping.
        for kind in [BacklogTraceKind::Stream, BacklogTraceKind::Aggregate] {
            for pending in [false, true] {
                for value in [0, 1, u64::MAX] {
                    let deferred = DeferredBacklogTraceDetails {
                        kind,
                        pending,
                        produced_monotonic_ns: value,
                        production_sequence: value,
                    };
                    let raw = match kind {
                        BacklogTraceKind::Stream => {
                            QcsdObservation::EgressStreamBacklog { pending }
                        }
                        BacklogTraceKind::Aggregate => QcsdObservation::EgressBacklog { pending },
                    };
                    let mut reference = serde_json::to_value(raw).expect("original fixed object");
                    let fields = reference.as_object_mut().expect("original typed object");
                    fields.insert("production_monotonic_ns".into(), Value::from(value));
                    fields.insert("production_sequence".into(), Value::from(value));
                    assert_eq!(
                        deferred.render().expect("fixed primitive rendering"),
                        serde_json::to_string(&reference)
                            .expect("original primitive serde")
                            .replace('"', "\"\""),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod root_buflo_owned_terminal_process_clock_tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use neqo_csdef::{
        BufloConfig, DefenseConfig, QcsdAction, QcsdConfig, QcsdObservationClock,
        QcsdRequestRole, StaticSchedule, Trace,
    };

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct OwnedFixture {
        controller: QcsdController,
        traces: TraceFiles,
        path: std::path::PathBuf,
        endpoint: QcsdEndpointId,
        slot: QcsdSlotId,
        packet: Packet,
    }
    impl OwnedFixture {
        fn new(consumed: u64) -> Self {
            let start = Instant::now();
            let path = std::env::temp_dir().join(format!(
                "neqo-buflo-owned-process-clock-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("fresh fixture");
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1200).expect("owned1200");
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    max_udp_payload_size: 1200,
                    initial_max_stream_data: 1,
                    defense: DefenseConfig::Buflo(BufloConfig {
                        parameters: "fixture-only.json".into(),
                    }),
                    ..QcsdConfig::default()
                },
                None,
                Box::new(StaticSchedule::new(Trace::new([packet]), false)),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(0);
            let stream = QcsdStreamId(4);
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: "https://clock.example".into(),
                    max_udp_payload_size: 1200,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(1201),
                },
                Duration::ZERO,
            );
            // The original one-byte initial window is not scheduled credit.
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 1,
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller.poll(Duration::ZERO);
            let action = controller
                .drain_actions()
                .find(|a| matches!(a, QcsdAction::IncreaseReceiveLimit { .. }))
                .expect("original owned receive action");
            let QcsdAction::IncreaseReceiveLimit {
                slot,
                absolute_limit,
                packet: actual,
                ..
            } = action
            else {
                unreachable!()
            };
            assert_eq!(actual, packet);
            assert_eq!(absolute_limit, 1201, "one initial byte plus full1200 scheduled credit");
            let mut traces = TraceFiles::new(&path, start).expect("traces");
            traces.require_cs_incoming_process_witnesses();
            let advertised = Instant::now();
            traces
                .register_incoming_action(
                    advertised,
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                )
                .expect("register owner");
            let clock = QcsdObservationClock::new(start);
            let record = clock.record_at(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                advertised,
            );
            controller.observe(
                record.observation().clone(),
                advertised.duration_since(start),
            );
            traces
                .observation_after_controller(
                    Some(endpoint),
                    &record,
                    &controller,
                    Some(advertised),
                )
                .expect("original physical advertisement");
            let before_read = controller.defense_diagnostics();
            assert_eq!(
                (before_read.scheduled_incoming_requested_bytes,
                 before_read.scheduled_incoming_advertised_bytes,
                 before_read.scheduled_incoming_consumed_bytes,
                 before_read.scheduled_incoming_retired_bytes),
                (1200, 1200, 0, 0),
                "the fixture must own a fully advertised1200-byte scheduled window before reads"
            );
            for bytes in [1, 1, 1, consumed - 3] {
                let at = Instant::now().duration_since(start);
                controller.observe(
                    QcsdObservation::BytesRead {
                        endpoint,
                        stream,
                        bytes,
                    },
                    at,
                );
            }
            let after_read = controller.defense_diagnostics();
            assert_eq!(
                (after_read.scheduled_incoming_requested_bytes,
                 after_read.scheduled_incoming_advertised_bytes,
                 after_read.scheduled_incoming_consumed_bytes,
                 after_read.scheduled_incoming_retired_bytes),
                (1200, 1200, consumed, 0),
                "the public ledger must record exactly the supplied1200 or1199 bytes without retirement"
            );
            Self {
                controller,
                traces,
                path,
                endpoint,
                slot,
                packet,
            }
        }
        fn action(&self) -> QcsdAction {
            QcsdAction::SlotSatisfied {
                endpoint: Some(self.endpoint),
                packet: self.packet,
                slot: self.slot,
            }
        }
        fn row(&self, serialized_at: Instant) -> ScheduleTraceRow<'static> {
            ScheduleTraceRow {
                action_time_us: self.traces.elapsed_us(serialized_at),
                endpoint: Some(self.endpoint),
                packet: self.packet,
                satisfaction: "satisfied",
                observed: None,
                miss_reason: "",
                slot: self.slot,
                qcsd: QcsdTraceColumns::exact(1200, None),
                terminal_defense_elapsed_us: u64::try_from(
                    self.controller
                        .terminal_slot_resolution_at(self.slot)
                        .expect("real controller resolution")
                        .as_micros(),
                )
                .expect("bounded"),
            }
        }
    }
    impl Drop for OwnedFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn queued_serialization_11823us_keeps_independent_consumption_clock() {
        let mut f = OwnedFixture::new(1200);
        let witness = f
            .controller
            .incoming_terminal_process_witness(f.slot)
            .expect("actual owned1200 witness");
        let serialized = witness.captured_at() + Duration::from_micros(11823);
        let action = f.action();
        f.traces
            .bind_cs_incoming_process_witness(&f.controller, &action, serialized)
            .expect("bind independent witness");
        let row = f.row(serialized);
        f.traces.schedule(&row).expect("saved schedule");
        f.traces.schedule.flush().expect("schedule flush");
        let text = fs::read_to_string(f.path.join("schedule.csv")).expect("raw schedule");
        let mut lines = text.lines();
        let headers: Vec<_> = lines.next().expect("headers").split(',').collect();
        let values: Vec<_> = lines.next().expect("one terminal").split(',').collect();
        let field = |name| {
            values[headers.iter().position(|v| *v == name).expect("column")]
                .parse::<u64>()
                .expect("integer")
        };
        let consumed = field("credit_consumed_at_us");
        assert_eq!(consumed, f.traces.elapsed_us(witness.captured_at()));
        let serialized_us = f.traces.elapsed_us(serialized);
        assert_eq!(serialized_us - consumed, 11823);
        // Original h controller-action bound remains 10000us. Only the genuine
        // earlier clock witness passes; late serialization is still exposed.
        assert!(consumed >= row.terminal_defense_elapsed_us);
        assert!(consumed - row.terminal_defense_elapsed_us <= 10000);
        assert!(serialized_us - row.terminal_defense_elapsed_us > 10000);
        let event = f
            .traces
            .event_rows
            .iter()
            .find(|r| r.event == "incoming_terminal_process_clock")
            .expect("separate serialization event");
        assert_eq!(
            event.monotonic_ns,
            u64::try_from(serialized.duration_since(f.traces.start).as_nanos()).expect("bounded")
        );
        assert!(f.traces.cs_incoming_process_witnesses.is_empty());

        let mut missing = OwnedFixture::new(1200);
        let missing_witness = missing
            .controller
            .incoming_terminal_process_witness(missing.slot)
            .expect("owned BF1200 witness exists before trace binding");
        let missing_serialized = missing_witness.captured_at() + Duration::from_micros(11823);
        let missing_row = missing.row(missing_serialized);
        assert!(missing.traces.schedule(&missing_row).is_err(),
            "BF trace must reject a missing owned process-clock binding");

        let mut incomplete = OwnedFixture::new(1199);
        assert!(incomplete.controller.incoming_terminal_process_witness(incomplete.slot).is_none());
        let incomplete_action = incomplete.action();
        assert!(incomplete.traces.bind_cs_incoming_process_witness(
            &incomplete.controller, &incomplete_action, Instant::now()).is_err(),
            "1199 bytes cannot fabricate a full1200 owned consumption witness");
    }

}

#[cfg(test)]
mod trace_growth_diagnostic_tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    use neqo_csdef::{QcsdObservation, QcsdObservationClock};

    use super::{
        Direction, Packet, PacketTraceRow, QcsdEndpointId, QcsdSlotId, QcsdTraceColumns,
        ScheduleTraceRow, TraceFiles,
    };

    struct OutputDirectory(PathBuf);

    impl Drop for OutputDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn trace_growth_diagnostics_preserve_exact_csv_bytes() -> Result<(), Box<dyn std::error::Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = OutputDirectory(std::env::temp_dir().join(format!(
            "qcsd-trace-growth-equivalence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir(&root.0)?;
        let disabled_path = root.0.join("disabled");
        let enabled_path = root.0.join("enabled");
        fs::create_dir(&disabled_path)?;
        fs::create_dir(&enabled_path)?;
        let start = Instant::now();
        let mut disabled = TraceFiles::new(&disabled_path, start)?;
        let mut enabled = TraceFiles::new(&enabled_path, start)?;
        // Set private instance flags before any row. The test neither depends
        // on nor mutates the process-global environment while tests run.
        disabled.trace_growth_diagnostics = false;
        enabled.trace_growth_diagnostics = true;
        let clock = QcsdObservationClock::new(start);
        let endpoint = QcsdEndpointId(7);

        for index in 0..2_048_u64 {
            let produced = start + Duration::from_nanos(index * 2);
            let earlier = clock.record_at(
                QcsdObservation::EgressBacklog {
                    pending: index.is_multiple_of(2),
                },
                produced,
            );
            let later = clock.record_at(
                QcsdObservation::EgressStreamBacklog {
                    pending: !index.is_multiple_of(2),
                },
                produced,
            );
            for traces in [&mut disabled, &mut enabled] {
                // Delayed harvest must retain production ordering, including
                // the existing deferred fixed-backlog serialization path.
                traces.observation(None, &later)?;
                traces.observation(None, &earlier)?;
                traces.event(
                    produced + Duration::from_nanos(1),
                    Some(endpoint),
                    "growth-equivalence",
                    "recorded",
                    &serde_json::json!({"index": index, "text": "comma, quote\" newline\nΩ"}),
                )?;
            }
        }

        assert_eq!(enabled.event_rows.len(), 6_144);
        assert_eq!(disabled.event_rows.len(), enabled.event_rows.len());
        assert_eq!(disabled.event_string_capacity_bytes, 0);
        let actual_string_capacity: usize = enabled
            .event_rows
            .iter()
            .map(|row| {
                row.connection.capacity()
                    + row.event.capacity()
                    + row.outcome.capacity()
                    + row.details.capacity()
            })
            .sum();
        assert_eq!(enabled.event_string_capacity_bytes, actual_string_capacity);
        assert!(actual_string_capacity > 0);
        assert!(enabled
            .event_rows
            .iter()
            .any(|row| row.deferred_backlog_details.is_some()));

        let packet = Packet::new(Duration::from_millis(1), Direction::Outgoing, 1_200)?;
        for traces in [&mut disabled, &mut enabled] {
            traces.packet(&PacketTraceRow {
                now: start + Duration::from_millis(2),
                endpoint,
                direction: "outgoing",
                observed: 1_200,
                scheduled: Some(1_200),
                satisfaction: "satisfied",
                slot: Some(QcsdSlotId(1)),
                qcsd: QcsdTraceColumns::exact(1_200, Some(1_200)),
            })?;
            traces.schedule(&ScheduleTraceRow {
                action_time_us: 2_000,
                endpoint: Some(endpoint),
                packet,
                satisfaction: "satisfied",
                observed: Some(1_200),
                miss_reason: "",
                slot: QcsdSlotId(1),
                qcsd: QcsdTraceColumns::exact(1_200, Some(1_200)),
                terminal_defense_elapsed_us: 2_000,
            })?;
            traces.flush_events()?;
            assert!(traces.event_rows.is_empty());
            assert_eq!(traces.event_string_capacity_bytes, 0);
        }

        for name in ["events.csv", "packets.csv", "schedule.csv"] {
            let expected = fs::read(disabled_path.join(name))?;
            let actual = fs::read(enabled_path.join(name))?;
            assert!(!actual.is_empty());
            assert_eq!(actual, expected, "diagnostics changed {name}");
        }
        Ok(())
    }
}
