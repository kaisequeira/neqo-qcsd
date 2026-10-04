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
    Direction, MissedSlotReason, Packet, QcsdCongestionReason, QcsdController, QcsdEndpointId,
    QcsdObservation, QcsdSendPolicy, QcsdSlotComposition, QcsdSlotId, QcsdSlotOutcome,
    QcsdStreamId, TimestampedQcsdObservation,
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

struct EventTraceRow {
    monotonic_ns: u64,
    production_sequence: Option<u64>,
    insertion_sequence: u64,
    connection: String,
    event: String,
    outcome: String,
    details: String,
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
            next_event_sequence: 0,
            events_flushed: false,
            pending_slots: HashMap::new(),
            incoming_target_limits: HashMap::new(),
            physical_receive_advertisements: HashMap::new(),
            terminal_slots: HashMap::new(),
        })
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
        if self.pending_slots.is_empty() {
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
            // covers preceding parser-owned capacity. A slotless parser-lease
            // advertisement has scalar provenance only when it covers exactly
            // one logical owner. Every covered schedule row always retains
            // its own independently frozen boundary.
            let scalar_slot = (*slot).or(match slots.as_slice() {
                [only] => Some(*only),
                _ => None,
            });
            if let Some(scalar_slot) = scalar_slot {
                let pending = &self.pending_slots[&scalar_slot];
                qcsd.schema_version = Some(2);
                qcsd.credit_advertised_at_us = pending.credit_advertised_at_us;
                qcsd.credit_advertisement_delay_us = pending
                    .credit_advertised_at_us
                    .map(|advertised| advertised.saturating_sub(pending.action_time_us));
            }
        }
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
        let details = serde_json::to_string(&details)?.replace('"', "\"\"");
        self.push_event(EventTraceRow {
            monotonic_ns: record.produced_monotonic_ns(),
            production_sequence: Some(record.sequence()),
            insertion_sequence: self.next_event_sequence,
            connection: endpoint.map_or_else(String::new, |value| value.0.to_string()),
            event: "observation".into(),
            outcome: "recorded".into(),
            details,
            qcsd,
        })?;
        if let Some(controller) = controller
            && matches!(record.observation(), QcsdObservation::BytesRead { .. })
        {
            self.reconcile_consumed_incoming_realizations(controller, record)?;
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
        self.event_rows.push(row);
        Ok(())
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
            writeln!(
                self.events,
                "{},{},{},{},\"{}\",{}",
                row.monotonic_ns / 1_000,
                row.connection,
                row.event,
                row.outcome,
                row.details,
                row.qcsd.csv_suffix(),
            )?;
        }
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
                    qcsd.credit_consumed_at_us = Some(terminal_time_us);
                    qcsd.credit_consumption_delay_us =
                        Some(terminal_time_us.saturating_sub(pending.action_time_us));
                }
            }
        }
        // Schedule schema three binds every terminal row directly to the
        // controller's defense-relative resolution time. This supersedes the
        // schema-one/two outcome identity while preserving every older field.
        qcsd.schema_version = Some(3);
        qcsd.terminal_defense_elapsed_us = Some(row.terminal_defense_elapsed_us);
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
        QcsdAction, QcsdConfig, QcsdObservationClock, QcsdRequestRole, StaticSchedule, Trace,
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
}
