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
    Direction, Packet, QcsdCongestionReason, QcsdEndpointId, QcsdObservation, QcsdSendPolicy,
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
    /// Latest on-wire `MAX_STREAM_DATA` encoding time for this logical slot.
    pub(super) credit_advertised_at_us: Option<u64>,
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
            "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction,slot_id,qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,congestion_reason,credit_advertised_at_us,credit_advertisement_delay_us,credit_consumed_at_us,credit_consumption_delay_us"
        )?;
        let mut events = BufWriter::with_capacity(
            TRACE_BUFFER_BYTES,
            File::create(output_dir.join("events.csv"))?,
        );
        writeln!(
            events,
            "monotonic_us,connection,event,outcome,details,qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,congestion_reason,credit_advertised_at_us,credit_advertisement_delay_us,credit_consumed_at_us,credit_consumption_delay_us"
        )?;
        let mut schedule = BufWriter::with_capacity(
            TRACE_BUFFER_BYTES,
            File::create(output_dir.join("schedule.csv"))?,
        );
        writeln!(
            schedule,
            "target_time_us,direction,size,connection,action_time_us,satisfaction,observed_size,miss_reason,slot_id,qcsd_outcome_schema_version,send_policy,desired_udp_bytes,observed_udp_bytes,application_stream_bytes,retransmission_stream_bytes,chaff_stream_bytes,defense_control_bytes,quic_padding_bytes,other_quic_bytes,lateness_us,congestion_reason,credit_advertised_at_us,credit_advertisement_delay_us,credit_consumed_at_us,credit_consumption_delay_us"
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
        let mut qcsd =
            QcsdTraceColumns::from_observation(record.observation(), &self.terminal_slots);
        if let QcsdObservation::ReceiveLimitAdvertised {
            slot: Some(slot), ..
        } = record.observation()
        {
            let advertised_at_us = record.produced_monotonic_ns() / 1_000;
            let pending = self.pending_slots.get_mut(slot).ok_or_else(|| {
                Error::SlotInvariant(format!(
                    "receive-credit advertisement targeted unknown slot {}",
                    slot.0
                ))
            })?;
            pending.credit_advertised_at_us = Some(
                pending
                    .credit_advertised_at_us
                    .map_or(advertised_at_us, |previous| previous.max(advertised_at_us)),
            );
            qcsd.schema_version = Some(2);
            qcsd.credit_advertised_at_us = Some(advertised_at_us);
            qcsd.credit_advertisement_delay_us =
                Some(advertised_at_us.saturating_sub(pending.action_time_us));
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
        })
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
