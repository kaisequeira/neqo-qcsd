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
    collections::{HashMap, HashSet},
    fs::File,
    io::Write as _,
    path::Path,
    time::Instant,
};

use neqo_csdef::{Direction, Packet, QcsdEndpointId, QcsdSlotId};
use serde::Serialize;

use super::Error;

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingSlot {
    pub(super) endpoint: QcsdEndpointId,
    pub(super) packet: Packet,
    pub(super) action_time_us: u64,
}

#[derive(Clone, Copy)]
pub(super) struct PacketTraceRow<'a> {
    pub(super) now: Instant,
    pub(super) endpoint: QcsdEndpointId,
    pub(super) direction: &'a str,
    pub(super) observed: usize,
    pub(super) scheduled: Option<u16>,
    pub(super) satisfaction: &'a str,
    pub(super) slot: Option<QcsdSlotId>,
}

#[derive(Clone, Copy)]
pub(super) struct ScheduleTraceRow<'a> {
    pub(super) action_time_us: u64,
    pub(super) endpoint: Option<QcsdEndpointId>,
    pub(super) packet: Packet,
    pub(super) satisfaction: &'a str,
    pub(super) observed: Option<usize>,
    pub(super) miss_reason: &'a str,
    pub(super) slot: Option<QcsdSlotId>,
}

pub(super) struct TraceFiles {
    packets: File,
    events: File,
    schedule: File,
    start: Instant,
    pending_slots: HashMap<QcsdSlotId, PendingSlot>,
    terminal_slots: HashSet<QcsdSlotId>,
}

impl TraceFiles {
    pub(super) fn new(output_dir: &Path, start: Instant) -> Result<Self, Error> {
        let mut packets = File::create(output_dir.join("packets.csv"))?;
        writeln!(
            packets,
            "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction,slot_id"
        )?;
        let mut events = File::create(output_dir.join("events.csv"))?;
        writeln!(events, "monotonic_us,connection,event,outcome,details")?;
        let mut schedule = File::create(output_dir.join("schedule.csv"))?;
        writeln!(
            schedule,
            "target_time_us,direction,size,connection,action_time_us,satisfaction,observed_size,miss_reason,slot_id"
        )?;
        Ok(Self {
            packets,
            events,
            schedule,
            start,
            pending_slots: HashMap::new(),
            terminal_slots: HashSet::new(),
        })
    }

    pub(super) fn elapsed_us(&self, now: Instant) -> u64 {
        u64::try_from(now.duration_since(self.start).as_micros()).unwrap_or(u64::MAX)
    }

    pub(super) fn packet(&mut self, row: &PacketTraceRow<'_>) -> Result<(), Error> {
        let &PacketTraceRow {
            now,
            endpoint,
            direction,
            observed,
            scheduled,
            satisfaction,
            slot,
        } = row;
        writeln!(
            self.packets,
            "{direction},{},{},{observed},{},{satisfaction},{}",
            self.elapsed_us(now),
            endpoint.0,
            scheduled.map_or_else(String::new, |value| value.to_string()),
            slot.map_or_else(String::new, |value| value.0.to_string()),
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
        if self.terminal_slots.contains(&slot) {
            return Err(Error::SlotInvariant(format!(
                "slot {} was scheduled after reaching a terminal state",
                slot.0
            )));
        }
        let pending = PendingSlot {
            endpoint,
            packet,
            action_time_us: self.elapsed_us(now),
        };
        if let Some(existing) = self.pending_slots.get(&slot) {
            if existing.endpoint != endpoint || existing.packet != packet {
                return Err(Error::SlotInvariant(format!(
                    "slot {} was reused for a different action",
                    slot.0
                )));
            }
        } else {
            self.pending_slots.insert(slot, pending);
        }
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
        let details = serde_json::to_string(details)?.replace('"', "\"\"");
        writeln!(
            self.events,
            "{},{},{event},{outcome},\"{details}\"",
            self.elapsed_us(now),
            endpoint.map_or_else(String::new, |value| value.0.to_string())
        )?;
        Ok(())
    }

    pub(super) fn schedule(&mut self, row: &ScheduleTraceRow<'_>) -> Result<(), Error> {
        let &ScheduleTraceRow {
            mut action_time_us,
            endpoint,
            packet,
            satisfaction,
            observed,
            miss_reason,
            slot,
        } = row;
        if let Some(slot) = slot {
            if !self.terminal_slots.insert(slot) {
                return Err(Error::SlotInvariant(format!(
                    "slot {} reached more than one terminal state",
                    slot.0
                )));
            }
            if let Some(pending) = self.pending_slots.remove(&slot) {
                if pending.packet != packet {
                    return Err(Error::SlotInvariant(format!(
                        "slot {} terminated with a different packet",
                        slot.0
                    )));
                }
                action_time_us = pending.action_time_us;
            }
        }
        writeln!(
            self.schedule,
            "{},{},{},{},{action_time_us},{satisfaction},{},{miss_reason},{}",
            packet.timestamp_us(),
            match packet.direction() {
                Direction::Outgoing => "outgoing",
                Direction::Incoming => "incoming",
            },
            packet.length(),
            endpoint.map_or_else(String::new, |value| value.0.to_string()),
            observed.map_or_else(String::new, |value| value.to_string()),
            slot.map_or_else(String::new, |value| value.0.to_string()),
        )?;
        Ok(())
    }
}
