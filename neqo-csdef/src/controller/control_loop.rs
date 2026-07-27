// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::HashSet;

use crate::{Packet, QcsdEndpointId, QcsdSlotId, QcsdStreamId};

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingIncoming {
    pub slot: QcsdSlotId,
    pub packet: Packet,
    pub endpoint: Option<QcsdEndpointId>,
    pub remaining: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingOutgoing {
    pub slot: QcsdSlotId,
    pub packet: Packet,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PendingCredit {
    pub slot: QcsdSlotId,
    pub packet: Packet,
    pub endpoint: QcsdEndpointId,
    pub stream: QcsdStreamId,
    pub absolute_limit: u64,
    pub increase: u64,
}

#[derive(Debug, Default)]
pub(super) struct ControlLoop {
    pub next_slot_id: u64,
    pub last_incoming_boundary_us: Option<u64>,
    pub incoming: Vec<PendingIncoming>,
    pub outgoing: Vec<PendingOutgoing>,
    pub credit: Vec<PendingCredit>,
    /// Incoming slots already classified as missed must not later be marked
    /// satisfied when a partially released credit fragment is encoded.
    pub terminal_incoming: HashSet<QcsdSlotId>,
}

impl ControlLoop {
    pub(super) const fn next_slot(&mut self) -> QcsdSlotId {
        let slot = QcsdSlotId(self.next_slot_id);
        self.next_slot_id = self.next_slot_id.saturating_add(1);
        slot
    }

    pub(super) const fn boundary_us(elapsed_us: u64, interval_us: u64) -> u64 {
        (elapsed_us / interval_us) * interval_us
    }

    pub(super) fn should_process_incoming(&mut self, boundary_us: u64) -> bool {
        if self.last_incoming_boundary_us == Some(boundary_us) {
            return false;
        }
        self.last_incoming_boundary_us = Some(boundary_us);
        true
    }

    pub(super) fn incoming_backlog(&self) -> u64 {
        self.incoming
            .iter()
            .fold(0, |total, pending| total.saturating_add(pending.remaining))
    }

    pub(super) fn reassign_endpoint(&mut self, endpoint: QcsdEndpointId) {
        for pending in &mut self.incoming {
            if pending.endpoint == Some(endpoint) {
                pending.endpoint = None;
            }
        }
    }

    pub(super) fn incoming_slot_pending(&self, slot: QcsdSlotId) -> bool {
        self.incoming.iter().any(|pending| pending.slot == slot)
            || self.credit.iter().any(|credit| credit.slot == slot)
    }
}
