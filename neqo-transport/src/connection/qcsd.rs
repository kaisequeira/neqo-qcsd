// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::{Duration, Instant};

use neqo_csdef::{
    MissedSlotReason, Packet, QcsdEndpointId, QcsdObservation, QcsdRequestRole, QcsdSlotId,
};

use super::{Connection, Error, Res, RetransmissionPriority, StreamId, TransmissionPriority};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PacketTarget {
    pub slot: QcsdSlotId,
    pub udp_payload_size: u16,
    pub packet: Packet,
    pub deadline: Instant,
    pub allow_stream_data: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingReceiveCredit {
    pub slot: QcsdSlotId,
    pub stream: StreamId,
    pub absolute_limit: u64,
}

impl Connection {
    pub(super) fn qcsd_stream_priority_is_budgeted(&self, priority: TransmissionPriority) -> bool {
        if self.qcsd_chaff_send_released
            && priority == TransmissionPriority::Normal
            && self.qcsd_active_target.is_none()
        {
            return false;
        }
        self.qcsd_send_shaping
            || self
                .qcsd_active_target
                .is_some_and(|target| !target.allow_stream_data)
    }

    pub(super) fn qcsd_observe(
        &mut self,
        observation: impl FnOnce(QcsdEndpointId) -> QcsdObservation,
    ) {
        if let Some(endpoint) = self.qcsd_endpoint {
            self.qcsd_observations.push_back(observation(endpoint));
        }
    }

    /// Drain transport-level QCSD observations.
    #[must_use]
    pub fn qcsd_observations(&mut self) -> Vec<QcsdObservation> {
        self.qcsd_observations.drain(..).collect()
    }

    /// Bind transport target outcomes to a controller endpoint.
    pub const fn qcsd_enable(&mut self, endpoint: QcsdEndpointId, shape_stream_sends: bool) {
        self.qcsd_endpoint = Some(endpoint);
        self.qcsd_enable_send_shaping(shape_stream_sends);
    }

    /// Configure native Neqo keep-alive scheduling for controlled streams.
    pub const fn qcsd_set_keep_alive_lead_time(&mut self, lead_time: Duration) {
        self.idle_timeout.set_keep_alive_lead_time(lead_time);
    }

    /// Register a request-stream role before output scheduling begins.
    ///
    /// In a shaped run, application requests occupy `Important` slots and
    /// chaff requests remain `Normal`, including retransmissions. Thus the
    /// existing Neqo scheduler provides application-before-chaff service
    /// without a parallel stream implementation.
    ///
    /// # Errors
    ///
    /// Returns an error when the stream is unknown or its priority cannot be
    /// changed.
    pub fn qcsd_register_stream_role(
        &mut self,
        stream_id: StreamId,
        role: QcsdRequestRole,
    ) -> Res<()> {
        if !self.qcsd_send_shaping {
            return Ok(());
        }
        let priority = match role {
            QcsdRequestRole::Application => TransmissionPriority::Important,
            QcsdRequestRole::Chaff { .. } => TransmissionPriority::Normal,
        };
        self.stream_priority(stream_id, priority, RetransmissionPriority::Same)
    }

    /// Queue an attributed exact-size 1-RTT UDP payload target.
    ///
    /// # Errors
    ///
    /// Returns `NotAvailable` before 1-RTT keys/path state are usable and
    /// `InvalidInput` when the target is outside the active path range.
    pub fn qcsd_queue_scheduled_packet_target(
        &mut self,
        slot: QcsdSlotId,
        packet: Packet,
        deadline: Instant,
        allow_stream_data: bool,
    ) -> Res<()> {
        let udp_payload_size = packet.length();
        if !self.state.connected() {
            self.qcsd_observe(|endpoint| QcsdObservation::SlotMissed {
                endpoint,
                slot,
                packet,
                reason: MissedSlotReason::KeysUnavailable,
            });
            return Err(Error::NotAvailable);
        }
        let path = self.paths.primary().ok_or(Error::NotAvailable)?;
        if udp_payload_size < 64 || usize::from(udp_payload_size) > path.borrow().plpmtu() {
            self.qcsd_observe(|endpoint| QcsdObservation::SlotMissed {
                endpoint,
                slot,
                packet,
                reason: MissedSlotReason::PathMtu,
            });
            return Err(Error::InvalidInput);
        }
        self.qcsd_packet_targets.push_back(PacketTarget {
            slot,
            udp_payload_size,
            packet,
            deadline,
            allow_stream_data,
        });
        Ok(())
    }

    pub(super) fn qcsd_expire_packet_targets(
        &mut self,
        now: Instant,
        congestion_limit: Option<usize>,
        paced: bool,
    ) {
        while self
            .qcsd_packet_targets
            .front()
            .is_some_and(|target| now >= target.deadline)
        {
            let target = self
                .qcsd_packet_targets
                .pop_front()
                .expect("front target inspected");
            let reason = if paced {
                MissedSlotReason::PacingLimited
            } else if congestion_limit
                .is_some_and(|limit| limit < usize::from(target.udp_payload_size))
            {
                MissedSlotReason::CongestionLimited
            } else {
                MissedSlotReason::DeadlineExpired
            };
            self.qcsd_observe(|endpoint| QcsdObservation::SlotMissed {
                endpoint,
                slot: target.slot,
                packet: target.packet,
                reason,
            });
        }
    }

    pub(super) fn qcsd_target_satisfied(&mut self, target: &PacketTarget) {
        self.qcsd_observe(|endpoint| QcsdObservation::SlotSatisfied {
            endpoint,
            slot: target.slot,
            observed_size: target.udp_payload_size,
        });
    }

    pub(super) fn qcsd_target_missed(&mut self, target: &PacketTarget, reason: MissedSlotReason) {
        self.qcsd_observe(|endpoint| QcsdObservation::SlotMissed {
            endpoint,
            slot: target.slot,
            packet: target.packet,
            reason,
        });
    }

    pub(super) fn qcsd_receive_limit_advertised(&mut self, stream: StreamId, absolute_limit: u64) {
        let mut slots = Vec::new();
        self.qcsd_pending_receive_credit.retain(|credit| {
            if credit.stream == stream && credit.absolute_limit <= absolute_limit {
                slots.push(credit.slot);
                false
            } else {
                true
            }
        });
        if slots.is_empty() {
            self.qcsd_observe(|endpoint| QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: neqo_csdef::QcsdStreamId(stream.as_u64()),
                absolute_limit,
                slot: None,
            });
            return;
        }
        for slot in slots {
            self.qcsd_observe(|endpoint| QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: neqo_csdef::QcsdStreamId(stream.as_u64()),
                absolute_limit,
                slot: Some(slot),
            });
        }
    }
}
