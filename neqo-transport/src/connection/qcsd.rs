// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    time::{Duration, Instant},
};

use enum_map::EnumMap;
use neqo_csdef::{
    Direction, MissedSlotReason, Packet, QcsdDatagramClass, QcsdEndpointId, QcsdObservation,
    QcsdObservationClock, QcsdRequestRole, QcsdSlotId, TimestampedQcsdObservation,
    TrafficMorphingEgress,
};

use super::{Connection, Error, Res, RetransmissionPriority, StreamId, TransmissionPriority};
use crate::{
    frame::Frame,
    recovery::{self, StreamRecoveryToken, Token},
    tracking::PacketNumberSpace,
};

const MAX_CLASSIFIED_PACKETS_PER_SPACE: usize = 8_192;

#[derive(Debug, Default)]
pub(super) struct QcsdPacketClassifier {
    outgoing: EnumMap<PacketNumberSpace, BTreeMap<u64, QcsdDatagramClass>>,
    incoming: EnumMap<PacketNumberSpace, BTreeMap<u64, QcsdDatagramClass>>,
}

impl QcsdPacketClassifier {
    fn history(
        &self,
        direction: Direction,
        space: PacketNumberSpace,
    ) -> &BTreeMap<u64, QcsdDatagramClass> {
        match direction {
            Direction::Outgoing => &self.outgoing[space],
            Direction::Incoming => &self.incoming[space],
        }
    }

    fn history_mut(
        &mut self,
        direction: Direction,
        space: PacketNumberSpace,
    ) -> &mut BTreeMap<u64, QcsdDatagramClass> {
        match direction {
            Direction::Outgoing => &mut self.outgoing[space],
            Direction::Incoming => &mut self.incoming[space],
        }
    }

    pub(super) fn record(
        &mut self,
        direction: Direction,
        space: PacketNumberSpace,
        packet_number: u64,
        class: QcsdDatagramClass,
    ) {
        let history = self.history_mut(direction, space);
        history.insert(packet_number, class);
        while history.len() > MAX_CLASSIFIED_PACKETS_PER_SPACE {
            let _: Option<(u64, QcsdDatagramClass)> = history.pop_first();
        }
    }

    pub(super) fn recorded(
        &self,
        direction: Direction,
        space: PacketNumberSpace,
        packet_number: u64,
    ) -> QcsdDatagramClass {
        self.history(direction, space)
            .get(&packet_number)
            .copied()
            .unwrap_or(QcsdDatagramClass::Natural)
    }

    pub(super) fn classify_ack(
        &self,
        ack_direction: Direction,
        space: PacketNumberSpace,
        ranges: impl IntoIterator<Item = RangeInclusive<u64>>,
    ) -> QcsdDatagramClass {
        let acknowledged_direction = match ack_direction {
            Direction::Outgoing => Direction::Incoming,
            Direction::Incoming => Direction::Outgoing,
        };
        let history = self.history(acknowledged_direction, space);
        let mut observed_range = false;
        for range in ranges {
            observed_range = true;
            if !Self::range_is_exclusively_cover(history, range) {
                return QcsdDatagramClass::Natural;
            }
        }
        if observed_range {
            QcsdDatagramClass::DefenseCover
        } else {
            QcsdDatagramClass::Natural
        }
    }

    fn range_is_exclusively_cover(
        history: &BTreeMap<u64, QcsdDatagramClass>,
        range: RangeInclusive<u64>,
    ) -> bool {
        let start = *range.start();
        let end = *range.end();
        let mut expected = start;
        for (&packet_number, &class) in history.range(start..=end) {
            if packet_number != expected || class != QcsdDatagramClass::DefenseCover {
                return false;
            }
            if packet_number == end {
                return true;
            }
            expected = packet_number.saturating_add(1);
        }
        false
    }
}

pub(super) const fn combine_datagram_class(
    current: Option<QcsdDatagramClass>,
    next: QcsdDatagramClass,
) -> QcsdDatagramClass {
    match (current, next) {
        (Some(QcsdDatagramClass::Natural), _) | (_, QcsdDatagramClass::Natural) => {
            QcsdDatagramClass::Natural
        }
        (Some(QcsdDatagramClass::DefenseCover) | None, QcsdDatagramClass::DefenseCover) => {
            QcsdDatagramClass::DefenseCover
        }
    }
}

fn classify_outgoing_evidence(
    scheduled_cover: bool,
    token_classes: impl IntoIterator<Item = QcsdDatagramClass>,
) -> QcsdDatagramClass {
    token_classes
        .into_iter()
        .fold(
            scheduled_cover.then_some(QcsdDatagramClass::DefenseCover),
            |current, next| Some(combine_datagram_class(current, next)),
        )
        .unwrap_or(QcsdDatagramClass::Natural)
}

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
        if let (Some(endpoint), Some(clock)) =
            (self.qcsd_endpoint, self.qcsd_observation_clock.as_ref())
        {
            self.qcsd_observations
                .push_back(clock.record(observation(endpoint)));
        }
    }

    /// Drain transport-level observations with causal production metadata.
    #[must_use]
    pub fn qcsd_timestamped_observations(&mut self) -> Vec<TimestampedQcsdObservation> {
        self.qcsd_observations.drain(..).collect()
    }

    pub(super) fn qcsd_observe_stream_transmissions(&mut self, tokens: &recovery::Tokens) {
        let transmissions: Vec<_> = tokens
            .iter()
            .filter_map(|token| {
                let Token::Stream(StreamRecoveryToken::Stream(token)) = token else {
                    return None;
                };
                let role = self.qcsd_stream_roles.get(&token.stream_id()).copied()?;
                let bytes = u64::try_from(token.length()).ok()?;
                (bytes > 0).then_some((token.stream_id(), role, token.offset(), bytes))
            })
            .collect();
        for (stream, role, offset, bytes) in transmissions {
            self.qcsd_observe(|endpoint| QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: neqo_csdef::QcsdStreamId(stream.as_u64()),
                role,
                offset,
                bytes,
            });
        }
    }

    /// Bind transport target outcomes to a controller endpoint.
    pub fn qcsd_enable(&mut self, endpoint: QcsdEndpointId, shape_stream_sends: bool) {
        #![expect(
            clippy::disallowed_methods,
            reason = "standalone adapter callers need a monotonic observation-clock origin"
        )]
        self.qcsd_enable_with_observation_clock(
            endpoint,
            shape_stream_sends,
            QcsdObservationClock::new(Instant::now()),
        );
    }

    /// Enable QCSD with a clock shared by every connection in one runner.
    pub fn qcsd_enable_with_observation_clock(
        &mut self,
        endpoint: QcsdEndpointId,
        shape_stream_sends: bool,
        observation_clock: QcsdObservationClock,
    ) {
        self.qcsd_endpoint = Some(endpoint);
        self.qcsd_observation_clock = Some(observation_clock);
        self.qcsd_enable_send_shaping(shape_stream_sends);
    }

    /// Apply one UDP-payload ceiling to every packet-number space in a QCSD run.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` below QUIC's 1200-byte minimum datagram size.
    pub const fn qcsd_set_udp_payload_ceiling(&mut self, ceiling: u16) -> Res<()> {
        if ceiling < 1_200 {
            return Err(Error::InvalidInput);
        }
        self.qcsd_udp_payload_ceiling = Some(ceiling);
        Ok(())
    }

    /// Install a per-connection same-datagram Traffic Morphing sampler.
    pub fn qcsd_enable_traffic_morphing(&mut self, morpher: TrafficMorphingEgress) {
        self.qcsd_traffic_morphing = Some(morpher);
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
        self.qcsd_stream_roles.insert(stream_id, role);
        if !self.qcsd_send_shaping && self.qcsd_traffic_morphing.is_none() {
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
        let path_limit = path.borrow().plpmtu();
        let effective_limit = self
            .qcsd_udp_payload_ceiling
            .map_or(path_limit, |ceiling| path_limit.min(usize::from(ceiling)));
        if udp_payload_size < 64 || usize::from(udp_payload_size) > effective_limit {
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

    fn qcsd_stream_class(&self, stream: StreamId) -> QcsdDatagramClass {
        match self.qcsd_stream_roles.get(&stream) {
            Some(QcsdRequestRole::Chaff { .. }) => QcsdDatagramClass::DefenseCover,
            Some(QcsdRequestRole::Application) | None => QcsdDatagramClass::Natural,
        }
    }

    pub(super) fn qcsd_classify_incoming_frame(
        &self,
        space: PacketNumberSpace,
        frame: &Frame<'_>,
    ) -> Option<QcsdDatagramClass> {
        match frame {
            Frame::Padding(_) => None,
            Frame::Ack {
                largest_acknowledged,
                first_ack_range,
                ack_ranges,
                ..
            } => Some(
                Frame::decode_ack_frame(*largest_acknowledged, *first_ack_range, ack_ranges)
                    .map_or(QcsdDatagramClass::Natural, |ranges| {
                        self.qcsd_packet_classifier
                            .classify_ack(Direction::Incoming, space, ranges)
                    }),
            ),
            Frame::Stream { stream_id, .. }
            | Frame::ResetStream { stream_id, .. }
            | Frame::ResetStreamAt { stream_id, .. }
            | Frame::StopSending { stream_id, .. }
            | Frame::MaxStreamData { stream_id, .. }
            | Frame::StreamDataBlocked { stream_id, .. } => {
                Some(self.qcsd_stream_class(*stream_id))
            }
            Frame::Ping
            | Frame::Crypto { .. }
            | Frame::NewToken { .. }
            | Frame::MaxData { .. }
            | Frame::MaxStreams { .. }
            | Frame::DataBlocked { .. }
            | Frame::StreamsBlocked { .. }
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId { .. }
            | Frame::PathChallenge { .. }
            | Frame::PathResponse { .. }
            | Frame::ConnectionClose { .. }
            | Frame::HandshakeDone
            | Frame::AckFrequency { .. }
            | Frame::Datagram { .. } => Some(QcsdDatagramClass::Natural),
        }
    }

    pub(super) fn qcsd_record_incoming_packet(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        class: QcsdDatagramClass,
    ) {
        self.qcsd_packet_classifier
            .record(Direction::Incoming, space, packet_number, class);
        self.qcsd_incoming_datagram_class = Some(combine_datagram_class(
            self.qcsd_incoming_datagram_class,
            class,
        ));
    }

    pub(super) fn qcsd_record_duplicate_incoming_packet(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
    ) {
        let class = self
            .qcsd_packet_classifier
            .recorded(Direction::Incoming, space, packet_number);
        self.qcsd_incoming_datagram_class = Some(combine_datagram_class(
            self.qcsd_incoming_datagram_class,
            class,
        ));
    }

    pub(super) const fn qcsd_begin_incoming_datagram(&mut self) {
        self.qcsd_incoming_datagram_class = None;
    }

    pub(super) fn qcsd_finish_incoming_datagram(&mut self, length: usize) {
        let class = self
            .qcsd_incoming_datagram_class
            .take()
            .unwrap_or(QcsdDatagramClass::Natural);
        let length = u16::try_from(length).unwrap_or(u16::MAX);
        self.qcsd_observe(|endpoint| QcsdObservation::ClassifiedDatagram {
            endpoint,
            direction: Direction::Incoming,
            length,
            class,
        });
    }

    fn qcsd_classify_outgoing_token(
        &self,
        space: PacketNumberSpace,
        token: &Token,
    ) -> Option<QcsdDatagramClass> {
        match token {
            Token::Ack(ack) => Some(
                self.qcsd_packet_classifier.classify_ack(
                    Direction::Outgoing,
                    space,
                    ack.ranges()
                        .iter()
                        .map(|range| range.smallest()..=range.largest()),
                ),
            ),
            Token::Stream(StreamRecoveryToken::Stream(token)) => {
                Some(self.qcsd_stream_class(token.stream_id()))
            }
            Token::Stream(
                StreamRecoveryToken::ResetStream { stream_id }
                | StreamRecoveryToken::StopSending { stream_id }
                | StreamRecoveryToken::MaxStreamData { stream_id, .. }
                | StreamRecoveryToken::StreamDataBlocked { stream_id, .. },
            ) => Some(self.qcsd_stream_class(*stream_id)),
            Token::EcnEct0 => None,
            Token::Stream(
                StreamRecoveryToken::MaxData(_)
                | StreamRecoveryToken::DataBlocked(_)
                | StreamRecoveryToken::MaxStreams { .. }
                | StreamRecoveryToken::StreamsBlocked { .. },
            )
            | Token::Crypto(_)
            | Token::HandshakeDone
            | Token::KeepAlive
            | Token::NewToken(_)
            | Token::NewConnectionId(_)
            | Token::RetireConnectionId(_)
            | Token::AckFrequency(_)
            | Token::Datagram(_)
            | Token::PmtudProbe => Some(QcsdDatagramClass::Natural),
        }
    }

    pub(super) fn qcsd_classify_outgoing_packet(
        &mut self,
        space: PacketNumberSpace,
        packet_number: u64,
        tokens: &recovery::Tokens,
        scheduled_cover: bool,
    ) -> QcsdDatagramClass {
        let class = classify_outgoing_evidence(
            scheduled_cover,
            tokens
                .iter()
                .filter_map(|token| self.qcsd_classify_outgoing_token(space, token)),
        );
        self.qcsd_packet_classifier
            .record(Direction::Outgoing, space, packet_number, class);
        class
    }

    pub(super) fn qcsd_observe_outgoing_datagram(
        &mut self,
        length: usize,
        class: Option<QcsdDatagramClass>,
    ) {
        let length = u16::try_from(length).unwrap_or(u16::MAX);
        let class = class.unwrap_or(QcsdDatagramClass::Natural);
        self.qcsd_observe(|endpoint| QcsdObservation::ClassifiedDatagram {
            endpoint,
            direction: Direction::Outgoing,
            length,
            class,
        });
    }
}

#[cfg(test)]
mod tests {
    use neqo_csdef::{Direction, QcsdDatagramClass};

    use super::{QcsdPacketClassifier, classify_outgoing_evidence};
    use crate::tracking::PacketNumberSpace;

    const SPACE: PacketNumberSpace = PacketNumberSpace::ApplicationData;

    #[test]
    fn outgoing_cover_ack_is_causally_cover() {
        let mut classifier = QcsdPacketClassifier::default();
        classifier.record(
            Direction::Outgoing,
            SPACE,
            10,
            QcsdDatagramClass::DefenseCover,
        );
        assert_eq!(
            classifier.classify_ack(Direction::Incoming, SPACE, [10..=10]),
            QcsdDatagramClass::DefenseCover
        );
    }

    #[test]
    fn incoming_chaff_ack_is_causally_cover() {
        let mut classifier = QcsdPacketClassifier::default();
        classifier.record(
            Direction::Incoming,
            SPACE,
            20,
            QcsdDatagramClass::DefenseCover,
        );
        assert_eq!(
            classifier.classify_ack(Direction::Outgoing, SPACE, [20..=20]),
            QcsdDatagramClass::DefenseCover
        );
    }

    #[test]
    fn mixed_ack_range_is_natural() {
        let mut classifier = QcsdPacketClassifier::default();
        classifier.record(
            Direction::Outgoing,
            SPACE,
            30,
            QcsdDatagramClass::DefenseCover,
        );
        classifier.record(Direction::Outgoing, SPACE, 31, QcsdDatagramClass::Natural);
        assert_eq!(
            classifier.classify_ack(Direction::Incoming, SPACE, [30..=31]),
            QcsdDatagramClass::Natural
        );
    }

    #[test]
    fn unknown_ack_packet_number_is_natural() {
        let classifier = QcsdPacketClassifier::default();
        assert_eq!(
            classifier.classify_ack(Direction::Incoming, SPACE, [40..=40]),
            QcsdDatagramClass::Natural
        );
    }

    #[test]
    fn natural_application_or_control_ack_remains_natural() {
        let mut classifier = QcsdPacketClassifier::default();
        classifier.record(Direction::Incoming, SPACE, 50, QcsdDatagramClass::Natural);
        assert_eq!(
            classifier.classify_ack(Direction::Outgoing, SPACE, [50..=50]),
            QcsdDatagramClass::Natural
        );
    }

    #[test]
    fn scheduled_cover_mixed_with_natural_control_is_natural() {
        assert_eq!(
            classify_outgoing_evidence(
                true,
                [QcsdDatagramClass::DefenseCover, QcsdDatagramClass::Natural,],
            ),
            QcsdDatagramClass::Natural
        );
    }

    #[test]
    fn scheduled_cover_with_only_cover_ack_remains_cover() {
        assert_eq!(
            classify_outgoing_evidence(true, [QcsdDatagramClass::DefenseCover]),
            QcsdDatagramClass::DefenseCover
        );
    }
}
