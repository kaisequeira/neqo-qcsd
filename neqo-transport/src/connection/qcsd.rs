// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{
    collections::{BTreeMap, VecDeque},
    ops::RangeInclusive,
    time::{Duration, Instant},
};

use enum_map::EnumMap;
use neqo_csdef::{
    Direction, MissedSlotReason, Packet, QcsdCongestionReason, QcsdDatagramClass, QcsdEndpointId,
    QcsdObservation, QcsdObservationClock, QcsdReceiveActionIdentity, QcsdRequestRole,
    QcsdSendPolicy, QcsdSlotComposition, QcsdSlotId, QcsdSlotOutcome, TimestampedQcsdObservation,
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
    pub endpoint: Option<QcsdEndpointId>,
    pub slot: QcsdSlotId,
    pub udp_payload_size: u16,
    pub attempt_udp_payload_size: u16,
    pub packet: Packet,
    pub not_before: Option<Instant>,
    pub deadline: Instant,
    pub allow_stream_data: bool,
    pub send_policy: QcsdSendPolicy,
    pub defense_control_bytes: u16,
    pub lateness_us: u64,
    /// UDP bytes present immediately before QUIC PADDING is applied.
    pub unpadded_udp_bytes: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingReceiveCredit {
    pub slot: QcsdSlotId,
    pub stream: StreamId,
    pub absolute_limit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingReceiveAction {
    pub identity: QcsdReceiveActionIdentity,
    pub previous_limit: u64,
    pub previous_frame_pending: bool,
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
        let Some(endpoint) = self.qcsd_endpoint else {
            return;
        };
        self.qcsd_observe_at_endpoint(endpoint, observation);
    }

    fn qcsd_observe_at_endpoint(
        &mut self,
        endpoint: QcsdEndpointId,
        observation: impl FnOnce(QcsdEndpointId) -> QcsdObservation,
    ) {
        let Some(clock) = self.qcsd_observation_clock.as_ref() else {
            return;
        };
        self.qcsd_observations
            .push_back(clock.record(observation(endpoint)));
    }

    /// Drain transport-level observations with causal production metadata.
    #[must_use]
    pub fn qcsd_timestamped_observations(&mut self) -> Vec<TimestampedQcsdObservation> {
        self.qcsd_observations.drain(..).collect()
    }

    /// Drain every encoded STREAM frame, including HTTP/3 and QPACK critical
    /// streams that do not have a registered request role.
    #[must_use]
    pub fn qcsd_stream_transmissions(&mut self) -> Vec<neqo_csdef::QcsdStreamTransmission> {
        self.qcsd_stream_transmissions
            .as_mut()
            .map(|transmissions| transmissions.drain(..).collect())
            .unwrap_or_default()
    }

    /// Enable or disable the qualifier-only raw all-STREAM transcript.
    pub fn qcsd_enable_stream_transcript(&mut self, enabled: bool) {
        self.qcsd_stream_transmissions = enabled.then(VecDeque::new);
        self.qcsd_next_stream_transmission_sequence = 0;
    }

    /// Whether transport retains any unsent or retransmission STREAM frame.
    pub fn qcsd_has_pending_stream_send(&mut self) -> bool {
        self.streams.qcsd_has_pending_send_data()
    }

    /// Whether candidate-defense receive control or a local-ET cancellation
    /// remains unencoded, in flight, or awaiting loss recovery.
    #[must_use]
    pub fn qcsd_has_pending_defense_control(&self) -> bool {
        !self.qcsd_pending_receive_actions.is_empty()
            || !self.qcsd_pending_receive_credit.is_empty()
            || self
                .qcsd_unacked_defense_receive_limits
                .keys()
                .any(|stream| {
                    self.streams
                        .qcsd_receive_limit_pending_or_in_flight(*stream)
                })
            || self.qcsd_unacked_local_et_resets.iter().any(|stream| {
                self.streams
                    .qcsd_local_et_reset_pending_or_in_flight(*stream)
            })
            || self
                .qcsd_unacked_local_et_stop_sending
                .iter()
                .any(|stream| {
                    self.streams
                        .qcsd_local_et_stop_pending_or_in_flight(*stream)
                })
    }

    /// Mark each transport cancellation control actually queued by a
    /// successful typed candidate-defense chaff cancellation as defense-owned.
    pub fn qcsd_mark_chaff_cancellation(&mut self, stream: StreamId) {
        // STOP_SENDING supersedes receive-window advertisement for this
        // abandoned response. The transport will not regenerate an unacked
        // MAX_STREAM_DATA after the receive side enters AbortReading.
        self.qcsd_unacked_defense_receive_limits.remove(&stream);
        let (reset, stop_sending) = self.streams.qcsd_local_et_cancellation_controls(stream);
        if reset {
            self.qcsd_unacked_local_et_resets.insert(stream);
        }
        if stop_sending {
            self.qcsd_unacked_local_et_stop_sending.insert(stream);
        }
    }

    /// Whether any STREAM other than the explicitly allowed streams remains pending.
    pub fn qcsd_has_pending_stream_send_excluding(&mut self, allowed: &[StreamId]) -> bool {
        self.streams.qcsd_has_pending_send_data_excluding(allowed)
    }

    /// Whether one exact stream retains unsent or retransmission STREAM data.
    pub fn qcsd_has_pending_stream_send_for(&mut self, stream_id: StreamId) -> bool {
        self.streams.qcsd_has_pending_send_data_for(stream_id)
    }

    /// Whether a registered application request's QUIC send half is terminal
    /// and peer-confirmed.
    ///
    /// This becomes true only in transport `DataRecvd` (all STREAM bytes and
    /// FIN acknowledged) or `ResetRecvd` (`RESET_STREAM` acknowledged). Merely
    /// reaching `DataSent`, `ResetSent`, or `ResetSentReliable` is not enough.
    #[must_use]
    pub fn qcsd_application_send_stream_peer_confirmed(&self, stream_id: StreamId) -> bool {
        matches!(
            self.qcsd_stream_roles.get(&stream_id),
            Some(QcsdRequestRole::Application)
        ) && self.streams.qcsd_send_stream_peer_confirmed(stream_id)
    }

    pub(super) fn qcsd_observe_stream_transmissions(&mut self, tokens: &recovery::Tokens) {
        let slot = self.qcsd_active_target.map(|target| target.slot);
        let transmissions: Vec<_> = tokens
            .iter()
            .filter_map(|token| {
                let Token::Stream(StreamRecoveryToken::Stream(token)) = token else {
                    return None;
                };
                let bytes = u64::try_from(token.length()).ok()?;
                (bytes > 0 || token.fin()).then_some((
                    token.stream_id(),
                    self.qcsd_stream_roles.get(&token.stream_id()).copied(),
                    token.offset(),
                    bytes,
                    token.fin(),
                ))
            })
            .collect();
        for (stream, role, offset, bytes, fin) in transmissions {
            let stream = neqo_csdef::QcsdStreamId(stream.as_u64());
            if let Some(transcript) = self.qcsd_stream_transmissions.as_mut() {
                transcript.push_back(neqo_csdef::QcsdStreamTransmission {
                    sequence: self.qcsd_next_stream_transmission_sequence,
                    stream,
                    role,
                    offset,
                    bytes,
                    fin,
                    slot,
                });
                self.qcsd_next_stream_transmission_sequence = self
                    .qcsd_next_stream_transmission_sequence
                    .saturating_add(1);
            }
            if let Some(role) = role {
                self.qcsd_observe(|endpoint| QcsdObservation::StreamDataTransmitted {
                    endpoint,
                    stream,
                    role,
                    offset,
                    bytes,
                    fin,
                    slot,
                });
            }
        }
    }

    pub(super) fn qcsd_observe_stream_acknowledgment(
        &mut self,
        token: &crate::send_stream::RecoveryToken,
    ) {
        let Some(role) = self.qcsd_stream_roles.get(&token.stream_id()).copied() else {
            return;
        };
        let Ok(bytes) = u64::try_from(token.length()) else {
            return;
        };
        if bytes == 0 && !token.fin() {
            return;
        }
        self.qcsd_observe(|endpoint| QcsdObservation::StreamDataAcknowledged {
            endpoint,
            stream: neqo_csdef::QcsdStreamId(token.stream_id().as_u64()),
            role,
            offset: token.offset(),
            bytes,
            fin: token.fin(),
        });
    }

    /// Bind transport target outcomes to a controller endpoint.
    ///
    /// A repeated bind is ignored, preserving the connection's original
    /// endpoint, observation clock, and send-shaping policy.
    pub fn qcsd_enable(&mut self, endpoint: QcsdEndpointId, shape_stream_sends: bool) {
        let _enable_result = self.qcsd_try_enable(endpoint, shape_stream_sends);
    }

    /// Bind transport target outcomes to a controller endpoint, reporting a
    /// repeated bind to callers that require fail-closed setup.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when QCSD is already bound. A binding includes
    /// its observation clock and cannot be replaced while the connection is
    /// alive.
    pub fn qcsd_try_enable(
        &mut self,
        endpoint: QcsdEndpointId,
        shape_stream_sends: bool,
    ) -> Res<()> {
        #![expect(
            clippy::disallowed_methods,
            reason = "standalone adapter callers need a monotonic observation-clock origin"
        )]
        self.qcsd_try_enable_with_observation_clock(
            endpoint,
            shape_stream_sends,
            QcsdObservationClock::new(Instant::now()),
        )
    }

    /// Enable QCSD with a clock shared by every connection in one runner.
    ///
    /// A repeated bind is ignored, preserving the connection's original
    /// endpoint, observation clock, and send-shaping policy.
    pub fn qcsd_enable_with_observation_clock(
        &mut self,
        endpoint: QcsdEndpointId,
        shape_stream_sends: bool,
        observation_clock: QcsdObservationClock,
    ) {
        let _enable_result = self.qcsd_try_enable_with_observation_clock(
            endpoint,
            shape_stream_sends,
            observation_clock,
        );
    }

    /// Enable QCSD with a shared clock, reporting a repeated bind to callers
    /// that require fail-closed setup.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` when QCSD is already bound. A binding includes
    /// its observation clock and cannot be replaced while the connection is
    /// alive.
    pub fn qcsd_try_enable_with_observation_clock(
        &mut self,
        endpoint: QcsdEndpointId,
        shape_stream_sends: bool,
        observation_clock: QcsdObservationClock,
    ) -> Res<()> {
        if self.qcsd_endpoint.is_some() {
            return Err(Error::InvalidInput);
        }
        self.qcsd_endpoint = Some(endpoint);
        self.qcsd_observation_clock = Some(observation_clock);
        self.qcsd_enable_send_shaping(shape_stream_sends);
        Ok(())
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

    /// Queue an immediately eligible, attributed exact-size 1-RTT UDP payload target.
    ///
    /// # Errors
    ///
    /// Returns `NotAvailable` before 1-RTT keys/path state are usable and
    /// `InvalidInput` when the target regresses queue order or is outside the
    /// active path range.
    pub fn qcsd_queue_scheduled_packet_target(
        &mut self,
        slot: QcsdSlotId,
        packet: Packet,
        deadline: Instant,
        allow_stream_data: bool,
    ) -> Res<()> {
        self.qcsd_validate_packet_target_window(None, deadline)?;
        self.qcsd_queue_scheduled_packet_target_inner(
            slot,
            packet,
            None,
            deadline,
            allow_stream_data,
            QcsdSendPolicy::Exact,
        )
    }

    /// Queue an attributed exact-size 1-RTT UDP payload target with an
    /// explicit eligibility window.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an empty window or one that regresses relative
    /// to the preceding target. Otherwise returns the same errors as
    /// [`Self::qcsd_queue_scheduled_packet_target`].
    pub fn qcsd_queue_scheduled_packet_target_window(
        &mut self,
        slot: QcsdSlotId,
        packet: Packet,
        not_before: Instant,
        deadline: Instant,
        allow_stream_data: bool,
    ) -> Res<()> {
        self.qcsd_validate_packet_target_window(Some(not_before), deadline)?;
        self.qcsd_queue_scheduled_packet_target_inner(
            slot,
            packet,
            Some(not_before),
            deadline,
            allow_stream_data,
            QcsdSendPolicy::Exact,
        )
    }

    /// Queue a scheduled target with an explicit realization policy.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as
    /// [`Self::qcsd_queue_scheduled_packet_target_window`].
    pub fn qcsd_queue_scheduled_packet_target_window_with_policy(
        &mut self,
        slot: QcsdSlotId,
        packet: Packet,
        not_before: Instant,
        deadline: Instant,
        allow_stream_data: bool,
        send_policy: QcsdSendPolicy,
    ) -> Res<()> {
        self.qcsd_validate_packet_target_window(Some(not_before), deadline)?;
        self.qcsd_queue_scheduled_packet_target_inner(
            slot,
            packet,
            Some(not_before),
            deadline,
            allow_stream_data,
            send_policy,
        )
    }

    fn qcsd_validate_packet_target_window(
        &self,
        not_before: Option<Instant>,
        deadline: Instant,
    ) -> Res<()> {
        if not_before.is_some_and(|release| release >= deadline)
            || self.qcsd_packet_targets.back().is_some_and(|previous| {
                not_before < previous.not_before || deadline < previous.deadline
            })
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    fn qcsd_queue_scheduled_packet_target_inner(
        &mut self,
        slot: QcsdSlotId,
        packet: Packet,
        not_before: Option<Instant>,
        deadline: Instant,
        allow_stream_data: bool,
        send_policy: QcsdSendPolicy,
    ) -> Res<()> {
        let endpoint = self.qcsd_endpoint;
        let udp_payload_size = packet.length();
        if !self.state.connected() {
            if let Some(endpoint) = endpoint {
                self.qcsd_observe_at_endpoint(endpoint, |endpoint| QcsdObservation::SlotMissed {
                    endpoint,
                    slot,
                    packet,
                    reason: MissedSlotReason::KeysUnavailable,
                });
            }
            return Err(Error::NotAvailable);
        }
        let path = self.paths.primary().ok_or(Error::NotAvailable)?;
        let path_limit = path.borrow().plpmtu();
        let effective_limit = self
            .qcsd_udp_payload_ceiling
            .map_or(path_limit, |ceiling| path_limit.min(usize::from(ceiling)));
        if udp_payload_size < 64 || usize::from(udp_payload_size) > effective_limit {
            if let Some(endpoint) = endpoint {
                self.qcsd_observe_at_endpoint(endpoint, |endpoint| QcsdObservation::SlotMissed {
                    endpoint,
                    slot,
                    packet,
                    reason: MissedSlotReason::PathMtu,
                });
            }
            return Err(Error::InvalidInput);
        }
        self.qcsd_packet_targets.push_back(PacketTarget {
            endpoint,
            slot,
            udp_payload_size,
            attempt_udp_payload_size: udp_payload_size,
            packet,
            not_before,
            deadline,
            allow_stream_data,
            send_policy,
            defense_control_bytes: 0,
            lateness_us: 0,
            unpadded_udp_bytes: None,
        });
        Ok(())
    }

    pub(super) fn qcsd_packet_target_wakeup(&self, now: Instant) -> Option<Instant> {
        self.qcsd_packet_targets.front().map(|target| {
            if now >= target.deadline {
                now
            } else if let Some(not_before) = target.not_before.filter(|release| now < *release) {
                not_before
            } else {
                target.deadline
            }
        })
    }

    pub(super) fn qcsd_eligible_packet_target(&self, now: Instant) -> Option<PacketTarget> {
        self.qcsd_packet_targets
            .iter()
            .find(|target| now < target.deadline)
            .copied()
            .filter(|target| {
                target.not_before.is_none_or(|not_before| now >= not_before)
                    && now < target.deadline
            })
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
            let mut target = self
                .qcsd_packet_targets
                .pop_front()
                .expect("front target inspected");
            target.lateness_us = target.not_before.map_or(0, |release| {
                u64::try_from(now.saturating_duration_since(release).as_micros())
                    .unwrap_or(u64::MAX)
            });
            let congestion_reason = if paced {
                Some(QcsdCongestionReason::PacingLimited)
            } else if congestion_limit
                .is_some_and(|limit| limit < usize::from(target.udp_payload_size))
            {
                Some(QcsdCongestionReason::CongestionLimited)
            } else {
                None
            };
            if target.send_policy == QcsdSendPolicy::CongestionSensitive
                && let Some(reason) = congestion_reason
            {
                self.qcsd_target_resolved(
                    &target,
                    QcsdSlotOutcome::Suppressed {
                        composition: Self::qcsd_suppressed_composition(&target),
                        reason,
                    },
                );
            } else {
                let reason = match congestion_reason {
                    Some(QcsdCongestionReason::PacingLimited) => MissedSlotReason::PacingLimited,
                    Some(QcsdCongestionReason::CongestionLimited) => {
                        MissedSlotReason::CongestionLimited
                    }
                    None => MissedSlotReason::DeadlineExpired,
                };
                self.qcsd_target_missed(&target, reason);
            }
        }
    }

    pub(super) fn qcsd_target_satisfied(&mut self, target: &PacketTarget) {
        if let Some(endpoint) = target.endpoint {
            self.qcsd_observe_at_endpoint(endpoint, |endpoint| QcsdObservation::SlotSatisfied {
                endpoint,
                slot: target.slot,
                observed_size: target.udp_payload_size,
            });
        }
    }

    pub(super) fn qcsd_target_resolved(&mut self, target: &PacketTarget, outcome: QcsdSlotOutcome) {
        if let Some(endpoint) = target.endpoint {
            self.qcsd_observe_at_endpoint(endpoint, |endpoint| QcsdObservation::SlotResolved {
                endpoint,
                slot: target.slot,
                packet: target.packet,
                outcome,
            });
        }
    }

    pub(super) fn qcsd_suppress_congestion_sensitive_target(
        &mut self,
        target: &PacketTarget,
        reason: QcsdCongestionReason,
    ) {
        let removed = self.qcsd_packet_targets.pop_front();
        debug_assert!(removed.is_some_and(|queued| queued.slot == target.slot));
        self.qcsd_target_resolved(
            target,
            QcsdSlotOutcome::Suppressed {
                composition: Self::qcsd_suppressed_composition(target),
                reason,
            },
        );
    }

    const fn qcsd_suppressed_composition(target: &PacketTarget) -> QcsdSlotComposition {
        QcsdSlotComposition {
            desired_udp_bytes: target.udp_payload_size,
            observed_udp_bytes: 0,
            application_stream_bytes: 0,
            retransmission_stream_bytes: 0,
            chaff_stream_bytes: 0,
            defense_control_bytes: 0,
            quic_padding_bytes: 0,
            other_quic_bytes: 0,
            lateness_us: target.lateness_us,
        }
    }

    pub(super) fn qcsd_miss_congestion_sensitive_target(
        &mut self,
        target: &PacketTarget,
        reason: MissedSlotReason,
    ) {
        let removed = self.qcsd_packet_targets.pop_front();
        debug_assert!(removed.is_some_and(|queued| queued.slot == target.slot));
        self.qcsd_target_missed(target, reason);
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the transport reports every mutually exclusive wire-composition category"
    )]
    pub(super) fn qcsd_resolve_congestion_sensitive_target(
        &mut self,
        target: &PacketTarget,
        observed_udp_bytes: u16,
        application_stream_bytes: u16,
        retransmission_stream_bytes: u16,
        chaff_stream_bytes: u16,
        quic_padding_bytes: u16,
        reason: Option<QcsdCongestionReason>,
    ) {
        let removed = self.qcsd_packet_targets.pop_front();
        debug_assert!(removed.is_some_and(|queued| queued.slot == target.slot));
        let classified_bytes = application_stream_bytes
            .saturating_add(retransmission_stream_bytes)
            .saturating_add(chaff_stream_bytes)
            .saturating_add(target.defense_control_bytes)
            .saturating_add(quic_padding_bytes);
        let composition = QcsdSlotComposition {
            desired_udp_bytes: target.udp_payload_size,
            observed_udp_bytes,
            application_stream_bytes,
            retransmission_stream_bytes,
            chaff_stream_bytes,
            defense_control_bytes: target.defense_control_bytes,
            quic_padding_bytes,
            other_quic_bytes: observed_udp_bytes.saturating_sub(classified_bytes),
            lateness_us: target.lateness_us,
        };
        let outcome = reason.map_or(QcsdSlotOutcome::Full { composition }, |reason| {
            QcsdSlotOutcome::Partial {
                composition,
                reason,
            }
        });
        self.qcsd_target_resolved(target, outcome);
    }

    pub(super) fn qcsd_target_missed(&mut self, target: &PacketTarget, reason: MissedSlotReason) {
        if let Some(endpoint) = target.endpoint {
            self.qcsd_observe_at_endpoint(endpoint, |endpoint| QcsdObservation::SlotMissed {
                endpoint,
                slot: target.slot,
                packet: target.packet,
                reason,
            });
        }
    }

    pub(super) fn qcsd_receive_limit_advertised(&mut self, stream: StreamId, absolute_limit: u64) {
        if self.qcsd_receive_limit_is_defense_control(stream, absolute_limit) {
            self.qcsd_defense_receive_limit_high_water
                .entry(stream)
                .and_modify(|high_water| *high_water = (*high_water).max(absolute_limit))
                .or_insert(absolute_limit);
            self.qcsd_unacked_defense_receive_limits
                .entry(stream)
                .and_modify(|pending| *pending = (*pending).max(absolute_limit))
                .or_insert(absolute_limit);
        }
        self.qcsd_pending_receive_actions.retain(|pending| {
            pending.identity.stream().0 != stream.as_u64()
                || pending.identity.absolute_limit() > absolute_limit
        });
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

    pub(super) fn qcsd_receive_limit_is_defense_control(
        &self,
        stream: StreamId,
        absolute_limit: u64,
    ) -> bool {
        self.qcsd_pending_receive_actions.iter().any(|pending| {
            pending.identity.stream().0 == stream.as_u64()
                && pending.identity.absolute_limit() <= absolute_limit
        }) || self
            .qcsd_pending_receive_credit
            .iter()
            .any(|credit| credit.stream == stream && credit.absolute_limit <= absolute_limit)
            || self
                .qcsd_defense_receive_limit_high_water
                .get(&stream)
                .is_some_and(|high_water| absolute_limit <= *high_water)
    }

    pub(super) fn qcsd_defense_receive_control_acked(
        &mut self,
        stream: StreamId,
        absolute_limit: u64,
    ) {
        if self
            .qcsd_unacked_defense_receive_limits
            .get(&stream)
            .is_some_and(|pending| absolute_limit >= *pending)
        {
            self.qcsd_unacked_defense_receive_limits.remove(&stream);
        }
    }

    pub(super) fn qcsd_defense_receive_control_lost(
        &mut self,
        stream: StreamId,
        absolute_limit: u64,
    ) {
        if self
            .qcsd_unacked_defense_receive_limits
            .get(&stream)
            .is_some_and(|pending| absolute_limit >= *pending)
            && !self.streams.qcsd_receive_limit_pending_or_in_flight(stream)
        {
            self.qcsd_unacked_defense_receive_limits.remove(&stream);
        }
    }

    pub(super) fn qcsd_local_et_receive_state_changed(&mut self, stream: StreamId) {
        // ACKing STOP_SENDING is not terminal when the peer's final size is
        // still unknown: the receive side enters WaitForReset until the peer
        // supplies RESET_STREAM. Retain the defense-control identity across
        // that interval so the runner cannot finish with an open QUIC stream.
        if !self.streams.qcsd_local_et_stop_pending_or_in_flight(stream) {
            self.qcsd_unacked_local_et_stop_sending.remove(&stream);
        }
    }

    pub(super) fn qcsd_local_et_reset_acked(&mut self, stream: StreamId) {
        self.qcsd_unacked_local_et_resets.remove(&stream);
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
            composition: None,
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
            Token::Stream(StreamRecoveryToken::MaxStreamData {
                stream_id,
                max_data,
            }) if self.qcsd_receive_limit_is_defense_control(*stream_id, *max_data) => {
                Some(QcsdDatagramClass::DefenseCover)
            }
            Token::Stream(
                StreamRecoveryToken::ResetStream { stream_id, .. }
                | StreamRecoveryToken::StopSending { stream_id, .. }
                | StreamRecoveryToken::StreamDataBlocked { stream_id, .. },
            ) => Some(self.qcsd_stream_class(*stream_id)),
            Token::Stream(StreamRecoveryToken::MaxStreamData { stream_id, .. }) => {
                Some(self.qcsd_stream_class(*stream_id))
            }
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
        composition: QcsdSlotComposition,
    ) {
        let length = u16::try_from(length).unwrap_or(u16::MAX);
        let class = class.unwrap_or(QcsdDatagramClass::Natural);
        self.qcsd_observe(|endpoint| QcsdObservation::ClassifiedDatagram {
            endpoint,
            direction: Direction::Outgoing,
            length,
            class,
            composition: Some(composition),
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
