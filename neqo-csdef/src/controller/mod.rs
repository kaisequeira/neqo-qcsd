// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

mod control_loop;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

use control_loop::{ControlLoop, PendingCredit, PendingIncoming, PendingOutgoing};

use crate::{
    Capacity, Defense, DefenseConfig, DefenseDiagnostics, DefenseMode, DefenseSignal, Direction,
    EventOutcome, Front, MissedSlotReason, QcsdAction, QcsdConfig, QcsdEndpointId, QcsdObservation,
    QcsdRequestRole, QcsdSlotId, QcsdStreamId, ResourceManifest, Result, RoundRobinScheduler,
    SignalKind, StaticSchedule, Tamaraw, TrafficMorphing, WalkieTalkie, WtfPad,
    chaff_manager::ChaffManager, stream::StreamRegistry,
};

#[derive(Clone, Copy, Debug)]
enum QueuedDefenseObservation {
    Signal(DefenseSignal),
    ApplicationBytes {
        at: Duration,
        direction: Direction,
        bytes: u64,
    },
}

impl QueuedDefenseObservation {
    const fn at(self) -> Duration {
        match self {
            Self::Signal(signal) => signal.at,
            Self::ApplicationBytes { at, .. } => at,
        }
    }
}

fn covered_range_bytes(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().fold(0_u64, |total, (start, end)| {
        total.saturating_add(end.saturating_sub(*start))
    })
}

fn merge_ranges(ranges: &mut Vec<(u64, u64)>) {
    if ranges.is_empty() {
        return;
    }
    let mut merged_index = 0;
    for candidate_index in 1..ranges.len() {
        let candidate = ranges[candidate_index];
        if candidate.0 <= ranges[merged_index].1 {
            ranges[merged_index].1 = ranges[merged_index].1.max(candidate.1);
        } else {
            merged_index += 1;
            ranges[merged_index] = candidate;
        }
    }
    ranges.truncate(merged_index + 1);
}

fn consume_ranges(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) -> u64 {
    let mut consumed = 0_u64;
    for range in &mut *ranges {
        let overlap_start = range.0.max(start);
        let overlap_end = range.1.min(end);
        consumed = consumed.saturating_add(overlap_end.saturating_sub(overlap_start));
        if range.0 < end {
            range.0 = end.min(range.1);
        }
    }
    ranges.retain(|(range_start, range_end)| range_start < range_end);
    consumed
}

fn range_bytes(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().fold(0_u64, |total, (start, end)| {
        total.saturating_add(end.saturating_sub(*start))
    })
}

/// Orchestrates one defense across one or more client connections.
///
/// This is the single-owner modern equivalent of the published `FlowShaper`.
/// It deliberately contains no Neqo types or synchronization primitives.
#[derive(Debug)]
pub struct QcsdController {
    config: QcsdConfig,
    defense: Box<dyn Defense>,
    scheduler: RoundRobinScheduler,
    endpoint_origins: HashMap<QcsdEndpointId, String>,
    streams: StreamRegistry,
    chaff: Option<ChaffManager>,
    control: ControlLoop,
    actions: VecDeque<QcsdAction>,
    observations: VecDeque<QueuedDefenseObservation>,
    application_stream_ranges: HashMap<(QcsdEndpointId, QcsdStreamId), Vec<(u64, u64)>>,
    advertised_incoming_credit: HashMap<(QcsdEndpointId, QcsdStreamId), Vec<(u64, u64)>>,
    last_capacity: Option<Capacity>,
    last_delivered_observation_at: Option<Duration>,
    pending_slots: HashMap<QcsdSlotId, crate::Packet>,
    application_complete: bool,
    completion_emitted: bool,
    completion_due: Option<Duration>,
    released_chaff_send_shaping: HashSet<QcsdEndpointId>,
}

impl QcsdController {
    /// Construct a controller from a built-in resolved configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, manifests, or schedules.
    pub fn new(config: QcsdConfig, seed: u64, resources: Option<ResourceManifest>) -> Result<Self> {
        config.validate()?;
        let enable_chaff = !matches!(config.defense, DefenseConfig::None);
        let max_udp_payload_size = config.max_udp_payload_size;
        let defense: Box<dyn Defense> = match &config.defense {
            DefenseConfig::None => Box::new(StaticSchedule::new(crate::Trace::default(), true)),
            DefenseConfig::Static {
                schedule,
                padding_only,
            } => Box::new(StaticSchedule::from_legacy_csv(schedule, *padding_only)?),
            DefenseConfig::Front(front) => Box::new(Front::new(front, seed)),
            DefenseConfig::Tamaraw(tamaraw) => Box::new(Tamaraw::new(tamaraw)),
            DefenseConfig::TrafficMorphing(config) => {
                Box::new(TrafficMorphing::new(config, seed, max_udp_payload_size)?)
            }
            DefenseConfig::WtfPad(config) => {
                Box::new(WtfPad::new(config, seed, max_udp_payload_size)?)
            }
            DefenseConfig::WalkieTalkie(config) => {
                Box::new(WalkieTalkie::new(config, max_udp_payload_size)?)
            }
        };
        Self::build(config, resources, defense, enable_chaff)
    }

    /// Construct a controller around a programmatic defense implementation.
    ///
    /// This keeps new research defenses independent of [`DefenseConfig`]. The
    /// supplied configuration still controls the common flow shaper policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid common configuration or resource input.
    pub fn with_defense(
        config: QcsdConfig,
        resources: Option<ResourceManifest>,
        defense: Box<dyn Defense>,
    ) -> Result<Self> {
        config.validate()?;
        Self::build(config, resources, defense, true)
    }

    fn build(
        config: QcsdConfig,
        resources: Option<ResourceManifest>,
        defense: Box<dyn Defense>,
        enable_chaff: bool,
    ) -> Result<Self> {
        if let Some(resources) = &resources {
            resources.validate()?;
        }
        let chaff = resources
            .filter(|_| enable_chaff)
            .map(|manifest| ChaffManager::new(manifest, config.use_empty_resources));
        Ok(Self {
            config,
            defense,
            scheduler: RoundRobinScheduler::empty(),
            endpoint_origins: HashMap::new(),
            streams: StreamRegistry::default(),
            chaff,
            control: ControlLoop::default(),
            actions: VecDeque::new(),
            observations: VecDeque::new(),
            application_stream_ranges: HashMap::new(),
            advertised_incoming_credit: HashMap::new(),
            last_capacity: None,
            last_delivered_observation_at: None,
            pending_slots: HashMap::new(),
            application_complete: false,
            completion_emitted: false,
            completion_due: None,
            released_chaff_send_shaping: HashSet::new(),
        })
    }

    /// Resolved configuration used for the run.
    #[must_use]
    pub const fn config(&self) -> &QcsdConfig {
        &self.config
    }

    /// Defense-specific runtime counters for the run artifact.
    #[must_use]
    pub fn defense_diagnostics(&self) -> DefenseDiagnostics {
        self.defense.diagnostics()
    }

    /// Whether the selected defense permits opening another application batch.
    #[must_use]
    pub fn can_start_application_batch(&self) -> bool {
        self.defense.can_start_application_batch()
    }

    /// Snapshot every defense event that has not reached a terminal outcome.
    ///
    /// The runner uses this at abnormal termination so events that never
    /// reached an adapter still receive one terminal trace record.
    #[must_use]
    pub fn pending_slots(&self) -> Vec<(QcsdSlotId, crate::Packet)> {
        let mut pending: Vec<_> = self
            .pending_slots
            .iter()
            .map(|(slot, packet)| (*slot, *packet))
            .collect();
        pending.sort_unstable_by_key(|(slot, _)| *slot);
        pending
    }

    /// Consume one endpoint, HTTP/3, or transport observation.
    ///
    /// `at` is relative to defense start. Callers may use zero for
    /// pre-defense observations that cannot produce a [`DefenseSignal`].
    #[expect(
        clippy::too_many_lines,
        reason = "the exhaustive observation reducer makes every state transition auditable"
    )]
    pub fn observe(&mut self, observation: QcsdObservation, at: Duration) {
        match observation {
            QcsdObservation::EndpointReady {
                endpoint, origin, ..
            } => {
                self.scheduler.add_endpoint(endpoint);
                self.endpoint_origins.insert(endpoint, origin);
                self.release_chaff_send_shaping_for(endpoint);
            }
            QcsdObservation::EndpointClosed { endpoint } => {
                self.scheduler.remove_endpoint(endpoint);
                self.endpoint_origins.remove(&endpoint);
                self.streams.remove_endpoint(endpoint);
                self.application_stream_ranges
                    .retain(|(candidate, _), _| *candidate != endpoint);
                let mut retired = 0_u64;
                self.advertised_incoming_credit
                    .retain(|(candidate, _), ranges| {
                        if *candidate == endpoint {
                            retired = retired.saturating_add(range_bytes(ranges));
                            false
                        } else {
                            true
                        }
                    });
                if retired > 0 {
                    self.push_signal(at, SignalKind::ReceiveCreditRetired { bytes: retired });
                }
                self.control.reassign_endpoint(endpoint);
                self.return_endpoint_credit(endpoint, at);
                self.released_chaff_send_shaping.remove(&endpoint);
            }
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role,
                expected_response_length,
            } => self.open_stream(endpoint, stream, role, expected_response_length),
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining,
            } => self.streams.header_progress(
                endpoint,
                stream,
                min_remaining,
                self.config.max_stream_data_excess,
            ),
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream,
                status,
                content_length,
                ..
            } => {
                if let Some(state) = self.streams.get_mut(endpoint, stream) {
                    state.status = status;
                    state.receive.response_headers(content_length);
                }
            }
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                data_bytes,
                ..
            } => {
                if let Some(state) = self.streams.get_mut(endpoint, stream) {
                    state.receive.data_frame(data_bytes);
                }
            }
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes,
            } => {
                if let Some((cover, consumed_start, consumed_end)) =
                    self.streams.get_mut(endpoint, stream).map(|state| {
                        let consumed_start = state.receive.consumed();
                        let cover = matches!(state.role, QcsdRequestRole::Chaff { .. });
                        state
                            .receive
                            .bytes_read(bytes, self.config.max_stream_data_excess);
                        (cover, consumed_start, state.receive.consumed())
                    })
                {
                    let consumed_credit = self
                        .advertised_incoming_credit
                        .get_mut(&(endpoint, stream))
                        .map_or(0, |ranges| {
                            consume_ranges(ranges, consumed_start, consumed_end)
                        });
                    self.push_signal(
                        at,
                        SignalKind::PayloadBytes {
                            direction: Direction::Incoming,
                            bytes,
                            cover,
                        },
                    );
                    // Attribute natural request-stream offsets while the
                    // receive event still belongs to its incoming mould
                    // component. Consuming the final scheduled credit can
                    // advance Walkie-Talkie into the next outgoing component.
                    if !cover {
                        self.push_application_bytes(at, Direction::Incoming, bytes);
                    }
                    if consumed_credit > 0 {
                        self.push_signal(
                            at,
                            SignalKind::ReceiveCreditConsumed {
                                bytes: consumed_credit,
                            },
                        );
                    }
                }
            }
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream,
                blocked_at,
            } => self
                .streams
                .stream_data_blocked(endpoint, stream, blocked_at),
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot,
            } => self.credit_advertised(endpoint, stream, absolute_limit, slot, at),
            QcsdObservation::StreamFinished {
                endpoint, stream, ..
            } => self.close_stream(endpoint, stream, at),
            QcsdObservation::ChaffRequestFailed {
                resource_id,
                request_id,
            } => {
                if let Some(chaff) = &mut self.chaff {
                    chaff.request_failed(resource_id, request_id);
                }
            }
            QcsdObservation::ResourceCompleted {
                resource_id,
                success,
            } => {
                if let Some(chaff) = &mut self.chaff {
                    chaff.resource_completed(resource_id, success, 0);
                }
            }
            QcsdObservation::ApplicationBatchStarted => {
                self.push_signal(at, SignalKind::ApplicationBatchStarted);
            }
            QcsdObservation::ApplicationBatchCompleted => {
                self.push_signal(at, SignalKind::ApplicationBatchCompleted);
            }
            QcsdObservation::ApplicationComplete => {
                if !self.application_complete {
                    self.application_complete = true;
                    self.push_signal(at, SignalKind::ApplicationComplete);
                }
            }
            QcsdObservation::Datagram {
                direction, length, ..
            } => self.push_signal(at, SignalKind::Wire { direction, length }),
            QcsdObservation::ClassifiedDatagram {
                direction,
                length,
                class,
                ..
            } => self.push_signal(
                at,
                SignalKind::ClassifiedWire {
                    direction,
                    length,
                    class,
                },
            ),
            QcsdObservation::TrafficMorphingEgress {
                source_udp_size,
                outcome,
                ..
            } => self.push_signal(
                at,
                SignalKind::TrafficMorphingEgress {
                    source: source_udp_size,
                    outcome,
                },
            ),
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream,
                role,
                offset,
                bytes,
            } => {
                let cover = matches!(role, QcsdRequestRole::Chaff { .. });
                self.push_signal(
                    at,
                    SignalKind::PayloadBytes {
                        direction: Direction::Outgoing,
                        bytes,
                        cover,
                    },
                );
                if !cover {
                    let unique =
                        self.record_application_stream_range(endpoint, stream, offset, bytes);
                    self.push_application_bytes(at, Direction::Outgoing, unique);
                }
            }
            QcsdObservation::SlotSatisfied {
                slot,
                observed_size,
                ..
            } => {
                self.resolve_slot(
                    at,
                    slot,
                    EventOutcome::Satisfied {
                        observed: observed_size,
                    },
                );
            }
            QcsdObservation::SlotMissed { slot, reason, .. } => {
                self.fail_incoming_slot(slot);
                self.resolve_slot(at, slot, EventOutcome::Missed(reason));
            }
        }
    }

    fn push_signal(&mut self, at: Duration, kind: SignalKind) {
        self.observations
            .push_back(QueuedDefenseObservation::Signal(DefenseSignal { at, kind }));
    }

    fn push_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
        if bytes > 0 {
            self.observations
                .push_back(QueuedDefenseObservation::ApplicationBytes {
                    at,
                    direction,
                    bytes,
                });
        }
    }

    fn record_application_stream_range(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        offset: u64,
        bytes: u64,
    ) -> u64 {
        let end = offset.saturating_add(bytes);
        if end <= offset {
            return 0;
        }
        let ranges = self
            .application_stream_ranges
            .entry((endpoint, stream))
            .or_default();
        let before = covered_range_bytes(ranges);
        ranges.push((offset, end));
        ranges.sort_unstable();
        merge_ranges(ranges);
        covered_range_bytes(ranges).saturating_sub(before)
    }

    fn resolve_slot(&mut self, at: Duration, slot: QcsdSlotId, outcome: EventOutcome) {
        let Some(packet) = self.pending_slots.remove(&slot) else {
            return;
        };
        self.push_signal(at, SignalKind::Resolved { packet, outcome });
    }

    fn open_stream(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        expected_response_length: Option<u64>,
    ) {
        let expected = match role {
            QcsdRequestRole::Application => expected_response_length.unwrap_or(0),
            QcsdRequestRole::Chaff {
                resource_id,
                request_id,
            } => self.chaff.as_mut().map_or(0, |chaff| {
                chaff.request_opened(request_id);
                chaff.estimate(resource_id)
            }),
        };
        let controlled = self.controls(role);
        let initial_limit = self.config.effective_initial_max_stream_data();
        self.streams.open(
            endpoint,
            stream,
            role,
            controlled,
            initial_limit,
            self.config.max_stream_data_excess,
            expected,
        );
        if controlled {
            self.actions.push_back(QcsdAction::ConfigureManualReceive {
                endpoint,
                stream,
                initial_limit,
            });
        } else if !matches!(self.config.defense, DefenseConfig::None) {
            self.actions
                .push_back(QcsdAction::ConfigureAutomaticReceive {
                    endpoint,
                    stream,
                    window: self.config.automatic_receive_window,
                });
        }
    }

    fn close_stream(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId, at: Duration) {
        self.application_stream_ranges.remove(&(endpoint, stream));
        let Some((state, data_length, _unadvertised)) = self.streams.close(endpoint, stream) else {
            return;
        };
        self.return_stream_credit(endpoint, stream, at);
        let retired = self
            .advertised_incoming_credit
            .remove(&(endpoint, stream))
            .map_or(0, |ranges| range_bytes(&ranges));
        if retired > 0 {
            self.push_signal(at, SignalKind::ReceiveCreditRetired { bytes: retired });
        }
        if let QcsdRequestRole::Chaff { resource_id, .. } = state.role {
            let success = state
                .status
                .is_some_and(|status| (200..300).contains(&status))
                && data_length > 0;
            if let Some(chaff) = &mut self.chaff {
                chaff.resource_completed(resource_id, success, data_length);
            }
        }
    }

    fn credit_advertised(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        slot: Option<QcsdSlotId>,
        at: Duration,
    ) {
        if let Some(state) = self.streams.get_mut(endpoint, stream) {
            state.receive.advertised(absolute_limit);
        }
        let packet = slot.and_then(|slot| {
            self.control
                .credit
                .iter()
                .find(|credit| {
                    credit.endpoint == endpoint
                        && credit.stream == stream
                        && credit.slot == slot
                        && credit.absolute_limit <= absolute_limit
                })
                .map(|credit| credit.packet)
        });
        let mut advertised_ranges = Vec::new();
        self.control.credit.retain(|credit| {
            let same_release = credit.endpoint == endpoint
                && credit.stream == stream
                && credit.absolute_limit <= absolute_limit
                && slot.is_none_or(|slot| credit.slot == slot);
            if same_release {
                advertised_ranges.push((
                    credit.absolute_limit.saturating_sub(credit.increase),
                    credit.absolute_limit,
                ));
            }
            !same_release
        });
        if !advertised_ranges.is_empty() {
            let ranges = self
                .advertised_incoming_credit
                .entry((endpoint, stream))
                .or_default();
            ranges.append(&mut advertised_ranges);
            ranges.sort_unstable();
            merge_ranges(ranges);
        }
        if let (Some(slot), Some(packet)) = (slot, packet)
            && !self.control.terminal_incoming.contains(&slot)
            && !self.control.incoming_slot_pending(slot)
        {
            self.control.terminal_incoming.insert(slot);
            self.actions.push_back(QcsdAction::SlotSatisfied {
                endpoint: Some(endpoint),
                packet,
                slot,
            });
            self.resolve_slot(
                at,
                slot,
                EventOutcome::Satisfied {
                    observed: packet.length(),
                },
            );
        }
    }

    fn return_stream_credit(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        at: Duration,
    ) {
        let mut returned = Vec::new();
        self.control.credit.retain(|credit| {
            if credit.endpoint == endpoint && credit.stream == stream {
                returned.push(*credit);
                false
            } else {
                true
            }
        });
        for credit in returned {
            self.return_credit(&credit, at);
        }
    }

    fn return_endpoint_credit(&mut self, endpoint: QcsdEndpointId, at: Duration) {
        let mut returned = Vec::new();
        self.control.credit.retain(|credit| {
            if credit.endpoint == endpoint {
                returned.push(*credit);
                false
            } else {
                true
            }
        });
        for credit in returned {
            self.return_credit(&credit, at);
        }
    }

    fn return_credit(&mut self, credit: &PendingCredit, at: Duration) {
        if self.config.drop_unsatisfied_events {
            if !self.control.terminal_incoming.insert(credit.slot) {
                return;
            }
            self.actions.push_back(QcsdAction::SlotMissed {
                endpoint: Some(credit.endpoint),
                packet: credit.packet,
                slot: credit.slot,
                reason: MissedSlotReason::EndpointClosed,
            });
            self.resolve_slot(
                at,
                credit.slot,
                EventOutcome::Missed(MissedSlotReason::EndpointClosed),
            );
            return;
        }
        if let Some(pending) = self
            .control
            .incoming
            .iter_mut()
            .find(|pending| pending.slot == credit.slot)
        {
            pending.remaining = pending.remaining.saturating_add(credit.increase);
            pending.endpoint = None;
        } else {
            self.control.incoming.push(PendingIncoming {
                slot: credit.slot,
                packet: credit.packet,
                endpoint: None,
                remaining: credit.increase,
            });
        }
    }

    fn fail_incoming_slot(&mut self, slot: QcsdSlotId) {
        let had_credit = self.control.credit.iter().any(|credit| credit.slot == slot);
        let had_backlog = self
            .control
            .incoming
            .iter()
            .any(|incoming| incoming.slot == slot);
        if had_credit || had_backlog {
            self.control.credit.retain(|credit| credit.slot != slot);
            self.control
                .incoming
                .retain(|incoming| incoming.slot != slot);
            self.control.terminal_incoming.insert(slot);
        }
    }

    /// Advance the published control loop to `elapsed` and queue due actions.
    pub fn poll(&mut self, elapsed: Duration) {
        self.emit_capacity_signal(elapsed);
        self.drain_observations();
        self.request_chaff_if_needed();
        self.collect_due_events(elapsed);
        self.process_outgoing(elapsed);
        self.release_chaff_send_shaping_if_needed();

        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let boundary_us = ControlLoop::boundary_us(elapsed_us, self.config.control_interval_us);
        if self.control.should_process_incoming(boundary_us) {
            self.process_incoming(boundary_us, elapsed);
        }

        self.request_chaff_if_needed();
        self.update_completion(elapsed);
    }

    fn emit_capacity_signal(&mut self, at: Duration) {
        let capacity = self.streams.aggregate_capacity();
        if self.last_capacity != Some(capacity) {
            self.last_capacity = Some(capacity);
            self.push_signal(at, SignalKind::Capacity(capacity));
        }
    }

    fn drain_observations(&mut self) {
        let mut pending: Vec<_> = self.observations.drain(..).collect();
        pending.sort_by_key(|observation| observation.at());
        for observation in pending {
            let at = self
                .last_delivered_observation_at
                .map_or_else(|| observation.at(), |last| observation.at().max(last));
            self.last_delivered_observation_at = Some(at);
            match observation {
                QueuedDefenseObservation::Signal(mut signal) => {
                    signal.at = at;
                    self.defense.observe(signal);
                }
                QueuedDefenseObservation::ApplicationBytes {
                    direction, bytes, ..
                } => self.defense.observe_application_bytes(at, direction, bytes),
            }
        }
    }

    fn collect_due_events(&mut self, elapsed: Duration) {
        while let Some(packet) = self.defense.next_event(elapsed) {
            let slot = self.control.next_slot();
            self.pending_slots.insert(slot, packet);
            match packet.direction() {
                Direction::Outgoing => self.control.outgoing.push(PendingOutgoing { slot, packet }),
                Direction::Incoming => self.control.incoming.push(PendingIncoming {
                    slot,
                    packet,
                    endpoint: None,
                    remaining: u64::from(packet.length()),
                }),
            }
        }
    }

    fn process_outgoing(&mut self, elapsed: Duration) {
        let pending = std::mem::take(&mut self.control.outgoing);
        for outgoing in pending {
            let deadline = outgoing
                .packet
                .timestamp()
                .saturating_add(self.config.control_interval());
            if elapsed >= deadline {
                self.actions.push_back(QcsdAction::SlotMissed {
                    endpoint: None,
                    packet: outgoing.packet,
                    slot: outgoing.slot,
                    reason: MissedSlotReason::DeadlineExpired,
                });
                self.resolve_slot(
                    elapsed,
                    outgoing.slot,
                    EventOutcome::Missed(MissedSlotReason::DeadlineExpired),
                );
                continue;
            }
            let Some(endpoint) = self.scheduler.next_outgoing() else {
                if self.config.drop_unsatisfied_events {
                    self.actions.push_back(QcsdAction::SlotMissed {
                        endpoint: None,
                        packet: outgoing.packet,
                        slot: outgoing.slot,
                        reason: MissedSlotReason::NoEndpoint,
                    });
                    self.resolve_slot(
                        elapsed,
                        outgoing.slot,
                        EventOutcome::Missed(MissedSlotReason::NoEndpoint),
                    );
                } else {
                    self.control.outgoing.push(outgoing);
                }
                continue;
            };
            self.actions.push_back(QcsdAction::SendPacket {
                endpoint,
                packet: outgoing.packet,
                slot: outgoing.slot,
                deadline_after_us: u64::try_from(deadline.saturating_sub(elapsed).as_micros())
                    .unwrap_or(u64::MAX),
                allow_stream_data: self.defense.mode() == DefenseMode::ChaffAndShape,
            });
        }
    }

    fn process_incoming(&mut self, boundary_us: u64, elapsed: Duration) {
        let pending = std::mem::take(&mut self.control.incoming);
        for mut incoming in pending {
            if incoming.packet.timestamp_us() > boundary_us {
                self.control.incoming.push(incoming);
                continue;
            }
            let endpoint_count = self.scheduler.endpoints().len();
            let mut attempted = HashSet::new();
            let mut miss_reason = if endpoint_count == 0 {
                MissedSlotReason::NoEndpoint
            } else {
                MissedSlotReason::InsufficientIncomingCapacity
            };
            while incoming.remaining > 0 && attempted.len() < endpoint_count {
                if incoming.endpoint.is_none() {
                    let streams = &self.streams;
                    incoming.endpoint = self
                        .scheduler
                        .next_incoming(incoming.remaining, self.defense.mode(), |endpoint| {
                            if attempted.contains(&endpoint) {
                                Capacity::default()
                            } else {
                                streams.capacity(endpoint)
                            }
                        })
                        .map(|(endpoint, _)| endpoint);
                }
                let Some(endpoint) = incoming.endpoint else {
                    miss_reason = MissedSlotReason::NoEndpoint;
                    break;
                };
                if !attempted.insert(endpoint) {
                    incoming.endpoint = None;
                    continue;
                }

                let releases =
                    self.streams
                        .release(endpoint, incoming.remaining, self.defense.mode());
                let released_bytes = releases.iter().fold(0_u64, |total, release| {
                    total.saturating_add(release.increase)
                });
                for release in releases {
                    self.control.credit.push(PendingCredit {
                        slot: incoming.slot,
                        packet: incoming.packet,
                        endpoint,
                        stream: release.stream,
                        absolute_limit: release.absolute_limit,
                        increase: release.increase,
                    });
                    self.actions.push_back(QcsdAction::IncreaseReceiveLimit {
                        endpoint,
                        stream: release.stream,
                        absolute_limit: release.absolute_limit,
                        packet: incoming.packet,
                        slot: incoming.slot,
                    });
                }
                incoming.remaining = incoming.remaining.saturating_sub(released_bytes);
                // One logical incoming slot is an aggregate receive budget.
                // When the preferred application endpoint supplies only a
                // fragment, continue the identical slot over another endpoint
                // before classifying it as unrealizable.
                incoming.endpoint = None;
            }
            if incoming.remaining > 0 {
                self.unsatisfied_incoming(incoming, miss_reason, elapsed);
            }
        }
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the pending event is deliberately transferred back into the queue"
    )]
    fn unsatisfied_incoming(
        &mut self,
        incoming: PendingIncoming,
        reason: MissedSlotReason,
        at: Duration,
    ) {
        if self.config.drop_unsatisfied_events {
            self.control.terminal_incoming.insert(incoming.slot);
            self.actions.push_back(QcsdAction::SlotMissed {
                endpoint: incoming.endpoint,
                packet: incoming.packet,
                slot: incoming.slot,
                reason,
            });
            self.resolve_slot(at, incoming.slot, EventOutcome::Missed(reason));
        } else {
            self.control.incoming.push(incoming);
        }
    }

    fn update_completion(&mut self, elapsed: Duration) {
        let has_backlog = self.control.incoming_backlog() > 0
            || !self.control.outgoing.is_empty()
            || !self.control.credit.is_empty()
            || !self.pending_slots.is_empty()
            || !self.observations.is_empty();
        if self.defense.is_complete() && !has_backlog {
            let due = *self.completion_due.get_or_insert_with(|| {
                elapsed.saturating_add(Duration::from_micros(self.config.tail_wait_us))
            });
            if !self.completion_emitted && elapsed >= due {
                self.completion_emitted = true;
                self.actions.push_back(QcsdAction::DefenseComplete);
            }
        } else {
            self.completion_due = None;
        }
    }

    fn release_chaff_send_shaping_if_needed(&mut self) {
        if self.defense.mode() != DefenseMode::ChaffAndShape
            || !self.defense.can_release_chaff_send_shaping()
            || (self.defense.is_complete()
                && self.control.incoming_backlog() == 0
                && self.control.credit.is_empty())
        {
            return;
        }
        let endpoints = self.scheduler.endpoints().to_vec();
        for endpoint in endpoints {
            self.release_chaff_send_shaping_for(endpoint);
        }
    }

    fn release_chaff_send_shaping_for(&mut self, endpoint: QcsdEndpointId) {
        if self.defense.mode() == DefenseMode::ChaffAndShape
            && self.defense.can_release_chaff_send_shaping()
            && (!self.defense.is_complete()
                || self.control.incoming_backlog() > 0
                || !self.control.credit.is_empty())
            && self.released_chaff_send_shaping.insert(endpoint)
        {
            self.actions
                .push_back(QcsdAction::ReleaseChaffSendShaping { endpoint });
        }
    }

    /// Earliest time at which [`Self::poll`] can produce another action.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        let mut candidates = Vec::new();
        if !self.observations.is_empty() {
            candidates.push(Duration::ZERO);
        }
        if let Some(next) = self.defense.next_event_at() {
            candidates.push(next);
        }
        if !self.control.outgoing.is_empty() {
            candidates.push(Duration::ZERO);
        }
        if !self.control.incoming.is_empty() {
            let earliest = self
                .control
                .incoming
                .iter()
                .map(|pending| pending.packet.timestamp_us())
                .min()
                .unwrap_or(0);
            let interval = self.config.control_interval_us;
            let next = if earliest == 0 {
                0
            } else {
                earliest.div_ceil(interval).saturating_mul(interval)
            };
            let next_unprocessed = self
                .control
                .last_incoming_boundary_us
                .filter(|last| next <= *last)
                .map_or(next, |last| last.saturating_add(interval));
            candidates.push(Duration::from_micros(next_unprocessed));
        }
        if let Some(due) = self.completion_due.filter(|_| !self.completion_emitted) {
            candidates.push(due);
        }
        candidates.into_iter().min()
    }

    /// Remove the next queued action.
    pub fn next_action(&mut self) -> Option<QcsdAction> {
        self.actions.pop_front()
    }

    /// Drain all queued actions in order.
    pub fn drain_actions(&mut self) -> impl Iterator<Item = QcsdAction> + '_ {
        self.actions.drain(..)
    }

    /// Whether the defense emitted its terminal action.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completion_emitted
    }

    fn controls(&self, role: QcsdRequestRole) -> bool {
        self.defense.mode() == DefenseMode::ChaffAndShape
            || matches!(role, QcsdRequestRole::Chaff { .. })
    }

    fn request_chaff_if_needed(&mut self) {
        let Some(chaff) = &mut self.chaff else {
            return;
        };
        let endpoints: Vec<_> = self
            .scheduler
            .endpoints()
            .iter()
            .filter_map(|endpoint| {
                self.endpoint_origins
                    .get(endpoint)
                    .map(|origin| (*endpoint, origin.clone()))
            })
            .collect();
        let requests = chaff.replenish(
            self.streams.aggregate_capacity().chaff_incoming,
            self.streams.open_chaff_count(),
            self.config.max_chaff_streams,
            self.config.low_watermark,
            &endpoints,
        );
        for request in requests {
            self.actions.push_back(QcsdAction::RequestChaff {
                endpoint: request.endpoint,
                resource: request.resource,
                request_id: request.request_id,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{BTreeSet, VecDeque},
        rc::Rc,
        time::Duration,
    };

    use super::{QcsdController, consume_ranges, merge_ranges, range_bytes};
    use crate::{
        Defense, DefenseConfig, DefenseDiagnostics, DefenseMode, DefenseSignal, Direction,
        EventOutcome, HeaderPolicy, MissedSlotReason, Packet, QcsdAction, QcsdConfig,
        QcsdDatagramClass, QcsdEndpointId, QcsdObservation, QcsdRequestRole, QcsdSlotId,
        QcsdStreamFinish, QcsdStreamId, Resource, ResourceManifest, SignalKind, StaticSchedule,
        TamarawConfig, Trace, TrafficMorphing, TrafficMorphingConfig, WalkieTalkie,
        WalkieTalkieConfig, WtfPad, WtfPadConfig,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecordedCall {
        Signal(DefenseSignal),
        ApplicationBytes {
            at: Duration,
            direction: Direction,
            bytes: u64,
        },
        NextEvent(Duration),
    }

    #[test]
    fn scheduled_receive_credit_uses_exact_raw_stream_offset_intersections() {
        let mut ranges = vec![(16, 116), (116, 216)];
        merge_ranges(&mut ranges);
        assert_eq!(ranges, [(16, 216)]);

        // The first 16 bytes came from the transport's initial stream limit,
        // so only offsets 16..40 consume defense-scheduled credit.
        assert_eq!(consume_ranges(&mut ranges, 0, 40), 24);
        assert_eq!(ranges, [(40, 216)]);
        assert_eq!(consume_ranges(&mut ranges, 40, 150), 110);
        assert_eq!(range_bytes(&ranges), 66);
    }

    #[derive(Debug)]
    struct RecordingDefense {
        events: VecDeque<Packet>,
        mode: DefenseMode,
        calls: Rc<RefCell<Vec<RecordedCall>>>,
    }

    impl RecordingDefense {
        fn new(
            events: impl IntoIterator<Item = Packet>,
            mode: DefenseMode,
        ) -> (Self, Rc<RefCell<Vec<RecordedCall>>>) {
            let calls = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    events: events.into_iter().collect(),
                    mode,
                    calls: Rc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl Defense for RecordingDefense {
        fn observe(&mut self, signal: DefenseSignal) {
            self.calls.borrow_mut().push(RecordedCall::Signal(signal));
        }

        fn observe_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
            self.calls
                .borrow_mut()
                .push(RecordedCall::ApplicationBytes {
                    at,
                    direction,
                    bytes,
                });
        }

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.calls
                .borrow_mut()
                .push(RecordedCall::NextEvent(elapsed));
            self.events
                .front()
                .copied()
                .filter(|packet| packet.timestamp() <= elapsed)?;
            self.events.pop_front()
        }

        fn next_event_at(&self) -> Option<Duration> {
            self.events.front().map(|packet| packet.timestamp())
        }

        fn is_complete(&self) -> bool {
            self.events.is_empty()
        }

        fn is_outgoing_complete(&self) -> bool {
            !self
                .events
                .iter()
                .any(|packet| packet.direction() == Direction::Outgoing)
        }

        fn mode(&self) -> DefenseMode {
            self.mode
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ReplayTerminal {
        endpoint: Option<QcsdEndpointId>,
        packet: Packet,
        slot: QcsdSlotId,
        outcome: EventOutcome,
    }

    #[derive(Debug, Default, Eq, PartialEq)]
    struct ControllerReplay {
        actions: Vec<QcsdAction>,
        terminals: Vec<ReplayTerminal>,
        diagnostics: DefenseDiagnostics,
        pending_slots: Vec<(QcsdSlotId, Packet)>,
        complete: bool,
    }

    fn replay_wire(at_us: u64, direction: Direction, length: u16) -> (Duration, QcsdObservation) {
        (
            Duration::from_micros(at_us),
            QcsdObservation::ClassifiedDatagram {
                endpoint: QcsdEndpointId(1),
                direction,
                length,
                class: QcsdDatagramClass::Natural,
            },
        )
    }

    fn satisfy_replay_incoming(
        controller: &mut QcsdController,
        at: Duration,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        packet: Packet,
        slot: QcsdSlotId,
    ) {
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            at,
        );
        // Model the coalesced MAX_STREAM_DATA control datagram and the
        // corresponding observed cover response at the terminal instant.
        for (direction, length) in [
            (Direction::Outgoing, 80),
            (Direction::Incoming, packet.length()),
        ] {
            controller.observe(
                QcsdObservation::Datagram {
                    endpoint,
                    direction,
                    length,
                    timestamp_us: u64::try_from(at.as_micros()).unwrap_or(u64::MAX),
                },
                at,
            );
            controller.observe(
                QcsdObservation::ClassifiedDatagram {
                    endpoint,
                    direction,
                    length,
                    class: QcsdDatagramClass::DefenseCover,
                },
                at,
            );
        }
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: u64::from(packet.length()),
            },
            at,
        );
    }

    fn resolve_replay_actions(
        controller: &mut QcsdController,
        at: Duration,
        replay: &mut ControllerReplay,
    ) {
        while let Some(action) = controller.next_action() {
            replay.actions.push(action.clone());
            match action {
                QcsdAction::SendPacket {
                    endpoint,
                    packet,
                    slot,
                    ..
                } => {
                    replay.terminals.push(ReplayTerminal {
                        endpoint: Some(endpoint),
                        packet,
                        slot,
                        outcome: EventOutcome::Satisfied {
                            observed: packet.length(),
                        },
                    });
                    controller.observe(
                        QcsdObservation::SlotSatisfied {
                            endpoint,
                            slot,
                            observed_size: packet.length(),
                        },
                        at,
                    );
                    controller.observe(
                        QcsdObservation::Datagram {
                            endpoint,
                            direction: Direction::Outgoing,
                            length: packet.length(),
                            timestamp_us: u64::try_from(at.as_micros()).unwrap_or(u64::MAX),
                        },
                        at,
                    );
                }
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                } => satisfy_replay_incoming(
                    controller,
                    at,
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                ),
                QcsdAction::SlotSatisfied {
                    endpoint,
                    packet,
                    slot,
                } => replay.terminals.push(ReplayTerminal {
                    endpoint,
                    packet,
                    slot,
                    outcome: EventOutcome::Satisfied {
                        observed: packet.length(),
                    },
                }),
                QcsdAction::SlotMissed {
                    endpoint,
                    packet,
                    slot,
                    reason,
                } => replay.terminals.push(ReplayTerminal {
                    endpoint,
                    packet,
                    slot,
                    outcome: EventOutcome::Missed(reason),
                }),
                QcsdAction::DefenseComplete => replay.complete = true,
                QcsdAction::ConfigureManualReceive { .. }
                | QcsdAction::ConfigureAutomaticReceive { .. }
                | QcsdAction::ReleaseChaffSendShaping { .. }
                | QcsdAction::RequestChaff { .. } => {}
            }
        }
    }

    fn replay_controller(
        configured_defense: DefenseConfig,
        defense: Box<dyn Defense>,
        role: QcsdRequestRole,
        script: impl IntoIterator<Item = (Duration, QcsdObservation)>,
    ) -> ControllerReplay {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 100,
                max_stream_data_excess: 4_096,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                tail_wait_us: 0,
                defense: configured_defense,
                ..QcsdConfig::default()
            },
            None,
            defense,
        )
        .expect("replay controller");
        let endpoint = QcsdEndpointId(1);
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint,
                origin: "https://replay.example".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: QcsdStreamId(4),
                role,
                expected_response_length: None,
            },
            Duration::ZERO,
        );

        let mut script: VecDeque<_> = script.into_iter().collect();
        assert!(
            script
                .make_contiguous()
                .windows(2)
                .all(|window| matches!(window, [left, right] if left.0 <= right.0)),
            "virtual observations must be time ordered"
        );
        let mut replay = ControllerReplay::default();
        let mut now = Duration::ZERO;
        for _step in 0..512 {
            resolve_replay_actions(&mut controller, now, &mut replay);
            if replay.complete {
                break;
            }

            let external_at = script.front().map(|(at, _)| *at);
            let deadline = controller.next_deadline().map(|at| at.max(now));
            let next = match (external_at, deadline) {
                (Some(external), Some(internal)) if external <= internal => external,
                (Some(_) | None, Some(internal)) => internal,
                (Some(external), None) => external,
                (None, None) => panic!("replay controller stalled before completion"),
            };
            now = next;
            while script.front().is_some_and(|(at, _)| *at == now) {
                let (_, observation) = script.pop_front().expect("checked front");
                controller.observe(observation, now);
            }
            controller.poll(now);
        }

        resolve_replay_actions(&mut controller, now, &mut replay);
        replay.diagnostics = controller.defense_diagnostics();
        replay.pending_slots = controller.pending_slots();
        replay.complete = controller.is_complete();

        let action_slots: BTreeSet<_> = replay
            .actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. }
                | QcsdAction::SendPacket { slot, .. }
                | QcsdAction::SlotMissed { slot, .. }
                | QcsdAction::SlotSatisfied { slot, .. } => Some(*slot),
                QcsdAction::ConfigureManualReceive { .. }
                | QcsdAction::ConfigureAutomaticReceive { .. }
                | QcsdAction::ReleaseChaffSendShaping { .. }
                | QcsdAction::RequestChaff { .. }
                | QcsdAction::DefenseComplete => None,
            })
            .collect();
        let terminal_slots: BTreeSet<_> = replay
            .terminals
            .iter()
            .map(|terminal| terminal.slot)
            .collect();
        assert!(
            script.is_empty(),
            "replay completed before consuming its input"
        );
        assert!(
            replay.complete,
            "replay did not reach DefenseComplete: {replay:#?}"
        );
        assert!(replay.pending_slots.is_empty());
        assert_eq!(terminal_slots, action_slots);
        assert_eq!(replay.terminals.len(), terminal_slots.len());
        replay
    }

    fn traffic_morphing_replay(seed: u64) -> ControllerReplay {
        let config = TrafficMorphingConfig {
            matrix: "inline-controller-replay.json".into(),
            workload_id: "controller replay source".into(),
            ingress_packet_size: 200,
            max_ingress_deficit_bytes: 200,
        };
        let matrix = r#"{
            "adaptation": "qcsd-client-only",
            "schema_version": 2,
            "generated_by": "controller test",
            "paper_equivalent": false,
            "udp_payload_ceiling": 200,
            "buckets": [64, 100, 200],
            "profiles": [{
                "source": "controller replay source",
                "target": "controller replay target",
                "outgoing": {
                    "expected_added_bytes": 78.8,
                    "l1_distance": 0.0,
                    "source_distribution": [1.0, 0.0, 0.0],
                    "target_distribution": [0.2, 0.3, 0.5],
                    "realized_distribution": [0.2, 0.3, 0.5],
                    "rows": [
                        [0.2, 0.3, 0.5],
                        [0.0, 0.4, 0.6],
                        [0.0, 0.0, 1.0]
                    ]
                },
                "incoming": {
                    "expected_added_bytes": 136.0,
                    "l1_distance": 0.0,
                    "source_distribution": [1.0, 0.0, 0.0],
                    "target_distribution": [0.0, 0.0, 1.0],
                    "realized_distribution": [0.0, 0.0, 1.0],
                    "rows": [
                        [0.0, 0.0, 1.0],
                        [0.0, 0.0, 1.0],
                        [0.0, 0.0, 1.0]
                    ]
                }
            }]
        }"#;
        let defense =
            TrafficMorphing::from_json(&config, seed, 200, matrix).expect("replay matrix");
        let mut script = vec![
            replay_wire(10, Direction::Outgoing, 64),
            (
                Duration::from_micros(11),
                QcsdObservation::TrafficMorphingEgress {
                    endpoint: QcsdEndpointId(1),
                    source_udp_size: 64,
                    outcome: crate::TrafficMorphingOutcome::Morphed {
                        target_udp_size: 200,
                    },
                },
            ),
            replay_wire(12, Direction::Incoming, 64),
            replay_wire(12, Direction::Incoming, 64),
            replay_wire(12, Direction::Incoming, 64),
            replay_wire(14, Direction::Outgoing, 80),
            replay_wire(16, Direction::Incoming, 80),
        ];
        script.push((
            Duration::from_micros(30),
            QcsdObservation::ApplicationComplete,
        ));
        script.push((
            Duration::from_secs(1),
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                finish: QcsdStreamFinish::Fin,
            },
        ));
        replay_controller(
            DefenseConfig::TrafficMorphing(config),
            Box::new(defense),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            script,
        )
    }

    fn wtf_pad_replay(seed: u64) -> ControllerReplay {
        let config = WtfPadConfig {
            histograms: "inline-controller-replay.json".into(),
            packet_size: 100,
            max_padding_events: 32,
        };
        let defense = WtfPad::from_json(
            &config,
            seed,
            1_200,
            include_str!("../../tests/data/wtf-pad-golden.json"),
        )
        .expect("replay histograms");
        let mut script = vec![
            replay_wire(4, Direction::Outgoing, 80),
            replay_wire(12, Direction::Incoming, 90),
            replay_wire(13, Direction::Incoming, 95),
        ];
        script.push((
            Duration::from_micros(40),
            QcsdObservation::ApplicationComplete,
        ));
        script.push((
            Duration::from_secs(1),
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                finish: QcsdStreamFinish::Fin,
            },
        ));
        replay_controller(
            DefenseConfig::WtfPad(config),
            Box::new(defense),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            script,
        )
    }

    fn walkie_talkie_replay() -> ControllerReplay {
        let config = WalkieTalkieConfig {
            molded: "walkie-talkie-golden.json".into(),
            workload_id: "real page".into(),
            packet_size: 100,
        };
        let defense = WalkieTalkie::from_json(
            &config,
            1_200,
            include_str!("../../tests/data/walkie-talkie-golden.json"),
        )
        .expect("replay molded sequence");
        replay_controller(
            DefenseConfig::WalkieTalkie(config),
            Box::new(defense),
            QcsdRequestRole::Application,
            [
                (Duration::ZERO, QcsdObservation::ApplicationBatchStarted),
                (
                    Duration::from_micros(1),
                    QcsdObservation::ApplicationBatchCompleted,
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamFinished {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(4),
                        finish: QcsdStreamFinish::Fin,
                    },
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamOpened {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(8),
                        role: QcsdRequestRole::Application,
                        expected_response_length: None,
                    },
                ),
                (
                    Duration::from_micros(201),
                    QcsdObservation::ApplicationBatchStarted,
                ),
                (
                    Duration::from_micros(202),
                    QcsdObservation::ApplicationBatchCompleted,
                ),
                (
                    Duration::from_micros(203),
                    QcsdObservation::ApplicationComplete,
                ),
            ],
        )
    }

    #[test]
    fn traffic_morphing_full_controller_replay_is_exact_at_the_same_seed() {
        let replay = traffic_morphing_replay(0x5eed);
        assert_eq!(traffic_morphing_replay(0x5eed), replay);
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(
            replay
                .terminals
                .iter()
                .all(|terminal| matches!(terminal.outcome, EventOutcome::Satisfied { .. }))
        );
        assert!(replay.diagnostics.suppressed_cover_feedback > 0);
        assert_eq!(replay.diagnostics.morphing_egress_packets, 1);
        assert_eq!(replay.diagnostics.morphing_ingress_shortfall_bytes, 328);
    }

    #[test]
    fn wtf_pad_full_controller_replay_is_exact_at_the_same_seed() {
        let replay = wtf_pad_replay(0x5eed);
        assert_eq!(wtf_pad_replay(0x5eed), replay);
        assert!(replay.diagnostics.padding_events > 0);
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(
            replay
                .terminals
                .iter()
                .all(|terminal| matches!(terminal.outcome, EventOutcome::Satisfied { .. }))
        );
        assert!(replay.diagnostics.suppressed_cover_feedback > 0);
        assert!(replay.diagnostics.wtf_pad_incoming_desired_bytes > 0);
        assert_eq!(
            replay.diagnostics.wtf_pad_incoming_received_bytes,
            replay.diagnostics.wtf_pad_incoming_desired_bytes
        );
        assert_eq!(replay.diagnostics.wtf_pad_incoming_shortfall_bytes, 0);
        assert!(replay.diagnostics.wtf_pad_incoming_observed_events > 0);
    }

    #[test]
    fn walkie_talkie_full_controller_replay_is_exact_for_identical_signals() {
        let replay = walkie_talkie_replay();
        assert_eq!(walkie_talkie_replay(), replay);
        assert!(replay.actions.iter().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit: 0,
                ..
            }
        )));
        assert!(!replay.actions.iter().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit,
                ..
            } if *initial_limit > 0
        )));
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(
            replay
                .terminals
                .iter()
                .all(|terminal| matches!(terminal.outcome, EventOutcome::Satisfied { .. }))
        );
        assert_eq!(replay.diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(replay.diagnostics.retried_outgoing_events, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the regression keeps the cross-layer receive-credit ordering explicit"
    )]
    fn completing_natural_read_stays_in_its_incoming_mould_component() {
        let molded = r#"{
            "adaptation": "qcsd-client-only",
            "burst_definition": "global-application-batch-direction-transitions",
            "cell_byte_domain": "http3-request-stream-offset.bytes",
            "schema_version": 2,
            "generated_by": "controller ordering test",
            "matching_algorithm": "minimum-cost-one-to-one",
            "paper_equivalent": false,
            "packet_size": 100,
            "training_split": "train",
            "profiles": [{
                "real": "real page",
                "decoy": "decoy page",
                "matching_cost_packets": 0,
                "training_inputs": {
                    "real": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                    "decoy": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                },
                "variation": {
                    "real": {"visit_count": 1, "varying_components": 0, "maximum_component_spread": 0},
                    "decoy": {"visit_count": 1, "varying_components": 0, "maximum_component_spread": 0}
                },
                "source_envelopes": {
                    "real": [
                        {"outgoing": 0, "incoming": 1},
                        {"outgoing": 1, "incoming": 1}
                    ],
                    "decoy": [
                        {"outgoing": 0, "incoming": 1},
                        {"outgoing": 1, "incoming": 1}
                    ]
                },
                "batch_ends": {"real": [1], "decoy": [1]},
                "molded_batch_ends": [1],
                "total_scheduled_bytes": 300,
                "bursts": [
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]
            }]
        }"#;
        let config = WalkieTalkieConfig {
            molded: "inline-ordering-test.json".into(),
            workload_id: "real page".into(),
            packet_size: 100,
        };
        let defense = WalkieTalkie::from_json(&config, 1_200, molded).expect("valid mould");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 0,
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(200),
            },
            Duration::ZERO,
        );
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit: 0,
                ..
            }
        )));
        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.poll(Duration::ZERO);
        let (absolute_limit, slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    absolute_limit,
                    slot,
                    ..
                } => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("first incoming mould credit");
        assert_eq!(absolute_limit, 100);

        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 100,
            },
            Duration::from_micros(1),
        );
        controller.poll(Duration::from_micros(1));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 100);
        assert_eq!(
            diagnostics.walkie_talkie_application_stream_crossing_bytes,
            0
        );
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SendPacket { packet, .. }
                if packet.direction() == Direction::Outgoing
        )));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        reason = "the regression preserves both FIN/retry/batch transitions end to end"
    )]
    fn walkie_talkie_fin_residual_credit_is_exact_and_admits_later_batches() {
        let config = WalkieTalkieConfig {
            molded: "walkie-talkie-golden.json".into(),
            workload_id: "real page".into(),
            packet_size: 100,
        };
        let defense = WalkieTalkie::from_json(
            &config,
            1_200,
            include_str!("../../tests/data/walkie-talkie-golden.json"),
        )
        .expect("two-batch Walkie-Talkie fixture");
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_000),
                data_length: 1_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 16,
                low_watermark: 0,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                tail_wait_us: 0,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        ready(&mut controller, 1, "https://example.com");
        for (stream, role, expected_response_length) in [
            (QcsdStreamId(0), QcsdRequestRole::Application, Some(300)),
            (
                QcsdStreamId(4),
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
        ] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length,
                },
                Duration::ZERO,
            );
        }
        let initial_actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            initial_actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::ConfigureManualReceive { .. }))
                .count(),
            2
        );
        assert!(initial_actions.iter().all(|action| !matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit,
                ..
            } if *initial_limit != 0
        )));

        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 100,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let first_outgoing: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::SendPacket { packet, slot, .. } => Some((packet, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(first_outgoing.len(), 2);
        for (packet, slot) in first_outgoing {
            controller.observe(
                QcsdObservation::SlotSatisfied {
                    endpoint,
                    slot,
                    observed_size: packet.length(),
                },
                Duration::from_micros(1),
            );
        }
        controller.poll(Duration::from_micros(1));
        let first_credits: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                    ..
                } => Some((stream, absolute_limit, packet, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(first_credits.len(), 2);
        assert!(first_credits.iter().all(|credit| credit.2.length() == 100));
        assert_eq!(
            first_credits
                .iter()
                .map(|(stream, absolute_limit, _, _)| (*stream, *absolute_limit))
                .collect::<Vec<_>>(),
            [(QcsdStreamId(0), 100), (QcsdStreamId(0), 200),]
        );
        for (stream, absolute_limit, _, slot) in first_credits {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(2),
            );
        }
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: QcsdStreamId(0),
                bytes: 150,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(0),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));
        let first_residual = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                    ..
                } if packet.length() != 100 => Some((stream, absolute_limit, packet, slot)),
                _ => None,
            })
            .expect("FIN creates one exact residual credit action");
        assert_eq!(first_residual.0, QcsdStreamId(4));
        assert_eq!(first_residual.1, 50);
        assert_eq!(first_residual.2.length(), 50);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: first_residual.0,
                absolute_limit: first_residual.1,
                slot: Some(first_residual.3),
            },
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { packet, .. } if packet.length() == 50
        )));

        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: QcsdStreamId(4),
                bytes: 50,
            },
            Duration::from_micros(4),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(4),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(4),
        );
        controller.poll(Duration::from_micros(4));
        assert!(controller.can_start_application_batch());
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );

        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: QcsdStreamId(8),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(200),
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: QcsdStreamId(12),
                role: QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                expected_response_length: None,
            },
            Duration::from_micros(5),
        );
        let later_stream_actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            later_stream_actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::ConfigureManualReceive { .. }))
                .count(),
            2
        );
        assert!(later_stream_actions.iter().all(|action| !matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit,
                ..
            } if *initial_limit != 0
        )));
        controller.observe(
            QcsdObservation::ApplicationBatchStarted,
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: QcsdStreamId(8),
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 100,
            },
            Duration::from_micros(5),
        );
        controller.poll(Duration::from_micros(5));
        let second_outgoing = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::SendPacket { packet, slot, .. } => Some((packet, slot)),
                _ => None,
            })
            .expect("batch start releases its outgoing mould slot");
        controller.observe(
            QcsdObservation::SlotSatisfied {
                endpoint,
                slot: second_outgoing.1,
                observed_size: second_outgoing.0.length(),
            },
            Duration::from_micros(6),
        );
        controller.poll(Duration::from_micros(6));
        let second_credit = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                    ..
                } if packet.length() == 100 => Some((stream, absolute_limit, packet, slot)),
                _ => None,
            })
            .expect("second batch incoming target");
        assert_eq!(second_credit.0, QcsdStreamId(8));
        assert_eq!(second_credit.1, 100);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: second_credit.0,
                absolute_limit: second_credit.1,
                slot: Some(second_credit.3),
            },
            Duration::from_micros(7),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: QcsdStreamId(8),
                bytes: 75,
            },
            Duration::from_micros(7),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(8),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(7),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(7),
        );
        controller.poll(Duration::from_micros(7));
        let second_residual = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                    ..
                } if packet.length() != 100 => Some((stream, absolute_limit, packet, slot)),
                _ => None,
            })
            .expect("the later FIN independently rearms an exact retry");
        assert_eq!(second_residual.0, QcsdStreamId(12));
        assert_eq!(second_residual.1, 25);
        assert_eq!(second_residual.2.length(), 25);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: second_residual.0,
                absolute_limit: second_residual.1,
                slot: Some(second_residual.3),
            },
            Duration::from_micros(8),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: QcsdStreamId(12),
                bytes: 25,
            },
            Duration::from_micros(8),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(12),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(8),
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(8),
        );
        controller.poll(Duration::from_micros(8));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 225);
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, 75);
        assert_eq!(
            diagnostics.walkie_talkie_application_stream_crossing_bytes,
            0
        );
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 2);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::DefenseComplete))
        );
    }

    fn tamaraw_controller() -> QcsdController {
        QcsdController::new(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Tamaraw(TamarawConfig {
                    incoming_interval_us: 5_000,
                    outgoing_interval_us: 20_000,
                    packet_size: 1_200,
                    modulo: 4,
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller")
    }

    fn ready(controller: &mut QcsdController, endpoint: u64, origin: &str) {
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(endpoint),
                origin: origin.into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
    }

    fn controller_with_application_length_hint(
        expected_response_length: Option<u64>,
    ) -> QcsdController {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Image".into(),
                content_length: Some(4_000),
                data_length: 4_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 500).expect("incoming packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 16,
                low_watermark: 0,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller
    }

    #[test]
    fn application_length_hint_schedules_application_credit_before_chaff() {
        // 11,445 bytes of expected body plus 1,000 bytes of framing allowance.
        let mut controller = controller_with_application_length_hint(Some(12_445));
        assert_eq!(
            controller
                .streams
                .capacity(QcsdEndpointId(1))
                .application_incoming,
            12_429
        );
        controller.poll(Duration::ZERO);
        let stream = controller.drain_actions().find_map(|action| match action {
            QcsdAction::IncreaseReceiveLimit { stream, .. } => Some(stream),
            _ => None,
        });
        assert_eq!(stream, Some(QcsdStreamId(0)));
    }

    #[test]
    fn omitted_application_length_hint_retains_zero_capacity() {
        let mut controller = controller_with_application_length_hint(None);
        assert_eq!(
            controller
                .streams
                .capacity(QcsdEndpointId(1))
                .application_incoming,
            0
        );
        controller.poll(Duration::ZERO);
        let stream = controller.drain_actions().find_map(|action| match action {
            QcsdAction::IncreaseReceiveLimit { stream, .. } => Some(stream),
            _ => None,
        });
        assert_eq!(stream, Some(QcsdStreamId(4)));
    }

    #[test]
    fn tamaraw_controls_application_and_emits_both_directions() {
        let mut controller = tamaraw_controller();
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureManualReceive {
                initial_limit: 16,
                ..
            })
        ));
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                frame_bytes: 10,
                status: Some(200),
                content_length: Some(5_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
    }

    #[test]
    fn front_leaves_application_receive_automatic() {
        let mut controller = QcsdController::new(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Front(crate::FrontConfig {
                    packet_size: 1_200,
                    ..crate::FrontConfig::default()
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureAutomaticReceive { .. })
        ));
    }

    #[test]
    fn independent_direction_cursors_start_at_the_first_endpoint() {
        let mut controller = tamaraw_controller();
        ready(&mut controller, 1, "https://one.example");
        ready(&mut controller, 2, "https://two.example");
        for (endpoint, stream) in [(1, 0), (2, 4)] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint: QcsdEndpointId(endpoint),
                    stream: QcsdStreamId(stream),
                    role: QcsdRequestRole::Application,
                    expected_response_length: None,
                },
                Duration::ZERO,
            );
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket {
                endpoint: QcsdEndpointId(1),
                ..
            }
        )));
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit {
                endpoint: QcsdEndpointId(1),
                ..
            }
        )));
    }

    #[test]
    fn partial_incoming_slot_fans_out_before_it_is_declared_missed() {
        let mut controller = QcsdController::new(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                defense: DefenseConfig::Tamaraw(TamarawConfig {
                    incoming_interval_us: 5_000,
                    outgoing_interval_us: 20_000,
                    packet_size: 1_200,
                    modulo: 4,
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller");
        ready(&mut controller, 1, "https://one.example");
        ready(&mut controller, 2, "https://two.example");
        // The first endpoint reproduces the Chromium config.json case:
        // 1,143 known bytes minus the 16-byte initial limit leaves only
        // 1,127 bytes for a 1,200-byte Tamaraw slot. The second endpoint has
        // enough capacity for the remaining 73 bytes.
        for (endpoint, stream, expected_response_length) in [(1, 0, 1_143), (2, 4, 5_000)] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint: QcsdEndpointId(endpoint),
                    stream: QcsdStreamId(stream),
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(expected_response_length),
                },
                Duration::ZERO,
            );
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
        let credits: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                } => Some((*endpoint, *stream, *absolute_limit, *packet, *slot)),
                _ => None,
            })
            .collect();
        assert_eq!(credits.len(), 2);
        assert_eq!(
            credits
                .iter()
                .map(|(endpoint, _, absolute_limit, _, _)| (*endpoint, *absolute_limit))
                .collect::<Vec<_>>(),
            [(QcsdEndpointId(1), 1_143), (QcsdEndpointId(2), 89)]
        );
        assert_eq!(credits[0].4, credits[1].4);

        for (index, (endpoint, stream, absolute_limit, _, slot)) in credits.into_iter().enumerate()
        {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(1),
            );
            if index == 0 {
                assert!(controller.next_action().is_none());
            } else {
                assert!(matches!(
                    controller.next_action(),
                    Some(QcsdAction::SlotSatisfied {
                        endpoint: Some(QcsdEndpointId(2)),
                        slot: satisfied,
                        ..
                    }) if satisfied == slot
                ));
            }
        }
    }

    #[test]
    fn chaff_repeats_a_large_same_origin_resource() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![Resource {
                id: 1,
                url: "https://one.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(250),
                data_length: 250,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::new(
            QcsdConfig {
                max_chaff_streams: 4,
                low_watermark: 1_000,
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Front(crate::FrontConfig {
                    packet_size: 1_200,
                    ..crate::FrontConfig::default()
                }),
                ..QcsdConfig::default()
            },
            42,
            Some(manifest),
        )
        .expect("valid controller");
        ready(&mut controller, 1, "https://one.example");
        controller.poll(Duration::ZERO);
        let request_count = controller
            .drain_actions()
            .filter(|action| matches!(action, QcsdAction::RequestChaff { .. }))
            .count();
        assert_eq!(request_count, 4);
    }

    #[test]
    fn exhausted_chaff_misses_incoming_slots_explicitly() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![Resource {
                id: 1,
                url: "https://one.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_200),
                data_length: 1_200,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Incoming, 1_200).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                max_chaff_streams: 1,
                low_watermark: 1_200,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(StaticSchedule::new(trace, true)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://one.example");
        controller.poll(Duration::ZERO);
        let request_id = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::RequestChaff { request_id, .. } => Some(request_id),
                _ => None,
            })
            .expect("initial chaff request");
        controller.observe(
            QcsdObservation::ChaffRequestFailed {
                resource_id: 1,
                request_id: Some(request_id),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::from_millis(5));
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
    }

    #[test]
    fn chaff_redirect_is_failed_and_never_promoted() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![Resource {
                id: 1,
                url: "https://one.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_200),
                data_length: 1_200,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Incoming, 1_200).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                max_chaff_streams: 1,
                low_watermark: 1_200,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(StaticSchedule::new(trace, true)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://one.example");
        controller.poll(Duration::ZERO);
        let request_id = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::RequestChaff { request_id, .. } => Some(request_id),
                _ => None,
            })
            .expect("initial chaff request");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Chaff {
                    resource_id: 1,
                    request_id: Some(request_id),
                },
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                frame_bytes: 40,
                status: Some(302),
                content_length: Some(1_200),
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::from_millis(5));
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::RequestChaff { .. }))
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
    }

    #[test]
    fn completion_waits_for_tail() {
        let mut controller = QcsdController::new(
            QcsdConfig {
                tail_wait_us: 100,
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller");
        controller.poll(Duration::ZERO);
        assert_eq!(controller.next_deadline(), Some(Duration::from_micros(100)));
        controller.poll(Duration::from_micros(100));
        assert!(controller.is_complete());
    }

    #[test]
    fn incoming_events_are_aggregated_at_control_interval_boundaries() {
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Incoming, 100).expect("packet"),
            Packet::new(Duration::from_millis(2), Direction::Incoming, 100).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::from_millis(2));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );

        controller.poll(Duration::from_millis(5));
        let released: u64 = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { packet, .. } => Some(u64::from(packet.length())),
                _ => None,
            })
            .sum();
        assert_eq!(released, 200);
    }

    #[test]
    fn incoming_slot_is_satisfied_only_after_credit_is_encoded() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let action = controller.next_action().expect("credit action");
        let QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit,
            slot,
            ..
        } = action
        else {
            panic!("expected attributed receive credit");
        };
        assert!(controller.next_action().is_none());

        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: observed_slot,
                ..
            }) if observed_slot == slot
        ));
    }

    #[test]
    fn unsatisfied_credit_is_only_retried_at_the_next_interval() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 100,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );

        controller.observe(
            QcsdObservation::DataFrame {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                frame_header_bytes: 2,
                data_bytes: 2_000,
            },
            Duration::from_millis(1),
        );
        controller.poll(Duration::from_millis(1));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        controller.poll(Duration::from_millis(5));
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
    }

    #[test]
    fn late_outgoing_slot_is_missed_before_transport() {
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Outgoing, 1_200).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.poll(Duration::from_millis(10));
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                slot: QcsdSlotId(0),
                reason: MissedSlotReason::DeadlineExpired,
                ..
            })
        ));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
    }

    #[test]
    fn incoming_only_tail_releases_chaff_send_shaping_once() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        let actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::ReleaseChaffSendShaping { .. }))
                .count(),
            1
        );
        controller.poll(Duration::ZERO);
        controller.poll(Duration::from_millis(1));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::ReleaseChaffSendShaping { .. }))
        );
    }

    #[test]
    fn failed_receive_action_terminates_its_pending_slot() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit { slot, packet, .. } =
            controller.next_action().expect("credit action")
        else {
            panic!("expected receive action");
        };
        controller.observe(
            QcsdObservation::SlotMissed {
                endpoint: QcsdEndpointId(1),
                slot,
                packet,
                reason: MissedSlotReason::EndpointClosed,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::from_millis(5));
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { slot: candidate, .. } if candidate == slot
        )));
    }

    #[test]
    fn signals_are_sorted_and_delivered_before_due_events() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 200,
                timestamp_us: 999,
            },
            Duration::from_micros(20),
        );
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(2),
                direction: Direction::Outgoing,
                length: 100,
                timestamp_us: 1,
            },
            Duration::from_micros(10),
        );

        controller.poll(Duration::from_micros(20));

        assert_eq!(
            *calls.borrow(),
            [
                RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(10),
                    kind: SignalKind::Wire {
                        direction: Direction::Outgoing,
                        length: 100,
                    },
                }),
                RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(20),
                    kind: SignalKind::Wire {
                        direction: Direction::Incoming,
                        length: 200,
                    },
                }),
                RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(20),
                    kind: SignalKind::Capacity(crate::Capacity::default()),
                }),
                RecordedCall::NextEvent(Duration::from_micros(20)),
            ]
        );
    }

    #[test]
    fn stale_signal_times_are_clamped_across_polls() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Outgoing,
                length: 100,
                timestamp_us: 10,
            },
            Duration::from_micros(10),
        );
        controller.poll(Duration::from_micros(10));
        calls.borrow_mut().clear();

        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 200,
                timestamp_us: 5,
            },
            Duration::from_micros(5),
        );
        controller.poll(Duration::from_micros(11));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(10),
                    kind: SignalKind::Wire {
                        direction: Direction::Incoming,
                        length: 200,
                    },
                }))
        );
    }

    #[test]
    fn application_complete_signal_is_idempotent() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(10),
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(11),
        );
        controller.poll(Duration::from_micros(11));

        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| {
                    matches!(
                        call,
                        RecordedCall::Signal(DefenseSignal {
                            kind: SignalKind::ApplicationComplete,
                            ..
                        })
                    )
                })
                .count(),
            1
        );
    }

    #[test]
    fn application_batch_lifecycle_is_delivered_in_order() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        assert!(controller.can_start_application_batch());
        controller.observe(
            QcsdObservation::ApplicationBatchStarted,
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(10),
        );
        controller.poll(Duration::from_micros(10));

        let lifecycle: Vec<_> = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::Signal(signal)
                    if matches!(
                        signal.kind,
                        SignalKind::ApplicationBatchStarted | SignalKind::ApplicationBatchCompleted
                    ) =>
                {
                    Some(*signal)
                }
                RecordedCall::Signal(_)
                | RecordedCall::ApplicationBytes { .. }
                | RecordedCall::NextEvent(_) => None,
            })
            .collect();
        assert_eq!(
            lifecycle,
            [
                DefenseSignal {
                    at: Duration::from_micros(5),
                    kind: SignalKind::ApplicationBatchStarted,
                },
                DefenseSignal {
                    at: Duration::from_micros(10),
                    kind: SignalKind::ApplicationBatchCompleted,
                },
            ]
        );
    }

    #[test]
    fn transmitted_stream_ranges_preserve_wire_bytes_and_deduplicate_natural_bytes() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Application,
                offset: 10,
                bytes: 25,
            },
            Duration::from_micros(7),
        );
        for at in [8, 9] {
            controller.observe(
                QcsdObservation::StreamDataTransmitted {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(4),
                    role: QcsdRequestRole::Application,
                    offset: 20,
                    bytes: 20,
                },
                Duration::from_micros(at),
            );
        }
        controller.poll(Duration::from_micros(9));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(7),
                    kind: SignalKind::PayloadBytes {
                        direction: Direction::Outgoing,
                        bytes: 25,
                        cover: false,
                    },
                }))
        );
        let application_bytes: Vec<_> = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::ApplicationBytes {
                    at,
                    direction,
                    bytes,
                } => Some((*at, *direction, *bytes)),
                RecordedCall::Signal(_) | RecordedCall::NextEvent(_) => None,
            })
            .collect();
        assert_eq!(
            application_bytes,
            [
                (Duration::from_micros(7), Direction::Outgoing, 25),
                (Duration::from_micros(8), Direction::Outgoing, 5),
            ]
        );
    }

    #[test]
    fn capacity_signal_is_emitted_only_when_the_aggregate_changes() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.poll(Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::from_micros(1),
        );
        controller.poll(Duration::from_micros(1));
        controller.poll(Duration::from_micros(2));

        let capacities: Vec<_> = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::Signal(DefenseSignal {
                    kind: SignalKind::Capacity(capacity),
                    ..
                }) => Some(*capacity),
                RecordedCall::Signal(_)
                | RecordedCall::ApplicationBytes { .. }
                | RecordedCall::NextEvent(_) => None,
            })
            .collect();
        assert_eq!(capacities.len(), 2);
        assert_eq!(capacities[0], crate::Capacity::default());
        assert!(capacities[1].application_incoming > 0);
    }

    #[test]
    fn outgoing_slot_resolution_is_atomic_and_wakes_controller() {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::SendPacket { slot, .. } = controller.next_action().expect("send action")
        else {
            panic!("expected outgoing slot");
        };
        assert!(!controller.is_complete());
        controller.observe(
            QcsdObservation::SlotSatisfied {
                endpoint: QcsdEndpointId(1),
                slot,
                observed_size: 1_180,
            },
            Duration::from_micros(100),
        );
        assert_eq!(controller.next_deadline(), Some(Duration::ZERO));
        controller.poll(Duration::from_micros(100));

        assert!(controller.pending_slots.is_empty());
        assert!(controller.is_complete());
        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(100),
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Satisfied { observed: 1_180 },
                    },
                }))
        );

        calls.borrow_mut().clear();
        controller.observe(
            QcsdObservation::SlotSatisfied {
                endpoint: QcsdEndpointId(1),
                slot,
                observed_size: 1_180,
            },
            Duration::from_micros(101),
        );
        controller.poll(Duration::from_micros(101));
        assert!(!calls.borrow().iter().any(|call| matches!(
            call,
            RecordedCall::Signal(DefenseSignal {
                kind: SignalKind::Resolved { .. },
                ..
            })
        )));
    }

    #[test]
    fn controller_generated_miss_resolves_and_clears_slot() {
        let packet =
            Packet::new(Duration::from_millis(1), Direction::Outgoing, 1_200).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::from_millis(10));
        assert!(controller.pending_slots.is_empty());
        assert_eq!(controller.next_deadline(), Some(Duration::ZERO));
        controller.poll(Duration::from_millis(10));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_millis(10),
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Missed(MissedSlotReason::DeadlineExpired),
                    },
                }))
        );
    }

    #[test]
    fn incoming_credit_resolution_reports_scheduled_credit() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(50),
        );
        controller.poll(Duration::from_micros(50));

        assert!(controller.pending_slots.is_empty());
        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(50),
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Satisfied { observed: 100 },
                    },
                }))
        );
    }

    #[test]
    fn controller_generated_incoming_miss_is_reported_once() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");

        controller.poll(Duration::ZERO);
        assert!(controller.pending_slots.is_empty());
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                reason: MissedSlotReason::NoEndpoint,
                ..
            })
        ));
        controller.poll(Duration::ZERO);

        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| {
                    matches!(
                        call,
                        RecordedCall::Signal(DefenseSignal {
                            kind: SignalKind::Resolved {
                                packet: resolved,
                                outcome: EventOutcome::Missed(MissedSlotReason::NoEndpoint),
                            },
                            ..
                        }) if *resolved == packet
                    )
                })
                .count(),
            1
        );
    }

    #[test]
    fn pending_slot_snapshot_includes_controller_only_retry_backlog() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");

        controller.poll(Duration::ZERO);

        assert_eq!(controller.pending_slots(), [(QcsdSlotId(0), packet)]);
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SlotMissed { .. }))
        );
    }

    #[test]
    fn classified_wire_is_additive_to_raw_wire_evidence() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        let at = Duration::from_micros(7);
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 123,
                timestamp_us: 7,
            },
            at,
        );
        controller.observe(
            QcsdObservation::ClassifiedDatagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 123,
                class: QcsdDatagramClass::DefenseCover,
            },
            at,
        );
        controller.poll(at);

        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at,
            kind: SignalKind::Wire {
                direction: Direction::Incoming,
                length: 123,
            },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at,
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 123,
                class: QcsdDatagramClass::DefenseCover,
            },
        })));
    }

    #[test]
    fn initial_allowance_is_excluded_from_consumed_scheduled_credit() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 116,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(116),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 100,
            },
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(2),
                    kind: SignalKind::ReceiveCreditConsumed { bytes: 84 },
                }))
        );
    }

    #[test]
    fn endpoint_close_retires_every_remaining_advertised_offset() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 116,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(116),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 40,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));

        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 24 },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditRetired { bytes: 76 },
        })));
    }
}
