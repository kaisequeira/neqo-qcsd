// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

mod control_loop;

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use control_loop::{ControlLoop, PendingCredit, PendingIncoming, PendingOutgoing};

use crate::{
    Defense, DefenseConfig, DefenseMode, Direction, Front, MissedSlotReason, QcsdAction,
    QcsdConfig, QcsdEndpointId, QcsdObservation, QcsdRequestRole, QcsdStreamId, ResourceManifest,
    Result, RoundRobinScheduler, StaticSchedule, Tamaraw, chaff_manager::ChaffManager,
    stream::StreamRegistry,
};

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
    actions: std::collections::VecDeque<QcsdAction>,
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
        let defense: Box<dyn Defense> = match &config.defense {
            DefenseConfig::None => Box::new(StaticSchedule::new(crate::Trace::default(), true)),
            DefenseConfig::Static {
                schedule,
                padding_only,
            } => Box::new(StaticSchedule::from_legacy_csv(schedule, *padding_only)?),
            DefenseConfig::Front(front) => Box::new(Front::new(front, seed)),
            DefenseConfig::Tamaraw(tamaraw) => Box::new(Tamaraw::new(tamaraw)),
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
            actions: std::collections::VecDeque::new(),
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

    /// Consume one endpoint, HTTP/3, or transport observation.
    #[expect(
        clippy::too_many_lines,
        reason = "the exhaustive observation reducer makes every state transition auditable"
    )]
    pub fn observe(&mut self, observation: QcsdObservation) {
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
                self.control.reassign_endpoint(endpoint);
                self.return_endpoint_credit(endpoint);
                self.released_chaff_send_shaping.remove(&endpoint);
            }
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role,
            } => self.open_stream(endpoint, stream, role),
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
                if let Some(state) = self.streams.get_mut(endpoint, stream) {
                    state
                        .receive
                        .bytes_read(bytes, self.config.max_stream_data_excess);
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
            } => self.credit_advertised(endpoint, stream, absolute_limit, slot),
            QcsdObservation::StreamFinished {
                endpoint, stream, ..
            } => self.close_stream(endpoint, stream),
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
            QcsdObservation::ApplicationComplete => {
                if !self.application_complete {
                    self.application_complete = true;
                    self.defense.on_application_complete();
                }
            }
            QcsdObservation::SlotMissed { slot, .. } => self.fail_incoming_slot(slot),
            QcsdObservation::Datagram { .. } | QcsdObservation::SlotSatisfied { .. } => {}
        }
    }

    fn open_stream(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
    ) {
        let expected = match role {
            QcsdRequestRole::Application => 0,
            QcsdRequestRole::Chaff {
                resource_id,
                request_id,
            } => self.chaff.as_mut().map_or(0, |chaff| {
                chaff.request_opened(request_id);
                chaff.estimate(resource_id)
            }),
        };
        let controlled = self.controls(role);
        self.streams.open(
            endpoint,
            stream,
            role,
            controlled,
            self.config.initial_max_stream_data,
            self.config.max_stream_data_excess,
            expected,
        );
        if controlled {
            self.actions.push_back(QcsdAction::ConfigureManualReceive {
                endpoint,
                stream,
                initial_limit: self.config.initial_max_stream_data,
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

    fn close_stream(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId) {
        let Some((state, data_length, _unadvertised)) = self.streams.close(endpoint, stream) else {
            return;
        };
        self.return_stream_credit(endpoint, stream);
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
        slot: Option<crate::QcsdSlotId>,
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
        self.control.credit.retain(|credit| {
            let same_release = credit.endpoint == endpoint
                && credit.stream == stream
                && credit.absolute_limit <= absolute_limit
                && slot.is_none_or(|slot| credit.slot == slot);
            !same_release
        });
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
        }
    }

    fn return_stream_credit(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId) {
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
            self.return_credit(&credit);
        }
    }

    fn return_endpoint_credit(&mut self, endpoint: QcsdEndpointId) {
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
            self.return_credit(&credit);
        }
    }

    fn return_credit(&mut self, credit: &PendingCredit) {
        if self.config.drop_unsatisfied_events {
            self.control.terminal_incoming.insert(credit.slot);
            self.actions.push_back(QcsdAction::SlotMissed {
                endpoint: Some(credit.endpoint),
                packet: credit.packet,
                slot: credit.slot,
                reason: MissedSlotReason::EndpointClosed,
            });
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

    fn fail_incoming_slot(&mut self, slot: crate::QcsdSlotId) {
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
        self.request_chaff_if_needed();
        self.collect_due_events(elapsed);
        self.process_outgoing(elapsed);
        self.release_chaff_send_shaping_if_needed();

        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let boundary_us = ControlLoop::boundary_us(elapsed_us, self.config.control_interval_us);
        if self.control.should_process_incoming(boundary_us) {
            self.process_incoming(boundary_us);
        }

        self.request_chaff_if_needed();
        self.update_completion(elapsed);
    }

    fn collect_due_events(&mut self, elapsed: Duration) {
        while let Some(packet) = self.defense.next_event(elapsed) {
            let slot = self.control.next_slot();
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

    fn process_incoming(&mut self, boundary_us: u64) {
        let pending = std::mem::take(&mut self.control.incoming);
        for mut incoming in pending {
            if incoming.packet.timestamp_us() > boundary_us {
                self.control.incoming.push(incoming);
                continue;
            }
            if incoming.endpoint.is_none() {
                let streams = &self.streams;
                incoming.endpoint = self
                    .scheduler
                    .next_incoming(incoming.remaining, self.defense.mode(), |endpoint| {
                        streams.capacity(endpoint)
                    })
                    .map(|(endpoint, _)| endpoint);
            }
            let Some(endpoint) = incoming.endpoint else {
                self.unsatisfied_incoming(incoming, MissedSlotReason::NoEndpoint);
                continue;
            };

            let releases = self
                .streams
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
            if incoming.remaining > 0 {
                self.unsatisfied_incoming(incoming, MissedSlotReason::InsufficientIncomingCapacity);
            }
        }
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the pending event is deliberately transferred back into the queue"
    )]
    fn unsatisfied_incoming(&mut self, incoming: PendingIncoming, reason: MissedSlotReason) {
        if self.config.drop_unsatisfied_events {
            self.control.terminal_incoming.insert(incoming.slot);
            self.actions.push_back(QcsdAction::SlotMissed {
                endpoint: incoming.endpoint,
                packet: incoming.packet,
                slot: incoming.slot,
                reason,
            });
        } else {
            self.control.incoming.push(incoming);
        }
    }

    fn update_completion(&mut self, elapsed: Duration) {
        let has_backlog = self.control.incoming_backlog() > 0
            || !self.control.outgoing.is_empty()
            || !self.control.credit.is_empty();
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
            || !self.defense.is_outgoing_complete()
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
            && self.defense.is_outgoing_complete()
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
            candidates.push(Duration::from_micros(next));
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
    use std::time::Duration;

    use super::QcsdController;
    use crate::{
        DefenseConfig, Direction, HeaderPolicy, MissedSlotReason, Packet, QcsdAction, QcsdConfig,
        QcsdEndpointId, QcsdObservation, QcsdRequestRole, QcsdSlotId, QcsdStreamFinish,
        QcsdStreamId, Resource, ResourceManifest, StaticSchedule, TamarawConfig, Trace,
    };

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
        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(endpoint),
            origin: origin.into(),
            max_udp_payload_size: 1_200,
        });
    }

    #[test]
    fn tamaraw_controls_application_and_emits_both_directions() {
        let mut controller = tamaraw_controller();
        ready(&mut controller, 1, "https://example.com");
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureManualReceive {
                initial_limit: 16,
                ..
            })
        ));
        controller.observe(QcsdObservation::ResponseHeaders {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            frame_bytes: 10,
            status: Some(200),
            content_length: Some(5_000),
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
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
            controller.observe(QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(endpoint),
                stream: QcsdStreamId(stream),
                role: QcsdRequestRole::Application,
            });
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
    fn incoming_slot_never_spans_connections() {
        let mut controller = tamaraw_controller();
        ready(&mut controller, 1, "https://one.example");
        ready(&mut controller, 2, "https://two.example");
        for (endpoint, stream) in [(1, 0), (2, 4)] {
            controller.observe(QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(endpoint),
                stream: QcsdStreamId(stream),
                role: QcsdRequestRole::Application,
            });
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let incoming_endpoints: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { endpoint, .. } => Some(endpoint),
                _ => None,
            })
            .collect();
        assert!(!incoming_endpoints.is_empty());
        assert!(
            incoming_endpoints
                .iter()
                .all(|endpoint| *endpoint == incoming_endpoints[0])
        );
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
        controller.observe(QcsdObservation::ChaffRequestFailed {
            resource_id: 1,
            request_id: Some(request_id),
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            role: QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: Some(request_id),
            },
        });
        controller.observe(QcsdObservation::ResponseHeaders {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            frame_bytes: 40,
            status: Some(302),
            content_length: Some(1_200),
        });
        controller.observe(QcsdObservation::StreamFinished {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(4),
            finish: QcsdStreamFinish::Fin,
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
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

        controller.observe(QcsdObservation::ReceiveLimitAdvertised {
            endpoint,
            stream,
            absolute_limit,
            slot: Some(slot),
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );

        controller.observe(QcsdObservation::DataFrame {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            frame_header_bytes: 2,
            data_bytes: 2_000,
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
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
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit { slot, packet, .. } =
            controller.next_action().expect("credit action")
        else {
            panic!("expected receive action");
        };
        controller.observe(QcsdObservation::SlotMissed {
            endpoint: QcsdEndpointId(1),
            slot,
            packet,
            reason: MissedSlotReason::EndpointClosed,
        });
        controller.poll(Duration::from_millis(5));
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { slot: candidate, .. } if candidate == slot
        )));
    }
}
