// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    Capacity, Defense, DefenseConfig, Direction, Front, Packet, QcsdConfig, Resource,
    ResourceManifest, Result, StaticSchedule, Tamaraw,
};

/// Stable identifier assigned by the runner to a QUIC connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QcsdEndpointId(pub u64);

/// Transport-independent QUIC stream identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QcsdStreamId(pub u64);

/// Whether an HTTP request carries application data or QCSD chaff.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdRequestRole {
    /// A request explicitly supplied by the experiment.
    Application,
    /// A same-origin request generated to provide downstream capacity.
    Chaff {
        /// Resource manifest identifier.
        resource_id: u32,
    },
}

/// Why a transport adapter could not satisfy a scheduled slot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissedSlotReason {
    /// No active connection could receive the action.
    NoEndpoint,
    /// No controlled response stream had enough unused receive capacity.
    InsufficientIncomingCapacity,
    /// Congestion control prevented transmission.
    CongestionLimited,
    /// Required packet-protection keys were not available.
    KeysUnavailable,
    /// The configured size was invalid for the active path.
    PathMtu,
    /// Mandatory QUIC frames could not fit the scheduled target.
    MandatoryFrames,
    /// The endpoint closed before the event was applied.
    EndpointClosed,
}

/// Events reported by Neqo transport and HTTP/3 to the controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QcsdObservation {
    /// A connection is ready to participate in shaping.
    EndpointReady {
        /// Runner-assigned connection identifier.
        endpoint: QcsdEndpointId,
        /// Normalized `https://authority` used for same-origin chaff routing.
        origin: String,
        /// Active path maximum UDP payload.
        max_udp_payload_size: u16,
    },
    /// A connection has closed.
    EndpointClosed {
        /// Closed connection.
        endpoint: QcsdEndpointId,
    },
    /// An HTTP request stream was created.
    StreamOpened {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
        /// Application or chaff role.
        role: QcsdRequestRole,
    },
    /// Response HEADERS were decoded.
    ResponseHeaders {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
        /// Encoded HTTP/3 frame bytes consumed by the headers.
        frame_bytes: u64,
        /// Parsed Content-Length, when present and valid.
        content_length: Option<u64>,
    },
    /// A response DATA frame was observed.
    DataFrame {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
        /// Encoded frame header bytes.
        frame_header_bytes: u64,
        /// DATA payload bytes.
        data_bytes: u64,
    },
    /// The application retired response bytes from a stream.
    BytesRead {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
        /// Newly retired bytes.
        bytes: u64,
    },
    /// Request body bytes were queued by the application.
    BytesQueued {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
        /// Newly queued bytes.
        bytes: u64,
    },
    /// Request body bytes were transmitted.
    BytesSent {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
        /// Newly transmitted bytes.
        bytes: u64,
    },
    /// A stream reached FIN or reset.
    StreamFinished {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// QUIC stream identifier.
        stream: QcsdStreamId,
    },
    /// Creation of a requested chaff stream failed.
    ChaffRequestFailed {
        /// Manifest identifier that failed.
        resource_id: u32,
    },
    /// All application requests have completed.
    ApplicationComplete,
    /// A UDP datagram was observed for research output.
    Datagram {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Traffic direction.
        direction: Direction,
        /// UDP payload bytes.
        length: u16,
        /// Monotonic time relative to run start.
        timestamp_us: u64,
    },
    /// Transport feedback for an action that could not be applied.
    SlotMissed {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Scheduled slot.
        packet: Packet,
        /// Failure classification.
        reason: MissedSlotReason,
    },
}

/// Commands emitted by the controller for a Neqo endpoint adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QcsdAction {
    /// Switch a receive stream from automatic to absolute manual credit.
    ConfigureManualReceive {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Stream to control.
        stream: QcsdStreamId,
        /// Initial absolute `MAX_STREAM_DATA` value.
        initial_limit: u64,
    },
    /// Restore normal automatic receive-window management for a stream.
    ConfigureAutomaticReceive {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Stream to leave unshaped.
        stream: QcsdStreamId,
        /// Automatic receive window.
        window: u64,
    },
    /// Raise an absolute receive limit.
    IncreaseReceiveLimit {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Stream to release.
        stream: QcsdStreamId,
        /// New absolute `MAX_STREAM_DATA` value.
        absolute_limit: u64,
        /// Scheduled event that caused this release.
        packet: Packet,
    },
    /// Permit request-stream data to fill an outgoing slot.
    IncreaseSendBudget {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Additional bytes eligible for transmission.
        bytes: u64,
        /// Scheduled event that caused this grant.
        packet: Packet,
    },
    /// Produce one exact-size 1-RTT UDP datagram, padding as required.
    SendPacket {
        /// Owning connection.
        endpoint: QcsdEndpointId,
        /// Target UDP payload length.
        udp_payload_size: u16,
        /// Scheduled event that caused this action.
        packet: Packet,
    },
    /// Open a same-origin chaff GET request.
    RequestChaff {
        /// Connection on which the request should be opened.
        endpoint: QcsdEndpointId,
        /// Selected resource and safe request metadata.
        resource: Resource,
    },
    /// Schedule transport keep-alive processing.
    KeepAlive {
        /// Owning connection.
        endpoint: QcsdEndpointId,
    },
    /// Record a controller-side unsatisfied slot.
    SlotMissed {
        /// Intended connection, when one exists.
        endpoint: Option<QcsdEndpointId>,
        /// Unfulfilled scheduled event.
        packet: Packet,
        /// Failure classification.
        reason: MissedSlotReason,
    },
    /// The defense and configured tail have completed.
    DefenseComplete,
}

#[derive(Clone, Debug)]
struct StreamState {
    role: QcsdRequestRole,
    expected_bytes: u64,
    released_limit: u64,
    observed_bytes: u64,
    read_bytes: u64,
}

impl StreamState {
    const fn remaining_capacity(&self) -> u64 {
        self.expected_bytes.saturating_sub(self.released_limit)
    }
}

/// Orchestrates a defense across one or more client connections.
#[derive(Debug)]
pub struct QcsdController {
    config: QcsdConfig,
    defense: Box<dyn Defense>,
    resources: Option<ResourceManifest>,
    endpoints: Vec<QcsdEndpointId>,
    endpoint_origins: HashMap<QcsdEndpointId, String>,
    endpoint_cursor: usize,
    streams: HashMap<(QcsdEndpointId, QcsdStreamId), StreamState>,
    completed_resources: HashSet<u32>,
    pending_chaff_resources: HashSet<u32>,
    pending_events: VecDeque<Packet>,
    actions: VecDeque<QcsdAction>,
    application_complete: bool,
    completion_emitted: bool,
    completion_due: Option<Duration>,
}

impl QcsdController {
    /// Construct a controller from resolved configuration and an explicit seed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, manifests, or static schedules.
    pub fn new(config: QcsdConfig, seed: u64, resources: Option<ResourceManifest>) -> Result<Self> {
        config.validate()?;
        if let Some(resources) = &resources {
            resources.validate()?;
        }
        let defense: Box<dyn Defense> = match &config.defense {
            DefenseConfig::None => Box::new(StaticSchedule::new(crate::Trace::default(), true)),
            DefenseConfig::Static {
                schedule,
                padding_only,
            } => Box::new(StaticSchedule::from_legacy_csv(schedule, *padding_only)?),
            DefenseConfig::Front(front) => Box::new(Front::new(front, seed)),
            DefenseConfig::Tamaraw(tamaraw) => Box::new(Tamaraw::new(tamaraw)),
        };
        Ok(Self {
            config,
            defense,
            resources,
            endpoints: Vec::new(),
            endpoint_origins: HashMap::new(),
            endpoint_cursor: 0,
            streams: HashMap::new(),
            completed_resources: HashSet::new(),
            pending_chaff_resources: HashSet::new(),
            pending_events: VecDeque::new(),
            actions: VecDeque::new(),
            application_complete: false,
            completion_emitted: false,
            completion_due: None,
        })
    }

    /// Resolved configuration used for the run.
    #[must_use]
    pub const fn config(&self) -> &QcsdConfig {
        &self.config
    }

    /// Consume one endpoint/HTTP observation.
    #[expect(
        clippy::too_many_lines,
        reason = "observations are owned queue messages and this exhaustive reducer keeps state transitions together"
    )]
    pub fn observe(&mut self, observation: QcsdObservation) {
        match observation {
            QcsdObservation::EndpointReady {
                endpoint,
                origin,
                max_udp_payload_size,
            } => {
                if max_udp_payload_size < self.config.max_udp_payload_size {
                    // The adapter still validates each target. Retaining the endpoint allows
                    // smaller static events to proceed and records oversized misses precisely.
                }
                if !self.endpoints.contains(&endpoint) {
                    self.endpoints.push(endpoint);
                }
                self.endpoint_origins.insert(endpoint, origin);
            }
            QcsdObservation::EndpointClosed { endpoint } => {
                self.endpoints.retain(|candidate| *candidate != endpoint);
                self.endpoint_origins.remove(&endpoint);
                self.streams
                    .retain(|(candidate, _), _| *candidate != endpoint);
                if self.endpoints.is_empty() {
                    self.endpoint_cursor = 0;
                } else {
                    self.endpoint_cursor %= self.endpoints.len();
                }
            }
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role,
            } => {
                let expected_bytes = match role {
                    QcsdRequestRole::Application => self.config.max_stream_data_excess,
                    QcsdRequestRole::Chaff { resource_id } => {
                        self.pending_chaff_resources.remove(&resource_id);
                        self.resources
                            .as_ref()
                            .and_then(|manifest| {
                                manifest
                                    .resources
                                    .iter()
                                    .find(|resource| resource.id == resource_id)
                            })
                            .map_or(self.config.max_stream_data_excess, |resource| {
                                resource
                                    .effective_length()
                                    .saturating_add(self.config.max_stream_data_excess)
                            })
                    }
                };
                self.streams.insert(
                    (endpoint, stream),
                    StreamState {
                        role,
                        expected_bytes,
                        released_limit: self.config.initial_max_stream_data,
                        observed_bytes: 0,
                        read_bytes: 0,
                    },
                );
                if self.controls(role) {
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
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream,
                frame_bytes,
                content_length,
            } => {
                if let Some(state) = self.streams.get_mut(&(endpoint, stream)) {
                    state.observed_bytes = state.observed_bytes.saturating_add(frame_bytes);
                    if let Some(content_length) = content_length {
                        state.expected_bytes = content_length
                            .saturating_add(frame_bytes)
                            .saturating_add(self.config.max_stream_data_excess);
                    }
                }
            }
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                frame_header_bytes,
                data_bytes,
            } => {
                if let Some(state) = self.streams.get_mut(&(endpoint, stream)) {
                    state.observed_bytes = state
                        .observed_bytes
                        .saturating_add(frame_header_bytes)
                        .saturating_add(data_bytes);
                    state.expected_bytes = state.expected_bytes.max(
                        state
                            .observed_bytes
                            .saturating_add(self.config.max_stream_data_excess),
                    );
                }
            }
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes,
            } => {
                if let Some(state) = self.streams.get_mut(&(endpoint, stream)) {
                    state.read_bytes = state.read_bytes.saturating_add(bytes);
                }
            }
            QcsdObservation::StreamFinished { endpoint, stream } => {
                if let Some(state) = self.streams.remove(&(endpoint, stream))
                    && let QcsdRequestRole::Chaff { resource_id } = state.role
                {
                    self.completed_resources.insert(resource_id);
                }
            }
            QcsdObservation::ChaffRequestFailed { resource_id } => {
                self.pending_chaff_resources.remove(&resource_id);
            }
            QcsdObservation::ApplicationComplete => {
                if !self.application_complete {
                    self.application_complete = true;
                    self.defense.on_application_complete();
                }
            }
            QcsdObservation::BytesQueued { .. }
            | QcsdObservation::BytesSent { .. }
            | QcsdObservation::Datagram { .. }
            | QcsdObservation::SlotMissed { .. } => {}
        }
    }

    /// Advance the defense to `elapsed` and queue all due actions.
    pub fn poll(&mut self, elapsed: Duration) {
        self.request_chaff_if_needed();
        let pending_count = self.pending_events.len();
        for _ in 0..pending_count {
            let Some(packet) = self.pending_events.pop_front() else {
                break;
            };
            if !self.schedule_packet(packet) {
                self.pending_events.push_back(packet);
            }
        }
        let mut capacity = self.capacity();
        while let Some(packet) = self.defense.next_event(elapsed, capacity) {
            if !self.schedule_packet(packet) {
                self.pending_events.push_back(packet);
            }
            capacity = self.capacity();
        }
        self.request_chaff_if_needed();
        if self.defense.is_complete() && self.pending_events.is_empty() {
            let due = *self.completion_due.get_or_insert_with(|| {
                elapsed.saturating_add(Duration::from_micros(self.config.tail_wait_us))
            });
            if !self.completion_emitted && elapsed >= due {
                self.completion_emitted = true;
                self.actions.push_back(QcsdAction::DefenseComplete);
            }
        }
    }

    /// Route one due defense packet, returning `false` when policy requires a retry.
    fn schedule_packet(&mut self, packet: Packet) -> bool {
        match packet.direction() {
            Direction::Outgoing => {
                let Some(endpoint) = self.next_endpoint() else {
                    if self.config.drop_unsatisfied_events {
                        self.actions.push_back(QcsdAction::SlotMissed {
                            endpoint: None,
                            packet,
                            reason: MissedSlotReason::NoEndpoint,
                        });
                        return true;
                    }
                    return false;
                };
                if !self.defense.is_padding_only() {
                    self.actions.push_back(QcsdAction::IncreaseSendBudget {
                        endpoint,
                        bytes: u64::from(packet.length()),
                        packet,
                    });
                }
                self.actions.push_back(QcsdAction::SendPacket {
                    endpoint,
                    udp_payload_size: packet.length(),
                    packet,
                });
                true
            }
            Direction::Incoming => {
                let available = self.capacity().available(self.defense.is_padding_only());
                if available < u64::from(packet.length()) {
                    if self.config.drop_unsatisfied_events {
                        let endpoint = self.next_endpoint();
                        self.actions.push_back(QcsdAction::SlotMissed {
                            endpoint,
                            packet,
                            reason: if endpoint.is_some() {
                                MissedSlotReason::InsufficientIncomingCapacity
                            } else {
                                MissedSlotReason::NoEndpoint
                            },
                        });
                        return true;
                    }
                    return false;
                }
                let endpoint = self.next_endpoint();
                self.release_incoming(endpoint, packet);
                true
            }
        }
    }

    /// Earliest time at which [`Self::poll`] can produce another defense slot.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        if self.pending_events.is_empty() {
            self.defense
                .next_event_at()
                .or_else(|| self.completion_due.filter(|_| !self.completion_emitted))
        } else {
            Some(Duration::ZERO)
        }
    }

    /// Remove the next queued action.
    pub fn next_action(&mut self) -> Option<QcsdAction> {
        self.actions.pop_front()
    }

    /// Drain all queued actions in order.
    pub fn drain_actions(&mut self) -> impl Iterator<Item = QcsdAction> + '_ {
        self.actions.drain(..)
    }

    /// Whether the defense has emitted its terminal action.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completion_emitted
    }

    fn controls(&self, role: QcsdRequestRole) -> bool {
        !self.defense.is_padding_only() || matches!(role, QcsdRequestRole::Chaff { .. })
    }

    fn next_endpoint(&mut self) -> Option<QcsdEndpointId> {
        if self.endpoints.is_empty() {
            return None;
        }
        let endpoint = self.endpoints[self.endpoint_cursor];
        self.endpoint_cursor = (self.endpoint_cursor + 1) % self.endpoints.len();
        Some(endpoint)
    }

    fn next_endpoint_for_origin(&mut self, origin: &str) -> Option<QcsdEndpointId> {
        for offset in 0..self.endpoints.len() {
            let index = (self.endpoint_cursor + offset) % self.endpoints.len();
            let endpoint = self.endpoints[index];
            if self
                .endpoint_origins
                .get(&endpoint)
                .is_some_and(|candidate| candidate == origin)
            {
                self.endpoint_cursor = (index + 1) % self.endpoints.len();
                return Some(endpoint);
            }
        }
        None
    }

    fn capacity(&self) -> Capacity {
        self.streams
            .values()
            .fold(Capacity::default(), |mut capacity, state| {
                let available = state.remaining_capacity();
                match state.role {
                    QcsdRequestRole::Application => {
                        capacity.application_incoming =
                            capacity.application_incoming.saturating_add(available);
                    }
                    QcsdRequestRole::Chaff { .. } => {
                        capacity.chaff_incoming = capacity.chaff_incoming.saturating_add(available);
                    }
                }
                capacity
            })
    }

    fn release_incoming(&mut self, preferred: Option<QcsdEndpointId>, packet: Packet) {
        let mut remaining = u64::from(packet.length());
        let padding_only = self.defense.is_padding_only();
        let mut keys: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, state)| self.controls(state.role) && state.remaining_capacity() > 0)
            .map(|(key, state)| (*key, state.role))
            .collect();
        keys.sort_by_key(|((endpoint, stream), role)| {
            let endpoint_rank = u8::from(Some(*endpoint) != preferred);
            let role_rank = match role {
                QcsdRequestRole::Application if !padding_only => 0,
                QcsdRequestRole::Chaff { .. } => 1,
                QcsdRequestRole::Application => 2,
            };
            (endpoint_rank, role_rank, *endpoint, *stream)
        });
        let mut selected_endpoint = preferred;
        for ((endpoint, stream), _) in keys {
            if remaining == 0 {
                break;
            }
            let state = self
                .streams
                .get_mut(&(endpoint, stream))
                .expect("key collected from stream map");
            let release = remaining.min(state.remaining_capacity());
            if release == 0 {
                continue;
            }
            state.released_limit = state.released_limit.saturating_add(release);
            remaining -= release;
            selected_endpoint = Some(endpoint);
            self.actions.push_back(QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: state.released_limit,
                packet,
            });
        }
        if remaining > 0 {
            self.actions.push_back(QcsdAction::SlotMissed {
                endpoint: selected_endpoint,
                packet,
                reason: MissedSlotReason::InsufficientIncomingCapacity,
            });
        }
    }

    fn request_chaff_if_needed(&mut self) {
        let Some(manifest) = &self.resources else {
            return;
        };
        if self.endpoints.is_empty() {
            return;
        }
        let open_chaff = self
            .streams
            .values()
            .filter(|state| matches!(state.role, QcsdRequestRole::Chaff { .. }))
            .count();
        let available = self.capacity().chaff_incoming;
        if available >= self.config.low_watermark
            || open_chaff + self.pending_chaff_resources.len() >= self.config.max_chaff_streams
        {
            return;
        }
        let slots = self
            .config
            .max_chaff_streams
            .saturating_sub(open_chaff + self.pending_chaff_resources.len());
        let selected: Vec<_> = manifest
            .select_chaff(manifest.resources.len(), &self.completed_resources)
            .into_iter()
            .filter(|resource| !self.pending_chaff_resources.contains(&resource.id))
            .filter(|resource| {
                resource.origin().is_some_and(|origin| {
                    self.endpoint_origins
                        .values()
                        .any(|candidate| candidate == &origin)
                })
            })
            .take(slots)
            .cloned()
            .collect();
        for resource in selected {
            let Some(origin) = resource.origin() else {
                continue;
            };
            let Some(endpoint) = self.next_endpoint_for_origin(&origin) else {
                break;
            };
            self.pending_chaff_resources.insert(resource.id);
            self.actions
                .push_back(QcsdAction::RequestChaff { endpoint, resource });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        QcsdAction, QcsdController, QcsdEndpointId, QcsdObservation, QcsdRequestRole, QcsdStreamId,
    };
    use crate::{DefenseConfig, QcsdConfig, Resource, ResourceManifest, TamarawConfig};

    fn tamaraw_controller() -> QcsdController {
        let config = QcsdConfig {
            max_udp_payload_size: 1_200,
            defense: DefenseConfig::Tamaraw(TamarawConfig {
                incoming_interval_us: 5_000,
                outgoing_interval_us: 20_000,
                packet_size: 1_200,
                modulo: 4,
            }),
            ..QcsdConfig::default()
        };
        QcsdController::new(config, 42, None).expect("valid controller")
    }

    #[test]
    fn tamaraw_configures_application_stream_and_emits_both_directions() {
        let mut controller = tamaraw_controller();
        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(1),
            origin: "https://example.com".into(),
            max_udp_payload_size: 1_200,
        });
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
    fn front_restores_automatic_application_receive_window() {
        let config = QcsdConfig {
            max_udp_payload_size: 1_200,
            defense: DefenseConfig::Front(crate::FrontConfig {
                packet_size: 1_200,
                ..crate::FrontConfig::default()
            }),
            ..QcsdConfig::default()
        };
        let mut controller = QcsdController::new(config, 42, None).expect("valid controller");
        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(1),
            origin: "https://example.com".into(),
            max_udp_payload_size: 1_200,
        });
        controller.observe(QcsdObservation::StreamOpened {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            role: QcsdRequestRole::Application,
        });
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureAutomaticReceive {
                window: 1_048_576,
                ..
            })
        ));
    }

    #[test]
    fn unsatisfied_event_waits_when_drop_is_disabled() {
        let mut controller = tamaraw_controller();
        controller.poll(Duration::ZERO);
        assert!(controller.drain_actions().next().is_none());
        assert_eq!(controller.next_deadline(), Some(Duration::ZERO));

        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(1),
            origin: "https://example.com".into(),
            max_udp_payload_size: 1_200,
        });
        controller.poll(Duration::ZERO);
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
    }

    #[test]
    fn unsatisfied_event_is_an_explicit_miss_when_drop_is_enabled() {
        let config = QcsdConfig {
            drop_unsatisfied_events: true,
            max_udp_payload_size: 1_200,
            defense: DefenseConfig::Tamaraw(TamarawConfig {
                incoming_interval_us: 5_000,
                outgoing_interval_us: 20_000,
                packet_size: 1_200,
                modulo: 4,
            }),
            ..QcsdConfig::default()
        };
        let mut controller = QcsdController::new(config, 42, None).expect("valid controller");
        controller.poll(Duration::ZERO);
        assert!(
            controller
                .drain_actions()
                .all(|action| matches!(action, QcsdAction::SlotMissed { .. }))
        );
    }

    #[test]
    fn unsatisfied_incoming_does_not_block_later_outgoing_slots() {
        let mut controller = tamaraw_controller();
        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(1),
            origin: "https://example.com".into(),
            max_udp_payload_size: 1_200,
        });

        controller.poll(Duration::from_millis(20));
        assert_eq!(
            controller
                .drain_actions()
                .filter(|action| matches!(action, QcsdAction::SendPacket { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn completion_waits_for_the_configured_tail() {
        let config = QcsdConfig {
            tail_wait_us: 100,
            ..QcsdConfig::default()
        };
        let mut controller = QcsdController::new(config, 42, None).expect("valid controller");

        controller.poll(Duration::ZERO);
        assert!(!controller.is_complete());
        assert_eq!(controller.next_deadline(), Some(Duration::from_micros(100)));

        controller.poll(Duration::from_micros(99));
        assert!(!controller.is_complete());
        controller.poll(Duration::from_micros(100));
        assert!(controller.is_complete());
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::DefenseComplete)
        ));
    }

    #[test]
    fn chaff_is_routed_to_an_exact_same_origin_endpoint() {
        let manifest = ResourceManifest {
            schema_version: 1,
            resources: vec![
                Resource {
                    id: 1,
                    url: "https://one.example/chaff".into(),
                    kind: "Document".into(),
                    content_length: Some(2_000),
                    data_length: 2_000,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 2,
                    url: "https://two.example/chaff".into(),
                    kind: "Document".into(),
                    content_length: Some(3_000),
                    data_length: 3_000,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
            ],
        };
        let config = QcsdConfig {
            max_chaff_streams: 2,
            low_watermark: 1,
            ..QcsdConfig::default()
        };
        let mut controller =
            QcsdController::new(config, 42, Some(manifest)).expect("valid controller");
        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(1),
            origin: "https://one.example".into(),
            max_udp_payload_size: 1_200,
        });
        controller.observe(QcsdObservation::EndpointReady {
            endpoint: QcsdEndpointId(2),
            origin: "https://two.example".into(),
            max_udp_payload_size: 1_200,
        });

        controller.poll(Duration::ZERO);
        let mut request_count = 0;
        for action in controller.drain_actions() {
            if let QcsdAction::RequestChaff { endpoint, resource } = action {
                request_count += 1;
                assert_eq!(
                    (endpoint, resource.origin().as_deref()),
                    match resource.id {
                        1 => (QcsdEndpointId(1), Some("https://one.example")),
                        2 => (QcsdEndpointId(2), Some("https://two.example")),
                        _ => panic!("unexpected resource"),
                    }
                );
            }
        }
        assert_eq!(request_count, 2);
    }
}
