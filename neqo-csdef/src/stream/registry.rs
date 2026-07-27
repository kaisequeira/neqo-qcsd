// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::HashMap;

use super::ReceiveState;
use crate::{Capacity, DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

const STREAM_DATA_BLOCKED_INCREMENT: u64 = 100;

#[derive(Clone, Debug)]
pub struct StreamState {
    pub role: QcsdRequestRole,
    pub receive: ReceiveState,
    pub status: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreditRelease {
    pub endpoint: QcsdEndpointId,
    pub stream: QcsdStreamId,
    pub absolute_limit: u64,
    pub increase: u64,
}

#[derive(Debug, Default)]
pub struct StreamRegistry {
    streams: HashMap<(QcsdEndpointId, QcsdStreamId), StreamState>,
}

impl StreamRegistry {
    #[expect(
        clippy::too_many_arguments,
        reason = "stream registration keeps all Figure-7 initialization inputs explicit"
    )]
    pub fn open(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        controlled: bool,
        initial: u64,
        excess: u64,
        expected: u64,
    ) {
        let mut receive = ReceiveState::created(controlled, initial, excess, expected);
        receive.open();
        debug_assert_eq!(receive.is_controlled(), controlled);
        self.streams.insert(
            (endpoint, stream),
            StreamState {
                role,
                receive,
                status: None,
            },
        );
    }

    pub fn get_mut(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<&mut StreamState> {
        self.streams.get_mut(&(endpoint, stream))
    }

    pub fn remove_endpoint(&mut self, endpoint: QcsdEndpointId) {
        self.streams
            .retain(|(candidate, _), _| *candidate != endpoint);
    }

    pub fn close(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<(StreamState, u64, u64)> {
        let mut state = self.streams.remove(&(endpoint, stream))?;
        let (data_length, unadvertised) = state.receive.close();
        Some((state, data_length, unadvertised))
    }

    pub fn capacity(&self, endpoint: QcsdEndpointId) -> Capacity {
        self.streams
            .iter()
            .filter(|((candidate, _), _)| *candidate == endpoint)
            .fold(Capacity::default(), |mut capacity, (_, state)| {
                let available = state.receive.available();
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

    pub fn aggregate_capacity(&self) -> Capacity {
        self.streams
            .values()
            .fold(Capacity::default(), |mut total, state| {
                let available = state.receive.available();
                match state.role {
                    QcsdRequestRole::Application => {
                        total.application_incoming =
                            total.application_incoming.saturating_add(available);
                    }
                    QcsdRequestRole::Chaff { .. } => {
                        total.chaff_incoming = total.chaff_incoming.saturating_add(available);
                    }
                }
                total
            })
    }

    pub fn release(
        &mut self,
        endpoint: QcsdEndpointId,
        amount: u64,
        mode: DefenseMode,
    ) -> Vec<CreditRelease> {
        let mut keys: Vec<_> = self
            .streams
            .iter()
            .filter(|((candidate, _), state)| {
                *candidate == endpoint
                    && state.receive.available() > 0
                    && (mode == DefenseMode::ChaffAndShape
                        || matches!(state.role, QcsdRequestRole::Chaff { .. }))
            })
            .map(|(key, state)| (*key, state.role))
            .collect();
        keys.sort_by_key(|((_, stream), role)| {
            let role_rank = match role {
                QcsdRequestRole::Application => 0,
                QcsdRequestRole::Chaff { .. } => 1,
            };
            (role_rank, *stream)
        });

        let mut remaining = amount;
        let mut releases = Vec::new();
        for ((candidate, stream), _) in keys {
            if remaining == 0 {
                break;
            }
            let state = self
                .streams
                .get_mut(&(candidate, stream))
                .expect("collected registry key");
            if let Some((absolute_limit, increase)) = state.receive.release(remaining) {
                releases.push(CreditRelease {
                    endpoint,
                    stream,
                    absolute_limit,
                    increase,
                });
                remaining -= increase;
            }
        }
        releases
    }

    pub fn open_chaff_count(&self) -> usize {
        self.streams
            .values()
            .filter(|state| matches!(state.role, QcsdRequestRole::Chaff { .. }))
            .count()
    }

    pub fn header_progress(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        min_remaining: u64,
        excess: u64,
    ) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state.receive.header_progress(min_remaining, excess);
        }
    }

    pub fn stream_data_blocked(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        blocked_at: u64,
    ) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state
                .receive
                .stream_data_blocked(blocked_at, STREAM_DATA_BLOCKED_INCREMENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StreamRegistry;
    use crate::{DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

    #[test]
    fn chaff_only_never_releases_application_capacity() {
        let endpoint = QcsdEndpointId(1);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            QcsdStreamId(0),
            QcsdRequestRole::Application,
            true,
            16,
            1_000,
            0,
        );
        registry.open(
            endpoint,
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            0,
        );
        let releases = registry.release(endpoint, 500, DefenseMode::ChaffOnly);
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].stream, QcsdStreamId(4));
    }

    #[test]
    fn shaped_release_prioritizes_application_streams() {
        let endpoint = QcsdEndpointId(1);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            0,
        );
        registry.open(
            endpoint,
            QcsdStreamId(0),
            QcsdRequestRole::Application,
            true,
            16,
            1_000,
            0,
        );
        let releases = registry.release(endpoint, 500, DefenseMode::ChaffAndShape);
        assert_eq!(releases[0].stream, QcsdStreamId(0));
    }
}
