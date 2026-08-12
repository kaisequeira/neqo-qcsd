// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::HashMap;

use super::ReceiveState;
use crate::{Capacity, DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationOpportunity {
    pub endpoint: QcsdEndpointId,
    pub stream: QcsdStreamId,
    pub role: QcsdRequestRole,
    pub exact: u64,
    pub claimable: u64,
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

    #[cfg(test)]
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

    /// Deterministic per-stream receive opportunities. `Capacity` remains an
    /// exact-only scientific signal; provisional framing allowance is exposed
    /// solely to the private allocator through `claimable`.
    pub fn allocation_opportunities(
        &self,
        endpoint: QcsdEndpointId,
        mode: DefenseMode,
    ) -> Vec<AllocationOpportunity> {
        let mut opportunities: Vec<_> = self
            .streams
            .iter()
            .filter(|((candidate, _), state)| {
                *candidate == endpoint
                    && (mode == DefenseMode::ChaffAndShape
                        || matches!(state.role, QcsdRequestRole::Chaff { .. }))
                    && (state.receive.available() > 0 || state.receive.claimable() > 0)
            })
            .map(|((_, stream), state)| AllocationOpportunity {
                endpoint,
                stream: *stream,
                role: state.role,
                exact: state.receive.available(),
                claimable: state.receive.claimable(),
            })
            .collect();
        opportunities.sort_unstable_by_key(|opportunity| {
            let role_rank = match opportunity.role {
                QcsdRequestRole::Application => 0,
                QcsdRequestRole::Chaff { .. } => 1,
            };
            (role_rank, opportunity.stream)
        });
        opportunities
    }

    pub fn release_stream(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        amount: u64,
    ) -> Option<CreditRelease> {
        let state = self.get_mut(endpoint, stream)?;
        let (absolute_limit, increase) = state.receive.release(amount)?;
        Some(CreditRelease {
            endpoint,
            stream,
            absolute_limit,
            increase,
        })
    }

    pub fn claim_stream(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        amount: u64,
    ) -> u64 {
        self.get_mut(endpoint, stream)
            .map_or(0, |state| state.receive.claim(amount))
    }

    pub fn restore_claim(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId, amount: u64) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state.receive.restore_claim(amount);
        }
    }

    pub fn cancel_release(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        increase: u64,
    ) -> bool {
        self.get_mut(endpoint, stream)
            .is_some_and(|state| state.receive.cancel_release(absolute_limit, increase))
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
        awaiting_data_frame: bool,
    ) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state
                .receive
                .header_progress(min_remaining, awaiting_data_frame);
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
        let opportunity = registry
            .allocation_opportunities(endpoint, DefenseMode::ChaffOnly)
            .into_iter()
            .next()
            .expect("chaff opportunity");
        let release = registry
            .release_stream(endpoint, opportunity.stream, 500)
            .expect("chaff release");
        assert_eq!(release.stream, QcsdStreamId(4));
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
        let opportunity = registry
            .allocation_opportunities(endpoint, DefenseMode::ChaffAndShape)
            .into_iter()
            .next()
            .expect("application opportunity");
        assert_eq!(opportunity.stream, QcsdStreamId(0));
    }

    #[test]
    fn allocation_opportunities_keep_claims_private_and_skip_application_in_chaff_only() {
        let endpoint = QcsdEndpointId(1);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            QcsdStreamId(0),
            QcsdRequestRole::Application,
            true,
            100,
            1_000,
            100,
        );
        registry.open(
            endpoint,
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            100,
            1_000,
            500,
        );

        assert_eq!(
            registry.capacity(endpoint),
            crate::Capacity {
                application_incoming: 0,
                chaff_incoming: 400,
            }
        );
        let shaped = registry.allocation_opportunities(endpoint, DefenseMode::ChaffAndShape);
        assert_eq!(shaped.len(), 2);
        assert!(matches!(shaped[0].role, QcsdRequestRole::Application));
        assert_eq!((shaped[0].exact, shaped[0].claimable), (0, 1_000));

        let chaff_only = registry.allocation_opportunities(endpoint, DefenseMode::ChaffOnly);
        assert_eq!(chaff_only.len(), 1);
        assert!(matches!(chaff_only[0].role, QcsdRequestRole::Chaff { .. }));
    }
}
