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
pub struct ParserLease {
    pub endpoint: QcsdEndpointId,
    pub stream: QcsdStreamId,
    pub absolute_limit: u64,
    pub increase: u64,
    pub scheduled: bool,
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

    /// Deterministic exact-capacity opportunities for a held receiver
    /// continuation. Only pristine controlled chaff streams are eligible;
    /// provisional framing claims are never exposed to this path.
    pub fn receiver_continuation_opportunities(
        &self,
        endpoint: QcsdEndpointId,
        required: u64,
        base_outstanding: u64,
        parser_ceiling: u64,
    ) -> Vec<AllocationOpportunity> {
        let mut opportunities: Vec<_> = self
            .streams
            .iter()
            .filter(|((candidate, _), state)| {
                *candidate == endpoint
                    && matches!(state.role, QcsdRequestRole::Chaff { .. })
                    && state.status.is_none()
                    && state.receive.has_receiver_continuation_capacity(
                        required,
                        base_outstanding,
                        parser_ceiling,
                    )
            })
            .map(|((_, stream), state)| AllocationOpportunity {
                endpoint,
                stream: *stream,
                role: state.role,
                exact: state.receive.available(),
                claimable: 0,
            })
            .collect();
        opportunities.sort_unstable_by_key(|opportunity| opportunity.stream);
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

    pub fn cancel_parser_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        increase: u64,
        unowned: bool,
    ) -> bool {
        self.get_mut(endpoint, stream).is_some_and(|state| {
            state
                .receive
                .cancel_parser_lease(absolute_limit, increase, unowned)
        })
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

    pub fn parser_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        pristine_data_boundary: bool,
        scheduled_backing: u64,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        let (absolute_limit, increase, scheduled) = state
            .receive
            .parser_lease(pristine_data_boundary, scheduled_backing)?;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled,
        })
    }

    pub fn schedule_parser_lease_bytes(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        amount: u64,
        recycle_unowned: bool,
    ) -> u64 {
        self.get_mut(endpoint, stream).map_or(0, |state| {
            state
                .receive
                .schedule_parser_lease_bytes(amount, recycle_unowned)
        })
    }

    pub fn has_pending_parser_boundary(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> bool {
        self.streams
            .get(&(endpoint, stream))
            .is_some_and(|state| state.receive.has_pending_parser_boundary())
    }

    pub fn pending_parser_boundaries(&self) -> Vec<(QcsdEndpointId, QcsdStreamId)> {
        let mut pending: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(key, state)| state.receive.has_pending_parser_boundary().then_some(*key))
            .collect();
        pending.sort_unstable();
        pending
    }

    pub fn clear_parser_boundaries(&mut self) {
        #[expect(
            clippy::iter_over_hash_type,
            reason = "clearing every independent stream boundary is order-insensitive"
        )]
        for state in self.streams.values_mut() {
            state.receive.clear_parser_boundary();
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

    #[test]
    fn pristine_chaff_opportunity_skips_application_active_chaff_and_claims() {
        let endpoint = QcsdEndpointId(1);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            QcsdStreamId(0),
            QcsdRequestRole::Application,
            true,
            0,
            1_000,
            20_000,
        );
        registry.open(
            endpoint,
            QcsdStreamId(20),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            0,
            1_000,
            13_527,
        );
        let active = registry
            .release_stream(endpoint, QcsdStreamId(20), 3_093)
            .expect("activate first chaff stream");
        let active_state = registry
            .get_mut(endpoint, QcsdStreamId(20))
            .expect("active chaff state");
        active_state.receive.advertised(active.absolute_limit);
        active_state.receive.bytes_read(3_093);

        registry.open(
            endpoint,
            QcsdStreamId(24),
            QcsdRequestRole::Chaff {
                resource_id: 8,
                request_id: None,
            },
            true,
            0,
            1_000,
            13_390,
        );
        registry.open(
            endpoint,
            QcsdStreamId(28),
            QcsdRequestRole::Chaff {
                resource_id: 9,
                request_id: None,
            },
            true,
            0,
            1_000,
            13_390,
        );
        assert_eq!(registry.claim_stream(endpoint, QcsdStreamId(28), 1), 1);

        let opportunities = registry.receiver_continuation_opportunities(endpoint, 1_200, 0, 1_000);
        assert_eq!(opportunities.len(), 1);
        assert_eq!(opportunities[0].stream, QcsdStreamId(24));
        assert_eq!(opportunities[0].exact, 13_390);
        assert_eq!(opportunities[0].claimable, 0);

        let continuation = registry
            .release_stream(endpoint, opportunities[0].stream, 1_200)
            .expect("whole continuation release");
        assert_eq!(continuation.absolute_limit, 1_200);
        assert_eq!(continuation.increase, 1_200);
    }
}
