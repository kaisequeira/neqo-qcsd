// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::HashMap;

use super::ReceiveState;
use crate::{Capacity, DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

#[derive(Clone, Debug)]
#[expect(
    clippy::partial_pub_fields,
    reason = "public stream facts coexist with private fail-closed request-ACK evidence"
)]
pub struct StreamState {
    pub role: QcsdRequestRole,
    pub receive: ReceiveState,
    pub status: Option<u16>,
    /// Exact transport proof retained only until HTTP/3 makes response-header
    /// progress or the prepared floor can activate the one bootstrap lease.
    pre_header_blocked_at: Option<u64>,
    request_acknowledged_ranges: Vec<(u64, u64)>,
    request_acknowledged_final_size: Option<u64>,
    request_acknowledgment_invalid: bool,
}

impl StreamState {
    fn record_request_acknowledgment(&mut self, offset: u64, bytes: u64, fin: bool) -> u64 {
        let Some(end) = offset.checked_add(bytes) else {
            self.request_acknowledgment_invalid = true;
            return 0;
        };
        if self
            .request_acknowledged_final_size
            .is_some_and(|final_size| end > final_size)
        {
            self.request_acknowledgment_invalid = true;
            return 0;
        }
        if fin {
            if self
                .request_acknowledged_final_size
                .is_some_and(|final_size| final_size != end)
                || self
                    .request_acknowledged_ranges
                    .last()
                    .is_some_and(|(_, acknowledged_end)| *acknowledged_end > end)
            {
                self.request_acknowledgment_invalid = true;
                return 0;
            }
            self.request_acknowledged_final_size = Some(end);
        }
        if end <= offset {
            return 0;
        }
        let before = covered_range_bytes(&self.request_acknowledged_ranges);
        self.request_acknowledged_ranges.push((offset, end));
        self.request_acknowledged_ranges.sort_unstable();
        merge_ranges(&mut self.request_acknowledged_ranges);
        covered_range_bytes(&self.request_acknowledged_ranges).saturating_sub(before)
    }

    /// Whether the peer acknowledged the complete request-stream range through
    /// its FIN. A response stream is not causally usable before this evidence
    /// is contiguous and internally consistent.
    pub fn chaff_request_activated(&self) -> bool {
        if !matches!(self.role, QcsdRequestRole::Chaff { .. })
            || self.request_acknowledgment_invalid
        {
            return false;
        }
        self.request_acknowledged_final_size
            .is_some_and(|final_size| {
                final_size > 0
                    && self
                        .request_acknowledged_ranges
                        .first()
                        .is_some_and(|(start, end)| *start == 0 && *end == final_size)
            })
    }
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
                pre_header_blocked_at: None,
                request_acknowledged_ranges: Vec::new(),
                request_acknowledged_final_size: None,
                request_acknowledgment_invalid: false,
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

    /// Raw response-stream offset consumed by HTTP/3.
    pub fn consumed(&self, endpoint: QcsdEndpointId, stream: QcsdStreamId) -> Option<u64> {
        self.streams
            .get(&(endpoint, stream))
            .map(|state| state.receive.consumed())
    }

    /// Record unique request-stream bytes only when the transport observation
    /// matches the registered chaff role exactly.
    pub fn record_chaff_request_acknowledgment(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        offset: u64,
        bytes: u64,
        fin: bool,
    ) -> u64 {
        let Some(state) = self.get_mut(endpoint, stream) else {
            return 0;
        };
        if state.role != role || !matches!(role, QcsdRequestRole::Chaff { .. }) {
            return 0;
        }
        state.record_request_acknowledgment(offset, bytes, fin)
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

    /// Ordinary allocation opportunities excluding protected continuation
    /// reserves. Other opportunities preserve the ordinary allocator's
    /// existing semantics; peer acknowledgment is special to continuation
    /// reservation and release.
    pub fn allocation_opportunities_excluding(
        &self,
        endpoint: QcsdEndpointId,
        mode: DefenseMode,
        excluded: &[(QcsdEndpointId, QcsdStreamId)],
        require_peer_acknowledged_chaff: bool,
    ) -> Vec<AllocationOpportunity> {
        self.allocation_opportunities(endpoint, mode)
            .into_iter()
            .filter(|opportunity| {
                !excluded.contains(&(opportunity.endpoint, opportunity.stream))
                    && (!require_peer_acknowledged_chaff
                        || matches!(opportunity.role, QcsdRequestRole::Application)
                        || self
                            .streams
                            .get(&(opportunity.endpoint, opportunity.stream))
                            .is_some_and(StreamState::chaff_request_activated))
            })
            .collect()
    }

    /// Deterministic exact-capacity opportunities for a held receiver
    /// continuation. Only peer-ACK-activated pristine controlled chaff streams
    /// are eligible; provisional framing claims are never exposed to this path.
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
                    && state.chaff_request_activated()
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

    /// Select one deterministic peer-ACK-activated pristine candidate for a future
    /// zero-outstanding continuation. Endpoint order remains controller-owned;
    /// stream order is stable within an endpoint.
    pub fn receiver_continuation_reserve_opportunities(
        &self,
        endpoint: QcsdEndpointId,
        required: u64,
        parser_ceiling: u64,
    ) -> Vec<AllocationOpportunity> {
        self.receiver_continuation_opportunities(endpoint, required, 0, parser_ceiling)
    }

    /// Deterministic peer-acknowledged pristine chaff streams that can carry
    /// one complete final chaff-only incoming slot without fragmentation.
    pub fn pristine_terminal_chaff_opportunities(
        &self,
        endpoint: QcsdEndpointId,
        required: u64,
        initial_limit: u64,
    ) -> Vec<AllocationOpportunity> {
        let mut opportunities: Vec<_> = self
            .streams
            .iter()
            .filter(|((candidate, _), state)| {
                *candidate == endpoint
                    && matches!(state.role, QcsdRequestRole::Chaff { .. })
                    && state.chaff_request_activated()
                    && state.status.is_none()
                    && state
                        .receive
                        .has_pristine_terminal_chaff_capacity(required, initial_limit)
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

    pub fn is_receiver_continuation_reserve(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        required: u64,
        parser_ceiling: u64,
    ) -> bool {
        self.streams.get(&(endpoint, stream)).is_some_and(|state| {
            matches!(state.role, QcsdRequestRole::Chaff { .. })
                && state.chaff_request_activated()
                && state.status.is_none()
                && state
                    .receive
                    .has_receiver_continuation_capacity(required, 0, parser_ceiling)
        })
    }

    /// Whether an exact ordinary base tail on this stream is waiting only for
    /// its local `MAX_STREAM_DATA` advertisement before a continuation can be
    /// coalesced onto it.
    pub fn is_pending_receiver_continuation_tail(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        required: u64,
        base_outstanding: u64,
        unadvertised_base: u64,
        parser_ceiling: u64,
    ) -> bool {
        self.streams.get(&(endpoint, stream)).is_some_and(|state| {
            matches!(state.role, QcsdRequestRole::Chaff { .. })
                && state.chaff_request_activated()
                && state.status.is_none()
                && state.receive.has_pending_receiver_continuation_capacity(
                    required,
                    base_outstanding,
                    unadvertised_base,
                    parser_ceiling,
                )
        })
    }

    pub fn reserved_exact_capacity(&self, reserves: &[(QcsdEndpointId, QcsdStreamId)]) -> u64 {
        reserves.iter().fold(0_u64, |total, key| {
            total.saturating_add(
                self.streams
                    .get(key)
                    .map_or(0, |state| state.receive.available()),
            )
        })
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
            state.pre_header_blocked_at = None;
            state
                .receive
                .header_progress(min_remaining, awaiting_data_frame);
        }
    }

    /// Invalidate transport-only pre-header proof after typed HTTP/3 progress.
    pub(crate) fn clear_pre_header_blocked(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state.pre_header_blocked_at = None;
        }
    }

    /// Record an exact, pristine pre-header `STREAM_DATA_BLOCKED` report.
    pub(crate) fn record_pre_header_blocked(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        blocked_at: u64,
    ) -> bool {
        let Some(state) = self.get_mut(endpoint, stream) else {
            return false;
        };
        if !state.receive.accepts_pre_header_blocked(blocked_at) {
            return false;
        }
        state.pre_header_blocked_at = Some(blocked_at);
        true
    }

    /// Lease the remaining prefix up to the stream's absolute framing ceiling
    /// after its prepared floor and retained blocked proof agree.
    pub(crate) fn pre_header_bootstrap_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        let blocked_at = state.pre_header_blocked_at?;
        let (absolute_limit, increase) = state.receive.pre_header_bootstrap_lease(blocked_at)?;
        state.pre_header_blocked_at = None;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled: false,
        })
    }

    pub fn parser_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        pristine_data_boundary: bool,
        scheduled_backing: u64,
        terminal_advertised_tail: Option<u64>,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        let (absolute_limit, increase, scheduled) = state.receive.parser_lease(
            pristine_data_boundary,
            scheduled_backing,
            terminal_advertised_tail,
        )?;
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
            state.pre_header_blocked_at = None;
            state.receive.clear_parser_boundary();
        }
    }
}

fn covered_range_bytes(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().fold(0_u64, |total, (start, end)| {
        total.saturating_add(end.saturating_sub(*start))
    })
}

fn merge_ranges(ranges: &mut Vec<(u64, u64)>) {
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges.drain(..) {
        if let Some((_, merged_end)) = merged.last_mut()
            && start <= *merged_end
        {
            *merged_end = (*merged_end).max(end);
        } else {
            merged.push((start, end));
        }
    }
    *ranges = merged;
}

#[cfg(test)]
mod tests {
    use super::StreamRegistry;
    use crate::{DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

    #[test]
    fn typed_header_progress_invalidates_retained_pre_header_blocked_proof() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            1_000,
            250,
        );
        assert!(registry.record_pre_header_blocked(endpoint, stream, 16));
        assert_eq!(
            registry
                .release_stream(endpoint, stream, 234)
                .map(|release| release.absolute_limit),
            Some(250)
        );

        // Even progress that does not raise the already prepared body floor
        // supersedes the transport-only proof.
        registry.header_progress(endpoint, stream, 1, false);
        registry
            .get_mut(endpoint, stream)
            .expect("stream")
            .receive
            .advertised(250);
        assert_eq!(registry.pre_header_bootstrap_lease(endpoint, stream), None);
    }

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
    #[expect(
        clippy::too_many_lines,
        reason = "every ineligible continuation stream class is preserved in one registry oracle"
    )]
    fn pristine_chaff_opportunity_skips_application_active_chaff_and_claims() {
        let endpoint = QcsdEndpointId(1);
        let mut registry = StreamRegistry::default();
        let active_role = QcsdRequestRole::Chaff {
            resource_id: 7,
            request_id: None,
        };
        let pristine_role = QcsdRequestRole::Chaff {
            resource_id: 8,
            request_id: None,
        };
        let claimed_role = QcsdRequestRole::Chaff {
            resource_id: 9,
            request_id: None,
        };
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
            active_role,
            true,
            0,
            1_000,
            13_527,
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(20),
                active_role,
                0,
                123,
                true,
            ),
            123
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
            pristine_role,
            true,
            0,
            1_000,
            13_390,
        );
        registry.open(
            endpoint,
            QcsdStreamId(28),
            claimed_role,
            true,
            0,
            1_000,
            13_390,
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(28),
                claimed_role,
                0,
                100,
                true,
            ),
            100
        );
        assert_eq!(registry.claim_stream(endpoint, QcsdStreamId(28), 1), 1);

        // Merely opening a response stream is not evidence that its request
        // was peer-acknowledged. A mismatched role is fail-closed too.
        assert!(
            registry
                .receiver_continuation_opportunities(endpoint, 1_200, 0, 1_000)
                .is_empty()
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(24),
                active_role,
                0,
                100,
                true,
            ),
            0
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(24),
                pristine_role,
                0,
                100,
                false,
            ),
            100
        );
        assert!(
            registry
                .receiver_continuation_opportunities(endpoint, 1_200, 0, 1_000)
                .is_empty()
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(24),
                pristine_role,
                100,
                0,
                true,
            ),
            0
        );
        // Retransmitted overlap contributes no new request bytes but the
        // original peer-ACK activation remains valid.
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(24),
                pristine_role,
                25,
                50,
                false,
            ),
            0
        );
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

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "gap, FIN, conflict, overflow, and zero-size activation cases remain explicit"
    )]
    fn request_acknowledgment_activation_is_gap_free_positive_and_fail_closed() {
        let endpoint = QcsdEndpointId(1);
        let mut registry = StreamRegistry::default();
        for stream in [32_u64, 36, 40, 44] {
            registry.open(
                endpoint,
                QcsdStreamId(stream),
                QcsdRequestRole::Chaff {
                    resource_id: u32::try_from(stream).expect("small test id"),
                    request_id: None,
                },
                true,
                0,
                1_000,
                2_400,
            );
        }

        let role = |resource_id| QcsdRequestRole::Chaff {
            resource_id,
            request_id: None,
        };

        // FIN can arrive before an earlier ACK range; only the completed union
        // activates the response stream.
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(32),
                role(32),
                100,
                100,
                true,
            ),
            100
        );
        assert!(
            !registry
                .get_mut(endpoint, QcsdStreamId(32))
                .expect("gap stream")
                .chaff_request_activated()
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(32),
                role(32),
                0,
                100,
                false,
            ),
            100
        );
        assert!(
            registry
                .get_mut(endpoint, QcsdStreamId(32))
                .expect("completed stream")
                .chaff_request_activated()
        );

        // Conflicting final sizes permanently invalidate otherwise complete
        // evidence instead of replacing the first final size.
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(36),
                role(36),
                0,
                100,
                true,
            ),
            100
        );
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(36),
                role(36),
                0,
                101,
                true,
            ),
            0
        );
        assert!(
            !registry
                .get_mut(endpoint, QcsdStreamId(36))
                .expect("conflicting FIN stream")
                .chaff_request_activated()
        );

        // Offset overflow is invalid evidence even if a later valid-looking
        // complete range arrives.
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(40),
                role(40),
                u64::MAX,
                1,
                false,
            ),
            0
        );
        _ = registry.record_chaff_request_acknowledgment(
            endpoint,
            QcsdStreamId(40),
            role(40),
            0,
            100,
            true,
        );
        assert!(
            !registry
                .get_mut(endpoint, QcsdStreamId(40))
                .expect("overflow stream")
                .chaff_request_activated()
        );

        // A zero-byte FIN is observable transport evidence, but it cannot be
        // an HTTP/3 request capable of causing a response.
        assert_eq!(
            registry.record_chaff_request_acknowledgment(
                endpoint,
                QcsdStreamId(44),
                role(44),
                0,
                0,
                true,
            ),
            0
        );
        assert!(
            !registry
                .get_mut(endpoint, QcsdStreamId(44))
                .expect("empty FIN stream")
                .chaff_request_activated()
        );
    }

    #[test]
    fn pending_receiver_tail_requires_exact_acked_unadvertised_base_delta() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let role = QcsdRequestRole::Chaff {
            resource_id: 7,
            request_id: None,
        };
        let mut registry = StreamRegistry::default();
        registry.open(endpoint, stream, role, true, 0, 1_000, 2_400);
        assert_eq!(
            registry.record_chaff_request_acknowledgment(endpoint, stream, role, 0, 100, true),
            100
        );
        let base = registry
            .release_stream(endpoint, stream, 324)
            .expect("small exact base tail");
        assert!(
            registry
                .is_pending_receiver_continuation_tail(endpoint, stream, 1_200, 324, 324, 1_000,)
        );
        assert!(
            !registry
                .is_pending_receiver_continuation_tail(endpoint, stream, 1_200, 324, 323, 1_000,)
        );

        registry
            .get_mut(endpoint, stream)
            .expect("registered chaff")
            .receive
            .advertised(base.absolute_limit);
        assert!(
            !registry
                .is_pending_receiver_continuation_tail(endpoint, stream, 1_200, 324, 324, 1_000,)
        );
        let ready = registry.receiver_continuation_opportunities(endpoint, 1_200, 324, 1_000);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].stream, stream);
    }

    #[test]
    fn terminal_chaff_opportunity_requires_ack_pristine_state_and_whole_capacity() {
        let endpoint = QcsdEndpointId(1);
        let role = QcsdRequestRole::Chaff {
            resource_id: 7,
            request_id: None,
        };
        let mut registry = StreamRegistry::default();
        for (stream, expected) in [(4, 38_376), (8, 38_376), (12, 1_215)] {
            registry.open(
                endpoint,
                QcsdStreamId(stream),
                role,
                true,
                16,
                1_000,
                expected,
            );
        }
        for stream in [4, 12] {
            assert_eq!(
                registry.record_chaff_request_acknowledgment(
                    endpoint,
                    QcsdStreamId(stream),
                    role,
                    0,
                    110,
                    true,
                ),
                110
            );
        }

        let eligible = registry.pristine_terminal_chaff_opportunities(endpoint, 1_200, 16);
        assert_eq!(
            eligible
                .iter()
                .map(|opportunity| opportunity.stream)
                .collect::<Vec<_>>(),
            [QcsdStreamId(4)],
            "stream 8 is unacknowledged and stream 12 lacks a whole slot"
        );

        let release = registry
            .release_stream(endpoint, QcsdStreamId(4), 1)
            .expect("touch pristine state");
        registry
            .get_mut(endpoint, QcsdStreamId(4))
            .expect("registered stream")
            .receive
            .advertised(release.absolute_limit);
        assert!(
            registry
                .pristine_terminal_chaff_opportunities(endpoint, 1_200, 16)
                .is_empty(),
            "previously advertised credit is not an untouched initial prefix"
        );
    }

    #[test]
    fn ordinary_allocation_keeps_unacknowledged_nonreserved_chaff() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            stream,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            0,
            1_000,
            2_400,
        );

        let opportunities = registry.allocation_opportunities_excluding(
            endpoint,
            DefenseMode::ChaffOnly,
            &[],
            false,
        );
        assert_eq!(opportunities.len(), 1);
        assert_eq!(opportunities[0].stream, stream);
        assert_eq!(opportunities[0].exact, 2_400);
        assert!(
            registry
                .allocation_opportunities_excluding(endpoint, DefenseMode::ChaffOnly, &[], true,)
                .is_empty(),
            "Walkie-Talkie may not stage base credit on unacknowledged chaff"
        );
    }
}
