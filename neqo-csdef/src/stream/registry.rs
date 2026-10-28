// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::HashMap;

use super::ReceiveState;
use crate::{Capacity, DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedResponseLength {
    Unobserved,
    Final {
        status: u16,
        content_length: Option<u64>,
    },
    Conflicting,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::partial_pub_fields,
    reason = "public stream facts coexist with private fail-closed request-ACK evidence"
)]
pub struct StreamState {
    pub role: QcsdRequestRole,
    pub receive: ReceiveState,
    pub status: Option<u16>,
    /// Whether the adapter can still accept new receive-limit actions.
    receive_actions_available: bool,
    /// Exact transport proof retained only until HTTP/3 makes response-header
    /// progress or an exact prepared/scheduled prefix can activate the one
    /// bootstrap lease.
    pre_header_blocked_at: Option<u64>,
    /// Actual post-header peer demand at one exact advertised frontier. The
    /// receive state rechecks this frontier at allocation and lease grant.
    parser_blocked_at: Option<u64>,
    /// One genuine pre-body frame-reader debt at its exact raw frontier.
    /// Retaining debt grants nothing before the issued request's FIN ACK.
    aggregate_framing_debt: Option<(u64, u64, bool)>,
    /// Actual final HEADERS evidence, distinct from a prepared body estimate.
    observed_response_length: ObservedResponseLength,
    /// Original prepared response extent, never replaced by live HEADERS.
    expected_chaff_body_bytes: u64,
    request_acknowledged_ranges: Vec<(u64, u64)>,
    request_acknowledged_final_size: Option<u64>,
    request_acknowledgment_invalid: bool,
}

impl StreamState {
    pub(crate) fn response_headers(
        &mut self,
        frame_bytes: u64,
        status: Option<u16>,
        content_length: Option<u64>,
    ) {
        if let Some(status) = status {
            self.status = Some(status);
            if status >= 200 {
                let observed = ObservedResponseLength::Final {
                    status,
                    content_length,
                };
                self.observed_response_length = match self.observed_response_length {
                    ObservedResponseLength::Unobserved => observed,
                    previous if previous == observed => previous,
                    _ => ObservedResponseLength::Conflicting,
                };
            } else if self.observed_response_length != ObservedResponseLength::Unobserved {
                self.observed_response_length = ObservedResponseLength::Conflicting;
            }
        }
        // A status-less trailer cannot establish or replace final HEADERS.
        self.receive.response_headers(frame_bytes, content_length);
    }

    fn application_response_content_length(&self) -> Option<u64> {
        if self.role != QcsdRequestRole::Application || !self.receive_actions_available {
            return None;
        }
        match self.observed_response_length {
            ObservedResponseLength::Final {
                status,
                content_length,
            } if self.status == Some(status)
                && (200..300).contains(&status)
                && !matches!(status, 204 | 205) =>
            {
                content_length
            }
            _ => None,
        }
    }

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

    /// The application request is causally available only after the same
    /// exact, positive contiguous request-range and FIN proof used for chaff.
    /// This evidence does not activate a chaff resource or incoming startup.
    fn application_request_activated(&self) -> bool {
        if self.role != QcsdRequestRole::Application || self.request_acknowledgment_invalid {
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

    /// Positive final request size after the same contiguous ACK/FIN check.
    pub fn activated_chaff_request_final_size(&self) -> Option<u64> {
        self.chaff_request_activated()
            .then_some(self.request_acknowledged_final_size)
            .flatten()
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
    /// Prospective controller-only capability; default false, no runner opt-in.
    cs_live_chaff_headers: bool,
}

impl StreamRegistry {
    pub(crate) fn enable_cs_live_chaff_headers(&mut self) -> bool {
        if self.cs_live_chaff_headers || !self.streams.is_empty() {
            return false;
        }
        self.cs_live_chaff_headers = true;
        true
    }

    pub(crate) const fn cs_live_chaff_headers_enabled(&self) -> bool {
        self.cs_live_chaff_headers
    }

    /// A saved estimate alone cannot fund a current chaff response. This
    /// capability requires actual, consistent 200 HEADERS with the unchanged
    /// prepared extent and an exact live request FIN ACK. Applications retain
    /// their original allocation behavior; full body validation stays external.
    fn scheduled_capacity_available(&self, state: &StreamState) -> bool {
        if !self.cs_live_chaff_headers || state.role == QcsdRequestRole::Application {
            return true;
        }
        state.activated_chaff_request_final_size().is_some()
            && state.expected_chaff_body_bytes > 0
            && matches!(state.observed_response_length,
                ObservedResponseLength::Final { status: 200, content_length: Some(length) }
                    if length == state.expected_chaff_body_bytes)
            && state.status == Some(200)
    }

    fn cs_live_chaff_without_length(&self, state: &StreamState) -> bool {
        self.cs_live_chaff_headers
            && state.receive_actions_available
            && matches!(state.role, QcsdRequestRole::Chaff { request_id: Some(_), .. })
            && state.activated_chaff_request_final_size().is_some()
            && state.expected_chaff_body_bytes > 0
            && state.status == Some(200)
            && matches!(state.observed_response_length,
                ObservedResponseLength::Final { status: 200, content_length: None })
            && !matches!(&state.receive, ReceiveState::ReceivingData { data_length, .. }
                if *data_length > state.expected_chaff_body_bytes)
    }

    fn scheduled_exact_capacity(&self, state: &StreamState) -> u64 {
        if self.scheduled_capacity_available(state) {
            state.receive.available()
        } else if self.cs_live_chaff_without_length(state) {
            state.receive.observed_data_available()
        } else {
            0
        }
    }

    /// Private allocator candidates only; these expose no forecast Capacity.
    pub(crate) fn cs_live_chaff_owned_data_opportunities(
        &self,
        endpoint: QcsdEndpointId,
    ) -> Vec<AllocationOpportunity> {
        let mut result: Vec<_> = self.streams.iter().filter_map(|((candidate, stream), state)| {
            (*candidate == endpoint
                && self.cs_live_chaff_owned_data_capacity(endpoint, *stream, 600) > 0)
                .then_some(AllocationOpportunity {
                    endpoint,
                    stream: *stream,
                    role: state.role,
                    exact: 0,
                    claimable: 0,
                })
        }).collect();
        result.sort_unstable_by_key(|opportunity| opportunity.stream);
        result
    }

    pub(crate) fn cs_live_chaff_owned_data_capacity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        remaining: u64,
    ) -> u64 {
        if remaining == 0 || remaining > 600 {
            return 0;
        }
        self.streams.get(&(endpoint, stream)).map_or(0, |state| {
            if self.cs_live_chaff_without_length(state) {
                let ReceiveState::ReceivingData { data_length, .. } = &state.receive else {
                    return 0;
                };
                // The prepared body extent is only a negative ceiling on this
                // private, due-cell-owned permission. It never supplies exact
                // Capacity: only a decoded DATA frame can do that. A short
                // final body leaves the rest of the same cell for other streams.
                let body_remaining = state.expected_chaff_body_bytes.saturating_sub(*data_length);
                state.receive.cs_owned_chaff_data_capacity(remaining.min(body_remaining))
            } else {
                0
            }
        })
    }

    pub(crate) fn cs_live_chaff_owned_data_continuation(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        remaining: u64,
    ) -> Option<ParserLease> {
        if self.cs_live_chaff_owned_data_capacity(endpoint, stream, remaining) != remaining
            || remaining == 0
        {
            return None;
        }
        let (absolute_limit, increase, scheduled) = self.get_mut(endpoint, stream)?
            .receive.cs_owned_chaff_data_continuation(remaining)?;
        Some(ParserLease { endpoint, stream, absolute_limit, increase, scheduled })
    }


    /// Append the original final parser allowance after an already owned short
    /// DATA prefix. The prepared extent only narrows this framing case; it
    /// supplies neither exact receive Capacity nor another scheduled owner.
    pub(crate) fn cs_live_chaff_owned_tail_framing_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        owned_tail: (u64, u64),
    ) -> Option<ParserLease> {
        const HEADER_PREFIX: u64 = 16;
        let state = self.streams.get(&(endpoint, stream))?;
        if !self.cs_live_chaff_without_length(state) {
            return None;
        }
        let expected = state.expected_chaff_body_bytes;
        let ReceiveState::ReceivingData {
            advertised_limit, requested_limit, known_limit, consumed,
            framing_bytes, data_length, parser_lease_capacity, parser_lease_used,
            parser_lease_exhausted, last_parser_lease_boundary,
            pending_parser_boundary, ..
        } = &mut self.get_mut(endpoint, stream)?.receive else {
            return None;
        };
        let tail = requested_limit.checked_sub(*consumed)?;
        let body_remaining = expected.checked_sub(*data_length)?;
        let allowance = parser_lease_capacity.checked_sub(*parser_lease_used)?;
        if owned_tail != (*consumed, *requested_limit)
            || !(1..=HEADER_PREFIX).contains(&tail)
            || body_remaining != tail
            || *advertised_limit != *requested_limit
            || *known_limit > *requested_limit
            || framing_bytes.checked_add(*data_length) != Some(*consumed)
            || *last_parser_lease_boundary != Some(*consumed)
            || pending_parser_boundary.is_some()
            || *parser_lease_exhausted
            || allowance != HEADER_PREFIX
        {
            return None;
        }
        let absolute_limit = requested_limit.checked_add(HEADER_PREFIX)?;
        *parser_lease_used = parser_lease_used.checked_add(HEADER_PREFIX)?;
        *parser_lease_exhausted = *parser_lease_used == *parser_lease_capacity;
        *requested_limit = absolute_limit;
        // Keep the recorded boundary and the old owner's raw offsets. The
        // exhausted original allowance prevents another lease at this point.
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase: HEADER_PREFIX,
            scheduled: false,
        })
    }

    /// Finish only a current pre-HEADERS debt. The existing aggregate wrapper
    /// authenticates exact role, FIN ACK, retained offset and lifetime budget;
    /// its receive-state leaf is unchanged. No DATA/body forecast is leased.
    pub(crate) fn cs_live_chaff_header_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        min_remaining: u64,
        prepared_body_bytes: u64,
    ) -> Option<ParserLease> {
        if !self.cs_live_chaff_headers {
            return None;
        }
        let state = self.streams.get(&(endpoint, stream))?;
        let QcsdRequestRole::Chaff { resource_id, request_id: Some(_) } = state.role else {
            return None;
        };
        if state.observed_response_length != ObservedResponseLength::Unobserved
            || state.status.is_some()
            || state.expected_chaff_body_bytes == 0
            || state.expected_chaff_body_bytes != prepared_body_bytes
        {
            return None;
        }
        let expected = state.expected_chaff_body_bytes;
        self.aggregate_prebody_framing_lease(
            endpoint, stream, resource_id, expected, min_remaining, false,
        )
    }

    /// Break only the pristine CS HEADERS bootstrap cycle. A qualified
    /// estimate and complete live request ACK authorize a bounded raw prefix;
    /// scheduled capacity remains unavailable until actual matching 200 HEADERS.
    pub(crate) fn cs_live_chaff_header_bootstrap_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        prepared_body_bytes: u64,
    ) -> Option<ParserLease> {
        if !self.cs_live_chaff_headers {
            return None;
        }
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available
            || !matches!(state.role, QcsdRequestRole::Chaff { request_id: Some(_), .. })
            || state.activated_chaff_request_final_size().is_none()
            || state.observed_response_length != ObservedResponseLength::Unobserved
            || state.status.is_some()
            || state.expected_chaff_body_bytes == 0
            || state.expected_chaff_body_bytes != prepared_body_bytes
            || state.aggregate_framing_debt.is_some()
        {
            return None;
        }
        let blocked_at = state.pre_header_blocked_at?;
        let (absolute_limit, increase) = state.receive
            .cs_pristine_chaff_header_bootstrap_lease(blocked_at)?;
        state.pre_header_blocked_at = None;
        Some(ParserLease { endpoint, stream, absolute_limit, increase, scheduled: false })
    }

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
                receive_actions_available: true,
                pre_header_blocked_at: None,
                parser_blocked_at: None,
                aggregate_framing_debt: None,
                observed_response_length: ObservedResponseLength::Unobserved,
                expected_chaff_body_bytes: expected,
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

    /// Same live response-qualified chaff request used by the allocator.
    pub(crate) fn is_activated_chaff_stream(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> bool {
        self.streams
            .get(&(endpoint, stream))
            .is_some_and(StreamState::chaff_request_activated)
    }

    /// Whether the exact live request stream belongs to the application.
    pub fn is_application_stream(&self, endpoint: QcsdEndpointId, stream: QcsdStreamId) -> bool {
        self.streams
            .get(&(endpoint, stream))
            .is_some_and(|state| state.role == QcsdRequestRole::Application)
    }

    /// Raw response-stream offset consumed by HTTP/3.
    pub fn consumed(&self, endpoint: QcsdEndpointId, stream: QcsdStreamId) -> Option<u64> {
        self.streams
            .get(&(endpoint, stream))
            .map(|state| state.receive.consumed())
    }

    /// Prevent future receive allocation while retaining the stream's
    /// advertised ownership and byte-consumption state until normal terminal
    /// observations arrive.
    pub fn mark_receive_unavailable(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> bool {
        let Some(state) = self.streams.get_mut(&(endpoint, stream)) else {
            return false;
        };
        state.receive_actions_available = false;
        state.aggregate_framing_debt = None;
        state.pre_header_blocked_at = None;
        state.parser_blocked_at = None;
        state.receive.clear_parser_boundary();
        true
    }

    pub fn receive_actions_available(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> bool {
        self.streams
            .get(&(endpoint, stream))
            .is_some_and(|state| state.receive_actions_available)
    }

    pub fn receive_limits(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<(u64, u64)> {
        self.streams
            .get(&(endpoint, stream))
            .and_then(|state| state.receive.limits())
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

    /// Retain genuine ACK evidence for only this exact live application
    /// stream. Reuse the fail-closed range/FIN ledger without treating the
    /// application as a chaff request or a peer-blocked observation.
    pub(crate) fn record_application_request_acknowledgment(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        offset: u64,
        bytes: u64,
        fin: bool,
    ) -> bool {
        let Some(state) = self.get_mut(endpoint, stream) else {
            return false;
        };
        if role != QcsdRequestRole::Application
            || state.role != role
            || !state.receive_actions_available
        {
            return false;
        }
        _ = state.record_request_acknowledgment(offset, bytes, fin);
        state.application_request_activated()
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
            .filter(|((candidate, _), state)| {
                *candidate == endpoint
                    && state.receive_actions_available
            })
            .fold(Capacity::default(), |mut capacity, (_, state)| {
                let available = self.scheduled_exact_capacity(state);
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

    pub(crate) fn scheduled_prefix_drain_is_stable(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> bool {
        self.streams.get(&(endpoint, stream)).is_some_and(|state| {
            state.receive_actions_available && state.receive.scheduled_prefix_drain_is_stable()
        })
    }

    pub fn aggregate_capacity(&self) -> Capacity {
        self.streams
            .values()
            .filter(|state| state.receive_actions_available)
            .fold(Capacity::default(), |mut total, state| {
                let available = self.scheduled_exact_capacity(state);
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
                    && state.receive_actions_available
                    && (mode == DefenseMode::ChaffAndShape
                        || matches!(state.role, QcsdRequestRole::Chaff { .. }))
                    && (self.scheduled_exact_capacity(state) > 0
                        || (self.scheduled_capacity_available(state)
                            && state.receive.claimable() > 0))
            })
            .map(|((_, stream), state)| AllocationOpportunity {
                endpoint,
                stream: *stream,
                role: state.role,
                exact: self.scheduled_exact_capacity(state),
                claimable: if self.scheduled_capacity_available(state) {
                    state.receive.claimable()
                } else {
                    0
                },
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

    /// One explicitly bound primary can expose an owned DATA opportunity even
    /// when its independent unowned framing reservation is exhausted. This
    /// does not change the ordinary opportunity list or exact Capacity signal.
    pub(crate) fn owned_data_continuation_opportunity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        due_quantum: u64,
    ) -> Option<AllocationOpportunity> {
        if self.owned_data_continuation_capacity(endpoint, stream, due_quantum) == 0 {
            return None;
        }
        Some(AllocationOpportunity {
            endpoint,
            stream,
            role: QcsdRequestRole::Application,
            exact: 0,
            claimable: 0,
        })
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
                    && state.receive_actions_available
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
                    && state.receive_actions_available
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
            state.receive_actions_available
                && matches!(state.role, QcsdRequestRole::Chaff { .. })
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
            state.receive_actions_available
                && matches!(state.role, QcsdRequestRole::Chaff { .. })
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
                    .filter(|state| state.receive_actions_available)
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
        let state = self.streams.get(&(endpoint, stream))?;
        let ordinary = self.scheduled_capacity_available(state);
        if !ordinary && !self.cs_live_chaff_without_length(state) {
            return None;
        }
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available {
            return None;
        }
        let (absolute_limit, increase) = if ordinary {
            state.receive.release(amount)?
        } else {
            state.receive.release_observed_data(amount)?
        };
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
        if self.streams.get(&(endpoint, stream)).is_none_or(|state| {
            !self.scheduled_capacity_available(state)
        }) {
            return 0;
        }
        self.get_mut(endpoint, stream).map_or(0, |state| {
            if state.receive_actions_available {
                state.receive.claim(amount)
            } else {
                0
            }
        })
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

    pub fn open_chaff_streams(&self) -> Vec<(QcsdEndpointId, QcsdStreamId)> {
        let mut streams: Vec<_> = self
            .streams
            .iter()
            .filter_map(|((endpoint, stream), state)| {
                matches!(state.role, QcsdRequestRole::Chaff { .. }).then_some((*endpoint, *stream))
            })
            .collect();
        streams.sort_unstable();
        streams
    }

    /// Atomically transfer every live application response to ordinary Neqo
    /// receive-window management. A stream with an unadvertised suffix blocks
    /// the complete batch, so a partial handoff can never occur.
    pub fn handoff_application_receive_to_automatic(
        &mut self,
    ) -> Result<Vec<(QcsdEndpointId, QcsdStreamId)>, (QcsdEndpointId, QcsdStreamId)> {
        let mut streams: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(key, state)| {
                (state.role == QcsdRequestRole::Application
                    && state.receive_actions_available
                    && state.receive.is_controlled())
                .then_some(*key)
            })
            .collect();
        streams.sort_unstable();
        if let Some(key) = streams.iter().copied().find(|key| {
            !self
                .streams
                .get(key)
                .is_some_and(|state| state.receive.can_handoff_to_automatic())
        }) {
            return Err(key);
        }
        for key in &streams {
            let state = self.streams.get_mut(key).ok_or(*key)?;
            state.pre_header_blocked_at = None;
            state.parser_blocked_at = None;
            if !state.receive.handoff_to_automatic() {
                return Err(*key);
            }
        }
        Ok(streams)
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

    pub(crate) fn retain_aggregate_framing_debt(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        min_remaining: u64,
        pristine_data_boundary: bool,
    ) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state.aggregate_framing_debt = (state.receive_actions_available
                && min_remaining > 0
                && matches!(state.receive, ReceiveState::ReceivingHeaders { .. }))
            .then_some((
                state.receive.consumed(),
                min_remaining,
                pristine_data_boundary,
            ));
        }
    }

    pub(crate) fn aggregate_framing_debts(&self) -> Vec<(QcsdEndpointId, QcsdStreamId, u64, bool)> {
        let mut debts: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(&(endpoint, stream), state)| {
                let (boundary, debt, pristine) = state.aggregate_framing_debt?;
                (state.receive_actions_available
                    && state.receive.consumed() == boundary
                    && matches!(state.receive, ReceiveState::ReceivingHeaders { .. }))
                .then_some((endpoint, stream, debt, pristine))
            })
            .collect();
        debts.sort_unstable();
        debts
    }

    /// Invalidate transport-only pre-header proof after typed HTTP/3 progress.
    pub(crate) fn clear_pre_header_blocked(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) {
        if let Some(state) = self.get_mut(endpoint, stream) {
            state.pre_header_blocked_at = None;
            state.aggregate_framing_debt = None;
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
        if !state.receive_actions_available {
            return false;
        }
        if !state.receive.accepts_pre_header_blocked(blocked_at) {
            return false;
        }
        state.pre_header_blocked_at = Some(blocked_at);
        true
    }

    /// Retain a real `STREAM_DATA_BLOCKED` observation for a live DATA stream.
    /// Bytes below the same limit may subsequently be parsed; the report still
    /// proves peer demand beyond that limit. A changed limit cannot reuse it.
    pub(crate) fn record_parser_blocked(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        blocked_at: u64,
    ) -> bool {
        let Some(state) = self.get_mut(endpoint, stream) else {
            return false;
        };
        if !state.receive_actions_available || !state.receive.accepts_parser_blocked(blocked_at) {
            return false;
        }
        state.parser_blocked_at = Some(blocked_at);
        true
    }

    /// Reserve solely against a real due cell, independently of the bounded
    /// legacy framing allowance. Only application DATA may use this route.
    pub(crate) fn owned_data_continuation_capacity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        due_quantum: u64,
    ) -> u64 {
        self.streams.get(&(endpoint, stream)).map_or(0, |state| {
            if !state.receive_actions_available || state.role != QcsdRequestRole::Application {
                return 0;
            }
            state
                .receive
                .owned_data_continuation_capacity(state.parser_blocked_at, due_quantum)
        })
    }

    pub(crate) fn owned_data_continuation(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        due_quantum: u64,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available || state.role != QcsdRequestRole::Application {
            return None;
        }
        let (absolute_limit, increase, scheduled) = state
            .receive
            .owned_data_continuation(state.parser_blocked_at, due_quantum)?;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled,
        })
    }

    /// Fresh scheduled parser bytes are limited to decoded unknown-length
    /// successful applications. Chaff and all existing mode APIs are unchanged.
    pub(crate) fn buflo_fresh_parser_bridge_capacity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        owned_suffix: Option<(u64, u64)>,
    ) -> u64 {
        let Some(state) = self.streams.get(&(endpoint, stream)) else {
            return 0;
        };
        if !state.receive_actions_available
            || state.role != QcsdRequestRole::Application
            || !matches!(state.observed_response_length,
                ObservedResponseLength::Final { status, content_length: None }
                if state.status == Some(status) && (200..300).contains(&status)
                    && !matches!(status, 204 | 205))
        {
            return 0;
        }
        state
            .receive
            .buflo_fresh_parser_bridge_capacity(state.parser_blocked_at, owned_suffix)
    }

    pub(crate) fn claim_buflo_fresh_parser_bridge(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        amount: u64,
        owned_suffix: Option<(u64, u64)>,
    ) -> u64 {
        if self.buflo_fresh_parser_bridge_capacity(endpoint, stream, owned_suffix) == 0 {
            return 0;
        }
        let Some(state) = self.get_mut(endpoint, stream) else {
            return 0;
        };
        state
            .receive
            .claim_buflo_fresh_parser_bridge(amount, state.parser_blocked_at, owned_suffix)
    }

    pub(crate) fn lease_buflo_fresh_parser_bridge(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        pristine_data_boundary: bool,
        scheduled_backing: u64,
        owned_suffix: Option<(u64, u64)>,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available
            || state.role != QcsdRequestRole::Application
            || !matches!(state.observed_response_length,
                ObservedResponseLength::Final { status, content_length: None }
                if state.status == Some(status) && (200..300).contains(&status)
                    && !matches!(status, 204 | 205))
        {
            return None;
        }
        let (absolute_limit, increase, scheduled) = state.receive.lease_buflo_fresh_parser_bridge(
            pristine_data_boundary,
            scheduled_backing,
            state.parser_blocked_at,
            owned_suffix,
        )?;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled,
        })
    }

    /// FIN permission release belongs only to the same decoded successful
    /// unknown-length application response as retained parser service.
    /// Actual drained DATA-end of an ACK-activated, known-length chaff response.
    /// The controller separately joins its qualified identity and owned suffix.
    /// This proves exact existing capacity, never new parser or FIN permission.
    pub(crate) fn buflo_known_chaff_data_end(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<(u32, u64, u64, u64)> {
        let state = self.streams.get(&(endpoint, stream))?;
        let QcsdRequestRole::Chaff { resource_id, .. } = state.role else {
            return None;
        };
        if !state.receive_actions_available || !state.chaff_request_activated() {
            return None;
        }
        let ObservedResponseLength::Final {
            status,
            content_length: Some(length),
        } = state.observed_response_length
        else {
            return None;
        };
        if state.status != Some(status)
            || !(200..300).contains(&status)
            || matches!(status, 204 | 205)
        {
            return None;
        }
        match &state.receive {
            ReceiveState::ReceivingData {
                advertised_limit,
                requested_limit,
                known_limit,
                consumed,
                framing_bytes,
                data_length,
                pending_parser_boundary,
                ..
            } if *data_length > 0
                && length > *data_length
                && framing_bytes.checked_add(*data_length) == Some(*consumed)
                && *pending_parser_boundary == Some(*consumed)
                && *advertised_limit == *requested_limit
                && *requested_limit >= *consumed
                && framing_bytes
                    .checked_add(length)
                    .is_some_and(|end| *known_limit >= end)
                && *known_limit > *requested_limit =>
            {
                Some((resource_id, length, *consumed, *requested_limit))
            }
            _ => None,
        }
    }

    pub(crate) fn buflo_final_permission_response_eligible(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> bool {
        self.streams.get(&(endpoint, stream)).is_some_and(|state| {
            state.receive_actions_available
                && state.role == QcsdRequestRole::Application
                && matches!(state.observed_response_length,
                    ObservedResponseLength::Final { status, content_length: None }
                        if state.status == Some(status) && (200..300).contains(&status)
                            && !matches!(status, 204 | 205))
        })
    }

    /// Capture genuine current DATA-end demand independently of whether the
    /// first due transaction can stage a particular fresh-parser quantum.
    /// This is intent only: no reservation, MAX, owner, or byte is created.
    pub(crate) fn buflo_retained_parser_demand_boundary(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<u64> {
        if !self.buflo_final_permission_response_eligible(endpoint, stream) {
            return None;
        }
        match &self.streams.get(&(endpoint, stream))?.receive {
            ReceiveState::ReceivingData {
                advertised_limit,
                requested_limit,
                known_limit,
                consumed,
                parser_lease_exhausted,
                pending_parser_boundary,
                data_length,
                ..
            } if *data_length > 0
                && *parser_lease_exhausted
                && *pending_parser_boundary == Some(*consumed)
                && *known_limit <= *consumed
                && *advertised_limit == *requested_limit
                && *requested_limit >= *consumed
                && requested_limit.saturating_sub(*consumed) <= 1_200 =>
            {
                Some(*consumed)
            }
            _ => None,
        }
    }

    /// The new retained service is still limited to an actual non-bodyless
    /// successful unknown-length application response, never prepared chaff.
    pub(crate) fn buflo_retained_parser_capacity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        boundary: u64,
        room: u64,
    ) -> u64 {
        let Some(state) = self.streams.get(&(endpoint, stream)) else {
            return 0;
        };
        if !state.receive_actions_available
            || state.role != QcsdRequestRole::Application
            || !matches!(state.observed_response_length,
                ObservedResponseLength::Final { status, content_length: None }
                    if state.status == Some(status) && (200..300).contains(&status)
                        && !matches!(status, 204 | 205))
        {
            return 0;
        }
        state.receive.buflo_retained_parser_capacity(boundary, room)
    }

    pub(crate) fn buflo_retained_parser_opportunity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        boundary: u64,
        room: u64,
    ) -> Option<AllocationOpportunity> {
        (self.buflo_retained_parser_capacity(endpoint, stream, boundary, room) > 0).then_some(
            AllocationOpportunity {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                exact: 0,
                claimable: 0,
            },
        )
    }

    pub(crate) fn claim_buflo_retained_parser(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        boundary: u64,
        room: u64,
        amount: u64,
    ) -> u64 {
        let capacity = self.buflo_retained_parser_capacity(endpoint, stream, boundary, room);
        let Some(state) = self.get_mut(endpoint, stream) else {
            return 0;
        };
        state
            .receive
            .claim_buflo_retained_parser(boundary, room, amount.min(capacity))
    }

    pub(crate) fn lease_buflo_retained_parser(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        boundary: u64,
        backing: u64,
    ) -> Option<ParserLease> {
        // The reservation is already debited, so recheck role/actual response
        // without requiring another unit of currently available reservation.
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available
            || state.role != QcsdRequestRole::Application
            || !matches!(state.observed_response_length,
                ObservedResponseLength::Final { status, content_length: None }
                    if state.status == Some(status) && (200..300).contains(&status)
                        && !matches!(status, 204 | 205))
        {
            return None;
        }
        let (absolute_limit, increase, scheduled) = state
            .receive
            .lease_buflo_retained_parser(boundary, backing)?;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled,
        })
    }

    pub(crate) fn scheduled_parser_lease_capacity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> u64 {
        let Some(state) = self.streams.get(&(endpoint, stream)) else {
            return 0;
        };
        if !state.receive_actions_available {
            return 0;
        }
        match (
            state.parser_blocked_at,
            state.application_response_content_length(),
        ) {
            (blocked_at, Some(content_length)) => state
                .receive
                .scheduled_parser_lease_capacity_with_evidence(blocked_at, Some(content_length)),
            (Some(blocked_at), None) => state
                .receive
                .scheduled_parser_lease_capacity_with_blocked(Some(blocked_at)),
            (None, None) => state.receive.scheduled_parser_lease_capacity(),
        }
    }

    pub(crate) fn claim_scheduled_parser_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        amount: u64,
    ) -> u64 {
        let Some(state) = self.get_mut(endpoint, stream) else {
            return 0;
        };
        if !state.receive_actions_available {
            return 0;
        }
        if let Some(content_length) = state.application_response_content_length() {
            state.receive.claim_scheduled_parser_lease_with_evidence(
                amount,
                state.parser_blocked_at,
                Some(content_length),
            )
        } else {
            state
                .receive
                .claim_scheduled_parser_lease_with_blocked(amount, state.parser_blocked_at)
        }
    }

    /// Lease the remaining prefix up to the stream's absolute framing ceiling
    /// after its retained blocked proof agrees with either the prepared floor
    /// or the controller's exact live scheduled prefix.
    pub(crate) fn pre_header_bootstrap_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        live_scheduled_prefix: Option<(u64, u64)>,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available {
            return None;
        }
        let blocked_at = state.pre_header_blocked_at?;
        let (absolute_limit, increase) = state
            .receive
            .pre_header_bootstrap_lease(blocked_at, live_scheduled_prefix)?;
        state.pre_header_blocked_at = None;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled: false,
        })
    }

    /// Retain real pristine peer demand independently of ACK arrival order.
    /// This intent cannot claim or materialize any receive permission.
    pub(crate) fn accepts_buflo_initial_headers_blocked(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frontier: u64,
    ) -> bool {
        self.streams.get(&(endpoint, stream)).is_some_and(|state| {
            state.receive_actions_available
                && state.role == QcsdRequestRole::Application
                && !state.request_acknowledgment_invalid
                && state.status.is_none()
                && state.observed_response_length == ObservedResponseLength::Unobserved
                && state.receive.buflo_initial_headers_capacity(frontier, 1_200) > 0
        })
    }

    /// Service retained demand only after the complete request range and FIN
    /// are acknowledged. No response/frame fact is fabricated.
    pub(crate) fn buflo_initial_headers_capacity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frontier: u64,
        room: u64,
    ) -> u64 {
        let Some(state) = self.streams.get(&(endpoint, stream)) else {
            return 0;
        };
        if !state.receive_actions_available
            || !state.application_request_activated()
            || state.status.is_some()
            || state.observed_response_length != ObservedResponseLength::Unobserved
        {
            return 0;
        }
        state.receive.buflo_initial_headers_capacity(frontier, room)
    }

    pub(crate) fn buflo_initial_headers_opportunity(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frontier: u64,
        room: u64,
    ) -> Option<AllocationOpportunity> {
        (self.buflo_initial_headers_capacity(endpoint, stream, frontier, room) > 0).then_some(
            AllocationOpportunity {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                exact: 0,
                claimable: 0,
            },
        )
    }

    pub(crate) fn claim_buflo_initial_headers(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frontier: u64,
        room: u64,
        amount: u64,
    ) -> u64 {
        let capacity = self.buflo_initial_headers_capacity(endpoint, stream, frontier, room);
        let Some(state) = self.get_mut(endpoint, stream) else {
            return 0;
        };
        state.receive.claim_buflo_initial_headers(frontier, room, amount.min(capacity))
    }

    pub(crate) fn lease_buflo_initial_headers(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        frontier: u64,
        backing: u64,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available
            || !state.application_request_activated()
            || state.status.is_some()
            || state.observed_response_length != ObservedResponseLength::Unobserved
        {
            return None;
        }
        let (absolute_limit, increase, scheduled) =
            state.receive.lease_buflo_initial_headers(frontier, backing)?;
        Some(ParserLease { endpoint, stream, absolute_limit, increase, scheduled })
    }

    /// A completely acknowledged application request permits the existing
    /// pristine framing bootstrap without optional STREAM_DATA_BLOCKED. The
    /// current advertised frontier is evidence of permission, not peer demand.
    /// The unchanged receive leaf enforces the same absolute 1000-byte target,
    /// lifetime budget, prepared/live prefix and zero parser-progress guards.
    pub(crate) fn acknowledged_application_pre_header_bootstrap_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        live_scheduled_prefix: Option<(u64, u64)>,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available
            || !state.application_request_activated()
            || state.status.is_some()
            || state.observed_response_length != ObservedResponseLength::Unobserved
        {
            return None;
        }
        let (advertised, requested) = state.receive.limits()?;
        if advertised != requested {
            return None;
        }
        let (absolute_limit, increase) = state
            .receive
            .pre_header_bootstrap_lease(advertised, live_scheduled_prefix)?;
        Some(ParserLease {
            endpoint,
            stream,
            absolute_limit,
            increase,
            scheduled: false,
        })
    }

    /// The aggregate capability may finish a typed initial framing prefix,
    /// never an inferred response-body prefix. HTTP/3 produces HeaderProgress
    /// from its frame reader rather than its DATA-body reader. Before final
    /// HEADERS, the observed debt is bounded by the remaining lifetime budget;
    /// after final HEADERS only the at-most-16-byte DATA frame prefix qualifies.
    pub(crate) fn aggregate_prebody_framing_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        resource_id: u32,
        body_bytes: u64,
        min_remaining: u64,
        pristine_data_boundary: bool,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available
            || !matches!(state.role, QcsdRequestRole::Chaff {
                resource_id: selected,
                request_id: Some(_),
            } if selected == resource_id)
            || state.activated_chaff_request_final_size().is_none()
        {
            return None;
        }
        if state.aggregate_framing_debt
            != Some((
                state.receive.consumed(),
                min_remaining,
                pristine_data_boundary,
            ))
        {
            return None;
        }
        match state.observed_response_length {
            ObservedResponseLength::Unobserved if state.status.is_none() => {
                if pristine_data_boundary {
                    return None;
                }
            }
            ObservedResponseLength::Final {
                status: 200,
                content_length: Some(length),
            } if state.status == Some(200) && length == body_bytes => {
                if min_remaining > 16 {
                    return None;
                }
            }
            _ => return None,
        }
        let (absolute_limit, increase) = state
            .receive
            .aggregate_prebody_framing_lease(min_remaining, pristine_data_boundary)?;
        state.aggregate_framing_debt = None;
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
        if !state.receive_actions_available {
            return None;
        }
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

    /// Exact-window materialization rechecks the same actual blocked frontier
    /// that allowed a positive short-tail claim in the complete slot allocation.
    pub(crate) fn parser_lease_with_blocked(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        pristine_data_boundary: bool,
        scheduled_backing: u64,
        terminal_advertised_tail: Option<u64>,
    ) -> Option<ParserLease> {
        let state = self.get_mut(endpoint, stream)?;
        if !state.receive_actions_available {
            return None;
        }
        let (absolute_limit, increase, scheduled) =
            if let Some(content_length) = state.application_response_content_length() {
                state.receive.parser_lease_with_evidence(
                    pristine_data_boundary,
                    scheduled_backing,
                    terminal_advertised_tail,
                    state.parser_blocked_at,
                    Some(content_length),
                )
            } else {
                state.receive.parser_lease_with_blocked(
                    pristine_data_boundary,
                    scheduled_backing,
                    terminal_advertised_tail,
                    state.parser_blocked_at,
                )
            }?;
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
        self.streams.get(&(endpoint, stream)).is_some_and(|state| {
            state.receive_actions_available && state.receive.has_pending_parser_boundary()
        })
    }

    pub fn pending_parser_boundaries(&self) -> Vec<(QcsdEndpointId, QcsdStreamId)> {
        let mut pending: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(key, state)| {
                (state.receive_actions_available && state.receive.has_pending_parser_boundary())
                    .then_some(*key)
            })
            .collect();
        pending.sort_unstable();
        pending
    }

    #[cfg(test)]
    pub fn has_any_pending_parser_boundary(&self) -> bool {
        self.streams.values().any(|state| {
            state.receive_actions_available && state.receive.has_pending_parser_boundary()
        })
    }

    /// Whether application response parsing still requires receive capacity.
    ///
    /// A client-local defense may cancel an exhausted reviewed-chaff response,
    /// including its retained HTTP/3 frame boundary. Application boundaries
    /// are never cancellable defense work and must remain part of the terminal
    /// backlog even when no parser lease is currently in flight.
    pub fn has_pending_application_parser_boundary(&self) -> bool {
        self.pending_application_parser_boundary_count() > 0
    }

    /// Number of application response parsers retained at an exact frame
    /// boundary. Unlike reviewed-chaff boundaries, these can never be erased
    /// by a client-local defense-tail cancellation.
    pub fn pending_application_parser_boundary_count(&self) -> usize {
        self.streams
            .values()
            .filter(|state| {
                state.receive_actions_available
                    && state.role == QcsdRequestRole::Application
                    && state.receive.has_pending_parser_boundary()
            })
            .count()
    }

    pub fn clear_parser_boundaries(&mut self) {
        #[expect(
            clippy::iter_over_hash_type,
            reason = "clearing every independent stream boundary is order-insensitive"
        )]
        for state in self.streams.values_mut() {
            state.pre_header_blocked_at = None;
            state.parser_blocked_at = None;
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
    use super::{ReceiveState, StreamRegistry};
    use crate::{DefenseMode, QcsdEndpointId, QcsdRequestRole, QcsdStreamId};

    fn recorded_primary_before_short_frame() -> (StreamRegistry, QcsdEndpointId, QcsdStreamId) {
        let endpoint = QcsdEndpointId(3);
        let stream = QcsdStreamId(0);
        let mut registry = StreamRegistry::default();
        registry.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            1_000,
            1,
        );
        assert!(registry.record_pre_header_blocked(endpoint, stream, 16));
        let bootstrap = registry
            .pre_header_bootstrap_lease(endpoint, stream, None)
            .expect("bootstrap");
        {
            let receive = &mut registry.get_mut(endpoint, stream).expect("primary").receive;
            receive.advertised(bootstrap.absolute_limit);
            receive.bytes_read(553);
            receive.response_headers(553, None);
            receive.bytes_read(3);
            receive.data_frame(3, 444);
            receive.bytes_read(444);
        }
        registry.header_progress(endpoint, stream, 1, true);
        let prefix = registry
            .parser_lease(endpoint, stream, true, 0, None)
            .expect("last unowned prefix");
        registry
            .get_mut(endpoint, stream)
            .expect("primary")
            .receive
            .advertised(prefix.absolute_limit);
        assert_eq!(prefix.absolute_limit, 1_016);
        (registry, endpoint, stream)
    }

    fn consume_recorded_short_frame(
        registry: &mut StreamRegistry,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) {
        let receive = &mut registry.get_mut(endpoint, stream).expect("primary").receive;
        receive.bytes_read(2);
        receive.data_frame(2, 13);
        receive.bytes_read(13);
        registry.header_progress(endpoint, stream, 1, true);
    }

    #[test]
    fn observed_response_length_is_final_consistent_application_evidence_only() {
        for tail in [1, 2] {
            let (mut registry, endpoint, stream) = recorded_primary_before_short_frame();
            consume_recorded_short_frame(&mut registry, endpoint, stream);
            let state = registry.get_mut(endpoint, stream).expect("primary");
            if let ReceiveState::ReceivingData {
                consumed,
                data_length,
                pending_parser_boundary,
                ..
            } = &mut state.receive
            {
                *consumed -= tail - 1;
                *data_length -= tail - 1;
                *pending_parser_boundary = Some(*consumed);
            }
            state.response_headers(0, Some(103), Some(458));
            assert_eq!(state.application_response_content_length(), None);
            state.response_headers(0, Some(200), Some(458));
            assert_eq!(state.application_response_content_length(), Some(458));
            assert_eq!(
                registry.scheduled_parser_lease_capacity(endpoint, stream),
                0,
                "headers clear the old boundary; a fresh typed stall is required"
            );
            registry.header_progress(endpoint, stream, 1, true);
            assert_eq!(
                registry.scheduled_parser_lease_capacity(endpoint, stream),
                3 - tail
            );
            registry
                .get_mut(endpoint, stream)
                .expect("primary")
                .response_headers(0, Some(200), Some(458));
            registry.header_progress(endpoint, stream, 1, true);
            assert_eq!(
                registry.scheduled_parser_lease_capacity(endpoint, stream),
                3 - tail
            );
            registry
                .get_mut(endpoint, stream)
                .expect("primary")
                .response_headers(0, None, Some(999));
            assert_eq!(
                registry
                    .get_mut(endpoint, stream)
                    .expect("primary")
                    .application_response_content_length(),
                Some(458),
                "trailers cannot replace final response proof"
            );
        }
        for invalid in 0..9 {
            let (mut registry, endpoint, stream) = recorded_primary_before_short_frame();
            consume_recorded_short_frame(&mut registry, endpoint, stream);
            let state = registry.get_mut(endpoint, stream).expect("primary");
            state.response_headers(0, Some(200), Some(458));
            match invalid {
                0 => state.response_headers(0, Some(200), Some(459)),
                1 => state.response_headers(0, Some(206), Some(458)),
                2 => state.response_headers(0, Some(200), None),
                3 => state.response_headers(0, Some(103), Some(458)),
                4 => {
                    state.role = QcsdRequestRole::Chaff {
                        resource_id: 1,
                        request_id: Some(crate::QcsdChaffRequestId(1)),
                    }
                }
                5 => state.receive_actions_available = false,
                6 => state.response_headers(0, Some(204), Some(458)),
                7 => state.response_headers(0, Some(205), Some(458)),
                _ => state.response_headers(0, Some(404), Some(458)),
            }
            assert_eq!(state.application_response_content_length(), None);
            state.response_headers(0, Some(200), Some(458));
            registry.header_progress(endpoint, stream, 1, true);
            assert_eq!(
                registry.scheduled_parser_lease_capacity(endpoint, stream),
                0
            );
            assert_eq!(
                registry.parser_lease_with_blocked(endpoint, stream, true, 2, None),
                None
            );
        }
    }

    #[test]
    fn observed_response_length_never_uses_prepared_hint_or_completed_variable_body() {
        for length in [None, Some(0), Some(457)] {
            let (mut registry, endpoint, stream) = recorded_primary_before_short_frame();
            consume_recorded_short_frame(&mut registry, endpoint, stream);
            let state = registry.get_mut(endpoint, stream).expect("primary");
            state.response_headers(0, Some(200), length);
            if let ReceiveState::ReceivingData { payload_floor, .. } = &mut state.receive {
                *payload_floor = 458;
            }
            state.receive.framing(0);
            registry.header_progress(endpoint, stream, 1, true);
            assert_eq!(
                registry.scheduled_parser_lease_capacity(endpoint, stream),
                0
            );
        }
        let (mut registry, endpoint, stream) = recorded_primary_before_short_frame();
        let state = registry.get_mut(endpoint, stream).expect("primary");
        state.response_headers(0, None, Some(1_000_000));
        assert_eq!(
            state.application_response_content_length(),
            None,
            "status-less observations cannot originate final-header proof"
        );
    }

    #[test]
    fn parser_blocked_registry_retains_actual_frontier_before_data_and_rechecks_grant() {
        let (mut registry, endpoint, stream) = recorded_primary_before_short_frame();
        assert!(!registry.record_parser_blocked(endpoint, stream, 1_015));
        assert!(registry.record_parser_blocked(endpoint, stream, 1_016));
        consume_recorded_short_frame(&mut registry, endpoint, stream);
        assert_eq!(
            registry.scheduled_parser_lease_capacity(endpoint, stream),
            2
        );
        assert_eq!(
            registry.claim_scheduled_parser_lease(endpoint, stream, 1),
            0
        );
        assert_eq!(
            registry.claim_scheduled_parser_lease(endpoint, stream, 2),
            2
        );
        registry.restore_claim(endpoint, stream, 2);
        assert_eq!(
            registry.scheduled_parser_lease_capacity(endpoint, stream),
            2
        );
        assert_eq!(
            registry.claim_scheduled_parser_lease(endpoint, stream, 2),
            2
        );
        let lease = registry
            .parser_lease_with_blocked(endpoint, stream, true, 2, None)
            .expect("complete owned DATA opportunity");
        assert_eq!(
            (lease.absolute_limit, lease.increase, lease.scheduled),
            (1_018, 2, true)
        );
        assert_eq!(
            registry.scheduled_parser_lease_capacity(endpoint, stream),
            0
        );
        assert_eq!(
            registry.parser_lease_with_blocked(endpoint, stream, true, 1, None),
            None
        );
    }

    #[test]
    fn parser_blocked_registry_rejects_missing_stale_closed_and_unavailable_proof() {
        let (mut missing, endpoint, stream) = recorded_primary_before_short_frame();
        consume_recorded_short_frame(&mut missing, endpoint, stream);
        assert_eq!(missing.scheduled_parser_lease_capacity(endpoint, stream), 0);
        assert_eq!(
            missing.parser_lease_with_blocked(endpoint, stream, true, 1, None),
            None
        );

        let (mut stale, endpoint, stream) = recorded_primary_before_short_frame();
        assert!(stale.record_parser_blocked(endpoint, stream, 1_016));
        consume_recorded_short_frame(&mut stale, endpoint, stream);
        if let ReceiveState::ReceivingData {
            requested_limit,
            advertised_limit,
            ..
        } = &mut stale.get_mut(endpoint, stream).expect("primary").receive
        {
            *requested_limit = 1_017;
            *advertised_limit = 1_017;
        }
        assert_eq!(stale.scheduled_parser_lease_capacity(endpoint, stream), 0);
        assert_eq!(
            stale.parser_lease_with_blocked(endpoint, stream, true, 1, None),
            None
        );

        let (mut unavailable, endpoint, stream) = recorded_primary_before_short_frame();
        assert!(unavailable.record_parser_blocked(endpoint, stream, 1_016));
        consume_recorded_short_frame(&mut unavailable, endpoint, stream);
        assert!(unavailable.mark_receive_unavailable(endpoint, stream));
        assert_eq!(
            unavailable.scheduled_parser_lease_capacity(endpoint, stream),
            0
        );
        assert!(!unavailable.record_parser_blocked(endpoint, stream, 1_016));
        assert_eq!(
            unavailable.parser_lease_with_blocked(endpoint, stream, true, 1, None),
            None
        );

        let (mut automatic, endpoint, stream) = recorded_primary_before_short_frame();
        assert!(automatic.record_parser_blocked(endpoint, stream, 1_016));
        consume_recorded_short_frame(&mut automatic, endpoint, stream);
        assert_eq!(
            automatic.handoff_application_receive_to_automatic(),
            Ok(vec![(endpoint, stream)])
        );
        assert_eq!(
            automatic
                .get_mut(endpoint, stream)
                .expect("automatic")
                .parser_blocked_at,
            None
        );
        assert_eq!(
            automatic.scheduled_parser_lease_capacity(endpoint, stream),
            0
        );
        assert!(!automatic.record_parser_blocked(endpoint, stream, 1_016));

        let (mut closed, endpoint, stream) = recorded_primary_before_short_frame();
        assert!(closed.record_parser_blocked(endpoint, stream, 1_016));
        assert!(closed.close(endpoint, stream).is_some());
        assert_eq!(closed.scheduled_parser_lease_capacity(endpoint, stream), 0);
        assert!(!closed.record_parser_blocked(endpoint, stream, 1_016));
    }

    #[test]
    fn application_handoff_is_atomic_preserves_counters_and_accepts_a_parser_boundary() {
        let endpoint = QcsdEndpointId(1);
        let first = QcsdStreamId(0);
        let blocked = QcsdStreamId(4);
        let mut registry = StreamRegistry::default();
        for stream in [first, blocked] {
            registry.open(
                endpoint,
                stream,
                QcsdRequestRole::Application,
                true,
                16,
                1_000,
                2_000,
            );
        }
        {
            let state = registry
                .get_mut(endpoint, first)
                .expect("first application");
            state.receive.data_frame(2, 31);
            state.receive.bytes_read(40);
            state.receive.header_progress(0, true);
        }
        let release = registry
            .release_stream(endpoint, blocked, 32)
            .expect("unadvertised suffix");
        assert_eq!(
            registry.handoff_application_receive_to_automatic(),
            Err((endpoint, blocked)),
            "one unsafe stream blocks the complete batch"
        );
        assert!(
            registry
                .get_mut(endpoint, first)
                .expect("first remains registered")
                .receive
                .is_controlled()
        );

        registry
            .get_mut(endpoint, blocked)
            .expect("blocked application")
            .receive
            .advertised(release.absolute_limit);
        assert_eq!(
            registry
                .handoff_application_receive_to_automatic()
                .expect("atomic application handoff"),
            [(endpoint, first), (endpoint, blocked)]
        );
        let first_state = registry
            .get_mut(endpoint, first)
            .expect("handed-off application");
        assert!(!first_state.receive.is_controlled());
        assert_eq!(first_state.receive.consumed(), 40);
    }

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
        assert_eq!(
            registry.pre_header_bootstrap_lease(endpoint, stream, None),
            None
        );
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
    fn scheduled_prefix_stability_requires_exact_live_stream_identity() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        for role in [
            QcsdRequestRole::Application,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        ] {
            let mut registry = StreamRegistry::default();
            registry.open(endpoint, stream, role, true, 16, 1_000, 1_798);
            assert!(!registry.scheduled_prefix_drain_is_stable(endpoint, stream));
            let state = registry
                .get_mut(endpoint, stream)
                .expect("live exact stream");
            state.receive.response_headers(662, Some(1_798));
            state.receive.data_frame(3, 1_798);
            assert!(registry.scheduled_prefix_drain_is_stable(endpoint, stream));
            assert!(!registry.scheduled_prefix_drain_is_stable(QcsdEndpointId(2), stream));
            assert!(!registry.scheduled_prefix_drain_is_stable(endpoint, QcsdStreamId(8)));
            assert!(registry.mark_receive_unavailable(endpoint, stream));
            assert!(!registry.scheduled_prefix_drain_is_stable(endpoint, stream));
        }
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

#[cfg(test)]
#[path = "cs_live_chaff_headers_tests.rs"]
mod cs_live_chaff_headers_tests;

#[cfg(test)]
#[path = "cs_live_chaff_owned_data_tests.rs"]
mod cs_live_chaff_owned_data_tests;
