// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

/// Published QCSD receive-side stream state machine (paper Figure 7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveState {
    /// Request stream exists but its receive policy has not been activated.
    Created {
        controlled: bool,
        initial_limit: u64,
        excess: u64,
        expected: u64,
    },
    /// A controlled request has been created and is parsing response headers.
    ReceivingHeaders {
        advertised_limit: u64,
        requested_limit: u64,
        known_limit: u64,
        reservation_capacity: u64,
        reservation_available: u64,
        consumed: u64,
        payload_floor: u64,
        framing_bytes: u64,
        parser_lease_capacity: u64,
        parser_lease_used: u64,
        last_parser_lease_boundary: Option<u64>,
        pending_parser_boundary: Option<u64>,
    },
    /// At least one HTTP/3 DATA frame length is known.
    ReceivingData {
        advertised_limit: u64,
        requested_limit: u64,
        known_limit: u64,
        reservation_capacity: u64,
        reservation_available: u64,
        consumed: u64,
        payload_floor: u64,
        framing_bytes: u64,
        parser_lease_capacity: u64,
        parser_lease_used: u64,
        last_parser_lease_boundary: Option<u64>,
        pending_parser_boundary: Option<u64>,
        data_length: u64,
    },
    /// Neqo owns receive-window growth; QCSD only records response size.
    Automatic { consumed: u64, data_length: u64 },
    /// Receive side ended. `unadvertised` is scheduled credit never encoded.
    Closed { data_length: u64, unadvertised: u64 },
}

impl ReceiveState {
    pub const fn created(controlled: bool, initial_limit: u64, excess: u64, expected: u64) -> Self {
        Self::Created {
            controlled,
            initial_limit,
            excess,
            expected,
        }
    }

    pub fn open(&mut self) {
        let Self::Created {
            controlled,
            initial_limit,
            excess,
            expected,
        } = *self
        else {
            return;
        };
        *self = if controlled {
            // A stream with no body estimate needs a bounded bootstrap window
            // so HTTP/3 can observe enough of HEADERS or a DATA frame to
            // establish an exact extent.  Prepared research workloads always
            // provide an estimate; zero remains the conservative compatibility
            // path for peers without one.
            let known_limit = if expected == 0 {
                initial_limit.max(excess)
            } else {
                initial_limit.max(expected)
            };
            let reservation_capacity = if expected == 0 { 0 } else { excess };
            Self::ReceivingHeaders {
                advertised_limit: initial_limit,
                requested_limit: initial_limit,
                // The workload body estimate is a conservative lower bound on
                // the raw response-stream extent.  HTTP/3 framing is added only
                // after the parser reports its exact size.  `excess` reserves
                // scheduling work for that framing, but is never itself
                // advertised as receive credit.
                known_limit,
                reservation_capacity,
                reservation_available: reservation_capacity,
                consumed: 0,
                payload_floor: expected,
                framing_bytes: 0,
                parser_lease_capacity: excess,
                parser_lease_used: 0,
                last_parser_lease_boundary: None,
                pending_parser_boundary: None,
            }
        } else {
            Self::Automatic {
                consumed: 0,
                data_length: 0,
            }
        };
    }

    #[cfg(test)]
    pub fn controlled(initial: u64, excess: u64, expected: u64) -> Self {
        let mut state = Self::created(true, initial, excess, expected);
        state.open();
        state
    }

    pub const fn is_controlled(&self) -> bool {
        matches!(
            self,
            Self::Created {
                controlled: true,
                ..
            } | Self::ReceivingHeaders { .. }
                | Self::ReceivingData { .. }
        )
    }

    pub const fn available(&self) -> u64 {
        match self {
            Self::ReceivingHeaders {
                requested_limit,
                known_limit,
                ..
            }
            | Self::ReceivingData {
                requested_limit,
                known_limit,
                ..
            } => known_limit.saturating_sub(*requested_limit),
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => 0,
        }
    }

    /// Maximum scheduled work that may still be claimed as a non-advertised
    /// reservation for this stream.
    pub const fn claimable(&self) -> u64 {
        match self {
            Self::ReceivingHeaders {
                reservation_available,
                ..
            }
            | Self::ReceivingData {
                reservation_available,
                ..
            } => *reservation_available,
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => 0,
        }
    }

    /// Claim at most the configured per-stream excess.  A claim is scheduling
    /// ownership only: it does not increase the advertised receive limit.
    pub fn claim(&mut self, amount: u64) -> u64 {
        match self {
            Self::ReceivingHeaders {
                reservation_available,
                ..
            }
            | Self::ReceivingData {
                reservation_available,
                ..
            } => {
                let claimed = amount.min(*reservation_available);
                *reservation_available -= claimed;
                claimed
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => 0,
        }
    }

    /// Restore a claim whose scheduled slot was terminalized before the claim
    /// became exact receive capacity.
    pub fn restore_claim(&mut self, amount: u64) {
        match self {
            Self::ReceivingHeaders {
                reservation_capacity,
                reservation_available,
                ..
            }
            | Self::ReceivingData {
                reservation_capacity,
                reservation_available,
                ..
            } => {
                *reservation_available = reservation_available
                    .saturating_add(amount)
                    .min(*reservation_capacity);
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    /// Raw stream bytes consumed by HTTP/3 so far.
    pub const fn consumed(&self) -> u64 {
        match self {
            Self::ReceivingHeaders { consumed, .. }
            | Self::ReceivingData { consumed, .. }
            | Self::Automatic { consumed, .. } => *consumed,
            Self::Created { .. } | Self::Closed { .. } => 0,
        }
    }

    pub fn header_progress(&mut self, min_remaining: u64, awaiting_data_frame: bool) {
        // A pristine boundary does not reveal the next frame's raw extent.
        // Its parser liveness is owned by `parser_lease`, never by scheduled
        // capacity.  Once decoding has begun, `min_remaining` is an exact
        // parser requirement and may safely extend the scheduled raw floor.
        if awaiting_data_frame {
            match self {
                Self::ReceivingHeaders {
                    consumed,
                    pending_parser_boundary,
                    ..
                }
                | Self::ReceivingData {
                    consumed,
                    pending_parser_boundary,
                    ..
                } => *pending_parser_boundary = Some(*consumed),
                Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
            }
            return;
        }
        match self {
            Self::ReceivingHeaders {
                known_limit,
                consumed,
                pending_parser_boundary,
                ..
            }
            | Self::ReceivingData {
                known_limit,
                consumed,
                pending_parser_boundary,
                ..
            } => {
                *pending_parser_boundary = None;
                *known_limit = (*known_limit).max(consumed.saturating_add(min_remaining));
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    /// Lease one maximum HTTP/3 frame-header prefix at a pristine DATA
    /// boundary after all exact receive capacity has been consumed.
    ///
    /// The returned raw range advances `requested_limit`, so later scheduled
    /// releases necessarily begin after it.  A boundary offset can lease once,
    /// and all leases over the stream lifetime are capped by the configured
    /// `max_stream_data_excess` value.
    pub fn parser_lease(&mut self, pristine_data_boundary: bool) -> Option<(u64, u64)> {
        if !pristine_data_boundary {
            return None;
        }
        match self {
            Self::ReceivingHeaders {
                advertised_limit,
                requested_limit,
                known_limit,
                consumed,
                parser_lease_capacity,
                parser_lease_used,
                last_parser_lease_boundary,
                pending_parser_boundary,
                ..
            }
            | Self::ReceivingData {
                advertised_limit,
                requested_limit,
                known_limit,
                consumed,
                parser_lease_capacity,
                parser_lease_used,
                last_parser_lease_boundary,
                pending_parser_boundary,
                ..
            } => {
                // `requested_limit > consumed` can be an advertised scheduled
                // RAW range whose next bytes are an HTTP/3 frame header.  A
                // parser lease is appended after that range; the controller's
                // offset ledger therefore keeps the two ownership domains
                // disjoint without reclassifying already advertised bytes.
                if *requested_limit != *advertised_limit
                    || *known_limit > *requested_limit
                    || *pending_parser_boundary != Some(*consumed)
                    || *last_parser_lease_boundary == Some(*consumed)
                {
                    return None;
                }
                let remaining = parser_lease_capacity.saturating_sub(*parser_lease_used);
                let increase = remaining.min(MAX_HTTP3_FRAME_HEADER_BYTES);
                if increase == 0 {
                    return None;
                }
                *last_parser_lease_boundary = Some(*consumed);
                *pending_parser_boundary = None;
                *parser_lease_used = parser_lease_used.saturating_add(increase);
                *requested_limit = requested_limit.saturating_add(increase);
                Some((*requested_limit, increase))
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => None,
        }
    }

    pub fn response_headers(&mut self, frame_bytes: u64, content_length: Option<u64>) {
        match self {
            Self::ReceivingHeaders {
                known_limit,
                payload_floor,
                framing_bytes,
                pending_parser_boundary,
                ..
            }
            | Self::ReceivingData {
                known_limit,
                payload_floor,
                framing_bytes,
                pending_parser_boundary,
                ..
            } => {
                *pending_parser_boundary = None;
                *framing_bytes = framing_bytes.saturating_add(frame_bytes);
                if let Some(content_length) = content_length {
                    *payload_floor = (*payload_floor).max(content_length);
                }
                let exact = payload_floor.saturating_add(*framing_bytes);
                *known_limit = (*known_limit).max(exact);
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn data_frame(&mut self, frame_header_bytes: u64, data: u64) {
        match self {
            Self::ReceivingHeaders {
                advertised_limit,
                requested_limit,
                known_limit,
                reservation_capacity,
                reservation_available,
                consumed,
                payload_floor,
                framing_bytes,
                parser_lease_capacity,
                parser_lease_used,
                last_parser_lease_boundary,
                pending_parser_boundary,
                ..
            } => {
                *pending_parser_boundary = None;
                let framing_bytes = framing_bytes.saturating_add(frame_header_bytes);
                let payload_floor = (*payload_floor).max(data);
                // The DATA payload becomes known after its frame header has
                // already contributed to consumed raw bytes.  Both forms are
                // exact lower bounds; neither includes the speculative reserve.
                let known_limit = (*known_limit)
                    .max(consumed.saturating_add(data))
                    .max(payload_floor.saturating_add(framing_bytes));
                *self = Self::ReceivingData {
                    advertised_limit: *advertised_limit,
                    requested_limit: *requested_limit,
                    known_limit,
                    reservation_capacity: *reservation_capacity,
                    reservation_available: *reservation_available,
                    consumed: *consumed,
                    payload_floor,
                    framing_bytes,
                    parser_lease_capacity: *parser_lease_capacity,
                    parser_lease_used: *parser_lease_used,
                    last_parser_lease_boundary: *last_parser_lease_boundary,
                    pending_parser_boundary: *pending_parser_boundary,
                    data_length: data,
                };
            }
            Self::ReceivingData {
                known_limit,
                consumed,
                payload_floor,
                framing_bytes,
                data_length,
                pending_parser_boundary,
                ..
            } => {
                *pending_parser_boundary = None;
                *data_length = data_length.saturating_add(data);
                *payload_floor = (*payload_floor).max(*data_length);
                *framing_bytes = framing_bytes.saturating_add(frame_header_bytes);
                *known_limit = (*known_limit)
                    .max(consumed.saturating_add(data))
                    .max(payload_floor.saturating_add(*framing_bytes));
            }
            Self::Automatic { data_length, .. } => {
                *data_length = data_length.saturating_add(data);
            }
            Self::Created { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn bytes_read(&mut self, bytes: u64) {
        match self {
            Self::ReceivingHeaders {
                known_limit,
                consumed,
                pending_parser_boundary,
                ..
            }
            | Self::ReceivingData {
                known_limit,
                consumed,
                pending_parser_boundary,
                ..
            } => {
                if bytes > 0 {
                    *pending_parser_boundary = None;
                }
                *consumed = consumed.saturating_add(bytes);
                *known_limit = (*known_limit).max(*consumed);
            }
            Self::Automatic { consumed, .. } => *consumed = consumed.saturating_add(bytes),
            Self::Created { .. } | Self::Closed { .. } => {}
        }
    }

    /// Add exact non-DATA HTTP/3 framing observed on the request stream.
    pub fn framing(&mut self, frame_bytes: u64) {
        match self {
            Self::ReceivingHeaders {
                known_limit,
                payload_floor,
                framing_bytes,
                pending_parser_boundary,
                ..
            }
            | Self::ReceivingData {
                known_limit,
                payload_floor,
                framing_bytes,
                pending_parser_boundary,
                ..
            } => {
                *pending_parser_boundary = None;
                *framing_bytes = framing_bytes.saturating_add(frame_bytes);
                *known_limit = (*known_limit).max(payload_floor.saturating_add(*framing_bytes));
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn release(&mut self, amount: u64) -> Option<(u64, u64)> {
        let available = self.available();
        let released = amount.min(available);
        if released == 0 {
            return None;
        }
        match self {
            Self::ReceivingHeaders {
                requested_limit, ..
            }
            | Self::ReceivingData {
                requested_limit, ..
            } => {
                *requested_limit = requested_limit.saturating_add(released);
                Some((*requested_limit, released))
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => None,
        }
    }

    /// Roll back one unadvertised staged release. Callers reverse releases in
    /// LIFO order, so the absolute limit must exactly match requested state.
    pub const fn cancel_release(&mut self, absolute_limit: u64, increase: u64) -> bool {
        match self {
            Self::ReceivingHeaders {
                requested_limit,
                advertised_limit,
                ..
            }
            | Self::ReceivingData {
                requested_limit,
                advertised_limit,
                ..
            } if *requested_limit == absolute_limit
                && absolute_limit.saturating_sub(increase) >= *advertised_limit =>
            {
                *requested_limit -= increase;
                true
            }
            _ => false,
        }
    }

    pub fn advertised(&mut self, absolute_limit: u64) {
        match self {
            Self::ReceivingHeaders {
                advertised_limit,
                requested_limit,
                ..
            }
            | Self::ReceivingData {
                advertised_limit,
                requested_limit,
                ..
            } => {
                *advertised_limit = (*advertised_limit).max(absolute_limit.min(*requested_limit));
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    pub const fn close(&mut self) -> (u64, u64) {
        let (data_length, unadvertised) = match self {
            Self::Created { .. } => (0, 0),
            Self::ReceivingHeaders {
                advertised_limit,
                requested_limit,
                ..
            } => (0, requested_limit.saturating_sub(*advertised_limit)),
            Self::ReceivingData {
                advertised_limit,
                requested_limit,
                data_length,
                ..
            } => (
                *data_length,
                requested_limit.saturating_sub(*advertised_limit),
            ),
            Self::Automatic { data_length, .. } | Self::Closed { data_length, .. } => {
                (*data_length, 0)
            }
        };
        *self = Self::Closed {
            data_length,
            unadvertised,
        };
        (data_length, unadvertised)
    }

    pub const fn clear_parser_boundary(&mut self) {
        match self {
            Self::ReceivingHeaders {
                pending_parser_boundary,
                ..
            }
            | Self::ReceivingData {
                pending_parser_boundary,
                ..
            } => *pending_parser_boundary = None,
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }
}

/// An HTTP/3 frame type and length are each QUIC varints of at most eight
/// bytes.  This is enough to classify the frame without leasing its payload.
const MAX_HTTP3_FRAME_HEADER_BYTES: u64 = 16;

#[cfg(test)]
mod tests {
    use super::ReceiveState;

    #[test]
    fn created_stream_transitions_to_the_selected_receive_policy() {
        let mut controlled = ReceiveState::created(true, 16, 1_000, 4_000);
        assert!(matches!(controlled, ReceiveState::Created { .. }));
        controlled.open();
        assert!(matches!(controlled, ReceiveState::ReceivingHeaders { .. }));

        let mut automatic = ReceiveState::created(false, 16, 1_000, 0);
        automatic.open();
        assert!(matches!(automatic, ReceiveState::Automatic { .. }));
    }

    #[test]
    fn controlled_stream_tracks_known_and_requested_credit() {
        let mut state = ReceiveState::controlled(16, 1_000, 600);
        assert_eq!(state.available(), 584);
        assert_eq!(state.claimable(), 1_000);
        assert_eq!(state.claim(1_200), 1_000);
        assert_eq!(state.claim(1), 0);
        assert_eq!(state.release(500), Some((516, 500)));
        assert_eq!(state.available(), 84);
        state.advertised(516);
        assert_eq!(state.close(), (0, 0));
    }

    #[test]
    fn data_frame_discovers_payload_capacity() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.bytes_read(2);
        state.data_frame(5, 4_000);
        assert_eq!(state.available(), 3_989);
        assert_eq!(state.close(), (4_000, 0));
    }

    #[test]
    fn header_progress_prevents_large_header_deadlock() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        assert_eq!(state.release(84), Some((100, 84)));
        assert_eq!(state.available(), 0);
        state.bytes_read(100);
        state.header_progress(2_000, false);
        assert_eq!(state.available(), 2_000);
    }

    #[test]
    fn closing_reports_credit_not_yet_advertised() {
        let mut state = ReceiveState::controlled(16, 1_000, 516);
        state.release(500);
        assert_eq!(state.close(), (0, 500));
    }

    #[test]
    fn multiple_data_frames_override_incorrect_content_length_safely() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.bytes_read(10);
        state.response_headers(10, Some(1));
        state.bytes_read(2);
        state.data_frame(2, 600);
        state.bytes_read(602);
        state.bytes_read(2);
        state.data_frame(2, 700);
        assert_eq!(state.close(), (1_300, 0));
    }

    #[test]
    fn partial_release_tracks_absolute_and_unadvertised_credit() {
        let mut state = ReceiveState::controlled(16, 1_000, 1_000);
        assert_eq!(state.release(250), Some((266, 250)));
        state.advertised(116);
        assert_eq!(state.close(), (0, 150));
    }

    #[test]
    fn automatic_stream_never_returns_scheduled_credit() {
        let mut state = ReceiveState::created(false, 16, 1_000, 0);
        state.open();
        state.data_frame(0, 900);
        assert_eq!(state.close(), (900, 0));
    }

    #[test]
    fn figure_seven_content_length_is_an_absolute_limit() {
        let mut state = ReceiveState::controlled(16, 1_000, 0);
        state.bytes_read(40);
        state.response_headers(40, Some(4_000));
        assert_eq!(state.available(), 4_024);
    }

    #[test]
    fn figure_seven_data_length_uses_consumed_raw_bytes() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.bytes_read(42);
        state.data_frame(2, 900);
        assert_eq!(state.available(), 926);
        state.bytes_read(400);
        assert_eq!(state.available(), 926);
    }

    #[test]
    fn exact_http3_framing_extends_a_known_body_without_advertising_the_reserve() {
        const BODY: u64 = 131_072;
        let mut state = ReceiveState::controlled(0, 1_000, BODY);
        assert_eq!(state.claim(1_000), 1_000);
        assert_eq!(state.release(BODY), Some((BODY, BODY)));
        assert_eq!(state.available(), 0);
        assert_eq!(state.claimable(), 0);
        state.advertised(BODY);

        state.bytes_read(11);
        state.response_headers(11, Some(BODY));
        assert_eq!(state.release(11), Some((BODY + 11, 11)));
        state.advertised(BODY + 11);

        for data in [32_768, 32_768, 32_768, 32_737, 29] {
            let frame_header_bytes = if data == 29 { 2 } else { 5 };
            state.bytes_read(frame_header_bytes);
            state.data_frame(frame_header_bytes, data);
            let absolute = state
                .release(frame_header_bytes)
                .map(|(absolute, released)| {
                    assert_eq!(released, frame_header_bytes);
                    absolute
                })
                .expect("observed DATA header becomes exact raw capacity");
            state.advertised(absolute);
            state.bytes_read(data);
        }

        assert_eq!(state.consumed(), BODY + 31);
        assert_eq!(BODY + 31, 131_103);
        // Exact retained live boundary: requested/advertised raw offset
        // 131,105 is two bytes ahead of consumed 131,103. Those existing raw
        // bytes remain scheduled; a disjoint parser tail begins at 131,105.
        state.header_progress(1, true);
        assert_eq!(state.parser_lease(true), Some((BODY + 49, 16)));
        assert_eq!(BODY + 33, 131_105);
        state.advertised(BODY + 49);
        state.bytes_read(2);
        state.data_frame(2, 2);
        state.bytes_read(2);
        assert_eq!(state.consumed(), BODY + 35);
        // A later distinct DATA(0) boundary can extend the bounded lease even
        // while part of the prior lease remains unused.
        state.header_progress(1, true);
        assert_eq!(state.parser_lease(true), Some((BODY + 65, 16)));
        state.advertised(BODY + 65);
        state.bytes_read(2);
        state.data_frame(2, 0);
        assert_eq!(state.consumed(), BODY + 37);
        assert_eq!(state.available(), 0);
        assert_eq!(state.close(), (BODY, 0));
    }

    #[test]
    fn pristine_parser_lease_is_idempotent_disjoint_and_lifetime_bounded() {
        let mut state = ReceiveState::controlled(1, 1_000, 1);
        state.bytes_read(1);
        let mut total = 0;
        for boundary in 0..63 {
            state.header_progress(1, true);
            let (absolute, increase) = state.parser_lease(true).expect("bounded lease");
            let expected = if boundary == 62 { 8 } else { 16 };
            assert_eq!(increase, expected);
            total += increase;
            assert_eq!(absolute, 1 + total);
            assert_eq!(state.parser_lease(true), None, "duplicate boundary");
            state.advertised(absolute);
            state.bytes_read(increase);
        }
        assert_eq!(total, 1_000);
        assert_eq!(state.parser_lease(true), None, "lifetime cap");
    }

    #[test]
    fn parser_lease_requires_a_pristine_exhausted_boundary() {
        let mut exact_available = ReceiveState::controlled(0, 100, 10);
        assert_eq!(exact_available.parser_lease(true), None);

        let mut outstanding = ReceiveState::controlled(1, 100, 1);
        outstanding.bytes_read(1);
        outstanding.header_progress(1, true);
        assert_eq!(outstanding.parser_lease(true), Some((17, 16)));
        assert_eq!(outstanding.parser_lease(false), None);

        let mut unadvertised = ReceiveState::controlled(1, 100, 2);
        unadvertised.bytes_read(1);
        assert_eq!(unadvertised.release(1), Some((2, 1)));
        unadvertised.header_progress(1, true);
        assert_eq!(unadvertised.parser_lease(true), None);
        unadvertised.advertised(2);
        assert_eq!(unadvertised.parser_lease(true), Some((18, 16)));

        let mut not_pristine = ReceiveState::controlled(1, 100, 1);
        not_pristine.bytes_read(1);
        not_pristine.header_progress(8, false);
        assert_eq!(not_pristine.parser_lease(false), None);
        assert_eq!(not_pristine.available(), 8);
    }

    #[test]
    fn unknown_length_uses_one_bounded_parser_bootstrap_then_exact_bytes() {
        let mut state = ReceiveState::controlled(16, 1_000, 0);
        assert_eq!(state.available(), 984);
        assert_eq!(state.release(984), Some((1_000, 984)));
        state.bytes_read(11);
        state.response_headers(11, None);
        assert_eq!(state.available(), 0);
        state.bytes_read(5);
        state.data_frame(5, 2_000);
        // Once the parser announces the frame, its exact payload and header
        // extend the raw limit without a speculative rolling allowance.
        assert_eq!(state.release(1_016), Some((2_016, 1_016)));
    }

    #[test]
    fn early_close_discards_only_the_unadvertised_reservation() {
        let mut state = ReceiveState::controlled(0, 1_000, 1_000);
        assert_eq!(state.release(1_000), Some((1_000, 1_000)));
        state.advertised(1_000);
        state.bytes_read(500);
        assert_eq!(state.claimable(), 1_000);
        assert_eq!(state.close(), (0, 0));
    }
}
