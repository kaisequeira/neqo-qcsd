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
        prospective_frame_header_bytes: u64,
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
        prospective_frame_header_bytes: u64,
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
                prospective_frame_header_bytes: 0,
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
        match self {
            Self::ReceivingHeaders {
                known_limit,
                consumed,
                payload_floor,
                framing_bytes,
                prospective_frame_header_bytes,
                ..
            } => {
                *prospective_frame_header_bytes = if awaiting_data_frame {
                    prospective_data_frame_header(*payload_floor)
                } else {
                    0
                };
                *known_limit = (*known_limit).max(consumed.saturating_add(min_remaining));
                *known_limit = (*known_limit).max(
                    payload_floor
                        .saturating_add(*framing_bytes)
                        .saturating_add(*prospective_frame_header_bytes),
                );
            }
            Self::ReceivingData {
                known_limit,
                consumed,
                payload_floor,
                framing_bytes,
                prospective_frame_header_bytes,
                data_length,
                ..
            } => {
                *prospective_frame_header_bytes = if awaiting_data_frame {
                    prospective_data_frame_header(payload_floor.saturating_sub(*data_length))
                } else {
                    0
                };
                *known_limit = (*known_limit).max(consumed.saturating_add(min_remaining));
                *known_limit = (*known_limit).max(
                    payload_floor
                        .saturating_add(*framing_bytes)
                        .saturating_add(*prospective_frame_header_bytes),
                );
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn response_headers(&mut self, frame_bytes: u64, content_length: Option<u64>) {
        match self {
            Self::ReceivingHeaders {
                known_limit,
                payload_floor,
                framing_bytes,
                prospective_frame_header_bytes,
                ..
            }
            | Self::ReceivingData {
                known_limit,
                payload_floor,
                framing_bytes,
                prospective_frame_header_bytes,
                ..
            } => {
                *framing_bytes = framing_bytes.saturating_add(frame_bytes);
                *prospective_frame_header_bytes = 0;
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
                ..
            } => {
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
                    prospective_frame_header_bytes: 0,
                    data_length: data,
                };
            }
            Self::ReceivingData {
                known_limit,
                consumed,
                payload_floor,
                framing_bytes,
                prospective_frame_header_bytes,
                data_length,
                ..
            } => {
                *data_length = data_length.saturating_add(data);
                *payload_floor = (*payload_floor).max(*data_length);
                *framing_bytes = framing_bytes.saturating_add(frame_header_bytes);
                *prospective_frame_header_bytes = 0;
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
                ..
            }
            | Self::ReceivingData {
                known_limit,
                consumed,
                ..
            } => {
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
                prospective_frame_header_bytes,
                ..
            }
            | Self::ReceivingData {
                known_limit,
                payload_floor,
                framing_bytes,
                prospective_frame_header_bytes,
                ..
            } => {
                *framing_bytes = framing_bytes.saturating_add(frame_bytes);
                *prospective_frame_header_bytes = 0;
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
}

/// At a pristine frame boundary the sender needs at least one byte for the
/// DATA type and one byte for the first length-varint octet.  The peer may
/// split the remaining body arbitrarily, so no wider speculative prefix is
/// safe until the parser observes it and reports `min_remaining`.
const fn prospective_data_frame_header(remaining_payload: u64) -> u64 {
    if remaining_payload == 0 { 0 } else { 2 }
}

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
        // A pristine frame boundary with two body bytes outstanding requires
        // the universal two-byte DATA type/length prefix.  This is the exact
        // liveness continuation missing from the failed live attempt.
        state.header_progress(0, true);
        assert_eq!(state.release(2), Some((BODY + 35, 2)));
        state.advertised(BODY + 35);
        state.bytes_read(2);
        state.data_frame(2, 2);
        state.bytes_read(2);
        assert_eq!(state.consumed(), BODY + 35);
        assert_eq!(state.available(), 0);
        assert_eq!(state.close(), (BODY, 0));
    }

    #[test]
    fn pristine_data_boundary_has_two_byte_universal_prefix_or_zero_when_complete() {
        for remaining in [1, 63, 64, 16_383, 16_384] {
            let body = 20_000;
            let mut state = ReceiveState::controlled(0, 1_000, body);
            state.data_frame(2, body - remaining);
            let before = state.available();
            state.header_progress(0, true);
            assert_eq!(state.available(), before + 2, "remaining={remaining}");
        }

        let mut complete = ReceiveState::controlled(0, 1_000, 20_000);
        complete.data_frame(2, 20_000);
        let before = complete.available();
        complete.header_progress(0, true);
        assert_eq!(complete.available(), before);
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
