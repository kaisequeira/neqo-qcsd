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
        consumed: u64,
    },
    /// At least one HTTP/3 DATA frame length is known.
    ReceivingData {
        advertised_limit: u64,
        requested_limit: u64,
        known_limit: u64,
        consumed: u64,
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
            Self::ReceivingHeaders {
                advertised_limit: initial_limit,
                requested_limit: initial_limit,
                // Figure 7 initializes `limit` to the largest independent
                // source of known capacity. `excess` is an absolute allowance,
                // not an increment on top of the transport's initial limit.
                known_limit: initial_limit.max(expected).max(excess),
                consumed: 0,
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

    pub fn header_progress(&mut self, min_remaining: u64, excess: u64) {
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
                *known_limit =
                    (*known_limit).max(consumed.saturating_add(min_remaining.max(excess)));
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn response_headers(&mut self, content_length: Option<u64>) {
        match self {
            Self::ReceivingHeaders { known_limit, .. }
            | Self::ReceivingData { known_limit, .. } => {
                if let Some(content_length) = content_length {
                    // Figure 7 action A3: `limit <- max(limit, x)`.
                    *known_limit = (*known_limit).max(content_length);
                }
            }
            Self::Created { .. } | Self::Automatic { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn data_frame(&mut self, data: u64) {
        match self {
            Self::ReceivingHeaders {
                advertised_limit,
                requested_limit,
                known_limit,
                consumed,
            } => {
                // Figure 7 action A1: the DATA payload becomes known after its
                // frame header has already contributed to consumed raw bytes.
                let known_limit = (*known_limit).max(consumed.saturating_add(data));
                *self = Self::ReceivingData {
                    advertised_limit: *advertised_limit,
                    requested_limit: *requested_limit,
                    known_limit,
                    consumed: *consumed,
                    data_length: data,
                };
            }
            Self::ReceivingData {
                known_limit,
                consumed,
                data_length,
                ..
            } => {
                *data_length = data_length.saturating_add(data);
                *known_limit = (*known_limit).max(consumed.saturating_add(data));
            }
            Self::Automatic { data_length, .. } => {
                *data_length = data_length.saturating_add(data);
            }
            Self::Created { .. } | Self::Closed { .. } => {}
        }
    }

    pub fn bytes_read(&mut self, bytes: u64, excess: u64) {
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
                *known_limit = (*known_limit).max(consumed.saturating_add(excess));
            }
            Self::Automatic { consumed, .. } => *consumed = consumed.saturating_add(bytes),
            Self::Created { .. } | Self::Closed { .. } => {}
        }
    }

    pub const fn stream_data_blocked(&mut self, blocked_at: u64, increment: u64) {
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
            } if *requested_limit == *known_limit && *requested_limit == blocked_at => {
                *known_limit = known_limit.saturating_add(increment);
            }
            _ => {}
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
        let mut state = ReceiveState::controlled(16, 1_000, 0);
        assert_eq!(state.available(), 984);
        assert_eq!(state.release(600), Some((616, 600)));
        assert_eq!(state.available(), 384);
        state.advertised(616);
        assert_eq!(state.close(), (0, 0));
    }

    #[test]
    fn data_frame_discovers_payload_capacity() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.bytes_read(2, 100);
        state.data_frame(4_000);
        assert_eq!(state.available(), 3_986);
        assert_eq!(state.close(), (4_000, 0));
    }

    #[test]
    fn header_progress_prevents_large_header_deadlock() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.release(100);
        assert_eq!(state.available(), 0);
        state.bytes_read(100, 100);
        state.header_progress(2_000, 100);
        assert!(state.available() >= 1_900);
    }

    #[test]
    fn closing_reports_credit_not_yet_advertised() {
        let mut state = ReceiveState::controlled(16, 1_000, 0);
        state.release(500);
        assert_eq!(state.close(), (0, 500));
    }

    #[test]
    fn blocked_stream_adds_capacity_only_at_the_known_limit() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.release(100);
        assert_eq!(state.available(), 0);
        state.stream_data_blocked(99, 100);
        assert_eq!(state.available(), 0);
        state.stream_data_blocked(100, 100);
        assert_eq!(state.available(), 100);
    }

    #[test]
    fn multiple_data_frames_override_incorrect_content_length_safely() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.bytes_read(10, 100);
        state.response_headers(Some(1));
        state.bytes_read(2, 100);
        state.data_frame(600);
        state.bytes_read(602, 100);
        state.bytes_read(2, 100);
        state.data_frame(700);
        assert_eq!(state.close(), (1_300, 0));
    }

    #[test]
    fn partial_release_tracks_absolute_and_unadvertised_credit() {
        let mut state = ReceiveState::controlled(16, 1_000, 0);
        assert_eq!(state.release(250), Some((266, 250)));
        state.advertised(116);
        assert_eq!(state.close(), (0, 150));
    }

    #[test]
    fn automatic_stream_never_returns_scheduled_credit() {
        let mut state = ReceiveState::created(false, 16, 1_000, 0);
        state.open();
        state.data_frame(900);
        assert_eq!(state.close(), (900, 0));
    }

    #[test]
    fn figure_seven_content_length_is_an_absolute_limit() {
        let mut state = ReceiveState::controlled(16, 1_000, 0);
        state.bytes_read(40, 1_000);
        state.response_headers(Some(4_000));
        assert_eq!(state.available(), 3_984);
    }

    #[test]
    fn figure_seven_data_length_uses_consumed_raw_bytes() {
        let mut state = ReceiveState::controlled(16, 100, 0);
        state.bytes_read(42, 100);
        state.data_frame(900);
        assert_eq!(state.available(), 926);
        state.bytes_read(400, 100);
        assert_eq!(state.available(), 926);
    }
}
