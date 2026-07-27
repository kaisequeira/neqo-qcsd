// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::Duration;

use super::{Defense, DefenseMode};
use crate::{Direction, Packet, Result, Trace};

/// A fixed, sorted defense schedule.
#[derive(Debug)]
pub struct StaticSchedule {
    trace: Trace,
    mode: DefenseMode,
}

impl StaticSchedule {
    /// Create a schedule from an in-memory trace.
    #[must_use]
    pub const fn new(trace: Trace, padding_only: bool) -> Self {
        Self {
            trace,
            mode: if padding_only {
                DefenseMode::ChaffOnly
            } else {
                DefenseMode::ChaffAndShape
            },
        }
    }

    /// Create a schedule with an explicit defense mode.
    #[must_use]
    pub const fn with_mode(trace: Trace, mode: DefenseMode) -> Self {
        Self { trace, mode }
    }

    /// Load the published `seconds,signed_size` schedule format.
    ///
    /// # Errors
    ///
    /// Returns an error when the schedule file cannot be read or parsed.
    pub fn from_legacy_csv<P: AsRef<std::path::Path>>(path: P, padding_only: bool) -> Result<Self> {
        Ok(Self::new(Trace::from_legacy_csv(path)?, padding_only))
    }
}

impl Defense for StaticSchedule {
    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        self.trace
            .front()
            .copied()
            .filter(|packet| packet.timestamp() <= elapsed)?;
        self.trace.pop_front()
    }

    fn next_event_at(&self) -> Option<Duration> {
        self.trace.front().map(|packet| packet.timestamp())
    }

    fn is_complete(&self) -> bool {
        self.trace.is_empty()
    }

    fn is_outgoing_complete(&self) -> bool {
        !self
            .trace
            .iter()
            .any(|packet| packet.direction() == Direction::Outgoing)
    }

    fn mode(&self) -> DefenseMode {
        self.mode
    }

    fn on_application_complete(&mut self) {}
}
