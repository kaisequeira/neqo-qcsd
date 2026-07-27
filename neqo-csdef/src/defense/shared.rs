// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use super::DefenseMode;
use crate::{QcsdEndpointId, Result};

/// Receive capacity reported for one endpoint during one control interval.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capacity {
    /// Bytes available from application response streams.
    pub application_incoming: u64,
    /// Bytes available from chaff response streams.
    pub chaff_incoming: u64,
}

impl Capacity {
    /// Remaining incoming bytes usable in the selected defense mode.
    #[must_use]
    pub const fn available(self, mode: DefenseMode) -> u64 {
        match mode {
            DefenseMode::ChaffOnly => self.chaff_incoming,
            DefenseMode::ChaffAndShape => self
                .application_incoming
                .saturating_add(self.chaff_incoming),
        }
    }
}

/// Deterministic single-owner equivalent of the published shared defense.
#[derive(Clone, Debug)]
pub struct RoundRobinScheduler {
    endpoints: Vec<QcsdEndpointId>,
    outgoing_cursor: usize,
    incoming_cursor: usize,
}

impl RoundRobinScheduler {
    /// Create a scheduler in stable endpoint order.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint is supplied.
    pub fn new(endpoints: Vec<QcsdEndpointId>) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(crate::Error::InvalidConfig(
                "a shared defense requires at least one endpoint".into(),
            ));
        }
        Ok(Self {
            endpoints,
            outgoing_cursor: 0,
            incoming_cursor: 0,
        })
    }

    /// Empty scheduler used before connections become ready.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            endpoints: Vec::new(),
            outgoing_cursor: 0,
            incoming_cursor: 0,
        }
    }

    /// Add an endpoint once, retaining insertion order.
    pub fn add_endpoint(&mut self, endpoint: QcsdEndpointId) {
        if !self.endpoints.contains(&endpoint) {
            self.endpoints.push(endpoint);
        }
    }

    /// Remove a closed endpoint while preserving survivor order and cursors.
    pub fn remove_endpoint(&mut self, endpoint: QcsdEndpointId) {
        let Some(index) = self
            .endpoints
            .iter()
            .position(|candidate| *candidate == endpoint)
        else {
            return;
        };
        self.endpoints.remove(index);
        Self::adjust_cursor(&mut self.outgoing_cursor, index, self.endpoints.len());
        Self::adjust_cursor(&mut self.incoming_cursor, index, self.endpoints.len());
    }

    const fn adjust_cursor(cursor: &mut usize, removed: usize, remaining: usize) {
        if remaining == 0 {
            *cursor = 0;
        } else if removed < *cursor || *cursor == remaining {
            *cursor = cursor.saturating_sub(1) % remaining;
        }
    }

    /// Select the next endpoint for an outgoing event.
    pub fn next_outgoing(&mut self) -> Option<QcsdEndpointId> {
        let endpoint = *self.endpoints.get(self.outgoing_cursor)?;
        self.outgoing_cursor = (self.outgoing_cursor + 1) % self.endpoints.len();
        Some(endpoint)
    }

    /// Select one endpoint for an incoming event.
    ///
    /// The boolean indicates whether the selected endpoint has enough capacity
    /// for the entire event. After one full round, the current endpoint is
    /// returned as the published fallback so partial work can become backlog.
    pub fn next_incoming<F>(
        &mut self,
        required: u64,
        mode: DefenseMode,
        mut capacity: F,
    ) -> Option<(QcsdEndpointId, bool)>
    where
        F: FnMut(QcsdEndpointId) -> Capacity,
    {
        if self.endpoints.is_empty() {
            return None;
        }
        let start = self.incoming_cursor;
        for offset in 0..self.endpoints.len() {
            let index = (start + offset) % self.endpoints.len();
            let endpoint = self.endpoints[index];
            let endpoint_capacity = capacity(endpoint);
            let available = endpoint_capacity.available(mode);
            // The published shared defense assigns a fresh incoming event to
            // the first connection with application capacity, even when that
            // capacity is smaller than the slot. This prevents an abundant
            // chaff stream on another connection from starving a partially
            // delivered application response.
            if mode == DefenseMode::ChaffAndShape && endpoint_capacity.application_incoming > 0 {
                self.incoming_cursor = (index + 1) % self.endpoints.len();
                return Some((endpoint, available >= required));
            }
            if available >= required {
                self.incoming_cursor = (index + 1) % self.endpoints.len();
                return Some((endpoint, true));
            }
        }
        let endpoint = self.endpoints[start];
        self.incoming_cursor = (start + 1) % self.endpoints.len();
        Some((endpoint, false))
    }

    /// Endpoints in deterministic scheduling order.
    #[must_use]
    pub fn endpoints(&self) -> &[QcsdEndpointId] {
        &self.endpoints
    }
}
