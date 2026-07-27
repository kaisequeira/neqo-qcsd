// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize};

use crate::Packet;

/// Whether a defense adds cover traffic or regulates the whole application.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseMode {
    /// Application traffic remains automatic; scheduled capacity is chaff-only.
    ChaffOnly,
    /// Application and chaff traffic are shaped toward the schedule.
    ChaffAndShape,
}

/// Stateful generator for a QCSD packet schedule.
///
/// A defense describes *what* should happen. Endpoint capacity, flow-control
/// releases, and packet construction are controller/adapter responsibilities.
pub trait Defense: Debug {
    /// Return the next event at or before `elapsed`.
    fn next_event(&mut self, elapsed: Duration) -> Option<Packet>;
    /// Time of the next event relative to defense start.
    fn next_event_at(&self) -> Option<Duration>;
    /// Whether no events remain.
    fn is_complete(&self) -> bool;
    /// Whether no outgoing events remain.
    fn is_outgoing_complete(&self) -> bool;
    /// How application traffic participates in the schedule.
    fn mode(&self) -> DefenseMode;
    /// Notify the defense that all application requests completed.
    fn on_application_complete(&mut self);
}
