// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::Duration;

use super::{Defense, DefenseMode};
use crate::{Direction, Packet, TamarawConfig};

/// Tamaraw constant-rate bidirectional defense.
#[derive(Debug)]
pub struct Tamaraw {
    incoming_interval_us: u64,
    outgoing_interval_us: u64,
    packet_size: u16,
    modulo: u32,
    next_incoming_us: u64,
    next_outgoing_us: u64,
    incoming_count: u64,
    outgoing_count: u64,
    final_incoming_count: Option<u64>,
    final_outgoing_count: Option<u64>,
}

impl Tamaraw {
    /// Construct a Tamaraw schedule from validated configuration.
    #[must_use]
    pub const fn new(config: &TamarawConfig) -> Self {
        Self {
            incoming_interval_us: config.incoming_interval_us,
            outgoing_interval_us: config.outgoing_interval_us,
            packet_size: config.packet_size,
            modulo: config.modulo,
            next_incoming_us: 0,
            next_outgoing_us: 0,
            incoming_count: 0,
            outgoing_count: 0,
            final_incoming_count: None,
            final_outgoing_count: None,
        }
    }

    fn direction_complete(&self, direction: Direction) -> bool {
        match direction {
            Direction::Incoming => self
                .final_incoming_count
                .is_some_and(|final_count| self.incoming_count >= final_count),
            Direction::Outgoing => self
                .final_outgoing_count
                .is_some_and(|final_count| self.outgoing_count >= final_count),
        }
    }

    fn pop_direction(&mut self, elapsed_us: u64, direction: Direction) -> Option<Packet> {
        if self.direction_complete(direction) {
            return None;
        }
        let (next_us, interval_us, count) = match direction {
            Direction::Incoming => (
                &mut self.next_incoming_us,
                self.incoming_interval_us,
                &mut self.incoming_count,
            ),
            Direction::Outgoing => (
                &mut self.next_outgoing_us,
                self.outgoing_interval_us,
                &mut self.outgoing_count,
            ),
        };
        if *next_us > elapsed_us {
            return None;
        }
        let packet =
            Packet::new(Duration::from_micros(*next_us), direction, self.packet_size).ok()?;
        *next_us = next_us.saturating_add(interval_us);
        *count = count.saturating_add(1);
        Some(packet)
    }

    fn rounded_final_count(&self, count: u64) -> u64 {
        let modulo = u64::from(self.modulo);
        let remainder = count % modulo;
        if remainder == 0 {
            count.saturating_add(modulo)
        } else {
            count.saturating_add(modulo - remainder)
        }
    }
}

impl Defense for Tamaraw {
    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let first = if self.next_outgoing_us <= self.next_incoming_us {
            Direction::Outgoing
        } else {
            Direction::Incoming
        };
        self.pop_direction(elapsed_us, first).or_else(|| {
            self.pop_direction(
                elapsed_us,
                match first {
                    Direction::Outgoing => Direction::Incoming,
                    Direction::Incoming => Direction::Outgoing,
                },
            )
        })
    }

    fn next_event_at(&self) -> Option<Duration> {
        if self.is_complete() {
            return None;
        }
        let incoming =
            (!self.direction_complete(Direction::Incoming)).then_some(self.next_incoming_us);
        let outgoing =
            (!self.direction_complete(Direction::Outgoing)).then_some(self.next_outgoing_us);
        incoming
            .into_iter()
            .chain(outgoing)
            .min()
            .map(Duration::from_micros)
    }

    fn is_complete(&self) -> bool {
        self.direction_complete(Direction::Incoming) && self.direction_complete(Direction::Outgoing)
    }

    fn is_outgoing_complete(&self) -> bool {
        self.direction_complete(Direction::Outgoing)
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffAndShape
    }

    fn on_application_complete(&mut self) {
        if self.final_incoming_count.is_none() {
            self.final_incoming_count = Some(self.rounded_final_count(self.incoming_count));
            self.final_outgoing_count = Some(self.rounded_final_count(self.outgoing_count));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Tamaraw;
    use crate::TamarawConfig;

    #[test]
    fn exact_modulo_boundary_adds_one_published_padding_block() {
        let defense = Tamaraw::new(&TamarawConfig {
            modulo: 4,
            ..TamarawConfig::default()
        });
        assert_eq!(defense.rounded_final_count(4), 8);
        assert_eq!(defense.rounded_final_count(5), 8);
    }
}
