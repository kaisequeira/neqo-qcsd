// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::Duration;

use super::{Defense, DefenseMode, DefenseSignal, SignalKind};
use crate::{Direction, Packet, QcsdSlotId, TamarawConfig};

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
    terminal_primary_partial: Option<QcsdSlotId>,
    terminal_primary_partial_failed: bool,
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
            terminal_primary_partial: None,
            terminal_primary_partial_failed: false,
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
    fn observe(&mut self, signal: DefenseSignal) {
        if let SignalKind::TerminalPrimaryPartial {
            slot,
            packet,
            consumed,
            retired,
        } = signal.kind
        {
            if self.terminal_primary_partial.is_some()
                || packet.timestamp() > signal.at
                || packet.timestamp_us() / self.incoming_interval_us >= self.incoming_count
                || !packet
                    .timestamp_us()
                    .is_multiple_of(self.incoming_interval_us)
                || !super::traits::terminal_primary_partial_split_valid(
                    packet,
                    self.packet_size,
                    consumed,
                    retired,
                )
            {
                self.terminal_primary_partial_failed = true;
            } else {
                self.terminal_primary_partial = Some(slot);
            }
        }
        if matches!(signal.kind, SignalKind::ApplicationComplete)
            && self.final_incoming_count.is_none()
        {
            self.final_incoming_count = Some(self.rounded_final_count(self.incoming_count));
            self.final_outgoing_count = Some(self.rounded_final_count(self.outgoing_count));
        }
    }

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
        !self.terminal_primary_partial_failed
            && self.direction_complete(Direction::Incoming)
            && self.direction_complete(Direction::Outgoing)
    }

    fn is_outgoing_complete(&self) -> bool {
        self.direction_complete(Direction::Outgoing)
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffAndShape
    }

    fn terminal_failure(&self) -> Option<&'static str> {
        self.terminal_primary_partial_failed
            .then_some("Tamaraw received an invalid terminal-primary partial signal")
    }
}

#[cfg(test)]
mod tests {
    use super::Tamaraw;
    use crate::TamarawConfig;

    #[test]
    fn terminal_primary_partial_preserves_scheduled_padding_and_is_not_a_full_cell() {
        use crate::{Defense as _, DefenseSignal, Direction, QcsdSlotId, SignalKind};
        use std::time::Duration;
        let mut defense = Tamaraw::new(&TamarawConfig {
            modulo: 1,
            packet_size: 1_200,
            ..TamarawConfig::default()
        });
        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing");
        assert_eq!(outgoing.direction(), Direction::Outgoing);
        let incoming = defense.next_event(Duration::ZERO).expect("incoming");
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::TerminalPrimaryPartial {
                slot: QcsdSlotId(1),
                packet: incoming,
                consumed: 1_199,
                retired: 1,
            },
        });
        assert_eq!(defense.incoming_count, 1);
        assert!(defense.terminal_failure().is_none());
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ApplicationComplete,
        });
        assert_eq!(defense.final_incoming_count, Some(2));
        assert!(!defense.is_complete());
        while defense.next_event(Duration::from_micros(20_000)).is_some() {}
        assert!(defense.is_complete());
        assert_eq!(defense.incoming_count, 2);
        assert_eq!(defense.terminal_primary_partial, Some(QcsdSlotId(1)));
    }

    #[test]
    fn terminal_primary_partial_rejects_bad_split_and_duplicate_without_changing_legacy_signals() {
        use crate::{
            Defense as _, DefenseSignal, EventOutcome, MissedSlotReason, QcsdSlotId, SignalKind,
        };
        use std::time::Duration;
        for invalid in 0..4 {
            let mut defense = Tamaraw::new(&TamarawConfig {
                packet_size: 1_200,
                ..TamarawConfig::default()
            });
            defense.next_event(Duration::ZERO).expect("outgoing");
            let packet = defense.next_event(Duration::ZERO).expect("incoming");
            let signal = SignalKind::TerminalPrimaryPartial {
                slot: QcsdSlotId(1),
                packet,
                consumed: if invalid == 0 { 0 } else { 1_199 },
                retired: if invalid == 1 { 2 } else { 1 },
            };
            if invalid == 3 {
                defense.observe(DefenseSignal {
                    at: Duration::ZERO,
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Missed(MissedSlotReason::ReceiveCreditRetired),
                    },
                });
                assert!(
                    defense.terminal_failure().is_none(),
                    "legacy generic resolution semantics"
                );
                assert!(defense.terminal_primary_partial.is_none());
            } else {
                defense.observe(DefenseSignal {
                    at: Duration::ZERO,
                    kind: signal,
                });
                if invalid == 2 {
                    defense.observe(DefenseSignal {
                        at: Duration::ZERO,
                        kind: signal,
                    });
                }
                assert!(defense.terminal_failure().is_some(), "invalid {invalid}");
            }
        }
    }

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
