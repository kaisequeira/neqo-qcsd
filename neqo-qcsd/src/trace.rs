// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cmp::Ordering, collections::VecDeque, fmt::Write as _, fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Direction of a scheduled or observed UDP datagram.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Traffic transmitted by the protected client.
    Outgoing,
    /// Traffic received by the protected client.
    Incoming,
}

/// One defense schedule slot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Packet {
    timestamp_us: u64,
    direction: Direction,
    length: u16,
}

impl Packet {
    /// Construct a non-empty schedule slot.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero length or an unrepresentable timestamp.
    pub fn new(timestamp: Duration, direction: Direction, length: u16) -> Result<Self> {
        if length == 0 {
            return Err(Error::InvalidConfig(
                "scheduled packet length must be greater than zero".into(),
            ));
        }
        let timestamp_us = u64::try_from(timestamp.as_micros()).map_err(|_| {
            Error::InvalidConfig("scheduled packet timestamp exceeds u64 microseconds".into())
        })?;
        Ok(Self {
            timestamp_us,
            direction,
            length,
        })
    }

    /// Construct a slot from the legacy `(milliseconds, signed length)` form.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or out-of-range packet sizes.
    pub fn from_legacy(timestamp_ms: u64, signed_length: i32) -> Result<Self> {
        let direction = match signed_length.cmp(&0) {
            Ordering::Greater => Direction::Outgoing,
            Ordering::Less => Direction::Incoming,
            Ordering::Equal => {
                return Err(Error::InvalidConfig(
                    "scheduled packet length must not be zero".into(),
                ));
            }
        };
        let length = u16::try_from(signed_length.unsigned_abs())
            .map_err(|_| Error::InvalidConfig("scheduled packet length exceeds u16".into()))?;
        Self::new(Duration::from_millis(timestamp_ms), direction, length)
    }

    /// Time relative to the defense start.
    #[must_use]
    pub const fn timestamp_us(self) -> u64 {
        self.timestamp_us
    }

    /// Time relative to the defense start.
    #[must_use]
    pub const fn timestamp(self) -> Duration {
        Duration::from_micros(self.timestamp_us)
    }

    /// Scheduled traffic direction.
    #[must_use]
    pub const fn direction(self) -> Direction {
        self.direction
    }

    /// Scheduled UDP payload or receive-credit amount.
    #[must_use]
    pub const fn length(self) -> u16 {
        self.length
    }

    /// Legacy signed length, with incoming traffic represented as negative.
    #[must_use]
    pub const fn signed_length(self) -> i32 {
        match self.direction {
            Direction::Outgoing => self.length as i32,
            Direction::Incoming => -(self.length as i32),
        }
    }
}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        let direction_order = |direction| match direction {
            Direction::Outgoing => 0_u8,
            Direction::Incoming => 1_u8,
        };
        (
            self.timestamp_us,
            direction_order(self.direction),
            self.length,
        )
            .cmp(&(
                other.timestamp_us,
                direction_order(other.direction),
                other.length,
            ))
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Sorted sequence of scheduled packets.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Trace(VecDeque<Packet>);

impl Trace {
    /// Sort a packet sequence into deterministic schedule order.
    #[must_use]
    pub fn new<I: IntoIterator<Item = Packet>>(packets: I) -> Self {
        let mut packets: Vec<_> = packets.into_iter().collect();
        packets.sort_unstable();
        Self(packets.into())
    }

    /// Parse the published `seconds,signed_size` CSV format.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or a record is invalid.
    pub fn from_legacy_csv<P: AsRef<Path>>(path: P) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_legacy_csv_str(&input)
    }

    /// Parse the published `seconds,signed_size` CSV format from memory.
    ///
    /// # Errors
    ///
    /// Returns an error identifying the first malformed record.
    pub fn from_legacy_csv_str(input: &str) -> Result<Self> {
        let mut packets = Vec::new();
        for (index, raw_line) in input.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (seconds, signed_length) =
                line.split_once(',').ok_or_else(|| Error::InvalidSchedule {
                    line: index + 1,
                    message: "expected seconds,signed_size".into(),
                })?;
            let seconds: f64 = seconds.trim().parse().map_err(|_| Error::InvalidSchedule {
                line: index + 1,
                message: "timestamp is not a number".into(),
            })?;
            if !seconds.is_finite() || seconds < 0.0 {
                return Err(Error::InvalidSchedule {
                    line: index + 1,
                    message: "timestamp must be finite and non-negative".into(),
                });
            }
            let signed_length: i32 =
                signed_length
                    .trim()
                    .parse()
                    .map_err(|_| Error::InvalidSchedule {
                        line: index + 1,
                        message: "signed_size is not a 32-bit integer".into(),
                    })?;
            let timestamp = Duration::from_secs_f64(seconds);
            let packet = Packet::new(
                timestamp,
                match signed_length.cmp(&0) {
                    Ordering::Greater => Direction::Outgoing,
                    Ordering::Less => Direction::Incoming,
                    Ordering::Equal => {
                        return Err(Error::InvalidSchedule {
                            line: index + 1,
                            message: "signed_size must not be zero".into(),
                        });
                    }
                },
                u16::try_from(signed_length.unsigned_abs()).map_err(|_| {
                    Error::InvalidSchedule {
                        line: index + 1,
                        message: "absolute packet size exceeds 65535".into(),
                    }
                })?,
            )?;
            packets.push(packet);
        }
        Ok(Self::new(packets))
    }

    /// Serialize using the legacy schedule format.
    #[must_use]
    pub fn to_legacy_csv(&self) -> String {
        let mut output = String::new();
        for packet in &self.0 {
            writeln!(
                output,
                "{:.6},{}",
                packet.timestamp().as_secs_f64(),
                packet.signed_length()
            )
            .expect("writing to a String cannot fail");
        }
        output
    }

    /// Remove and return the earliest packet.
    pub fn pop_front(&mut self) -> Option<Packet> {
        self.0.pop_front()
    }

    /// Inspect the earliest packet.
    #[must_use]
    pub fn front(&self) -> Option<&Packet> {
        self.0.front()
    }

    /// Whether no scheduled packets remain.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of scheduled packets remaining.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate in schedule order.
    pub fn iter(&self) -> impl Iterator<Item = &Packet> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Direction, Packet, Trace};

    #[test]
    fn legacy_csv_is_sorted_and_round_trips() {
        let trace =
            Trace::from_legacy_csv_str("0.010000,1500\n0,-300\n0,150\n").expect("valid trace");
        assert_eq!(trace.len(), 3);
        assert_eq!(
            trace.front().map(|packet| packet.signed_length()),
            Some(150)
        );
        assert_eq!(
            Trace::from_legacy_csv_str(&trace.to_legacy_csv()).expect("round trip"),
            trace
        );
    }

    #[test]
    fn outgoing_sorts_before_incoming_at_same_time() {
        let trace = Trace::new([
            Packet::new(Duration::ZERO, Direction::Incoming, 300).expect("valid"),
            Packet::new(Duration::ZERO, Direction::Outgoing, 150).expect("valid"),
        ]);
        assert_eq!(
            trace.front().map(|packet| packet.direction()),
            Some(Direction::Outgoing)
        );
    }
}
