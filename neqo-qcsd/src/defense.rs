// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{fmt::Debug, time::Duration};

use crate::{Direction, FrontConfig, Packet, QcsdEndpointId, Result, TamarawConfig, Trace};

/// Available application/chaff capacity used to satisfy an incoming slot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capacity {
    /// Bytes available from application response streams.
    pub application_incoming: u64,
    /// Bytes available from chaff response streams.
    pub chaff_incoming: u64,
    /// Bytes already assigned during this control interval.
    pub incoming_used: u64,
}

impl Capacity {
    /// Remaining incoming bytes available to a defense event.
    #[must_use]
    pub const fn available(self, padding_only: bool) -> u64 {
        let total = if padding_only {
            self.chaff_incoming
        } else {
            self.application_incoming
                .saturating_add(self.chaff_incoming)
        };
        total.saturating_sub(self.incoming_used)
    }
}

/// Stateful generator for a QCSD packet schedule.
pub trait Defense: Debug {
    /// Return the next event at or before `elapsed`.
    fn next_event(&mut self, elapsed: Duration, capacity: Capacity) -> Option<Packet>;
    /// Time of the next event relative to defense start.
    fn next_event_at(&self) -> Option<Duration>;
    /// Whether no events remain.
    fn is_complete(&self) -> bool;
    /// Whether no outgoing events remain.
    fn is_outgoing_complete(&self) -> bool;
    /// Whether incoming capacity may be drawn only from chaff streams.
    fn is_padding_only(&self) -> bool;
    /// Notify the defense that all application requests completed.
    fn on_application_complete(&mut self);
}

/// A fixed, sorted defense schedule.
#[derive(Debug)]
pub struct StaticSchedule {
    trace: Trace,
    padding_only: bool,
}

impl StaticSchedule {
    /// Create a schedule from an in-memory trace.
    #[must_use]
    pub const fn new(trace: Trace, padding_only: bool) -> Self {
        Self {
            trace,
            padding_only,
        }
    }

    /// Load the published `seconds,signed_size` schedule format.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or a record is invalid.
    pub fn from_legacy_csv<P: AsRef<std::path::Path>>(path: P, padding_only: bool) -> Result<Self> {
        Ok(Self::new(Trace::from_legacy_csv(path)?, padding_only))
    }
}

impl Defense for StaticSchedule {
    fn next_event(&mut self, elapsed: Duration, _capacity: Capacity) -> Option<Packet> {
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

    fn is_padding_only(&self) -> bool {
        self.padding_only
    }

    fn on_application_complete(&mut self) {}
}

/// Version-stable PRNG used to keep research traces reproducible.
#[derive(Clone, Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn range_inclusive(&mut self, maximum: u32) -> u32 {
        let range = u64::from(maximum);
        let rejection = u64::MAX - (u64::MAX % range);
        loop {
            let value = self.next_u64();
            if value < rejection {
                return u32::try_from(value % range).expect("bounded by u32") + 1;
            }
        }
    }

    fn unit_open(&mut self) -> f64 {
        // Use 53 significant bits and exclude both endpoints.
        let value = self.next_u64() >> 11;
        let high = u32::try_from(value >> 32).expect("21 high bits fit u32");
        let low = u32::try_from(value & u64::from(u32::MAX)).expect("32 low bits fit u32");
        let value = f64::from(high).mul_add(4_294_967_296.0, f64::from(low));
        (value + 0.5) / 9_007_199_254_740_992.0
    }

    fn range_f64(&mut self, minimum: f64, maximum: f64) -> f64 {
        self.unit_open().mul_add(maximum - minimum, minimum)
    }
}

/// FRONT chaff-only defense using Rayleigh-distributed packet times.
#[derive(Debug)]
pub struct Front {
    schedule: StaticSchedule,
}

impl Front {
    /// Generate a deterministic FRONT schedule.
    #[must_use]
    pub fn new(config: &FrontConfig, seed: u64) -> Self {
        let mut rng = SplitMix64::new(seed);
        let mut packets = Vec::new();
        Self::sample_direction(
            &mut packets,
            &mut rng,
            config,
            config.n_server_packets,
            Direction::Incoming,
        );
        Self::sample_direction(
            &mut packets,
            &mut rng,
            config,
            config.n_client_packets,
            Direction::Outgoing,
        );
        Self {
            schedule: StaticSchedule::new(Trace::new(packets), true),
        }
    }

    fn sample_direction(
        packets: &mut Vec<Packet>,
        rng: &mut SplitMix64,
        config: &FrontConfig,
        maximum: u32,
        direction: Direction,
    ) {
        let count = rng.range_inclusive(maximum);
        let sigma = rng.range_f64(config.peak_minimum_seconds, config.peak_maximum_seconds);
        for _ in 0..count {
            let seconds = sigma * (-2.0 * (1.0 - rng.unit_open()).ln()).sqrt();
            packets.push(
                Packet::new(
                    Duration::from_secs_f64(seconds),
                    direction,
                    config.packet_size,
                )
                .expect("validated FRONT configuration"),
            );
        }
    }
}

impl Defense for Front {
    fn next_event(&mut self, elapsed: Duration, capacity: Capacity) -> Option<Packet> {
        self.schedule.next_event(elapsed, capacity)
    }

    fn next_event_at(&self) -> Option<Duration> {
        self.schedule.next_event_at()
    }

    fn is_complete(&self) -> bool {
        self.schedule.is_complete()
    }

    fn is_outgoing_complete(&self) -> bool {
        self.schedule.is_outgoing_complete()
    }

    fn is_padding_only(&self) -> bool {
        true
    }

    fn on_application_complete(&mut self) {}
}

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
        let packet = Packet::new(Duration::from_micros(*next_us), direction, self.packet_size)
            .expect("validated Tamaraw configuration");
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
    fn next_event(&mut self, elapsed: Duration, _capacity: Capacity) -> Option<Packet> {
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

    fn is_padding_only(&self) -> bool {
        false
    }

    fn on_application_complete(&mut self) {
        if self.final_incoming_count.is_none() {
            self.final_incoming_count = Some(self.rounded_final_count(self.incoming_count));
            self.final_outgoing_count = Some(self.rounded_final_count(self.outgoing_count));
        }
    }
}

/// Round-robin assignment of one defense schedule to several connections.
#[derive(Debug)]
pub struct SharedDefense {
    defense: Box<dyn Defense>,
    endpoints: Vec<QcsdEndpointId>,
    cursor: usize,
}

impl SharedDefense {
    /// Wrap a defense and its participating endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error when no endpoint participates in the shared defense.
    pub fn new(defense: Box<dyn Defense>, endpoints: Vec<QcsdEndpointId>) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(crate::Error::InvalidConfig(
                "a shared defense requires at least one endpoint".into(),
            ));
        }
        Ok(Self {
            defense,
            endpoints,
            cursor: 0,
        })
    }

    /// Return the next due packet and the endpoint assigned to it.
    pub fn next_for(
        &mut self,
        elapsed: Duration,
        capacity: Capacity,
    ) -> Option<(QcsdEndpointId, Packet)> {
        let packet = self.defense.next_event(elapsed, capacity)?;
        let endpoint = self.endpoints[self.cursor];
        self.cursor = (self.cursor + 1) % self.endpoints.len();
        Some((endpoint, packet))
    }

    /// Remove a closed endpoint without disturbing the relative order of survivors.
    pub fn remove_endpoint(&mut self, endpoint: QcsdEndpointId) {
        if let Some(index) = self
            .endpoints
            .iter()
            .position(|candidate| *candidate == endpoint)
        {
            self.endpoints.remove(index);
            if self.endpoints.is_empty() {
                self.cursor = 0;
            } else if index < self.cursor || self.cursor == self.endpoints.len() {
                self.cursor = self.cursor.saturating_sub(1) % self.endpoints.len();
            }
        }
    }

    /// Whether the underlying defense is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.defense.is_complete()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Capacity, Defense as _, Front, SharedDefense, StaticSchedule, Tamaraw};
    use crate::{Direction, FrontConfig, Packet, QcsdEndpointId, TamarawConfig, Trace};

    #[test]
    fn static_schedule_preserves_legacy_order() {
        let trace = Trace::new([
            Packet::from_legacy(10, 1_500).expect("valid"),
            Packet::from_legacy(0, -300).expect("valid"),
            Packet::from_legacy(0, 150).expect("valid"),
        ]);
        let mut schedule = StaticSchedule::new(trace, true);
        assert_eq!(
            schedule
                .next_event(Duration::from_millis(1), Capacity::default())
                .map(Packet::signed_length),
            Some(150)
        );
        assert_eq!(
            schedule
                .next_event(Duration::from_millis(1), Capacity::default())
                .map(Packet::signed_length),
            Some(-300)
        );
    }

    #[test]
    fn front_is_seed_reproducible() {
        let config = FrontConfig {
            n_client_packets: 20,
            n_server_packets: 20,
            ..FrontConfig::default()
        };
        let mut left = Front::new(&config, 42);
        let mut right = Front::new(&config, 42);
        for millisecond in 0..10_000 {
            let elapsed = Duration::from_millis(millisecond);
            assert_eq!(
                left.next_event(elapsed, Capacity::default()),
                right.next_event(elapsed, Capacity::default())
            );
        }
    }

    #[test]
    fn tamaraw_rounds_each_direction_to_modulo() {
        let config = TamarawConfig {
            incoming_interval_us: 5_000,
            outgoing_interval_us: 20_000,
            packet_size: 1_200,
            modulo: 4,
        };
        let mut defense = Tamaraw::new(&config);
        let mut incoming = 0;
        let mut outgoing = 0;
        for _ in 0..7 {
            match defense.next_event(Duration::from_millis(21), Capacity::default()) {
                Some(packet) if packet.direction() == Direction::Incoming => incoming += 1,
                Some(_) => outgoing += 1,
                None => panic!("a Tamaraw slot should be due"),
            }
        }
        defense.on_application_complete();
        while let Some(packet) = defense.next_event(Duration::from_secs(1), Capacity::default()) {
            match packet.direction() {
                Direction::Incoming => incoming += 1,
                Direction::Outgoing => outgoing += 1,
            }
        }
        assert!(defense.is_complete());
        assert_eq!(incoming % 4, 0);
        assert_eq!(outgoing % 4, 0);
    }

    #[test]
    fn shared_schedule_is_round_robin() {
        let trace = Trace::new([
            Packet::from_legacy(0, 100).expect("valid"),
            Packet::from_legacy(1, 100).expect("valid"),
        ]);
        let mut shared = SharedDefense::new(
            Box::new(StaticSchedule::new(trace, true)),
            vec![QcsdEndpointId(4), QcsdEndpointId(8)],
        )
        .expect("endpoints");
        assert_eq!(
            shared.next_for(Duration::from_secs(1), Capacity::default()),
            Some((
                QcsdEndpointId(4),
                Packet::from_legacy(0, 100).expect("valid")
            ))
        );
        assert_eq!(
            shared.next_for(Duration::from_secs(1), Capacity::default()),
            Some((
                QcsdEndpointId(8),
                Packet::from_legacy(1, 100).expect("valid")
            ))
        );
    }
}
