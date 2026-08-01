// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::Duration;

use super::{Defense, DefenseMode, DefenseSignal, StaticSchedule};
use crate::{Direction, FrontConfig, Packet, SplitMix64, Trace};

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
            schedule: StaticSchedule::with_mode(Trace::new(packets), DefenseMode::ChaffOnly),
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
            let seconds = rayleigh_seconds(rng.unit_open(), sigma);
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

fn rayleigh_seconds(unit: f64, sigma: f64) -> f64 {
    sigma * (-2.0 * (1.0 - unit).ln()).sqrt()
}

impl Defense for Front {
    fn observe(&mut self, _signal: DefenseSignal) {}

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        self.schedule.next_event(elapsed)
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

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffOnly
    }
}

#[cfg(test)]
mod tests {
    use super::rayleigh_seconds;

    #[test]
    fn rayleigh_inverse_matches_the_published_transform() {
        let unit = 1.0 - (-0.5_f64).exp();
        assert!((rayleigh_seconds(unit, 2.5) - 2.5).abs() < f64::EPSILON * 4.0);
    }
}
