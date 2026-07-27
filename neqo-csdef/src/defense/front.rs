// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::Duration;

use super::{Defense, DefenseMode, StaticSchedule};
use crate::{Direction, FrontConfig, Packet, Trace};

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

    fn on_application_complete(&mut self) {}
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
