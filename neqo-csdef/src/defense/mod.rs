// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Defense schedule generators and shared endpoint scheduling.
//!
//! This mirrors the published `neqo-csdef/src/defences` boundary: a
//! [`Defense`] generates a transport-independent packet schedule, while the
//! controller decides which connection and stream can enact each event.

mod front;
mod shared;
mod static_schedule;
mod tamaraw;
mod traits;

pub use front::Front;
pub use shared::{Capacity, RoundRobinScheduler};
pub use static_schedule::StaticSchedule;
pub use tamaraw::Tamaraw;
pub use traits::{Defense, DefenseMode};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        Capacity, Defense as _, DefenseMode, Front, RoundRobinScheduler, StaticSchedule, Tamaraw,
    };
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
                .next_event(Duration::from_millis(1))
                .map(Packet::signed_length),
            Some(150)
        );
        assert_eq!(
            schedule
                .next_event(Duration::from_millis(1))
                .map(Packet::signed_length),
            Some(-300)
        );
    }

    #[test]
    fn static_schedule_preserves_exact_microsecond_sequence() {
        let trace = Trace::new([
            Packet::new(Duration::from_micros(3), Direction::Incoming, 333).expect("packet"),
            Packet::new(Duration::from_micros(1), Direction::Incoming, 222).expect("packet"),
            Packet::new(Duration::from_micros(1), Direction::Outgoing, 111).expect("packet"),
            Packet::new(Duration::from_micros(2), Direction::Outgoing, 444).expect("packet"),
        ]);
        let mut schedule = StaticSchedule::new(trace, false);
        let mut actual = Vec::new();
        for elapsed_us in 0..=3 {
            while let Some(packet) = schedule.next_event(Duration::from_micros(elapsed_us)) {
                actual.push((packet.timestamp_us(), packet.direction(), packet.length()));
            }
        }
        assert_eq!(
            actual,
            [
                (1, Direction::Outgoing, 111),
                (1, Direction::Incoming, 222),
                (2, Direction::Outgoing, 444),
                (3, Direction::Incoming, 333),
            ]
        );
        assert!(schedule.is_complete());
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
            assert_eq!(left.next_event(elapsed), right.next_event(elapsed));
        }
    }

    #[test]
    fn front_fixed_seed_has_a_golden_trace() {
        let config = FrontConfig {
            n_client_packets: 4,
            n_server_packets: 5,
            packet_size: 1_234,
            peak_minimum_seconds: 0.1,
            peak_maximum_seconds: 0.2,
        };
        let mut front = Front::new(&config, 42);
        let mut actual = Vec::new();
        while let Some(packet) = front.next_event(Duration::MAX) {
            actual.push((packet.timestamp_us(), packet.direction(), packet.length()));
        }
        assert_eq!(
            actual,
            [
                (32_299, Direction::Incoming, 1_234),
                (93_739, Direction::Incoming, 1_234),
                (106_545, Direction::Incoming, 1_234),
                (164_126, Direction::Outgoing, 1_234),
                (233_524, Direction::Incoming, 1_234),
                (249_969, Direction::Outgoing, 1_234),
            ]
        );
        assert!(front.is_complete());
    }

    #[test]
    fn front_seed_corpus_has_a_golden_distribution() {
        let config = FrontConfig {
            n_client_packets: 8,
            n_server_packets: 12,
            packet_size: 1_200,
            peak_minimum_seconds: 0.1,
            peak_maximum_seconds: 0.5,
        };
        let mut incoming = 0;
        let mut outgoing = 0;
        let mut bins = [0; 4];
        let mut timestamps = Vec::new();
        for seed in 0..256 {
            let mut front = Front::new(&config, seed);
            while let Some(packet) = front.next_event(Duration::MAX) {
                match packet.direction() {
                    Direction::Incoming => incoming += 1,
                    Direction::Outgoing => outgoing += 1,
                }
                let timestamp = packet.timestamp_us();
                timestamps.push(timestamp);
                bins[match timestamp {
                    0..100_000 => 0,
                    100_000..200_000 => 1,
                    200_000..500_000 => 2,
                    _ => 3,
                }] += 1;
            }
        }
        timestamps.sort_unstable();
        assert_eq!((incoming, outgoing), (1_752, 1_155));
        assert_eq!(bins, [230, 593, 1_261, 823]);
        assert_eq!(
            [
                timestamps[726],
                timestamps[1_453],
                timestamps[2_180],
                timestamps[2_906],
            ],
            [183_036, 324_104, 532_489, 2_162_681]
        );
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
            match defense.next_event(Duration::from_millis(21)) {
                Some(packet) if packet.direction() == Direction::Incoming => incoming += 1,
                Some(_) => outgoing += 1,
                None => panic!("a Tamaraw slot should be due"),
            }
        }
        defense.on_application_complete();
        while let Some(packet) = defense.next_event(Duration::from_secs(1)) {
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
    fn tamaraw_completion_has_a_golden_sequence() {
        let config = TamarawConfig {
            incoming_interval_us: 10_000,
            outgoing_interval_us: 30_000,
            packet_size: 1_200,
            modulo: 4,
        };
        let mut defense = Tamaraw::new(&config);
        let mut actual = Vec::new();
        while let Some(packet) = defense.next_event(Duration::from_millis(35)) {
            actual.push((packet.timestamp_us(), packet.direction()));
        }
        defense.on_application_complete();
        while let Some(packet) = defense.next_event(Duration::MAX) {
            actual.push((packet.timestamp_us(), packet.direction()));
        }
        assert_eq!(
            actual,
            [
                (0, Direction::Outgoing),
                (0, Direction::Incoming),
                (10_000, Direction::Incoming),
                (20_000, Direction::Incoming),
                (30_000, Direction::Outgoing),
                (30_000, Direction::Incoming),
                (40_000, Direction::Incoming),
                (50_000, Direction::Incoming),
                (60_000, Direction::Outgoing),
                (60_000, Direction::Incoming),
                (70_000, Direction::Incoming),
                (90_000, Direction::Outgoing),
            ]
        );
        assert!(defense.is_complete());
    }

    #[test]
    fn shared_schedule_has_independent_direction_cursors() {
        let endpoints = vec![QcsdEndpointId(4), QcsdEndpointId(8)];
        let mut scheduler = RoundRobinScheduler::new(endpoints).expect("endpoints");
        assert_eq!(scheduler.next_outgoing(), Some(QcsdEndpointId(4)));
        assert_eq!(scheduler.next_outgoing(), Some(QcsdEndpointId(8)));

        let selected = scheduler.next_incoming(100, DefenseMode::ChaffOnly, |_| Capacity {
            chaff_incoming: 100,
            ..Capacity::default()
        });
        assert_eq!(selected, Some((QcsdEndpointId(4), true)));
        assert_eq!(scheduler.next_outgoing(), Some(QcsdEndpointId(4)));
    }

    #[test]
    fn incoming_scheduler_prioritizes_partial_application_capacity() {
        let endpoints = vec![QcsdEndpointId(1), QcsdEndpointId(2)];
        let mut scheduler = RoundRobinScheduler::new(endpoints).expect("endpoints");
        let selected =
            scheduler.next_incoming(
                1_000,
                DefenseMode::ChaffAndShape,
                |endpoint| match endpoint {
                    QcsdEndpointId(1) => Capacity {
                        application_incoming: 100,
                        ..Capacity::default()
                    },
                    QcsdEndpointId(2) => Capacity {
                        chaff_incoming: 1_000,
                        ..Capacity::default()
                    },
                    _ => unreachable!("known endpoint"),
                },
            );
        assert_eq!(selected, Some((QcsdEndpointId(1), false)));
    }

    #[test]
    fn incoming_scheduler_uses_published_application_fallback() {
        let endpoints = vec![QcsdEndpointId(1), QcsdEndpointId(2)];
        let mut scheduler = RoundRobinScheduler::new(endpoints).expect("endpoints");
        let selected =
            scheduler.next_incoming(
                1_000,
                DefenseMode::ChaffAndShape,
                |endpoint| match endpoint {
                    QcsdEndpointId(1) => Capacity::default(),
                    QcsdEndpointId(2) => Capacity {
                        application_incoming: 100,
                        ..Capacity::default()
                    },
                    _ => unreachable!("known endpoint"),
                },
            );
        assert_eq!(selected, Some((QcsdEndpointId(2), false)));
    }

    #[test]
    fn endpoint_removal_preserves_stable_round_robin_order() {
        let endpoints = vec![QcsdEndpointId(1), QcsdEndpointId(2), QcsdEndpointId(3)];
        let mut scheduler = RoundRobinScheduler::new(endpoints).expect("endpoints");
        assert_eq!(scheduler.next_outgoing(), Some(QcsdEndpointId(1)));
        scheduler.remove_endpoint(QcsdEndpointId(2));
        assert_eq!(scheduler.next_outgoing(), Some(QcsdEndpointId(3)));
        assert_eq!(scheduler.next_outgoing(), Some(QcsdEndpointId(1)));
    }
}
