// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use serde::{Deserialize, Serialize};

use crate::{
    DefenseConfig, FrontConfig, QcsdConfig, Result, TamarawConfig, TrafficMorphingConfig,
    WalkieTalkieConfig, WtfPadConfig,
};

/// A complete family of QCSD controller and defense parameters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdProfile {
    /// Parameters used by the published QCSD implementation.
    Published,
    /// Conservative parameters for bounded experiments against public servers.
    Live,
}

/// Static schedule participation mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticMode {
    /// Add scheduled capacity as chaff without shaping application traffic.
    ChaffOnly,
    /// Shape application and chaff traffic toward the supplied schedule.
    ChaffAndShape,
}

/// Defense selected from a QCSD profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DefenseKind {
    /// Record an undefended baseline.
    None,
    /// Use the profile's FRONT parameters.
    Front,
    /// Use the profile's Tamaraw parameters.
    Tamaraw,
    /// Replay an explicit Static schedule.
    Static {
        /// Schedule file containing `seconds,signed_size` records.
        schedule: String,
        /// How application traffic participates in scheduled capacity.
        mode: StaticMode,
    },
    /// Use the profile's Traffic Morphing parameters and an explicit matrix.
    TrafficMorphing {
        /// Versioned workload-bound bidirectional morphing-matrix JSON bundle.
        matrix: String,
        /// Workload identity bound to exactly one source-to-decoy profile.
        workload_id: String,
    },
    /// Use the profile's WTF-PAD parameters and explicit histograms.
    WtfPad {
        /// Versioned bidirectional adaptive-padding histogram JSON file.
        histograms: String,
    },
    /// Use the profile's Walkie-Talkie parameters and an explicit molded sequence.
    WalkieTalkie {
        /// Versioned molded burst-sequence JSON file.
        molded: String,
        /// Workload identity bound to exactly one symmetric pair profile.
        workload_id: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDefinition {
    schema_version: u32,
    controller: ControllerProfile,
    front: FrontConfig,
    tamaraw: TamarawConfig,
    traffic_morphing: TrafficMorphingConfig,
    wtf_pad: WtfPadConfig,
    walkie_talkie: WalkieTalkieConfig,
}

impl ProfileDefinition {
    fn parse(source: &str) -> Result<Self> {
        let profile: Self = toml::from_str(source)?;
        if profile.schema_version != 2 {
            return Err(crate::Error::InvalidConfig(format!(
                "unsupported QCSD profile schema_version {}; expected 2",
                profile.schema_version
            )));
        }
        Ok(profile)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerProfile {
    control_interval_us: u64,
    initial_max_stream_data: u64,
    automatic_receive_window: u64,
    max_chaff_streams: usize,
    low_watermark: u64,
    use_empty_resources: bool,
    max_stream_data_excess: u64,
    max_udp_payload_size: u16,
    drop_unsatisfied_events: bool,
    keep_alive_lead_time_us: u64,
    tail_wait_us: u64,
}

impl QcsdProfile {
    /// Resolve one defense into the complete configuration recorded by a run.
    ///
    /// # Errors
    ///
    /// Returns an error when the checked-in profile or selected Static schedule
    /// violates a QCSD configuration invariant.
    pub fn resolve(self, defense: DefenseKind) -> Result<QcsdConfig> {
        let source = match self {
            Self::Published => include_str!("../profiles/published.toml"),
            Self::Live => include_str!("../profiles/live.toml"),
        };
        let profile = ProfileDefinition::parse(source)?;
        let defense = match defense {
            DefenseKind::None => DefenseConfig::None,
            DefenseKind::Front => DefenseConfig::Front(profile.front),
            DefenseKind::Tamaraw => DefenseConfig::Tamaraw(profile.tamaraw),
            DefenseKind::Static { schedule, mode } => DefenseConfig::Static {
                schedule,
                padding_only: mode == StaticMode::ChaffOnly,
            },
            DefenseKind::TrafficMorphing {
                matrix,
                workload_id,
            } => {
                let mut config = profile.traffic_morphing;
                config.matrix = matrix;
                config.workload_id = workload_id;
                DefenseConfig::TrafficMorphing(config)
            }
            DefenseKind::WtfPad { histograms } => {
                let mut config = profile.wtf_pad;
                config.histograms = histograms;
                DefenseConfig::WtfPad(config)
            }
            DefenseKind::WalkieTalkie {
                molded,
                workload_id,
            } => {
                let mut config = profile.walkie_talkie;
                config.molded = molded;
                config.workload_id = workload_id;
                DefenseConfig::WalkieTalkie(config)
            }
        };
        let controller = profile.controller;
        let config = QcsdConfig {
            schema_version: 2,
            control_interval_us: controller.control_interval_us,
            initial_max_stream_data: controller.initial_max_stream_data,
            automatic_receive_window: controller.automatic_receive_window,
            max_chaff_streams: controller.max_chaff_streams,
            low_watermark: controller.low_watermark,
            use_empty_resources: controller.use_empty_resources,
            max_stream_data_excess: controller.max_stream_data_excess,
            max_udp_payload_size: controller.max_udp_payload_size,
            drop_unsatisfied_events: controller.drop_unsatisfied_events,
            keep_alive_lead_time_us: controller.keep_alive_lead_time_us,
            tail_wait_us: controller.tail_wait_us,
            defense,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{DefenseKind, ProfileDefinition, QcsdProfile, StaticMode};
    use crate::{
        DefenseConfig, FrontConfig, TamarawConfig, TrafficMorphingConfig, WalkieTalkieConfig,
        WtfPadConfig,
    };

    #[test]
    fn published_profile_resolves_every_defense() {
        let baseline = QcsdProfile::Published
            .resolve(DefenseKind::None)
            .expect("published baseline");
        assert_eq!(baseline.defense, DefenseConfig::None);
        let front = QcsdProfile::Published
            .resolve(DefenseKind::Front)
            .expect("published FRONT");
        assert_eq!(front.defense, DefenseConfig::Front(FrontConfig::default()));
        let tamaraw = QcsdProfile::Published
            .resolve(DefenseKind::Tamaraw)
            .expect("published Tamaraw");
        assert_eq!(
            tamaraw.defense,
            DefenseConfig::Tamaraw(TamarawConfig::default())
        );
        let static_config = QcsdProfile::Published
            .resolve(DefenseKind::Static {
                schedule: "schedule.csv".into(),
                mode: StaticMode::ChaffAndShape,
            })
            .expect("published Static");
        assert_eq!(
            static_config.defense,
            DefenseConfig::Static {
                schedule: "schedule.csv".into(),
                padding_only: false,
            }
        );
        let traffic_morphing = QcsdProfile::Published
            .resolve(DefenseKind::TrafficMorphing {
                matrix: "matrix.json".into(),
                workload_id: "published-workload".into(),
            })
            .expect("published Traffic Morphing");
        assert_eq!(
            traffic_morphing.defense,
            DefenseConfig::TrafficMorphing(TrafficMorphingConfig {
                matrix: "matrix.json".into(),
                workload_id: "published-workload".into(),
                ..TrafficMorphingConfig::default()
            })
        );
        let wtf_pad = QcsdProfile::Published
            .resolve(DefenseKind::WtfPad {
                histograms: "histograms.json".into(),
            })
            .expect("published WTF-PAD");
        assert_eq!(
            wtf_pad.defense,
            DefenseConfig::WtfPad(WtfPadConfig {
                histograms: "histograms.json".into(),
                ..WtfPadConfig::default()
            })
        );
        let walkie_talkie = QcsdProfile::Published
            .resolve(DefenseKind::WalkieTalkie {
                molded: "molded.json".into(),
                workload_id: "published-workload".into(),
            })
            .expect("published Walkie-Talkie");
        assert_eq!(
            walkie_talkie.defense,
            DefenseConfig::WalkieTalkie(WalkieTalkieConfig {
                molded: "molded.json".into(),
                workload_id: "published-workload".into(),
                ..WalkieTalkieConfig::default()
            })
        );
    }

    #[test]
    fn live_profile_resolves_every_defense() {
        let baseline = QcsdProfile::Live
            .resolve(DefenseKind::None)
            .expect("live baseline");
        assert_eq!(baseline.defense, DefenseConfig::None);
        let front = QcsdProfile::Live
            .resolve(DefenseKind::Front)
            .expect("live FRONT");
        assert_eq!(front.max_chaff_streams, 2);
        assert_eq!(front.max_udp_payload_size, 1_200);
        assert_eq!(
            front.defense,
            DefenseConfig::Front(FrontConfig {
                n_client_packets: 32,
                n_server_packets: 48,
                packet_size: 1_200,
                peak_minimum_seconds: 0.1,
                peak_maximum_seconds: 1.0,
            })
        );
        let tamaraw = QcsdProfile::Live
            .resolve(DefenseKind::Tamaraw)
            .expect("live Tamaraw");
        assert_eq!(
            tamaraw.defense,
            DefenseConfig::Tamaraw(TamarawConfig {
                incoming_interval_us: 10_000,
                outgoing_interval_us: 30_000,
                packet_size: 1_200,
                modulo: 20,
            })
        );
        let static_config = QcsdProfile::Live
            .resolve(DefenseKind::Static {
                schedule: "live.csv".into(),
                mode: StaticMode::ChaffOnly,
            })
            .expect("live Static");
        assert_eq!(
            static_config.defense,
            DefenseConfig::Static {
                schedule: "live.csv".into(),
                padding_only: true,
            }
        );
        let traffic_morphing = QcsdProfile::Live
            .resolve(DefenseKind::TrafficMorphing {
                matrix: "live-matrix.json".into(),
                workload_id: "live-workload".into(),
            })
            .expect("live Traffic Morphing");
        assert_eq!(
            traffic_morphing.defense,
            DefenseConfig::TrafficMorphing(TrafficMorphingConfig {
                matrix: "live-matrix.json".into(),
                workload_id: "live-workload".into(),
                ingress_packet_size: 1_200,
                max_ingress_deficit_bytes: 8_000,
            })
        );
        let wtf_pad = QcsdProfile::Live
            .resolve(DefenseKind::WtfPad {
                histograms: "live-histograms.json".into(),
            })
            .expect("live WTF-PAD");
        assert_eq!(
            wtf_pad.defense,
            DefenseConfig::WtfPad(WtfPadConfig {
                histograms: "live-histograms.json".into(),
                packet_size: 1_200,
                max_padding_events: 10_000,
            })
        );
        let walkie_talkie = QcsdProfile::Live
            .resolve(DefenseKind::WalkieTalkie {
                molded: "live-molded.json".into(),
                workload_id: "live-workload".into(),
            })
            .expect("live Walkie-Talkie");
        assert_eq!(
            walkie_talkie.defense,
            DefenseConfig::WalkieTalkie(WalkieTalkieConfig {
                molded: "live-molded.json".into(),
                workload_id: "live-workload".into(),
                packet_size: 1_200,
            })
        );
    }

    #[test]
    fn profiles_reject_every_schema_except_version_two() {
        let version_one = include_str!("../profiles/live.toml").replacen(
            "schema_version = 2",
            "schema_version = 1",
            1,
        );
        let error = ProfileDefinition::parse(&version_one).expect_err("version one is obsolete");
        assert!(error.to_string().contains("expected 2"));
    }
}
