// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Complete, resolved configuration for one QCSD controller.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct QcsdConfig {
    /// Configuration schema version. Version one is the first modern port.
    pub schema_version: u32,
    /// How often the controller is polled, in microseconds.
    pub control_interval_us: u64,
    /// Initial receive allowance for manually controlled streams.
    pub initial_max_stream_data: u64,
    /// Automatic receive window restored for uncontrolled application streams.
    pub automatic_receive_window: u64,
    /// Maximum number of concurrently open chaff request streams.
    pub max_chaff_streams: usize,
    /// Desired aggregate unused chaff capacity.
    pub low_watermark: u64,
    /// Extra stream credit reserved for HTTP/3 frame headers.
    pub max_stream_data_excess: u64,
    /// Largest scheduled UDP payload accepted by the configuration.
    pub max_udp_payload_size: u16,
    /// Drop an event that cannot be satisfied instead of retrying it.
    pub drop_unsatisfied_events: bool,
    /// Lead time for keep-alive activity, in microseconds.
    pub keep_alive_lead_time_us: u64,
    /// Time to wait after the defense completes, in microseconds.
    pub tail_wait_us: u64,
    /// Selected defense and its parameters.
    pub defense: DefenseConfig,
}

impl Default for QcsdConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            control_interval_us: 5_000,
            initial_max_stream_data: 16,
            automatic_receive_window: 1_048_576,
            max_chaff_streams: 5,
            low_watermark: 1_000_000,
            max_stream_data_excess: 1_000,
            max_udp_payload_size: 1_450,
            drop_unsatisfied_events: false,
            keep_alive_lead_time_us: 100_000,
            tail_wait_us: 0,
            defense: DefenseConfig::None,
        }
    }
}

impl QcsdConfig {
    /// Load a versioned configuration from TOML.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_toml(&input)
    }

    /// Parse and validate a versioned configuration from TOML.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is invalid TOML or violates an invariant.
    pub fn from_toml(input: &str) -> Result<Self> {
        let config: Self = match toml::from_str(input) {
            Ok(config) => config,
            Err(_) if input.contains("[flow_shaper]") || input.contains("[front_defence]") => {
                return Self::from_legacy_toml(input);
            }
            Err(error) => return Err(error.into()),
        };
        config.validate()?;
        Ok(config)
    }

    /// Import the published `[flow_shaper]` and `[front_defence]` TOML schema.
    ///
    /// A present `front_defence` section selects FRONT. The old embedded FRONT
    /// seed is intentionally superseded by the runner's required explicit seed.
    /// Legacy TOML never encoded Static or Tamaraw selection; callers can replace
    /// [`Self::defense`] after importing the shared flow-shaper settings.
    ///
    /// # Errors
    ///
    /// Returns an error when the legacy input is invalid or cannot be represented
    /// by the modern integer configuration.
    pub fn from_legacy_toml(input: &str) -> Result<Self> {
        let legacy: LegacyConfigFile = toml::from_str(input)?;
        if legacy.flow_shaper.is_none() && legacy.front_defence.is_none() {
            return Err(Error::InvalidConfig(
                "legacy TOML has neither [flow_shaper] nor [front_defence]".into(),
            ));
        }
        let flow = legacy.flow_shaper.unwrap_or_default();
        let max_chaff_streams = usize::try_from(flow.max_chaff_streams)
            .map_err(|_| Error::InvalidConfig("legacy max_chaff_streams is too large".into()))?;
        let max_udp_payload_size = u16::try_from(flow.max_udp_payload_size).map_err(|_| {
            Error::InvalidConfig("legacy max_udp_payload_size exceeds 65535".into())
        })?;
        let defense = match legacy.front_defence {
            None => DefenseConfig::None,
            Some(front) => DefenseConfig::Front(FrontConfig {
                n_client_packets: front.n_client_packets,
                n_server_packets: front.n_server_packets,
                packet_size: u16::try_from(front.packet_size).map_err(|_| {
                    Error::InvalidConfig("legacy FRONT packet_size exceeds 65535".into())
                })?,
                peak_minimum_seconds: front.peak_minimum,
                peak_maximum_seconds: front.peak_maximum,
            }),
        };
        let config = Self {
            control_interval_us: flow.control_interval.saturating_mul(1_000),
            initial_max_stream_data: flow.initial_max_stream_data,
            automatic_receive_window: flow.rx_stream_data_window,
            max_chaff_streams,
            low_watermark: flow.low_watermark,
            max_stream_data_excess: flow.max_stream_data_excess,
            max_udp_payload_size,
            drop_unsatisfied_events: flow.drop_unsat_events,
            keep_alive_lead_time_us: flow.keep_alive_lead_time.saturating_mul(1_000),
            tail_wait_us: flow.tail_wait.saturating_mul(1_000),
            defense,
            ..Self::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate invariants that cannot be represented by Serde types.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first invalid parameter.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(Error::InvalidConfig(format!(
                "unsupported schema_version {}; expected 1",
                self.schema_version
            )));
        }
        if self.control_interval_us == 0 {
            return Err(Error::InvalidConfig(
                "control_interval_us must be greater than zero".into(),
            ));
        }
        if self.initial_max_stream_data == 0 {
            return Err(Error::InvalidConfig(
                "initial_max_stream_data must be greater than zero".into(),
            ));
        }
        if self.automatic_receive_window < self.initial_max_stream_data {
            return Err(Error::InvalidConfig(
                "automatic_receive_window cannot be smaller than initial_max_stream_data".into(),
            ));
        }
        if self.max_chaff_streams == 0 {
            return Err(Error::InvalidConfig(
                "max_chaff_streams must be greater than zero".into(),
            ));
        }
        if self.max_udp_payload_size < 64 {
            return Err(Error::InvalidConfig(
                "max_udp_payload_size is too small for a protected QUIC packet".into(),
            ));
        }
        self.defense.validate(self.max_udp_payload_size)
    }

    /// Controller poll interval.
    #[must_use]
    pub const fn control_interval(&self) -> Duration {
        Duration::from_micros(self.control_interval_us)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyConfigFile {
    #[serde(default)]
    flow_shaper: Option<LegacyFlowShaperConfig>,
    #[serde(default)]
    front_defence: Option<LegacyFrontConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyFlowShaperConfig {
    control_interval: u64,
    rx_stream_data_window: u64,
    #[serde(rename = "local_md")]
    _local_md: u64,
    initial_max_stream_data: u64,
    max_stream_data_excess: u64,
    max_udp_payload_size: u64,
    max_chaff_streams: u32,
    low_watermark: u64,
    #[serde(rename = "use_empty_resources")]
    _use_empty_resources: bool,
    drop_unsat_events: bool,
    keep_alive_lead_time: u64,
    tail_wait: u64,
}

impl Default for LegacyFlowShaperConfig {
    fn default() -> Self {
        Self {
            control_interval: 5,
            rx_stream_data_window: 1_048_576,
            _local_md: (1_u64 << 62) - 1,
            initial_max_stream_data: 16,
            max_stream_data_excess: 1_000,
            max_udp_payload_size: 65_527,
            max_chaff_streams: 5,
            low_watermark: 1_000_000,
            _use_empty_resources: false,
            drop_unsat_events: false,
            keep_alive_lead_time: 100,
            tail_wait: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyFrontConfig {
    n_client_packets: u32,
    n_server_packets: u32,
    packet_size: u32,
    peak_minimum: f64,
    peak_maximum: f64,
    #[serde(rename = "seed")]
    _seed: Option<u64>,
}

impl Default for LegacyFrontConfig {
    fn default() -> Self {
        Self {
            n_client_packets: 900,
            n_server_packets: 1_200,
            packet_size: 1_450,
            peak_minimum: 0.1,
            peak_maximum: 2.5,
            _seed: None,
        }
    }
}

/// Defense selection for one run.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefenseConfig {
    /// Record traffic without shaping it.
    #[default]
    None,
    /// Read a signed packet schedule from a legacy-compatible CSV file.
    Static {
        /// Schedule file containing `seconds,signed_size` records.
        schedule: String,
        /// Whether all scheduled capacity is chaff-only.
        #[serde(default)]
        padding_only: bool,
    },
    /// FRONT chaff-only defense.
    Front(FrontConfig),
    /// Tamaraw constant-rate defense.
    Tamaraw(TamarawConfig),
}

impl DefenseConfig {
    fn validate(&self, max_udp_payload_size: u16) -> Result<()> {
        let packet_size = match self {
            Self::None | Self::Static { .. } => return Ok(()),
            Self::Front(config) => {
                if config.n_client_packets == 0 || config.n_server_packets == 0 {
                    return Err(Error::InvalidConfig(
                        "FRONT packet counts must be greater than zero".into(),
                    ));
                }
                if !(config.peak_minimum_seconds.is_finite()
                    && config.peak_maximum_seconds.is_finite()
                    && config.peak_minimum_seconds > 0.0
                    && config.peak_minimum_seconds <= config.peak_maximum_seconds)
                {
                    return Err(Error::InvalidConfig(
                        "FRONT peaks must be finite, positive, and ordered".into(),
                    ));
                }
                config.packet_size
            }
            Self::Tamaraw(config) => {
                if config.incoming_interval_us == 0 || config.outgoing_interval_us == 0 {
                    return Err(Error::InvalidConfig(
                        "Tamaraw intervals must be greater than zero".into(),
                    ));
                }
                if config.modulo == 0 {
                    return Err(Error::InvalidConfig(
                        "Tamaraw modulo must be greater than zero".into(),
                    ));
                }
                config.packet_size
            }
        };
        if packet_size > max_udp_payload_size {
            return Err(Error::InvalidConfig(format!(
                "defense packet size {packet_size} exceeds max_udp_payload_size {max_udp_payload_size}"
            )));
        }
        Ok(())
    }
}

/// FRONT parameters, matching the published QCSD defaults.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FrontConfig {
    /// Maximum number of client-originated dummy packets.
    pub n_client_packets: u32,
    /// Maximum number of server-originated dummy packets.
    pub n_server_packets: u32,
    /// UDP payload target for every event.
    pub packet_size: u16,
    /// Minimum Rayleigh scale parameter in seconds.
    pub peak_minimum_seconds: f64,
    /// Maximum Rayleigh scale parameter in seconds.
    pub peak_maximum_seconds: f64,
}

impl Default for FrontConfig {
    fn default() -> Self {
        Self {
            n_client_packets: 900,
            n_server_packets: 1_200,
            packet_size: 1_450,
            peak_minimum_seconds: 0.1,
            peak_maximum_seconds: 2.5,
        }
    }
}

/// Tamaraw parameters, matching the published implementation defaults.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TamarawConfig {
    /// Delay between incoming slots.
    pub incoming_interval_us: u64,
    /// Delay between outgoing slots.
    pub outgoing_interval_us: u64,
    /// UDP payload or receive-credit size for each slot.
    pub packet_size: u16,
    /// Round each direction up to this many events after completion.
    pub modulo: u32,
}

impl Default for TamarawConfig {
    fn default() -> Self {
        Self {
            incoming_interval_us: 5_000,
            outgoing_interval_us: 20_000,
            packet_size: 1_450,
            modulo: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DefenseConfig, FrontConfig, QcsdConfig};

    #[test]
    fn partial_config_uses_published_defaults() {
        let config = QcsdConfig::from_toml(
            r#"
                control_interval_us = 10000
                [defense]
                kind = "front"
                n_server_packets = 21
            "#,
        )
        .expect("valid configuration");
        assert_eq!(config.control_interval_us, 10_000);
        assert_eq!(
            config.defense,
            DefenseConfig::Front(FrontConfig {
                n_server_packets: 21,
                ..FrontConfig::default()
            })
        );
    }

    #[test]
    fn rejects_packet_size_above_transport_limit() {
        let config = QcsdConfig {
            max_udp_payload_size: 1_200,
            defense: DefenseConfig::Front(FrontConfig::default()),
            ..QcsdConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn checked_in_presets_are_valid_resolved_configs() {
        for preset in [
            include_str!("../../qcsd-presets/baseline.toml"),
            include_str!("../../qcsd-presets/published-front.toml"),
            include_str!("../../qcsd-presets/published-tamaraw.toml"),
            include_str!("../../qcsd-presets/conservative-live.toml"),
            include_str!("../../qcsd-presets/static-example.toml"),
        ] {
            QcsdConfig::from_toml(preset).expect("checked-in preset must remain valid");
        }
    }

    #[test]
    fn imports_published_legacy_toml() {
        let config = QcsdConfig::from_toml(
            "
                [flow_shaper]
                control_interval = 10
                max_udp_payload_size = 1450
                tail_wait = 25

                [front_defence]
                packet_size = 1200
                n_server_packets = 21
                seed = 99
            ",
        )
        .expect("valid legacy configuration");
        assert_eq!(config.control_interval_us, 10_000);
        assert_eq!(config.tail_wait_us, 25_000);
        assert_eq!(config.low_watermark, 1_000_000);
        assert_eq!(
            config.defense,
            DefenseConfig::Front(FrontConfig {
                packet_size: 1_200,
                n_server_packets: 21,
                ..FrontConfig::default()
            })
        );
    }
}
