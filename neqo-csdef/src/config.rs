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
    /// Configuration schema version. New resolved configurations use version two.
    #[serde(default = "missing_schema_version")]
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
    /// Permit a zero-length resource as a last-resort chaff source.
    #[serde(default)]
    pub use_empty_resources: bool,
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
            schema_version: 2,
            control_interval_us: 5_000,
            initial_max_stream_data: 16,
            automatic_receive_window: 1_048_576,
            max_chaff_streams: 5,
            low_watermark: 1_000_000,
            use_empty_resources: false,
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
        let path = path.as_ref();
        let input = fs::read_to_string(path)?;
        let mut config = Self::from_toml(&input)?;
        config.resolve_defense_paths(path);
        Ok(config)
    }

    /// Parse and validate a versioned configuration from TOML.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is invalid TOML or violates an invariant.
    pub fn from_toml(input: &str) -> Result<Self> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate invariants that cannot be represented by Serde types.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first invalid parameter.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2 {
            return Err(Error::InvalidConfig(format!(
                "unsupported schema_version {}; expected 2",
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
        if self.max_udp_payload_size < 1_200 {
            return Err(Error::InvalidConfig(
                "max_udp_payload_size must satisfy QUIC's 1200-byte minimum".into(),
            ));
        }
        self.defense.validate(self.max_udp_payload_size)
    }

    /// Controller poll interval.
    #[must_use]
    pub const fn control_interval(&self) -> Duration {
        Duration::from_micros(self.control_interval_us)
    }

    /// Initial request-stream receive allowance actually used by this defense.
    ///
    /// Walkie-Talkie must not admit response HEADERS or DATA during its outgoing
    /// turn.  Its effective allowance is therefore zero even though the shared
    /// profile retains the published 16-byte value used by every other mode.
    #[must_use]
    pub const fn effective_initial_max_stream_data(&self) -> u64 {
        if matches!(self.defense, DefenseConfig::WalkieTalkie(_)) {
            0
        } else {
            self.initial_max_stream_data
        }
    }

    fn resolve_defense_paths(&mut self, config_path: &Path) {
        let Some(path) = self.defense.parameter_path_mut() else {
            return;
        };
        let parameter_path = Path::new(path);
        if parameter_path.is_absolute() {
            return;
        }
        let relative = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(parameter_path);
        *path = relative.to_string_lossy().into_owned();
    }
}

const fn missing_schema_version() -> u32 {
    0
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
    /// Traffic Morphing reactive size defense.
    TrafficMorphing(TrafficMorphingConfig),
    /// WTF-PAD adaptive-padding defense.
    WtfPad(WtfPadConfig),
    /// Walkie-Talkie half-duplex burst-molding defense.
    WalkieTalkie(WalkieTalkieConfig),
}

impl DefenseConfig {
    /// External parameter file used by this defense, if any.
    #[must_use]
    pub fn parameter_path(&self) -> Option<&str> {
        match self {
            Self::Static { schedule, .. } => Some(schedule),
            Self::TrafficMorphing(config) => Some(&config.matrix),
            Self::WtfPad(config) => Some(&config.histograms),
            Self::WalkieTalkie(config) => Some(&config.molded),
            Self::None | Self::Front(_) | Self::Tamaraw(_) => None,
        }
    }

    const fn parameter_path_mut(&mut self) -> Option<&mut String> {
        match self {
            Self::Static { schedule, .. } => Some(schedule),
            Self::TrafficMorphing(config) => Some(&mut config.matrix),
            Self::WtfPad(config) => Some(&mut config.histograms),
            Self::WalkieTalkie(config) => Some(&mut config.molded),
            Self::None | Self::Front(_) | Self::Tamaraw(_) => None,
        }
    }

    fn validate(&self, max_udp_payload_size: u16) -> Result<()> {
        let packet_size = match self {
            Self::None => return Ok(()),
            Self::Static { schedule, .. } => {
                if schedule.trim().is_empty() {
                    return Err(Error::InvalidConfig(
                        "static schedule path must not be empty".into(),
                    ));
                }
                return Ok(());
            }
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
            Self::TrafficMorphing(config) => return config.validate(max_udp_payload_size),
            Self::WtfPad(config) => return config.validate(max_udp_payload_size),
            Self::WalkieTalkie(config) => return config.validate(max_udp_payload_size),
        };
        if packet_size < crate::MIN_SHAPED_PAYLOAD {
            return Err(Error::InvalidConfig(format!(
                "defense packet size {packet_size} is below the minimum shapeable payload {}",
                crate::MIN_SHAPED_PAYLOAD
            )));
        }
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

/// Traffic Morphing parameters.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficMorphingConfig {
    /// Versioned workload-bound bidirectional morphing-matrix JSON bundle.
    pub matrix: String,
    /// Workload identity bound to exactly one source-to-decoy profile.
    pub workload_id: String,
    /// Largest receive-credit/chaff request used by the ingress approximation.
    pub ingress_packet_size: u16,
    /// Maximum unresolved aggregate ingress target deficit.
    pub max_ingress_deficit_bytes: u64,
}

impl Default for TrafficMorphingConfig {
    fn default() -> Self {
        Self {
            matrix: String::new(),
            workload_id: String::new(),
            ingress_packet_size: 1_450,
            max_ingress_deficit_bytes: 8_000,
        }
    }
}

impl TrafficMorphingConfig {
    pub(crate) fn validate(&self, max_udp_payload_size: u16) -> Result<()> {
        validate_parameter_path(&self.matrix, "Traffic Morphing matrix")?;
        if self.workload_id.trim().is_empty() || self.workload_id.trim() != self.workload_id {
            return Err(Error::InvalidConfig(
                "Traffic Morphing workload_id must be non-empty and have no surrounding whitespace"
                    .into(),
            ));
        }
        validate_shaped_packet_size(
            self.ingress_packet_size,
            max_udp_payload_size,
            "Traffic Morphing ingress adapter",
        )?;
        if self.max_ingress_deficit_bytes == 0 {
            return Err(Error::InvalidConfig(
                "Traffic Morphing max_ingress_deficit_bytes must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

/// WTF-PAD parameters.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WtfPadConfig {
    /// Versioned bidirectional adaptive-padding histogram JSON file.
    pub histograms: String,
    /// UDP payload or receive-credit size for each padding event.
    pub packet_size: u16,
    /// Hard bound that prevents a malformed distribution padding forever.
    pub max_padding_events: u64,
}

impl Default for WtfPadConfig {
    fn default() -> Self {
        Self {
            histograms: String::new(),
            packet_size: 1_450,
            max_padding_events: 100_000,
        }
    }
}

impl WtfPadConfig {
    pub(crate) fn validate(&self, max_udp_payload_size: u16) -> Result<()> {
        validate_parameter_path(&self.histograms, "WTF-PAD histogram")?;
        validate_shaped_packet_size(self.packet_size, max_udp_payload_size, "WTF-PAD")?;
        if self.max_padding_events == 0 {
            return Err(Error::InvalidConfig(
                "WTF-PAD max_padding_events must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

/// Walkie-Talkie parameters.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WalkieTalkieConfig {
    /// Versioned molded burst-sequence JSON file.
    pub molded: String,
    /// Workload identity selecting one symmetric pair profile from the bundle.
    pub workload_id: String,
    /// UDP payload or receive-credit size for each molded event.
    pub packet_size: u16,
}

impl Default for WalkieTalkieConfig {
    fn default() -> Self {
        Self {
            molded: String::new(),
            workload_id: String::new(),
            packet_size: 1_450,
        }
    }
}

impl WalkieTalkieConfig {
    pub(crate) fn validate(&self, max_udp_payload_size: u16) -> Result<()> {
        validate_parameter_path(&self.molded, "Walkie-Talkie molded-sequence")?;
        if self.workload_id.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie workload_id must not be empty".into(),
            ));
        }
        validate_shaped_packet_size(self.packet_size, max_udp_payload_size, "Walkie-Talkie")?;
        Ok(())
    }
}

fn validate_parameter_path(path: &str, label: &str) -> Result<()> {
    if path.trim().is_empty() {
        return Err(Error::InvalidConfig(format!(
            "{label} path must not be empty"
        )));
    }
    Ok(())
}

fn validate_shaped_packet_size(
    packet_size: u16,
    max_udp_payload_size: u16,
    defense: &str,
) -> Result<()> {
    if packet_size < crate::MIN_SHAPED_PAYLOAD {
        return Err(Error::InvalidConfig(format!(
            "{defense} packet size {packet_size} is below the minimum shapeable payload {}",
            crate::MIN_SHAPED_PAYLOAD
        )));
    }
    if packet_size > max_udp_payload_size {
        return Err(Error::InvalidConfig(format!(
            "{defense} packet size {packet_size} exceeds max_udp_payload_size {max_udp_payload_size}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{
        DefenseConfig, FrontConfig, QcsdConfig, TrafficMorphingConfig, WalkieTalkieConfig,
        WtfPadConfig,
    };

    #[test]
    fn partial_config_uses_published_defaults() {
        let config = QcsdConfig::from_toml(
            r#"
                schema_version = 2
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
    fn walkie_talkie_alone_starts_request_streams_with_zero_receive_credit() {
        let ordinary = QcsdConfig {
            defense: DefenseConfig::Front(FrontConfig::default()),
            ..QcsdConfig::default()
        };
        assert_eq!(ordinary.effective_initial_max_stream_data(), 16);

        let walkie_talkie = QcsdConfig {
            defense: DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default()),
            ..QcsdConfig::default()
        };
        assert_eq!(walkie_talkie.initial_max_stream_data, 16);
        assert_eq!(walkie_talkie.effective_initial_max_stream_data(), 0);
    }

    #[test]
    fn resolved_config_rejects_missing_schema_version() {
        let error = QcsdConfig::from_toml(
            r#"
                [defense]
                kind = "none"
            "#,
        )
        .expect_err("the version-two schema must be explicit");
        assert!(error.to_string().contains("expected 2"));
    }

    #[test]
    fn resolved_config_rejects_obsolete_schema_version_one() {
        let error = QcsdConfig::from_toml(
            r#"
                schema_version = 1
                [defense]
                kind = "none"
            "#,
        )
        .expect_err("schema version one is obsolete");
        assert!(error.to_string().contains("expected 2"));
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
    fn static_schedule_is_relative_to_its_configuration() {
        let directory =
            std::env::temp_dir().join(format!("neqo-csdef-config-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let schedule = directory.join("schedule.csv");
        fs::write(&schedule, "0.000000,1200\n").expect("write schedule");
        let config_path = directory.join("config.toml");
        fs::write(
            &config_path,
            r#"
                schema_version = 2
                [defense]
                kind = "static"
                schedule = "schedule.csv"
                padding_only = true
            "#,
        )
        .expect("write configuration");

        let config = QcsdConfig::from_toml_file(&config_path).expect("load configuration");
        assert_eq!(
            config.defense,
            DefenseConfig::Static {
                schedule: PathBuf::from(&schedule).to_string_lossy().into_owned(),
                padding_only: true,
            }
        );
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn defense_parameter_files_are_relative_to_their_configuration() {
        let directory = std::env::temp_dir().join(format!(
            "neqo-csdef-parameter-config-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("create temporary directory");
        let cases = [
            (
                "traffic_morphing",
                "matrix",
                "matrix.json",
                "workload_id = \"test-workload\"\n",
            ),
            ("wtf_pad", "histograms", "histograms.json", ""),
            (
                "walkie_talkie",
                "molded",
                "molded.json",
                "workload_id = \"test-workload\"\n",
            ),
        ];
        for (kind, field, filename, extra) in cases {
            let parameter_path = directory.join(filename);
            fs::write(&parameter_path, "{}").expect("write parameter fixture");
            let config_path = directory.join(format!("{kind}.toml"));
            fs::write(
                &config_path,
                format!(
                    "schema_version = 2\n[defense]\nkind = \"{kind}\"\n{field} = \"{filename}\"\n{extra}"
                ),
            )
            .expect("write configuration");
            let config = QcsdConfig::from_toml_file(&config_path).expect("load configuration");
            assert_eq!(
                config.defense.parameter_path(),
                Some(parameter_path.to_string_lossy().as_ref())
            );
        }
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn reactive_defense_bounds_are_validated() {
        let too_small = QcsdConfig {
            defense: DefenseConfig::TrafficMorphing(TrafficMorphingConfig {
                matrix: "matrix.json".into(),
                workload_id: "test-workload".into(),
                ingress_packet_size: 63,
                ..TrafficMorphingConfig::default()
            }),
            ..QcsdConfig::default()
        };
        assert!(too_small.validate().is_err());

        let unbounded_padding = QcsdConfig {
            defense: DefenseConfig::WtfPad(WtfPadConfig {
                histograms: "histograms.json".into(),
                max_padding_events: 0,
                ..WtfPadConfig::default()
            }),
            ..QcsdConfig::default()
        };
        assert!(unbounded_padding.validate().is_err());
    }
}
