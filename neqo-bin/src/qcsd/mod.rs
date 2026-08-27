// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Reproducible, current-thread QCSD research runner.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs::{self, File},
    io::{self, Write as _},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant, SystemTime},
};

use clap::{Parser, Subcommand, ValueEnum};
use futures::{
    FutureExt as _,
    future::{select, select_all},
};
use http::Uri;
use neqo_common::{Header, event::Provider as _};
use neqo_csdef::{
    ChaffManifest, ChaffQualification, DefenseConfig, DefenseDiagnostics, DefenseKind,
    DependencyTracker, Direction, ExpectedChaffResponse, MissedSlotReason, Packet, QcsdAction,
    QcsdChaffRequestId, QcsdConfig, QcsdController, QcsdEndpointId, QcsdObservation,
    QcsdObservationClock, QcsdProfile, QcsdReceiveActionIdentity, QcsdReceiveLimitError,
    QcsdReceiveLimitFatal, QcsdReceiveLimitOutcome, QcsdRequestRole, QcsdSendPolicy,
    QcsdSlotComposition, QcsdSlotId, QcsdSlotOutcome, QcsdStreamTransmission, Resource,
    ResourceManifest, ResourceRunState, ResponseOnlyChaffManifest, ResponseOnlyChaffManifestV4,
    ResponseOnlyChaffQualification, ResponseOnlyChaffQualificationV4, StaticMode,
    TimestampedQcsdObservation, TrafficMorphingEgress, WalkieTalkie,
    WalkieTalkieQualificationBinding, derive, normalize_content_encoding, sanitize_chaff_headers,
};
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Priority};
use neqo_transport::{
    Connection, ConnectionParameters, OutputBatch, Pmtud, RandomConnectionIdGenerator, StreamId,
    StreamType,
};
use neqo_udp::RecvBuf;
use nss::{AuthenticationStatus, hash::HashAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::udp::Socket;

mod trace_files;

use trace_files::{PacketTraceRow, QcsdTraceColumns, ScheduleTraceRow, TraceFiles};

const NEQO_BASE_COMMIT: &str = "8a04d065c2d35c8e8fd804f91c7081ab6bb60b89";
const PUBLISHED_QCSD_COMMIT: &str = "39e293fb384dd341156eedd1e4b833d24904b1f6";
const SUSTAINED_QUALIFICATION_REQUESTS: usize = 40;
const SUSTAINED_QUALIFICATION_PARALLEL_REQUESTS: usize = 5;
const SUSTAINED_QUALIFICATION_WAVES: usize =
    SUSTAINED_QUALIFICATION_REQUESTS / SUSTAINED_QUALIFICATION_PARALLEL_REQUESTS;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid arguments: {0}")]
    Argument(String),
    #[error(transparent)]
    Http3(#[from] neqo_http3::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Nss(#[from] nss::Error),
    #[error(transparent)]
    Qcsd(#[from] neqo_csdef::Error),
    #[error(transparent)]
    Transport(#[from] neqo_transport::Error),
    #[error("run timed out after {0} seconds")]
    Timeout(u64),
    #[error("run aborted: {0}")]
    RunAborted(String),
    #[error("QCSD slot accounting invariant failed: {0}")]
    SlotInvariant(String),
    #[error(transparent)]
    ReceiveLimit(#[from] QcsdReceiveLimitError),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Preset {
    PublishedFront,
    PublishedTamaraw,
    ConservativeLive,
}

impl Preset {
    fn resolve(self) -> neqo_csdef::Result<QcsdConfig> {
        match self {
            Self::PublishedFront => QcsdProfile::Published.resolve(DefenseKind::Front),
            Self::PublishedTamaraw => QcsdProfile::Published.resolve(DefenseKind::Tamaraw),
            Self::ConservativeLive => QcsdProfile::Live.resolve(DefenseKind::Front),
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProfileArg {
    Published,
    Live,
    #[value(name = "research-1200")]
    Research1200,
}

impl From<ProfileArg> for QcsdProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Published => Self::Published,
            ProfileArg::Live => Self::Live,
            ProfileArg::Research1200 => Self::Research1200,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum DefenseArg {
    None,
    Static,
    Front,
    Tamaraw,
    TrafficMorphing,
    WtfPad,
    WalkieTalkie,
    Buflo,
    CsBuflo,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum StaticModeArg {
    ChaffOnly,
    ChaffAndShape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum RequestPolicyArg {
    AsDefined,
    HalfDuplex,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ChaffRequestHeaderModeArg {
    #[value(name = "identity-chaff-v1")]
    IdentityChaffV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseQualificationMode {
    Legacy,
    SustainedIdentity,
}

impl From<StaticModeArg> for StaticMode {
    fn from(value: StaticModeArg) -> Self {
        match value {
            StaticModeArg::ChaffOnly => Self::ChaffOnly,
            StaticModeArg::ChaffAndShape => Self::ChaffAndShape,
        }
    }
}

fn response_qualification_mode(
    parallel_requests: usize,
    total_requests: Option<usize>,
    request_header_mode: Option<ChaffRequestHeaderModeArg>,
) -> Result<ResponseQualificationMode, Error> {
    match (total_requests, request_header_mode) {
        (None, None) if (5..=20).contains(&parallel_requests) => {
            Ok(ResponseQualificationMode::Legacy)
        }
        (
            Some(SUSTAINED_QUALIFICATION_REQUESTS),
            Some(ChaffRequestHeaderModeArg::IdentityChaffV1),
        ) if parallel_requests == SUSTAINED_QUALIFICATION_PARALLEL_REQUESTS =>
        {
            Ok(ResponseQualificationMode::SustainedIdentity)
        }
        (None, None) => Err(Error::Argument(
            "legacy response qualification requires 5..=20 parallel_requests".into(),
        )),
        _ => Err(Error::Argument(
            "sustained response qualification requires the exact paired flags --total-requests 40 --parallel-requests 5 --request-header-mode identity-chaff-v1"
                .into(),
        )),
    }
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Run client-side QCSD defenses with current Neqo"
)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "clap owns one selected command and its audited path-valued options"
)]
enum Command {
    /// Verify HTTP/3 connectivity and build a same-origin resource manifest.
    Probe {
        #[arg(required_unless_present = "input_manifest")]
        urls: Vec<Uri>,
        /// Preserve and enrich an existing discovered workload graph.
        #[arg(long, conflicts_with = "urls")]
        input_manifest: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 1_048_576)]
        max_bytes: u64,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    /// Qualify the exact concurrent compact selected-resource cohort over HTTP/3.
    QualifyChaffResponse {
        /// Exact frozen prepared source; response identities select and verify the live resource.
        #[arg(long)]
        workload: PathBuf,
        /// Application navigation root identity; current qualification requires zero.
        #[arg(long)]
        application_resource_id: u32,
        /// Deterministically selected same-origin application resource to project to AEL.
        #[arg(long)]
        selected_chaff_resource_id: u32,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        parallel_requests: usize,
        /// Total requests on the one sustained connection; schema three requires exactly 40.
        #[arg(long)]
        total_requests: Option<usize>,
        /// Isolated chaff request-header derivation; paired with --total-requests.
        #[arg(long, value_enum)]
        request_header_mode: Option<ChaffRequestHeaderModeArg>,
        #[arg(long, default_value_t = 1_048_576)]
        max_response_bytes: u64,
        #[arg(long, default_value_t = 1_200)]
        packet_size: u16,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    /// Prove every production Walkie-Talkie request-prefix activation stage.
    QualifyChaffPrefix {
        /// Exact frozen prepared source whose response identities bind every component batch.
        #[arg(long)]
        workload: PathBuf,
        /// Exact projected runtime workload used by defended execution (R).
        #[arg(long)]
        runtime_workload: PathBuf,
        /// Acyclic compact chaff core derived from response qualification.
        #[arg(long)]
        chaff_core: PathBuf,
        /// Dependency-free application navigation root bound to activation component zero.
        #[arg(long)]
        application_resource_id: u32,
        /// Immutable every-component Walkie-Talkie staged prefix-pack specification.
        #[arg(long)]
        prefix_pack_spec: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    /// Run one built-in, static, or reactive defense from a resolved configuration.
    Run {
        /// Explicit URLs for small manual runs. Use --workload for dependency graphs.
        urls: Vec<Uri>,
        /// Versioned application workload manifest.
        #[arg(long, conflicts_with = "urls")]
        workload: Option<PathBuf>,
        /// Exact frozen prepared source whose raw bytes bind qualified chaff.
        #[arg(long, requires = "workload")]
        application_workload_source: Option<PathBuf>,
        /// Complete custom configuration for thesis defenses and imported runs.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Compatibility alias for the published pre-profile runner interface.
        #[arg(
            long,
            value_enum,
            conflicts_with_all = [
                "config",
                "profile",
                "defense",
                "schedule",
                "static_mode",
                "buflo_parameters",
                "cs_buflo_parameters",
                "morphing_matrix",
                "wtf_pad_histograms",
                "walkie_talkie_molded"
            ]
        )]
        preset: Option<Preset>,
        /// Complete QCSD parameter family.
        #[arg(long, value_enum, conflicts_with_all = ["config", "preset"])]
        profile: Option<ProfileArg>,
        /// Defense selected from --profile.
        #[arg(long, value_enum, conflicts_with_all = ["config", "preset"])]
        defense: Option<DefenseArg>,
        /// Static schedule containing `seconds,signed_size` records.
        #[arg(long)]
        schedule: Option<PathBuf>,
        /// Whether Static capacity is chaff-only or shapes application traffic.
        #[arg(long, value_enum)]
        static_mode: Option<StaticModeArg>,
        /// Immutable versioned `BuFLO` numeric-parameter receipt.
        #[arg(long)]
        buflo_parameters: Option<PathBuf>,
        /// Immutable versioned CS-BuFLO receipt selecting CTSP or CPSP.
        #[arg(long)]
        cs_buflo_parameters: Option<PathBuf>,
        /// Workload-bound Traffic Morphing source-to-decoy matrix bundle.
        #[arg(long)]
        morphing_matrix: Option<PathBuf>,
        /// WTF-PAD adaptive-padding histograms.
        #[arg(long)]
        wtf_pad_histograms: Option<PathBuf>,
        /// Walkie-Talkie molded burst sequence.
        #[arg(long)]
        walkie_talkie_molded: Option<PathBuf>,
        /// Workload identity selecting a Traffic Morphing or Walkie-Talkie profile.
        #[arg(long)]
        workload_id: Option<String>,
        /// Explicit current qualified chaff manifest required by every defended run.
        #[arg(long = "chaff-manifest", visible_alias = "manifest")]
        chaff_manifest: Option<PathBuf>,
        /// Application request dispatch policy used by the campaign collector.
        #[arg(long, value_enum, default_value_t = RequestPolicyArg::AsDefined)]
        request_policy: RequestPolicyArg,
        #[arg(long)]
        seed: u64,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        max_response_bytes: u64,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
    },
}

impl Args {
    /// Execute the selected probe or research run.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid inputs, network/protocol failures, output
    /// failures, or when the configured run timeout expires.
    #[expect(
        clippy::future_not_send,
        clippy::too_many_lines,
        reason = "the binary deliberately uses Tokio's current-thread runtime"
    )]
    pub async fn execute(self) -> Result<(), Error> {
        if let Command::QualifyChaffResponse {
            parallel_requests,
            total_requests,
            request_header_mode,
            ..
        } = &self.command
        {
            response_qualification_mode(*parallel_requests, *total_requests, *request_header_mode)?;
        }
        neqo_common::log::init(None);
        nss::init()?;
        match self.command {
            Command::Probe {
                urls,
                input_manifest,
                output,
                max_bytes,
                timeout_seconds,
            } => {
                probe(
                    urls,
                    input_manifest.as_deref(),
                    &output,
                    max_bytes,
                    timeout_seconds,
                )
                .await
            }
            Command::Run {
                urls,
                workload,
                application_workload_source,
                config,
                preset,
                profile,
                defense,
                schedule,
                static_mode,
                buflo_parameters,
                cs_buflo_parameters,
                morphing_matrix,
                wtf_pad_histograms,
                walkie_talkie_molded,
                workload_id,
                chaff_manifest,
                request_policy,
                seed,
                output_dir,
                max_response_bytes,
                timeout_seconds,
            } => {
                let mut config = resolve_run_config_with_workload(
                    config.as_deref(),
                    preset,
                    profile,
                    defense,
                    schedule.as_deref(),
                    static_mode,
                    buflo_parameters.as_deref(),
                    cs_buflo_parameters.as_deref(),
                    morphing_matrix.as_deref(),
                    wtf_pad_histograms.as_deref(),
                    walkie_talkie_molded.as_deref(),
                    workload_id.as_deref(),
                )?;
                config.validate()?;
                if urls.is_empty() == workload.is_none() {
                    return Err(Error::Argument(
                        "provide exactly one of positional URLs or --workload".into(),
                    ));
                }
                let (workload, workload_hash) = if let Some(path) = workload {
                    load_manifest(&path)?
                } else {
                    let manifest = positional_manifest(&urls);
                    let hash = manifest_hash(&manifest)?;
                    (manifest, hash)
                };
                let application_workload_source = application_workload_source
                    .as_deref()
                    .map(load_application_workload_source)
                    .transpose()?;
                let (chaff_manifest, chaff_manifest_hash) = if let Some(path) = chaff_manifest {
                    let (manifest, raw_hash) = load_chaff_manifest(&path)?;
                    (Some(manifest), Some(raw_hash))
                } else {
                    (None, None)
                };
                if let Some(chaff) = &chaff_manifest {
                    validate_chaff_manifest_defense(&config.defense, chaff)?;
                    if !matches!(config.defense, DefenseConfig::None) {
                        bind_qualified_chaff_stream_limits(&mut config, chaff)?;
                    }
                }
                let defense_parameters = defense_parameter_provenance(&config)?;
                if !matches!(config.defense, DefenseConfig::None) && chaff_manifest.is_none() {
                    return Err(Error::Argument(
                        "every defended run requires an explicit current qualified --chaff-manifest"
                            .into(),
                    ));
                }
                if !matches!(config.defense, DefenseConfig::None)
                    && application_workload_source.is_none()
                {
                    return Err(Error::Argument(
                        "every defended run requires --application-workload-source binding the exact frozen prepared workload"
                            .into(),
                    ));
                }
                if matches!(config.defense, DefenseConfig::None) && chaff_manifest.is_some() {
                    return Err(Error::Argument(
                        "undefended runs must not supply --chaff-manifest".into(),
                    ));
                }
                if matches!(config.defense, DefenseConfig::None)
                    && application_workload_source.is_some()
                {
                    return Err(Error::Argument(
                        "undefended runs must not supply --application-workload-source".into(),
                    ));
                }
                let spec = RunSpec {
                    method: "GET",
                    workload,
                    workload_hash,
                    application_workload_source,
                    config,
                    defense_parameters,
                    chaff_manifest,
                    chaff_manifest_hash,
                    request_policy,
                    seed,
                    output_dir,
                    max_response_bytes,
                    timeout_seconds,
                };
                execute_run(spec).await.map(|_| ())
            }
            Command::QualifyChaffResponse {
                workload,
                application_resource_id,
                selected_chaff_resource_id,
                output_dir,
                parallel_requests,
                total_requests,
                request_header_mode,
                max_response_bytes,
                packet_size,
                timeout_seconds,
            } => {
                qualify_chaff_response(
                    &workload,
                    application_resource_id,
                    selected_chaff_resource_id,
                    &output_dir,
                    parallel_requests,
                    total_requests,
                    request_header_mode,
                    max_response_bytes,
                    packet_size,
                    timeout_seconds,
                )
                .await
            }
            Command::QualifyChaffPrefix {
                workload,
                runtime_workload,
                chaff_core,
                application_resource_id,
                prefix_pack_spec,
                output_dir,
                timeout_seconds,
            } => {
                qualify_chaff_prefix(
                    &workload,
                    &runtime_workload,
                    &chaff_core,
                    application_resource_id,
                    &prefix_pack_spec,
                    &output_dir,
                    timeout_seconds,
                )
                .await
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the resolver audits every mutually exclusive defense parameter explicitly"
)]
fn resolve_run_config_with_workload(
    config: Option<&Path>,
    preset: Option<Preset>,
    profile: Option<ProfileArg>,
    defense: Option<DefenseArg>,
    schedule: Option<&Path>,
    static_mode: Option<StaticModeArg>,
    buflo_parameters: Option<&Path>,
    cs_buflo_parameters: Option<&Path>,
    morphing_matrix: Option<&Path>,
    wtf_pad_histograms: Option<&Path>,
    walkie_talkie_molded: Option<&Path>,
    workload_id: Option<&str>,
) -> Result<QcsdConfig, Error> {
    let has_defense_options = schedule.is_some()
        || static_mode.is_some()
        || buflo_parameters.is_some()
        || cs_buflo_parameters.is_some()
        || morphing_matrix.is_some()
        || wtf_pad_histograms.is_some()
        || walkie_talkie_molded.is_some();
    if let Some(path) = config {
        if workload_id.is_some() {
            return Err(Error::Argument(
                "--config cannot be combined with --workload-id; bind it inside the config".into(),
            ));
        }
        if preset.is_some() || profile.is_some() || defense.is_some() || has_defense_options {
            return Err(Error::Argument(
                "--config cannot be combined with profile, preset, or defense options".into(),
            ));
        }
        return Ok(QcsdConfig::from_toml_file(path)?);
    }
    if let Some(preset) = preset {
        if workload_id.is_some() {
            return Err(Error::Argument(
                "--preset cannot be combined with --workload-id".into(),
            ));
        }
        if profile.is_some() || defense.is_some() || has_defense_options {
            return Err(Error::Argument(
                "--preset cannot be combined with profile or defense options".into(),
            ));
        }
        return Ok(preset.resolve()?);
    }
    let (Some(profile), Some(defense)) = (profile, defense) else {
        return Err(Error::Argument(
            "provide --config, --preset, or both --profile and --defense".into(),
        ));
    };
    reject_foreign_defense_options(
        defense,
        schedule,
        static_mode,
        buflo_parameters,
        cs_buflo_parameters,
        morphing_matrix,
        wtf_pad_histograms,
        walkie_talkie_molded,
    )?;
    if !matches!(
        defense,
        DefenseArg::TrafficMorphing | DefenseArg::WalkieTalkie
    ) && workload_id.is_some()
    {
        return Err(Error::Argument(
            "--workload-id is valid only with --defense traffic-morphing or walkie-talkie".into(),
        ));
    }
    let defense = match defense {
        DefenseArg::None => DefenseKind::None,
        DefenseArg::Front => DefenseKind::Front,
        DefenseArg::Tamaraw => DefenseKind::Tamaraw,
        DefenseArg::Buflo => {
            let Some(parameters) = buflo_parameters else {
                return Err(Error::Argument(
                    "--defense buflo requires --buflo-parameters".into(),
                ));
            };
            DefenseKind::Buflo {
                parameters: parameters.to_string_lossy().into_owned(),
            }
        }
        DefenseArg::CsBuflo => {
            let Some(parameters) = cs_buflo_parameters else {
                return Err(Error::Argument(
                    "--defense cs-buflo requires --cs-buflo-parameters".into(),
                ));
            };
            DefenseKind::CsBuflo {
                parameters: parameters.to_string_lossy().into_owned(),
            }
        }
        DefenseArg::Static => {
            let Some(schedule) = schedule else {
                return Err(Error::Argument(
                    "--defense static requires --schedule".into(),
                ));
            };
            let Some(mode) = static_mode else {
                return Err(Error::Argument(
                    "--defense static requires --static-mode".into(),
                ));
            };
            DefenseKind::Static {
                schedule: schedule.to_string_lossy().into_owned(),
                mode: mode.into(),
            }
        }
        DefenseArg::TrafficMorphing => {
            let Some(matrix) = morphing_matrix else {
                return Err(Error::Argument(
                    "--defense traffic-morphing requires --morphing-matrix".into(),
                ));
            };
            let Some(workload_id) = workload_id else {
                return Err(Error::Argument(
                    "--defense traffic-morphing requires --workload-id".into(),
                ));
            };
            if workload_id.trim().is_empty() {
                return Err(Error::Argument("--workload-id must not be empty".into()));
            }
            DefenseKind::TrafficMorphing {
                matrix: matrix.to_string_lossy().into_owned(),
                workload_id: workload_id.into(),
            }
        }
        DefenseArg::WtfPad => {
            let Some(histograms) = wtf_pad_histograms else {
                return Err(Error::Argument(
                    "--defense wtf-pad requires --wtf-pad-histograms".into(),
                ));
            };
            DefenseKind::WtfPad {
                histograms: histograms.to_string_lossy().into_owned(),
            }
        }
        DefenseArg::WalkieTalkie => {
            let Some(molded) = walkie_talkie_molded else {
                return Err(Error::Argument(
                    "--defense walkie-talkie requires --walkie-talkie-molded".into(),
                ));
            };
            let Some(workload_id) = workload_id else {
                return Err(Error::Argument(
                    "--defense walkie-talkie requires --workload-id".into(),
                ));
            };
            if workload_id.trim().is_empty() {
                return Err(Error::Argument("--workload-id must not be empty".into()));
            }
            DefenseKind::WalkieTalkie {
                molded: molded.to_string_lossy().into_owned(),
                workload_id: workload_id.into(),
            }
        }
    };
    Ok(QcsdProfile::from(profile).resolve(defense)?)
}

#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "test compatibility helper mirrors the public defense options"
)]
fn resolve_run_config(
    config: Option<&Path>,
    preset: Option<Preset>,
    profile: Option<ProfileArg>,
    defense: Option<DefenseArg>,
    schedule: Option<&Path>,
    static_mode: Option<StaticModeArg>,
    morphing_matrix: Option<&Path>,
    wtf_pad_histograms: Option<&Path>,
    walkie_talkie_molded: Option<&Path>,
) -> Result<QcsdConfig, Error> {
    resolve_run_config_with_workload(
        config,
        preset,
        profile,
        defense,
        schedule,
        static_mode,
        None,
        None,
        morphing_matrix,
        wtf_pad_histograms,
        walkie_talkie_molded,
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "every mutually exclusive defense receipt is audited explicitly"
)]
fn reject_foreign_defense_options(
    selected: DefenseArg,
    schedule: Option<&Path>,
    static_mode: Option<StaticModeArg>,
    buflo_parameters: Option<&Path>,
    cs_buflo_parameters: Option<&Path>,
    morphing_matrix: Option<&Path>,
    wtf_pad_histograms: Option<&Path>,
    walkie_talkie_molded: Option<&Path>,
) -> Result<(), Error> {
    let has_foreign = (selected != DefenseArg::Static
        && (schedule.is_some() || static_mode.is_some()))
        || (selected != DefenseArg::Buflo && buflo_parameters.is_some())
        || (selected != DefenseArg::CsBuflo && cs_buflo_parameters.is_some())
        || (selected != DefenseArg::TrafficMorphing && morphing_matrix.is_some())
        || (selected != DefenseArg::WtfPad && wtf_pad_histograms.is_some())
        || (selected != DefenseArg::WalkieTalkie && walkie_talkie_molded.is_some());
    if has_foreign {
        return Err(Error::Argument(
            "defense parameter options must match the selected --defense".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct DefenseParameterProvenance {
    kind: &'static str,
    path: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    implementation_scope: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paper_equivalent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    early_termination_semantics: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_tcp_write_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_nominal_tcp_packet_size_bytes: Option<u64>,
}

fn defense_parameter_provenance(
    config: &QcsdConfig,
) -> Result<Option<DefenseParameterProvenance>, Error> {
    let (kind, path, scope, paper_equivalent, early_termination, reference_write, reference_packet) =
        match &config.defense {
            DefenseConfig::Static { schedule, .. } => {
                ("static", schedule.as_str(), None, None, None, None, None)
            }
            DefenseConfig::TrafficMorphing(config) => (
                "traffic_morphing",
                config.matrix.as_str(),
                None,
                None,
                None,
                None,
                None,
            ),
            DefenseConfig::WtfPad(config) => (
                "wtf_pad",
                config.histograms.as_str(),
                None,
                None,
                None,
                None,
                None,
            ),
            DefenseConfig::WalkieTalkie(config) => (
                "walkie_talkie",
                config.molded.as_str(),
                None,
                None,
                None,
                None,
                None,
            ),
            DefenseConfig::Buflo(config) => (
                "buflo",
                config.parameters.as_str(),
                Some("client_only_quic"),
                Some(false),
                None,
                None,
                None,
            ),
            DefenseConfig::CsBuflo(config) => (
                "cs_buflo",
                config.parameters.as_str(),
                Some("client_only_quic"),
                Some(false),
                Some("udp_client_only_observed_udp_power_of_two_crossing"),
                Some(548),
                Some(600),
            ),
            DefenseConfig::None | DefenseConfig::Front(_) | DefenseConfig::Tamaraw(_) => {
                return Ok(None);
            }
        };
    let contents = fs::read(path)?;
    Ok(Some(DefenseParameterProvenance {
        kind,
        path: path.to_string(),
        sha256: sha256(&contents)?,
        implementation_scope: scope,
        paper_equivalent,
        early_termination_semantics: early_termination,
        reference_tcp_write_size_bytes: reference_write,
        reference_nominal_tcp_packet_size_bytes: reference_packet,
    }))
}

enum RuntimeChaffManifest {
    SchemaTwo(ChaffManifest),
    ResponseOnlyV3(ResponseOnlyChaffManifest),
    ResponseOnlyV4(ResponseOnlyChaffManifestV4),
}

struct RuntimeChaffQualification<'a> {
    request_stream_bytes: u64,
    expected_response: &'a ExpectedChaffResponse,
}

impl RuntimeChaffQualification<'_> {
    const fn request_stream_bytes(&self) -> u64 {
        self.request_stream_bytes
    }

    const fn expected_response(&self) -> &ExpectedChaffResponse {
        self.expected_response
    }
}

impl From<ChaffManifest> for RuntimeChaffManifest {
    fn from(value: ChaffManifest) -> Self {
        Self::SchemaTwo(value)
    }
}

impl From<ResponseOnlyChaffManifest> for RuntimeChaffManifest {
    fn from(value: ResponseOnlyChaffManifest) -> Self {
        Self::ResponseOnlyV3(value)
    }
}

impl From<ResponseOnlyChaffManifestV4> for RuntimeChaffManifest {
    fn from(value: ResponseOnlyChaffManifestV4) -> Self {
        Self::ResponseOnlyV4(value)
    }
}

impl RuntimeChaffManifest {
    fn from_json(input: &str) -> neqo_csdef::Result<Self> {
        let value: serde_json::Value = serde_json::from_str(input)?;
        match value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
        {
            Some(2) => ChaffManifest::from_json(input).map(Self::SchemaTwo),
            Some(3) => ResponseOnlyChaffManifest::from_json(input).map(Self::ResponseOnlyV3),
            Some(4) => ResponseOnlyChaffManifestV4::from_json(input).map(Self::ResponseOnlyV4),
            _ => Err(neqo_csdef::Error::InvalidConfig(
                "qualified chaff manifest schema_version must be exactly 2, 3, or 4".into(),
            )),
        }
    }

    const fn schema_two(&self) -> Option<&ChaffManifest> {
        match self {
            Self::SchemaTwo(manifest) => Some(manifest),
            Self::ResponseOnlyV3(_) | Self::ResponseOnlyV4(_) => None,
        }
    }

    const fn is_response_only(&self) -> bool {
        matches!(self, Self::ResponseOnlyV3(_) | Self::ResponseOnlyV4(_))
    }

    const fn is_identity_chaff_v4(&self) -> bool {
        matches!(self, Self::ResponseOnlyV4(_))
    }

    fn application_workload_sha256(&self) -> &str {
        match self {
            Self::SchemaTwo(manifest) => &manifest.application_workload_sha256,
            Self::ResponseOnlyV3(manifest) => &manifest.application_workload_sha256,
            Self::ResponseOnlyV4(manifest) => &manifest.application_workload_sha256,
        }
    }

    const fn application_resource_id(&self) -> u32 {
        match self {
            Self::SchemaTwo(manifest) => manifest.application_resource_id,
            Self::ResponseOnlyV3(manifest) => manifest.application_resource_id,
            Self::ResponseOnlyV4(manifest) => manifest.application_resource_id,
        }
    }

    const fn selected_chaff_resource_id(&self) -> u32 {
        match self {
            Self::SchemaTwo(manifest) => manifest.selected_chaff_resource_id,
            Self::ResponseOnlyV3(manifest) => manifest.selected_chaff_resource_id,
            Self::ResponseOnlyV4(manifest) => manifest.selected_chaff_resource_id,
        }
    }

    const fn qualified_parallel_chaff_streams(&self) -> usize {
        match self {
            Self::SchemaTwo(manifest) => manifest.qualified_parallel_chaff_streams,
            Self::ResponseOnlyV3(manifest) => manifest.qualified_parallel_chaff_streams,
            Self::ResponseOnlyV4(manifest) => manifest.qualified_parallel_chaff_streams,
        }
    }

    fn resource_manifest(&self) -> ResourceManifest {
        match self {
            Self::SchemaTwo(manifest) => manifest.resource_manifest(),
            Self::ResponseOnlyV3(manifest) => manifest.resource_manifest(),
            Self::ResponseOnlyV4(manifest) => manifest.resource_manifest(),
        }
    }

    fn selected_resource(&self) -> Resource {
        self.resource_manifest()
            .resources
            .into_iter()
            .next()
            .expect("validated chaff manifests contain exactly one resource")
    }

    fn qualification(&self, resource_id: u32) -> Option<RuntimeChaffQualification<'_>> {
        match self {
            Self::SchemaTwo(manifest) => {
                manifest
                    .qualification(resource_id)
                    .map(
                        |qualification: &ChaffQualification| RuntimeChaffQualification {
                            request_stream_bytes: qualification.request_stream_bytes,
                            expected_response: &qualification.expected_response,
                        },
                    )
            }
            Self::ResponseOnlyV3(manifest) => manifest.qualification(resource_id).map(
                |qualification: &ResponseOnlyChaffQualification| RuntimeChaffQualification {
                    request_stream_bytes: qualification.request_stream_bytes,
                    expected_response: &qualification.expected_response,
                },
            ),
            Self::ResponseOnlyV4(manifest) => manifest.qualification(resource_id).map(
                |qualification: &ResponseOnlyChaffQualificationV4| RuntimeChaffQualification {
                    request_stream_bytes: qualification.request_stream_bytes,
                    expected_response: &qualification.expected_response,
                },
            ),
        }
    }
}

fn validate_chaff_manifest_defense(
    defense: &DefenseConfig,
    chaff: &RuntimeChaffManifest,
) -> Result<(), Error> {
    if chaff.is_response_only()
        && !matches!(
            defense,
            DefenseConfig::Front(_)
                | DefenseConfig::Tamaraw(_)
                | DefenseConfig::Buflo(_)
                | DefenseConfig::CsBuflo(_)
        )
    {
        return Err(Error::Argument(
            "response-only schema-three/four chaff manifests are accepted only for FRONT, Tamaraw, BuFLO, and CS-BuFLO"
                .into(),
        ));
    }
    Ok(())
}

fn bind_qualified_chaff_stream_limits(
    config: &mut QcsdConfig,
    chaff: &RuntimeChaffManifest,
) -> Result<(), Error> {
    if matches!(config.defense, DefenseConfig::WalkieTalkie(_)) {
        let schema_two = chaff.schema_two().ok_or_else(|| {
            Error::Argument(
                "Walkie-Talkie requires a schema-two prefix-qualified chaff manifest".into(),
            )
        })?;
        config.max_chaff_streams = schema_two.walkie_talkie_required_chaff_streams;
        config.validate()?;
    }
    if config.max_chaff_streams > chaff.qualified_parallel_chaff_streams() {
        return Err(Error::Argument(format!(
            "configured max_chaff_streams {} exceeds response-qualified parallel cohort {}",
            config.max_chaff_streams,
            chaff.qualified_parallel_chaff_streams()
        )));
    }
    Ok(())
}

struct RunSpec {
    method: &'static str,
    workload: ResourceManifest,
    workload_hash: String,
    application_workload_source: Option<(
        ResourceManifest,
        String,
        BTreeMap<u32, PreparedExpectedResponse>,
    )>,
    config: QcsdConfig,
    defense_parameters: Option<DefenseParameterProvenance>,
    chaff_manifest: Option<RuntimeChaffManifest>,
    chaff_manifest_hash: Option<String>,
    request_policy: RequestPolicyArg,
    seed: u64,
    output_dir: PathBuf,
    max_response_bytes: u64,
    timeout_seconds: u64,
}

struct RunCompletion<'a> {
    ended_unix_ns: Option<u128>,
    status: &'a str,
    error: Option<&'a str>,
    defense_start_monotonic_ns: Option<u64>,
    application_completion_monotonic_ns: Option<u64>,
    defense_diagnostics: Option<DefenseDiagnostics>,
    runner_wakeup_metrics: Option<RunnerWakeupMetrics>,
}

const QCSD_CLIENT_SCHEDULER_CONTRACT: &str = "qcsd-client-rr1-cpu10-v1";

fn requested_scheduler_contract() -> Result<Option<String>, Error> {
    match std::env::var("QCSD_CAPTURE_SCHEDULER_CONTRACT") {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::RunAborted(
            "client scheduler contract is not valid UTF-8".into(),
        )),
    }
}

#[derive(Clone, Debug, Serialize)]
struct RealtimePriorityLimit {
    soft: u64,
    hard: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ProcessSchedulerEvidence {
    schema_version: u32,
    source: &'static str,
    policy: String,
    priority: i32,
    affinity_cpus: Vec<usize>,
    rlimit_rtprio: RealtimePriorityLimit,
    no_new_privileges: Option<bool>,
    effective_capabilities_hex: Option<String>,
    cgroup_effective_cpuset: Option<String>,
    affinity_scope: &'static str,
    contract: Option<String>,
    contract_valid: bool,
}

fn scheduler_contract_matches(evidence: &ProcessSchedulerEvidence) -> bool {
    evidence.contract.as_deref().is_none_or(|value| {
        value == QCSD_CLIENT_SCHEDULER_CONTRACT
            && evidence.source == "linux-sched-and-procfs-v1"
            && evidence.policy == "SCHED_RR"
            && evidence.priority == 1
            && evidence.affinity_cpus == [10]
            && evidence.rlimit_rtprio.soft == 1
            && evidence.rlimit_rtprio.hard == 1
            && evidence.no_new_privileges == Some(true)
            && evidence.effective_capabilities_hex.as_deref() == Some("0000000000000000")
            && evidence.cgroup_effective_cpuset.as_deref() == Some("10-11")
            && evidence.affinity_scope
                == "qcsd_container_affinity_partition_not_physical_cpu_isolation"
    })
}

#[cfg(target_os = "linux")]
fn process_scheduler_evidence() -> Result<ProcessSchedulerEvidence, Error> {
    let policy = {
        // SAFETY: Querying the current process does not dereference pointers.
        let value = unsafe { libc::sched_getscheduler(0) };
        if value < 0 {
            return Err(io::Error::last_os_error().into());
        }
        value
    };
    let mut parameters = libc::sched_param { sched_priority: 0 };
    // SAFETY: `parameters` is a valid writable sched_param for this process.
    if unsafe { libc::sched_getparam(0, &raw mut parameters) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: A zeroed cpu_set_t is a valid destination for sched_getaffinity.
    let mut affinity: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: `affinity` and its exact size describe a valid writable buffer.
    if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut affinity) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let affinity_cpus = (0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| {
            // SAFETY: `cpu` is bounded by CPU_SETSIZE and `affinity` is initialized.
            unsafe { libc::CPU_ISSET(*cpu, &affinity) }
        })
        .collect::<Vec<_>>();
    // SAFETY: A zeroed rlimit is a valid destination for getrlimit.
    let mut rtprio: libc::rlimit = unsafe { mem::zeroed() };
    // SAFETY: `rtprio` is a valid writable rlimit for the RLIMIT_RTPRIO query.
    if unsafe { libc::getrlimit(libc::RLIMIT_RTPRIO, &raw mut rtprio) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer arguments for this query.
    let no_new_privileges_raw = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privileges_raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let no_new_privileges = no_new_privileges_raw == 1;
    let policy = match policy {
        libc::SCHED_OTHER => "SCHED_OTHER",
        libc::SCHED_FIFO => "SCHED_FIFO",
        libc::SCHED_RR => "SCHED_RR",
        libc::SCHED_BATCH => "SCHED_BATCH",
        libc::SCHED_IDLE => "SCHED_IDLE",
        _ => "SCHED_UNKNOWN",
    }
    .to_string();
    let effective_capabilities_hex =
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("CapEff:\t"))
                    .map(str::trim)
                    .map(str::to_string)
            });
    let cgroup_effective_cpuset = fs::read_to_string("/sys/fs/cgroup/cpuset.cpus.effective")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let contract = requested_scheduler_contract()?;
    let mut evidence = ProcessSchedulerEvidence {
        schema_version: 1,
        source: "linux-sched-and-procfs-v1",
        policy,
        priority: parameters.sched_priority,
        affinity_cpus,
        rlimit_rtprio: RealtimePriorityLimit {
            soft: rtprio.rlim_cur,
            hard: rtprio.rlim_max,
        },
        no_new_privileges: Some(no_new_privileges),
        effective_capabilities_hex,
        cgroup_effective_cpuset,
        affinity_scope: "qcsd_container_affinity_partition_not_physical_cpu_isolation",
        contract,
        contract_valid: false,
    };
    evidence.contract_valid = scheduler_contract_matches(&evidence);
    if !evidence.contract_valid {
        return Err(Error::RunAborted(format!(
            "client scheduler contract failed: contract={:?} policy={} priority={} affinity={:?} rtprio={}/{} no_new_privileges={:?} effective_capabilities={:?} cgroup_effective_cpuset={:?}",
            evidence.contract,
            evidence.policy,
            evidence.priority,
            evidence.affinity_cpus,
            evidence.rlimit_rtprio.soft,
            evidence.rlimit_rtprio.hard,
            evidence.no_new_privileges,
            evidence.effective_capabilities_hex,
            evidence.cgroup_effective_cpuset,
        )));
    }
    Ok(evidence)
}

#[cfg(not(target_os = "linux"))]
fn process_scheduler_evidence() -> Result<ProcessSchedulerEvidence, Error> {
    let contract = requested_scheduler_contract()?;
    if contract.is_some() {
        return Err(Error::RunAborted(
            "client scheduler contract is supported only on Linux".into(),
        ));
    }
    Ok(ProcessSchedulerEvidence {
        schema_version: 1,
        source: "unsupported-platform-v1",
        policy: "unavailable".into(),
        priority: 0,
        affinity_cpus: Vec::new(),
        rlimit_rtprio: RealtimePriorityLimit { soft: 0, hard: 0 },
        no_new_privileges: None,
        effective_capabilities_hex: None,
        cgroup_effective_cpuset: None,
        affinity_scope: "unavailable",
        contract,
        contract_valid: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct RunnerWakeupMetrics {
    schema_version: u32,
    semantics: &'static str,
    wait_returns: u64,
    socket_readiness_wakeups: u64,
    timer_wakeups: u64,
    controller_deadline_timer_wakeups: u64,
    other_timer_wakeups: u64,
}

impl RunnerWakeupMetrics {
    const fn new() -> Self {
        Self {
            schema_version: 1,
            semantics: "actual_select_return_source; socket_wins_simultaneous_readiness; controller_subset_is_effective_earliest_deadline; scheduled_cells_are_not_wakeups",
            wait_returns: 0,
            socket_readiness_wakeups: 0,
            timer_wakeups: 0,
            controller_deadline_timer_wakeups: 0,
            other_timer_wakeups: 0,
        }
    }

    const fn record(&mut self, wake: ActivityWake, controller_deadline_selected: bool) {
        self.wait_returns = self.wait_returns.saturating_add(1);
        match wake {
            ActivityWake::SocketReady => {
                self.socket_readiness_wakeups = self.socket_readiness_wakeups.saturating_add(1);
            }
            ActivityWake::Timer => {
                self.timer_wakeups = self.timer_wakeups.saturating_add(1);
                if controller_deadline_selected {
                    self.controller_deadline_timer_wakeups =
                        self.controller_deadline_timer_wakeups.saturating_add(1);
                } else {
                    self.other_timer_wakeups = self.other_timer_wakeups.saturating_add(1);
                }
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct ResponseResult {
    resource_id: u32,
    url: String,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    content_length: Option<u64>,
    bytes: u64,
    body_sha256: String,
    request_stream_bytes: u64,
    complete: bool,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct ChaffResponseResult {
    resource_id: u32,
    request_id: Option<u64>,
    url: String,
    request_headers: Vec<(String, String)>,
    request_stream_bytes: u64,
    expected_request_stream_bytes: Option<u64>,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    content_encoding: Option<String>,
    bytes: u64,
    body_sha256: Option<String>,
    complete: bool,
    status_match: Option<bool>,
    content_encoding_match: Option<bool>,
    body_bytes_match: Option<bool>,
    body_sha256_match: Option<bool>,
    identity_verified: Option<bool>,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct ResponseQualificationRequest {
    request_index: usize,
    stream_id: u64,
    request_stream_bytes: u64,
    status: Option<u16>,
    content_encoding: Option<String>,
    body_bytes: u64,
    body_sha256: Option<String>,
    complete: bool,
    outcome: &'static str,
}

#[derive(Debug, Serialize)]
struct SustainedResponseQualificationRequest {
    request_index: usize,
    wave_index: usize,
    stream_id: u64,
    request_stream_bytes: u64,
    status: Option<u16>,
    content_encoding: Option<String>,
    body_bytes: u64,
    body_sha256: Option<String>,
    complete: bool,
    outcome: &'static str,
}

fn qualification_content_encoding(headers: &[Header]) -> Option<String> {
    let fields: Vec<_> = headers
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case("content-encoding"))
        .map(Header::value_utf8)
        .collect();
    match fields.as_slice() {
        [] => normalize_content_encoding(None),
        [Ok(value)] => normalize_content_encoding(Some(value)),
        [Err(_)] | [_, _, ..] => None,
    }
}

fn sustained_qualification_content_encoding(headers: &[Header]) -> Result<String, Error> {
    let mut fields = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case("content-encoding"))
    {
        let value = header.value_utf8().map_err(|_| {
            Error::RunAborted(
                "sustained response qualification received a non-UTF-8 content-encoding field"
                    .into(),
            )
        })?;
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(Error::RunAborted(
                "sustained response qualification received an empty content-encoding field".into(),
            ));
        }
        fields.push(normalized);
    }
    Ok(if fields.is_empty() {
        "identity".into()
    } else {
        fields.join(", ")
    })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChaffQualificationCore {
    schema_version: u32,
    method: String,
    request_stream_bytes: u64,
    qualified_parallel_chaff_streams: usize,
    walkie_talkie_required_chaff_streams: usize,
    expected_response: ExpectedChaffResponse,
    response_qualification_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifiedChaffCoreResource {
    id: u32,
    url: String,
    #[serde(rename = "type")]
    kind: String,
    content_length: Option<u64>,
    data_length: u64,
    chaff_priority: bool,
    known_valid: bool,
    depends_on: Vec<u32>,
    headers: Vec<(String, String)>,
    chaff_qualification_core: ChaffQualificationCore,
}

impl QualifiedChaffCoreResource {
    fn as_resource(&self) -> Resource {
        Resource {
            id: self.id,
            url: self.url.clone(),
            kind: self.kind.clone(),
            content_length: self.content_length,
            data_length: self.data_length,
            chaff_priority: self.chaff_priority,
            known_valid: self.known_valid,
            depends_on: self.depends_on.clone(),
            headers: self.headers.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifiedChaffCore {
    schema_version: u32,
    artifact_type: String,
    application_workload_sha256: String,
    application_resource_id: u32,
    selected_chaff_resource_id: u32,
    qualified_parallel_chaff_streams: usize,
    walkie_talkie_required_chaff_streams: usize,
    resources: Vec<QualifiedChaffCoreResource>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrefixBurst {
    incoming: u64,
    outgoing: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrefixNumericProfile {
    bursts: Vec<PrefixBurst>,
    packet_size: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixPackSpec {
    schema_version: u32,
    artifact_type: String,
    workload_id: String,
    packet_size: u16,
    max_stream_data_excess: u64,
    maximum_receiver_continuation_reserve_horizon: usize,
    required_chaff_survivors: usize,
    numeric_profile_sha256: String,
    source_walkie_talkie_artifact_sha256: String,
    application_resource_id: u32,
    selected_chaff_resource_id: u32,
    selected_chaff_body_bytes: u64,
    required_chaff_streams: usize,
    stream_activation_stages: Vec<StreamActivationStage>,
    numeric_profile: PrefixNumericProfile,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StreamActivationStage {
    component_index: usize,
    application_resource_ids: Vec<u32>,
    exact_target_cells: u64,
    outgoing_cells: u64,
    symmetric_incoming_cells: u64,
    adapted_incoming_cells: u64,
    application_body_floor_bytes: u64,
    base_chaff_bytes: u64,
    continuation_bytes: u64,
    required_active_chaff_streams: usize,
    newly_required_chaff_streams: usize,
    future_continuation_reserves: usize,
    exact_capacity_before_bytes: u64,
    ordinary_capacity_before_bytes: u64,
    exact_capacity_after_bytes: u64,
    early_continuation_required: bool,
}

#[derive(Clone, Debug, Serialize)]
struct QualificationPacketObservation {
    sequence: u64,
    phase: &'static str,
    direction: &'static str,
    udp_payload_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
struct QualificationAcknowledgement {
    sequence: u64,
    offset: u64,
    bytes: u64,
    fin: bool,
}

#[derive(Debug, Serialize)]
struct PrefixRequestStream {
    request_order: usize,
    opening_stage_index: usize,
    role: &'static str,
    resource_id: u32,
    request_id: Option<u64>,
    stream_id: u64,
    request_stream_bytes: u64,
    qualified_request_stream_bytes: Option<u64>,
    acknowledgements: Vec<QualificationAcknowledgement>,
}

#[derive(Debug, Serialize)]
struct PrefixStreamReceipt<'a> {
    request_order: usize,
    opening_stage_index: usize,
    role: &'static str,
    resource_id: u32,
    request_id: Option<u64>,
    stream_id: u64,
    request_stream_bytes: u64,
    qualified_request_stream_bytes: Option<u64>,
    transmitted_unique_ranges: Vec<[u64; 2]>,
    transmitted_unique_bytes: u64,
    fin_transmitted: bool,
    acknowledgements: &'a [QualificationAcknowledgement],
    acknowledged_unique_ranges: Vec<[u64; 2]>,
    acknowledged_unique_bytes: u64,
    fin_acknowledged: bool,
}

#[derive(Debug, Serialize)]
struct PacketStatistics {
    incoming: PacketDirectionStats,
    outgoing: PacketDirectionStats,
    total: PacketDirectionStats,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedWorkloadSource {
    preparation: serde_json::Value,
    resources: Vec<Resource>,
    #[serde(default)]
    replay: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedExpectedResponse {
    resource_id: u32,
    status: u16,
    bytes: u64,
    body_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct PacketDirectionStats {
    packet_count: u64,
    observed_udp_payload_max: usize,
    oversized_packet_count: u64,
}

impl PacketDirectionStats {
    fn observe(&mut self, bytes: usize, ceiling: u16) {
        self.packet_count = self.packet_count.saturating_add(1);
        self.observed_udp_payload_max = self.observed_udp_payload_max.max(bytes);
        self.oversized_packet_count = self
            .oversized_packet_count
            .saturating_add(u64::from(bytes > usize::from(ceiling)));
    }
}

#[derive(Debug)]
struct StreamRecord {
    resource_id: u32,
    url: String,
    role: QcsdRequestRole,
    request_headers: Vec<(String, String)>,
    request_stream_bytes: u64,
    expected_request_stream_bytes: Option<u64>,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    content_length: Option<u64>,
    body: Vec<u8>,
    bytes: u64,
    complete: bool,
    outcome: &'static str,
    expected_chaff_response: Option<ExpectedChaffIdentity>,
}

#[derive(Clone, Debug)]
struct ExpectedChaffIdentity {
    status: u16,
    content_encoding: String,
    body_bytes: u64,
    body_sha256: String,
}

#[derive(Debug)]
struct ApplicationRequest {
    resource_id: u32,
    url: Uri,
    headers: Vec<(String, String)>,
    expected_response_length: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct ScheduledOutgoing {
    slot: QcsdSlotId,
    packet: Packet,
    /// Absolute adapter deadline derived from the same action timestamp and
    /// relative window passed to transport. A target is not accepted unless
    /// the committed UDP datagram reaches the OS socket before this instant.
    deadline: Instant,
}

#[derive(Clone, Copy, Debug)]
struct SatisfiedDatagram {
    slot: QcsdSlotId,
    observed_size: usize,
    status: &'static str,
    qcsd: QcsdTraceColumns,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrafficMorphingActivation {
    NotSelected,
    Pending,
    Active,
}

struct Endpoint {
    id: QcsdEndpointId,
    origin: Uri,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    socket: Socket,
    recv_buf: RecvBuf,
    client: Http3Client,
    pending: VecDeque<ApplicationRequest>,
    streams: HashMap<StreamId, StreamRecord>,
    /// Every application request send half opened on this endpoint. Entries
    /// remain after response retirement so candidate-defense completion can
    /// require peer confirmation of the corresponding QUIC bytes and FIN.
    application_send_streams: BTreeSet<StreamId>,
    completed: Vec<StreamRecord>,
    connected: bool,
    retired_applications: Vec<(u32, ResourceRunState)>,
    scheduled_outgoing: VecDeque<ScheduledOutgoing>,
    traffic_morphing_activation: TrafficMorphingActivation,
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn probe(
    urls: Vec<Uri>,
    input_manifest: Option<&Path>,
    output: &Path,
    max_bytes: u64,
    timeout_seconds: u64,
) -> Result<(), Error> {
    let mut manifest = if let Some(path) = input_manifest {
        ResourceManifest::from_json_file(path)?
    } else {
        positional_manifest(&urls)
    };
    manifest.validate()?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("manifest");
    let head_dir = parent.join(format!("{stem}.probe-head"));
    // Probe every resource independently. A failed parent must not prevent a
    // separately fetchable descendant from being measured and retained.
    let mut head_manifest = manifest.clone();
    for resource in &mut head_manifest.resources {
        resource.depends_on.clear();
    }
    let head = execute_run(RunSpec {
        method: "HEAD",
        workload_hash: manifest_hash(&head_manifest)?,
        workload: head_manifest,
        application_workload_source: None,
        config: QcsdConfig::default(),
        defense_parameters: None,
        chaff_manifest: None,
        chaff_manifest_hash: None,
        request_policy: RequestPolicyArg::AsDefined,
        seed: 0,
        output_dir: head_dir,
        max_response_bytes: 0,
        timeout_seconds,
    })
    .await?;

    let missing: Vec<_> = head
        .iter()
        .filter(|response| {
            !response
                .status
                .is_some_and(|status| (200..300).contains(&status))
                || response.content_length.is_none()
        })
        .map(|response| response.resource_id)
        .collect();
    let fallback = if missing.is_empty() {
        Vec::new()
    } else {
        let mut fallback_manifest = manifest.clone();
        fallback_manifest
            .resources
            .retain(|resource| missing.contains(&resource.id));
        for resource in &mut fallback_manifest.resources {
            resource.depends_on.clear();
        }
        execute_run(RunSpec {
            method: "GET",
            workload_hash: manifest_hash(&fallback_manifest)?,
            workload: fallback_manifest,
            application_workload_source: None,
            config: QcsdConfig::default(),
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 0,
            output_dir: parent.join(format!("{stem}.probe-get")),
            max_response_bytes: max_bytes,
            timeout_seconds,
        })
        .await?
    };
    let fallback: HashMap<_, _> = fallback
        .into_iter()
        .map(|response| (response.resource_id, response))
        .collect();
    let head: HashMap<_, _> = head
        .into_iter()
        .map(|response| (response.resource_id, response))
        .collect();
    for resource in &mut manifest.resources {
        let Some(response) = head.get(&resource.id) else {
            continue;
        };
        let response = fallback.get(&resource.id).unwrap_or(response);
        resource.content_length = response
            .content_length
            .or_else(|| (response.bytes > 0).then_some(response.bytes));
        resource.data_length = response.bytes;
        resource.known_valid = response
            .status
            .is_some_and(|status| (200..300).contains(&status))
            && response.complete;
    }
    manifest.validate()?;
    atomic_write(output, manifest.to_json_pretty()?.as_bytes())?;
    Ok(())
}

fn projected_ael(resource: &Resource) -> Result<Vec<(String, String)>, Error> {
    if !resource.known_valid {
        return Err(Error::Argument(
            "chaff response qualification requires a known-valid resource".into(),
        ));
    }
    let projected: Vec<_> = resource
        .headers
        .iter()
        .filter(|(name, _)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "accept" | "accept-encoding" | "accept-language"
            )
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    let names: Vec<_> = projected.iter().map(|(name, _)| name.as_str()).collect();
    if names != ["accept", "accept-encoding", "accept-language"]
        || resource.headers.iter().any(|(name, _)| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "accept" | "accept-encoding" | "accept-language"
            ) && name != &name.to_ascii_lowercase()
        })
    {
        return Err(Error::Argument(
            "application resource must project exactly one accept, accept-encoding, and accept-language header in that order"
                .into(),
        ));
    }
    Ok(projected)
}

fn projected_identity_chaff_headers(resource: &Resource) -> Result<Vec<(String, String)>, Error> {
    if !resource.known_valid {
        return Err(Error::Argument(
            "identity chaff response qualification requires a known-valid resource".into(),
        ));
    }
    let mut accept = None;
    let mut accept_encoding = None;
    let mut accept_language = None;
    for (name, value) in &resource.headers {
        let normalized = name.to_ascii_lowercase();
        let slot = match normalized.as_str() {
            "accept" => Some(&mut accept),
            "accept-encoding" => Some(&mut accept_encoding),
            "accept-language" => Some(&mut accept_language),
            _ => None,
        };
        if let Some(slot) = slot {
            if name != &normalized || slot.is_some() {
                return Err(Error::Argument(
                    "identity chaff application headers must contain each exact lowercase accept, accept-encoding, and accept-language field once"
                        .into(),
                ));
            }
            *slot = Some(value.clone());
        }
    }
    let (Some(accept), Some(_application_accept_encoding), Some(accept_language)) =
        (accept, accept_encoding, accept_language)
    else {
        return Err(Error::Argument(
            "identity chaff application headers must contain each exact lowercase accept, accept-encoding, and accept-language field once"
                .into(),
        ));
    };
    Ok(vec![
        ("accept".into(), accept),
        ("accept-encoding".into(), "identity".into()),
        ("accept-language".into(), accept_language),
    ])
}

fn validate_qualification_application_root(
    resource: &Resource,
    application_resource_id: u32,
) -> Result<(), Error> {
    if application_resource_id != 0
        || resource.id != application_resource_id
        || resource.kind != "Document"
        || !resource.known_valid
        || !resource.depends_on.is_empty()
        || resource.origin().is_none()
    {
        return Err(Error::Argument(
            "qualification requires the unique known-valid dependency-free Document navigation root with resource ID 0"
                .into(),
        ));
    }
    Ok(())
}

fn deterministic_selected_chaff_resource<'a>(
    workload: &'a ResourceManifest,
    expected: &'a BTreeMap<u32, PreparedExpectedResponse>,
    application: &Resource,
) -> Result<(&'a Resource, &'a PreparedExpectedResponse), Error> {
    let application_origin = application.origin().ok_or_else(|| {
        Error::Argument("application navigation root has no valid HTTPS origin".into())
    })?;
    let mut candidates: Vec<_> = workload
        .resources
        .iter()
        .filter_map(|resource| {
            let response = expected.get(&resource.id)?;
            (resource.known_valid
                && resource.origin().as_deref() == Some(application_origin.as_str())
                && response.bytes >= 1_200
                && projected_ael(resource).is_ok())
            .then_some((resource, response))
        })
        .collect();
    candidates.sort_by(
        |(left_resource, left_response), (right_resource, right_response)| {
            right_response
                .bytes
                .cmp(&left_response.bytes)
                .then_with(|| left_resource.id.cmp(&right_resource.id))
                .then_with(|| left_resource.url.cmp(&right_resource.url))
        },
    );
    candidates.into_iter().next().ok_or_else(|| {
        Error::Argument(
            "prepared workload has no deterministic known-valid same-origin one-cell chaff resource"
                .into(),
        )
    })
}

fn selected_identity_chaff_resource<'a>(
    workload: &'a ResourceManifest,
    expected: &'a BTreeMap<u32, PreparedExpectedResponse>,
    application: &Resource,
    selected_chaff_resource_id: u32,
) -> Result<(&'a Resource, &'a PreparedExpectedResponse), Error> {
    let resource = workload
        .resources
        .iter()
        .find(|resource| resource.id == selected_chaff_resource_id)
        .ok_or_else(|| {
            Error::Argument("selected_chaff_resource_id is absent from workload".into())
        })?;
    let response = expected.get(&selected_chaff_resource_id).ok_or_else(|| {
        Error::Argument(
            "selected identity-chaff resource lacks a frozen prepared response identity".into(),
        )
    })?;
    if !resource.known_valid
        || resource.origin().is_none()
        || resource.origin() != application.origin()
        || response.bytes < 1_200
    {
        return Err(Error::Argument(
            "selected identity-chaff resource must be known-valid, same-origin, and have a prepared body of at least 1200 bytes"
                .into(),
        ));
    }
    projected_identity_chaff_headers(resource)?;
    Ok((resource, response))
}

#[derive(Debug)]
struct QualifierStream {
    request_index: usize,
    stream_id: StreamId,
    request_stream_bytes: u64,
    status: Option<u16>,
    content_encoding: Option<String>,
    body: Vec<u8>,
    body_bytes: u64,
    complete: bool,
    outcome: &'static str,
}

fn drain_qualifier_stream_data(
    streams: &mut HashMap<StreamId, QualifierStream>,
    completed: &mut Vec<QualifierStream>,
    stream_id: StreamId,
    max_response_bytes: u64,
    mut read_data: impl FnMut(&mut [u8]) -> Result<(usize, bool), Error>,
) -> Result<(), Error> {
    // Processing a batch of received datagrams can queue more than one
    // `DataReadable` for a stream.  The first event may consume its FIN and
    // retire the HTTP/3 receive stream, making every remaining event stale.
    if !streams.contains_key(&stream_id) {
        return if completed.iter().any(|record| record.stream_id == stream_id) {
            Ok(())
        } else {
            Err(Error::RunAborted(
                "data arrived for an unknown qualifier stream".into(),
            ))
        };
    }

    let mut buffer = vec![0_u8; 32 * 1024];
    loop {
        let (read, fin) = read_data(&mut buffer)?;
        let record = streams
            .get_mut(&stream_id)
            .expect("active qualifier stream remains present until FIN");
        record.body_bytes = record
            .body_bytes
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        record.complete |= fin;
        if record.body_bytes > max_response_bytes {
            record.outcome = "response_limit";
            return Err(Error::RunAborted(format!(
                "qualification response exceeds {max_response_bytes} bytes"
            )));
        }
        record.body.extend_from_slice(&buffer[..read]);
        if fin {
            let mut record = streams.remove(&stream_id).expect("present");
            record.outcome = "complete";
            completed.push(record);
            break;
        }
        if read == 0 {
            break;
        }
    }
    Ok(())
}

fn open_qualifier_wave(
    client: &mut Http3Client,
    now: Instant,
    url: &Uri,
    headers: &[Header],
    streams: &mut HashMap<StreamId, QualifierStream>,
    next_request_index: &mut usize,
    wave_size: usize,
) -> Result<(), Error> {
    for _ in 0..wave_size {
        let request_index = *next_request_index;
        let stream_id = client.qcsd_fetch_nonblocking(now, url, headers)?;
        let request_stream_bytes = client.qcsd_request_stream_bytes(stream_id)?;
        if request_stream_bytes == 0 {
            return Err(Error::RunAborted(
                "production nonblocking encoder produced an empty request".into(),
            ));
        }
        client.stream_close_send(stream_id, now)?;
        streams.insert(
            stream_id,
            QualifierStream {
                request_index,
                stream_id,
                request_stream_bytes,
                status: None,
                content_encoding: None,
                body: Vec::new(),
                body_bytes: 0,
                complete: false,
                outcome: "in_flight",
            },
        );
        *next_request_index = next_request_index.saturating_add(1);
    }
    Ok(())
}

fn sustained_requests_are_classifiable(requests: &[ResponseQualificationRequest]) -> bool {
    requests.len() == SUSTAINED_QUALIFICATION_REQUESTS
        && requests.iter().enumerate().all(|(index, request)| {
            request.request_index == index
                && request.complete
                && request.outcome == "complete"
                && request
                    .status
                    .is_some_and(|status| (100..=599).contains(&status))
                && request.content_encoding.is_some()
                && request.body_sha256.is_some()
        })
        && requests
            .iter()
            .map(|request| request.stream_id)
            .collect::<BTreeSet<_>>()
            .len()
            == SUSTAINED_QUALIFICATION_REQUESTS
}

fn sustained_representation_failure(
    requests: &[ResponseQualificationRequest],
) -> Option<&'static str> {
    if requests.iter().any(|request| request.body_bytes < 1_200) {
        return Some("capacity");
    }
    let identities: Vec<_> = requests
        .iter()
        .map(|request| {
            (
                request.status,
                request.content_encoding.as_deref(),
                request.body_bytes,
                request.body_sha256.as_deref(),
            )
        })
        .collect();
    (identities
        .windows(2)
        .any(|pair| pair.first() != pair.last())
        || requests.iter().any(|request| {
            !request
                .status
                .is_some_and(|status| (200..300).contains(&status))
                || request.content_encoding.as_deref() != Some("identity")
        }))
    .then_some("identity")
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the dedicated qualification loop retains packet and response evidence in one lifecycle"
)]
async fn qualify_chaff_response(
    workload_path: &Path,
    application_resource_id: u32,
    selected_chaff_resource_id: u32,
    output_dir: &Path,
    parallel_requests: usize,
    total_requests: Option<usize>,
    request_header_mode: Option<ChaffRequestHeaderModeArg>,
    max_response_bytes: u64,
    packet_size: u16,
    timeout_seconds: u64,
) -> Result<(), Error> {
    let mode = response_qualification_mode(parallel_requests, total_requests, request_header_mode)?;
    if packet_size != 1_200 || max_response_bytes == 0 {
        return Err(Error::Argument(
            "response qualification requires packet_size=1200 and positive max_response_bytes"
                .into(),
        ));
    }
    let (workload, workload_hash, expected_responses) =
        load_application_workload_source(workload_path)?;
    let application = workload
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .ok_or_else(|| {
            Error::Argument("application_resource_id 0 is absent from workload".into())
        })?;
    validate_qualification_application_root(application, application_resource_id)?;
    let (resource, prepared_selected) = match mode {
        ResponseQualificationMode::Legacy => {
            let (deterministic, prepared) =
                deterministic_selected_chaff_resource(&workload, &expected_responses, application)?;
            if deterministic.id != selected_chaff_resource_id {
                return Err(Error::Argument(format!(
                    "selected_chaff_resource_id {selected_chaff_resource_id} is not deterministic source {}",
                    deterministic.id
                )));
            }
            (deterministic, prepared)
        }
        ResponseQualificationMode::SustainedIdentity => selected_identity_chaff_resource(
            &workload,
            &expected_responses,
            application,
            selected_chaff_resource_id,
        )?,
    };
    let request_headers = match mode {
        ResponseQualificationMode::Legacy => projected_ael(resource)?,
        ResponseQualificationMode::SustainedIdentity => projected_identity_chaff_headers(resource)?,
    };
    let url: Uri = resource
        .url
        .parse()
        .map_err(|_| Error::Argument("application root URL is invalid".into()))?;
    if output_dir.exists() && fs::read_dir(output_dir)?.next().is_some() {
        return Err(Error::Argument(format!(
            "output directory must be empty: {}",
            output_dir.display()
        )));
    }
    fs::create_dir_all(output_dir)?;
    let started_unix_ns = unix_nanos();
    let started = now();
    let authority = url
        .authority()
        .ok_or_else(|| Error::Argument("URL has no authority".into()))?;
    let host = authority.host().to_owned();
    let port = authority.port_u16().unwrap_or(443);
    let remote_addr = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Argument(format!("could not resolve {host}:{port}")))?;
    let wildcard = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let route_probe = std::net::UdpSocket::bind(wildcard)?;
    route_probe.connect(remote_addr)?;
    let socket =
        Socket::bind_for_direct_capture(SocketAddr::new(route_probe.local_addr()?.ip(), 0))?;
    let local_addr = socket.local_addr()?;
    let transport = Connection::new_client(
        &host,
        &["h3"],
        Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8))),
        local_addr,
        remote_addr,
        ConnectionParameters::default().max_udp_payload_size(u64::from(packet_size)),
        started,
    )?;
    let mut client = Http3Client::new_with_conn(
        transport,
        Http3Parameters::default().max_concurrent_push_streams(0),
    );
    let origin: Uri = format!("https://{authority}")
        .parse()
        .map_err(|_| Error::Argument("invalid origin".into()))?;
    client.enable_qcsd(
        QcsdEndpointId(0),
        &origin,
        packet_size,
        false,
        Duration::from_secs(1),
    )?;
    let headers: Vec<_> = request_headers
        .iter()
        .map(|(name, value)| Header::new(name.as_str(), value.as_str()))
        .collect();
    let mut streams = HashMap::<StreamId, QualifierStream>::new();
    let mut completed = Vec::<QualifierStream>::new();
    let mut recv_buf = RecvBuf::default();
    let mut incoming = PacketDirectionStats {
        packet_count: 0,
        observed_udp_payload_max: 0,
        oversized_packet_count: 0,
    };
    let mut outgoing = PacketDirectionStats {
        packet_count: 0,
        observed_udp_payload_max: 0,
        oversized_packet_count: 0,
    };
    let mut packet_observations = Vec::<QualificationPacketObservation>::new();
    let mut next_packet_sequence = 0_u64;
    let deadline = started + Duration::from_secs(timeout_seconds);
    let request_target = match mode {
        ResponseQualificationMode::Legacy => parallel_requests,
        ResponseQualificationMode::SustainedIdentity => SUSTAINED_QUALIFICATION_REQUESTS,
    };
    let mut opened = false;
    let mut next_request_index = 0_usize;
    let mut request_waves = 0_usize;
    let mut max_concurrent_requests = 0_usize;
    let mut requests_opened_before_first_network_output = 0_usize;
    let mut qualification_network_output_seen = false;
    let loop_result: Result<(), Error> = async {
        loop {
            let loop_now = now();
            if loop_now >= deadline {
                return Err(Error::Timeout(timeout_seconds));
            }
            while let Some(datagrams) = socket.recv(local_addr, &mut recv_buf)? {
                for datagram in datagrams {
                    incoming.observe(datagram.len(), packet_size);
                    packet_observations.push(QualificationPacketObservation {
                        sequence: next_packet_sequence,
                        phase: if opened { "qualification" } else { "handshake" },
                        direction: "incoming",
                        udp_payload_bytes: datagram.len(),
                    });
                    next_packet_sequence = next_packet_sequence.saturating_add(1);
                    client.process_input(datagram, loop_now);
                }
            }
            while let Some(event) = client.next_event() {
                match event {
                    Http3ClientEvent::AuthenticationNeeded => {
                        client.authenticated(AuthenticationStatus::Ok, loop_now);
                    }
                    Http3ClientEvent::StateChange(Http3State::Connected) if !opened => {
                        opened = true;
                        open_qualifier_wave(
                            &mut client,
                            loop_now,
                            &url,
                            &headers,
                            &mut streams,
                            &mut next_request_index,
                            parallel_requests,
                        )?;
                        request_waves = request_waves.saturating_add(1);
                        max_concurrent_requests = max_concurrent_requests.max(streams.len());
                        requests_opened_before_first_network_output = streams.len();
                    }
                    Http3ClientEvent::HeaderReady {
                        stream_id,
                        headers,
                        fin,
                        ..
                    } => {
                        if let Some(record) = streams.get_mut(&stream_id) {
                            record.status = header_u64(&headers, ":status")
                                .and_then(|value| value.try_into().ok());
                            record.content_encoding = match mode {
                                ResponseQualificationMode::Legacy => {
                                    qualification_content_encoding(&headers)
                                }
                                ResponseQualificationMode::SustainedIdentity => {
                                    Some(sustained_qualification_content_encoding(&headers)?)
                                }
                            };
                            if fin {
                                record.complete = true;
                            }
                        }
                        if fin && let Some(mut record) = streams.remove(&stream_id) {
                            record.outcome = "complete";
                            completed.push(record);
                        }
                    }
                    Http3ClientEvent::DataReadable { stream_id } => {
                        drain_qualifier_stream_data(
                            &mut streams,
                            &mut completed,
                            stream_id,
                            max_response_bytes,
                            |buffer| Ok(client.read_data(loop_now, stream_id, buffer)?),
                        )?;
                    }
                    Http3ClientEvent::Reset { stream_id, .. } => {
                        if let Some(mut record) = streams.remove(&stream_id) {
                            record.outcome = "reset";
                            completed.push(record);
                        }
                    }
                    Http3ClientEvent::StateChange(Http3State::Closed(_)) => {
                        return Err(Error::RunAborted(
                            "HTTP/3 endpoint closed during chaff response qualification".into(),
                        ));
                    }
                    _ => {}
                }
            }
            if completed.len() == request_target {
                return Ok(());
            }
            if opened && streams.is_empty() && next_request_index < request_target {
                let remaining = request_target.saturating_sub(next_request_index);
                let wave_size = remaining.min(parallel_requests);
                open_qualifier_wave(
                    &mut client,
                    loop_now,
                    &url,
                    &headers,
                    &mut streams,
                    &mut next_request_index,
                    wave_size,
                )?;
                request_waves = request_waves.saturating_add(1);
                max_concurrent_requests = max_concurrent_requests.max(streams.len());
            }
            let output = client.process_multiple_output(loop_now, NonZeroUsize::MIN);
            let delay = match output {
                OutputBatch::DatagramBatch(batch) => {
                    for datagram in batch.iter() {
                        outgoing.observe(datagram.len(), packet_size);
                        packet_observations.push(QualificationPacketObservation {
                            sequence: next_packet_sequence,
                            phase: if opened { "qualification" } else { "handshake" },
                            direction: "outgoing",
                            udp_payload_bytes: datagram.len(),
                        });
                        next_packet_sequence = next_packet_sequence.saturating_add(1);
                    }
                    qualification_network_output_seen |= opened;
                    loop {
                        match socket.send(&batch) {
                            Ok(()) => break,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                socket.writable().await?;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Duration::from_millis(1)
                }
                OutputBatch::Callback(delay) => delay,
                OutputBatch::None => Duration::from_millis(10),
            };
            wait_for_activity(
                [&socket],
                bounded_qualification_wait(delay, deadline, timeout_seconds)?,
            )
            .await?;
        }
    }
    .await;

    let mut remaining: Vec<_> = streams.drain().map(|(_, record)| record).collect();
    remaining.sort_by_key(|record| record.request_index);
    for mut record in remaining {
        if record.outcome == "in_flight" {
            record.outcome = "incomplete";
        }
        completed.push(record);
    }
    completed.sort_by_key(|record| record.request_index);
    let requests = completed
        .iter()
        .map(|record| {
            Ok(ResponseQualificationRequest {
                request_index: record.request_index,
                stream_id: record.stream_id.as_u64(),
                request_stream_bytes: record.request_stream_bytes,
                status: record.status,
                content_encoding: record.content_encoding.clone(),
                body_bytes: record.body_bytes,
                body_sha256: (record.complete
                    && u64::try_from(record.body.len()).ok() == Some(record.body_bytes))
                .then(|| sha256(&record.body))
                .transpose()?,
                complete: record.complete,
                outcome: record.outcome,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let identities: Vec<_> = requests
        .iter()
        .map(|request| {
            (
                request.status,
                request.content_encoding.as_deref(),
                request.body_bytes,
                request.body_sha256.as_deref(),
            )
        })
        .collect();
    let legacy_passed = loop_result.is_ok()
        && requests.len() == parallel_requests
        && requests.iter().all(|request| {
            request.complete
                && request
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
                && request.content_encoding.is_some()
                && request.body_sha256.is_some()
                && request.status == Some(prepared_selected.status)
                && request.body_bytes == prepared_selected.bytes
                && request.body_sha256.as_deref() == Some(prepared_selected.body_sha256.as_str())
        })
        && identities
            .windows(2)
            .all(|pair| pair.first() == pair.last())
        && requests.windows(2).all(|pair| {
            pair.first().zip(pair.last()).is_some_and(|(first, last)| {
                first.request_stream_bytes == last.request_stream_bytes
            })
        })
        && incoming.oversized_packet_count == 0
        && outgoing.oversized_packet_count == 0
        && requests_opened_before_first_network_output == parallel_requests
        && qualification_network_output_seen;
    let request_stream_bytes = requests
        .first()
        .map(|request| request.request_stream_bytes)
        .filter(|size| {
            requests
                .iter()
                .all(|request| request.request_stream_bytes == *size)
        });
    let sustained_classifiable = loop_result.is_ok()
        && sustained_requests_are_classifiable(&requests)
        && request_stream_bytes.is_some()
        && next_request_index == SUSTAINED_QUALIFICATION_REQUESTS
        && request_waves == SUSTAINED_QUALIFICATION_WAVES
        && max_concurrent_requests == SUSTAINED_QUALIFICATION_PARALLEL_REQUESTS
        && requests_opened_before_first_network_output == SUSTAINED_QUALIFICATION_PARALLEL_REQUESTS
        && incoming.oversized_packet_count == 0
        && outgoing.oversized_packet_count == 0
        && qualification_network_output_seen;
    let sustained_failure_class = sustained_classifiable
        .then(|| sustained_representation_failure(&requests))
        .flatten();
    let sustained_passed = sustained_classifiable && sustained_failure_class.is_none();
    let loop_error = loop_result.as_ref().err().map(ToString::to_string);
    let sustained_error =
        if sustained_passed {
            None
        } else if let Some(failure_class) = sustained_failure_class {
            Some(format!(
                "sustained chaff response qualification classified a {failure_class} failure"
            ))
        } else {
            Some(loop_error.clone().unwrap_or_else(|| {
                "sustained chaff response qualification invariants failed".into()
            }))
        };
    let sustained_requests: Vec<_> = requests
        .iter()
        .map(|request| SustainedResponseQualificationRequest {
            request_index: request.request_index,
            wave_index: request.request_index / SUSTAINED_QUALIFICATION_PARALLEL_REQUESTS,
            stream_id: request.stream_id,
            request_stream_bytes: request.request_stream_bytes,
            status: request.status,
            content_encoding: request.content_encoding.clone(),
            body_bytes: request.body_bytes,
            body_sha256: request.body_sha256.clone(),
            complete: request.complete,
            outcome: request.outcome,
        })
        .collect();
    let packet_log = serde_json::to_vec(&packet_observations)?;
    atomic_write(&output_dir.join("packets.json"), &packet_log)?;
    let packet_log_sha256 = sha256(&packet_log)?;
    let ended_unix_ns = unix_nanos();
    let receipt = match mode {
        ResponseQualificationMode::Legacy => json!({
            "schema_version": 2,
            "artifact_type": "qcsd-chaff-response-qualification",
            "invocation_id": format!("{}-{local_addr}", started_unix_ns),
            "neqo_version": env!("CARGO_PKG_VERSION"),
            "application_workload_sha256": workload_hash,
            "application_resource_id": application_resource_id,
            "selected_chaff_resource_id": selected_chaff_resource_id,
            "qualified_parallel_chaff_streams": parallel_requests,
            "method": "GET",
            "url": url.to_string(),
            "request_headers": &request_headers,
            "parallel_requests": parallel_requests,
            "connection_count": 1,
            "requests_opened_before_first_network_output": requests_opened_before_first_network_output,
            "request_stream_bytes": request_stream_bytes,
            "max_response_bytes": max_response_bytes,
            "udp_payload_ceiling": packet_size,
            "started_unix_ns": started_unix_ns,
            "ended_unix_ns": ended_unix_ns,
            "completion_status": if legacy_passed { "complete" } else { "error" },
            "error": loop_error,
            "source": {
                "neqo_base_commit": NEQO_BASE_COMMIT,
                "published_qcsd_commit": PUBLISHED_QCSD_COMMIT,
                "migration_commit": option_env!("NEQO_QCSD_GIT_COMMIT").unwrap_or("working-tree"),
            },
            "requests": &requests,
            "packet_observations": &packet_observations,
            "packet_log_sha256": packet_log_sha256,
            "packets": {
                "incoming": &incoming,
                "outgoing": &outgoing,
                "total": {
                    "packet_count": incoming.packet_count.saturating_add(outgoing.packet_count),
                    "observed_udp_payload_max": incoming.observed_udp_payload_max.max(outgoing.observed_udp_payload_max),
                    "oversized_packet_count": incoming.oversized_packet_count.saturating_add(outgoing.oversized_packet_count),
                },
            },
            "passed": legacy_passed,
        }),
        ResponseQualificationMode::SustainedIdentity => json!({
            "schema_version": 3,
            "artifact_type": "qcsd-chaff-response-qualification",
            "invocation_id": format!("{}-{local_addr}", started_unix_ns),
            "neqo_version": env!("CARGO_PKG_VERSION"),
            "application_workload_sha256": workload_hash,
            "application_resource_id": application_resource_id,
            "selected_chaff_resource_id": selected_chaff_resource_id,
            "qualified_parallel_chaff_streams": parallel_requests,
            "method": "GET",
            "url": url.to_string(),
            "request_headers": &request_headers,
            "request_header_mode": "identity-chaff-v1",
            "parallel_requests": parallel_requests,
            "total_requests": SUSTAINED_QUALIFICATION_REQUESTS,
            "request_waves": request_waves,
            "max_concurrent_requests": max_concurrent_requests,
            "connection_count": 1,
            "requests_opened_before_first_network_output": requests_opened_before_first_network_output,
            "request_stream_bytes": request_stream_bytes,
            "max_response_bytes": max_response_bytes,
            "udp_payload_ceiling": packet_size,
            "started_unix_ns": started_unix_ns,
            "ended_unix_ns": ended_unix_ns,
            "completion_status": if sustained_classifiable { "complete" } else { "error" },
            "error": sustained_error,
            "failure_class": sustained_failure_class,
            "source": {
                "neqo_base_commit": NEQO_BASE_COMMIT,
                "published_qcsd_commit": PUBLISHED_QCSD_COMMIT,
                "migration_commit": option_env!("NEQO_QCSD_GIT_COMMIT").unwrap_or("working-tree"),
            },
            "requests": &sustained_requests,
            "packet_observations": &packet_observations,
            "packet_log_sha256": packet_log_sha256,
            "packets": {
                "incoming": &incoming,
                "outgoing": &outgoing,
                "total": {
                    "packet_count": incoming.packet_count.saturating_add(outgoing.packet_count),
                    "observed_udp_payload_max": incoming.observed_udp_payload_max.max(outgoing.observed_udp_payload_max),
                    "oversized_packet_count": incoming.oversized_packet_count.saturating_add(outgoing.oversized_packet_count),
                },
            },
            "passed": sustained_passed,
        }),
    };
    atomic_write(
        &output_dir.join("qualification.json"),
        serde_json::to_string_pretty(&receipt)?.as_bytes(),
    )?;
    let passed = match mode {
        ResponseQualificationMode::Legacy => legacy_passed,
        ResponseQualificationMode::SustainedIdentity => sustained_passed,
    };
    if passed {
        Ok(())
    } else {
        Err(loop_result.err().unwrap_or_else(|| {
            let message = sustained_failure_class.map_or_else(
                || "chaff response qualification invariants failed".into(),
                |failure_class| {
                    format!(
                    "sustained chaff response qualification classified a {failure_class} failure"
                )
                },
            );
            Error::RunAborted(message)
        }))
    }
}

fn merged_ranges(ranges: impl IntoIterator<Item = (u64, u64)>) -> Vec<[u64; 2]> {
    let mut ranges: Vec<_> = ranges
        .into_iter()
        .filter_map(|(start, bytes)| (bytes > 0).then_some([start, start.saturating_add(bytes)]))
        .collect();
    ranges.sort_unstable();
    let mut merged = Vec::<[u64; 2]>::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range[0] <= last[1]
        {
            last[1] = last[1].max(range[1]);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn range_bytes(ranges: &[[u64; 2]]) -> u64 {
    ranges.iter().fold(0_u64, |total, range| {
        total.saturating_add(range[1].saturating_sub(range[0]))
    })
}

fn prefix_stream_receipts<'a>(
    requests: &'a [PrefixRequestStream],
    transmissions: &[QcsdStreamTransmission],
) -> Vec<PrefixStreamReceipt<'a>> {
    requests
        .iter()
        .map(|request| {
            let tx: Vec<_> = transmissions
                .iter()
                .filter(|transmission| transmission.stream.0 == request.stream_id)
                .collect();
            let transmitted_unique_ranges = merged_ranges(
                tx.iter()
                    .map(|transmission| (transmission.offset, transmission.bytes)),
            );
            let acknowledged_unique_ranges = merged_ranges(
                request
                    .acknowledgements
                    .iter()
                    .map(|ack| (ack.offset, ack.bytes)),
            );
            PrefixStreamReceipt {
                request_order: request.request_order,
                opening_stage_index: request.opening_stage_index,
                role: request.role,
                resource_id: request.resource_id,
                request_id: request.request_id,
                stream_id: request.stream_id,
                request_stream_bytes: request.request_stream_bytes,
                qualified_request_stream_bytes: request.qualified_request_stream_bytes,
                transmitted_unique_bytes: range_bytes(&transmitted_unique_ranges),
                fin_transmitted: tx.iter().any(|transmission| transmission.fin),
                transmitted_unique_ranges,
                acknowledgements: &request.acknowledgements,
                acknowledged_unique_bytes: range_bytes(&acknowledged_unique_ranges),
                fin_acknowledged: request.acknowledgements.iter().any(|ack| ack.fin),
                acknowledged_unique_ranges,
            }
        })
        .collect()
}

fn prefix_receipts_pass(
    receipts: &[PrefixStreamReceipt<'_>],
    required_active_chaff_streams: usize,
) -> bool {
    if receipts.is_empty()
        || receipts
            .iter()
            .enumerate()
            .any(|(index, receipt)| receipt.request_order != index)
        || receipts
            .iter()
            .map(|receipt| receipt.stream_id)
            .collect::<BTreeSet<_>>()
            .len()
            != receipts.len()
    {
        return false;
    }
    let app_tx_complete = receipts
        .iter()
        .filter(|receipt| receipt.role == "application")
        .all(|receipt| {
            receipt.transmitted_unique_ranges == [[0, receipt.request_stream_bytes]]
                && receipt.transmitted_unique_bytes == receipt.request_stream_bytes
                && receipt.fin_transmitted
        });
    let chaff_complete = receipts
        .iter()
        .filter(|receipt| receipt.role == "chaff")
        .take(required_active_chaff_streams)
        .all(|receipt| {
            receipt.qualified_request_stream_bytes == Some(receipt.request_stream_bytes)
                && receipt.transmitted_unique_ranges == [[0, receipt.request_stream_bytes]]
                && receipt.transmitted_unique_bytes == receipt.request_stream_bytes
                && receipt.fin_transmitted
                && receipt.acknowledged_unique_ranges == [[0, receipt.request_stream_bytes]]
                && receipt.acknowledged_unique_bytes == receipt.request_stream_bytes
                && receipt.fin_acknowledged
        });
    app_tx_complete
        && chaff_complete
        && receipts
            .iter()
            .filter(|receipt| receipt.role == "chaff")
            .count()
            >= required_active_chaff_streams
}

fn intentionally_pending_late_chaff(
    requests: &[PrefixRequestStream],
    required_active_chaff_streams: usize,
) -> Vec<StreamId> {
    requests
        .iter()
        .filter(|request| request.role == "chaff")
        .skip(required_active_chaff_streams)
        .map(|request| StreamId::new(request.stream_id))
        .collect()
}

fn prefix_targetless_stream_bytes(
    transmissions: &[QcsdStreamTransmission],
    scheduled_slots: &BTreeSet<u64>,
) -> u64 {
    transmissions
        .iter()
        .filter(|transmission| {
            transmission
                .slot
                .is_none_or(|slot| !scheduled_slots.contains(&slot.0))
        })
        .fold(0_u64, |total, transmission| {
            total.saturating_add(transmission.bytes)
        })
}

fn record_prefix_observations(
    client: &mut Http3Client,
    requests: &mut [PrefixRequestStream],
    transmissions: &mut Vec<QcsdStreamTransmission>,
    scheduled_slots: &BTreeSet<u64>,
    satisfied_slots: &mut BTreeSet<u64>,
) -> Result<(), Error> {
    transmissions.extend(client.qcsd_stream_transmissions());
    for record in client.qcsd_timestamped_observations() {
        let sequence = record.sequence();
        match record.into_observation() {
            QcsdObservation::StreamDataAcknowledged {
                stream,
                offset,
                bytes,
                fin,
                ..
            } => {
                let request = requests
                    .iter_mut()
                    .find(|request| request.stream_id == stream.0)
                    .ok_or_else(|| {
                        Error::RunAborted(
                            "ACK observation referenced an unknown prefix request stream".into(),
                        )
                    })?;
                request.acknowledgements.push(QualificationAcknowledgement {
                    sequence,
                    offset,
                    bytes,
                    fin,
                });
            }
            QcsdObservation::SlotSatisfied {
                slot,
                observed_size,
                ..
            } if scheduled_slots.contains(&slot.0) && observed_size == 1_200 => {
                satisfied_slots.insert(slot.0);
            }
            QcsdObservation::SlotSatisfied { slot, .. } => {
                return Err(Error::RunAborted(format!(
                    "unexpected or wrong-sized prefix-pack slot satisfaction: {}",
                    slot.0
                )));
            }
            QcsdObservation::SlotMissed { slot, reason, .. }
                if scheduled_slots.contains(&slot.0) =>
            {
                return Err(Error::RunAborted(format!(
                    "prefix-pack target {} was missed: {reason:?}",
                    slot.0
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct PrefixActivationStageReceipt {
    stage_index: usize,
    component_index: usize,
    application_resource_ids: Vec<u32>,
    application_request_orders: Vec<usize>,
    application_stream_ids: Vec<u64>,
    target_slot_ids: Vec<u64>,
    exact_target_cells: u64,
    scheduled_target_bytes: u64,
    required_active_chaff_streams: usize,
    newly_required_chaff_streams: usize,
    peer_acknowledged_active_chaff_streams: usize,
    newly_peer_acknowledged_request_orders: Vec<usize>,
    newly_peer_acknowledged_stream_ids: Vec<u64>,
    allowed_pending_chaff_request_orders: Vec<usize>,
    allowed_pending_chaff_stream_ids: Vec<u64>,
    targetless_stream_bytes_at_gate: u64,
    pending_required_prefix_stream_send: bool,
    passed: bool,
}

fn queue_prefix_stage_targets(
    client: &mut Http3Client,
    now: Instant,
    stage: &StreamActivationStage,
    packet_size: u16,
    timeout_seconds: u64,
    next_slot_id: &mut u64,
    scheduled_slots: &mut BTreeSet<u64>,
) -> Result<Vec<u64>, Error> {
    let mut slots = Vec::new();
    for _ in 0..stage.exact_target_cells {
        let slot_id = *next_slot_id;
        *next_slot_id = next_slot_id.saturating_add(1);
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, packet_size)?;
        client.apply_qcsd_action(
            now,
            QcsdAction::SendPacket {
                endpoint: QcsdEndpointId(0),
                packet,
                slot: QcsdSlotId(slot_id),
                not_before_after_us: 0,
                deadline_after_us: u64::try_from(Duration::from_secs(timeout_seconds).as_micros())
                    .unwrap_or(u64::MAX),
                allow_stream_data: true,
                send_policy: QcsdSendPolicy::Exact,
            },
        )?;
        scheduled_slots.insert(slot_id);
        slots.push(slot_id);
    }
    Ok(slots)
}

fn open_prefix_application_stage(
    client: &mut Http3Client,
    now: Instant,
    workload: &ResourceManifest,
    stage_index: usize,
    resource_ids: &[u32],
    requests: &mut Vec<PrefixRequestStream>,
) -> Result<(), Error> {
    for resource_id in resource_ids {
        let resource = workload
            .resources
            .iter()
            .find(|resource| resource.id == *resource_id)
            .ok_or_else(|| {
                Error::Argument(format!(
                    "activation-stage application resource {resource_id} is absent"
                ))
            })?;
        let url: Uri = resource.url.parse().map_err(|_| {
            Error::Argument(format!(
                "activation-stage application resource {resource_id} has an invalid URL"
            ))
        })?;
        let headers = workload.application_headers(*resource_id)?;
        let headers: Vec<_> = headers
            .iter()
            .map(|(name, value)| Header::new(name.as_str(), value.as_str()))
            .collect();
        let stream = client.fetch(now, "GET", &url, &headers, Priority::default())?;
        client.register_qcsd_stream(stream, QcsdRequestRole::Application, None)?;
        let size = client.qcsd_request_stream_bytes(stream)?;
        client.stream_close_send(stream, now)?;
        requests.push(PrefixRequestStream {
            request_order: requests.len(),
            opening_stage_index: stage_index,
            role: "application",
            resource_id: *resource_id,
            request_id: None,
            stream_id: stream.as_u64(),
            request_stream_bytes: size,
            qualified_request_stream_bytes: None,
            acknowledgements: Vec::new(),
        });
    }
    Ok(())
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_lines,
    reason = "the production prefix qualifier retains every bound input and wire observation in one lifecycle"
)]
async fn qualify_chaff_prefix(
    application_source_path: &Path,
    runtime_workload_path: &Path,
    chaff_core_path: &Path,
    application_resource_id: u32,
    prefix_pack_spec_path: &Path,
    output_dir: &Path,
    timeout_seconds: u64,
) -> Result<(), Error> {
    let (application_source, application_source_sha256, prepared_expected_responses) =
        load_application_workload_source(application_source_path)?;
    let (runtime_workload, runtime_workload_sha256) = load_manifest(runtime_workload_path)?;
    let (chaff_core, chaff_core_sha256) = load_chaff_core(chaff_core_path)?;
    let (prefix_spec, prefix_pack_spec_sha256) = load_prefix_pack_spec(prefix_pack_spec_path)?;
    validate_prefix_pack_spec(&prefix_spec)?;
    validate_prefix_prepared_response_binding(
        &prefix_spec,
        &application_source,
        &prepared_expected_responses,
    )?;
    if application_resource_id != prefix_spec.application_resource_id {
        return Err(Error::Argument(
            "CLI application_resource_id does not match the hash-bound prefix specification".into(),
        ));
    }
    validate_chaff_core_binding(
        &chaff_core,
        &application_source,
        &application_source_sha256,
        &prefix_spec,
        &prepared_expected_responses,
    )?;
    let application = runtime_workload
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .ok_or_else(|| Error::Argument("runtime application root is absent".into()))?;
    let source_application = application_source
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .expect("validated");
    validate_qualification_application_root(application, application_resource_id)?;
    if runtime_workload
        .resources
        .iter()
        .filter(|resource| resource.depends_on.is_empty())
        .count()
        != 1
        || (
            &application.url,
            &application.kind,
            application.chaff_priority,
            application.known_valid,
            &application.depends_on,
            projected_ael(application)?,
        ) != (
            &source_application.url,
            &source_application.kind,
            source_application.chaff_priority,
            source_application.known_valid,
            &source_application.depends_on,
            projected_ael(source_application)?,
        )
    {
        return Err(Error::Argument(
            "runtime workload and frozen source disagree on the unique navigation root request"
                .into(),
        ));
    }
    let application_origin = application.origin().expect("validated root origin");
    for resource_id in prefix_spec
        .stream_activation_stages
        .iter()
        .flat_map(|stage| &stage.application_resource_ids)
    {
        let runtime_resource = runtime_workload
            .resources
            .iter()
            .find(|resource| resource.id == *resource_id)
            .ok_or_else(|| {
                Error::Argument(format!(
                    "runtime workload lacks activation-stage resource {resource_id}"
                ))
            })?;
        let source_resource = application_source
            .resources
            .iter()
            .find(|resource| resource.id == *resource_id)
            .ok_or_else(|| {
                Error::Argument(format!(
                    "frozen source lacks activation-stage resource {resource_id}"
                ))
            })?;
        if runtime_resource.origin().as_deref() != Some(application_origin.as_str())
            || (
                &runtime_resource.url,
                &runtime_resource.kind,
                runtime_resource.chaff_priority,
                runtime_resource.known_valid,
                &runtime_resource.depends_on,
                &runtime_resource.headers,
            ) != (
                &source_resource.url,
                &source_resource.kind,
                source_resource.chaff_priority,
                source_resource.known_valid,
                &source_resource.depends_on,
                &source_resource.headers,
            )
        {
            return Err(Error::Argument(format!(
                "runtime and frozen activation-stage resource {resource_id} disagree or are not same-origin"
            )));
        }
    }
    if output_dir.exists() && fs::read_dir(output_dir)?.next().is_some() {
        return Err(Error::Argument(format!(
            "output directory must be empty: {}",
            output_dir.display()
        )));
    }
    fs::create_dir_all(output_dir)?;
    let started_unix_ns = unix_nanos();
    let started = now();
    let url: Uri = application
        .url
        .parse()
        .map_err(|_| Error::Argument("runtime application root URL is invalid".into()))?;
    let authority = url
        .authority()
        .ok_or_else(|| Error::Argument("application root URL has no authority".into()))?;
    let host = authority.host().to_owned();
    let port = authority.port_u16().unwrap_or(443);
    let remote_addr = format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Argument(format!("could not resolve {host}:{port}")))?;
    let wildcard = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let route_probe = std::net::UdpSocket::bind(wildcard)?;
    route_probe.connect(remote_addr)?;
    let socket =
        Socket::bind_for_direct_capture(SocketAddr::new(route_probe.local_addr()?.ip(), 0))?;
    let local_addr = socket.local_addr()?;
    let params = ConnectionParameters::default()
        .max_stream_data(StreamType::BiDi, false, 0)
        .max_udp_payload_size(u64::from(prefix_spec.packet_size));
    let transport = Connection::new_client(
        &host,
        &["h3"],
        Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8))),
        local_addr,
        remote_addr,
        params,
        started,
    )?;
    let mut client = Http3Client::new_with_conn(
        transport,
        Http3Parameters::default().max_concurrent_push_streams(0),
    );
    let origin: Uri = format!("https://{authority}")
        .parse()
        .map_err(|_| Error::Argument("invalid application origin".into()))?;
    client.enable_qcsd(
        QcsdEndpointId(0),
        &origin,
        prefix_spec.packet_size,
        false,
        Duration::from_secs(1),
    )?;
    let deadline = started + Duration::from_secs(timeout_seconds);
    let mut recv_buf = RecvBuf::default();
    let mut packet_observations = Vec::<QualificationPacketObservation>::new();
    let mut next_packet_sequence = 0_u64;
    let mut incoming = PacketDirectionStats {
        packet_count: 0,
        observed_udp_payload_max: 0,
        oversized_packet_count: 0,
    };
    let mut outgoing = incoming.clone();
    let mut peer_settings_received = false;
    let mut warmup_stream_output_drained = false;
    let mut packet_cutoff_sequence = 0_u64;
    let mut requests = Vec::<PrefixRequestStream>::new();
    let mut transmissions = Vec::<QcsdStreamTransmission>::new();
    let mut qualification_started = false;
    let mut current_stage_index = 0_usize;
    let mut current_stage_slots = Vec::<u64>::new();
    let mut scheduled_slots = BTreeSet::<u64>::new();
    let mut satisfied_slots = BTreeSet::<u64>::new();
    let mut next_slot_id = 1_u64;
    let mut activation_stage_receipts = Vec::<PrefixActivationStageReceipt>::new();
    let loop_result: Result<(), Error> = async {
        loop {
            let loop_now = now();
            if loop_now >= deadline {
                return Err(Error::Timeout(timeout_seconds));
            }
            while let Some(datagrams) = socket.recv(local_addr, &mut recv_buf)? {
                for datagram in datagrams {
                    incoming.observe(datagram.len(), prefix_spec.packet_size);
                    packet_observations.push(QualificationPacketObservation {
                        sequence: next_packet_sequence,
                        phase: if qualification_started {
                            "qualification"
                        } else {
                            "warmup"
                        },
                        direction: "incoming",
                        udp_payload_bytes: datagram.len(),
                    });
                    next_packet_sequence = next_packet_sequence.saturating_add(1);
                    client.process_input(datagram, loop_now);
                }
            }
            while let Some(event) = client.next_event() {
                match event {
                    Http3ClientEvent::AuthenticationNeeded => {
                        client.authenticated(AuthenticationStatus::Ok, loop_now);
                    }
                    Http3ClientEvent::StateChange(Http3State::Closed(_)) => {
                        return Err(Error::RunAborted(
                            "HTTP/3 endpoint closed during prefix qualification".into(),
                        ));
                    }
                    _ => {}
                }
            }
            if !qualification_started && client.qcsd_peer_settings_received() {
                peer_settings_received = true;
                client.qcsd_prepare_stream_output(loop_now);
                if !client.qcsd_has_pending_stream_send() {
                    warmup_stream_output_drained = true;
                    client.qcsd_enable_send_shaping(true);
                    client.qcsd_enable_stream_transcript(true);
                    packet_cutoff_sequence = next_packet_sequence;
                    drop(client.qcsd_timestamped_observations());

                    let first_stage = &prefix_spec.stream_activation_stages[0];
                    open_prefix_application_stage(
                        &mut client,
                        loop_now,
                        &runtime_workload,
                        0,
                        &first_stage.application_resource_ids,
                        &mut requests,
                    )?;
                    let core_resource = &chaff_core.resources[0];
                    let compact = core_resource.as_resource();
                    for index in 0..prefix_spec.required_chaff_streams {
                        let request_id =
                            QcsdChaffRequestId(u64::try_from(index).unwrap_or(u64::MAX));
                        let stream = client
                            .apply_qcsd_action(
                                loop_now,
                                QcsdAction::RequestChaff {
                                    endpoint: QcsdEndpointId(0),
                                    resource: compact.clone(),
                                    request_id,
                                },
                            )?
                            .ok_or_else(|| {
                                Error::RunAborted("chaff request was not opened".into())
                            })?;
                        let size = client.qcsd_request_stream_bytes(stream)?;
                        client.stream_close_send(stream, loop_now)?;
                        if size != core_resource.chaff_qualification_core.request_stream_bytes {
                            return Err(Error::RunAborted(format!(
                                "compact chaff request encoded {size} bytes, expected {}",
                                core_resource.chaff_qualification_core.request_stream_bytes
                            )));
                        }
                        requests.push(PrefixRequestStream {
                            request_order: requests.len(),
                            opening_stage_index: 0,
                            role: "chaff",
                            resource_id: core_resource.id,
                            request_id: Some(request_id.0),
                            stream_id: stream.as_u64(),
                            request_stream_bytes: size,
                            qualified_request_stream_bytes: Some(
                                core_resource.chaff_qualification_core.request_stream_bytes,
                            ),
                            acknowledgements: Vec::new(),
                        });
                    }
                    current_stage_slots = queue_prefix_stage_targets(
                        &mut client,
                        loop_now,
                        first_stage,
                        prefix_spec.packet_size,
                        timeout_seconds,
                        &mut next_slot_id,
                        &mut scheduled_slots,
                    )?;
                    qualification_started = true;
                }
            }

            record_prefix_observations(
                &mut client,
                &mut requests,
                &mut transmissions,
                &scheduled_slots,
                &mut satisfied_slots,
            )?;
            if qualification_started {
                let stage = &prefix_spec.stream_activation_stages[current_stage_index];
                let current_targets_satisfied = current_stage_slots
                    .iter()
                    .all(|slot_id| satisfied_slots.contains(slot_id));
                let receipts = prefix_stream_receipts(&requests, &transmissions);
                let allowed_pending = intentionally_pending_late_chaff(
                    &requests,
                    stage.required_active_chaff_streams,
                );
                let pending_required =
                    client.qcsd_has_pending_required_prefix_stream_send(&allowed_pending);
                if current_targets_satisfied
                    && prefix_receipts_pass(&receipts, stage.required_active_chaff_streams)
                    && !pending_required
                {
                    let active_chaff: Vec<_> = receipts
                        .iter()
                        .filter(|receipt| {
                            receipt.role == "chaff"
                                && receipt.acknowledged_unique_ranges
                                    == [[0, receipt.request_stream_bytes]]
                                && receipt.fin_acknowledged
                        })
                        .collect();
                    let previously_required =
                        current_stage_index.checked_sub(1).map_or(0, |previous| {
                            prefix_spec.stream_activation_stages[previous]
                                .required_active_chaff_streams
                        });
                    let newly_activated: Vec<_> = active_chaff
                        .iter()
                        .filter(|receipt| {
                            receipt
                                .request_id
                                .and_then(|id| usize::try_from(id).ok())
                                .is_some_and(|id| {
                                    (previously_required..stage.required_active_chaff_streams)
                                        .contains(&id)
                                })
                        })
                        .collect();
                    let allowed_pending_orders: Vec<_> = requests
                        .iter()
                        .filter(|request| {
                            allowed_pending.contains(&StreamId::new(request.stream_id))
                        })
                        .map(|request| request.request_order)
                        .collect();
                    let targetless_at_gate =
                        prefix_targetless_stream_bytes(&transmissions, &scheduled_slots);
                    let active_required_count = active_chaff
                        .iter()
                        .filter(|receipt| {
                            receipt
                                .request_id
                                .and_then(|id| usize::try_from(id).ok())
                                .is_some_and(|id| id < stage.required_active_chaff_streams)
                        })
                        .count();
                    let stage_passed = active_required_count == stage.required_active_chaff_streams
                        && newly_activated.len() == stage.newly_required_chaff_streams
                        && targetless_at_gate == 0
                        && !pending_required;
                    activation_stage_receipts.push(PrefixActivationStageReceipt {
                        stage_index: current_stage_index,
                        component_index: stage.component_index,
                        application_resource_ids: stage.application_resource_ids.clone(),
                        application_request_orders: requests
                            .iter()
                            .filter(|request| {
                                request.role == "application"
                                    && request.opening_stage_index == current_stage_index
                            })
                            .map(|request| request.request_order)
                            .collect(),
                        application_stream_ids: requests
                            .iter()
                            .filter(|request| {
                                request.role == "application"
                                    && request.opening_stage_index == current_stage_index
                            })
                            .map(|request| request.stream_id)
                            .collect(),
                        target_slot_ids: current_stage_slots.clone(),
                        exact_target_cells: stage.exact_target_cells,
                        scheduled_target_bytes: stage
                            .exact_target_cells
                            .saturating_mul(u64::from(prefix_spec.packet_size)),
                        required_active_chaff_streams: stage.required_active_chaff_streams,
                        newly_required_chaff_streams: stage.newly_required_chaff_streams,
                        peer_acknowledged_active_chaff_streams: active_required_count,
                        newly_peer_acknowledged_request_orders: newly_activated
                            .iter()
                            .map(|receipt| receipt.request_order)
                            .collect(),
                        newly_peer_acknowledged_stream_ids: newly_activated
                            .iter()
                            .map(|receipt| receipt.stream_id)
                            .collect(),
                        allowed_pending_chaff_request_orders: allowed_pending_orders,
                        allowed_pending_chaff_stream_ids: allowed_pending
                            .iter()
                            .map(|stream| stream.as_u64())
                            .collect(),
                        targetless_stream_bytes_at_gate: targetless_at_gate,
                        pending_required_prefix_stream_send: pending_required,
                        passed: stage_passed,
                    });
                    if !stage_passed {
                        return Err(Error::RunAborted(
                            "prefix stage activation or target ownership invariant failed".into(),
                        ));
                    }
                    if current_stage_index + 1 == prefix_spec.stream_activation_stages.len() {
                        return Ok(());
                    }
                    current_stage_index = current_stage_index.saturating_add(1);
                    let next_stage = &prefix_spec.stream_activation_stages[current_stage_index];
                    open_prefix_application_stage(
                        &mut client,
                        loop_now,
                        &runtime_workload,
                        current_stage_index,
                        &next_stage.application_resource_ids,
                        &mut requests,
                    )?;
                    current_stage_slots = queue_prefix_stage_targets(
                        &mut client,
                        loop_now,
                        next_stage,
                        prefix_spec.packet_size,
                        timeout_seconds,
                        &mut next_slot_id,
                        &mut scheduled_slots,
                    )?;
                }
            }

            let output = client.process_multiple_output(loop_now, NonZeroUsize::MIN);
            record_prefix_observations(
                &mut client,
                &mut requests,
                &mut transmissions,
                &scheduled_slots,
                &mut satisfied_slots,
            )?;
            let delay = match output {
                OutputBatch::DatagramBatch(batch) => {
                    for datagram in batch.iter() {
                        outgoing.observe(datagram.len(), prefix_spec.packet_size);
                        packet_observations.push(QualificationPacketObservation {
                            sequence: next_packet_sequence,
                            phase: if qualification_started {
                                "qualification"
                            } else {
                                "warmup"
                            },
                            direction: "outgoing",
                            udp_payload_bytes: datagram.len(),
                        });
                        next_packet_sequence = next_packet_sequence.saturating_add(1);
                    }
                    loop {
                        match socket.send(&batch) {
                            Ok(()) => break,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                socket.writable().await?;
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Duration::from_millis(1)
                }
                OutputBatch::Callback(delay) => delay,
                OutputBatch::None => Duration::from_millis(10),
            };
            wait_for_activity(
                [&socket],
                bounded_qualification_wait(delay, deadline, timeout_seconds)?,
            )
            .await?;
        }
    }
    .await;

    let final_observation_result = record_prefix_observations(
        &mut client,
        &mut requests,
        &mut transmissions,
        &scheduled_slots,
        &mut satisfied_slots,
    );
    let stream_receipts = prefix_stream_receipts(&requests, &transmissions);
    let targetless_stream_bytes = prefix_targetless_stream_bytes(&transmissions, &scheduled_slots);
    let all_streams_owned = transmissions.iter().all(|transmission| {
        transmission
            .slot
            .is_some_and(|slot| scheduled_slots.contains(&slot.0))
    });
    let post_slot_pending_stream_send = client.qcsd_has_pending_stream_send();
    let allowed_pending =
        intentionally_pending_late_chaff(&requests, prefix_spec.required_chaff_streams);
    let allowed_pending_late_chaff_request_orders: Vec<_> = requests
        .iter()
        .filter(|request| allowed_pending.contains(&StreamId::new(request.stream_id)))
        .map(|request| request.request_order)
        .collect();
    let allowed_pending_late_chaff_stream_ids: Vec<_> = allowed_pending
        .iter()
        .map(|stream_id| stream_id.as_u64())
        .collect();
    let qpack_decoder_stream_id = client.qcsd_qpack_decoder_stream_id().map(StreamId::as_u64);
    let qpack_decoder_handler_pending = client.qcsd_qpack_decoder_handler_pending();
    let qpack_decoder_transport_pending = client.qcsd_qpack_decoder_transport_pending();
    let post_slot_pending_required_prefix_stream_send =
        client.qcsd_has_pending_required_prefix_stream_send(&allowed_pending);
    let passed = loop_result.is_ok()
        && final_observation_result.is_ok()
        && peer_settings_received
        && warmup_stream_output_drained
        && requests
            .iter()
            .filter(|request| request.role == "chaff")
            .count()
            == prefix_spec.required_chaff_streams
        && satisfied_slots == scheduled_slots
        && activation_stage_receipts.len() == prefix_spec.stream_activation_stages.len()
        && activation_stage_receipts.iter().all(|stage| stage.passed)
        && all_streams_owned
        && targetless_stream_bytes == 0
        && prefix_receipts_pass(&stream_receipts, prefix_spec.required_chaff_streams)
        && !post_slot_pending_required_prefix_stream_send
        && incoming.oversized_packet_count == 0
        && outgoing.oversized_packet_count == 0;
    let packet_log = serde_json::to_vec(&packet_observations)?;
    atomic_write(&output_dir.join("packets.json"), &packet_log)?;
    let packet_log_sha256 = sha256(&packet_log)?;
    let total = PacketDirectionStats {
        packet_count: incoming.packet_count.saturating_add(outgoing.packet_count),
        observed_udp_payload_max: incoming
            .observed_udp_payload_max
            .max(outgoing.observed_udp_payload_max),
        oversized_packet_count: incoming
            .oversized_packet_count
            .saturating_add(outgoing.oversized_packet_count),
    };
    let packets = PacketStatistics {
        incoming,
        outgoing,
        total,
    };
    let error = loop_result
        .as_ref()
        .err()
        .or_else(|| final_observation_result.as_ref().err())
        .map(ToString::to_string);
    let mut receipt = json!({
        "schema_version": 2,
        "artifact_type": "qcsd-chaff-prefix-pack-qualification",
        "invocation_id": format!("{}-{local_addr}", started_unix_ns),
        "neqo_version": env!("CARGO_PKG_VERSION"),
        "application_workload_source_sha256": application_source_sha256,
        "runtime_workload_sha256": runtime_workload_sha256,
        "chaff_core_sha256": chaff_core_sha256,
        "prefix_pack_spec_sha256": prefix_pack_spec_sha256,
        "application_resource_id": application_resource_id,
        "selected_chaff_resource_id": prefix_spec.selected_chaff_resource_id,
        "selected_chaff_body_bytes": prefix_spec.selected_chaff_body_bytes,
        "required_chaff_streams": prefix_spec.required_chaff_streams,
        "workload_id": prefix_spec.workload_id,
        "numeric_profile_sha256": prefix_spec.numeric_profile_sha256,
        "source_walkie_talkie_artifact_sha256": prefix_spec.source_walkie_talkie_artifact_sha256,
        "packet_size": prefix_spec.packet_size,
        "max_stream_data_excess": prefix_spec.max_stream_data_excess,
        "maximum_receiver_continuation_reserve_horizon": prefix_spec.maximum_receiver_continuation_reserve_horizon,
        "required_chaff_survivors": prefix_spec.required_chaff_survivors,
    });
    let evidence = json!({
        "connection_count": 1,
        "peer_settings_received": peer_settings_received,
        "warmup_stream_output_drained": warmup_stream_output_drained,
        "packet_cutoff_sequence": packet_cutoff_sequence,
        "requests_opened": requests.len(),
        "scheduled_target_slot_ids": scheduled_slots,
        "satisfied_target_slot_ids": satisfied_slots,
        "activation_stage_receipts": activation_stage_receipts,
        "streams": stream_receipts,
        "stream_transmissions": transmissions,
        "packet_observations": packet_observations,
        "packet_log_sha256": packet_log_sha256,
        "packets": packets,
        "post_slot_pending_stream_send": post_slot_pending_stream_send,
        "post_slot_pending_required_prefix_stream_send": post_slot_pending_required_prefix_stream_send,
        "allowed_pending_late_chaff_request_orders": allowed_pending_late_chaff_request_orders,
        "allowed_pending_late_chaff_stream_ids": allowed_pending_late_chaff_stream_ids,
        "targetless_stream_bytes": targetless_stream_bytes,
    });
    let completion = json!({
        "completion_status": if passed { "complete" } else { "error" },
        "error": error,
        "started_unix_ns": started_unix_ns,
        "ended_unix_ns": unix_nanos(),
        "source": {
            "neqo_base_commit": NEQO_BASE_COMMIT,
            "published_qcsd_commit": PUBLISHED_QCSD_COMMIT,
            "migration_commit": option_env!("NEQO_QCSD_GIT_COMMIT").unwrap_or("working-tree"),
        },
        "passed": passed,
    });
    let receipt_object = receipt.as_object_mut().ok_or_else(|| {
        Error::RunAborted("prefix qualification receipt is not a JSON object".into())
    })?;
    let serde_json::Value::Object(evidence) = evidence else {
        return Err(Error::RunAborted(
            "prefix qualification evidence is not a JSON object".into(),
        ));
    };
    receipt_object.extend(evidence);
    let serde_json::Value::Object(completion) = completion else {
        return Err(Error::RunAborted(
            "prefix qualification completion is not a JSON object".into(),
        ));
    };
    receipt_object.extend(completion);
    receipt_object.insert(
        "qpack_decoder_stream_id".into(),
        json!(qpack_decoder_stream_id),
    );
    receipt_object.insert(
        "qpack_decoder_handler_pending".into(),
        json!(qpack_decoder_handler_pending),
    );
    receipt_object.insert(
        "qpack_decoder_transport_pending".into(),
        json!(qpack_decoder_transport_pending),
    );
    atomic_write(
        &output_dir.join("qualification.json"),
        serde_json::to_string_pretty(&receipt)?.as_bytes(),
    )?;
    if passed {
        Ok(())
    } else {
        Err(loop_result
            .err()
            .or_else(|| final_observation_result.err())
            .unwrap_or_else(|| {
                Error::RunAborted("chaff prefix-pack qualification invariants failed".into())
            }))
    }
}

fn positional_manifest(urls: &[Uri]) -> ResourceManifest {
    ResourceManifest {
        resources: urls
            .iter()
            .enumerate()
            .map(|(id, url)| Resource {
                id: u32::try_from(id).unwrap_or(u32::MAX),
                url: url.to_string(),
                kind: "Unknown".into(),
                content_length: None,
                data_length: 0,
                chaff_priority: false,
                known_valid: false,
                depends_on: Vec::new(),
                headers: Vec::new(),
            })
            .collect(),
    }
}

fn load_manifest(path: &Path) -> Result<(ResourceManifest, String), Error> {
    let bytes = fs::read(path)?;
    let manifest = ResourceManifest::from_json(
        std::str::from_utf8(&bytes)
            .map_err(|_| Error::Argument(format!("manifest is not UTF-8: {}", path.display())))?,
    )?;
    Ok((manifest, sha256(&bytes)?))
}

fn load_application_workload_source(
    path: &Path,
) -> Result<
    (
        ResourceManifest,
        String,
        BTreeMap<u32, PreparedExpectedResponse>,
    ),
    Error,
> {
    let bytes = fs::read(path)?;
    let source: PreparedWorkloadSource = serde_json::from_slice(&bytes)?;
    if !source.preparation.is_object() || source.replay.is_some() {
        return Err(Error::Argument(
            "application workload source requires preparation metadata and must not contain replay metadata"
                .into(),
        ));
    }
    let expected = source
        .preparation
        .get("expected_responses")
        .ok_or_else(|| {
            Error::Argument(
                "prepared application source lacks preparation.expected_responses".into(),
            )
        })?
        .clone();
    let expected: Vec<PreparedExpectedResponse> = serde_json::from_value(expected)?;
    let mut by_id = BTreeMap::new();
    for response in expected {
        if !(200..300).contains(&response.status)
            || !lower_hex_sha256(&response.body_sha256)
            || by_id.insert(response.resource_id, response).is_some()
        {
            return Err(Error::Argument(
                "prepared expected response identities are invalid or duplicated".into(),
            ));
        }
    }
    if by_id.is_empty() {
        return Err(Error::Argument(
            "prepared expected response identities are empty".into(),
        ));
    }
    let manifest = ResourceManifest {
        resources: source.resources,
    };
    manifest.validate()?;
    Ok((manifest, sha256(&bytes)?, by_id))
}

fn load_chaff_manifest(path: &Path) -> Result<(RuntimeChaffManifest, String), Error> {
    let bytes = fs::read(path)?;
    let manifest = RuntimeChaffManifest::from_json(std::str::from_utf8(&bytes).map_err(|_| {
        Error::Argument(format!(
            "qualified chaff manifest is not UTF-8: {}",
            path.display()
        ))
    })?)?;
    let raw_hash = sha256(&bytes)?;
    Ok((manifest, raw_hash))
}

fn load_chaff_core(path: &Path) -> Result<(QualifiedChaffCore, String), Error> {
    let bytes = fs::read(path)?;
    let core: QualifiedChaffCore = serde_json::from_slice(&bytes)?;
    Ok((core, sha256(&bytes)?))
}

fn load_prefix_pack_spec(path: &Path) -> Result<(PrefixPackSpec, String), Error> {
    let bytes = fs::read(path)?;
    let spec: PrefixPackSpec = serde_json::from_slice(&bytes)?;
    Ok((spec, sha256(&bytes)?))
}

fn lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn all_future_receiver_continuation_reserve_horizon(bursts: &[PrefixBurst]) -> usize {
    bursts.iter().filter(|burst| burst.incoming > 0).count()
}

fn prefix_numeric_profile_sha256(profile: &PrefixNumericProfile) -> Result<String, Error> {
    // This is the exact UTF-8 produced by Python's
    // json.dumps(value, sort_keys=True, separators=(",", ":")) for this
    // integer-only schema. Keeping the construction explicit makes the
    // cross-language domain separation independently auditable.
    let canonical = serde_json::to_vec(profile)?;
    let mut preimage = b"qcsd-walkie-talkie-numeric-profile-v1\0".to_vec();
    preimage.extend_from_slice(&canonical);
    sha256(&preimage)
}

fn validate_prefix_pack_spec(spec: &PrefixPackSpec) -> Result<(), Error> {
    let horizon = all_future_receiver_continuation_reserve_horizon(&spec.numeric_profile.bursts);
    if spec.schema_version != 2
        || spec.artifact_type != "qcsd-walkie-talkie-prefix-pack-spec"
        || spec.workload_id.trim().is_empty()
        || spec.packet_size != 1_200
        || spec.max_stream_data_excess != 1_000
        || spec.numeric_profile.packet_size != spec.packet_size
        || spec.numeric_profile.bursts.is_empty()
        || horizon == 0
        || spec.maximum_receiver_continuation_reserve_horizon != horizon
        || spec.required_chaff_survivors != horizon.saturating_add(1)
        || spec.application_resource_id != 0
        || spec.selected_chaff_body_bytes < u64::from(spec.packet_size)
        || !(spec.required_chaff_survivors..=20).contains(&spec.required_chaff_streams)
        || spec.stream_activation_stages.len() != spec.numeric_profile.bursts.len()
        || !lower_hex_sha256(&spec.numeric_profile_sha256)
        || !lower_hex_sha256(&spec.source_walkie_talkie_artifact_sha256)
        || prefix_numeric_profile_sha256(&spec.numeric_profile)? != spec.numeric_profile_sha256
    {
        return Err(Error::Argument(
            "prefix-pack specification schema or numeric derivation is invalid".into(),
        ));
    }
    validate_prefix_capacity_plan(spec)
}

fn validate_prefix_capacity_plan(spec: &PrefixPackSpec) -> Result<(), Error> {
    if spec.stream_activation_stages.len() != spec.numeric_profile.bursts.len() {
        return Err(Error::Argument(
            "prefix capacity plan must cover every numeric component exactly once".into(),
        ));
    }
    let mut previous_active = 0_usize;
    let mut previous_exact_capacity_after = 0_u64;
    let mut application_ids = BTreeSet::new();
    for (stage_index, stage) in spec.stream_activation_stages.iter().enumerate() {
        let burst = &spec.numeric_profile.bursts[stage_index];
        let expected_future_reserves = spec.numeric_profile.bursts[stage_index..]
            .iter()
            .filter(|candidate| candidate.incoming > 0)
            .count();
        let expected_symmetric = stage
            .adapted_incoming_cells
            .saturating_sub(u64::from(stage.adapted_incoming_cells > 0));
        let expected_base_chaff_bytes = stage
            .symmetric_incoming_cells
            .checked_mul(u64::from(spec.packet_size))
            .ok_or_else(|| Error::Argument("prefix base capacity overflows u64".into()))?
            .saturating_sub(stage.application_body_floor_bytes);
        let expected_continuation_bytes =
            u64::from(spec.packet_size) * u64::from(stage.adapted_incoming_cells > 0);
        let newly_required_bytes = u64::try_from(stage.newly_required_chaff_streams)
            .ok()
            .and_then(|count| count.checked_mul(spec.selected_chaff_body_bytes))
            .ok_or_else(|| Error::Argument("new chaff capacity overflows u64".into()))?;
        let expected_exact_before = previous_exact_capacity_after
            .checked_add(newly_required_bytes)
            .ok_or_else(|| Error::Argument("exact chaff capacity overflows u64".into()))?;
        let reserved_bytes = u64::try_from(expected_future_reserves)
            .ok()
            .and_then(|count| count.checked_mul(spec.selected_chaff_body_bytes))
            .ok_or_else(|| Error::Argument("future reserve capacity overflows u64".into()))?;
        let Some(expected_ordinary_before) = expected_exact_before.checked_sub(reserved_bytes)
        else {
            return Err(Error::Argument(format!(
                "component {stage_index} lacks its exact future continuation reserves"
            )));
        };
        let Some(expected_exact_after) = expected_exact_before
            .checked_sub(expected_base_chaff_bytes)
            .and_then(|capacity| capacity.checked_sub(expected_continuation_bytes))
        else {
            return Err(Error::Argument(format!(
                "component {stage_index} consumes more exact chaff capacity than is available"
            )));
        };
        let consumed_reserve = usize::from(stage.adapted_incoming_cells > 0);
        let remaining_reserve_bytes =
            u64::try_from(expected_future_reserves.saturating_sub(consumed_reserve))
                .ok()
                .and_then(|count| count.checked_mul(spec.selected_chaff_body_bytes))
                .ok_or_else(|| {
                    Error::Argument("remaining reserve capacity overflows u64".into())
                })?;
        if stage.exact_target_cells == 0
            || stage.component_index != stage_index
            || stage.exact_target_cells != stage.outgoing_cells
            || stage.outgoing_cells != burst.outgoing
            || stage.adapted_incoming_cells != burst.incoming
            || stage.symmetric_incoming_cells != expected_symmetric
            || stage.required_active_chaff_streams < previous_active
            || stage.required_active_chaff_streams > spec.required_chaff_streams
            || stage.newly_required_chaff_streams
                != stage
                    .required_active_chaff_streams
                    .saturating_sub(previous_active)
            || stage.future_continuation_reserves != expected_future_reserves
            || (stage_index == 0
                && (stage.application_resource_ids.as_slice() != [spec.application_resource_id]
                    || stage.required_active_chaff_streams != spec.required_chaff_survivors))
            || stage
                .application_resource_ids
                .iter()
                .any(|resource_id| !application_ids.insert(*resource_id))
            || stage.base_chaff_bytes != expected_base_chaff_bytes
            || stage.continuation_bytes != expected_continuation_bytes
            || stage.exact_capacity_before_bytes != expected_exact_before
            || stage.ordinary_capacity_before_bytes != expected_ordinary_before
            || stage.exact_capacity_after_bytes != expected_exact_after
            || stage.early_continuation_required
                != (expected_base_chaff_bytes > expected_ordinary_before)
            || expected_exact_after < remaining_reserve_bytes
        {
            return Err(Error::Argument(
                "prefix activation stage ordering, target, cohort, or application batch is invalid"
                    .into(),
            ));
        }
        previous_active = stage.required_active_chaff_streams;
        previous_exact_capacity_after = expected_exact_after;
    }
    if previous_active != spec.required_chaff_streams {
        return Err(Error::Argument(
            "final prefix activation stage must prove the exact required chaff cohort".into(),
        ));
    }
    Ok(())
}

fn validate_prefix_prepared_response_binding(
    spec: &PrefixPackSpec,
    workload: &ResourceManifest,
    expected: &BTreeMap<u32, PreparedExpectedResponse>,
) -> Result<(), Error> {
    let application_batches = application_resource_batches(workload)?;
    let application = workload
        .resources
        .iter()
        .find(|resource| resource.id == spec.application_resource_id)
        .ok_or_else(|| Error::Argument("application navigation root is absent".into()))?;
    let (selected_resource, selected) =
        deterministic_selected_chaff_resource(workload, expected, application)?;
    if selected_resource.id != spec.selected_chaff_resource_id
        || selected.bytes != spec.selected_chaff_body_bytes
    {
        return Err(Error::Argument(
            "prefix spec selected chaff identity or body length is not the deterministic frozen source"
                .into(),
        ));
    }
    for (stage_index, stage) in spec.stream_activation_stages.iter().enumerate() {
        let expected_ids = application_batches
            .get(stage_index)
            .map_or(&[][..], Vec::as_slice);
        if stage.application_resource_ids != expected_ids {
            return Err(Error::Argument(format!(
                "component {stage_index} application_resource_ids do not equal the frozen dependency batch"
            )));
        }
        let mut body_floor = 0_u64;
        for resource_id in &stage.application_resource_ids {
            if !workload
                .resources
                .iter()
                .any(|resource| resource.id == *resource_id)
            {
                return Err(Error::Argument(format!(
                    "activation-stage resource {resource_id} is absent from the frozen source"
                )));
            }
            let response = expected.get(resource_id).ok_or_else(|| {
                Error::Argument(format!(
                    "activation-stage resource {resource_id} lacks a prepared response identity"
                ))
            })?;
            body_floor = body_floor.checked_add(response.bytes).ok_or_else(|| {
                Error::Argument("activation-stage application body floor overflows u64".into())
            })?;
        }
        if body_floor != stage.application_body_floor_bytes {
            return Err(Error::Argument(format!(
                "component {} application_body_floor_bytes is {}, expected exact prepared body sum {body_floor}",
                stage.component_index, stage.application_body_floor_bytes
            )));
        }
    }
    Ok(())
}

fn application_resource_batches(workload: &ResourceManifest) -> Result<Vec<Vec<u32>>, Error> {
    let mut depths = BTreeMap::<u32, usize>::new();
    while depths.len() < workload.resources.len() {
        let before = depths.len();
        for resource in &workload.resources {
            if depths.contains_key(&resource.id) {
                continue;
            }
            let depth = if resource.depends_on.is_empty() {
                Some(0)
            } else {
                resource
                    .depends_on
                    .iter()
                    .map(|dependency| depths.get(dependency).copied())
                    .collect::<Option<Vec<_>>>()
                    .and_then(|values| values.into_iter().max())
                    .map(|maximum| maximum.saturating_add(1))
            };
            if let Some(depth) = depth {
                depths.insert(resource.id, depth);
            }
        }
        if depths.len() == before {
            return Err(Error::Argument(
                "frozen application dependency graph is cyclic or unresolved".into(),
            ));
        }
    }
    let maximum = depths.values().copied().max().unwrap_or(0);
    let mut batches = vec![Vec::new(); maximum.saturating_add(1)];
    for (resource_id, depth) in depths {
        batches[depth].push(resource_id);
    }
    for batch in &mut batches {
        batch.sort_unstable();
    }
    if batches.first().map(Vec::as_slice) != Some(&[0]) {
        return Err(Error::Argument(
            "frozen application dependency batch zero must contain only navigation root zero"
                .into(),
        ));
    }
    Ok(batches)
}

#[expect(
    clippy::suspicious_operation_groupings,
    reason = "the canonical core deliberately maps differently named selected-resource and prepared-response fields"
)]
fn validate_chaff_core_binding(
    core: &QualifiedChaffCore,
    workload: &ResourceManifest,
    workload_hash: &str,
    spec: &PrefixPackSpec,
    expected: &BTreeMap<u32, PreparedExpectedResponse>,
) -> Result<(), Error> {
    if core.schema_version != 2
        || core.artifact_type != "qcsd-qualified-chaff-core"
        || core.application_workload_sha256 != workload_hash
        || core.application_resource_id != spec.application_resource_id
        || core.selected_chaff_resource_id != spec.selected_chaff_resource_id
        || core.qualified_parallel_chaff_streams != spec.required_chaff_streams.max(5)
        || core.walkie_talkie_required_chaff_streams != spec.required_chaff_streams
        || core.resources.len() != 1
    {
        return Err(Error::Argument(
            "qualified chaff core top-level binding is invalid".into(),
        ));
    }
    let application = workload
        .resources
        .iter()
        .find(|resource| resource.id == spec.application_resource_id)
        .ok_or_else(|| Error::Argument("application root is absent from workload".into()))?;
    validate_qualification_application_root(application, spec.application_resource_id)?;
    let selected = workload
        .resources
        .iter()
        .find(|resource| resource.id == spec.selected_chaff_resource_id)
        .ok_or_else(|| Error::Argument("selected chaff resource is absent from workload".into()))?;
    if selected.origin().is_none() || selected.origin() != application.origin() {
        return Err(Error::Argument(
            "selected chaff resource does not share the navigation root origin".into(),
        ));
    }
    let compact_headers = projected_ael(selected)?;
    let resource = &core.resources[0];
    let qualification = &resource.chaff_qualification_core;
    let response = &qualification.expected_response;
    let prepared_selected = expected
        .get(&spec.selected_chaff_resource_id)
        .ok_or_else(|| Error::Argument("selected prepared response identity is absent".into()))?;
    if (resource.id != spec.selected_chaff_resource_id)
        || resource.url != selected.url
        || resource.kind != selected.kind
        || resource.chaff_priority != selected.chaff_priority
        || !resource.known_valid
        || !resource.depends_on.is_empty()
        || resource.headers != compact_headers
        || qualification.schema_version != 2
        || qualification.method != "GET"
        || qualification.request_stream_bytes == 0
        || qualification.qualified_parallel_chaff_streams != core.qualified_parallel_chaff_streams
        || qualification.walkie_talkie_required_chaff_streams
            != core.walkie_talkie_required_chaff_streams
        || !(200..300).contains(&response.status)
        || response.body_bytes < 1_200
        || (response.body_bytes != spec.selected_chaff_body_bytes)
        || response.status != prepared_selected.status
        || response.body_bytes != prepared_selected.bytes
        || response.body_sha256 != prepared_selected.body_sha256
        || resource.content_length != Some(response.body_bytes)
        || resource.data_length != response.body_bytes
        || normalize_content_encoding(Some(&response.content_encoding)).as_deref()
            != Some(response.content_encoding.as_str())
        || !lower_hex_sha256(&response.body_sha256)
        || !lower_hex_sha256(&qualification.response_qualification_sha256)
    {
        return Err(Error::Argument(
            "qualified chaff core root, compact request, or response binding is invalid".into(),
        ));
    }
    ResourceManifest {
        resources: vec![resource.as_resource()],
    }
    .validate()?;
    Ok(())
}

fn manifest_hash(manifest: &ResourceManifest) -> Result<String, Error> {
    sha256(manifest.to_json_pretty()?.as_bytes())
}

fn sha256(bytes: &[u8]) -> Result<String, Error> {
    Ok(hex::encode(nss::hash::hash(
        &HashAlgorithm::SHA2_256,
        bytes,
    )?))
}

#[expect(
    clippy::future_not_send,
    reason = "the current-thread runner keeps the connection and controller lifecycle in one event loop"
)]
async fn execute_run(spec: RunSpec) -> Result<Vec<ResponseResult>, Error> {
    // Capture campaigns bind a least-privilege scheduling contract. Direct
    // developer invocations still serialize their unconstrained observation.
    _ = process_scheduler_evidence()?;
    spec.workload.validate()?;
    validate_workload_urls(&spec.workload)?;
    if let Some(chaff) = &spec.chaff_manifest {
        validate_chaff_manifest_defense(&spec.config.defense, chaff)?;
    }
    validate_qualified_chaff_binding(&spec)?;
    validate_walkie_talkie_chaff_precondition(&spec)?;
    if spec.output_dir.exists() && fs::read_dir(&spec.output_dir)?.next().is_some() {
        return Err(Error::Argument(format!(
            "output directory must be empty: {}",
            spec.output_dir.display()
        )));
    }
    fs::create_dir_all(&spec.output_dir)?;
    let wall_start = unix_nanos();
    let process_start = now();
    write_run_json(
        &spec,
        &[],
        &[],
        wall_start,
        &RunCompletion {
            ended_unix_ns: None,
            status: "running",
            error: None,
            defense_start_monotonic_ns: None,
            application_completion_monotonic_ns: None,
            defense_diagnostics: None,
            runner_wakeup_metrics: None,
        },
    )?;
    let result = execute_run_inner(&spec, wall_start, process_start).await;
    if let Err(error) = &result
        && !matches!(error, Error::Timeout(_))
        && !run_artifact_is_terminal(&spec.output_dir)
    {
        let message = error.to_string();
        write_run_json(
            &spec,
            &[],
            &[],
            wall_start,
            &RunCompletion {
                ended_unix_ns: Some(unix_nanos()),
                status: "error",
                error: Some(&message),
                defense_start_monotonic_ns: None,
                application_completion_monotonic_ns: None,
                defense_diagnostics: None,
                runner_wakeup_metrics: None,
            },
        )?;
    }
    result
}

fn validate_walkie_talkie_chaff_precondition(spec: &RunSpec) -> Result<(), Error> {
    let DefenseConfig::WalkieTalkie(config) = &spec.config.defense else {
        return Ok(());
    };
    if spec.config.use_empty_resources {
        return Err(Error::Argument(
            "Walkie-Talkie receiver continuations require positive-length chaff resources; use_empty_resources is unsupported".into(),
        ));
    }
    let binding = WalkieTalkie::new(
        config,
        spec.config.max_udp_payload_size,
        spec.config.max_stream_data_excess,
    )?
    .qualification_binding()
    .clone();
    let chaff_manifest_hash = spec.chaff_manifest_hash.as_deref().ok_or_else(|| {
        Error::Argument("Walkie-Talkie requires a raw qualified chaff manifest hash".into())
    })?;
    let chaff = spec
        .chaff_manifest
        .as_ref()
        .and_then(RuntimeChaffManifest::schema_two)
        .ok_or_else(|| {
            Error::Argument(
                "Walkie-Talkie requires a schema-two prefix-qualified chaff manifest".into(),
            )
        })?;
    if !walkie_talkie_qualification_binding_matches(
        &binding,
        &config.workload_id,
        chaff_manifest_hash,
        chaff,
        spec.config.max_chaff_streams,
    ) {
        return Err(Error::Argument(
            "Walkie-Talkie selected qualification binding does not match the exact chaff manifest resource identities, stream counts, or embedded prefix-pack spec hashes"
                .into(),
        ));
    }
    let mut origins: Vec<_> = spec
        .workload
        .resources
        .iter()
        .filter_map(Resource::origin)
        .collect();
    origins.sort_unstable();
    origins.dedup();
    let selected = spec.chaff_manifest.as_ref().and_then(|manifest| {
        manifest
            .resource_manifest()
            .initial_chaff_selection_effective_length_for_origins(&origins)
    });
    if selected.is_none_or(|length| length < u64::from(config.packet_size)) {
        return Err(Error::Argument(format!(
            "Walkie-Talkie initial same-origin chaff selection must provide at least {} response bytes",
            config.packet_size
        )));
    }
    Ok(())
}

fn walkie_talkie_qualification_binding_matches(
    binding: &WalkieTalkieQualificationBinding,
    workload_id: &str,
    chaff_manifest_hash: &str,
    chaff: &ChaffManifest,
    effective_max_chaff_streams: usize,
) -> bool {
    let Some(resource) = chaff.resources.first() else {
        return false;
    };
    binding.workload_id == workload_id
        && binding.qualified_chaff_manifest_sha256 == chaff_manifest_hash
        && binding.prefix_pack_spec_sha256 == resource.chaff_qualification.prefix_spec_sha256
        && binding.application_resource_id == chaff.application_resource_id
        && binding.selected_chaff_resource_id == chaff.selected_chaff_resource_id
        && binding.qualified_parallel_chaff_streams == chaff.qualified_parallel_chaff_streams
        && binding.walkie_talkie_required_chaff_streams
            == chaff.walkie_talkie_required_chaff_streams
        && effective_max_chaff_streams == chaff.walkie_talkie_required_chaff_streams
}

#[expect(
    clippy::suspicious_operation_groupings,
    clippy::too_many_lines,
    reason = "the runtime gate compares one qualified manifest against its frozen source and prepared response identities"
)]
fn validate_qualified_chaff_binding(spec: &RunSpec) -> Result<(), Error> {
    let Some(chaff) = &spec.chaff_manifest else {
        return Ok(());
    };
    let Some((source, source_hash, expected_responses)) = &spec.application_workload_source else {
        return Err(Error::Argument(
            "qualified chaff requires an exact application workload source binding".into(),
        ));
    };
    if chaff.application_workload_sha256() != source_hash {
        return Err(Error::Argument(
            "qualified chaff application_workload_sha256 does not match the exact frozen application workload source"
                .into(),
        ));
    }
    let qualified = chaff.selected_resource();
    let selected_chaff_resource_id = chaff.selected_chaff_resource_id();
    let application_resource_id = chaff.application_resource_id();
    let prepared_selected = expected_responses
        .get(&selected_chaff_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff selected resource lacks a frozen prepared response identity"
                    .into(),
            )
        })?;
    let application_root = spec
        .workload
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff application_resource_id is absent from the workload".into(),
            )
        })?;
    let source_application_root = source
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff application_resource_id is absent from the frozen source".into(),
            )
        })?;
    if (
        &application_root.url,
        &application_root.kind,
        application_root.chaff_priority,
        application_root.known_valid,
        &application_root.depends_on,
        &application_root.headers,
    ) != (
        &source_application_root.url,
        &source_application_root.kind,
        source_application_root.chaff_priority,
        source_application_root.known_valid,
        &source_application_root.depends_on,
        &source_application_root.headers,
    ) {
        return Err(Error::Argument(
            "runtime workload and frozen application source disagree on the navigation root request"
                .into(),
        ));
    }
    validate_qualification_application_root(application_root, application_resource_id)?;
    if chaff.is_identity_chaff_v4() {
        selected_identity_chaff_resource(
            source,
            expected_responses,
            source_application_root,
            selected_chaff_resource_id,
        )?;
    } else {
        let (deterministic_selected, deterministic_response) =
            deterministic_selected_chaff_resource(
                source,
                expected_responses,
                source_application_root,
            )?;
        if deterministic_selected.id != selected_chaff_resource_id
            || deterministic_response.resource_id != selected_chaff_resource_id
        {
            return Err(Error::Argument(
                "qualified chaff manifest does not select the deterministic frozen same-origin resource"
                    .into(),
            ));
        }
    }
    let selected = spec
        .workload
        .resources
        .iter()
        .find(|resource| resource.id == selected_chaff_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff selected_chaff_resource_id is absent from the workload".into(),
            )
        })?;
    let source_selected = source
        .resources
        .iter()
        .find(|resource| resource.id == selected_chaff_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff selected_chaff_resource_id is absent from the frozen source"
                    .into(),
            )
        })?;
    let selected_headers = if chaff.is_identity_chaff_v4() {
        projected_identity_chaff_headers(selected)?
    } else {
        projected_ael(selected)?
    };
    let source_selected_headers = if chaff.is_identity_chaff_v4() {
        projected_identity_chaff_headers(source_selected)?
    } else {
        projected_ael(source_selected)?
    };
    if (
        &selected.url,
        &selected.kind,
        selected.chaff_priority,
        selected.known_valid,
        &selected.depends_on,
        &selected_headers,
    ) != (
        &source_selected.url,
        &source_selected.kind,
        source_selected.chaff_priority,
        source_selected.known_valid,
        &source_selected.depends_on,
        &source_selected_headers,
    ) {
        return Err(Error::Argument(
            "runtime workload and frozen application source disagree on the selected chaff request"
                .into(),
        ));
    }
    if selected.origin().is_none()
        || selected.origin() != application_root.origin()
        || selected.url != qualified.url
        || selected.kind != qualified.kind
        || selected.chaff_priority != qualified.chaff_priority
        || !selected.known_valid
        || selected_headers != qualified.headers
    {
        return Err(Error::Argument(
            "qualified chaff selected-resource metadata, origin, or exact AEL projection is invalid"
                .into(),
        ));
    }
    let qualification = chaff
        .qualification(selected_chaff_resource_id)
        .ok_or_else(|| {
            Error::Argument("qualified chaff selected resource lacks qualification data".into())
        })?;
    let identity = qualification.expected_response();
    let expected = identity.body_bytes;
    if !chaff.is_identity_chaff_v4()
        && (identity.status != prepared_selected.status
            || identity.body_bytes != prepared_selected.bytes
            || identity.body_sha256 != prepared_selected.body_sha256)
    {
        return Err(Error::Argument(
            "qualified chaff response identity does not match frozen prepared status, body length, and body SHA-256"
                .into(),
        ));
    }
    if expected > spec.max_response_bytes {
        return Err(Error::Argument(format!(
            "qualified chaff response body {expected} exceeds max_response_bytes {}",
            spec.max_response_bytes
        )));
    }
    Ok(())
}

fn run_artifact_is_terminal(output_dir: &Path) -> bool {
    let Ok(contents) = fs::read(output_dir.join("run.json")) else {
        return false;
    };
    let Ok(run) = serde_json::from_slice::<serde_json::Value>(&contents) else {
        return false;
    };
    run.get("completion_status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|status| status != "running")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ApplicationBatchLifecycle {
    enabled: bool,
    active: bool,
}

impl ApplicationBatchLifecycle {
    fn new(defense: &DefenseConfig, request_policy: RequestPolicyArg) -> Self {
        Self {
            enabled: matches!(defense, DefenseConfig::WalkieTalkie(_))
                || request_policy == RequestPolicyArg::HalfDuplex,
            active: false,
        }
    }

    const fn before_dispatch(
        &mut self,
        application_stream_in_flight: bool,
    ) -> Option<QcsdObservation> {
        if !self.enabled || !self.active || application_stream_in_flight {
            return None;
        }
        self.active = false;
        Some(QcsdObservation::ApplicationBatchCompleted)
    }

    fn after_dispatch(
        &mut self,
        started_requests: usize,
    ) -> Result<Option<QcsdObservation>, Error> {
        if !self.enabled || started_requests == 0 {
            return Ok(None);
        }
        if self.active {
            return Err(Error::SlotInvariant(
                "opened a new application request while the previous global batch was active"
                    .into(),
            ));
        }
        self.active = true;
        Ok(Some(QcsdObservation::ApplicationBatchStarted))
    }
}

fn deadline_error(
    defense: &DefenseConfig,
    controller_complete: bool,
    timeout_seconds: u64,
) -> Error {
    if matches!(defense, DefenseConfig::WalkieTalkie(_)) && !controller_complete {
        Error::RunAborted(
            "Walkie-Talkie stalled before its application batch and byte budget completed".into(),
        )
    } else {
        Error::Timeout(timeout_seconds)
    }
}

fn ensure_defense_realizable(controller: &QcsdController) -> Result<(), Error> {
    if let Some(failure) = controller.terminal_failure() {
        return Err(Error::RunAborted(failure.into()));
    }
    Ok(())
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_lines,
    reason = "the current-thread runner keeps the connection and controller lifecycle in one event loop"
)]
async fn execute_run_inner(
    spec: &RunSpec,
    wall_start: u128,
    process_start: Instant,
) -> Result<Vec<ResponseResult>, Error> {
    let mut traces = TraceFiles::new(&spec.output_dir, process_start)?;
    let observation_clock = QcsdObservationClock::new(process_start);
    let mut endpoints = create_endpoints(spec, process_start, &observation_clock)?;
    let mut controller = QcsdController::new(
        spec.config.clone(),
        spec.seed,
        spec.chaff_manifest
            .as_ref()
            .map(RuntimeChaffManifest::resource_manifest),
    )?;
    let mut dependencies = DependencyTracker::new(spec.workload.clone())?;
    let mut defense_start = None;
    let mut application_completion = None;
    let mut application_complete_observed = false;
    let mut last_egress_backlog = None;
    let mut application_batches =
        ApplicationBatchLifecycle::new(&spec.config.defense, spec.request_policy);
    let mut runner_wakeup_metrics = RunnerWakeupMetrics::new();
    let deadline = process_start + Duration::from_secs(spec.timeout_seconds);

    let loop_result: Result<(), Error> = async {
        loop {
            let loop_now = now();
            if loop_now >= deadline {
                return Err(deadline_error(
                    &spec.config.defense,
                    controller.is_complete(),
                    spec.timeout_seconds,
                ));
            }

            let elapsed_before_http =
                defense_start.map(|start| loop_now.saturating_duration_since(start));
            for endpoint in &mut endpoints {
                // Socket activity is reduced into defense signals before a due
                // timer is polled. This lets a real packet cancel a pending
                // reactive-defense decision.
                process_input(
                    endpoint,
                    &mut controller,
                    &mut traces,
                    &observation_clock,
                    loop_now,
                    elapsed_before_http,
                )?;
                handle_http_events(endpoint, spec, loop_now, &mut traces)?;
                for (resource_id, state) in endpoint.retired_applications.drain(..) {
                    let success = state == ResourceRunState::Succeeded;
                    if success {
                        dependencies.mark_succeeded(resource_id)?;
                    } else {
                        dependencies.mark_failed(resource_id)?;
                    }
                    let record = observation_clock.record(QcsdObservation::ResourceCompleted {
                        resource_id,
                        success,
                    });
                    traces.observation(Some(endpoint.id), &record)?;
                    controller.observe(
                        record.into_observation(),
                        elapsed_before_http.unwrap_or(Duration::ZERO),
                    );
                }
            }

            if defense_start.is_none() && endpoints.iter().all(|endpoint| endpoint.connected) {
                // Handshake datagrams predate the defense clock even though
                // their transport classifications can still be queued when
                // the final endpoint becomes ready.  Retain the endpoint and
                // stream/capacity observations at elapsed zero, but never let
                // those pre-defense datagrams arm a reactive defense.
                handle_defense_activation_observations(
                    &mut endpoints,
                    &mut controller,
                    &mut traces,
                )?;
                if matches!(&spec.config.defense, DefenseConfig::TrafficMorphing(_)) {
                    // Direct capture already includes every handshake packet.
                    // Start only the morpher at the global defense boundary so
                    // an origin that connected early cannot contribute a
                    // pre-defense 1-RTT bootstrap bypass at elapsed time zero.
                    activate_traffic_morphing(&mut endpoints, &spec.config, spec.seed)?;
                    defense_start = Some(now());
                } else {
                    defense_start = Some(loop_now);
                }
            }

            let defense_elapsed =
                defense_start.map(|start| loop_now.saturating_duration_since(start));
            if let Some(defense_elapsed) = defense_elapsed {
                // Drain observations produced while the previous application
                // batch was retired before closing that batch.  In
                // particular, BytesRead and stream lifecycle observations
                // must causally precede ApplicationBatchCompleted.  Complete
                // the old batch before dispatching the next layer made
                // eligible by dependency retirement in this same loop turn.
                handle_all_qcsd_observations(
                    &mut endpoints,
                    &mut controller,
                    &mut traces,
                    defense_elapsed,
                )?;
                let application_stream_in_flight = has_in_flight_application_stream(
                    endpoints
                        .iter()
                        .flat_map(|endpoint| endpoint.streams.values()),
                );
                if let Some(observation) =
                    application_batches.before_dispatch(application_stream_in_flight)
                {
                    let record = observation_clock.record(observation);
                    traces.observation(None, &record)?;
                    controller.observe(record.into_observation(), defense_elapsed);
                }
                controller.flush_defense_observations();
                ensure_defense_realizable(&controller)?;
                let started_requests = dispatch_ready_requests(
                    &mut endpoints,
                    spec,
                    &mut dependencies,
                    loop_now,
                    &mut traces,
                    controller.can_start_application_batch(),
                )?;
                let batch_started = application_batches.after_dispatch(started_requests)?;
                handle_all_qcsd_observations(
                    &mut endpoints,
                    &mut controller,
                    &mut traces,
                    defense_elapsed,
                )?;
                if let Some(observation) = batch_started {
                    let record = observation_clock.record(observation);
                    traces.observation(None, &record)?;
                    controller.observe(record.into_observation(), defense_elapsed);
                }
            }

            let wake_base = now();
            let mut next_wakeup = absolute_wakeup(wake_base, spec.config.control_interval())
                .ok_or_else(|| Error::RunAborted("runner wake deadline overflow".into()))?;
            let mut controller_deadline_selected = false;
            for endpoint_index in 0..endpoints.len() {
                // Flush output that was already available (including newly
                // dispatched application requests) so its Wire signals precede
                // the defense poll.
                if let Some(wakeup) = drive_endpoint_output(
                    endpoint_index,
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    &observation_clock,
                    defense_start,
                )
                .await?
                    && wakeup < next_wakeup
                {
                    next_wakeup = wakeup;
                    controller_deadline_selected = false;
                }
            }

            let control_now = now();
            let control_elapsed =
                defense_start.map(|start| control_now.saturating_duration_since(start));
            if let Some(defense_elapsed) = control_elapsed {
                handle_all_qcsd_observations(
                    &mut endpoints,
                    &mut controller,
                    &mut traces,
                    defense_elapsed,
                )?;
                let candidate_defense = matches!(
                    spec.config.defense,
                    DefenseConfig::Buflo(_) | DefenseConfig::CsBuflo(_)
                );
                let egress_backlog_pending = endpoints.iter_mut().any(|endpoint| {
                    endpoint.client.qcsd_has_pending_stream_send()
                        || (candidate_defense && endpoint.client.qcsd_has_pending_defense_control())
                });
                if last_egress_backlog != Some(egress_backlog_pending) {
                    last_egress_backlog = Some(egress_backlog_pending);
                    let record = observation_clock.record(QcsdObservation::EgressBacklog {
                        pending: egress_backlog_pending,
                    });
                    traces.observation(None, &record)?;
                    controller.observe(record.into_observation(), defense_elapsed);
                }
                if !application_complete_observed && dependencies.is_complete() {
                    application_complete_observed = true;
                    application_completion = Some(control_now);
                    let observation = QcsdObservation::ApplicationComplete;
                    let record = observation_clock.record(observation);
                    traces.observation(None, &record)?;
                    controller.observe(record.into_observation(), defense_elapsed);
                }
                controller.poll(defense_elapsed);
                ensure_defense_realizable(&controller)?;
                apply_queued_actions(
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    control_now,
                    defense_elapsed,
                )?;
            }

            for endpoint_index in 0..endpoints.len() {
                // Retain a post-action flush so newly scheduled packet targets can
                // be placed on the wire without waiting for another loop turn.
                if let Some(wakeup) = drive_endpoint_output(
                    endpoint_index,
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    &observation_clock,
                    defense_start,
                )
                .await?
                    && wakeup < next_wakeup
                {
                    next_wakeup = wakeup;
                    controller_deadline_selected = false;
                }
                let endpoint = &mut endpoints[endpoint_index];
                let input_now = now();
                let input_elapsed =
                    defense_start.map(|start| input_now.saturating_duration_since(start));
                process_input(
                    endpoint,
                    &mut controller,
                    &mut traces,
                    &observation_clock,
                    input_now,
                    input_elapsed,
                )?;
            }

            if application_complete_observed
                && controller.is_complete()
                && endpoints.iter_mut().all(|endpoint| {
                    endpoint.connected
                        && matches!(endpoint.client.state(), Http3State::Connected)
                        && endpoint.scheduled_outgoing.is_empty()
                        && endpoint.client.qcsd_pending_packet_targets() == 0
                        && (!matches!(
                            spec.config.defense,
                            DefenseConfig::Buflo(_) | DefenseConfig::CsBuflo(_)
                        ) || (!endpoint.client.qcsd_has_pending_stream_send()
                            && !endpoint.client.qcsd_has_pending_defense_control()
                            && application_send_halves_peer_confirmed(endpoint)))
                })
            {
                traces.ensure_no_pending_slots()?;
                break;
            }
            if let Some(defense_start) = defense_start
                && let Some(next_deadline) = controller.next_deadline()
            {
                let controller_wakeup = defense_start
                    .checked_add(next_deadline)
                    .ok_or_else(|| Error::RunAborted("controller wake deadline overflow".into()))?;
                if controller_wakeup <= next_wakeup {
                    next_wakeup = controller_wakeup;
                    controller_deadline_selected = true;
                }
            }
            let wake = wait_for_activity_until(
                endpoints.iter().map(|endpoint| &endpoint.socket),
                next_wakeup,
            )
            .await?;
            runner_wakeup_metrics.record(wake, controller_deadline_selected);
        }
        Ok(())
    }
    .await;

    if let Err(error) = loop_result {
        let (status, miss_reason) = if matches!(&error, Error::Timeout(_)) {
            ("timeout", MissedSlotReason::DeadlineExpired)
        } else {
            ("error", MissedSlotReason::RunAborted)
        };
        let ended_at = now();
        let terminal_elapsed = defense_start.map_or(Duration::ZERO, |started| {
            ended_at.saturating_duration_since(started)
        });
        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            ended_at,
            terminal_elapsed,
            miss_reason,
        )?;
        for endpoint in &mut endpoints {
            endpoint.scheduled_outgoing.clear();
        }
        let responses = collect_responses(&mut endpoints)?;
        let message = error.to_string();
        traces.flush_events()?;
        write_run_json(
            spec,
            &endpoints,
            &responses,
            wall_start,
            &RunCompletion {
                ended_unix_ns: Some(unix_nanos()),
                status,
                error: Some(&message),
                defense_start_monotonic_ns: defense_start
                    .map(|instant| elapsed_ns(process_start, instant)),
                application_completion_monotonic_ns: application_completion
                    .map(|instant| elapsed_ns(process_start, instant)),
                defense_diagnostics: Some(controller.defense_diagnostics()),
                runner_wakeup_metrics: Some(runner_wakeup_metrics),
            },
        )?;
        return Err(error);
    }

    let responses = collect_responses(&mut endpoints)?;
    let completion_status = if dependencies.is_successful() {
        "complete"
    } else {
        "partial"
    };
    traces.flush_events()?;
    write_run_json(
        spec,
        &endpoints,
        &responses,
        wall_start,
        &RunCompletion {
            ended_unix_ns: Some(unix_nanos()),
            status: completion_status,
            error: None,
            defense_start_monotonic_ns: defense_start
                .map(|instant| elapsed_ns(process_start, instant)),
            application_completion_monotonic_ns: application_completion
                .map(|instant| elapsed_ns(process_start, instant)),
            defense_diagnostics: Some(controller.defense_diagnostics()),
            runner_wakeup_metrics: Some(runner_wakeup_metrics),
        },
    )?;
    Ok(responses)
}

fn validate_workload_urls(workload: &ResourceManifest) -> Result<(), Error> {
    if workload.resources.is_empty() {
        return Err(Error::Argument("at least one URL is required".into()));
    }
    for resource in &workload.resources {
        let url: Uri = resource
            .url
            .parse()
            .map_err(|_| Error::Argument(format!("invalid URL: {}", resource.url)))?;
        if url.scheme_str() != Some("https") || url.authority().is_none() {
            return Err(Error::Argument(format!(
                "URL must be absolute HTTPS: {url}"
            )));
        }
    }
    Ok(())
}

/// Gate application and chaff STREAM data for defenses that shape sends.
///
/// ACK, path-validation, and other mandatory QUIC control frames remain owned
/// by the transport and are never suppressed by this runner-level policy.
const fn shapes_stream_sends(defense: &DefenseConfig) -> bool {
    matches!(
        defense,
        DefenseConfig::Tamaraw(_)
            | DefenseConfig::Buflo(_)
            | DefenseConfig::CsBuflo(_)
            | DefenseConfig::WalkieTalkie(_)
            | DefenseConfig::Static {
                padding_only: false,
                ..
            }
    )
}

fn expected_application_response_length(
    resource: &Resource,
    max_response_bytes: u64,
) -> Option<u64> {
    (max_response_bytes > 0).then(|| resource.effective_length().min(max_response_bytes))
}

fn traffic_morphing_endpoint_seed(seed: u64, endpoint: QcsdEndpointId) -> u64 {
    derive(seed, &format!("traffic-morphing-endpoint-{}", endpoint.0)).next_u64()
}

fn activate_traffic_morphing(
    endpoints: &mut [Endpoint],
    config: &QcsdConfig,
    seed: u64,
) -> Result<(), Error> {
    let DefenseConfig::TrafficMorphing(morphing_config) = &config.defense else {
        return Ok(());
    };
    if endpoints.iter().any(|endpoint| !endpoint.connected) {
        return Err(Error::SlotInvariant(
            "Traffic Morphing cannot activate before every endpoint is connected".into(),
        ));
    }
    if endpoints
        .iter()
        .any(|endpoint| endpoint.traffic_morphing_activation != TrafficMorphingActivation::Pending)
    {
        return Err(Error::SlotInvariant(
            "Traffic Morphing must activate each endpoint exactly once".into(),
        ));
    }

    // Construct every sampler before installing any of them so a parameter
    // failure cannot leave only a subset of origins morphed.
    let morphers = endpoints
        .iter()
        .map(|endpoint| {
            TrafficMorphingEgress::new(
                morphing_config,
                traffic_morphing_endpoint_seed(seed, endpoint.id),
                config.max_udp_payload_size,
            )
        })
        .collect::<neqo_csdef::Result<Vec<_>>>()?;
    for (endpoint, morpher) in endpoints.iter_mut().zip(morphers) {
        endpoint.client.enable_qcsd_traffic_morphing(morpher);
        endpoint.traffic_morphing_activation = TrafficMorphingActivation::Active;
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "endpoint construction validates and binds one fail-closed multi-origin QCSD unit"
)]
fn create_endpoints(
    spec: &RunSpec,
    start: Instant,
    observation_clock: &QcsdObservationClock,
) -> Result<Vec<Endpoint>, Error> {
    let mut grouped = BTreeMap::<(String, u16), VecDeque<ApplicationRequest>>::new();
    for resource in &spec.workload.resources {
        let url: Uri = resource
            .url
            .parse()
            .map_err(|_| Error::Argument(format!("invalid URL: {}", resource.url)))?;
        let authority = url.authority().expect("validated");
        grouped
            .entry((
                authority.host().to_owned(),
                authority.port_u16().unwrap_or(443),
            ))
            .or_default()
            .push_back(ApplicationRequest {
                resource_id: resource.id,
                url,
                headers: spec.workload.application_headers(resource.id)?,
                expected_response_length: expected_application_response_length(
                    resource,
                    spec.max_response_bytes,
                ),
            });
    }
    grouped
        .into_iter()
        .enumerate()
        .map(|(index, ((host, port), pending))| {
            let remote_addr = format!("{host}:{port}")
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| Error::Argument(format!("could not resolve {host}:{port}")))?;
            let wildcard = match remote_addr {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let route_probe = std::net::UdpSocket::bind(wildcard)?;
            route_probe.connect(remote_addr)?;
            let bind_addr = SocketAddr::new(route_probe.local_addr()?.ip(), 0);
            let socket = Socket::bind_for_direct_capture(bind_addr)?;
            let local_addr = socket.local_addr()?;
            let params = qcsd_connection_parameters(&spec.config, remote_addr.ip());
            let transport = Connection::new_client(
                &host,
                &["h3"],
                Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8))),
                local_addr,
                remote_addr,
                params,
                start,
            )?;
            let mut client = Http3Client::new_with_conn(
                transport,
                Http3Parameters::default().max_concurrent_push_streams(0),
            );
            let endpoint_id = QcsdEndpointId(u64::try_from(index).unwrap_or(u64::MAX));
            let origin: Uri = format!(
                "https://{}",
                pending
                    .front()
                    .expect("nonempty")
                    .url
                    .authority()
                    .expect("validated")
            )
            .parse()
            .map_err(|_| Error::Argument("invalid origin".into()))?;
            let shape_stream_sends = shapes_stream_sends(&spec.config.defense);
            client.enable_qcsd_with_observation_clock(
                endpoint_id,
                &origin,
                spec.config.max_udp_payload_size,
                shape_stream_sends,
                Duration::from_micros(spec.config.keep_alive_lead_time_us),
                observation_clock.clone(),
            )?;
            Ok(Endpoint {
                id: endpoint_id,
                origin,
                remote_addr,
                local_addr,
                socket,
                recv_buf: RecvBuf::default(),
                client,
                pending,
                streams: HashMap::new(),
                application_send_streams: BTreeSet::new(),
                completed: Vec::new(),
                connected: false,
                retired_applications: Vec::new(),
                scheduled_outgoing: VecDeque::new(),
                traffic_morphing_activation: if matches!(
                    &spec.config.defense,
                    DefenseConfig::TrafficMorphing(_)
                ) {
                    TrafficMorphingActivation::Pending
                } else {
                    TrafficMorphingActivation::NotSelected
                },
            })
        })
        .collect()
}

fn qcsd_connection_parameters(config: &QcsdConfig, remote_ip: IpAddr) -> ConnectionParameters {
    let params = if matches!(config.defense, DefenseConfig::None) {
        ConnectionParameters::default()
    } else {
        ConnectionParameters::default().max_stream_data(
            StreamType::BiDi,
            false,
            config.effective_initial_max_stream_data(),
        )
    };

    // Keep packetization fixed when the default path already accommodates the
    // configured defense ceiling. Larger published/custom ceilings still need
    // discovery; enabling it from the shared run config applies one policy to
    // every defense, including the undefended baseline.
    params
        .max_udp_payload_size(u64::from(config.max_udp_payload_size))
        .pmtud(usize::from(config.max_udp_payload_size) > Pmtud::default_plpmtu(remote_ip))
}

fn dispatch_ready_requests(
    endpoints: &mut [Endpoint],
    spec: &RunSpec,
    dependencies: &mut DependencyTracker,
    now: Instant,
    traces: &mut TraceFiles,
    defense_batch_ready: bool,
) -> Result<usize, Error> {
    let application_stream_in_flight = has_in_flight_application_stream(
        endpoints
            .iter()
            .flat_map(|endpoint| endpoint.streams.values()),
    );
    let ready = ready_request_batch(
        &spec.config.defense,
        spec.request_policy,
        application_stream_in_flight,
        defense_batch_ready,
        dependencies,
    );
    let mut started_requests = 0;
    for endpoint in endpoints {
        let pending_count = endpoint.pending.len();
        for _ in 0..pending_count {
            let Some(request) = endpoint.pending.pop_front() else {
                break;
            };
            if dependencies.state(request.resource_id) == Some(ResourceRunState::SkippedDependency)
            {
                endpoint.completed.push(application_record(
                    &request,
                    QcsdRequestRole::Application,
                    "skipped_dependency",
                ));
                traces.event(
                    now,
                    Some(endpoint.id),
                    "application_request",
                    "skipped_dependency",
                    &request.resource_id,
                )?;
                continue;
            }
            if !ready.contains(&request.resource_id) {
                endpoint.pending.push_back(request);
                continue;
            }
            let headers: Vec<_> = request
                .headers
                .iter()
                .map(|(name, value)| Header::new(name.as_str(), value.as_str()))
                .collect();
            let stream = match endpoint.client.fetch(
                now,
                spec.method,
                &request.url,
                &headers,
                Priority::default(),
            ) {
                Ok(stream) => stream,
                Err(error) => {
                    dependencies.mark_failed(request.resource_id)?;
                    endpoint.completed.push(application_record(
                        &request,
                        QcsdRequestRole::Application,
                        "request_error",
                    ));
                    traces.event(
                        now,
                        Some(endpoint.id),
                        "application_request",
                        "failed",
                        &error.to_string(),
                    )?;
                    continue;
                }
            };
            endpoint.client.register_qcsd_stream(
                stream,
                QcsdRequestRole::Application,
                request.expected_response_length,
            )?;
            let request_stream_bytes = endpoint.client.qcsd_request_stream_bytes(stream)?;
            endpoint.client.stream_close_send(stream, now)?;
            endpoint.application_send_streams.insert(stream);
            dependencies.mark_in_flight(request.resource_id)?;
            started_requests += 1;
            endpoint.streams.insert(stream, {
                let mut record =
                    application_record(&request, QcsdRequestRole::Application, "in_flight");
                record.request_stream_bytes = request_stream_bytes;
                record
            });
            traces.event(
                now,
                Some(endpoint.id),
                "application_request",
                "started",
                &request.resource_id,
            )?;
        }
    }
    Ok(started_requests)
}

fn has_in_flight_application_stream<'a>(
    streams: impl IntoIterator<Item = &'a StreamRecord>,
) -> bool {
    streams
        .into_iter()
        .any(|record| record.role == QcsdRequestRole::Application && record.outcome == "in_flight")
}

fn application_send_halves_peer_confirmed(endpoint: &Endpoint) -> bool {
    tracked_application_send_halves_peer_confirmed(&endpoint.application_send_streams, |stream| {
        endpoint
            .client
            .qcsd_application_send_stream_peer_confirmed(stream)
    })
}

fn tracked_application_send_halves_peer_confirmed(
    streams: &BTreeSet<StreamId>,
    mut peer_confirmed: impl FnMut(StreamId) -> bool,
) -> bool {
    streams.iter().copied().all(&mut peer_confirmed)
}

fn ready_request_batch(
    defense: &DefenseConfig,
    request_policy: RequestPolicyArg,
    application_stream_in_flight: bool,
    defense_batch_ready: bool,
    dependencies: &DependencyTracker,
) -> Vec<u32> {
    if matches!(defense, DefenseConfig::WalkieTalkie(_))
        && (!defense_batch_ready || application_stream_in_flight)
        || request_policy == RequestPolicyArg::HalfDuplex && application_stream_in_flight
    {
        return Vec::new();
    }
    dependencies
        .ready()
        .iter()
        .map(|resource| resource.id)
        .collect()
}

fn application_record(
    request: &ApplicationRequest,
    role: QcsdRequestRole,
    outcome: &'static str,
) -> StreamRecord {
    StreamRecord {
        resource_id: request.resource_id,
        url: request.url.to_string(),
        role,
        request_headers: request.headers.clone(),
        request_stream_bytes: 0,
        expected_request_stream_bytes: None,
        response_headers: Vec::new(),
        status: None,
        content_length: None,
        body: Vec::new(),
        bytes: 0,
        complete: false,
        outcome,
        expected_chaff_response: None,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "HTTP/3 stream lifecycle reduction preserves terminal application and chaff evidence"
)]
fn handle_http_events(
    endpoint: &mut Endpoint,
    spec: &RunSpec,
    now: Instant,
    traces: &mut TraceFiles,
) -> Result<(), Error> {
    while let Some(event) = endpoint.client.next_event() {
        match event {
            Http3ClientEvent::AuthenticationNeeded => {
                endpoint.client.authenticated(AuthenticationStatus::Ok, now);
            }
            Http3ClientEvent::StateChange(Http3State::Connected) => endpoint.connected = true,
            Http3ClientEvent::StateChange(Http3State::Closed(reason)) => {
                endpoint.connected = false;
                let streams: Vec<_> = endpoint.streams.keys().copied().collect();
                for stream_id in streams {
                    if let Some(record) = endpoint.streams.get_mut(&stream_id)
                        && record.outcome == "in_flight"
                    {
                        record.outcome = "endpoint_closed";
                    }
                    finish_stream(endpoint, stream_id)?;
                }
                while let Some(request) = endpoint.pending.pop_front() {
                    endpoint
                        .retired_applications
                        .push((request.resource_id, ResourceRunState::Failed));
                    endpoint.completed.push(application_record(
                        &request,
                        QcsdRequestRole::Application,
                        "endpoint_closed",
                    ));
                }
                return Err(Error::RunAborted(format!(
                    "HTTP/3 endpoint {} closed before accepted run completion: {reason:?}",
                    endpoint.id.0
                )));
            }
            Http3ClientEvent::HeaderReady {
                stream_id,
                headers,
                interim,
                fin,
            } => {
                if interim {
                    continue;
                }
                let mut known_chaff_mismatch = false;
                if let Some(record) = endpoint.streams.get_mut(&stream_id) {
                    record.response_headers = headers
                        .iter()
                        .map(|header| {
                            (
                                header.name().to_owned(),
                                String::from_utf8_lossy(header.value()).into_owned(),
                            )
                        })
                        .collect();
                    record.status =
                        header_u64(&headers, ":status").and_then(|value| value.try_into().ok());
                    record.content_length = header_u64(&headers, "content-length");
                    known_chaff_mismatch = chaff_headers_contradict_qualification(record);
                    if known_chaff_mismatch {
                        record.outcome = "identity_mismatch";
                    }
                    if fin {
                        record.complete = true;
                    }
                }
                if known_chaff_mismatch {
                    finish_stream(endpoint, stream_id)?;
                    return Err(Error::RunAborted(format!(
                        "chaff response headers on stream {} contradict its qualified identity",
                        stream_id.as_u64()
                    )));
                }
                if fin {
                    finish_stream(endpoint, stream_id)?;
                }
            }
            Http3ClientEvent::DataReadable { stream_id } => {
                // A header-only response can queue `DataReadable` alongside a
                // terminal `HeaderReady`; the latter has already retired it.
                if !endpoint.streams.contains_key(&stream_id) {
                    continue;
                }
                let mut buffer = vec![0_u8; 32 * 1024];
                loop {
                    let (read, fin) = endpoint.client.read_data(now, stream_id, &mut buffer)?;
                    let mut too_large = false;
                    if let Some(record) = endpoint.streams.get_mut(&stream_id) {
                        record.bytes = record
                            .bytes
                            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                        if record.role == QcsdRequestRole::Application {
                            too_large = record.bytes > spec.max_response_bytes;
                            if !too_large {
                                record.body.extend_from_slice(&buffer[..read]);
                            }
                        } else if let Some(expected) = &record.expected_chaff_response {
                            too_large = record.bytes > expected.body_bytes;
                            if !too_large {
                                record.body.extend_from_slice(&buffer[..read]);
                            }
                        }
                        record.complete |= fin;
                    }
                    if too_large {
                        let chaff_overflow =
                            endpoint.streams.get(&stream_id).is_some_and(|record| {
                                matches!(record.role, QcsdRequestRole::Chaff { .. })
                            });
                        if !fin {
                            endpoint.client.cancel_fetch(stream_id, 0)?;
                        }
                        traces.event(
                            now,
                            Some(endpoint.id),
                            "response_limit",
                            "canceled",
                            &stream_id.as_u64(),
                        )?;
                        if let Some(record) = endpoint.streams.get_mut(&stream_id) {
                            record.outcome = "response_limit";
                        }
                        finish_stream(endpoint, stream_id)?;
                        if chaff_overflow {
                            return Err(Error::RunAborted(format!(
                                "chaff response on stream {} exceeded its qualified body length",
                                stream_id.as_u64()
                            )));
                        }
                        break;
                    }
                    if fin {
                        finish_stream(endpoint, stream_id)?;
                        break;
                    }
                    if read == 0 {
                        break;
                    }
                }
            }
            Http3ClientEvent::Reset { stream_id, .. } => {
                if let Some(record) = endpoint.streams.get_mut(&stream_id)
                    && record.outcome == "in_flight"
                {
                    record.outcome = "reset";
                }
                finish_stream(endpoint, stream_id)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn finish_stream(endpoint: &mut Endpoint, stream_id: StreamId) -> Result<(), Error> {
    if let Some(mut record) = endpoint.streams.remove(&stream_id) {
        let mut result = Ok(());
        if record.role == QcsdRequestRole::Application {
            let state = finish_application_record(&mut record);
            endpoint
                .retired_applications
                .push((record.resource_id, state));
        }
        if matches!(record.role, QcsdRequestRole::Chaff { .. }) {
            result = finish_chaff_record(&mut record, stream_id);
        }
        endpoint.completed.push(record);
        result?;
    }
    Ok(())
}

fn finish_chaff_record(record: &mut StreamRecord, stream_id: StreamId) -> Result<(), Error> {
    if record.complete && record.outcome == "in_flight" {
        let verified = chaff_response_result(record)?.identity_verified == Some(true);
        if verified {
            record.outcome = "succeeded";
        } else {
            record.outcome = "identity_mismatch";
            return Err(Error::RunAborted(format!(
                "completed chaff response on stream {} did not match its qualified identity",
                stream_id.as_u64()
            )));
        }
    } else if record.outcome == "in_flight" {
        record.outcome = "incomplete";
    }
    Ok(())
}

fn response_content_encoding(headers: &[(String, String)]) -> Option<String> {
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, value)| value.as_str())
        .collect();
    if values.len() > 1 {
        return None;
    }
    normalize_content_encoding(values.first().copied())
}

fn chaff_headers_contradict_qualification(record: &StreamRecord) -> bool {
    let Some(expected) = record.expected_chaff_response.as_ref() else {
        return matches!(record.role, QcsdRequestRole::Chaff { .. });
    };
    matches!(record.role, QcsdRequestRole::Chaff { .. })
        && (record.status != Some(expected.status)
            || response_content_encoding(&record.response_headers).as_deref()
                != Some(expected.content_encoding.as_str()))
}

fn chaff_response_result(record: &StreamRecord) -> Result<ChaffResponseResult, Error> {
    let QcsdRequestRole::Chaff { request_id, .. } = record.role else {
        return Err(Error::SlotInvariant(
            "application stream cannot produce a chaff response receipt".into(),
        ));
    };
    let expected = record.expected_chaff_response.as_ref();
    let status = record.complete.then_some(record.status).flatten();
    let encoding = (record.complete && !record.response_headers.is_empty())
        .then(|| response_content_encoding(&record.response_headers))
        .flatten();
    let body_fully_retained = u64::try_from(record.body.len()).ok() == Some(record.bytes);
    let body_sha256 = (record.complete && body_fully_retained)
        .then(|| sha256(&record.body))
        .transpose()?;
    let (status_match, encoding_match, bytes_match, hash_match, verified) = if record.complete {
        let status_match = expected.is_some_and(|expected| record.status == Some(expected.status));
        let encoding_match = expected.is_some_and(|expected| {
            encoding.as_deref() == Some(expected.content_encoding.as_str())
        });
        let bytes_match = expected.is_some_and(|expected| record.bytes == expected.body_bytes);
        let hash_match = expected
            .is_some_and(|expected| body_sha256.as_deref() == Some(expected.body_sha256.as_str()));
        (
            Some(status_match),
            Some(encoding_match),
            Some(bytes_match),
            Some(hash_match),
            Some(status_match && encoding_match && bytes_match && hash_match),
        )
    } else {
        (None, None, None, None, None)
    };
    Ok(ChaffResponseResult {
        resource_id: record.resource_id,
        request_id: request_id.map(|id| id.0),
        url: record.url.clone(),
        request_headers: record.request_headers.clone(),
        request_stream_bytes: record.request_stream_bytes,
        expected_request_stream_bytes: record.expected_request_stream_bytes,
        response_headers: record.response_headers.clone(),
        status,
        content_encoding: encoding,
        bytes: record.bytes,
        body_sha256,
        complete: record.complete,
        status_match,
        content_encoding_match: encoding_match,
        body_bytes_match: bytes_match,
        body_sha256_match: hash_match,
        identity_verified: verified,
        outcome: record.outcome,
    })
}

fn finish_application_record(record: &mut StreamRecord) -> ResourceRunState {
    let succeeded = record.complete
        && record
            .status
            .is_some_and(|status| (200..300).contains(&status));
    if succeeded {
        record.outcome = "succeeded";
        ResourceRunState::Succeeded
    } else {
        if record.outcome == "in_flight" {
            record.outcome = "failed";
        }
        ResourceRunState::Failed
    }
}

fn header_u64(headers: &[Header], name: &str) -> Option<u64> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .and_then(|header| header.value_utf8().ok())
        .and_then(|value| value.parse().ok())
}

fn sanitize_chaff_action_headers(action: &mut QcsdAction) {
    if let QcsdAction::RequestChaff { resource, .. } = action {
        // Sanitize before cloning the action so the adapter, action event, and
        // response receipt all describe the same frozen request headers.
        resource.headers = sanitize_chaff_headers(mem::take(&mut resource.headers));
    }
}

const fn action_endpoint(action: &QcsdAction) -> Option<QcsdEndpointId> {
    match action {
        QcsdAction::ConfigureManualReceive { endpoint, .. }
        | QcsdAction::ConfigureAutomaticReceive { endpoint, .. }
        | QcsdAction::IncreaseReceiveLimit { endpoint, .. }
        | QcsdAction::LeaseParserReceive { endpoint, .. }
        | QcsdAction::SendPacket { endpoint, .. }
        | QcsdAction::RequestChaff { endpoint, .. }
        | QcsdAction::CancelChaff { endpoint, .. }
        | QcsdAction::ReleaseChaffSendShaping { endpoint } => Some(*endpoint),
        QcsdAction::SlotMissed { endpoint, .. } | QcsdAction::SlotSatisfied { endpoint, .. } => {
            *endpoint
        }
        QcsdAction::DefenseComplete => None,
    }
}

fn handle_qcsd_observations(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    defense_elapsed: Duration,
) -> Result<(), Error> {
    let observations = endpoint.client.qcsd_timestamped_observations();
    for observation in observations {
        record_qcsd_observation(endpoint, traces, &observation)?;
        controller.observe(observation.into_observation(), defense_elapsed);
    }
    Ok(())
}

fn handle_all_qcsd_observations(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    defense_elapsed: Duration,
) -> Result<(), Error> {
    for (endpoint_index, observation) in take_all_qcsd_observations(endpoints) {
        record_qcsd_observation(&mut endpoints[endpoint_index], traces, &observation)?;
        controller.observe(observation.into_observation(), defense_elapsed);
    }
    Ok(())
}

fn take_all_qcsd_observations(
    endpoints: &mut [Endpoint],
) -> Vec<(usize, TimestampedQcsdObservation)> {
    let mut observations = endpoints
        .iter_mut()
        .enumerate()
        .flat_map(|(endpoint_index, endpoint)| {
            endpoint
                .client
                .qcsd_timestamped_observations()
                .into_iter()
                .map(move |observation| (endpoint_index, observation))
        })
        .collect::<Vec<_>>();
    observations.sort_by_key(|(_, observation)| observation.sequence());
    observations
}

fn forward_qcsd_observation(
    controller: &mut QcsdController,
    observation: TimestampedQcsdObservation,
    defense_elapsed: Option<Duration>,
) {
    if defense_elapsed.is_some()
        || !matches!(
            observation.observation(),
            QcsdObservation::ClassifiedDatagram { .. }
        )
    {
        controller.observe(
            observation.into_observation(),
            defense_elapsed.unwrap_or(Duration::ZERO),
        );
    }
}

fn handle_defense_activation_observations(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
) -> Result<(), Error> {
    for (endpoint_index, observation) in take_all_qcsd_observations(endpoints) {
        record_qcsd_observation(&mut endpoints[endpoint_index], traces, &observation)?;
        forward_qcsd_observation(controller, observation, None);
    }
    Ok(())
}

fn satisfied_datagrams_for(
    endpoint: &Endpoint,
    observations: &[TimestampedQcsdObservation],
) -> Result<Vec<SatisfiedDatagram>, Error> {
    let mut scheduled_slots: BTreeSet<_> = endpoint
        .scheduled_outgoing
        .iter()
        .map(|scheduled| scheduled.slot)
        .collect();
    observations
        .iter()
        .filter_map(|record| {
            let observation = record.observation();
            let (slot, observed_size, status, qcsd) = match observation {
                QcsdObservation::SlotSatisfied {
                    slot,
                    observed_size,
                    ..
                } => {
                    let desired = endpoint
                        .scheduled_outgoing
                        .iter()
                        .find(|scheduled| scheduled.slot == *slot)
                        .map_or(*observed_size, |scheduled| scheduled.packet.length());
                    (
                        *slot,
                        *observed_size,
                        "satisfied",
                        QcsdTraceColumns::exact(desired, Some(*observed_size)),
                    )
                }
                QcsdObservation::SlotResolved {
                    slot,
                    packet,
                    outcome,
                    ..
                } => match outcome {
                    QcsdSlotOutcome::Full { composition } => (
                        *slot,
                        composition.observed_udp_bytes,
                        "full",
                        QcsdTraceColumns::from_outcome(*packet, *outcome),
                    ),
                    QcsdSlotOutcome::Partial { composition, .. } => (
                        *slot,
                        composition.observed_udp_bytes,
                        "partial",
                        QcsdTraceColumns::from_outcome(*packet, *outcome),
                    ),
                    QcsdSlotOutcome::Suppressed { .. } => return None,
                },
                _ => return None,
            };
            Some(if scheduled_slots.remove(&slot) {
                endpoint
                    .scheduled_outgoing
                    .iter()
                    .find(|scheduled| scheduled.slot == slot)
                    .map_or_else(
                        || {
                            Err(Error::SlotInvariant(format!(
                                "transport satisfied outgoing slot {} without a handoff deadline",
                                slot.0
                            )))
                        },
                        |scheduled| {
                            Ok(SatisfiedDatagram {
                                slot,
                                observed_size: usize::from(observed_size),
                                status,
                                qcsd,
                                deadline: scheduled.deadline,
                            })
                        },
                    )
            } else {
                Err(Error::SlotInvariant(format!(
                    "transport satisfied unknown outgoing slot {}",
                    slot.0
                )))
            })
        })
        .collect()
}

fn built_outgoing_datagrams_for(
    observations: &[TimestampedQcsdObservation],
) -> Vec<(usize, QcsdSlotComposition)> {
    observations
        .iter()
        .filter_map(|record| match record.observation() {
            QcsdObservation::ClassifiedDatagram {
                direction: Direction::Outgoing,
                length,
                composition: Some(composition),
                ..
            } => Some((usize::from(*length), *composition)),
            _ => None,
        })
        .collect()
}

#[expect(
    clippy::too_many_lines,
    reason = "one reducer atomically terminalizes every typed slot observation"
)]
fn record_qcsd_observation(
    endpoint: &mut Endpoint,
    traces: &mut TraceFiles,
    record: &TimestampedQcsdObservation,
) -> Result<(), Error> {
    let observation = record.observation();
    match observation {
        QcsdObservation::SlotSatisfied {
            slot,
            observed_size,
            ..
        } => {
            let Some(index) = endpoint
                .scheduled_outgoing
                .iter()
                .position(|scheduled| scheduled.slot == *slot)
            else {
                return Err(Error::SlotInvariant(format!(
                    "transport satisfied unknown outgoing slot {}",
                    slot.0
                )));
            };
            let scheduled = endpoint
                .scheduled_outgoing
                .remove(index)
                .expect("located outgoing slot");
            traces.schedule(&ScheduleTraceRow {
                action_time_us: record.produced_monotonic_ns() / 1_000,
                endpoint: Some(endpoint.id),
                packet: scheduled.packet,
                satisfaction: "satisfied",
                observed: Some(usize::from(*observed_size)),
                miss_reason: "",
                slot: scheduled.slot,
                qcsd: QcsdTraceColumns::exact(scheduled.packet.length(), Some(*observed_size)),
            })?;
        }
        QcsdObservation::SlotMissed {
            slot,
            reason,
            packet,
            ..
        } => {
            let scheduled = endpoint
                .scheduled_outgoing
                .iter()
                .position(|scheduled| scheduled.slot == *slot)
                .and_then(|index| endpoint.scheduled_outgoing.remove(index));
            let scheduled_packet = scheduled.map_or(*packet, |value| value.packet);
            let miss_reason = format!("{reason:?}");
            traces.schedule(&ScheduleTraceRow {
                action_time_us: record.produced_monotonic_ns() / 1_000,
                endpoint: Some(endpoint.id),
                packet: scheduled_packet,
                satisfaction: "missed",
                observed: None,
                miss_reason: &miss_reason,
                slot: *slot,
                qcsd: QcsdTraceColumns::default(),
            })?;
        }
        QcsdObservation::SlotResolved {
            slot,
            packet,
            outcome,
            ..
        } => {
            let scheduled = endpoint
                .scheduled_outgoing
                .iter()
                .position(|scheduled| scheduled.slot == *slot)
                .and_then(|index| endpoint.scheduled_outgoing.remove(index));
            let scheduled_packet = scheduled.map_or(*packet, |value| value.packet);
            let (satisfaction, observed, miss_reason) = match outcome {
                QcsdSlotOutcome::Full { composition } => (
                    "full",
                    Some(usize::from(composition.observed_udp_bytes)),
                    String::new(),
                ),
                QcsdSlotOutcome::Partial {
                    composition,
                    reason,
                } => (
                    "partial",
                    Some(usize::from(composition.observed_udp_bytes)),
                    format!("{reason:?}"),
                ),
                QcsdSlotOutcome::Suppressed { reason, .. } => {
                    ("suppressed", None, format!("{reason:?}"))
                }
            };
            traces.schedule(&ScheduleTraceRow {
                action_time_us: record.produced_monotonic_ns() / 1_000,
                endpoint: Some(endpoint.id),
                packet: scheduled_packet,
                satisfaction,
                observed,
                miss_reason: &miss_reason,
                slot: *slot,
                qcsd: QcsdTraceColumns::from_outcome(scheduled_packet, *outcome),
            })?;
        }
        _ => {}
    }
    traces.observation(Some(endpoint.id), record)?;
    Ok(())
}

fn record_terminal_action(
    traces: &mut TraceFiles,
    now: Instant,
    action_time_us: u64,
    event_outcome: &str,
    action: &QcsdAction,
) -> Result<bool, Error> {
    let (endpoint, packet, satisfaction, miss_reason, slot) = match action {
        QcsdAction::SlotMissed {
            endpoint,
            packet,
            slot,
            reason,
        } => (*endpoint, *packet, "missed", format!("{reason:?}"), *slot),
        QcsdAction::SlotSatisfied {
            endpoint,
            packet,
            slot,
        } => (*endpoint, *packet, "satisfied", String::new(), *slot),
        _ => return Ok(false),
    };
    traces.schedule(&ScheduleTraceRow {
        action_time_us,
        endpoint,
        packet,
        satisfaction,
        observed: None,
        miss_reason: &miss_reason,
        slot,
        qcsd: QcsdTraceColumns::exact(packet.length(), None),
    })?;
    traces.event(now, endpoint, "action", event_outcome, action)?;
    Ok(true)
}

fn terminalize_pending_slots(
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    reason: MissedSlotReason,
) -> Result<(), Error> {
    record_queued_terminal_actions(controller, traces, now)?;
    controller.abort_pending_slots(defense_elapsed, reason);
    record_queued_terminal_actions(controller, traces, now)?;

    let mut pending = BTreeMap::new();
    let terminal_time_us = traces.elapsed_us(now);
    for (slot, packet) in controller.pending_slots() {
        pending.insert(slot, (packet, None, terminal_time_us));
    }
    for (slot, trace_pending) in traces.pending_slots() {
        if let Some((packet, _, _)) = pending.get(&slot)
            && *packet != trace_pending.packet
        {
            return Err(Error::SlotInvariant(format!(
                "slot {} has different controller and trace packets",
                slot.0
            )));
        }
        pending.insert(
            slot,
            (
                trace_pending.packet,
                Some(trace_pending.endpoint),
                trace_pending.action_time_us,
            ),
        );
    }

    for (slot, (packet, endpoint, action_time_us)) in pending {
        if traces.is_slot_terminal(slot) {
            continue;
        }
        let action = QcsdAction::SlotMissed {
            endpoint,
            packet,
            slot,
            reason,
        };
        record_terminal_action(traces, now, action_time_us, "terminalized_run_end", &action)?;
    }
    Ok(())
}

fn record_queued_terminal_actions(
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
) -> Result<(), Error> {
    for action in controller.drain_actions() {
        let terminal_slot = match &action {
            QcsdAction::SlotMissed { slot, .. } | QcsdAction::SlotSatisfied { slot, .. } => {
                Some(*slot)
            }
            _ => None,
        };
        if terminal_slot.is_some_and(|slot| traces.is_slot_terminal(slot)) {
            continue;
        }
        let action_time_us = traces.elapsed_us(now);
        record_terminal_action(traces, now, action_time_us, "terminalized_queued", &action)?;
    }
    Ok(())
}

const fn scheduled_action(action: &QcsdAction) -> Option<(QcsdEndpointId, Packet, QcsdSlotId)> {
    match action {
        QcsdAction::SendPacket {
            endpoint,
            packet,
            slot,
            ..
        }
        | QcsdAction::IncreaseReceiveLimit {
            endpoint,
            packet,
            slot,
            ..
        } => Some((*endpoint, *packet, *slot)),
        QcsdAction::LeaseParserReceive {
            endpoint,
            owner: Some(owner),
            ..
        } => Some((*endpoint, owner.packet, owner.slot)),
        _ => None,
    }
}

fn register_action_batch(
    traces: &mut TraceFiles,
    now: Instant,
    actions: &[QcsdAction],
) -> Result<BTreeSet<QcsdSlotId>, Error> {
    let mut registered_slots = BTreeMap::new();
    let mut incoming_fanout_slots = BTreeSet::new();
    for action in actions {
        let Some((endpoint, packet, slot)) = scheduled_action(action) else {
            continue;
        };
        let incoming_action = match action {
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit,
                ..
            }
            | QcsdAction::LeaseParserReceive {
                endpoint,
                stream,
                absolute_limit,
                owner: Some(_),
                ..
            } => Some((*endpoint, *stream, *absolute_limit)),
            QcsdAction::SendPacket { .. } => None,
            _ => unreachable!("scheduled_action returned an unscheduled action"),
        };
        if let std::collections::btree_map::Entry::Vacant(entry) = registered_slots.entry(slot) {
            entry.insert(incoming_action.is_some());
        } else {
            let primary_is_incoming = registered_slots.get(&slot).copied().unwrap_or(false);
            if !primary_is_incoming || incoming_action.is_none() {
                return Err(Error::SlotInvariant(format!(
                    "slot {} was reused outside an incoming receive-credit fan-out",
                    slot.0
                )));
            }
            incoming_fanout_slots.insert(slot);
        }
        if let Some((endpoint, stream, absolute_limit)) = incoming_action {
            traces.register_incoming_action(now, endpoint, stream, absolute_limit, packet, slot)?;
        } else {
            traces.register_slot(now, endpoint, packet, slot)?;
        }
    }
    Ok(incoming_fanout_slots)
}

#[derive(Debug)]
struct ReceiveBatchPreflight {
    expected: Vec<Option<QcsdReceiveLimitOutcome>>,
    rejected_streams: BTreeMap<(QcsdEndpointId, neqo_csdef::QcsdStreamId), QcsdReceiveLimitOutcome>,
}

const fn receive_action_target(
    action: &QcsdAction,
) -> Option<(QcsdEndpointId, neqo_csdef::QcsdStreamId, u64)> {
    match action {
        QcsdAction::ConfigureManualReceive {
            endpoint,
            stream,
            initial_limit,
        } => Some((*endpoint, *stream, *initial_limit)),
        QcsdAction::ConfigureAutomaticReceive {
            endpoint,
            stream,
            window,
        } => Some((*endpoint, *stream, *window)),
        QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit,
            ..
        }
        | QcsdAction::LeaseParserReceive {
            endpoint,
            stream,
            absolute_limit,
            ..
        } => Some((*endpoint, *stream, *absolute_limit)),
        _ => None,
    }
}

const fn receive_action_requires_controller_ledger(action: &QcsdAction) -> bool {
    matches!(
        action,
        QcsdAction::ConfigureManualReceive { .. }
            | QcsdAction::IncreaseReceiveLimit { .. }
            | QcsdAction::LeaseParserReceive { .. }
    )
}

const fn receive_limit_outcome_name(outcome: QcsdReceiveLimitOutcome) -> &'static str {
    match outcome {
        QcsdReceiveLimitOutcome::Applied => "applied",
        QcsdReceiveLimitOutcome::FinalKnown => "final_known",
        QcsdReceiveLimitOutcome::Terminal => "terminal",
        QcsdReceiveLimitOutcome::Gone => "gone",
    }
}

const fn receive_limit_fatal_name(fatal: QcsdReceiveLimitFatal) -> &'static str {
    match fatal {
        QcsdReceiveLimitFatal::WouldRevoke => "would_revoke",
        QcsdReceiveLimitFatal::Order => "order",
        QcsdReceiveLimitFatal::Ledger => "ledger",
    }
}

fn record_receive_limit_error(
    traces: &mut TraceFiles,
    now: Instant,
    action: &QcsdAction,
    phase: &str,
    error: QcsdReceiveLimitError,
) -> Result<(), Error> {
    let outcome = format!(
        "failed_receive_{phase}_{}",
        receive_limit_fatal_name(error.kind)
    );
    traces.event(now, action_endpoint(action), "action", &outcome, action)?;
    traces.event(now, action_endpoint(action), "action_error", phase, &error)?;
    Ok(())
}

fn record_adapter_action_error(
    traces: &mut TraceFiles,
    now: Instant,
    action: &QcsdAction,
    error: &neqo_http3::Error,
) -> Result<(), Error> {
    traces.event(now, action_endpoint(action), "action", "failed", action)?;
    traces.event(
        now,
        action_endpoint(action),
        "action_error",
        "adapter",
        &json!({ "error": error.to_string() }),
    )?;
    Ok(())
}

fn preflight_receive_actions_with(
    actions: &[QcsdAction],
    mut preview: impl FnMut(
        usize,
        &QcsdAction,
        Option<u64>,
    ) -> Result<Option<QcsdReceiveLimitOutcome>, QcsdReceiveLimitError>,
) -> Result<ReceiveBatchPreflight, (usize, QcsdReceiveLimitError)> {
    let mut expected = vec![None; actions.len()];
    let mut virtual_high_water = BTreeMap::new();
    let mut rejected_streams = BTreeMap::new();
    for (index, action) in actions.iter().enumerate() {
        let Some((endpoint, stream, absolute_limit)) = receive_action_target(action) else {
            continue;
        };
        let key = (endpoint, stream);
        if let Some(outcome) = rejected_streams.get(&key).copied() {
            expected[index] = Some(outcome);
            continue;
        }
        let Some(outcome) = preview(index, action, virtual_high_water.get(&key).copied())
            .map_err(|error| (index, error))?
        else {
            // A missing endpoint is handled by the established EndpointClosed
            // dispatch path. It has no transport state to preflight.
            continue;
        };
        expected[index] = Some(outcome);
        match outcome {
            QcsdReceiveLimitOutcome::Applied => {
                virtual_high_water.insert(key, absolute_limit);
            }
            QcsdReceiveLimitOutcome::FinalKnown
            | QcsdReceiveLimitOutcome::Terminal
            | QcsdReceiveLimitOutcome::Gone => {
                rejected_streams.insert(key, outcome);
            }
        }
    }
    Ok(ReceiveBatchPreflight {
        expected,
        rejected_streams,
    })
}

fn preflight_receive_action_batch(
    endpoints: &[Endpoint],
    traces: &mut TraceFiles,
    now: Instant,
    actions: &[QcsdAction],
) -> Result<ReceiveBatchPreflight, Error> {
    match preflight_receive_actions_with(actions, |_, action, virtual_high_water| {
        let (endpoint_id, _, absolute_limit) =
            receive_action_target(action).ok_or(QcsdReceiveLimitError {
                kind: QcsdReceiveLimitFatal::Ledger,
                requested_limit: 0,
                reference_limit: 0,
            })?;
        let Some(endpoint) = endpoints
            .iter()
            .find(|candidate| candidate.id == endpoint_id)
        else {
            // Existing missing-endpoint dispatch produces the exact
            // EndpointClosed slot outcome and controller rollback.
            return Ok(None);
        };
        match endpoint
            .client
            .preview_qcsd_receive_action(action, virtual_high_water)
        {
            Ok(Some(outcome)) => Ok(Some(outcome)),
            Ok(None) => Err(QcsdReceiveLimitError {
                kind: QcsdReceiveLimitFatal::Ledger,
                requested_limit: absolute_limit,
                reference_limit: 0,
            }),
            Err(error) => Err(error),
        }
    }) {
        Ok(preflight) => Ok(preflight),
        Err((index, error)) => {
            record_receive_limit_error(traces, now, &actions[index], "preflight", error)?;
            Err(error.into())
        }
    }
}

fn pending_receive_identity_is_reconciled(
    identity: &QcsdReceiveActionIdentity,
    restored_limits: &[(QcsdEndpointId, neqo_csdef::QcsdStreamId, u64)],
    canceled: &[QcsdReceiveActionIdentity],
    retained: &[QcsdReceiveActionIdentity],
) -> bool {
    let Some((_, _, cutoff)) = restored_limits
        .iter()
        .find(|candidate| candidate.0 == identity.endpoint() && candidate.1 == identity.stream())
    else {
        return true;
    };
    if identity.absolute_limit() > *cutoff {
        canceled.contains(identity)
    } else {
        retained.contains(identity) && !canceled.contains(identity)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "global observation flush, three-ledger bijection, adapter preview, and atomic multi-stream commit form one audited transaction"
)]
fn cancel_rejected_receive_streams(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    actions: &[QcsdAction],
    rejected_streams: &BTreeMap<
        (QcsdEndpointId, neqo_csdef::QcsdStreamId),
        QcsdReceiveLimitOutcome,
    >,
) -> Result<BTreeMap<usize, QcsdReceiveLimitOutcome>, Error> {
    if rejected_streams.is_empty() {
        return Ok(BTreeMap::new());
    }

    // Preserve the transport-wide production order of FIN, BytesRead, and
    // MAX_STREAM_DATA encoding observations before consulting controller
    // ownership.  A queued advertisement must cease to be cancelable first.
    handle_all_qcsd_observations(endpoints, controller, traces, defense_elapsed)?;
    controller.flush_defense_observations();
    ensure_defense_realizable(controller)?;

    let ledger_rejected_streams: BTreeSet<_> = rejected_streams
        .keys()
        .copied()
        .filter(|&(endpoint, stream)| {
            actions.iter().any(|action| {
                receive_action_requires_controller_ledger(action)
                    && receive_action_target(action).is_some_and(
                        |(candidate, candidate_stream, _)| {
                            candidate == endpoint && candidate_stream == stream
                        },
                    )
            })
        })
        .collect();
    if ledger_rejected_streams.is_empty() {
        let mut canceled_indices = BTreeMap::new();
        for (index, action) in actions.iter().enumerate() {
            if let Some((endpoint, stream, _)) = receive_action_target(action)
                && let Some(outcome) = rejected_streams.get(&(endpoint, stream)).copied()
            {
                canceled_indices.insert(index, outcome);
            }
        }
        for (&(endpoint, stream), &outcome) in rejected_streams {
            traces.event(
                now,
                Some(endpoint),
                "receive_cancellation",
                receive_limit_outcome_name(outcome),
                &json!({
                    "stream": stream.0,
                    "drained_indices": canceled_indices
                        .keys()
                        .copied()
                        .filter(|index| receive_action_target(&actions[*index])
                            .is_some_and(|(candidate, candidate_stream, _)|
                                candidate == endpoint && candidate_stream == stream))
                        .collect::<Vec<_>>(),
                    "canceled_slots": Vec::<u64>::new(),
                    "canceled_actions": Vec::<String>::new(),
                }),
            )?;
        }
        handle_all_qcsd_observations(endpoints, controller, traces, defense_elapsed)?;
        controller.flush_defense_observations();
        ensure_defense_realizable(controller)?;
        return Ok(canceled_indices);
    }

    let rejections: Vec<_> = rejected_streams
        .keys()
        .filter(|key| ledger_rejected_streams.contains(key))
        .map(|&(endpoint, stream)| {
            let roots = actions
                .iter()
                .filter_map(QcsdAction::receive_identity)
                .filter(|identity| identity.endpoint() == endpoint && identity.stream() == stream)
                .collect();
            (endpoint, stream, roots)
        })
        .collect();
    let plan = controller.plan_receive_streams_unavailable(&rejections)?;

    let mut current = Vec::new();
    for (index, action) in actions.iter().enumerate() {
        let Some(identity) = action.receive_identity() else {
            continue;
        };
        if current
            .iter()
            .any(|(other, _): &(QcsdReceiveActionIdentity, usize)| *other == identity)
        {
            return Err(Error::SlotInvariant(format!(
                "duplicate drained receive identity {identity:?}"
            )));
        }
        current.push((identity, index));
    }
    let mut pending = Vec::new();
    for endpoint in endpoints.iter() {
        for identity in endpoint.client.qcsd_pending_receive_action_identities() {
            if identity.endpoint() != endpoint.id {
                return Err(Error::SlotInvariant(format!(
                    "adapter {} reported cross-endpoint pending identity {identity:?}",
                    endpoint.id.0
                )));
            }
            if pending.contains(&identity) || current.iter().any(|(other, _)| *other == identity) {
                return Err(Error::SlotInvariant(format!(
                    "pending receive identity is duplicate or not disjoint: {identity:?}"
                )));
            }
            pending.push(identity);
        }
    }
    let queued = controller.queued_receive_action_identities();
    for (index, identity) in queued.iter().enumerate() {
        if queued[..index].contains(identity)
            || current.iter().any(|(candidate, _)| candidate == identity)
            || pending.contains(identity)
        {
            return Err(Error::SlotInvariant(format!(
                "queued receive identity is duplicate or not disjoint: {identity:?}"
            )));
        }
    }

    for identity in plan.canceled_actions() {
        let current_matches = current
            .iter()
            .filter(|(candidate, _)| candidate == identity)
            .count();
        let pending_matches = pending
            .iter()
            .filter(|candidate| *candidate == identity)
            .count();
        let queued_matches = queued
            .iter()
            .filter(|candidate| *candidate == identity)
            .count();
        if current_matches + pending_matches + queued_matches != 1 {
            return Err(Error::SlotInvariant(format!(
                "planned receive cancellation {identity:?} matched {current_matches} drained, {pending_matches} pending, and {queued_matches} queued actions"
            )));
        }
    }
    for identity in plan.retained_actions() {
        let matches = current
            .iter()
            .filter(|(candidate, _)| candidate == identity)
            .count()
            + pending
                .iter()
                .filter(|candidate| *candidate == identity)
                .count()
            + queued
                .iter()
                .filter(|candidate| *candidate == identity)
                .count();
        if matches != 1 {
            return Err(Error::SlotInvariant(format!(
                "retained controller receive identity {identity:?} matched {matches} runner/adapter identities"
            )));
        }
    }
    for (identity, _) in &current {
        if rejected_streams.contains_key(&(identity.endpoint(), identity.stream()))
            && !plan.canceled_actions().contains(identity)
        {
            return Err(Error::SlotInvariant(format!(
                "receive cancellation omitted drained rejected identity {identity:?}"
            )));
        }
    }
    for identity in current
        .iter()
        .map(|(identity, _)| identity)
        .chain(pending.iter())
        .chain(queued.iter())
    {
        if !pending_receive_identity_is_reconciled(
            identity,
            plan.restored_limits(),
            plan.canceled_actions(),
            plan.retained_actions(),
        ) {
            return Err(Error::SlotInvariant(format!(
                "controller plan misclassified runner/adapter identity around rollback cutoff: {identity:?}"
            )));
        }
    }

    let mut pending_by_endpoint: BTreeMap<QcsdEndpointId, Vec<QcsdReceiveActionIdentity>> =
        BTreeMap::new();
    for identity in plan.canceled_actions() {
        if pending.contains(identity) {
            pending_by_endpoint
                .entry(identity.endpoint())
                .or_default()
                .push(*identity);
        }
    }
    // Preview every adapter, including the last endpoint, before any commit.
    let mut adapter_boundaries = Vec::new();
    for (endpoint_id, identities) in &pending_by_endpoint {
        let endpoint = endpoints
            .iter()
            .find(|candidate| candidate.id == *endpoint_id)
            .ok_or_else(|| {
                Error::SlotInvariant(format!(
                    "receive cancellation lost pending endpoint {}",
                    endpoint_id.0
                ))
            })?;
        endpoint
            .client
            .preview_qcsd_receive_action_cancellation(identities)?;
        adapter_boundaries.extend(
            endpoint
                .client
                .qcsd_receive_action_cancellation_boundaries(identities)?,
        );
    }
    for (index, boundary) in adapter_boundaries.iter().enumerate() {
        if adapter_boundaries[..index]
            .iter()
            .any(|candidate| candidate.0 == boundary.0 && candidate.1 == boundary.1)
        {
            return Err(Error::SlotInvariant(format!(
                "adapter receive rollback repeated boundary {}:{}",
                boundary.0.0, boundary.1.0
            )));
        }
        let matches: Vec<_> = plan
            .restored_limits()
            .iter()
            .filter(|candidate| candidate.0 == boundary.0 && candidate.1 == boundary.1)
            .collect();
        if matches.len() != 1 || matches[0].2 != boundary.2 {
            return Err(Error::SlotInvariant(format!(
                "adapter/controller receive rollback boundary diverged on {}:{}: adapter {}, controller {:?}",
                boundary.0.0,
                boundary.1.0,
                boundary.2,
                matches
                    .iter()
                    .map(|candidate| candidate.2)
                    .collect::<Vec<_>>()
            )));
        }
    }

    let mut canceled_indices = BTreeMap::new();
    let fallback_outcome = *rejected_streams
        .values()
        .next()
        .expect("nonempty rejected streams checked above");
    for (identity, index) in &current {
        if plan.canceled_actions().contains(identity) {
            let outcome = rejected_streams
                .get(&(identity.endpoint(), identity.stream()))
                .copied()
                .unwrap_or(fallback_outcome);
            if canceled_indices.insert(*index, outcome).is_some() {
                return Err(Error::SlotInvariant(format!(
                    "drained receive action {index} was canceled more than once"
                )));
            }
        }
    }
    for (index, action) in actions.iter().enumerate() {
        let Some((endpoint, stream, _)) = receive_action_target(action) else {
            continue;
        };
        if action.receive_identity().is_none()
            && let Some(outcome) = rejected_streams.get(&(endpoint, stream)).copied()
            && canceled_indices.insert(index, outcome).is_some()
        {
            return Err(Error::SlotInvariant(format!(
                "drained receive configuration {index} was canceled more than once"
            )));
        }
    }

    for (endpoint_id, identities) in &pending_by_endpoint {
        let endpoint = endpoints
            .iter_mut()
            .find(|candidate| candidate.id == *endpoint_id)
            .expect("pending endpoint survived pure validation");
        endpoint
            .client
            .commit_qcsd_receive_action_cancellation(identities)?;
    }
    let cancellation = controller.commit_receive_streams_unavailable(&plan, defense_elapsed)?;

    for (&(endpoint, stream), &outcome) in rejected_streams {
        let mut drained_indices: Vec<_> = canceled_indices
            .keys()
            .copied()
            .filter(|index| {
                receive_action_target(&actions[*index]).is_some_and(
                    |(candidate, candidate_stream, _)| {
                        candidate == endpoint && candidate_stream == stream
                    },
                )
            })
            .collect();
        drained_indices.sort_unstable();
        traces.event(
            now,
            Some(endpoint),
            "receive_cancellation",
            receive_limit_outcome_name(outcome),
            &json!({
                "stream": stream.0,
                "drained_indices": drained_indices,
                "canceled_slots": cancellation
                    .canceled_slots()
                    .iter()
                    .map(|slot| slot.0)
                    .collect::<Vec<_>>(),
                "canceled_actions": cancellation
                    .canceled_actions()
                    .iter()
                    .map(|identity| format!("{identity:?}"))
                    .collect::<Vec<_>>(),
            }),
        )?;
    }

    // Cancellation and terminal observations are a reducer barrier: no later,
    // unrelated action may reach an adapter before global ordered delivery.
    handle_all_qcsd_observations(endpoints, controller, traces, defense_elapsed)?;
    controller.flush_defense_observations();
    ensure_defense_realizable(controller)?;
    Ok(canceled_indices)
}

fn apply_action_batch(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    actions: Vec<QcsdAction>,
) -> Result<(), Error> {
    let incoming_fanout_slots = register_action_batch(traces, now, &actions)?;
    let preflight = preflight_receive_action_batch(endpoints, traces, now, &actions)?;
    let canceled_indices = cancel_rejected_receive_streams(
        endpoints,
        controller,
        traces,
        now,
        defense_elapsed,
        &actions,
        &preflight.rejected_streams,
    )?;
    for (index, action) in actions.into_iter().enumerate() {
        if let Some(outcome) = canceled_indices.get(&index).copied() {
            let event_outcome = format!("canceled_receive_{}", receive_limit_outcome_name(outcome));
            traces.event(
                now,
                action_endpoint(&action),
                "action",
                &event_outcome,
                &action,
            )?;
            continue;
        }
        let may_skip_terminal_sibling = scheduled_action(&action)
            .is_some_and(|(_, _, slot)| incoming_fanout_slots.contains(&slot));
        apply_action(
            endpoints,
            controller,
            chaff_manifest,
            traces,
            now,
            defense_elapsed,
            action,
            may_skip_terminal_sibling,
            preflight.expected[index],
        )?;
    }
    Ok(())
}

fn apply_queued_actions(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
) -> Result<(), Error> {
    loop {
        // FRONT's frozen schedule is reconciled before every action batch so
        // RequestChaff-created streams can immediately receive any due credit
        // before a prearmed outgoing target is eligible to flush.
        controller.reconcile_due_fixed(defense_elapsed);
        let actions: Vec<_> = controller.drain_actions().collect();
        if actions.is_empty() {
            return Ok(());
        }
        // Actions emitted while this batch is applied remain queued and are
        // pre-registered as a fresh batch on the next iteration.
        apply_action_batch(
            endpoints,
            controller,
            chaff_manifest,
            traces,
            now,
            defense_elapsed,
            actions,
        )?;
    }
}

fn validate_local_et_chaff_target(
    streams: &HashMap<StreamId, StreamRecord>,
    stream: neqo_csdef::QcsdStreamId,
) -> Result<StreamId, Error> {
    let stream_id = StreamId::new(stream.0);
    let Some(record) = streams.get(&stream_id) else {
        return Err(Error::SlotInvariant(format!(
            "local CS-BuFLO termination targeted unknown chaff stream {}",
            stream.0
        )));
    };
    if !matches!(record.role, QcsdRequestRole::Chaff { .. }) {
        return Err(Error::SlotInvariant(format!(
            "local CS-BuFLO termination targeted application stream {}",
            stream.0
        )));
    }
    Ok(stream_id)
}

/// Validate a local-ET cancellation before touching HTTP/3, then atomically
/// roll back any receive-limit action that transport accepted but has not yet
/// encoded. The controller has already closed this chaff stream and removed
/// the matching unadvertised suffix before it emits `CancelChaff`; leaving the
/// adapter suffix alive would strand terminal defense-control backlog once
/// `STOP_SENDING` moves the transport receive state out of `Recv`.
fn prepare_local_et_chaff_cancellation(
    endpoint: &mut Endpoint,
    traces: &mut TraceFiles,
    now: Instant,
    action: &QcsdAction,
) -> Result<Option<StreamId>, Error> {
    let QcsdAction::CancelChaff { stream, .. } = action else {
        return Ok(None);
    };
    let stream_id = validate_local_et_chaff_target(&endpoint.streams, *stream)?;

    let identities: Vec<QcsdReceiveActionIdentity> = endpoint
        .client
        .qcsd_pending_receive_action_identities()
        .into_iter()
        .filter(|identity| {
            identity.endpoint() == endpoint.id && identity.stream().0 == stream_id.as_u64()
        })
        .collect();
    if !identities.is_empty() {
        endpoint
            .client
            .preview_qcsd_receive_action_cancellation(&identities)?;
        let boundaries = endpoint
            .client
            .qcsd_receive_action_cancellation_boundaries(&identities)?;
        endpoint
            .client
            .commit_qcsd_receive_action_cancellation(&identities)?;
        traces.event(
            now,
            Some(endpoint.id),
            "receive_cancellation",
            "local_et_unencoded_rollback",
            &json!({
                "stream": stream.0,
                "identities": identities
                    .iter()
                    .map(|identity| format!("{identity:?}"))
                    .collect::<Vec<_>>(),
                "restored_boundaries": boundaries
                    .iter()
                    .map(|(_, candidate, limit)| json!({
                        "stream": candidate.0,
                        "absolute_limit": limit,
                    }))
                    .collect::<Vec<_>>(),
            }),
        )?;
    }
    Ok(Some(stream_id))
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "action dispatch records every transport and trace outcome in one exhaustive reducer"
)]
fn apply_action(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    mut action: QcsdAction,
    may_skip_terminal_sibling: bool,
    expected_receive: Option<QcsdReceiveLimitOutcome>,
) -> Result<(), Error> {
    sanitize_chaff_action_headers(&mut action);
    let endpoint_id = action_endpoint(&action);
    let action_time_us = traces.elapsed_us(now);
    if record_terminal_action(traces, now, action_time_us, "recorded", &action)? {
        return Ok(());
    }
    if matches!(&action, QcsdAction::DefenseComplete) {
        traces.event(now, endpoint_id, "action", "recorded", &action)?;
        return Ok(());
    }
    let trace_action = action.clone();
    let scheduled_action = scheduled_action(&trace_action);
    if let Some((_, packet, slot)) = scheduled_action {
        if traces.is_slot_terminal(slot) {
            if !may_skip_terminal_sibling {
                return Err(Error::SlotInvariant(format!(
                    "slot {} action reached dispatch after its terminal state",
                    slot.0
                )));
            }
            debug_assert_eq!(packet.direction(), Direction::Incoming);
            // A logical incoming slot may have several stream-credit actions
            // in the same controller batch. If one sibling fails, its terminal
            // outcome invalidates the rest; applying them would release
            // unaccounted receive credit.
            traces.event(
                now,
                endpoint_id,
                "action",
                "skipped_terminal_slot",
                &trace_action,
            )?;
            return Ok(());
        }
        if !traces.is_slot_pending(slot) {
            return Err(Error::SlotInvariant(format!(
                "slot {} action reached dispatch without batch registration",
                slot.0
            )));
        }
    }
    let Some(endpoint) = endpoints
        .iter_mut()
        .find(|candidate| Some(candidate.id) == endpoint_id)
    else {
        if let Some((endpoint, packet, slot)) = scheduled_action {
            let reason = MissedSlotReason::EndpointClosed;
            controller.observe(
                QcsdObservation::SlotMissed {
                    endpoint,
                    slot,
                    packet,
                    reason,
                },
                defense_elapsed,
            );
            let miss_reason = format!("{reason:?}");
            traces.schedule(&ScheduleTraceRow {
                action_time_us: traces.elapsed_us(now),
                endpoint: Some(endpoint),
                packet,
                satisfaction: "missed",
                observed: None,
                miss_reason: &miss_reason,
                slot,
                qcsd: QcsdTraceColumns::default(),
            })?;
        }
        traces.event(now, endpoint_id, "action", "missing_endpoint", &action)?;
        return Ok(());
    };
    // This is deliberately before `apply_qcsd_action`: a stale or invalid
    // CancelChaff identity must never mutate an application or unknown stream.
    let local_et_stream =
        prepare_local_et_chaff_cancellation(endpoint, traces, now, &trace_action)?;
    let scheduled_packet = match &trace_action {
        QcsdAction::SendPacket {
            packet,
            slot,
            deadline_after_us,
            ..
        } => Some((*packet, *slot, *deadline_after_us)),
        _ => None,
    };
    if let Some((_, _, absolute_limit)) = receive_action_target(&trace_action) {
        let Some(expected) = expected_receive else {
            return Err(Error::SlotInvariant(
                "receive action reached a live endpoint without preflight".into(),
            ));
        };
        if expected != QcsdReceiveLimitOutcome::Applied {
            return Err(Error::SlotInvariant(format!(
                "receive action reached dispatch with non-live {expected:?} preflight"
            )));
        }
        match endpoint.client.apply_qcsd_receive_action(&trace_action) {
            Ok(Some(QcsdReceiveLimitOutcome::Applied)) => {
                traces.event(now, endpoint_id, "action", "applied", &trace_action)?;
                return Ok(());
            }
            Ok(Some(actual)) => {
                traces.event(
                    now,
                    endpoint_id,
                    "action",
                    "failed_receive_apply_mismatch",
                    &trace_action,
                )?;
                traces.event(
                    now,
                    endpoint_id,
                    "action_error",
                    "apply_mismatch",
                    &json!({
                        "expected": receive_limit_outcome_name(expected),
                        "actual": receive_limit_outcome_name(actual),
                    }),
                )?;
                return Err(Error::SlotInvariant(format!(
                    "receive action previewed {expected:?} but applied as {actual:?}"
                )));
            }
            Ok(None) => {
                let error = QcsdReceiveLimitError {
                    kind: QcsdReceiveLimitFatal::Ledger,
                    requested_limit: absolute_limit,
                    reference_limit: 0,
                };
                record_receive_limit_error(traces, now, &trace_action, "apply", error)?;
                return Err(error.into());
            }
            Err(error) => {
                record_receive_limit_error(traces, now, &trace_action, "apply", error)?;
                return Err(error.into());
            }
        }
    }
    match endpoint.client.apply_qcsd_action(now, action) {
        Ok(chaff_stream) => {
            if let Some((packet, slot, deadline_after_us)) = scheduled_packet {
                let deadline = now
                    .checked_add(Duration::from_micros(deadline_after_us))
                    .ok_or_else(|| {
                        Error::SlotInvariant(format!(
                            "outgoing slot {} succeeded without a representable handoff deadline",
                            slot.0
                        ))
                    })?;
                endpoint.scheduled_outgoing.push_back(ScheduledOutgoing {
                    slot,
                    packet,
                    deadline,
                });
            }
            if let Some(stream_id) = chaff_stream {
                let (resource_id, request_id, url, request_headers) = match &trace_action {
                    QcsdAction::RequestChaff {
                        resource,
                        request_id,
                        ..
                    } => (
                        resource.id,
                        *request_id,
                        resource.url.clone(),
                        resource.headers.clone(),
                    ),
                    _ => unreachable!("only chaff actions return a stream"),
                };
                let request_stream_bytes = endpoint.client.qcsd_request_stream_bytes(stream_id)?;
                endpoint.client.stream_close_send(stream_id, now)?;
                let qualification = chaff_manifest
                    .and_then(|manifest| manifest.qualification(resource_id))
                    .ok_or_else(|| {
                        Error::RunAborted(
                            "chaff request lacks a current qualification binding".into(),
                        )
                    })?;
                let expected_request_stream_bytes = qualification.request_stream_bytes();
                let expected_response = qualification.expected_response();
                let expected_chaff_response = ExpectedChaffIdentity {
                    status: expected_response.status,
                    content_encoding: expected_response.content_encoding.clone(),
                    body_bytes: expected_response.body_bytes,
                    body_sha256: expected_response.body_sha256.clone(),
                };
                if request_stream_bytes != expected_request_stream_bytes {
                    endpoint.streams.insert(
                        stream_id,
                        StreamRecord {
                            resource_id,
                            url,
                            role: QcsdRequestRole::Chaff {
                                resource_id,
                                request_id: Some(request_id),
                            },
                            request_headers,
                            request_stream_bytes,
                            expected_request_stream_bytes: Some(expected_request_stream_bytes),
                            response_headers: Vec::new(),
                            status: None,
                            content_length: None,
                            body: Vec::new(),
                            bytes: 0,
                            complete: false,
                            outcome: "request_size_mismatch",
                            expected_chaff_response: Some(expected_chaff_response),
                        },
                    );
                    return Err(Error::RunAborted(format!(
                        "chaff request stream encoded {request_stream_bytes} bytes, expected qualified size {expected_request_stream_bytes}"
                    )));
                }
                endpoint.streams.insert(
                    stream_id,
                    StreamRecord {
                        resource_id,
                        url,
                        role: QcsdRequestRole::Chaff {
                            resource_id,
                            request_id: Some(request_id),
                        },
                        request_headers,
                        request_stream_bytes,
                        expected_request_stream_bytes: Some(expected_request_stream_bytes),
                        response_headers: Vec::new(),
                        status: None,
                        content_length: None,
                        body: Vec::new(),
                        bytes: 0,
                        complete: false,
                        outcome: "in_flight",
                        expected_chaff_response: Some(expected_chaff_response),
                    },
                );
                // Apply manual receive control before the newly created chaff
                // request is eligible for its first transport output.
                handle_qcsd_observations(endpoint, controller, traces, defense_elapsed)?;
            }
            if let Some(stream_id) = local_et_stream {
                let Some(record) = endpoint.streams.get_mut(&stream_id) else {
                    return Err(Error::SlotInvariant(format!(
                        "local CS-BuFLO termination targeted unknown chaff stream {}",
                        stream_id.as_u64()
                    )));
                };
                if !matches!(record.role, QcsdRequestRole::Chaff { .. }) {
                    return Err(Error::SlotInvariant(format!(
                        "local CS-BuFLO termination targeted application stream {}",
                        stream_id.as_u64()
                    )));
                }
                record.outcome = "local_early_termination_cancelled";
                finish_stream(endpoint, stream_id)?;
            }
            traces.event(now, endpoint_id, "action", "applied", &trace_action)?;
        }
        Err(error) => {
            handle_qcsd_observations(endpoint, controller, traces, defense_elapsed)?;
            if let Some((_, packet, slot)) = scheduled_action
                && traces.is_slot_pending(slot)
            {
                let reason = action_failure_reason(&trace_action, &error);
                controller.observe(
                    QcsdObservation::SlotMissed {
                        endpoint: endpoint.id,
                        slot,
                        packet,
                        reason,
                    },
                    defense_elapsed,
                );
                let miss_reason = format!("{reason:?}");
                traces.schedule(&ScheduleTraceRow {
                    action_time_us: traces.elapsed_us(now),
                    endpoint: endpoint_id,
                    packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: &miss_reason,
                    slot,
                    qcsd: QcsdTraceColumns::default(),
                })?;
            }
            record_adapter_action_error(traces, now, &trace_action, &error)?;
            return Err(error.into());
        }
    }
    Ok(())
}

const fn action_failure_reason(action: &QcsdAction, error: &neqo_http3::Error) -> MissedSlotReason {
    match (action, error) {
        (
            QcsdAction::SendPacket { .. },
            neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput),
        ) => MissedSlotReason::PathMtu,
        (
            QcsdAction::SendPacket { .. },
            neqo_http3::Error::Transport(neqo_transport::Error::NotAvailable),
        ) => MissedSlotReason::KeysUnavailable,
        _ => MissedSlotReason::RunAborted,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivityWake {
    SocketReady,
    Timer,
}

async fn wait_for_activity<'a>(
    sockets: impl IntoIterator<Item = &'a Socket>,
    delay: Duration,
) -> Result<ActivityWake, Error> {
    let readiness: Vec<_> = sockets
        .into_iter()
        .map(|socket| Box::pin(socket.readable()))
        .collect();
    if readiness.is_empty() {
        tokio::time::sleep(delay).await;
        return Ok(ActivityWake::Timer);
    }
    let sockets_ready =
        select_all(readiness).map(|(result, _, _)| result.map(|()| ActivityWake::SocketReady));
    let timeout_ready = Box::pin(tokio::time::sleep(delay).map(|()| Ok(ActivityWake::Timer)));
    select(sockets_ready, timeout_ready)
        .map(|either| either.factor_first().0)
        .await
        .map_err(Error::from)
}

async fn wait_for_activity_until<'a>(
    sockets: impl IntoIterator<Item = &'a Socket>,
    wakeup: Instant,
) -> Result<ActivityWake, Error> {
    // A future callback retains its absolute monotonic deadline instead of
    // converting it to a relative sleep after every loop turn. An already-due
    // callback still yields once so Tokio's current-thread reactor can publish
    // socket readiness before the runner retries its work loop.
    if remaining_wakeup_delay(wakeup, now()).is_none() {
        return wait_for_activity(sockets, Duration::from_micros(1)).await;
    }
    let readiness: Vec<_> = sockets
        .into_iter()
        .map(|socket| Box::pin(socket.readable()))
        .collect();
    let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(wakeup));
    if readiness.is_empty() {
        timer.await;
        return Ok(ActivityWake::Timer);
    }
    let sockets_ready =
        select_all(readiness).map(|(result, _, _)| result.map(|()| ActivityWake::SocketReady));
    let timeout_ready = Box::pin(timer.map(|()| Ok(ActivityWake::Timer)));
    select(sockets_ready, timeout_ready)
        .map(|either| either.factor_first().0)
        .await
        .map_err(Error::from)
}

fn absolute_wakeup(base: Instant, delay: Duration) -> Option<Instant> {
    base.checked_add(delay)
}

fn remaining_wakeup_delay(wakeup: Instant, current: Instant) -> Option<Duration> {
    let remaining = wakeup.saturating_duration_since(current);
    (!remaining.is_zero()).then_some(remaining)
}

fn bounded_qualification_wait(
    delay: Duration,
    deadline: Instant,
    timeout_seconds: u64,
) -> Result<Duration, Error> {
    let remaining = deadline.saturating_duration_since(now());
    if remaining.is_zero() {
        return Err(Error::Timeout(timeout_seconds));
    }
    Ok(delay.min(remaining))
}

fn datagram_observation(
    endpoint: QcsdEndpointId,
    direction: Direction,
    length: u16,
    defense_elapsed: Option<Duration>,
) -> Option<(QcsdObservation, Duration)> {
    let at = defense_elapsed?;
    Some((
        QcsdObservation::Datagram {
            endpoint,
            direction,
            length,
            timestamp_us: u64::try_from(at.as_micros()).unwrap_or(u64::MAX),
        },
        at,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputDrive {
    Datagram,
    Callback(Instant),
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketHandoff {
    Sent(Instant),
    RetryUnshaped,
}

fn attempt_socket_handoff(
    target_deadlines: &[Instant],
    send: impl FnOnce() -> io::Result<()>,
    clock: impl FnOnce() -> Instant,
) -> Result<SocketHandoff, Error> {
    match send() {
        Ok(()) => {
            let sent_at = clock();
            if let Some(deadline) = target_deadlines
                .iter()
                .copied()
                .find(|deadline| sent_at >= *deadline)
            {
                return Err(Error::SlotInvariant(format!(
                    "target-bearing UDP datagram reached the socket at or after its adapter deadline ({sent_at:?} >= {deadline:?})"
                )));
            }
            Ok(SocketHandoff::Sent(sent_at))
        }
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock && !target_deadlines.is_empty() =>
        {
            Err(Error::SlotInvariant(
                "target-bearing UDP datagram encountered socket backpressure after transport commit; refusing a late retry"
                    .into(),
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Ok(SocketHandoff::RetryUnshaped)
        }
        Err(error) => Err(error.into()),
    }
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn drive_endpoint_output(
    endpoint_index: usize,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
) -> Result<Option<Instant>, Error> {
    loop {
        // One fresh timestamp governs the complete fixed-schedule microstep:
        // reconcile every event due at that instant, apply its incoming
        // actions, and only then let transport observe target eligibility.
        let drive_now = now();
        if controller.has_fixed_schedule_staging()
            && let Some(started) = defense_start
        {
            let drive_elapsed = drive_now.saturating_duration_since(started);
            controller.reconcile_due_fixed(drive_elapsed);
            apply_queued_actions(
                endpoints,
                controller,
                chaff_manifest,
                traces,
                drive_now,
                drive_elapsed,
            )?;
        }

        match process_output_once(
            &mut endpoints[endpoint_index],
            controller,
            traces,
            observation_clock,
            drive_now,
            defense_start,
        )
        .await?
        {
            OutputDrive::Datagram => {}
            OutputDrive::Callback(wakeup) => return Ok(Some(wakeup)),
            OutputDrive::None => return Ok(None),
        }
    }
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn process_output_once(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    drive_now: Instant,
    defense_start: Option<Instant>,
) -> Result<OutputDrive, Error> {
    let output = endpoint
        .client
        .process_multiple_output(drive_now, NonZeroUsize::MIN);
    let batch = match output {
        OutputBatch::DatagramBatch(batch) => batch,
        OutputBatch::Callback(delay) => {
            let wakeup = absolute_wakeup(drive_now, delay)
                .ok_or_else(|| Error::RunAborted("transport callback deadline overflow".into()))?;
            return Ok(OutputDrive::Callback(wakeup));
        }
        OutputBatch::None => return Ok(OutputDrive::None),
    };
    let observations = endpoint.client.qcsd_timestamped_observations();
    let mut satisfied_datagrams = satisfied_datagrams_for(endpoint, &observations)?;
    let built_datagrams = built_outgoing_datagrams_for(&observations);
    let batch_datagrams = batch.iter().count();
    if built_datagrams.len() != batch_datagrams {
        return Err(Error::SlotInvariant(format!(
            "transport reported {} packet-build compositions for {batch_datagrams} outgoing datagrams",
            built_datagrams.len()
        )));
    }
    let mut attributed_datagrams = Vec::new();
    for (datagram, (built_length, composition)) in batch.iter().zip(built_datagrams) {
        if datagram.len() != built_length
            || composition.observed_udp_bytes != u16::try_from(datagram.len()).unwrap_or(u16::MAX)
        {
            return Err(Error::SlotInvariant(format!(
                "packet-build composition length {built_length}/{} did not match raw outgoing datagram {}",
                composition.observed_udp_bytes,
                datagram.len()
            )));
        }
        let satisfied = satisfied_datagrams
            .iter()
            .position(|candidate| candidate.observed_size == datagram.len())
            .map(|index| satisfied_datagrams.remove(index));
        attributed_datagrams.push((datagram.len(), satisfied, composition));
    }
    if let Some(satisfied) = satisfied_datagrams.first() {
        return Err(Error::SlotInvariant(format!(
            "satisfied outgoing slot {} had no matching datagram",
            satisfied.slot.0
        )));
    }

    let target_deadlines: Vec<_> = attributed_datagrams
        .iter()
        .filter_map(|(_, satisfied, _)| satisfied.map(|target| target.deadline))
        .collect();
    let sent_at = loop {
        match attempt_socket_handoff(&target_deadlines, || endpoint.socket.send(&batch), now)? {
            SocketHandoff::Sent(sent_at) => break sent_at,
            SocketHandoff::RetryUnshaped => {
                endpoint.socket.writable().await?;
            }
        }
    };
    let wire_elapsed = defense_start.map(|started| sent_at.saturating_duration_since(started));
    for observation in observations {
        record_qcsd_observation(endpoint, traces, &observation)?;
        forward_qcsd_observation(controller, observation, wire_elapsed);
    }
    for (observed, satisfied, composition) in attributed_datagrams {
        let qcsd = satisfied
            .map_or_else(QcsdTraceColumns::default, |target| target.qcsd)
            .with_built_composition(composition);
        traces.packet(&PacketTraceRow {
            now: sent_at,
            endpoint: endpoint.id,
            direction: "outgoing",
            observed,
            scheduled: satisfied
                .map(|target| u16::try_from(target.observed_size).unwrap_or(u16::MAX)),
            satisfaction: satisfied.map_or("unshaped", |target| target.status),
            slot: satisfied.map(|target| target.slot),
            qcsd,
        })?;
        if let Some((observation, at)) = datagram_observation(
            endpoint.id,
            Direction::Outgoing,
            u16::try_from(observed).unwrap_or(u16::MAX),
            wire_elapsed,
        ) {
            let record = observation_clock.record_at(observation, sent_at);
            traces.observation(Some(endpoint.id), &record)?;
            controller.observe(record.into_observation(), at);
        }
    }
    Ok(OutputDrive::Datagram)
}

fn process_input(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    now: Instant,
    defense_elapsed: Option<Duration>,
) -> Result<(), Error> {
    while let Some(datagrams) = endpoint
        .socket
        .recv(endpoint.local_addr, &mut endpoint.recv_buf)?
    {
        for datagram in datagrams {
            traces.packet(&PacketTraceRow {
                now,
                endpoint: endpoint.id,
                direction: "incoming",
                observed: datagram.len(),
                scheduled: None,
                satisfaction: "observed",
                slot: None,
                qcsd: QcsdTraceColumns::default(),
            })?;
            if let Some((observation, at)) = datagram_observation(
                endpoint.id,
                Direction::Incoming,
                u16::try_from(datagram.len()).unwrap_or(u16::MAX),
                defense_elapsed,
            ) {
                let record = observation_clock.record_at(observation, now);
                traces.observation(Some(endpoint.id), &record)?;
                controller.observe(record.into_observation(), at);
            }
            endpoint.client.process_input(datagram, now);
        }
    }
    Ok(())
}

fn response_result(record: &StreamRecord) -> Result<ResponseResult, Error> {
    Ok(ResponseResult {
        resource_id: record.resource_id,
        url: record.url.clone(),
        request_headers: record.request_headers.clone(),
        response_headers: record.response_headers.clone(),
        status: record.status,
        content_length: record.content_length,
        bytes: record.bytes,
        body_sha256: hex::encode(nss::hash::hash(&HashAlgorithm::SHA2_256, &record.body)?),
        request_stream_bytes: record.request_stream_bytes,
        complete: record.complete,
        outcome: record.outcome,
    })
}

fn collect_responses(endpoints: &mut [Endpoint]) -> Result<Vec<ResponseResult>, Error> {
    let mut responses = Vec::new();
    for endpoint in endpoints {
        while let Some(request) = endpoint.pending.pop_front() {
            endpoint.completed.push(application_record(
                &request,
                QcsdRequestRole::Application,
                "not_started",
            ));
        }
        endpoint
            .completed
            .extend(endpoint.streams.drain().map(|(_, mut record)| {
                if record.outcome == "in_flight" {
                    record.outcome = "incomplete";
                }
                record
            }));
        for record in &endpoint.completed {
            if record.role == QcsdRequestRole::Application {
                responses.push(response_result(record)?);
            }
        }
    }
    responses.sort_by_key(|response| response.resource_id);
    Ok(responses)
}

fn collect_chaff_responses(endpoints: &[Endpoint]) -> Result<Vec<ChaffResponseResult>, Error> {
    let mut responses = endpoints
        .iter()
        .flat_map(|endpoint| endpoint.completed.iter())
        .filter(|record| matches!(record.role, QcsdRequestRole::Chaff { .. }))
        .map(chaff_response_result)
        .collect::<Result<Vec<_>, _>>()?;
    responses.sort_by_key(|response| (response.resource_id, response.request_id));
    Ok(responses)
}

fn buflo_run_summary(
    defense: &DefenseConfig,
    diagnostics: Option<&DefenseDiagnostics>,
) -> Option<serde_json::Value> {
    let DefenseConfig::Buflo(_) = defense else {
        return None;
    };
    diagnostics.map(|diagnostics| {
        json!({
            "schema_version": 1,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": false,
            "incoming_opportunity_semantics": "client_receive_credit_and_response_qualified_chaff_attempt",
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "diagnostics": diagnostics,
        })
    })
}

fn cs_buflo_run_summary(
    defense: &DefenseConfig,
    diagnostics: Option<&DefenseDiagnostics>,
) -> Option<serde_json::Value> {
    let DefenseConfig::CsBuflo(_) = defense else {
        return None;
    };
    diagnostics.map(|diagnostics| {
        json!({
            "schema_version": 2,
            "kind": "cs_buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": false,
            "incoming_opportunity_semantics": "client_receive_credit_and_response_qualified_chaff_attempt",
            "incoming_cadence_boundary": "complete_local_on_wire_max_stream_data_advertisement",
            "incoming_terminal_boundary": "eventual_peer_stream_offset_consumption",
            "incoming_boundary_separation": "advertisement_rearms_cadence_but_does_not_claim_peer_datagram_or_consumption",
            "unavailable_peer_properties": [
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size",
            ],
            "early_termination_semantics": diagnostics.cs_buflo_early_termination_semantics,
            "diagnostics": diagnostics,
        })
    })
}

fn write_run_json(
    spec: &RunSpec,
    endpoints: &[Endpoint],
    responses: &[ResponseResult],
    started_unix_ns: u128,
    completion: &RunCompletion<'_>,
) -> Result<(), Error> {
    let process_scheduler = process_scheduler_evidence()?;
    let chaff_responses = collect_chaff_responses(endpoints)?;
    let buflo_summary = buflo_run_summary(
        &spec.config.defense,
        completion.defense_diagnostics.as_ref(),
    );
    let cs_buflo_summary = cs_buflo_run_summary(
        &spec.config.defense,
        completion.defense_diagnostics.as_ref(),
    );
    let endpoint_data: Vec<_> = endpoints
        .iter()
        .map(|endpoint| {
            json!({
                "id": endpoint.id.0,
                "origin": endpoint.origin.to_string(),
                "local_address": endpoint.local_addr.to_string(),
                "remote_address": endpoint.remote_addr.to_string(),
                "tuple": {
                    "protocol": "udp",
                    "local": endpoint.local_addr.to_string(),
                    "remote": endpoint.remote_addr.to_string(),
                },
                "negotiated_protocol": endpoint.client.tls_info().and_then(|info| info.alpn()),
                "transport_stats": format!("{:?}", endpoint.client.transport_stats()),
            })
        })
        .collect();
    let run = json!({
        "neqo_version": env!("CARGO_PKG_VERSION"),
        "neqo_base_commit": NEQO_BASE_COMMIT,
        "published_qcsd_commit": PUBLISHED_QCSD_COMMIT,
        "migration_commit": option_env!("NEQO_QCSD_GIT_COMMIT").unwrap_or("working-tree"),
        "resolved_configuration": spec.config,
        "defense_parameters": spec.defense_parameters,
        "seed": spec.seed,
        "method": spec.method,
        "request_policy": spec.request_policy,
        "workload_hash_sha256": spec.workload_hash,
        "application_workload_source_hash_sha256": spec.application_workload_source.as_ref().map(|(_, hash, _)| hash),
        "chaff_manifest_hash_sha256": spec.chaff_manifest_hash,
        "max_response_bytes": spec.max_response_bytes,
        "time_anchor_unix_ns": started_unix_ns,
        "started_unix_ns": started_unix_ns,
        "ended_unix_ns": completion.ended_unix_ns,
        "defense_start_monotonic_ns": completion.defense_start_monotonic_ns,
        "application_completion_monotonic_ns": completion.application_completion_monotonic_ns,
        "defense_diagnostics": completion.defense_diagnostics,
        "runner_wakeup_metrics": completion.runner_wakeup_metrics,
        "process_scheduler": process_scheduler,
        "buflo_summary": buflo_summary,
        "cs_buflo_summary": cs_buflo_summary,
        "completion_status": completion.status,
        "error": completion.error,
        "endpoints": endpoint_data,
        "responses": responses,
        "chaff_responses": chaff_responses,
    });
    atomic_write(
        &spec.output_dir.join("run.json"),
        serde_json::to_string_pretty(&run)?.as_bytes(),
    )?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), Error> {
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("file")
    ));
    let mut file = File::create(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos()
}

fn elapsed_ns(start: Instant, instant: Instant) -> u64 {
    u64::try_from(instant.duration_since(start).as_nanos()).unwrap_or(u64::MAX)
}

fn now() -> Instant {
    #![expect(
        clippy::disallowed_methods,
        reason = "research traces require monotonic wall time"
    )]
    Instant::now()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };

    use clap::Parser as _;
    use neqo_csdef::{
        ChaffManifest, ChaffQualification, Defense, DefenseConfig, DefenseDiagnostics, DefenseMode,
        DefenseSignal, DependencyTracker, Direction, ExpectedChaffResponse, FrontConfig,
        IdentityChaffRequestHeaderPrimitive, MissedSlotReason, Packet, QcsdAction,
        QcsdChaffRequestId, QcsdConfig, QcsdCongestionReason, QcsdController, QcsdDatagramClass,
        QcsdEndpointId, QcsdObservation, QcsdObservationClock, QcsdParserLeaseOwner,
        QcsdReceiveActionIdentity, QcsdReceiveLimitError, QcsdReceiveLimitFatal,
        QcsdReceiveLimitOutcome, QcsdSendPolicy, QcsdSlotComposition, QcsdSlotId, QcsdSlotOutcome,
        QcsdStreamFinish, QcsdStreamId, QcsdStreamTransmission, QualifiedChaffResource, Resource,
        ResourceManifest, ResponseOnlyChaffManifest, ResponseOnlyChaffManifestV4,
        ResponseOnlyChaffQualification, ResponseOnlyChaffQualificationV4,
        ResponseOnlyQualifiedChaffResource, ResponseOnlyQualifiedChaffResourceV4, SignalKind,
        StaticSchedule, TamarawConfig, Trace, TrafficMorphingConfig, WalkieTalkieConfig,
        WalkieTalkieQualificationBinding, WtfPad, WtfPadConfig, sanitize_chaff_headers,
    };
    use neqo_udp::RecvBuf;
    use serde_json::json;

    use super::{
        ActivityWake, ApplicationBatchLifecycle, Args, ChaffRequestHeaderModeArg, DefenseArg,
        Error, ExpectedChaffIdentity, PrefixBurst, PrefixNumericProfile, PrefixPackSpec,
        PrefixStreamReceipt, PreparedExpectedResponse, Preset, ProfileArg, QcsdRequestRole,
        QualificationAcknowledgement, QualifierStream, RequestPolicyArg, ResourceRunState,
        ResponseQualificationMode, ResponseQualificationRequest, RunCompletion, RunSpec,
        RunnerWakeupMetrics, RuntimeChaffManifest, Socket, SocketHandoff, StaticModeArg,
        StreamActivationStage, StreamRecord, StreamType, SustainedResponseQualificationRequest,
        TrafficMorphingActivation, absolute_wakeup, action_failure_reason,
        activate_traffic_morphing, application_send_halves_peer_confirmed, apply_action_batch,
        attempt_socket_handoff, bind_qualified_chaff_stream_limits, bounded_qualification_wait,
        buflo_run_summary, create_endpoints, cs_buflo_run_summary, datagram_observation,
        deadline_error, defense_parameter_provenance, drain_qualifier_stream_data,
        ensure_defense_realizable, expected_application_response_length, finish_application_record,
        finish_chaff_record, finish_stream, forward_qcsd_observation, handle_http_events,
        has_in_flight_application_stream, now, pending_receive_identity_is_reconciled,
        prefix_receipts_pass, prefix_targetless_stream_bytes, preflight_receive_actions_with,
        prepare_local_et_chaff_cancellation, projected_ael, projected_identity_chaff_headers,
        qcsd_connection_parameters, qualification_content_encoding, ready_request_batch,
        record_adapter_action_error, record_receive_limit_error, record_terminal_action,
        register_action_batch, remaining_wakeup_delay, resolve_run_config,
        resolve_run_config_with_workload, response_qualification_mode,
        sanitize_chaff_action_headers, sha256, shapes_stream_sends,
        sustained_qualification_content_encoding, sustained_representation_failure,
        sustained_requests_are_classifiable, terminalize_pending_slots,
        trace_files::{PacketTraceRow, QcsdTraceColumns, ScheduleTraceRow, TraceFiles},
        traffic_morphing_endpoint_seed, validate_chaff_manifest_defense,
        validate_local_et_chaff_target, validate_prefix_capacity_plan,
        validate_qualified_chaff_binding, validate_walkie_talkie_chaff_precondition,
        wait_for_activity_until, walkie_talkie_qualification_binding_matches, write_run_json,
    };

    fn trace_output_dir(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "neqo-qcsd-runner-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create trace test directory");
        path
    }

    fn application(status: Option<u16>, complete: bool) -> StreamRecord {
        StreamRecord {
            resource_id: 1,
            url: "https://example.com/resource".into(),
            role: QcsdRequestRole::Application,
            request_headers: Vec::new(),
            request_stream_bytes: 0,
            expected_request_stream_bytes: None,
            response_headers: Vec::new(),
            status,
            content_length: None,
            body: Vec::new(),
            bytes: 0,
            complete,
            outcome: "in_flight",
            expected_chaff_response: None,
        }
    }

    fn chaff(body: &[u8], complete: bool) -> StreamRecord {
        test_fixture::fixture_init();
        StreamRecord {
            resource_id: 0,
            url: "https://example.com/".into(),
            role: QcsdRequestRole::Chaff {
                resource_id: 0,
                request_id: Some(QcsdChaffRequestId(7)),
            },
            request_headers: vec![
                ("accept".into(), "text/html".into()),
                ("accept-encoding".into(), "gzip".into()),
                ("accept-language".into(), "en".into()),
            ],
            request_stream_bytes: 23,
            expected_request_stream_bytes: Some(23),
            response_headers: vec![(":status".into(), "200".into())],
            status: Some(200),
            content_length: Some(u64::try_from(body.len()).expect("body length")),
            body: body.to_vec(),
            bytes: u64::try_from(body.len()).expect("body length"),
            complete,
            outcome: "in_flight",
            expected_chaff_response: Some(ExpectedChaffIdentity {
                status: 200,
                content_encoding: "identity".into(),
                body_bytes: u64::try_from(body.len()).expect("body length"),
                body_sha256: sha256(body).expect("hash body"),
            }),
        }
    }

    #[test]
    fn local_et_chaff_target_is_validated_before_adapter_mutation() {
        let application_stream = neqo_transport::StreamId::new(0);
        let chaff_stream = neqo_transport::StreamId::new(4);
        let streams = HashMap::from([
            (application_stream, application(Some(200), false)),
            (chaff_stream, chaff(b"cover", false)),
        ]);

        assert!(matches!(
            validate_local_et_chaff_target(&streams, QcsdStreamId(8)),
            Err(Error::SlotInvariant(message)) if message.contains("unknown chaff stream 8")
        ));
        assert!(matches!(
            validate_local_et_chaff_target(&streams, QcsdStreamId(0)),
            Err(Error::SlotInvariant(message)) if message.contains("application stream 0")
        ));
        assert_eq!(
            validate_local_et_chaff_target(&streams, QcsdStreamId(4)).expect("known chaff"),
            chaff_stream
        );
        assert_eq!(streams.len(), 2, "validation is side-effect free");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the real cross-layer cancellation lifecycle is one regression oracle"
    )]
    async fn local_et_rolls_back_real_unencoded_receive_identities_and_reaches_terminal_transport()
    {
        test_fixture::fixture_init();
        let output = trace_output_dir("local-et-real-receive-rollback");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let config = QcsdConfig {
            initial_max_stream_data: 16,
            defense: DefenseConfig::Front(FrontConfig::default()),
            ..QcsdConfig::default()
        };
        let mut client = test_fixture::http3_client_with_params(
            neqo_http3::Http3Parameters::default().connection_parameters(
                qcsd_connection_parameters(&config, test_fixture::DEFAULT_ADDR.ip()),
            ),
        );
        let mut server = test_fixture::default_http3_server();
        let trailing = test_fixture::connect_peers(&mut client, &mut server);
        let server_output = server.process(trailing, test_fixture::now()).dgram();
        test_fixture::exchange_packets(&mut client, &mut server, false, server_output);
        client
            .enable_qcsd_with_observation_clock(
                QcsdEndpointId(0),
                &http::Uri::from_static("https://example.com/"),
                1_200,
                false,
                Duration::from_millis(100),
                clock.clone(),
            )
            .expect("enable the connected QCSD adapter");
        for _ in 0..8 {
            if !client.qcsd_has_pending_stream_send() {
                break;
            }
            let client_output = client.process_output(test_fixture::now());
            let server_output = server.process(client_output.dgram(), test_fixture::now());
            drop(client.process(server_output.dgram(), test_fixture::now()));
        }
        assert!(
            !client.qcsd_has_pending_stream_send(),
            "preflush every HTTP/3 critical stream before shaping"
        );
        client.qcsd_enable_send_shaping(true);

        let spec = RunSpec {
            method: "GET",
            workload: ResourceManifest {
                resources: vec![request(1, "https://127.0.0.1:4433", Vec::new())],
            },
            workload_hash: "local-et-real-receive-rollback".into(),
            application_workload_source: None,
            config,
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 7,
            output_dir: output.clone(),
            max_response_bytes: 1,
            timeout_seconds: 1,
        };
        let mut endpoint = create_endpoints(&spec, started, &clock)
            .expect("construct runner endpoint")
            .remove(0);
        endpoint.client = client;
        endpoint.connected = true;
        endpoint.pending.clear();

        let request_id = QcsdChaffRequestId(7);
        let stream = endpoint
            .client
            .apply_qcsd_action(
                started,
                QcsdAction::RequestChaff {
                    endpoint: endpoint.id,
                    resource: Resource {
                        id: 0,
                        url: "https://example.com/chaff".into(),
                        kind: "Other".into(),
                        content_length: Some(5),
                        data_length: 5,
                        chaff_priority: true,
                        known_valid: true,
                        depends_on: Vec::new(),
                        headers: Vec::new(),
                    },
                    request_id,
                },
            )
            .expect("create real chaff request")
            .expect("chaff request stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close chaff request send handler");
        endpoint.streams.insert(stream, chaff(b"cover", false));

        let stream = QcsdStreamId(stream.as_u64());
        let configure = QcsdAction::ConfigureManualReceive {
            endpoint: endpoint.id,
            stream,
            initial_limit: 16,
        };
        assert_eq!(
            endpoint
                .client
                .apply_qcsd_receive_action(&configure)
                .expect("configure manual receive"),
            Some(QcsdReceiveLimitOutcome::Applied)
        );
        let scheduled_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("scheduled packet");
        let scheduled = QcsdAction::IncreaseReceiveLimit {
            endpoint: endpoint.id,
            stream,
            absolute_limit: 26,
            packet: scheduled_packet,
            slot: QcsdSlotId(90),
        };
        let parser_packet =
            Packet::new(Duration::from_micros(1), Direction::Incoming, 3).expect("parser packet");
        let parser = QcsdAction::LeaseParserReceive {
            endpoint: endpoint.id,
            stream,
            absolute_limit: 29,
            increase: 3,
            owner: Some(QcsdParserLeaseOwner {
                packet: parser_packet,
                slot: QcsdSlotId(91),
            }),
        };
        for action in [&scheduled, &parser] {
            assert_eq!(
                endpoint
                    .client
                    .apply_qcsd_receive_action(action)
                    .expect("accept typed receive action"),
                Some(QcsdReceiveLimitOutcome::Applied)
            );
        }
        let expected_identities = vec![
            scheduled.receive_identity().expect("scheduled identity"),
            parser.receive_identity().expect("parser identity"),
        ];
        assert_eq!(
            endpoint.client.qcsd_pending_receive_action_identities(),
            expected_identities,
            "both actions are accepted but still unencoded"
        );

        let cancel = QcsdAction::CancelChaff {
            endpoint: endpoint.id,
            stream,
        };
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        assert_eq!(
            prepare_local_et_chaff_cancellation(&mut endpoint, &mut traces, started, &cancel,)
                .expect("prepare exact local-ET rollback"),
            Some(neqo_transport::StreamId::new(stream.0))
        );
        assert!(
            endpoint
                .client
                .qcsd_pending_receive_action_identities()
                .is_empty(),
            "the exact scheduled and parser suffix is reconciled"
        );
        let restored_probe = QcsdAction::LeaseParserReceive {
            endpoint: endpoint.id,
            stream,
            absolute_limit: 19,
            increase: 3,
            owner: None,
        };
        assert_eq!(
            endpoint
                .client
                .preview_qcsd_receive_action(&restored_probe, None)
                .expect("preview restored boundary"),
            Some(QcsdReceiveLimitOutcome::Applied),
            "rollback restores the original 16-byte receive boundary"
        );

        endpoint
            .client
            .apply_qcsd_action(started, cancel)
            .expect("apply local-ET RESET_STREAM and STOP_SENDING");
        endpoint
            .streams
            .get_mut(&neqo_transport::StreamId::new(stream.0))
            .expect("tracked chaff stream")
            .outcome = "local_early_termination_cancelled";
        finish_stream(&mut endpoint, neqo_transport::StreamId::new(stream.0))
            .expect("retire chaff record");
        assert!(endpoint.streams.is_empty());
        assert!(endpoint.client.qcsd_has_pending_defense_control());

        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
        assert_eq!(endpoint.client.state(), neqo_http3::Http3State::Connected);
        let qpack_decoder = endpoint
            .client
            .qcsd_qpack_decoder_stream_id()
            .expect("fixture QPACK decoder stream");
        let pending_except_qpack_decoder = endpoint
            .client
            .qcsd_has_pending_stream_send_excluding(&[qpack_decoder]);
        let qpack_decoder_handler_pending = endpoint.client.qcsd_qpack_decoder_handler_pending();
        let qpack_decoder_transport_pending =
            endpoint.client.qcsd_qpack_decoder_transport_pending();
        assert!(
            !pending_except_qpack_decoder,
            "the cancelled request has no STREAM backlog; only the fixture's lazily created QPACK decoder stream may remain"
        );
        assert!(!qpack_decoder_handler_pending);
        assert!(qpack_decoder_transport_pending);
        assert!(!endpoint.client.qcsd_has_pending_defense_control());
        assert!(application_send_halves_peer_confirmed(&endpoint));

        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert!(events.contains("local_et_unencoded_rollback"));
        drop(endpoint);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn unexpected_endpoint_close_cannot_complete_and_aborts_with_reason() {
        test_fixture::fixture_init();
        let output = trace_output_dir("unexpected-endpoint-close");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let config = QcsdConfig {
            initial_max_stream_data: 16,
            defense: DefenseConfig::Front(FrontConfig::default()),
            ..QcsdConfig::default()
        };
        let mut client = test_fixture::http3_client_with_params(
            neqo_http3::Http3Parameters::default().connection_parameters(
                qcsd_connection_parameters(&config, test_fixture::DEFAULT_ADDR.ip()),
            ),
        );
        let mut server = test_fixture::default_http3_server();
        let trailing = test_fixture::connect_peers(&mut client, &mut server);
        let server_output = server.process(trailing, test_fixture::now()).dgram();
        test_fixture::exchange_packets(&mut client, &mut server, false, server_output);
        client
            .enable_qcsd_with_observation_clock(
                QcsdEndpointId(0),
                &http::Uri::from_static("https://example.com/"),
                1_200,
                true,
                Duration::from_millis(100),
                clock.clone(),
            )
            .expect("enable the connected QCSD adapter");
        let spec = RunSpec {
            method: "GET",
            workload: ResourceManifest {
                resources: vec![request(1, "https://127.0.0.1:4433", Vec::new())],
            },
            workload_hash: "unexpected-endpoint-close".into(),
            application_workload_source: None,
            config,
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 9,
            output_dir: output.clone(),
            max_response_bytes: 1,
            timeout_seconds: 1,
        };
        let mut endpoint = create_endpoints(&spec, started, &clock)
            .expect("construct runner endpoint")
            .remove(0);
        endpoint.client = client;
        endpoint.connected = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        endpoint
            .client
            .close(started, 85, "unexpected runner close");
        assert!(matches!(
            endpoint.client.state(),
            neqo_http3::Http3State::Closing(_)
        ));
        handle_http_events(&mut endpoint, &spec, started, &mut traces)
            .expect("the closing phase is guarded while transport finishes closing");
        assert!(endpoint.connected);
        assert!(
            !(endpoint.connected
                && matches!(endpoint.client.state(), neqo_http3::Http3State::Connected)),
            "a Closing endpoint cannot satisfy the runner completion guard"
        );

        let closed_at = started + Duration::from_secs(60);
        drop(endpoint.client.process_output(closed_at));
        assert!(matches!(
            endpoint.client.state(),
            neqo_http3::Http3State::Closed(_)
        ));
        let error = handle_http_events(&mut endpoint, &spec, closed_at, &mut traces)
            .expect_err("a terminal close must abort the run");
        assert!(matches!(
            error,
            Error::RunAborted(message)
                if message.contains("HTTP/3 endpoint 0 closed before accepted run completion")
                    && message.contains("Application(85)")
        ));
        assert!(!endpoint.connected);
        assert!(endpoint.pending.is_empty());
        assert_eq!(endpoint.completed.len(), 1);
        assert_eq!(endpoint.completed[0].outcome, "endpoint_closed");

        drop(traces);
        drop(endpoint);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    fn qualified_chaff_manifest(resources: Vec<Resource>) -> ChaffManifest {
        let resources: Vec<QualifiedChaffResource> = resources
            .into_iter()
            .map(|resource| QualifiedChaffResource {
                id: resource.id,
                url: resource.url,
                kind: resource.kind,
                content_length: resource.content_length,
                data_length: resource.data_length,
                chaff_priority: resource.chaff_priority,
                known_valid: resource.known_valid,
                depends_on: resource.depends_on,
                headers: resource.headers,
                chaff_qualification: ChaffQualification {
                    schema_version: 2,
                    method: "GET".into(),
                    request_stream_bytes: 1,
                    qualified_parallel_chaff_streams: 5,
                    walkie_talkie_required_chaff_streams: 5,
                    expected_response: ExpectedChaffResponse {
                        status: 200,
                        content_encoding: "identity".into(),
                        body_bytes: 1,
                        body_sha256: "a".repeat(64),
                    },
                    response_qualification_sha256: "b".repeat(64),
                    prefix_pack_qualification_sha256: "c".repeat(64),
                    prefix_spec_sha256: "d".repeat(64),
                },
            })
            .collect();
        ChaffManifest {
            schema_version: 2,
            artifact_type: "qcsd-qualified-chaff-manifest".into(),
            application_workload_sha256: "e".repeat(64),
            application_resource_id: 0,
            selected_chaff_resource_id: resources
                .first()
                .map_or(0, |resource: &QualifiedChaffResource| resource.id),
            qualified_parallel_chaff_streams: 5,
            walkie_talkie_required_chaff_streams: 5,
            resources,
        }
    }

    fn response_only_chaff_manifest() -> ResponseOnlyChaffManifest {
        ResponseOnlyChaffManifest {
            schema_version: 3,
            artifact_type: "qcsd-qualified-chaff-manifest".into(),
            qualification_scope: "response-only".into(),
            application_workload_sha256: "e".repeat(64),
            application_resource_id: 0,
            selected_chaff_resource_id: 6,
            qualified_parallel_chaff_streams: 5,
            resources: vec![ResponseOnlyQualifiedChaffResource {
                id: 6,
                url: "https://example.com/font.woff2".into(),
                kind: "Font".into(),
                content_length: Some(1_200),
                data_length: 1_200,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: vec![
                    ("accept".into(), "text/html".into()),
                    ("accept-encoding".into(), "gzip, br".into()),
                    ("accept-language".into(), "en-AU".into()),
                ],
                chaff_qualification: ResponseOnlyChaffQualification {
                    schema_version: 3,
                    qualification_scope: "response-only".into(),
                    method: "GET".into(),
                    request_stream_bytes: 42,
                    qualified_parallel_chaff_streams: 5,
                    expected_response: ExpectedChaffResponse {
                        status: 200,
                        content_encoding: "br".into(),
                        body_bytes: 1_200,
                        body_sha256: "a".repeat(64),
                    },
                    response_qualification_sha256: "b".repeat(64),
                },
            }],
        }
    }

    fn response_only_chaff_manifest_v4(
        selected_resource_id: u32,
        url: &str,
        body_bytes: u64,
        body_sha256: &str,
    ) -> ResponseOnlyChaffManifestV4 {
        ResponseOnlyChaffManifestV4 {
            schema_version: 4,
            artifact_type: "qcsd-qualified-chaff-manifest".into(),
            qualification_scope: "response-only".into(),
            application_workload_sha256: "e".repeat(64),
            application_resource_id: 0,
            selected_chaff_resource_id: selected_resource_id,
            qualified_parallel_chaff_streams: 5,
            resources: vec![ResponseOnlyQualifiedChaffResourceV4 {
                id: selected_resource_id,
                url: url.into(),
                kind: "Stylesheet".into(),
                content_length: Some(body_bytes),
                data_length: body_bytes,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: vec![
                    ("accept".into(), "text/html".into()),
                    ("accept-encoding".into(), "identity".into()),
                    ("accept-language".into(), "en-AU".into()),
                ],
                chaff_qualification: ResponseOnlyChaffQualificationV4 {
                    schema_version: 4,
                    qualification_scope: "response-only".into(),
                    method: "GET".into(),
                    request_header_primitive: IdentityChaffRequestHeaderPrimitive {
                        mode: "identity-chaff-v1".into(),
                        copied_from_application: vec!["accept".into(), "accept-language".into()],
                        forced: vec![("accept-encoding".into(), "identity".into())],
                    },
                    request_stream_bytes: 42,
                    qualified_parallel_chaff_streams: 5,
                    qualified_completion_count: 120,
                    expected_response: ExpectedChaffResponse {
                        status: 200,
                        content_encoding: "identity".into(),
                        body_bytes,
                        body_sha256: body_sha256.into(),
                    },
                    response_qualification_sha256: "b".repeat(64),
                },
            }],
        }
    }

    fn request(resource_id: u32, origin: &str, depends_on: Vec<u32>) -> Resource {
        Resource {
            id: resource_id,
            url: format!("{origin}/{resource_id}"),
            kind: "Other".into(),
            content_length: Some(1),
            data_length: 1,
            chaff_priority: false,
            known_valid: true,
            depends_on,
            headers: Vec::new(),
        }
    }

    #[test]
    fn runner_replays_frozen_safe_chaff_headers_without_mutable_state() {
        let expected = vec![
            ("accept".into(), "text/html".into()),
            ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
            ("accept-language".into(), "en-AU,en;q=0.9".into()),
            ("te".into(), "trailers".into()),
        ];
        let mut action = QcsdAction::RequestChaff {
            endpoint: QcsdEndpointId(7),
            resource: Resource {
                headers: vec![
                    ("Accept".into(), "text/html".into()),
                    ("Accept-Encoding".into(), "gzip, deflate, br, zstd".into()),
                    ("Accept-Language".into(), "en-AU,en;q=0.9".into()),
                    ("Cookie".into(), "secret=1".into()),
                    ("Cookie2".into(), "secret=2".into()),
                    ("Authorization".into(), "Bearer secret".into()),
                    ("Proxy-Authorization".into(), "Basic secret".into()),
                    ("If-Match".into(), "etag".into()),
                    ("If-Modified-Since".into(), "yesterday".into()),
                    ("If-None-Match".into(), "etag".into()),
                    ("If-Range".into(), "etag".into()),
                    ("If-Unmodified-Since".into(), "today".into()),
                    ("Range".into(), "bytes=0-99".into()),
                    ("Host".into(), "attacker.example".into()),
                    ("Connection".into(), "keep-alive".into()),
                    ("Keep-Alive".into(), "timeout=5".into()),
                    ("Proxy-Connection".into(), "keep-alive".into()),
                    ("Transfer-Encoding".into(), "chunked".into()),
                    ("Upgrade".into(), "websocket".into()),
                    ("TE".into(), "deflate".into()),
                    ("te".into(), "trailers".into()),
                    (":authority".into(), "attacker.example".into()),
                    ("bad name".into(), "unsafe".into()),
                    ("x-bad-value".into(), "unsafe\r\nvalue".into()),
                ],
                ..request(3, "https://example.com", Vec::new())
            },
            request_id: QcsdChaffRequestId(11),
        };

        sanitize_chaff_action_headers(&mut action);

        let QcsdAction::RequestChaff { resource, .. } = action else {
            unreachable!("test constructs a chaff action")
        };
        assert_eq!(resource.headers, expected);
    }

    #[test]
    fn runner_does_not_inject_chaff_accept_encoding() {
        assert_eq!(
            sanitize_chaff_headers(vec![("Accept".into(), "text/html".into())]),
            vec![("accept".into(), "text/html".into())]
        );
    }

    #[test]
    fn runtime_chaff_manifest_dispatches_only_strict_schema_two_three_and_four_inputs() {
        let response_only = response_only_chaff_manifest();
        let response_only_json = serde_json::to_string(&response_only).expect("serialize schema 3");
        let runtime =
            RuntimeChaffManifest::from_json(&response_only_json).expect("load schema three");
        assert!(runtime.is_response_only());
        assert_eq!(runtime.application_resource_id(), 0);
        assert_eq!(runtime.selected_chaff_resource_id(), 6);
        assert_eq!(runtime.qualified_parallel_chaff_streams(), 5);
        let qualification = runtime.qualification(6).expect("qualification");
        assert_eq!(qualification.request_stream_bytes(), 42);
        assert_eq!(qualification.expected_response().body_bytes, 1_200);

        let schema_four = response_only_chaff_manifest_v4(
            7,
            "https://example.com/site.css",
            1_463,
            &"f".repeat(64),
        );
        let schema_four_json = serde_json::to_string(&schema_four).expect("serialize schema four");
        let runtime = RuntimeChaffManifest::from_json(&schema_four_json).expect("load schema four");
        assert!(runtime.is_response_only());
        assert!(runtime.is_identity_chaff_v4());
        assert_eq!(runtime.selected_chaff_resource_id(), 7);
        assert_eq!(
            runtime
                .qualification(7)
                .expect("schema-four qualification")
                .expected_response()
                .content_encoding,
            "identity"
        );

        let resource = Resource {
            id: 6,
            url: "https://example.com/font.woff2".into(),
            kind: "Font".into(),
            content_length: Some(1_200),
            data_length: 1_200,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: vec![
                ("accept".into(), "text/html".into()),
                ("accept-encoding".into(), "gzip, br".into()),
                ("accept-language".into(), "en-AU".into()),
            ],
        };
        let mut schema_two = qualified_chaff_manifest(vec![resource]);
        schema_two.resources[0]
            .chaff_qualification
            .expected_response
            .body_bytes = 1_200;
        let schema_two_json = serde_json::to_string(&schema_two).expect("serialize schema 2");
        let runtime =
            RuntimeChaffManifest::from_json(&schema_two_json).expect("load schema two unchanged");
        assert!(runtime.schema_two().is_some());

        let mut forbidden = serde_json::to_value(response_only).expect("schema three value");
        forbidden["walkie_talkie_required_chaff_streams"] = serde_json::json!(5);
        assert!(RuntimeChaffManifest::from_json(&forbidden.to_string()).is_err());

        for schema_version in [0, 1, 5, 99] {
            let mut unknown = serde_json::to_value(&schema_four).expect("schema four value");
            unknown["schema_version"] = serde_json::json!(schema_version);
            assert!(RuntimeChaffManifest::from_json(&unknown.to_string()).is_err());
        }
    }

    #[test]
    fn response_only_runtime_contract_is_exclusive_to_sustained_padding_defenses() {
        let manifests: Vec<RuntimeChaffManifest> = vec![
            response_only_chaff_manifest().into(),
            response_only_chaff_manifest_v4(
                7,
                "https://example.com/site.css",
                1_463,
                &"f".repeat(64),
            )
            .into(),
        ];
        for manifest in &manifests {
            for defense in [
                DefenseConfig::Front(FrontConfig::default()),
                DefenseConfig::Tamaraw(TamarawConfig::default()),
                DefenseConfig::Buflo(neqo_csdef::BufloConfig {
                    parameters: "buflo.json".into(),
                }),
                DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
                    parameters: "cs-buflo.json".into(),
                }),
            ] {
                validate_chaff_manifest_defense(&defense, manifest)
                    .expect("response-only defense is supported");
            }
            let mut front = QcsdConfig {
                defense: DefenseConfig::Front(FrontConfig::default()),
                ..QcsdConfig::default()
            };
            bind_qualified_chaff_stream_limits(&mut front, manifest)
                .expect("FRONT consumes the five-stream response qualification");
            front.max_chaff_streams = 6;
            assert!(bind_qualified_chaff_stream_limits(&mut front, manifest).is_err());
            for defense in [
                DefenseConfig::None,
                DefenseConfig::Static {
                    schedule: "schedule.csv".into(),
                    padding_only: true,
                },
                DefenseConfig::TrafficMorphing(TrafficMorphingConfig::default()),
                DefenseConfig::WtfPad(WtfPadConfig::default()),
                DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default()),
            ] {
                assert!(validate_chaff_manifest_defense(&defense, manifest).is_err());
            }
        }

        let schema_two: RuntimeChaffManifest = qualified_chaff_manifest(Vec::new()).into();
        for defense in [
            DefenseConfig::None,
            DefenseConfig::Static {
                schedule: "schedule.csv".into(),
                padding_only: true,
            },
            DefenseConfig::Front(FrontConfig::default()),
            DefenseConfig::Tamaraw(TamarawConfig::default()),
            DefenseConfig::TrafficMorphing(TrafficMorphingConfig::default()),
            DefenseConfig::WtfPad(WtfPadConfig::default()),
            DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default()),
        ] {
            validate_chaff_manifest_defense(&defense, &schema_two)
                .expect("schema-two compatibility remains unchanged");
        }
    }

    #[test]
    fn schema_four_runtime_binding_accepts_a_qualified_fallback_candidate_only() {
        let application_headers = vec![
            ("accept".into(), "text/html".into()),
            ("accept-encoding".into(), "gzip, br".into()),
            ("accept-language".into(), "en-AU".into()),
        ];
        let source = ResourceManifest {
            resources: vec![
                Resource {
                    id: 0,
                    url: "https://example.com/".into(),
                    kind: "Document".into(),
                    content_length: Some(6_165),
                    data_length: 6_165,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: application_headers.clone(),
                },
                Resource {
                    id: 1,
                    url: "https://example.com/site.css".into(),
                    kind: "Stylesheet".into(),
                    content_length: Some(1_463),
                    data_length: 1_463,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: vec![0],
                    headers: application_headers,
                },
            ],
        };
        let expected = BTreeMap::from([
            (
                0,
                PreparedExpectedResponse {
                    resource_id: 0,
                    status: 200,
                    bytes: 6_165,
                    body_sha256: "a".repeat(64),
                },
            ),
            (
                1,
                PreparedExpectedResponse {
                    resource_id: 1,
                    status: 200,
                    bytes: 1_463,
                    body_sha256: "b".repeat(64),
                },
            ),
        ]);
        let schema_four = response_only_chaff_manifest_v4(
            1,
            "https://example.com/site.css",
            1_500,
            &"c".repeat(64),
        );
        let spec = RunSpec {
            method: "GET",
            workload: source.clone(),
            workload_hash: "runtime".into(),
            application_workload_source: Some((source.clone(), "e".repeat(64), expected)),
            config: QcsdConfig {
                defense: DefenseConfig::Front(FrontConfig::default()),
                ..QcsdConfig::default()
            },
            defense_parameters: None,
            chaff_manifest: Some(schema_four.into()),
            chaff_manifest_hash: Some("f".repeat(64)),
            request_policy: RequestPolicyArg::AsDefined,
            seed: 0,
            output_dir: trace_output_dir("schema-four-fallback"),
            max_response_bytes: 2_000,
            timeout_seconds: 1,
        };
        validate_qualified_chaff_binding(&spec)
            .expect("schema four accepts the second eligible sustained candidate");

        let mut schema_three = response_only_chaff_manifest();
        schema_three.selected_chaff_resource_id = 1;
        schema_three.resources[0].id = 1;
        schema_three.resources[0].url = "https://example.com/site.css".into();
        schema_three.resources[0].kind = "Stylesheet".into();
        schema_three.resources[0].content_length = Some(1_463);
        schema_three.resources[0].data_length = 1_463;
        schema_three.resources[0].headers =
            projected_ael(&source.resources[1]).expect("legacy compact projection");
        schema_three.resources[0]
            .chaff_qualification
            .expected_response
            .body_bytes = 1_463;
        schema_three.resources[0]
            .chaff_qualification
            .expected_response
            .body_sha256 = "b".repeat(64);
        let mut legacy_spec = spec;
        legacy_spec.chaff_manifest = Some(schema_three.into());
        assert!(validate_qualified_chaff_binding(&legacy_spec).is_err());
    }

    #[test]
    fn qualified_manifest_rewrites_walkie_talkie_limit_before_provenance_use() {
        let resource = Resource {
            id: 6,
            url: "https://example.com/font.woff2".into(),
            kind: "Font".into(),
            content_length: Some(1),
            data_length: 1,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        };
        let mut manifest = qualified_chaff_manifest(vec![resource]);
        manifest.qualified_parallel_chaff_streams = 20;
        manifest.walkie_talkie_required_chaff_streams = 20;
        manifest.resources[0]
            .chaff_qualification
            .qualified_parallel_chaff_streams = 20;
        manifest.resources[0]
            .chaff_qualification
            .walkie_talkie_required_chaff_streams = 20;
        let mut config = QcsdConfig {
            max_chaff_streams: 5,
            defense: DefenseConfig::WalkieTalkie(WalkieTalkieConfig {
                molded: "molded.json".into(),
                workload_id: "workload".into(),
                ..WalkieTalkieConfig::default()
            }),
            ..QcsdConfig::default()
        };

        bind_qualified_chaff_stream_limits(&mut config, &manifest.clone().into())
            .expect("hash-bound exact stream count");
        assert_eq!(config.max_chaff_streams, 20);

        manifest.qualified_parallel_chaff_streams = 5;
        manifest.walkie_talkie_required_chaff_streams = 3;
        manifest.resources[0]
            .chaff_qualification
            .qualified_parallel_chaff_streams = 5;
        manifest.resources[0]
            .chaff_qualification
            .walkie_talkie_required_chaff_streams = 3;
        config.max_chaff_streams = 20;
        bind_qualified_chaff_stream_limits(&mut config, &manifest.into())
            .expect("WT replaces a common ceiling before checking qualified concurrency");
        assert_eq!(config.max_chaff_streams, 3);
    }

    #[test]
    fn walkie_talkie_binding_requires_exact_resource_ids_and_stream_counts() {
        let resource = Resource {
            id: 6,
            url: "https://example.com/font.woff2".into(),
            kind: "Font".into(),
            content_length: Some(1_200),
            data_length: 1_200,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        };
        let manifest = qualified_chaff_manifest(vec![resource]);
        let binding = WalkieTalkieQualificationBinding {
            workload_id: "workload".into(),
            chaff_qualification_sidecar_sha256: "a".repeat(64),
            prefix_pack_spec_sha256: "d".repeat(64),
            qualified_chaff_manifest_sha256: "f".repeat(64),
            application_resource_id: 0,
            selected_chaff_resource_id: 6,
            qualified_parallel_chaff_streams: 5,
            walkie_talkie_required_chaff_streams: 5,
        };
        let matches = |binding: &WalkieTalkieQualificationBinding| {
            walkie_talkie_qualification_binding_matches(
                binding,
                "workload",
                &"f".repeat(64),
                &manifest,
                5,
            )
        };
        assert!(matches(&binding));

        let mut mutated = binding.clone();
        mutated.application_resource_id = 1;
        assert!(!matches(&mutated));
        mutated = binding.clone();
        mutated.selected_chaff_resource_id = 7;
        assert!(!matches(&mutated));
        mutated = binding.clone();
        mutated.qualified_parallel_chaff_streams = 6;
        assert!(!matches(&mutated));
        mutated = binding;
        mutated.walkie_talkie_required_chaff_streams = 4;
        assert!(!matches(&mutated));
    }

    #[test]
    fn walkie_talkie_chaff_preflight_filters_origins_before_priority_selection() {
        let molded_path = trace_output_dir("walkie-preflight-molded").join("molded.json");
        let mut molded: serde_json::Value = serde_json::from_str(include_str!(
            "../../../neqo-csdef/tests/data/walkie-talkie-golden.json"
        ))
        .expect("strict Walkie-Talkie fixture");
        let binding = &mut molded["qualification_bindings"][0];
        binding["qualified_chaff_manifest_sha256"] = serde_json::json!("f".repeat(64));
        binding["prefix_pack_spec_sha256"] = serde_json::json!("d".repeat(64));
        binding["selected_chaff_resource_id"] = serde_json::json!(7);
        fs::write(
            &molded_path,
            serde_json::to_vec(&molded).expect("serialize Walkie-Talkie fixture"),
        )
        .expect("write Walkie-Talkie fixture");
        let workload = ResourceManifest {
            resources: vec![request(1, "https://match.example", Vec::new())],
        };
        let chaff = |id, origin: &str, length, priority| Resource {
            id,
            url: format!("{origin}/{id}"),
            kind: "Image".into(),
            content_length: Some(length),
            data_length: length,
            chaff_priority: priority,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        };
        let spec = |resources, use_empty_resources| RunSpec {
            method: "GET",
            workload: workload.clone(),
            workload_hash: "preflight".into(),
            application_workload_source: None,
            config: QcsdConfig {
                use_empty_resources,
                defense: DefenseConfig::WalkieTalkie(WalkieTalkieConfig {
                    molded: molded_path.to_string_lossy().into_owned(),
                    workload_id: "real page".into(),
                    packet_size: 1_200,
                }),
                ..QcsdConfig::default()
            },
            defense_parameters: None,
            chaff_manifest: Some(qualified_chaff_manifest(resources).into()),
            chaff_manifest_hash: Some("f".repeat(64)),
            request_policy: RequestPolicyArg::AsDefined,
            seed: 0,
            output_dir: trace_output_dir("walkie-preflight"),
            max_response_bytes: 1,
            timeout_seconds: 1,
        };

        validate_walkie_talkie_chaff_precondition(&spec(
            vec![
                chaff(7, "https://other.example", 1_199, true),
                chaff(8, "https://match.example", 1_200, false),
            ],
            false,
        ))
        .expect("unmatched priority resource cannot suppress matching fallback");

        assert!(
            validate_walkie_talkie_chaff_precondition(&spec(
                vec![
                    chaff(7, "https://match.example", 1_199, true),
                    chaff(8, "https://match.example", 1_200, false),
                ],
                false,
            ))
            .is_err()
        );
        validate_walkie_talkie_chaff_precondition(&spec(
            vec![chaff(7, "https://match.example", 1_200, true)],
            false,
        ))
        .expect("selected same-origin resource supplies one whole cell");
        assert!(
            validate_walkie_talkie_chaff_precondition(&spec(
                vec![chaff(7, "https://match.example", 0, true)],
                true,
            ))
            .is_err()
        );
    }

    #[test]
    fn measured_scheduler_contract_rejects_every_receipted_mismatch() {
        fn assert_rejected(
            exact: &super::ProcessSchedulerEvidence,
            mutate: impl FnOnce(&mut super::ProcessSchedulerEvidence),
        ) {
            let mut value = exact.clone();
            mutate(&mut value);
            assert!(!super::scheduler_contract_matches(&value));
        }

        let exact = super::ProcessSchedulerEvidence {
            schema_version: 1,
            source: "linux-sched-and-procfs-v1",
            policy: "SCHED_RR".into(),
            priority: 1,
            affinity_cpus: vec![10],
            rlimit_rtprio: super::RealtimePriorityLimit { soft: 1, hard: 1 },
            no_new_privileges: Some(true),
            effective_capabilities_hex: Some("0000000000000000".into()),
            cgroup_effective_cpuset: Some("10-11".into()),
            affinity_scope: "qcsd_container_affinity_partition_not_physical_cpu_isolation",
            contract: Some("qcsd-client-rr1-cpu10-v1".into()),
            contract_valid: false,
        };
        assert!(super::scheduler_contract_matches(&exact));

        assert_rejected(&exact, |value| value.source = "wrong-source");
        assert_rejected(&exact, |value| value.policy = "SCHED_OTHER".into());
        assert_rejected(&exact, |value| value.priority = 2);
        assert_rejected(&exact, |value| value.affinity_cpus = vec![10, 11]);
        assert_rejected(&exact, |value| value.rlimit_rtprio.soft = 0);
        assert_rejected(&exact, |value| value.rlimit_rtprio.hard = 2);
        assert_rejected(&exact, |value| value.no_new_privileges = Some(false));
        assert_rejected(&exact, |value| {
            value.effective_capabilities_hex = Some("0000000000002000".into());
        });
        assert_rejected(&exact, |value| {
            value.cgroup_effective_cpuset = Some("0-11".into());
        });
        assert_rejected(&exact, |value| value.affinity_scope = "physical-dedication");
        assert_rejected(&exact, |value| value.contract = Some("unknown".into()));

        let mut unconstrained = exact;
        unconstrained.contract = None;
        unconstrained.policy = "SCHED_OTHER".into();
        assert!(
            super::scheduler_contract_matches(&unconstrained),
            "direct developer runs have no requested scheduler contract"
        );
    }

    #[test]
    fn run_receipt_keeps_evidence_without_duplicate_workload_fields() {
        let output = trace_output_dir("minimal-run-receipt");
        let spec = RunSpec {
            method: "GET",
            workload: ResourceManifest {
                resources: vec![request(1, "https://example.com", Vec::new())],
            },
            workload_hash: "frozen-workload-hash".into(),
            application_workload_source: None,
            config: QcsdConfig::default(),
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 7,
            output_dir: output.clone(),
            max_response_bytes: 1_024,
            timeout_seconds: 30,
        };
        write_run_json(
            &spec,
            &[],
            &[],
            1,
            &RunCompletion {
                ended_unix_ns: Some(2),
                status: "complete",
                error: None,
                defense_start_monotonic_ns: Some(3),
                application_completion_monotonic_ns: Some(4),
                defense_diagnostics: None,
                runner_wakeup_metrics: Some(RunnerWakeupMetrics {
                    schema_version: 1,
                    semantics: "test-select-return-semantics",
                    wait_returns: 3,
                    socket_readiness_wakeups: 1,
                    timer_wakeups: 2,
                    controller_deadline_timer_wakeups: 1,
                    other_timer_wakeups: 1,
                }),
            },
        )
        .expect("write run receipt");

        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("run.json")).expect("read run receipt"))
                .expect("parse run receipt");
        assert!(receipt.get("resolved_workload").is_none());
        assert!(receipt.get("urls").is_none());
        assert_eq!(receipt["workload_hash_sha256"], "frozen-workload-hash");
        assert_eq!(receipt["runner_wakeup_metrics"]["schema_version"], 1);
        assert_eq!(receipt["runner_wakeup_metrics"]["timer_wakeups"], 2);
        assert_eq!(receipt["process_scheduler"]["schema_version"], 1);
        assert!(receipt["process_scheduler"]["policy"].is_string());
        assert!(receipt["process_scheduler"]["affinity_cpus"].is_array());
        assert_eq!(
            receipt["process_scheduler"]["contract"],
            serde_json::Value::Null
        );
        assert_eq!(receipt["process_scheduler"]["contract_valid"], true);
        for retained in [
            "resolved_configuration",
            "responses",
            "endpoints",
            "completion_status",
        ] {
            assert!(receipt.get(retained).is_some(), "missing {retained}");
        }
    }

    #[test]
    fn run_receipt_summaries_are_versioned_and_mode_specific() {
        let diagnostics = DefenseDiagnostics {
            buflo_client_only: true,
            cs_buflo_client_only: true,
            cs_buflo_early_termination_semantics: "udp_client_only_observed_udp_power_of_two_crossing",
            ..DefenseDiagnostics::default()
        };
        let buflo = DefenseConfig::Buflo(neqo_csdef::BufloConfig {
            parameters: "buflo.json".into(),
        });
        let cs_buflo = DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
            parameters: "cs-buflo.json".into(),
        });

        let buflo_summary = buflo_run_summary(&buflo, Some(&diagnostics)).expect("BuFLO summary");
        assert_eq!(buflo_summary["schema_version"], 1);
        assert_eq!(buflo_summary["kind"], "buflo");
        assert_eq!(buflo_summary["implementation_scope"], "client_only_quic");
        assert_eq!(buflo_summary["paper_equivalent"], false);
        assert_eq!(
            buflo_summary["incoming_opportunity_semantics"],
            "client_receive_credit_and_response_qualified_chaff_attempt"
        );
        assert_eq!(
            buflo_summary["unavailable_peer_properties"],
            json!([
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size"
            ])
        );
        assert_eq!(buflo_summary["diagnostics"]["buflo_client_only"], true);
        assert!(cs_buflo_run_summary(&buflo, Some(&diagnostics)).is_none());

        let cs_summary =
            cs_buflo_run_summary(&cs_buflo, Some(&diagnostics)).expect("CS-BuFLO summary");
        assert_eq!(cs_summary["schema_version"], 2);
        assert_eq!(cs_summary["kind"], "cs_buflo");
        assert_eq!(cs_summary["implementation_scope"], "client_only_quic");
        assert_eq!(cs_summary["paper_equivalent"], false);
        assert_eq!(
            cs_summary["incoming_opportunity_semantics"],
            "client_receive_credit_and_response_qualified_chaff_attempt"
        );
        assert_eq!(
            cs_summary["incoming_cadence_boundary"],
            "complete_local_on_wire_max_stream_data_advertisement"
        );
        assert_eq!(
            cs_summary["incoming_terminal_boundary"],
            "eventual_peer_stream_offset_consumption"
        );
        assert_eq!(
            cs_summary["unavailable_peer_properties"],
            json!([
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size"
            ])
        );
        assert_eq!(
            cs_summary["early_termination_semantics"],
            "udp_client_only_observed_udp_power_of_two_crossing"
        );
        assert_eq!(cs_summary["diagnostics"]["cs_buflo_client_only"], true);
        assert!(buflo_run_summary(&cs_buflo, Some(&diagnostics)).is_none());
        assert!(buflo_run_summary(&buflo, None).is_none());
        assert!(cs_buflo_run_summary(&cs_buflo, None).is_none());
    }

    const TRAFFIC_MORPHING_PARAMETERS: &str = r#"{
        "adaptation": "qcsd-client-only",
        "buckets": [64, 1200],
        "generated_by": "runner activation test",
        "paper_equivalent": false,
        "profiles": [{
            "incoming": {
                "expected_added_bytes": 0.0,
                "l1_distance": 0.0,
                "realized_distribution": [1.0, 0.0],
                "rows": [[1.0, 0.0], [0.0, 1.0]],
                "source_distribution": [1.0, 0.0],
                "target_distribution": [1.0, 0.0]
            },
            "outgoing": {
                "expected_added_bytes": 0.0,
                "l1_distance": 0.0,
                "realized_distribution": [1.0, 0.0],
                "rows": [[1.0, 0.0], [0.0, 1.0]],
                "source_distribution": [1.0, 0.0],
                "target_distribution": [1.0, 0.0]
            },
            "source": "runner-source",
            "target": "runner-decoy"
        }],
        "schema_version": 2,
        "udp_payload_ceiling": 1200
    }"#;

    #[test]
    fn defense_activation_retains_endpoint_and_capacity_without_arming_wtf_pad() {
        let wtf_pad = WtfPad::from_json(
            &WtfPadConfig {
                histograms: "activation-boundary-fixture.json".into(),
                packet_size: 100,
                max_padding_events: 32,
            },
            0x5eed,
            1_200,
            include_str!("../../../neqo-csdef/tests/data/wtf-pad-golden.json"),
        )
        .expect("construct WTF-PAD fixture");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(wtf_pad),
        )
        .expect("construct controller");
        let start = now();
        let clock = QcsdObservationClock::new(start);
        let endpoint = QcsdEndpointId(0);
        let stream = QcsdStreamId(4);

        for observation in [
            QcsdObservation::EndpointReady {
                endpoint,
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                expected_response_length: Some(1_000),
            },
            QcsdObservation::ClassifiedDatagram {
                endpoint,
                direction: Direction::Outgoing,
                length: 1_200,
                class: QcsdDatagramClass::Natural,
                composition: None,
            },
        ] {
            forward_qcsd_observation(&mut controller, clock.record(observation), None);
        }
        controller.poll(Duration::from_secs(1));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.padding_events, 0);
        assert_eq!(diagnostics.wtf_pad_silent_to_burst, 0);
        assert_eq!(diagnostics.wtf_pad_burst_to_gap, 0);
        assert_eq!(diagnostics.wtf_pad_gap_to_burst, 0);
        assert_eq!(diagnostics.wtf_pad_burst_to_silent, 0);
        assert!(controller.drain_actions().any(|action| {
            matches!(
                action,
                QcsdAction::ConfigureManualReceive {
                    endpoint: configured_endpoint,
                    stream: configured_stream,
                    initial_limit: 16,
                } if configured_endpoint == endpoint && configured_stream == stream
            )
        }));

        forward_qcsd_observation(
            &mut controller,
            clock.record(QcsdObservation::ClassifiedDatagram {
                endpoint,
                direction: Direction::Outgoing,
                length: 1_200,
                class: QcsdDatagramClass::Natural,
                composition: None,
            }),
            Some(Duration::from_secs(2)),
        );
        controller.poll(Duration::from_secs(2));
        assert_eq!(controller.defense_diagnostics().wtf_pad_silent_to_burst, 1);
    }

    #[tokio::test]
    async fn traffic_morphing_activation_waits_for_every_endpoint_and_runs_once() {
        test_fixture::fixture_init();
        let output = trace_output_dir("traffic-morphing-activation");
        let matrix = output.join("matrix.json");
        fs::write(&matrix, TRAFFIC_MORPHING_PARAMETERS).expect("write morphing matrix");
        let config = QcsdConfig {
            max_udp_payload_size: 1_200,
            defense: DefenseConfig::TrafficMorphing(TrafficMorphingConfig {
                matrix: matrix.to_string_lossy().into_owned(),
                workload_id: "runner-source".into(),
                ingress_packet_size: 1_200,
                max_ingress_deficit_bytes: 8_000,
            }),
            ..QcsdConfig::default()
        };
        let spec = RunSpec {
            method: "GET",
            workload: ResourceManifest {
                resources: vec![
                    request(1, "https://127.0.0.1:4433", Vec::new()),
                    request(2, "https://127.0.0.1:4434", Vec::new()),
                ],
            },
            workload_hash: "activation-test".into(),
            application_workload_source: None,
            config,
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 0x5eed,
            output_dir: output.clone(),
            max_response_bytes: 1,
            timeout_seconds: 1,
        };
        let start = now();
        let clock = QcsdObservationClock::new(start);
        let mut endpoints = create_endpoints(&spec, start, &clock).expect("construct endpoints");
        assert!(!output.join("qlog").exists());

        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().all(|endpoint| {
            endpoint.traffic_morphing_activation == TrafficMorphingActivation::Pending
        }));
        assert!(endpoints.iter_mut().all(|endpoint| {
            endpoint
                .client
                .qcsd_timestamped_observations()
                .into_iter()
                .all(|record| {
                    !matches!(
                        record.observation(),
                        QcsdObservation::TrafficMorphingEgress { .. }
                    )
                })
        }));

        endpoints[0].connected = true;
        assert!(matches!(
            activate_traffic_morphing(&mut endpoints, &spec.config, spec.seed),
            Err(Error::SlotInvariant(message)) if message.contains("every endpoint")
        ));
        assert!(endpoints.iter().all(|endpoint| {
            endpoint.traffic_morphing_activation == TrafficMorphingActivation::Pending
        }));

        endpoints[1].connected = true;
        activate_traffic_morphing(&mut endpoints, &spec.config, spec.seed)
            .expect("activate all endpoint morphers");
        assert!(endpoints.iter().all(|endpoint| {
            endpoint.traffic_morphing_activation == TrafficMorphingActivation::Active
        }));
        assert!(matches!(
            activate_traffic_morphing(&mut endpoints, &spec.config, spec.seed),
            Err(Error::SlotInvariant(message)) if message.contains("exactly once")
        ));

        drop(endpoints);
        fs::remove_dir_all(output).expect("remove activation test directory");
    }

    #[test]
    fn traffic_morphing_endpoint_seeds_remain_domain_separated_and_pinned() {
        assert_eq!(
            [
                traffic_morphing_endpoint_seed(0x5eed, QcsdEndpointId(0)),
                traffic_morphing_endpoint_seed(0x5eed, QcsdEndpointId(1)),
            ],
            [2_893_922_826_792_763_185, 11_664_867_745_989_641_890]
        );
    }

    #[test]
    fn walkie_talkie_batches_all_globally_ready_requests() {
        let mut tracker = DependencyTracker::new(ResourceManifest {
            resources: vec![
                request(1, "https://first.example", Vec::new()),
                request(2, "https://second.example", Vec::new()),
                request(3, "https://second.example", vec![1]),
            ],
        })
        .expect("dependency tracker");
        let defense = DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default());

        assert_eq!(
            ready_request_batch(&defense, RequestPolicyArg::AsDefined, false, true, &tracker),
            [1, 2]
        );
        assert!(
            ready_request_batch(&defense, RequestPolicyArg::AsDefined, true, true, &tracker)
                .is_empty()
        );
        assert!(
            ready_request_batch(
                &defense,
                RequestPolicyArg::AsDefined,
                false,
                false,
                &tracker
            )
            .is_empty()
        );
        assert_eq!(
            ready_request_batch(
                &DefenseConfig::None,
                RequestPolicyArg::AsDefined,
                true,
                true,
                &tracker,
            ),
            [1, 2]
        );
        assert!(
            ready_request_batch(
                &DefenseConfig::None,
                RequestPolicyArg::HalfDuplex,
                true,
                true,
                &tracker,
            )
            .is_empty()
        );

        tracker.mark_in_flight(1).expect("first request started");
        tracker.mark_in_flight(2).expect("second request started");
        tracker.mark_succeeded(1).expect("first request completed");
        tracker.mark_succeeded(2).expect("second request completed");
        assert_eq!(
            ready_request_batch(&defense, RequestPolicyArg::AsDefined, false, true, &tracker),
            [3]
        );
    }

    #[test]
    fn application_batch_lifecycle_uses_actual_global_application_streams() {
        let defense = DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default());
        let mut lifecycle = ApplicationBatchLifecycle::new(&defense, RequestPolicyArg::AsDefined);

        assert_eq!(lifecycle.before_dispatch(false), None);
        assert_eq!(
            lifecycle.after_dispatch(2).expect("start batch"),
            Some(QcsdObservation::ApplicationBatchStarted)
        );
        assert_eq!(lifecycle.before_dispatch(true), None);
        assert_eq!(
            lifecycle.before_dispatch(false),
            Some(QcsdObservation::ApplicationBatchCompleted)
        );
        assert_eq!(lifecycle.before_dispatch(false), None);

        assert_eq!(lifecycle.after_dispatch(0).expect("no batch"), None);
        assert_eq!(
            lifecycle.after_dispatch(1).expect("start next batch"),
            Some(QcsdObservation::ApplicationBatchStarted)
        );
        assert!(lifecycle.after_dispatch(1).is_err());
    }

    #[test]
    fn candidate_completion_requires_every_tracked_application_send_half() {
        let streams = BTreeSet::from([
            neqo_transport::StreamId::new(0),
            neqo_transport::StreamId::new(4),
        ]);
        let mut queried = Vec::new();
        assert!(!super::tracked_application_send_halves_peer_confirmed(
            &streams,
            |stream| {
                queried.push(stream);
                stream == neqo_transport::StreamId::new(0)
            },
        ));
        assert_eq!(queried, streams.iter().copied().collect::<Vec<_>>());
        assert!(super::tracked_application_send_halves_peer_confirmed(
            &streams,
            |_| true,
        ));
    }

    #[test]
    fn application_batch_lifecycle_closes_before_dependent_batch_dispatch() {
        let defense = DefenseConfig::None;
        let mut lifecycle = ApplicationBatchLifecycle::new(&defense, RequestPolicyArg::HalfDuplex);

        assert_eq!(
            lifecycle.after_dispatch(1).expect("start root batch"),
            Some(QcsdObservation::ApplicationBatchStarted)
        );
        assert_eq!(lifecycle.before_dispatch(true), None);

        // Once the root stream retires, its dependent resources can become
        // ready in this same event-loop turn.  The global batch must close
        // before that newly ready layer is dispatched.
        assert_eq!(
            lifecycle.before_dispatch(false),
            Some(QcsdObservation::ApplicationBatchCompleted)
        );
        assert_eq!(
            lifecycle.after_dispatch(8).expect("start dependent batch"),
            Some(QcsdObservation::ApplicationBatchStarted)
        );
        assert_eq!(lifecycle.before_dispatch(true), None);
        assert_eq!(
            lifecycle.before_dispatch(false),
            Some(QcsdObservation::ApplicationBatchCompleted)
        );
    }

    #[test]
    fn incomplete_walkie_talkie_deadline_is_an_aborted_stall() {
        let walkie_talkie = DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default());
        assert!(matches!(
            deadline_error(&walkie_talkie, false, 30),
            Error::RunAborted(_)
        ));
        assert!(matches!(
            deadline_error(&walkie_talkie, true, 30),
            Error::Timeout(30)
        ));
        assert!(matches!(
            deadline_error(&DefenseConfig::None, false, 30),
            Error::Timeout(30)
        ));
    }

    #[derive(Debug, Default)]
    struct TerminalAfterObservation {
        failed: bool,
    }

    impl Defense for TerminalAfterObservation {
        fn observe(&mut self, signal: DefenseSignal) {
            self.failed |= matches!(signal.kind, SignalKind::ApplicationComplete);
        }

        fn next_event(&mut self, _elapsed: Duration) -> Option<Packet> {
            None
        }

        fn next_event_at(&self) -> Option<Duration> {
            None
        }

        fn is_complete(&self) -> bool {
            false
        }

        fn is_outgoing_complete(&self) -> bool {
            false
        }

        fn terminal_failure(&self) -> Option<&'static str> {
            self.failed
                .then_some("synthetic terminal realization failure")
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }
    }

    #[test]
    fn reduced_terminal_defense_failure_is_a_prompt_typed_run_abort() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::<TerminalAfterObservation>::default(),
        )
        .expect("synthetic controller");
        controller.observe(QcsdObservation::ApplicationComplete, Duration::ZERO);

        ensure_defense_realizable(&controller).expect("queued signal is not reduced early");
        controller.flush_defense_observations();
        let error = ensure_defense_realizable(&controller).expect_err("terminal failure aborts");
        assert!(matches!(
            error,
            Error::RunAborted(message) if message == "synthetic terminal realization failure"
        ));
    }

    #[test]
    fn walkie_talkie_batch_gate_only_counts_active_application_streams() {
        let active_application = application(None, false);
        assert!(has_in_flight_application_stream([&active_application]));

        let mut completed_application = application(Some(200), true);
        completed_application.outcome = "succeeded";
        assert!(!has_in_flight_application_stream([&completed_application]));

        let mut chaff = application(None, false);
        chaff.role = QcsdRequestRole::Chaff {
            resource_id: 1,
            request_id: None,
        };
        assert!(!has_in_flight_application_stream([&chaff]));
        assert!(!has_in_flight_application_stream(std::iter::empty::<
            &StreamRecord,
        >()));
    }

    #[test]
    fn application_length_hint_caps_body_without_adding_receive_reserve() {
        let mut resource = Resource {
            id: 1,
            url: "https://example.com/resource".into(),
            kind: "Document".into(),
            content_length: Some(125_959),
            data_length: 125_959,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        };
        assert_eq!(
            expected_application_response_length(&resource, 1_048_576),
            Some(125_959)
        );
        resource.data_length = 130_000;
        assert_eq!(
            expected_application_response_length(&resource, 128_000),
            Some(128_000)
        );
        assert_eq!(expected_application_response_length(&resource, 0), None);
        resource.data_length = u64::MAX;
        assert_eq!(
            expected_application_response_length(&resource, u64::MAX),
            Some(u64::MAX)
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the cross-layer receive-credit lifecycle is one regression oracle"
    )]
    fn exact_application_response_consumes_scheduled_credit_without_retiring_reserve() {
        let resource = Resource {
            id: 1,
            url: "https://example.com/resource".into(),
            kind: "Document".into(),
            content_length: Some(100),
            data_length: 100,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        };
        let expected_response_length = expected_application_response_length(&resource, 1_024);
        assert_eq!(expected_response_length, Some(100));

        // The 100-byte body occupies 131 raw request-stream bytes. The
        // controller learns the 31 framing bytes from HTTP/3 observations;
        // the 1,000-byte receive reserve must not become expected body work.
        let first = Packet::new(Duration::ZERO, Direction::Incoming, 84).expect("first slot");
        let framing =
            Packet::new(Duration::from_micros(1), Direction::Incoming, 31).expect("framing slot");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::new([first, framing]), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint,
                origin: "https://example.com".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("body credit")
        else {
            panic!("expected body receive credit");
        };
        assert_eq!(absolute_limit, 100);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 31,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                frame_header_bytes: 2,
                data_bytes: 100,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 69,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied { slot: satisfied, .. }) if satisfied == slot
        ));

        controller.poll(Duration::from_micros(1));
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("framing credit")
        else {
            panic!("expected framing receive credit");
        };
        assert_eq!(absolute_limit, 131);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 31,
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(1),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied { slot: satisfied, .. }) if satisfied == slot
        ));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 115);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 115);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn event_trace_flushes_endpoint_drain_order_as_global_production_order() {
        let output = trace_output_dir("causal-event-order");
        let started = now();
        let clock = QcsdObservationClock::new(started);
        let first = clock.record_at(
            QcsdObservation::ApplicationBatchStarted,
            started + Duration::from_micros(1),
        );
        let second = clock.record_at(
            QcsdObservation::ApplicationComplete,
            started + Duration::from_micros(2),
        );
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        // Persist in the opposite order to model endpoint-at-a-time draining.
        traces
            .observation(Some(QcsdEndpointId(1)), &second)
            .expect("later observation");
        traces
            .observation(Some(QcsdEndpointId(0)), &first)
            .expect("earlier observation");
        traces.flush_events().expect("causal event flush");
        drop(traces);

        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        let rows: Vec<_> = events.lines().collect();
        assert_eq!(rows.len(), 3);
        assert!(rows[1].starts_with("1,0,observation,recorded,"));
        assert!(rows[1].contains("\"\"production_sequence\"\":0"));
        assert!(rows[2].starts_with("2,1,observation,recorded,"));
        assert!(rows[2].contains("\"\"production_sequence\"\":1"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn trace_files_preserve_historical_prefixes_and_append_typed_outcome_v1() {
        let output = trace_output_dir("typed-outcome-columns");
        let started = now();
        let clock = QcsdObservationClock::new(started);
        let endpoint = QcsdEndpointId(7);
        let slot = QcsdSlotId(31);
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 600).expect("packet");
        let composition = QcsdSlotComposition {
            desired_udp_bytes: 600,
            observed_udp_bytes: 400,
            application_stream_bytes: 100,
            retransmission_stream_bytes: 50,
            chaff_stream_bytes: 75,
            defense_control_bytes: 1,
            quic_padding_bytes: 100,
            other_quic_bytes: 74,
            lateness_us: 23,
        };
        let outcome = QcsdSlotOutcome::Partial {
            composition,
            reason: QcsdCongestionReason::CongestionLimited,
        };
        let qcsd = QcsdTraceColumns::from_outcome(packet, outcome);
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        traces
            .packet(&PacketTraceRow {
                now: started,
                endpoint,
                direction: "outgoing",
                observed: 400,
                scheduled: Some(400),
                satisfaction: "partial",
                slot: Some(slot),
                qcsd,
            })
            .expect("packet row");
        traces
            .schedule(&ScheduleTraceRow {
                action_time_us: 0,
                endpoint: Some(endpoint),
                packet,
                satisfaction: "partial",
                observed: Some(400),
                miss_reason: "CongestionLimited",
                slot,
                qcsd,
            })
            .expect("schedule row");
        let observation = clock.record(QcsdObservation::SlotResolved {
            endpoint,
            slot,
            packet,
            outcome,
        });
        traces
            .observation(Some(endpoint), &observation)
            .expect("event row");
        traces.flush_events().expect("events");

        // Explicit finalization, rather than Drop, must make all three buffered
        // trace streams visible before run.json is written.
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packets");
        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert!(packets.lines().next().expect("header").starts_with(
            "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction,slot_id,"
        ));
        assert!(
            events
                .lines()
                .next()
                .expect("header")
                .starts_with("monotonic_us,connection,event,outcome,details,")
        );
        assert!(schedule.lines().next().expect("header").starts_with(
            "target_time_us,direction,size,connection,action_time_us,satisfaction,observed_size,miss_reason,slot_id,"
        ));
        let expected_suffix =
            ",1,congestion_sensitive,600,400,100,50,75,1,100,74,23,congestion_limited,,,,";
        assert!(
            packets
                .lines()
                .nth(1)
                .expect("packet row")
                .ends_with(expected_suffix)
        );
        assert!(
            events
                .lines()
                .nth(1)
                .expect("event row")
                .ends_with(expected_suffix)
        );
        assert!(
            schedule
                .lines()
                .nth(1)
                .expect("schedule row")
                .ends_with(expected_suffix)
        );
        drop(traces);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn logical_slot_registration_allows_strict_incoming_continuation() {
        let output = trace_output_dir("logical-slot");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let slot = QcsdSlotId(7);

        traces
            .register_incoming_action(
                started + Duration::from_micros(3),
                QcsdEndpointId(1),
                QcsdStreamId(0),
                116,
                packet,
                slot,
            )
            .expect("first stream fragment");
        traces
            .register_incoming_action(
                started + Duration::from_micros(6),
                QcsdEndpointId(1),
                QcsdStreamId(0),
                131,
                packet,
                slot,
            )
            .expect("later receive-limit continuation");
        traces
            .register_incoming_action(
                started + Duration::from_micros(7),
                QcsdEndpointId(1),
                QcsdStreamId(4),
                216,
                packet,
                slot,
            )
            .expect("stream fan-out");
        traces
            .register_incoming_action(
                started + Duration::from_micros(8),
                QcsdEndpointId(2),
                QcsdStreamId(0),
                16,
                packet,
                slot,
            )
            .expect("endpoint reassignment");
        assert!(traces.is_slot_pending(slot));
        traces
            .schedule(&ScheduleTraceRow {
                action_time_us: 99,
                endpoint: Some(QcsdEndpointId(2)),
                packet,
                satisfaction: "missed",
                observed: None,
                miss_reason: "EndpointClosed",
                slot,
                qcsd: QcsdTraceColumns::default(),
            })
            .expect("terminal row");
        assert!(
            traces
                .register_incoming_action(
                    started + Duration::from_micros(9),
                    QcsdEndpointId(2),
                    QcsdStreamId(0),
                    32,
                    packet,
                    slot,
                )
                .is_err()
        );
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("EndpointClosed,7"));
        let fields: Vec<_> = schedule
            .lines()
            .nth(1)
            .expect("terminal row")
            .split(',')
            .collect();
        assert_eq!(fields[4], "3");
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn pending_incoming_slot_rejects_duplicate_regressing_and_cross_kind_reuse() {
        let output = trace_output_dir("invalid-incoming-slot-reuse");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let slot = QcsdSlotId(8);
        traces
            .register_incoming_action(
                started,
                QcsdEndpointId(1),
                QcsdStreamId(0),
                116,
                packet,
                slot,
            )
            .expect("initial incoming action");

        for invalid_limit in [116, 115] {
            assert!(
                traces
                    .register_incoming_action(
                        started,
                        QcsdEndpointId(1),
                        QcsdStreamId(0),
                        invalid_limit,
                        packet,
                        slot,
                    )
                    .is_err()
            );
        }
        let different_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 101).expect("different packet");
        assert!(
            traces
                .register_incoming_action(
                    started,
                    QcsdEndpointId(1),
                    QcsdStreamId(4),
                    216,
                    different_packet,
                    slot,
                )
                .is_err()
        );
        let outgoing_packet =
            Packet::new(Duration::ZERO, Direction::Outgoing, 100).expect("outgoing packet");
        assert!(
            traces
                .register_slot(started, QcsdEndpointId(1), outgoing_packet, slot)
                .is_err()
        );
        drop(traces);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn consumed_incoming_slot_is_serialized_as_terminally_satisfied() {
        let output = trace_output_dir("consumed-incoming-slot");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let endpoint = QcsdEndpointId(1);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let slot = QcsdSlotId(21);
        traces
            .register_incoming_action(started, endpoint, QcsdStreamId(0), 116, packet, slot)
            .expect("incoming registration");
        let advertisement = QcsdObservationClock::new(started).record_at(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: QcsdStreamId(0),
                absolute_limit: 116,
                slot: Some(slot),
            },
            started + Duration::from_micros(3),
        );
        traces
            .observation(Some(endpoint), &advertisement)
            .expect("credit advertisement");

        assert!(
            record_terminal_action(
                &mut traces,
                started + Duration::from_micros(7),
                7,
                "recorded",
                &QcsdAction::SlotSatisfied {
                    endpoint: Some(endpoint),
                    packet,
                    slot,
                },
            )
            .expect("terminal action")
        );
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        let row = schedule.lines().nth(1).expect("terminal row");
        let mut fields = row.split(',');
        assert_eq!(fields.nth(1), Some("incoming"));
        assert_eq!(fields.nth(3), Some("satisfied"));
        assert_eq!(fields.next(), Some(""));
        assert_eq!(fields.next(), Some(""));
        assert_eq!(fields.next(), Some("21"));
        assert_eq!(fields.next(), Some("2"));
        assert_eq!(fields.next(), Some("exact"));
        assert!(schedule.contains("credit_advertised_at_us"));
        assert!(schedule.contains("credit_consumed_at_us"));
        assert!(row.ends_with(",3,3,7,7"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn outgoing_slot_registration_rejects_pending_and_terminal_reuse() {
        let output = trace_output_dir("outgoing-slot-reuse");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 100).expect("packet");
        let slot = QcsdSlotId(11);

        traces
            .register_slot(started, QcsdEndpointId(1), packet, slot)
            .expect("first registration");
        assert!(
            traces
                .register_slot(started, QcsdEndpointId(1), packet, slot)
                .is_err()
        );
        traces
            .schedule(&ScheduleTraceRow {
                action_time_us: 0,
                endpoint: Some(QcsdEndpointId(1)),
                packet,
                satisfaction: "missed",
                observed: None,
                miss_reason: "RunAborted",
                slot,
                qcsd: QcsdTraceColumns::default(),
            })
            .expect("terminal row");
        assert!(
            traces
                .register_slot(started, QcsdEndpointId(1), packet, slot)
                .is_err()
        );
        drop(traces);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn action_batch_allows_increasing_incoming_credit_continuation_and_fanout() {
        let output = trace_output_dir("action-batch-fanout");
        let started = now();
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let slot = QcsdSlotId(13);
        let incoming = |endpoint, stream, absolute_limit| QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(endpoint),
            stream: QcsdStreamId(stream),
            absolute_limit,
            packet,
            slot,
        };

        let mut valid = TraceFiles::new(&output, started).expect("trace files");
        let fanout = register_action_batch(
            &mut valid,
            started,
            &[incoming(1, 0, 116), incoming(2, 4, 216)],
        )
        .expect("cross-endpoint receive-credit fanout");
        assert_eq!(fanout, std::iter::once(slot).collect());
        assert!(valid.is_slot_pending(slot));
        assert!(
            register_action_batch(
                &mut valid,
                started + Duration::from_micros(1),
                &[incoming(1, 0, 131)],
            )
            .expect("later action-batch continuation")
            .is_empty()
        );
        drop(valid);
        fs::remove_dir_all(&output).expect("remove valid trace test directory");

        fs::create_dir_all(&output).expect("recreate trace test directory");
        let mut duplicate = TraceFiles::new(&output, started).expect("trace files");
        register_action_batch(&mut duplicate, started, &[incoming(1, 0, 116)])
            .expect("initial target");
        assert!(
            register_action_batch(
                &mut duplicate,
                started + Duration::from_micros(1),
                &[incoming(1, 0, 116)],
            )
            .is_err()
        );
        assert!(
            register_action_batch(
                &mut duplicate,
                started + Duration::from_micros(2),
                &[incoming(1, 0, 115)],
            )
            .is_err()
        );
        drop(duplicate);
        fs::remove_dir_all(&output).expect("remove duplicate trace test directory");

        fs::create_dir_all(&output).expect("recreate trace test directory");
        let mut outgoing = TraceFiles::new(&output, started).expect("trace files");
        let outgoing_packet =
            Packet::new(Duration::ZERO, Direction::Outgoing, 100).expect("packet");
        let send = QcsdAction::SendPacket {
            endpoint: QcsdEndpointId(1),
            packet: outgoing_packet,
            slot,
            not_before_after_us: 0,
            deadline_after_us: 1,
            allow_stream_data: false,
            send_policy: QcsdSendPolicy::Exact,
        };
        assert!(register_action_batch(&mut outgoing, started, &[send.clone(), send]).is_err());
        drop(outgoing);
        fs::remove_dir_all(output).expect("remove outgoing trace test directory");
    }

    #[test]
    fn parser_lease_is_not_a_schedule_slot_and_slot_has_one_terminal_row() {
        let output = trace_output_dir("parser-lease-not-scheduled");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let endpoint = QcsdEndpointId(1);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 3).expect("packet");
        let slot = QcsdSlotId(17);
        let actions = [
            QcsdAction::LeaseParserReceive {
                endpoint,
                stream: QcsdStreamId(0),
                absolute_limit: 20,
                increase: 16,
                owner: None,
            },
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream: QcsdStreamId(0),
                absolute_limit: 4,
                packet,
                slot,
            },
        ];
        assert!(
            register_action_batch(&mut traces, started, &actions)
                .expect("lease plus scheduled action")
                .is_empty()
        );
        assert!(traces.is_slot_pending(slot));
        assert!(
            record_terminal_action(
                &mut traces,
                started + Duration::from_micros(5),
                5,
                "recorded",
                &QcsdAction::SlotSatisfied {
                    endpoint: Some(endpoint),
                    packet,
                    slot,
                },
            )
            .expect("one terminal action")
        );
        assert!(matches!(
            record_terminal_action(
                &mut traces,
                started + Duration::from_micros(6),
                6,
                "recorded",
                &QcsdAction::SlotSatisfied {
                    endpoint: Some(endpoint),
                    packet,
                    slot,
                },
            ),
            Err(Error::SlotInvariant(message))
                if message == "slot 17 reached more than one terminal state"
        ));
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("satisfied"));
        assert!(!schedule.contains("parser"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn owned_parser_lease_records_issuance_as_the_slot_action_time() {
        let output = trace_output_dir("owned-parser-lease-action-time");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let endpoint = QcsdEndpointId(1);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let slot = QcsdSlotId(23);
        let lease = QcsdAction::LeaseParserReceive {
            endpoint,
            stream: QcsdStreamId(4),
            absolute_limit: 27,
            increase: 10,
            owner: Some(QcsdParserLeaseOwner { packet, slot }),
        };

        assert!(
            register_action_batch(&mut traces, started + Duration::from_micros(3), &[lease])
                .expect("owned parser lease")
                .is_empty()
        );
        assert!(traces.is_slot_pending(slot));
        assert!(
            record_terminal_action(
                &mut traces,
                started + Duration::from_micros(9),
                9,
                "recorded",
                &QcsdAction::SlotSatisfied {
                    endpoint: Some(endpoint),
                    packet,
                    slot,
                },
            )
            .expect("terminal action")
        );
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        let fields: Vec<_> = schedule
            .lines()
            .nth(1)
            .expect("terminal row")
            .split(',')
            .collect();
        assert_eq!(fields[4], "3");
        assert_eq!(fields[5], "satisfied");
        assert_eq!(fields[8], "23");
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn missing_adapter_terminalizes_an_owned_parser_lease_once() {
        let output = trace_output_dir("owned-parser-lease-missing-adapter");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let mut controller =
            QcsdController::new(QcsdConfig::default(), 0, None).expect("controller");
        let endpoint = QcsdEndpointId(9);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let slot = QcsdSlotId(24);
        let lease = QcsdAction::LeaseParserReceive {
            endpoint,
            stream: QcsdStreamId(4),
            absolute_limit: 27,
            increase: 10,
            owner: Some(QcsdParserLeaseOwner { packet, slot }),
        };
        let mut endpoints = Vec::new();

        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started + Duration::from_micros(3),
            Duration::from_micros(3),
            vec![lease],
        )
        .expect("missing adapter is a terminal slot outcome");
        traces.ensure_no_pending_slots().expect("terminal slot");
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        let fields: Vec<_> = schedule
            .lines()
            .nth(1)
            .expect("terminal row")
            .split(',')
            .collect();
        assert_eq!(fields[4], "3");
        assert_eq!(fields[5], "missed");
        assert_eq!(fields[7], "EndpointClosed");
        assert_eq!(fields[8], "24");
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn adapter_errors_use_specific_send_reasons_and_abort_other_actions() {
        let send = QcsdAction::SendPacket {
            endpoint: QcsdEndpointId(1),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 100).expect("packet"),
            slot: QcsdSlotId(1),
            not_before_after_us: 0,
            deadline_after_us: 1,
            allow_stream_data: false,
            send_policy: QcsdSendPolicy::Exact,
        };
        assert_eq!(
            action_failure_reason(
                &send,
                &neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput),
            ),
            MissedSlotReason::PathMtu
        );
        assert_eq!(
            action_failure_reason(
                &send,
                &neqo_http3::Error::Transport(neqo_transport::Error::NotAvailable),
            ),
            MissedSlotReason::KeysUnavailable
        );
        assert_eq!(
            action_failure_reason(&send, &neqo_http3::Error::InvalidState),
            MissedSlotReason::RunAborted
        );

        let receive = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(0),
            absolute_limit: 116,
            packet: Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet"),
            slot: QcsdSlotId(2),
        };
        assert_eq!(
            action_failure_reason(
                &receive,
                &neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput),
            ),
            MissedSlotReason::RunAborted
        );
    }

    #[test]
    fn receive_batch_preflight_uses_virtual_high_water_and_rejects_one_stream_transitively() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let other_stream = QcsdStreamId(8);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let scheduled = |stream, absolute_limit, slot| QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit,
            packet,
            slot: QcsdSlotId(slot),
        };
        let actions = vec![
            scheduled(stream, 26, 1),
            QcsdAction::LeaseParserReceive {
                endpoint,
                stream,
                absolute_limit: 29,
                increase: 3,
                owner: None,
            },
            scheduled(stream, 39, 2),
            scheduled(other_stream, 17, 3),
        ];
        let mut calls = Vec::new();
        let preflight = preflight_receive_actions_with(&actions, |index, _, virtual_limit| {
            calls.push((index, virtual_limit));
            Ok(Some(match index {
                0 | 3 => QcsdReceiveLimitOutcome::Applied,
                1 => QcsdReceiveLimitOutcome::Terminal,
                _ => panic!("rejected suffix must not be previewed independently"),
            }))
        })
        .expect("lifecycle outcomes are cancellable");

        assert_eq!(calls, vec![(0, None), (1, Some(26)), (3, None)]);
        assert_eq!(
            preflight.expected,
            vec![
                Some(QcsdReceiveLimitOutcome::Applied),
                Some(QcsdReceiveLimitOutcome::Terminal),
                Some(QcsdReceiveLimitOutcome::Terminal),
                Some(QcsdReceiveLimitOutcome::Applied),
            ]
        );
        assert_eq!(
            preflight.rejected_streams,
            BTreeMap::from([((endpoint, stream), QcsdReceiveLimitOutcome::Terminal)])
        );

        let fatal = QcsdReceiveLimitError {
            kind: QcsdReceiveLimitFatal::Order,
            requested_limit: 25,
            reference_limit: 26,
        };
        let mut fatal_calls = Vec::new();
        let result = preflight_receive_actions_with(&actions, |index, _, virtual_limit| {
            fatal_calls.push((index, virtual_limit));
            if index == 1 {
                Err(fatal)
            } else {
                Ok(Some(QcsdReceiveLimitOutcome::Applied))
            }
        });
        assert_eq!(result.unwrap_err(), (1, fatal));
        assert_eq!(fatal_calls, vec![(0, None), (1, Some(26))]);
    }

    #[test]
    fn configure_receive_actions_join_typed_batch_preflight() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let actions = vec![
            QcsdAction::ConfigureManualReceive {
                endpoint,
                stream,
                initial_limit: 16,
            },
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: 26,
                packet,
                slot: QcsdSlotId(1),
            },
        ];
        let mut calls = Vec::new();
        let preflight = preflight_receive_actions_with(&actions, |index, _, high_water| {
            calls.push((index, high_water));
            Ok(Some(QcsdReceiveLimitOutcome::FinalKnown))
        })
        .expect("typed configure rejection");
        assert_eq!(calls, vec![(0, None)]);
        assert_eq!(
            preflight.expected,
            vec![
                Some(QcsdReceiveLimitOutcome::FinalKnown),
                Some(QcsdReceiveLimitOutcome::FinalKnown),
            ]
        );

        let automatic = vec![QcsdAction::ConfigureAutomaticReceive {
            endpoint,
            stream,
            window: 1_024,
        }];
        let preflight = preflight_receive_actions_with(&automatic, |_, _, _| {
            Ok(Some(QcsdReceiveLimitOutcome::Terminal))
        })
        .expect("typed automatic no-op");
        assert_eq!(
            preflight.rejected_streams,
            BTreeMap::from([((endpoint, stream), QcsdReceiveLimitOutcome::Terminal)])
        );

        let mixed = vec![
            QcsdAction::ConfigureAutomaticReceive {
                endpoint,
                stream,
                window: 1_024,
            },
            QcsdAction::ConfigureManualReceive {
                endpoint,
                stream,
                initial_limit: 16,
            },
        ];
        let mut calls = Vec::new();
        let preflight = preflight_receive_actions_with(&mixed, |index, _, _| {
            calls.push(index);
            Ok(Some(QcsdReceiveLimitOutcome::Terminal))
        })
        .expect("mixed receive configuration is rejected as one typed stream lifecycle");
        assert_eq!(calls, vec![0]);
        assert_eq!(
            preflight.expected,
            vec![
                Some(QcsdReceiveLimitOutcome::Terminal),
                Some(QcsdReceiveLimitOutcome::Terminal),
            ]
        );
        assert_eq!(
            preflight.rejected_streams,
            BTreeMap::from([((endpoint, stream), QcsdReceiveLimitOutcome::Terminal)])
        );
    }

    #[test]
    fn omitted_pending_suffix_on_transitive_stream_fails_precommit() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(8);
        let prefix = QcsdReceiveActionIdentity::Scheduled {
            endpoint,
            stream,
            absolute_limit: 26,
            slot: QcsdSlotId(1),
        };
        let suffix = QcsdReceiveActionIdentity::Scheduled {
            endpoint,
            stream,
            absolute_limit: 36,
            slot: QcsdSlotId(2),
        };
        let limits = [(endpoint, stream, 26)];
        assert!(pending_receive_identity_is_reconciled(
            &prefix,
            &limits,
            &[suffix],
            &[prefix],
        ));
        assert!(
            !pending_receive_identity_is_reconciled(&prefix, &limits, &[suffix], &[]),
            "retained accepted prefix must biject controller retained ledger"
        );
        assert!(
            !pending_receive_identity_is_reconciled(&suffix, &limits, &[], &[prefix]),
            "pending suffix above cutoff cannot be omitted"
        );
    }

    #[test]
    fn omitted_current_suffix_on_transitive_stream_fails_precommit() {
        let identity = QcsdReceiveActionIdentity::Scheduled {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(8),
            absolute_limit: 36,
            slot: QcsdSlotId(2),
        };
        assert!(!pending_receive_identity_is_reconciled(
            &identity,
            &[(QcsdEndpointId(1), QcsdStreamId(8), 26)],
            &[],
            &[],
        ));
    }

    #[test]
    fn omitted_queued_suffix_on_transitive_stream_fails_precommit() {
        let identity = QcsdReceiveActionIdentity::ParserLease {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(8),
            absolute_limit: 36,
            increase: 10,
            owner: None,
        };
        assert!(!pending_receive_identity_is_reconciled(
            &identity,
            &[(QcsdEndpointId(1), QcsdStreamId(8), 26)],
            &[],
            &[],
        ));
    }

    #[test]
    fn v009_receive_failure_trace_preserves_action_json_and_adds_structured_error() {
        let output = trace_output_dir("v009-receive-action-error");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let action = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(1),
            stream: QcsdStreamId(136),
            absolute_limit: 284_035,
            packet: Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("packet"),
            slot: QcsdSlotId(1_372),
        };
        let error = QcsdReceiveLimitError {
            kind: QcsdReceiveLimitFatal::Ledger,
            requested_limit: 284_035,
            reference_limit: 283_710,
        };
        record_adapter_action_error(
            &mut traces,
            started,
            &action,
            &neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput),
        )
        .expect("record adapter failure");
        record_receive_limit_error(
            &mut traces,
            started + Duration::from_nanos(1),
            &action,
            "preflight",
            error,
        )
        .expect("record typed failure");
        drop(traces);

        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        let adapter_action_row = events
            .lines()
            .find(|row| row.contains(",action,failed,"))
            .expect("adapter action row");
        assert!(adapter_action_row.contains("\"\"type\"\":\"\"increase_receive_limit\"\""));
        assert!(adapter_action_row.contains("\"\"stream\"\":136"));
        assert!(adapter_action_row.contains("\"\"absolute_limit\"\":284035"));
        assert!(adapter_action_row.contains("\"\"slot\"\":1372"));
        let adapter_error_row = events
            .lines()
            .find(|row| row.contains(",action_error,adapter,"))
            .expect("adapter error row");
        assert!(adapter_error_row.contains("\"\"error\"\""));
        assert!(adapter_error_row.contains("Transport error: invalid input"));
        let action_row = events
            .lines()
            .find(|row| row.contains(",action,failed_receive_preflight_ledger,"))
            .expect("failed action row");
        assert!(action_row.contains("\"\"type\"\":\"\"increase_receive_limit\"\""));
        assert!(action_row.contains("\"\"stream\"\":136"));
        assert!(action_row.contains("\"\"absolute_limit\"\":284035"));
        assert!(action_row.contains("\"\"slot\"\":1372"));
        let error_row = events
            .lines()
            .find(|row| row.contains(",action_error,preflight,"))
            .expect("typed error row");
        assert!(error_row.contains("\"\"kind\"\":\"\"ledger\"\""));
        assert!(error_row.contains("\"\"requested_limit\"\":284035"));
        assert!(error_row.contains("\"\"reference_limit\"\":283710"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn terminal_slot_rejects_reuse_for_a_different_packet() {
        let output = trace_output_dir("terminal-slot-packet-reuse");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let different_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 101).expect("different packet");
        let slot = QcsdSlotId(12);

        traces
            .register_incoming_action(
                started,
                QcsdEndpointId(1),
                QcsdStreamId(0),
                116,
                packet,
                slot,
            )
            .expect("registration");
        traces
            .schedule(&ScheduleTraceRow {
                action_time_us: 0,
                endpoint: Some(QcsdEndpointId(1)),
                packet,
                satisfaction: "missed",
                observed: None,
                miss_reason: "RunAborted",
                slot,
                qcsd: QcsdTraceColumns::default(),
            })
            .expect("terminal row");
        assert!(
            traces
                .schedule(&ScheduleTraceRow {
                    action_time_us: 0,
                    endpoint: Some(QcsdEndpointId(1)),
                    packet: different_packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: "RunAborted",
                    slot,
                    qcsd: QcsdTraceColumns::default(),
                })
                .is_err()
        );
        assert!(
            traces
                .register_incoming_action(
                    started,
                    QcsdEndpointId(1),
                    QcsdStreamId(0),
                    131,
                    different_packet,
                    slot,
                )
                .is_err()
        );
        drop(traces);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn terminal_receive_sibling_is_skipped_only_within_its_registered_batch() {
        let output = trace_output_dir("sibling-failure");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let mut controller =
            QcsdController::new(QcsdConfig::default(), 0, None).expect("controller");
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let first = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(9),
            stream: QcsdStreamId(0),
            absolute_limit: 116,
            packet,
            slot: QcsdSlotId(3),
        };
        let second = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(9),
            stream: QcsdStreamId(4),
            absolute_limit: 216,
            packet,
            slot: QcsdSlotId(3),
        };
        let mut endpoints = Vec::new();

        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![first.clone(), second],
        )
        .expect("pre-registered sibling is skipped after the first terminalizes");
        assert!(
            apply_action_batch(
                &mut endpoints,
                &mut controller,
                None,
                &mut traces,
                started,
                Duration::ZERO,
                vec![first],
            )
            .is_err()
        );
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        assert!(events.contains("skipped_terminal_slot"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn run_end_terminalizes_controller_only_slots() {
        let output = trace_output_dir("controller-only");
        let started = now();
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
        controller.poll(Duration::ZERO);
        assert_eq!(controller.pending_slots(), [(QcsdSlotId(0), packet)]);
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            started,
            Duration::ZERO,
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize controller slot");
        traces
            .ensure_no_pending_slots()
            .expect("no adapter backlog");
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("RunAborted,0"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn run_end_retires_registered_incoming_slot_with_one_terminal_row() {
        let output = trace_output_dir("registered-incoming-abort");
        let started = now();
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let slot = QcsdSlotId(0);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
        controller.poll(Duration::ZERO);
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        traces
            .register_incoming_action(
                started,
                QcsdEndpointId(7),
                QcsdStreamId(0),
                116,
                packet,
                slot,
            )
            .expect("registered incoming action");

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            started + Duration::from_micros(9),
            Duration::from_micros(9),
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize registered incoming slot");
        traces.ensure_no_pending_slots().expect("no trace backlog");
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        assert_eq!(schedule.matches("RunAborted").count(), 1);
        let fields: Vec<_> = schedule
            .lines()
            .nth(1)
            .expect("terminal row")
            .split(',')
            .collect();
        assert_eq!(fields[7], "RunAborted");
        assert_eq!(fields[8], "0");
        assert_eq!(fields[9], "2");
        assert_eq!(fields[10], "exact");
        assert_eq!(fields[11], "100");
        assert!(fields[12..].iter().all(|field| field.is_empty()));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn run_end_records_queued_controller_terminal_action() {
        let output = trace_output_dir("queued-controller-terminal");
        let started = now();
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
        controller.poll(Duration::ZERO);
        assert!(controller.pending_slots().is_empty());
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            started,
            Duration::ZERO,
            MissedSlotReason::DeadlineExpired,
        )
        .expect("record queued terminal action");
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("NoEndpoint,0"));
        assert!(!schedule.contains("DeadlineExpired,0"));
        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        assert!(events.contains("terminalized_queued"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn application_404_is_a_failed_resource() {
        let mut record = application(Some(404), true);
        assert_eq!(
            finish_application_record(&mut record),
            ResourceRunState::Failed
        );
        assert_eq!(record.outcome, "failed");
    }

    #[test]
    fn application_redirect_is_recorded_without_following_it() {
        let mut record = application(Some(302), true);
        record
            .response_headers
            .push(("location".into(), "https://other.example/".into()));
        assert_eq!(
            finish_application_record(&mut record),
            ResourceRunState::Failed
        );
        assert_eq!(record.url, "https://example.com/resource");
        assert_eq!(record.outcome, "failed");
    }

    #[test]
    fn reset_application_is_a_failed_resource() {
        let mut record = application(Some(200), false);
        assert_eq!(
            finish_application_record(&mut record),
            ResourceRunState::Failed
        );
        assert_eq!(record.outcome, "failed");
    }

    #[test]
    fn completed_qualified_chaff_is_succeeded_only_after_exact_identity_match() {
        let mut record = chaff(b"compact body", true);
        finish_chaff_record(&mut record, neqo_transport::StreamId::new(4))
            .expect("exact qualified identity");

        assert_eq!(record.outcome, "succeeded");
        let receipt = super::chaff_response_result(&record).expect("receipt");
        assert_eq!(receipt.identity_verified, Some(true));
        assert_eq!(receipt.status_match, Some(true));
        assert_eq!(receipt.content_encoding_match, Some(true));
        assert_eq!(receipt.body_bytes_match, Some(true));
        assert_eq!(receipt.body_sha256_match, Some(true));
    }

    #[test]
    fn completed_chaff_mismatch_is_terminal_and_preserves_identity_evidence() {
        let mut record = chaff(b"compact body", true);
        record.status = Some(404);
        assert!(finish_chaff_record(&mut record, neqo_transport::StreamId::new(8)).is_err());

        assert_eq!(record.outcome, "identity_mismatch");
        let receipt = super::chaff_response_result(&record).expect("receipt");
        assert_eq!(receipt.status, Some(404));
        assert_eq!(receipt.status_match, Some(false));
        assert_eq!(receipt.identity_verified, Some(false));
        assert!(receipt.body_sha256.is_some());
    }

    #[test]
    fn malformed_or_duplicate_chaff_content_encoding_is_not_identity() {
        for response_headers in [
            vec![("content-encoding".into(), "gzip, br".into())],
            vec![
                ("content-encoding".into(), "gzip".into()),
                ("content-encoding".into(), "br".into()),
            ],
        ] {
            let mut record = chaff(b"compact body", true);
            record.response_headers = response_headers;
            assert!(finish_chaff_record(&mut record, neqo_transport::StreamId::new(12)).is_err());
            let receipt = super::chaff_response_result(&record).expect("total receipt");
            assert_eq!(receipt.content_encoding, None);
            assert_eq!(receipt.content_encoding_match, Some(false));
            assert_eq!(receipt.identity_verified, Some(false));
            assert_eq!(record.outcome, "identity_mismatch");
        }
    }

    #[test]
    fn partial_chaff_termination_keeps_null_identity_fields_and_exact_outcome() {
        for outcome in ["in_flight", "reset", "endpoint_closed"] {
            let mut record = chaff(b"prefix", false);
            record.outcome = outcome;
            finish_chaff_record(&mut record, neqo_transport::StreamId::new(16))
                .expect("partial response is not an identity contradiction");
            assert_eq!(
                record.outcome,
                if outcome == "in_flight" {
                    "incomplete"
                } else {
                    outcome
                }
            );
            let receipt = super::chaff_response_result(&record).expect("partial receipt");
            assert_eq!(receipt.status, None);
            assert_eq!(receipt.content_encoding, None);
            assert_eq!(receipt.body_sha256, None);
            assert_eq!(receipt.status_match, None);
            assert_eq!(receipt.content_encoding_match, None);
            assert_eq!(receipt.body_bytes_match, None);
            assert_eq!(receipt.body_sha256_match, None);
            assert_eq!(receipt.identity_verified, None);
        }
    }

    #[test]
    fn fin_overflow_preserves_response_limit_cause() {
        let mut record = chaff(b"one byte too many", true);
        record.outcome = "response_limit";
        record
            .expected_chaff_response
            .as_mut()
            .expect("expected identity")
            .body_bytes = record.bytes.saturating_sub(1);
        finish_chaff_record(&mut record, neqo_transport::StreamId::new(20))
            .expect("caller owns the terminal overflow error");

        assert_eq!(record.outcome, "response_limit");
        let receipt = super::chaff_response_result(&record).expect("overflow receipt");
        assert_eq!(receipt.body_bytes_match, Some(false));
        assert_eq!(receipt.identity_verified, Some(false));
    }

    #[test]
    fn response_qualification_distinguishes_absent_invalid_and_duplicate_content_encoding() {
        assert_eq!(qualification_content_encoding(&[]), Some("identity".into()));
        assert_eq!(
            qualification_content_encoding(&[neqo_common::Header::new("content-encoding", "Br")]),
            Some("br".into())
        );
        assert_eq!(
            qualification_content_encoding(&[neqo_common::Header::new("content-encoding", [0xff])]),
            None
        );
        assert_eq!(
            qualification_content_encoding(&[
                neqo_common::Header::new("content-encoding", "gzip"),
                neqo_common::Header::new("content-encoding", "br"),
            ]),
            None
        );
        assert_eq!(
            qualification_content_encoding(&[neqo_common::Header::new(
                "content-encoding",
                "gzip, br"
            )]),
            None
        );
    }

    #[test]
    fn sustained_response_qualification_preserves_nonidentity_content_encoding_evidence() {
        assert_eq!(
            sustained_qualification_content_encoding(&[]).expect("absent encoding"),
            "identity"
        );
        assert_eq!(
            sustained_qualification_content_encoding(&[neqo_common::Header::new(
                "content-encoding",
                " Identity ",
            )])
            .expect("normalized identity"),
            "identity"
        );
        assert_eq!(
            sustained_qualification_content_encoding(&[
                neqo_common::Header::new("content-encoding", "GZIP"),
                neqo_common::Header::new("content-encoding", "Br"),
            ])
            .expect("duplicate valid fields"),
            "gzip, br"
        );
        assert_eq!(
            sustained_qualification_content_encoding(&[neqo_common::Header::new(
                "content-encoding",
                "GZIP, BR",
            )])
            .expect("coding stack evidence"),
            "gzip, br"
        );
        for invalid in [
            neqo_common::Header::new("content-encoding", [0xff]),
            neqo_common::Header::new("content-encoding", "  "),
        ] {
            assert!(sustained_qualification_content_encoding(&[invalid]).is_err());
        }
    }

    #[test]
    fn identity_chaff_projection_is_order_independent_but_exact_and_lowercase() {
        let mut resource = Resource {
            id: 7,
            url: "https://example.com/site.css".into(),
            kind: "Stylesheet".into(),
            content_length: Some(1_463),
            data_length: 1_463,
            chaff_priority: false,
            known_valid: true,
            depends_on: vec![0],
            headers: vec![
                ("accept-language".into(), "en-AU".into()),
                ("user-agent".into(), "browser".into()),
                ("accept".into(), "text/html".into()),
                ("accept-encoding".into(), "gzip, br".into()),
            ],
        };
        assert_eq!(
            projected_identity_chaff_headers(&resource).expect("identity projection"),
            [
                ("accept".into(), "text/html".into()),
                ("accept-encoding".into(), "identity".into()),
                ("accept-language".into(), "en-AU".into()),
            ]
        );

        resource.headers.push(("Accept".into(), "duplicate".into()));
        assert!(projected_identity_chaff_headers(&resource).is_err());
        resource.headers.pop();
        resource.headers[2].0 = "Accept".into();
        assert!(projected_identity_chaff_headers(&resource).is_err());
    }

    fn sustained_request(request_index: usize) -> ResponseQualificationRequest {
        ResponseQualificationRequest {
            request_index,
            stream_id: u64::try_from(request_index).expect("request index") * 4,
            request_stream_bytes: 169,
            status: Some(200),
            content_encoding: Some("identity".into()),
            body_bytes: 1_463,
            body_sha256: Some("a".repeat(64)),
            complete: true,
            outcome: "complete",
        }
    }

    #[test]
    fn sustained_response_classification_checks_all_forty_and_prioritizes_capacity() {
        let mut requests: Vec<_> = (0..40).map(sustained_request).collect();
        assert!(sustained_requests_are_classifiable(&requests));
        assert_eq!(sustained_representation_failure(&requests), None);

        requests[35].body_sha256 = Some("b".repeat(64));
        assert_eq!(
            sustained_representation_failure(&requests),
            Some("identity")
        );
        requests[35].body_bytes = 1_199;
        assert_eq!(
            sustained_representation_failure(&requests),
            Some("capacity")
        );

        requests[35].body_bytes = 1_463;
        requests[35].body_sha256 = Some("a".repeat(64));
        requests[35].content_encoding = Some("gzip, br".into());
        assert_eq!(
            sustained_representation_failure(&requests),
            Some("identity")
        );
        requests[35].content_encoding = Some("identity".into());
        requests[35].status = Some(404);
        assert_eq!(
            sustained_representation_failure(&requests),
            Some("identity")
        );

        requests[35].status = None;
        assert!(!sustained_requests_are_classifiable(&requests));
    }

    #[test]
    fn sustained_request_adds_wave_index_without_changing_legacy_request_shape() {
        let legacy = sustained_request(35);
        let legacy_value = serde_json::to_value(&legacy).expect("legacy request value");
        assert!(legacy_value.get("wave_index").is_none());

        let sustained = SustainedResponseQualificationRequest {
            request_index: legacy.request_index,
            wave_index: legacy.request_index / 5,
            stream_id: legacy.stream_id,
            request_stream_bytes: legacy.request_stream_bytes,
            status: legacy.status,
            content_encoding: legacy.content_encoding,
            body_bytes: legacy.body_bytes,
            body_sha256: legacy.body_sha256,
            complete: legacy.complete,
            outcome: legacy.outcome,
        };
        let sustained_value = serde_json::to_value(&sustained).expect("sustained request value");
        assert_eq!(sustained_value["wave_index"], 7);
        assert_eq!(
            sustained_value.as_object().expect("request object").len(),
            legacy_value
                .as_object()
                .expect("legacy request object")
                .len()
                + 1
        );
    }

    #[test]
    fn sustained_response_cli_mode_requires_the_exact_paired_40_by_5_contract() {
        assert_eq!(
            response_qualification_mode(5, None, None).expect("legacy mode"),
            ResponseQualificationMode::Legacy
        );
        assert_eq!(
            response_qualification_mode(
                5,
                Some(40),
                Some(ChaffRequestHeaderModeArg::IdentityChaffV1),
            )
            .expect("sustained mode"),
            ResponseQualificationMode::SustainedIdentity
        );
        for (parallel, total, header_mode) in [
            (5, Some(40), None),
            (5, None, Some(ChaffRequestHeaderModeArg::IdentityChaffV1)),
            (
                4,
                Some(40),
                Some(ChaffRequestHeaderModeArg::IdentityChaffV1),
            ),
            (
                6,
                Some(40),
                Some(ChaffRequestHeaderModeArg::IdentityChaffV1),
            ),
            (
                5,
                Some(39),
                Some(ChaffRequestHeaderModeArg::IdentityChaffV1),
            ),
        ] {
            assert!(response_qualification_mode(parallel, total, header_mode).is_err());
        }
    }

    #[test]
    fn response_qualification_ignores_queued_data_readable_after_fin_retirement() {
        let stream_id = neqo_transport::StreamId::new(12);
        let mut streams = HashMap::from([(
            stream_id,
            QualifierStream {
                request_index: 3,
                stream_id,
                request_stream_bytes: 169,
                status: Some(200),
                content_encoding: Some("br".into()),
                body: Vec::new(),
                body_bytes: 0,
                complete: false,
                outcome: "in_flight",
            },
        )]);
        let mut completed = Vec::new();
        let mut read_calls = 0;
        let events = [
            neqo_http3::Http3ClientEvent::DataReadable { stream_id },
            neqo_http3::Http3ClientEvent::DataReadable { stream_id },
        ];

        for event in events {
            let neqo_http3::Http3ClientEvent::DataReadable { stream_id } = event else {
                unreachable!("fixture contains only data-readable events")
            };
            drain_qualifier_stream_data(&mut streams, &mut completed, stream_id, 1_024, |buffer| {
                read_calls += 1;
                assert_eq!(read_calls, 1, "stale event must not read a retired stream");
                buffer[..4].copy_from_slice(b"body");
                Ok((4, true))
            })
            .expect("duplicate data-readable event is harmless");
        }

        assert_eq!(read_calls, 1);
        assert!(streams.is_empty());
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].body, b"body");
        assert!(completed[0].complete);
        assert_eq!(completed[0].outcome, "complete");

        let unknown = neqo_transport::StreamId::new(16);
        let error =
            drain_qualifier_stream_data(&mut streams, &mut completed, unknown, 1_024, |_| {
                panic!("unknown stream must fail before an HTTP/3 read")
            })
            .expect_err("a genuinely unknown stream remains fail-closed");
        assert!(matches!(
            error,
            Error::RunAborted(message)
                if message == "data arrived for an unknown qualifier stream"
        ));
    }

    #[test]
    fn profile_cli_resolves_baseline() {
        let baseline = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::None),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("live baseline profile");
        assert_eq!(baseline.defense, DefenseConfig::None);
    }

    #[test]
    fn profile_cli_accepts_only_the_exact_research_1200_token() {
        let parse = |profile| {
            Args::try_parse_from([
                "neqo-qcsd-client",
                "run",
                "https://example.com/",
                "--profile",
                profile,
                "--defense",
                "none",
                "--seed",
                "7",
                "--output-dir",
                "output",
                "--max-response-bytes",
                "4096",
            ])
        };

        assert!(parse("research-1200").is_ok());
        for invalid in ["research_1200", "research1200", "Research-1200"] {
            assert!(parse(invalid).is_err());
        }
    }

    #[test]
    fn profile_cli_resolves_research_1200() {
        let front = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Research1200),
            Some(DefenseArg::Front),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("research-1200 FRONT profile");
        assert_eq!(front.max_udp_payload_size, 1_200);
        assert_eq!(
            front.defense,
            DefenseConfig::Front(FrontConfig {
                n_client_packets: 900,
                n_server_packets: 1_200,
                packet_size: 1_200,
                peak_minimum_seconds: 0.1,
                peak_maximum_seconds: 2.5,
            })
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the single table-style test deliberately covers every CLI defense"
    )]
    fn profile_cli_resolves_every_defense() {
        let front = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::Front),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("live FRONT profile");
        assert!(matches!(
            front.defense,
            DefenseConfig::Front(FrontConfig { .. })
        ));

        let tamaraw = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::Tamaraw),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("live Tamaraw profile");
        assert!(matches!(
            tamaraw.defense,
            DefenseConfig::Tamaraw(TamarawConfig { .. })
        ));

        let static_config = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::Static),
            Some(std::path::Path::new("schedule.csv")),
            Some(StaticModeArg::ChaffOnly),
            None,
            None,
            None,
        )
        .expect("live Static profile");
        assert_eq!(
            static_config.defense,
            DefenseConfig::Static {
                schedule: "schedule.csv".into(),
                padding_only: true,
            }
        );

        let traffic_morphing = resolve_run_config_with_workload(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::TrafficMorphing),
            None,
            None,
            None,
            None,
            Some(std::path::Path::new("matrix.json")),
            None,
            None,
            Some("test-workload"),
        )
        .expect("live Traffic Morphing profile");
        assert!(matches!(
            traffic_morphing.defense,
            DefenseConfig::TrafficMorphing(_)
        ));

        let wtf_pad = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::WtfPad),
            None,
            None,
            None,
            Some(std::path::Path::new("histograms.json")),
            None,
        )
        .expect("live WTF-PAD profile");
        assert!(matches!(wtf_pad.defense, DefenseConfig::WtfPad(_)));

        let walkie_talkie = resolve_run_config_with_workload(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::WalkieTalkie),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(std::path::Path::new("molded.json")),
            Some("test-workload"),
        )
        .expect("live Walkie-Talkie profile");
        assert!(matches!(
            walkie_talkie.defense,
            DefenseConfig::WalkieTalkie(_)
        ));
    }

    #[test]
    fn walkie_talkie_enables_transport_stream_send_shaping() {
        assert!(!shapes_stream_sends(&DefenseConfig::None));
        assert!(shapes_stream_sends(&DefenseConfig::Tamaraw(
            TamarawConfig::default()
        )));
        assert!(shapes_stream_sends(&DefenseConfig::Buflo(
            neqo_csdef::BufloConfig {
                parameters: "buflo.json".into(),
            }
        )));
        assert!(shapes_stream_sends(&DefenseConfig::CsBuflo(
            neqo_csdef::CsBufloConfig {
                parameters: "cs-buflo.json".into(),
            }
        )));
        assert!(shapes_stream_sends(&DefenseConfig::WalkieTalkie(
            WalkieTalkieConfig::default()
        )));
        assert!(shapes_stream_sends(&DefenseConfig::Static {
            schedule: "schedule.csv".into(),
            padding_only: false,
        }));
        assert!(!shapes_stream_sends(&DefenseConfig::Static {
            schedule: "schedule.csv".into(),
            padding_only: true,
        }));
        assert!(!shapes_stream_sends(&DefenseConfig::Front(
            FrontConfig::default()
        )));
        assert!(!shapes_stream_sends(&DefenseConfig::TrafficMorphing(
            TrafficMorphingConfig::default()
        )));
        assert!(!shapes_stream_sends(&DefenseConfig::WtfPad(
            WtfPadConfig::default()
        )));
    }

    #[test]
    fn old_presets_remain_profile_aliases() {
        let front = resolve_run_config(
            None,
            Some(Preset::PublishedFront),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("compatibility preset");
        assert_eq!(front.defense, DefenseConfig::Front(FrontConfig::default()));
        let tamaraw = resolve_run_config(
            None,
            Some(Preset::PublishedTamaraw),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("published Tamaraw compatibility preset");
        assert_eq!(
            tamaraw.defense,
            DefenseConfig::Tamaraw(TamarawConfig::default())
        );
        let live = resolve_run_config(
            None,
            Some(Preset::ConservativeLive),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("conservative live compatibility preset");
        assert!(matches!(live.defense, DefenseConfig::Front(_)));
    }

    #[test]
    fn custom_toml_remains_available() {
        let path = std::env::temp_dir().join(format!(
            "neqo-qcsd-runner-config-{}.toml",
            std::process::id()
        ));
        fs::write(&path, "schema_version = 2\n[defense]\nkind = \"none\"\n")
            .expect("write custom config");
        let config =
            resolve_run_config(Some(&path), None, None, None, None, None, None, None, None)
                .expect("custom configuration");
        assert_eq!(config.defense, DefenseConfig::None);
        fs::remove_file(path).expect("remove custom config");
    }

    #[test]
    fn static_cli_requires_schedule_and_mode() {
        assert!(
            resolve_run_config(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::Static),
                None,
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn reactive_cli_requires_its_own_parameter_file_and_rejects_foreign_files() {
        assert!(
            resolve_run_config_with_workload(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::TrafficMorphing),
                None,
                None,
                None,
                None,
                Some(std::path::Path::new("matrix.json")),
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            resolve_run_config(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::WtfPad),
                None,
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            resolve_run_config(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::Front),
                None,
                None,
                Some(std::path::Path::new("matrix.json")),
                None,
                None,
            )
            .is_err()
        );
        assert!(
            resolve_run_config(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::TrafficMorphing),
                None,
                None,
                Some(std::path::Path::new("matrix.json")),
                Some(std::path::Path::new("histograms.json")),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn buflo_parameter_flags_are_required_scoped_and_keep_ctsp_cpsp_distinct() {
        let buflo_path = std::path::Path::new("buflo.json");
        let ctsp_path = std::path::Path::new("cs-buflo-ctsp.json");
        let cpsp_path = std::path::Path::new("cs-buflo-cpsp.json");
        assert!(
            resolve_run_config_with_workload(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::Buflo),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        let buflo = resolve_run_config_with_workload(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::Buflo),
            None,
            None,
            Some(buflo_path),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("BuFLO parameter override");
        assert!(matches!(
            &buflo.defense,
            DefenseConfig::Buflo(config) if config.parameters == "buflo.json"
        ));

        let resolve_cs = |parameters| {
            resolve_run_config_with_workload(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::CsBuflo),
                None,
                None,
                None,
                Some(parameters),
                None,
                None,
                None,
                None,
            )
        };
        let total_payload = resolve_cs(ctsp_path).expect("CTSP override");
        let payload_payload = resolve_cs(cpsp_path).expect("CPSP override");
        assert!(matches!(
            &total_payload.defense,
            DefenseConfig::CsBuflo(config) if config.parameters == "cs-buflo-ctsp.json"
        ));
        assert!(matches!(
            &payload_payload.defense,
            DefenseConfig::CsBuflo(config) if config.parameters == "cs-buflo-cpsp.json"
        ));
        assert!(
            resolve_run_config_with_workload(
                None,
                None,
                Some(ProfileArg::Live),
                Some(DefenseArg::Buflo),
                None,
                None,
                Some(buflo_path),
                Some(ctsp_path),
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn external_defense_parameters_have_raw_sha256_provenance() {
        test_fixture::fixture_init();
        let path = std::env::temp_dir().join(format!(
            "neqo-qcsd-defense-parameters-{}",
            std::process::id()
        ));
        fs::write(&path, b"abc").expect("write parameter fixture");
        let config = QcsdConfig {
            defense: DefenseConfig::Static {
                schedule: path.to_string_lossy().into_owned(),
                padding_only: true,
            },
            ..QcsdConfig::default()
        };
        let provenance = defense_parameter_provenance(&config)
            .expect("hash parameter file")
            .expect("file-backed defense");
        assert_eq!(provenance.kind, "static");
        assert_eq!(provenance.implementation_scope, None);
        assert_eq!(provenance.early_termination_semantics, None);
        assert_eq!(
            provenance.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        for (defense, expected_kind) in [
            (
                DefenseConfig::Buflo(neqo_csdef::BufloConfig {
                    parameters: path.to_string_lossy().into_owned(),
                }),
                "buflo",
            ),
            (
                DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
                    parameters: path.to_string_lossy().into_owned(),
                }),
                "cs_buflo",
            ),
        ] {
            let config = QcsdConfig {
                defense,
                ..QcsdConfig::default()
            };
            let provenance = defense_parameter_provenance(&config)
                .expect("hash parameter file")
                .expect("file-backed defense");
            assert_eq!(provenance.kind, expected_kind);
            assert_eq!(provenance.implementation_scope, Some("client_only_quic"));
            assert_eq!(provenance.paper_equivalent, Some(false));
            if expected_kind == "cs_buflo" {
                assert_eq!(
                    provenance.early_termination_semantics,
                    Some("udp_client_only_observed_udp_power_of_two_crossing")
                );
                assert_eq!(provenance.reference_tcp_write_size_bytes, Some(548));
                assert_eq!(
                    provenance.reference_nominal_tcp_packet_size_bytes,
                    Some(600)
                );
            } else {
                assert_eq!(provenance.early_termination_semantics, None);
                assert_eq!(provenance.reference_tcp_write_size_bytes, None);
                assert_eq!(provenance.reference_nominal_tcp_packet_size_bytes, None);
            }
            assert_eq!(
                provenance.sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }
        fs::remove_file(path).expect("remove parameter fixture");
    }

    #[test]
    fn datagram_observations_use_only_the_defense_clock() {
        assert_eq!(
            datagram_observation(QcsdEndpointId(1), Direction::Incoming, 1_200, None,),
            None
        );

        let elapsed = Duration::from_micros(12_345);
        let (observation, at) =
            datagram_observation(QcsdEndpointId(7), Direction::Outgoing, 1_234, Some(elapsed))
                .expect("post-start datagram");
        assert_eq!(at, elapsed);
        assert_eq!(
            observation,
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(7),
                direction: Direction::Outgoing,
                length: 1_234,
                timestamp_us: 12_345,
            }
        );
    }

    #[test]
    fn runner_uses_absolute_target_wakeups_and_refreshes_now() {
        let first_drive = now();
        let callback_delay = Duration::from_millis(10);
        let first_wakeup =
            absolute_wakeup(first_drive, callback_delay).expect("first absolute wakeup");

        let refreshed_drive = first_drive + Duration::from_millis(3);
        let refreshed_wakeup =
            absolute_wakeup(refreshed_drive, callback_delay).expect("refreshed absolute wakeup");
        assert_eq!(first_wakeup, first_drive + callback_delay);
        assert_eq!(refreshed_wakeup, refreshed_drive + callback_delay);
        assert_eq!(
            refreshed_wakeup.duration_since(first_wakeup),
            Duration::from_millis(3)
        );
    }

    #[test]
    fn runner_rechecks_due_target_before_sleep() {
        let base = now();
        let wakeup = base + Duration::from_millis(10);
        assert_eq!(
            remaining_wakeup_delay(wakeup, base + Duration::from_millis(9)),
            Some(Duration::from_millis(1))
        );
        assert_eq!(remaining_wakeup_delay(wakeup, wakeup), None);
        assert_eq!(
            remaining_wakeup_delay(wakeup, wakeup + Duration::from_nanos(1)),
            None
        );
    }

    #[test]
    fn target_socket_backpressure_aborts_without_retrying_committed_datagram() {
        let deadline = now() + Duration::from_millis(5);
        let mut attempts = 0;
        let error = attempt_socket_handoff(
            &[deadline],
            || {
                attempts += 1;
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            },
            now,
        )
        .expect_err("target-bearing WouldBlock must abort");
        assert_eq!(attempts, 1, "a committed defense datagram is never retried");
        assert!(matches!(
            error,
            Error::SlotInvariant(message) if message.contains("socket backpressure")
        ));

        assert_eq!(
            attempt_socket_handoff(
                &[],
                || Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                now,
            )
            .expect("unshaped datagrams retain ordinary readiness retry"),
            SocketHandoff::RetryUnshaped
        );
    }

    #[test]
    fn target_socket_handoff_must_precede_absolute_adapter_deadline() {
        let base = now();
        let deadline = base + Duration::from_millis(5);
        let before_deadline = deadline
            .checked_sub(Duration::from_nanos(1))
            .expect("deadline has a predecessor");
        assert_eq!(
            attempt_socket_handoff(&[deadline], || Ok(()), || before_deadline)
                .expect("pre-deadline handoff"),
            SocketHandoff::Sent(before_deadline)
        );

        for sent_at in [deadline, deadline + Duration::from_nanos(1)] {
            let error = attempt_socket_handoff(&[deadline], || Ok(()), || sent_at)
                .expect_err("at-or-after-deadline handoff must reject the run");
            assert!(matches!(
                error,
                Error::SlotInvariant(message) if message.contains("adapter deadline")
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn past_runner_wakeup_yields_and_services_socket_readiness_before_retry() {
        let socket = Socket::bind("127.0.0.1:0").expect("receiver socket");
        let local_addr = socket.local_addr().expect("receiver address");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
        let sender_polled = Arc::new(AtomicBool::new(false));
        let sender_polled_in_task = Arc::clone(&sender_polled);
        let sender_task = tokio::spawn(async move {
            sender_polled_in_task.store(true, Ordering::SeqCst);
            sender
                .send_to(&[1], local_addr)
                .expect("send datagram after runner yields");
        });
        assert!(!sender_polled.load(Ordering::SeqCst));

        wait_for_activity_until([&socket], now())
            .await
            .expect("expired wakeup must still service reactor readiness");
        assert!(
            sender_polled.load(Ordering::SeqCst),
            "an expired wakeup must yield instead of starting an await-free retry loop"
        );
        tokio::time::timeout(Duration::from_secs(1), sender_task)
            .await
            .expect("sender task timeout")
            .expect("sender task failure");
        let mut recv_buf = RecvBuf::default();
        assert!(
            socket
                .recv(local_addr, &mut recv_buf)
                .expect("receive queued datagram")
                .is_some(),
            "an expired controller wakeup must not bypass the reactor"
        );
    }

    #[test]
    fn qcsd_runner_discovers_only_above_the_fixed_path_payload() {
        let mut config = QcsdConfig {
            max_udp_payload_size: 1_200,
            ..QcsdConfig::default()
        };
        let ipv4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let ipv4_params = qcsd_connection_parameters(&config, ipv4);
        let ipv6_params = qcsd_connection_parameters(&config, ipv6);
        assert_eq!(ipv4_params.get_max_udp_payload_size(), 1_200);
        assert_eq!(ipv6_params.get_max_udp_payload_size(), 1_200);
        assert!(!ipv4_params.pmtud_enabled());
        assert!(!ipv6_params.pmtud_enabled());

        config.max_udp_payload_size = 1_240;
        assert!(!qcsd_connection_parameters(&config, ipv4).pmtud_enabled());
        assert!(qcsd_connection_parameters(&config, ipv6).pmtud_enabled());

        config.max_udp_payload_size = 1_252;
        assert!(!qcsd_connection_parameters(&config, ipv4).pmtud_enabled());
        config.max_udp_payload_size = 1_253;
        assert!(qcsd_connection_parameters(&config, ipv4).pmtud_enabled());

        config.max_udp_payload_size = 1_232;
        assert!(!qcsd_connection_parameters(&config, ipv6).pmtud_enabled());
        config.max_udp_payload_size = 1_233;
        assert!(qcsd_connection_parameters(&config, ipv6).pmtud_enabled());

        config.max_udp_payload_size = 1_450;
        assert!(qcsd_connection_parameters(&config, ipv4).pmtud_enabled());
        assert!(qcsd_connection_parameters(&config, ipv6).pmtud_enabled());

        config.max_udp_payload_size = 1_200;
        config.defense = DefenseConfig::Front(FrontConfig::default());
        assert!(!qcsd_connection_parameters(&config, ipv4).pmtud_enabled());
    }

    #[test]
    fn walkie_talkie_alone_advertises_zero_initial_request_stream_credit() {
        let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut config = QcsdConfig {
            initial_max_stream_data: 16,
            max_udp_payload_size: 1_200,
            defense: DefenseConfig::Front(FrontConfig::default()),
            ..QcsdConfig::default()
        };
        assert_eq!(
            qcsd_connection_parameters(&config, remote_ip)
                .get_max_stream_data(StreamType::BiDi, false),
            16
        );

        config.defense = DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default());
        assert_eq!(
            qcsd_connection_parameters(&config, remote_ip)
                .get_max_stream_data(StreamType::BiDi, false),
            0
        );
    }

    #[tokio::test]
    async fn socket_readiness_preempts_the_absolute_runner_timer() {
        let socket = Socket::bind("127.0.0.1:0").expect("receiver socket");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
        sender
            .send_to(&[1], socket.local_addr().expect("receiver address"))
            .expect("queue datagram");

        let wake = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_activity_until([&socket], now() + Duration::from_secs(60)),
        )
        .await
        .expect("readiness should beat the timeout")
        .expect("readiness wait");
        assert_eq!(wake, ActivityWake::SocketReady);
    }

    #[tokio::test]
    async fn empty_socket_wait_reaches_the_absolute_runner_deadline() {
        let deadline = now() + Duration::from_millis(1);
        let wake = wait_for_activity_until(std::iter::empty(), deadline)
            .await
            .expect("timer wait");
        assert_eq!(wake, ActivityWake::Timer);
        assert!(now() >= deadline);
    }

    #[test]
    fn runner_wakeup_metrics_partition_actual_select_returns() {
        let mut metrics = RunnerWakeupMetrics::new();
        metrics.record(ActivityWake::SocketReady, true);
        metrics.record(ActivityWake::Timer, false);
        metrics.record(ActivityWake::Timer, true);
        assert_eq!(metrics.schema_version, 1);
        assert_eq!(metrics.wait_returns, 3);
        assert_eq!(metrics.socket_readiness_wakeups, 1);
        assert_eq!(metrics.timer_wakeups, 2);
        assert_eq!(metrics.controller_deadline_timer_wakeups, 1);
        assert_eq!(metrics.other_timer_wakeups, 1);
        assert_eq!(
            metrics.timer_wakeups,
            metrics.controller_deadline_timer_wakeups + metrics.other_timer_wakeups
        );
        assert!(
            metrics
                .semantics
                .contains("scheduled_cells_are_not_wakeups")
        );
    }

    #[test]
    fn qualification_wait_is_capped_by_its_inner_deadline() {
        let deadline = now() + Duration::from_millis(25);
        let bounded = bounded_qualification_wait(Duration::from_secs(60), deadline, 30)
            .expect("positive remaining deadline");
        assert!(bounded <= Duration::from_millis(25));
        assert!(bounded > Duration::ZERO);
        assert!(matches!(
            bounded_qualification_wait(Duration::from_secs(60), now(), 30),
            Err(Error::Timeout(30))
        ));
    }

    fn two_stage_prefix_spec() -> PrefixPackSpec {
        PrefixPackSpec {
            schema_version: 2,
            artifact_type: "qcsd-walkie-talkie-prefix-pack-spec".into(),
            workload_id: "capacity-test".into(),
            packet_size: 1_200,
            max_stream_data_excess: 1_000,
            maximum_receiver_continuation_reserve_horizon: 2,
            required_chaff_survivors: 3,
            numeric_profile_sha256: "a".repeat(64),
            source_walkie_talkie_artifact_sha256: "b".repeat(64),
            application_resource_id: 0,
            selected_chaff_resource_id: 6,
            selected_chaff_body_bytes: 10_000,
            required_chaff_streams: 4,
            numeric_profile: PrefixNumericProfile {
                bursts: vec![
                    PrefixBurst {
                        incoming: 2,
                        outgoing: 1,
                    },
                    PrefixBurst {
                        incoming: 2,
                        outgoing: 1,
                    },
                ],
                packet_size: 1_200,
            },
            stream_activation_stages: vec![
                StreamActivationStage {
                    component_index: 0,
                    application_resource_ids: vec![0],
                    exact_target_cells: 1,
                    outgoing_cells: 1,
                    symmetric_incoming_cells: 1,
                    adapted_incoming_cells: 2,
                    application_body_floor_bytes: 200,
                    base_chaff_bytes: 1_000,
                    continuation_bytes: 1_200,
                    required_active_chaff_streams: 3,
                    newly_required_chaff_streams: 3,
                    future_continuation_reserves: 2,
                    exact_capacity_before_bytes: 30_000,
                    ordinary_capacity_before_bytes: 10_000,
                    exact_capacity_after_bytes: 27_800,
                    early_continuation_required: false,
                },
                StreamActivationStage {
                    component_index: 1,
                    application_resource_ids: vec![1],
                    exact_target_cells: 1,
                    outgoing_cells: 1,
                    symmetric_incoming_cells: 1,
                    adapted_incoming_cells: 2,
                    application_body_floor_bytes: 1_200,
                    base_chaff_bytes: 0,
                    continuation_bytes: 1_200,
                    required_active_chaff_streams: 4,
                    newly_required_chaff_streams: 1,
                    future_continuation_reserves: 1,
                    exact_capacity_before_bytes: 37_800,
                    ordinary_capacity_before_bytes: 27_800,
                    exact_capacity_after_bytes: 36_600,
                    early_continuation_required: false,
                },
            ],
        }
    }

    #[test]
    fn prefix_capacity_plan_covers_every_component_and_checks_exact_recurrence() {
        let spec = two_stage_prefix_spec();
        validate_prefix_capacity_plan(&spec).expect("valid exact recurrence");

        let mut one_adapted_cell = two_stage_prefix_spec();
        one_adapted_cell.numeric_profile.bursts[1].incoming = 1;
        one_adapted_cell.stream_activation_stages[1].adapted_incoming_cells = 1;
        one_adapted_cell.stream_activation_stages[1].symmetric_incoming_cells = 0;
        validate_prefix_capacity_plan(&one_adapted_cell)
            .expect("one adapted incoming cell has zero symmetric base cells");
        one_adapted_cell.stream_activation_stages[1].symmetric_incoming_cells = 1;
        assert!(validate_prefix_capacity_plan(&one_adapted_cell).is_err());

        let mut mutated = two_stage_prefix_spec();
        mutated.stream_activation_stages[1].ordinary_capacity_before_bytes += 1;
        assert!(validate_prefix_capacity_plan(&mutated).is_err());

        let mut sparse = two_stage_prefix_spec();
        sparse.stream_activation_stages.pop();
        assert!(validate_prefix_capacity_plan(&sparse).is_err());
    }

    #[test]
    fn prefix_stage_gate_allows_later_cohort_to_begin_early_but_not_activate_early() {
        let app_acks = Vec::<QualificationAcknowledgement>::new();
        let chaff_acks: Vec<_> = (0..4)
            .map(|index| {
                vec![QualificationAcknowledgement {
                    sequence: index,
                    offset: 0,
                    bytes: 10,
                    fin: true,
                }]
            })
            .collect();
        let mut receipts = vec![PrefixStreamReceipt {
            request_order: 0,
            opening_stage_index: 0,
            role: "application",
            resource_id: 0,
            request_id: None,
            stream_id: 0,
            request_stream_bytes: 10,
            qualified_request_stream_bytes: None,
            transmitted_unique_ranges: vec![[0, 10]],
            transmitted_unique_bytes: 10,
            fin_transmitted: true,
            acknowledgements: &app_acks,
            acknowledged_unique_ranges: Vec::new(),
            acknowledged_unique_bytes: 0,
            fin_acknowledged: false,
        }];
        for (index, acknowledgements) in chaff_acks.iter().enumerate().take(4) {
            let complete = index < 3;
            receipts.push(PrefixStreamReceipt {
                request_order: index + 1,
                opening_stage_index: 0,
                role: "chaff",
                resource_id: 6,
                request_id: Some(u64::try_from(index).expect("small index")),
                stream_id: u64::try_from(index + 1).expect("small index"),
                request_stream_bytes: 10,
                qualified_request_stream_bytes: Some(10),
                transmitted_unique_ranges: vec![[0, if complete { 10 } else { 5 }]],
                transmitted_unique_bytes: if complete { 10 } else { 5 },
                fin_transmitted: complete,
                acknowledgements,
                acknowledged_unique_ranges: vec![[0, 10]],
                acknowledged_unique_bytes: 10,
                fin_acknowledged: true,
            });
        }
        assert!(prefix_receipts_pass(&receipts, 3));
        assert!(!prefix_receipts_pass(&receipts, 4));
        receipts[4].transmitted_unique_ranges = vec![[0, 10]];
        receipts[4].transmitted_unique_bytes = 10;
        receipts[4].fin_transmitted = true;
        assert!(prefix_receipts_pass(&receipts, 4));
    }

    #[test]
    fn prefix_stream_ownership_rejects_none_or_undeclared_slots() {
        let slots = BTreeSet::from([1, 2]);
        let transmission = |slot| QcsdStreamTransmission {
            sequence: 0,
            stream: QcsdStreamId(7),
            role: None,
            offset: 0,
            bytes: 5,
            fin: false,
            slot,
        };
        assert_eq!(
            prefix_targetless_stream_bytes(
                &[
                    transmission(Some(QcsdSlotId(1))),
                    transmission(Some(QcsdSlotId(2)))
                ],
                &slots,
            ),
            0
        );
        assert_eq!(
            prefix_targetless_stream_bytes(&[transmission(None)], &slots),
            5
        );
        assert_eq!(
            prefix_targetless_stream_bytes(&[transmission(Some(QcsdSlotId(99)))], &slots),
            5
        );
    }
}
