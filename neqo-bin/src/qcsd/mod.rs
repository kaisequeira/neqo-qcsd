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
    ChaffManifest, DefenseConfig, DefenseDiagnostics, DefenseKind, DependencyTracker, Direction,
    ExpectedChaffResponse, MissedSlotReason, Packet, QcsdAction, QcsdChaffRequestId, QcsdConfig,
    QcsdController, QcsdEndpointId, QcsdObservation, QcsdObservationClock, QcsdProfile,
    QcsdRequestRole, QcsdSlotId, QcsdStreamTransmission, Resource, ResourceManifest,
    ResourceRunState, StaticMode, TimestampedQcsdObservation, TrafficMorphingEgress, WalkieTalkie,
    derive, normalize_content_encoding, sanitize_chaff_headers,
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

use trace_files::{PacketTraceRow, ScheduleTraceRow, TraceFiles};

const NEQO_BASE_COMMIT: &str = "8a04d065c2d35c8e8fd804f91c7081ab6bb60b89";
const PUBLISHED_QCSD_COMMIT: &str = "39e293fb384dd341156eedd1e4b833d24904b1f6";

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

impl From<StaticModeArg> for StaticMode {
    fn from(value: StaticModeArg) -> Self {
        match value {
            StaticModeArg::ChaffOnly => Self::ChaffOnly,
            StaticModeArg::ChaffAndShape => Self::ChaffAndShape,
        }
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
    /// Qualify five concurrent compact navigation-root responses over HTTP/3.
    QualifyChaffResponse {
        /// Exact frozen prepared application source (A); response preparation metadata is not
        /// used.
        #[arg(long)]
        workload: PathBuf,
        /// Dependency-free application navigation root to project to AEL.
        #[arg(long)]
        application_resource_id: u32,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 5)]
        parallel_requests: usize,
        #[arg(long, default_value_t = 1_048_576)]
        max_response_bytes: u64,
        #[arg(long, default_value_t = 1_200)]
        packet_size: u16,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    /// Prove the production first-cell application/chaff request prefix pack.
    QualifyChaffPrefix {
        /// Exact frozen prepared application source (A).
        #[arg(long)]
        workload: PathBuf,
        /// Exact projected runtime workload used by defended execution (R).
        #[arg(long)]
        runtime_workload: PathBuf,
        /// Acyclic compact chaff core derived from response qualification.
        #[arg(long)]
        chaff_core: PathBuf,
        /// Dependency-free application navigation root competing in the cell.
        #[arg(long)]
        application_resource_id: u32,
        /// Standalone immutable numeric Walkie-Talkie prefix-pack specification.
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
        /// Explicit schema-one qualified chaff manifest required by every defended run.
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
                let config = resolve_run_config_with_workload(
                    config.as_deref(),
                    preset,
                    profile,
                    defense,
                    schedule.as_deref(),
                    static_mode,
                    morphing_matrix.as_deref(),
                    wtf_pad_histograms.as_deref(),
                    walkie_talkie_molded.as_deref(),
                    workload_id.as_deref(),
                )?;
                config.validate()?;
                let defense_parameters = defense_parameter_provenance(&config)?;
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
                if !matches!(config.defense, DefenseConfig::None) && chaff_manifest.is_none() {
                    return Err(Error::Argument(
                        "every defended run requires an explicit schema-one qualified --chaff-manifest"
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
                output_dir,
                parallel_requests,
                max_response_bytes,
                packet_size,
                timeout_seconds,
            } => {
                qualify_chaff_response(
                    &workload,
                    application_resource_id,
                    &output_dir,
                    parallel_requests,
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
    morphing_matrix: Option<&Path>,
    wtf_pad_histograms: Option<&Path>,
    walkie_talkie_molded: Option<&Path>,
    workload_id: Option<&str>,
) -> Result<QcsdConfig, Error> {
    let has_defense_options = schedule.is_some()
        || static_mode.is_some()
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
        morphing_matrix,
        wtf_pad_histograms,
        walkie_talkie_molded,
        None,
    )
}

fn reject_foreign_defense_options(
    selected: DefenseArg,
    schedule: Option<&Path>,
    static_mode: Option<StaticModeArg>,
    morphing_matrix: Option<&Path>,
    wtf_pad_histograms: Option<&Path>,
    walkie_talkie_molded: Option<&Path>,
) -> Result<(), Error> {
    let has_foreign = (selected != DefenseArg::Static
        && (schedule.is_some() || static_mode.is_some()))
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
}

fn defense_parameter_provenance(
    config: &QcsdConfig,
) -> Result<Option<DefenseParameterProvenance>, Error> {
    let (kind, path) = match &config.defense {
        DefenseConfig::Static { schedule, .. } => ("static", schedule.as_str()),
        DefenseConfig::TrafficMorphing(config) => ("traffic_morphing", config.matrix.as_str()),
        DefenseConfig::WtfPad(config) => ("wtf_pad", config.histograms.as_str()),
        DefenseConfig::WalkieTalkie(config) => ("walkie_talkie", config.molded.as_str()),
        DefenseConfig::None | DefenseConfig::Front(_) | DefenseConfig::Tamaraw(_) => {
            return Ok(None);
        }
    };
    let contents = fs::read(path)?;
    Ok(Some(DefenseParameterProvenance {
        kind,
        path: path.to_string(),
        sha256: sha256(&contents)?,
    }))
}

struct RunSpec {
    method: &'static str,
    workload: ResourceManifest,
    workload_hash: String,
    application_workload_source: Option<(ResourceManifest, String)>,
    config: QcsdConfig,
    defense_parameters: Option<DefenseParameterProvenance>,
    chaff_manifest: Option<ChaffManifest>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChaffQualificationCore {
    schema_version: u32,
    method: String,
    request_stream_bytes: u64,
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
    numeric_profile: PrefixNumericProfile,
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
    if !resource.known_valid || !resource.depends_on.is_empty() {
        return Err(Error::Argument(
            "chaff response qualification requires a known-valid dependency-free root".into(),
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
            "application root must project exactly one accept, accept-encoding, and accept-language header in that order"
                .into(),
        ));
    }
    Ok(projected)
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

#[expect(
    clippy::future_not_send,
    clippy::too_many_lines,
    reason = "the dedicated qualification loop retains packet and response evidence in one lifecycle"
)]
async fn qualify_chaff_response(
    workload_path: &Path,
    application_resource_id: u32,
    output_dir: &Path,
    parallel_requests: usize,
    max_response_bytes: u64,
    packet_size: u16,
    timeout_seconds: u64,
) -> Result<(), Error> {
    if parallel_requests != 5 || packet_size != 1_200 || max_response_bytes == 0 {
        return Err(Error::Argument(
            "response qualification requires parallel_requests=5, packet_size=1200, and positive max_response_bytes"
                .into(),
        ));
    }
    let (workload, workload_hash) = load_application_workload_source(workload_path)?;
    let resource = workload
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .ok_or_else(|| Error::Argument("application_resource_id is absent from workload".into()))?;
    validate_qualification_application_root(resource, application_resource_id)?;
    let request_headers = projected_ael(resource)?;
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
    let mut opened = false;
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
                        for request_index in 0..parallel_requests {
                            let stream_id =
                                client.qcsd_fetch_nonblocking(loop_now, &url, &headers)?;
                            let request_stream_bytes =
                                client.qcsd_request_stream_bytes(stream_id)?;
                            if request_stream_bytes == 0 {
                                return Err(Error::RunAborted(
                                    "production nonblocking encoder produced an empty request"
                                        .into(),
                                ));
                            }
                            client.stream_close_send(stream_id, loop_now)?;
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
                        }
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
                            record.content_encoding = qualification_content_encoding(&headers);
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
                        let mut buffer = vec![0_u8; 32 * 1024];
                        loop {
                            let (read, fin) = client.read_data(loop_now, stream_id, &mut buffer)?;
                            let record = streams.get_mut(&stream_id).ok_or_else(|| {
                                Error::RunAborted(
                                    "data arrived for an unknown qualifier stream".into(),
                                )
                            })?;
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
            if completed.len() == parallel_requests {
                return Ok(());
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
            wait_for_activity([&socket], delay).await?;
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
    let passed = loop_result.is_ok()
        && requests.len() == parallel_requests
        && requests.iter().all(|request| {
            request.complete
                && request
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
                && request.content_encoding.is_some()
                && request.body_sha256.is_some()
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
        && requests_opened_before_first_network_output == 5
        && qualification_network_output_seen;
    let error = loop_result.as_ref().err().map(ToString::to_string);
    let request_stream_bytes = requests
        .first()
        .map(|request| request.request_stream_bytes)
        .filter(|size| {
            requests
                .iter()
                .all(|request| request.request_stream_bytes == *size)
        });
    let packet_log = serde_json::to_vec(&packet_observations)?;
    atomic_write(&output_dir.join("packets.json"), &packet_log)?;
    let packet_log_sha256 = sha256(&packet_log)?;
    let receipt = json!({
        "schema_version": 1,
        "artifact_type": "qcsd-chaff-response-qualification",
        "invocation_id": format!("{}-{local_addr}", started_unix_ns),
        "neqo_version": env!("CARGO_PKG_VERSION"),
        "application_workload_sha256": workload_hash,
        "application_resource_id": application_resource_id,
        "method": "GET",
        "url": url.to_string(),
        "request_headers": request_headers,
        "parallel_requests": parallel_requests,
        "connection_count": 1,
        "requests_opened_before_first_network_output": requests_opened_before_first_network_output,
        "request_stream_bytes": request_stream_bytes,
        "max_response_bytes": max_response_bytes,
        "udp_payload_ceiling": packet_size,
        "started_unix_ns": started_unix_ns,
        "ended_unix_ns": unix_nanos(),
        "completion_status": if passed { "complete" } else { "error" },
        "error": error,
        "source": {
            "neqo_base_commit": NEQO_BASE_COMMIT,
            "published_qcsd_commit": PUBLISHED_QCSD_COMMIT,
            "migration_commit": option_env!("NEQO_QCSD_GIT_COMMIT").unwrap_or("working-tree"),
        },
        "requests": requests,
        "packet_observations": packet_observations,
        "packet_log_sha256": packet_log_sha256,
        "packets": {
            "incoming": incoming,
            "outgoing": outgoing,
            "total": {
                "packet_count": incoming.packet_count.saturating_add(outgoing.packet_count),
                "observed_udp_payload_max": incoming.observed_udp_payload_max.max(outgoing.observed_udp_payload_max),
                "oversized_packet_count": incoming.oversized_packet_count.saturating_add(outgoing.oversized_packet_count),
            },
        },
        "passed": passed,
    });
    atomic_write(
        &output_dir.join("qualification.json"),
        serde_json::to_string_pretty(&receipt)?.as_bytes(),
    )?;
    if passed {
        Ok(())
    } else {
        Err(loop_result.err().unwrap_or_else(|| {
            Error::RunAborted("chaff response qualification invariants failed".into())
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
    required_chaff_survivors: usize,
) -> bool {
    if receipts.len() != 6
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
    let app = &receipts[0];
    let app_tx_complete = app.role == "application"
        && app.transmitted_unique_ranges == [[0, app.request_stream_bytes]]
        && app.transmitted_unique_bytes == app.request_stream_bytes
        && app.fin_transmitted;
    let chaff_complete = receipts
        .iter()
        .skip(1)
        .take(required_chaff_survivors)
        .all(|receipt| {
            receipt.role == "chaff"
                && receipt.qualified_request_stream_bytes == Some(receipt.request_stream_bytes)
                && receipt.transmitted_unique_ranges == [[0, receipt.request_stream_bytes]]
                && receipt.transmitted_unique_bytes == receipt.request_stream_bytes
                && receipt.fin_transmitted
                && receipt.acknowledged_unique_ranges == [[0, receipt.request_stream_bytes]]
                && receipt.acknowledged_unique_bytes == receipt.request_stream_bytes
                && receipt.fin_acknowledged
        });
    app_tx_complete && chaff_complete
}

fn intentionally_pending_late_chaff(
    requests: &[PrefixRequestStream],
    required_chaff_survivors: usize,
) -> Vec<StreamId> {
    requests
        .iter()
        .skip(required_chaff_survivors.saturating_add(1))
        .map(|request| StreamId::new(request.stream_id))
        .collect()
}

fn record_prefix_observations(
    client: &mut Http3Client,
    requests: &mut [PrefixRequestStream],
    transmissions: &mut Vec<QcsdStreamTransmission>,
) -> Result<bool, Error> {
    transmissions.extend(client.qcsd_stream_transmissions());
    let mut slot_satisfied = false;
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
                slot: QcsdSlotId(1),
                observed_size: 1_200,
                ..
            } => slot_satisfied = true,
            QcsdObservation::SlotMissed {
                slot: QcsdSlotId(1),
                reason,
                ..
            } => {
                return Err(Error::RunAborted(format!(
                    "prefix-pack target was missed: {reason:?}"
                )));
            }
            _ => {}
        }
    }
    Ok(slot_satisfied)
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
    let (application_source, application_source_sha256) =
        load_application_workload_source(application_source_path)?;
    let (runtime_workload, runtime_workload_sha256) = load_manifest(runtime_workload_path)?;
    let (chaff_core, chaff_core_sha256) = load_chaff_core(chaff_core_path)?;
    let (prefix_spec, prefix_pack_spec_sha256) = load_prefix_pack_spec(prefix_pack_spec_path)?;
    validate_prefix_pack_spec(&prefix_spec)?;
    validate_chaff_core_binding(
        &chaff_core,
        &application_source,
        &application_source_sha256,
        application_resource_id,
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
    let mut target_queued = false;
    let mut target_sent = false;
    let mut target_satisfied = false;
    let mut first_target_output_count = 0_u64;
    let mut first_target_output_bytes = 0_u64;
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
                        phase: if target_queued {
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
            if !target_queued && client.qcsd_peer_settings_received() {
                peer_settings_received = true;
                client.qcsd_prepare_stream_output(loop_now);
                if !client.qcsd_has_pending_stream_send() {
                    warmup_stream_output_drained = true;
                    client.qcsd_enable_send_shaping(true);
                    client.qcsd_enable_stream_transcript(true);
                    packet_cutoff_sequence = next_packet_sequence;
                    drop(client.qcsd_timestamped_observations());

                    let app_headers =
                        runtime_workload.application_headers(application_resource_id)?;
                    let app_headers: Vec<_> = app_headers
                        .iter()
                        .map(|(name, value)| Header::new(name.as_str(), value.as_str()))
                        .collect();
                    let app_stream =
                        client.fetch(loop_now, "GET", &url, &app_headers, Priority::default())?;
                    client.register_qcsd_stream(app_stream, QcsdRequestRole::Application, None)?;
                    let app_size = client.qcsd_request_stream_bytes(app_stream)?;
                    client.stream_close_send(app_stream, loop_now)?;
                    requests.push(PrefixRequestStream {
                        request_order: 0,
                        role: "application",
                        resource_id: application_resource_id,
                        request_id: None,
                        stream_id: app_stream.as_u64(),
                        request_stream_bytes: app_size,
                        qualified_request_stream_bytes: None,
                        acknowledgements: Vec::new(),
                    });
                    let core_resource = &chaff_core.resources[0];
                    let compact = core_resource.as_resource();
                    for index in 0..5_usize {
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
                            request_order: index.saturating_add(1),
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
                    let packet =
                        Packet::new(Duration::ZERO, Direction::Outgoing, prefix_spec.packet_size)?;
                    client.apply_qcsd_action(
                        loop_now,
                        QcsdAction::SendPacket {
                            endpoint: QcsdEndpointId(0),
                            packet,
                            slot: QcsdSlotId(1),
                            deadline_after_us: u64::try_from(
                                Duration::from_secs(timeout_seconds).as_micros(),
                            )
                            .unwrap_or(u64::MAX),
                            allow_stream_data: true,
                        },
                    )?;
                    target_queued = true;
                }
            }

            target_satisfied |=
                record_prefix_observations(&mut client, &mut requests, &mut transmissions)?;
            let receipts = prefix_stream_receipts(&requests, &transmissions);
            let allowed_pending =
                intentionally_pending_late_chaff(&requests, prefix_spec.required_chaff_survivors);
            if target_satisfied
                && prefix_receipts_pass(&receipts, prefix_spec.required_chaff_survivors)
                && !client.qcsd_has_pending_stream_send_excluding(&allowed_pending)
            {
                return Ok(());
            }

            let output = client.process_multiple_output(loop_now, NonZeroUsize::MIN);
            target_satisfied |=
                record_prefix_observations(&mut client, &mut requests, &mut transmissions)?;
            let delay = match output {
                OutputBatch::DatagramBatch(batch) => {
                    for datagram in batch.iter() {
                        outgoing.observe(datagram.len(), prefix_spec.packet_size);
                        packet_observations.push(QualificationPacketObservation {
                            sequence: next_packet_sequence,
                            phase: if target_queued {
                                "qualification"
                            } else {
                                "warmup"
                            },
                            direction: "outgoing",
                            udp_payload_bytes: datagram.len(),
                        });
                        next_packet_sequence = next_packet_sequence.saturating_add(1);
                        if target_queued && !target_sent {
                            first_target_output_count = first_target_output_count.saturating_add(1);
                            first_target_output_bytes = first_target_output_bytes
                                .saturating_add(u64::try_from(datagram.len()).unwrap_or(u64::MAX));
                        }
                    }
                    if target_queued {
                        target_sent = true;
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
            wait_for_activity([&socket], delay).await?;
        }
    }
    .await;

    let final_observation_result =
        record_prefix_observations(&mut client, &mut requests, &mut transmissions);
    let stream_receipts = prefix_stream_receipts(&requests, &transmissions);
    let targetless_stream_bytes = transmissions
        .iter()
        .filter(|transmission| transmission.slot != Some(QcsdSlotId(1)))
        .fold(0_u64, |total, transmission| {
            total.saturating_add(transmission.bytes)
        });
    let all_streams_owned = transmissions
        .iter()
        .all(|transmission| transmission.slot == Some(QcsdSlotId(1)));
    let post_slot_pending_stream_send = client.qcsd_has_pending_stream_send();
    let allowed_pending =
        intentionally_pending_late_chaff(&requests, prefix_spec.required_chaff_survivors);
    let allowed_pending_late_chaff_request_orders: Vec<_> = requests
        .iter()
        .skip(prefix_spec.required_chaff_survivors.saturating_add(1))
        .map(|request| request.request_order)
        .collect();
    let allowed_pending_late_chaff_stream_ids: Vec<_> = allowed_pending
        .iter()
        .map(|stream_id| stream_id.as_u64())
        .collect();
    let post_slot_pending_required_stream_send =
        client.qcsd_has_pending_stream_send_excluding(&allowed_pending);
    let passed = loop_result.is_ok()
        && final_observation_result.is_ok()
        && peer_settings_received
        && warmup_stream_output_drained
        && requests.len() == 6
        && target_satisfied
        && first_target_output_count == 1
        && first_target_output_bytes == u64::from(prefix_spec.packet_size)
        && all_streams_owned
        && targetless_stream_bytes == 0
        && prefix_receipts_pass(&stream_receipts, prefix_spec.required_chaff_survivors)
        && !post_slot_pending_required_stream_send
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
    let receipt = json!({
        "schema_version": 1,
        "artifact_type": "qcsd-chaff-prefix-pack-qualification",
        "invocation_id": format!("{}-{local_addr}", started_unix_ns),
        "neqo_version": env!("CARGO_PKG_VERSION"),
        "application_workload_source_sha256": application_source_sha256,
        "runtime_workload_sha256": runtime_workload_sha256,
        "chaff_core_sha256": chaff_core_sha256,
        "prefix_pack_spec_sha256": prefix_pack_spec_sha256,
        "application_resource_id": application_resource_id,
        "workload_id": prefix_spec.workload_id,
        "numeric_profile_sha256": prefix_spec.numeric_profile_sha256,
        "source_walkie_talkie_artifact_sha256": prefix_spec.source_walkie_talkie_artifact_sha256,
        "packet_size": prefix_spec.packet_size,
        "max_stream_data_excess": prefix_spec.max_stream_data_excess,
        "maximum_receiver_continuation_reserve_horizon": prefix_spec.maximum_receiver_continuation_reserve_horizon,
        "required_chaff_survivors": prefix_spec.required_chaff_survivors,
        "max_chaff_streams": 5,
        "connection_count": 1,
        "peer_settings_received": peer_settings_received,
        "warmup_stream_output_drained": warmup_stream_output_drained,
        "packet_cutoff_sequence": packet_cutoff_sequence,
        "requests_opened_before_first_target": requests.len(),
        "scheduled_target": {
            "slot_id": 1,
            "direction": "outgoing",
            "udp_payload_bytes": prefix_spec.packet_size,
            "scheduled_datagrams": 1,
            "scheduled_bytes": prefix_spec.packet_size,
            "satisfied_datagrams": u64::from(target_satisfied),
            "satisfied_bytes": if target_satisfied { prefix_spec.packet_size } else { 0 },
        },
        "streams": stream_receipts,
        "stream_transmissions": transmissions,
        "packet_observations": packet_observations,
        "packet_log_sha256": packet_log_sha256,
        "packets": packets,
        "post_slot_pending_stream_send": post_slot_pending_stream_send,
        "post_slot_pending_required_stream_send": post_slot_pending_required_stream_send,
        "allowed_pending_late_chaff_request_orders": allowed_pending_late_chaff_request_orders,
        "allowed_pending_late_chaff_stream_ids": allowed_pending_late_chaff_stream_ids,
        "targetless_stream_bytes": targetless_stream_bytes,
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

fn load_application_workload_source(path: &Path) -> Result<(ResourceManifest, String), Error> {
    let bytes = fs::read(path)?;
    let source: PreparedWorkloadSource = serde_json::from_slice(&bytes)?;
    if !source.preparation.is_object() || source.replay.is_some() {
        return Err(Error::Argument(
            "application workload source requires preparation metadata and must not contain replay metadata"
                .into(),
        ));
    }
    let manifest = ResourceManifest {
        resources: source.resources,
    };
    manifest.validate()?;
    Ok((manifest, sha256(&bytes)?))
}

fn load_chaff_manifest(path: &Path) -> Result<(ChaffManifest, String), Error> {
    let bytes = fs::read(path)?;
    let manifest = ChaffManifest::from_json(std::str::from_utf8(&bytes).map_err(|_| {
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

fn maximum_receiver_continuation_reserve_horizon(bursts: &[PrefixBurst]) -> usize {
    let mut maximum = 0_usize;
    for (index, burst) in bursts.iter().enumerate() {
        if burst.incoming == 0 {
            continue;
        }
        let mut horizon = 0_usize;
        for (offset, candidate) in bursts[index..].iter().enumerate() {
            if offset > 0 && candidate.outgoing > 0 {
                break;
            }
            horizon = horizon.saturating_add(usize::from(candidate.incoming > 0));
        }
        maximum = maximum.max(horizon);
    }
    maximum
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
    let horizon = maximum_receiver_continuation_reserve_horizon(&spec.numeric_profile.bursts);
    if spec.schema_version != 1
        || spec.artifact_type != "qcsd-walkie-talkie-prefix-pack-spec"
        || spec.workload_id.trim().is_empty()
        || spec.packet_size != 1_200
        || spec.max_stream_data_excess != 1_000
        || spec.numeric_profile.packet_size != spec.packet_size
        || spec.numeric_profile.bursts.is_empty()
        || horizon == 0
        || spec.maximum_receiver_continuation_reserve_horizon != horizon
        || spec.required_chaff_survivors != horizon.saturating_add(1)
        || spec.required_chaff_survivors > 5
        || !lower_hex_sha256(&spec.numeric_profile_sha256)
        || !lower_hex_sha256(&spec.source_walkie_talkie_artifact_sha256)
        || prefix_numeric_profile_sha256(&spec.numeric_profile)? != spec.numeric_profile_sha256
    {
        return Err(Error::Argument(
            "prefix-pack specification schema or numeric derivation is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_chaff_core_binding(
    core: &QualifiedChaffCore,
    workload: &ResourceManifest,
    workload_hash: &str,
    application_resource_id: u32,
) -> Result<(), Error> {
    if core.schema_version != 1
        || core.artifact_type != "qcsd-qualified-chaff-core"
        || core.application_workload_sha256 != workload_hash
        || core.application_resource_id != application_resource_id
        || core.resources.len() != 1
    {
        return Err(Error::Argument(
            "qualified chaff core top-level binding is invalid".into(),
        ));
    }
    let application = workload
        .resources
        .iter()
        .find(|resource| resource.id == application_resource_id)
        .ok_or_else(|| Error::Argument("application root is absent from workload".into()))?;
    validate_qualification_application_root(application, application_resource_id)?;
    let compact_headers = projected_ael(application)?;
    let resource = &core.resources[0];
    let qualification = &resource.chaff_qualification_core;
    let response = &qualification.expected_response;
    if resource.id != application_resource_id
        || resource.url != application.url
        || resource.kind != application.kind
        || resource.chaff_priority != application.chaff_priority
        || !resource.known_valid
        || !resource.depends_on.is_empty()
        || resource.headers != compact_headers
        || qualification.schema_version != 1
        || qualification.method != "GET"
        || qualification.request_stream_bytes == 0
        || !(200..300).contains(&response.status)
        || response.body_bytes < 1_200
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
    spec.workload.validate()?;
    validate_workload_urls(&spec.workload)?;
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
    let chaff = spec.chaff_manifest.as_ref().expect("defended run gate");
    let prefix_spec_hash = &chaff.resources[0].chaff_qualification.prefix_spec_sha256;
    if binding.workload_id != config.workload_id
        || binding.qualified_chaff_manifest_sha256 != chaff_manifest_hash
        || binding.prefix_pack_spec_sha256 != *prefix_spec_hash
    {
        return Err(Error::Argument(
            "Walkie-Talkie selected qualification binding does not match the exact chaff manifest and embedded prefix-pack spec hashes"
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

fn validate_qualified_chaff_binding(spec: &RunSpec) -> Result<(), Error> {
    let Some(chaff) = &spec.chaff_manifest else {
        return Ok(());
    };
    let Some((source, source_hash)) = &spec.application_workload_source else {
        return Err(Error::Argument(
            "qualified chaff requires an exact application workload source binding".into(),
        ));
    };
    if chaff.application_workload_sha256 != *source_hash {
        return Err(Error::Argument(
            "qualified chaff application_workload_sha256 does not match the exact frozen application workload source"
                .into(),
        ));
    }
    let qualified = &chaff.resources[0];
    let application = spec
        .workload
        .resources
        .iter()
        .find(|resource| resource.id == chaff.application_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff application_resource_id is absent from the workload".into(),
            )
        })?;
    let source_application = source
        .resources
        .iter()
        .find(|resource| resource.id == chaff.application_resource_id)
        .ok_or_else(|| {
            Error::Argument(
                "qualified chaff application_resource_id is absent from the frozen source".into(),
            )
        })?;
    if (
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
    ) {
        return Err(Error::Argument(
            "runtime workload and frozen application source disagree on the qualified root request"
                .into(),
        ));
    }
    if !application.depends_on.is_empty() || application.url != qualified.url {
        return Err(Error::Argument(
            "qualified chaff must bind the exact dependency-free application root URL".into(),
        ));
    }
    let projected: Vec<_> = application
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
    if application.kind != qualified.kind
        || application.chaff_priority != qualified.chaff_priority
        || !application.known_valid
        || projected != qualified.headers
    {
        return Err(Error::Argument(
            "qualified chaff root metadata or exact AEL projection does not match its bound application root"
                .into(),
        ));
    }
    let expected = qualified.chaff_qualification.expected_response.body_bytes;
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
            .map(ChaffManifest::resource_manifest),
    )?;
    let mut dependencies = DependencyTracker::new(spec.workload.clone())?;
    let mut defense_start = None;
    let mut application_completion = None;
    let mut application_complete_observed = false;
    let mut application_batches =
        ApplicationBatchLifecycle::new(&spec.config.defense, spec.request_policy);
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

            let mut next_wakeup = spec.config.control_interval();
            for endpoint in &mut endpoints {
                // Flush output that was already available (including newly
                // dispatched application requests) so its Wire signals precede
                // the defense poll.
                let output_now = now();
                let output_elapsed =
                    defense_start.map(|start| output_now.saturating_duration_since(start));
                if let Some(delay) = process_output(
                    endpoint,
                    &mut controller,
                    &mut traces,
                    &observation_clock,
                    output_now,
                    output_elapsed,
                )
                .await?
                {
                    next_wakeup = next_wakeup.min(delay);
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

            for endpoint in &mut endpoints {
                // Retain a post-action flush so newly scheduled packet targets can
                // be placed on the wire without waiting for another loop turn.
                let output_now = now();
                let output_elapsed =
                    defense_start.map(|start| output_now.saturating_duration_since(start));
                if let Some(delay) = process_output(
                    endpoint,
                    &mut controller,
                    &mut traces,
                    &observation_clock,
                    output_now,
                    output_elapsed,
                )
                .await?
                {
                    next_wakeup = next_wakeup.min(delay);
                }
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
                && endpoints.iter().all(|endpoint| {
                    endpoint.scheduled_outgoing.is_empty()
                        && endpoint.client.qcsd_pending_packet_targets() == 0
                })
            {
                traces.ensure_no_pending_slots()?;
                break;
            }
            let wait_now = now();
            if let Some(defense_start) = defense_start
                && let Some(next_deadline) = controller.next_deadline()
            {
                let mut controller_delay =
                    next_deadline.saturating_sub(wait_now.saturating_duration_since(defense_start));
                if controller_delay.is_zero() {
                    controller_delay = Duration::from_micros(1);
                }
                next_wakeup = next_wakeup.min(controller_delay);
            }
            wait_for_activity(
                endpoints.iter().map(|endpoint| &endpoint.socket),
                next_wakeup,
            )
            .await?;
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
            Http3ClientEvent::StateChange(Http3State::Closed(_)) => {
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
        resource.headers = sanitize_chaff_headers(std::mem::take(&mut resource.headers));
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
) -> Result<Vec<(QcsdSlotId, usize)>, Error> {
    let mut scheduled_slots: BTreeSet<_> = endpoint
        .scheduled_outgoing
        .iter()
        .map(|scheduled| scheduled.slot)
        .collect();
    observations
        .iter()
        .filter_map(|record| {
            let observation = record.observation();
            let QcsdObservation::SlotSatisfied {
                slot,
                observed_size,
                ..
            } = observation
            else {
                return None;
            };
            Some(if scheduled_slots.remove(slot) {
                Ok((*slot, usize::from(*observed_size)))
            } else {
                Err(Error::SlotInvariant(format!(
                    "transport satisfied unknown outgoing slot {}",
                    slot.0
                )))
            })
        })
        .collect()
}

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

fn apply_action_batch(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&ChaffManifest>,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    actions: Vec<QcsdAction>,
) -> Result<(), Error> {
    let incoming_fanout_slots = register_action_batch(traces, now, &actions)?;
    for action in actions {
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
        )?;
    }
    Ok(())
}

fn apply_queued_actions(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&ChaffManifest>,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
) -> Result<(), Error> {
    loop {
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

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "action dispatch records every transport and trace outcome in one exhaustive reducer"
)]
fn apply_action(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&ChaffManifest>,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    mut action: QcsdAction,
    may_skip_terminal_sibling: bool,
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
            })?;
        }
        traces.event(now, endpoint_id, "action", "missing_endpoint", &action)?;
        return Ok(());
    };
    let scheduled_packet = match &trace_action {
        QcsdAction::SendPacket { packet, slot, .. } => Some((*packet, *slot)),
        _ => None,
    };
    match endpoint.client.apply_qcsd_action(now, action) {
        Ok(chaff_stream) => {
            if let Some((packet, slot)) = scheduled_packet {
                endpoint
                    .scheduled_outgoing
                    .push_back(ScheduledOutgoing { slot, packet });
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
                            "chaff request lacks a schema-one qualification binding".into(),
                        )
                    })?;
                if request_stream_bytes != qualification.request_stream_bytes {
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
                            expected_request_stream_bytes: Some(qualification.request_stream_bytes),
                            response_headers: Vec::new(),
                            status: None,
                            content_length: None,
                            body: Vec::new(),
                            bytes: 0,
                            complete: false,
                            outcome: "request_size_mismatch",
                            expected_chaff_response: Some(ExpectedChaffIdentity {
                                status: qualification.expected_response.status,
                                content_encoding: qualification
                                    .expected_response
                                    .content_encoding
                                    .clone(),
                                body_bytes: qualification.expected_response.body_bytes,
                                body_sha256: qualification.expected_response.body_sha256.clone(),
                            }),
                        },
                    );
                    return Err(Error::RunAborted(format!(
                        "chaff request stream encoded {request_stream_bytes} bytes, expected qualified size {}",
                        qualification.request_stream_bytes
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
                        expected_request_stream_bytes: Some(qualification.request_stream_bytes),
                        response_headers: Vec::new(),
                        status: None,
                        content_length: None,
                        body: Vec::new(),
                        bytes: 0,
                        complete: false,
                        outcome: "in_flight",
                        expected_chaff_response: chaff_manifest
                            .and_then(|manifest| manifest.qualification(resource_id))
                            .map(|qualification| ExpectedChaffIdentity {
                                status: qualification.expected_response.status,
                                content_encoding: qualification
                                    .expected_response
                                    .content_encoding
                                    .clone(),
                                body_bytes: qualification.expected_response.body_bytes,
                                body_sha256: qualification.expected_response.body_sha256.clone(),
                            }),
                    },
                );
                // Apply manual receive control before the newly created chaff
                // request is eligible for its first transport output.
                handle_qcsd_observations(endpoint, controller, traces, defense_elapsed)?;
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
                })?;
            }
            traces.event(now, endpoint_id, "action", "failed", &error.to_string())?;
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

async fn wait_for_activity<'a>(
    sockets: impl IntoIterator<Item = &'a Socket>,
    delay: Duration,
) -> Result<(), Error> {
    let readiness: Vec<_> = sockets
        .into_iter()
        .map(|socket| Box::pin(socket.readable()))
        .collect();
    if readiness.is_empty() {
        tokio::time::sleep(delay).await;
        return Ok(());
    }
    let sockets_ready = select_all(readiness).map(|(result, _, _)| result);
    let timeout_ready = Box::pin(tokio::time::sleep(delay).map(|()| Ok(())));
    select(sockets_ready, timeout_ready)
        .map(|either| either.factor_first().0)
        .await?;
    Ok(())
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

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn process_output(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    base_now: Instant,
    defense_elapsed: Option<Duration>,
) -> Result<Option<Duration>, Error> {
    loop {
        let output = endpoint
            .client
            .process_multiple_output(base_now, NonZeroUsize::MIN);
        let batch = match output {
            OutputBatch::DatagramBatch(batch) => batch,
            OutputBatch::Callback(delay) => return Ok(Some(delay)),
            OutputBatch::None => return Ok(None),
        };
        let observations = endpoint.client.qcsd_timestamped_observations();
        let mut satisfied_datagrams = satisfied_datagrams_for(endpoint, &observations)?;
        let mut attributed_datagrams = Vec::new();
        for datagram in batch.iter() {
            let satisfied = satisfied_datagrams
                .iter()
                .position(|(_, observed_size)| *observed_size == datagram.len())
                .map(|index| satisfied_datagrams.remove(index));
            attributed_datagrams.push((datagram.len(), satisfied));
        }
        if let Some((slot, _)) = satisfied_datagrams.first() {
            return Err(Error::SlotInvariant(format!(
                "satisfied outgoing slot {} had no matching datagram",
                slot.0
            )));
        }

        let sent_at = loop {
            match endpoint.socket.send(&batch) {
                Ok(()) => break now(),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    endpoint.socket.writable().await?;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let wire_elapsed = defense_elapsed
            .map(|elapsed| elapsed.saturating_add(sent_at.saturating_duration_since(base_now)));
        for observation in observations {
            record_qcsd_observation(endpoint, traces, &observation)?;
            forward_qcsd_observation(controller, observation, wire_elapsed);
        }
        for (observed, satisfied) in attributed_datagrams {
            traces.packet(&PacketTraceRow {
                now: sent_at,
                endpoint: endpoint.id,
                direction: "outgoing",
                observed,
                scheduled: satisfied
                    .map(|(_, observed_size)| u16::try_from(observed_size).unwrap_or(u16::MAX)),
                satisfaction: satisfied.map_or("unshaped", |_| "satisfied"),
                slot: satisfied.map(|(slot, _)| slot),
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
    }
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

fn write_run_json(
    spec: &RunSpec,
    endpoints: &[Endpoint],
    responses: &[ResponseResult],
    started_unix_ns: u128,
    completion: &RunCompletion<'_>,
) -> Result<(), Error> {
    let chaff_responses = collect_chaff_responses(endpoints)?;
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
        "application_workload_source_hash_sha256": spec.application_workload_source.as_ref().map(|(_, hash)| hash),
        "chaff_manifest_hash_sha256": spec.chaff_manifest_hash,
        "max_response_bytes": spec.max_response_bytes,
        "time_anchor_unix_ns": started_unix_ns,
        "started_unix_ns": started_unix_ns,
        "ended_unix_ns": completion.ended_unix_ns,
        "defense_start_monotonic_ns": completion.defense_start_monotonic_ns,
        "application_completion_monotonic_ns": completion.application_completion_monotonic_ns,
        "defense_diagnostics": completion.defense_diagnostics,
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
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use clap::Parser as _;
    use neqo_csdef::{
        ChaffManifest, ChaffQualification, Defense, DefenseConfig, DefenseMode, DefenseSignal,
        DependencyTracker, Direction, ExpectedChaffResponse, FrontConfig, MissedSlotReason, Packet,
        QcsdAction, QcsdChaffRequestId, QcsdConfig, QcsdController, QcsdDatagramClass,
        QcsdEndpointId, QcsdObservation, QcsdObservationClock, QcsdParserLeaseOwner, QcsdSlotId,
        QcsdStreamFinish, QcsdStreamId, QualifiedChaffResource, Resource, ResourceManifest,
        SignalKind, StaticSchedule, TamarawConfig, Trace, TrafficMorphingConfig,
        WalkieTalkieConfig, WtfPad, WtfPadConfig, sanitize_chaff_headers,
    };

    use super::{
        ApplicationBatchLifecycle, Args, DefenseArg, Error, ExpectedChaffIdentity, Preset,
        ProfileArg, QcsdRequestRole, RequestPolicyArg, ResourceRunState, RunCompletion, RunSpec,
        Socket, StaticModeArg, StreamRecord, StreamType, TrafficMorphingActivation,
        action_failure_reason, activate_traffic_morphing, apply_action_batch, create_endpoints,
        datagram_observation, deadline_error, defense_parameter_provenance,
        ensure_defense_realizable, expected_application_response_length, finish_application_record,
        finish_chaff_record, forward_qcsd_observation, has_in_flight_application_stream, now,
        qcsd_connection_parameters, qualification_content_encoding, ready_request_batch,
        record_terminal_action, register_action_batch, resolve_run_config,
        resolve_run_config_with_workload, sanitize_chaff_action_headers, sha256,
        shapes_stream_sends, terminalize_pending_slots,
        trace_files::{ScheduleTraceRow, TraceFiles},
        traffic_morphing_endpoint_seed, validate_walkie_talkie_chaff_precondition,
        wait_for_activity, write_run_json,
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
                    schema_version: 1,
                    method: "GET".into(),
                    request_stream_bytes: 1,
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
            schema_version: 1,
            artifact_type: "qcsd-qualified-chaff-manifest".into(),
            application_workload_sha256: "e".repeat(64),
            application_resource_id: resources
                .first()
                .map_or(0, |resource: &QualifiedChaffResource| resource.id),
            resources,
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
    fn walkie_talkie_chaff_preflight_filters_origins_before_priority_selection() {
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
                    packet_size: 1_200,
                    ..WalkieTalkieConfig::default()
                }),
                ..QcsdConfig::default()
            },
            defense_parameters: None,
            chaff_manifest: Some(qualified_chaff_manifest(resources)),
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
            },
        )
        .expect("write run receipt");

        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("run.json")).expect("read run receipt"))
                .expect("parse run receipt");
        assert!(receipt.get("resolved_workload").is_none());
        assert!(receipt.get("urls").is_none());
        assert_eq!(receipt["workload_hash_sha256"], "frozen-workload-hash");
        for retained in [
            "resolved_configuration",
            "responses",
            "endpoints",
            "completion_status",
        ] {
            assert!(receipt.get(retained).is_some(), "missing {retained}");
        }
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
        assert_eq!(fields.next(), None);
        assert!(!schedule.contains("credit_advertised"));
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
            deadline_after_us: 1,
            allow_stream_data: false,
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
            deadline_after_us: 1,
            allow_stream_data: false,
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
        assert!(schedule.ends_with("RunAborted,0\n"));
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
        assert_eq!(
            provenance.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
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
    async fn socket_readiness_preempts_the_runner_timer() {
        let socket = Socket::bind("127.0.0.1:0").expect("receiver socket");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
        sender
            .send_to(&[1], socket.local_addr().expect("receiver address"))
            .expect("queue datagram");

        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_activity([&socket], Duration::from_secs(60)),
        )
        .await
        .expect("readiness should beat the timeout")
        .expect("readiness wait");
    }
}
