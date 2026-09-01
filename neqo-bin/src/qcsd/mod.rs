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
use neqo_common::{Header, datagram, event::Provider as _};
use neqo_csdef::{
    ChaffManifest, ChaffQualification, DefenseConfig, DefenseDiagnostics, DefenseKind,
    DependencyTracker, Direction, ExpectedChaffResponse, MissedSlotReason, Packet, QcsdAction,
    QcsdChaffCancellationReason, QcsdChaffRequestId, QcsdConfig, QcsdController, QcsdEndpointId,
    QcsdObservation, QcsdObservationClock, QcsdPrearmCancellationReason, QcsdProfile,
    QcsdReceiveActionIdentity, QcsdReceiveLimitError, QcsdReceiveLimitFatal,
    QcsdReceiveLimitOutcome, QcsdRequestRole, QcsdSendPolicy, QcsdSlotComposition, QcsdSlotId,
    QcsdSlotOutcome, QcsdStreamTransmission, Resource, ResourceManifest, ResourceRunState,
    ResponseOnlyChaffManifest, ResponseOnlyChaffManifestV4, ResponseOnlyChaffQualification,
    ResponseOnlyChaffQualificationV4, StaticMode, TimestampedQcsdObservation,
    TrafficMorphingEgress, WalkieTalkie, WalkieTalkieQualificationBinding, derive,
    normalize_content_encoding, sanitize_chaff_headers,
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

fn resolve_remote_address(host: &str, port: u16) -> Result<SocketAddr, Error> {
    let addresses = format!("{host}:{port}")
        .to_socket_addrs()?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(Error::Argument(format!("could not resolve {host}:{port}")));
    }
    if std::env::var_os("QCSD_PUBLIC_ORIGIN_ONLY").is_some()
        && addresses
            .iter()
            .any(|address| !is_public_network_address(address.ip()))
    {
        return Err(Error::Argument(format!(
            "public-origin policy rejected a non-public DNS answer for {host}:{port}"
        )));
    }
    Ok(addresses[0])
}

fn is_public_network_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _d] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0)
                || (a == 192 && b == 168)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            let global_unicast = octets[0] & 0xe0 == 0x20;
            let ietf_special = octets[0] == 0x20 && octets[1] == 0x01 && octets[2] & 0xfe == 0;
            let deprecated_6to4 = octets[0] == 0x20 && octets[1] == 0x02;
            let documentation = octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
                || (octets[0] == 0x3f && octets[1] == 0xff && octets[2] & 0xf0 == 0);
            global_unicast && !ietf_special && !deprecated_6to4 && !documentation
        }
    }
}

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
    #[error("client defence execution failed: {0}")]
    DefenseExecution(String),
    #[error("QCSD slot accounting invariant failed: {0}")]
    SlotInvariant(String),
    #[error(
        "target-bearing UDP datagram reached or crossed its adapter deadline before socket handoff ({attempted_at:?} >= {deadline:?})"
    )]
    AdapterDeadlinePreHandoff {
        attempted_at: Instant,
        deadline: Instant,
    },
    #[error(
        "target-bearing UDP datagram reached the socket at or after its adapter deadline ({sent_at:?} >= {deadline:?})"
    )]
    AdapterDeadlineLateHandoff { sent_at: Instant, deadline: Instant },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketHandoffPolicy {
    /// Preserve Neqo's historical best-effort handling of local interface
    /// buffer exhaustion and oversized datagrams.
    HistoricalBestEffort,
    /// Candidate fidelity runs must fail closed if the OS did not accept the
    /// defense datagram; otherwise the slot could be falsely receipted.
    CandidateFidelityStrict,
}

impl SocketHandoffPolicy {
    const fn for_defense(defense: &DefenseConfig) -> Self {
        if is_candidate_defense(defense) {
            Self::CandidateFidelityStrict
        } else {
            Self::HistoricalBestEffort
        }
    }

    const fn for_response_qualification(mode: ResponseQualificationMode) -> Self {
        match mode {
            ResponseQualificationMode::Legacy => Self::HistoricalBestEffort,
            ResponseQualificationMode::SustainedIdentity => Self::CandidateFidelityStrict,
        }
    }

    fn send(self, socket: &Socket, batch: &datagram::Batch) -> io::Result<Option<Instant>> {
        match self {
            Self::HistoricalBestEffort => socket.send(batch).map(|()| None),
            Self::CandidateFidelityStrict => socket.send_qcsd_timestamped(batch, now).map(Some),
        }
    }
}

const fn is_candidate_defense(defense: &DefenseConfig) -> bool {
    matches!(defense, DefenseConfig::Buflo(_) | DefenseConfig::CsBuflo(_))
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
                Some(
                    "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing",
                ),
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
    error_class: Option<&'a str>,
    defense_start_monotonic_ns: Option<u64>,
    application_completion_monotonic_ns: Option<u64>,
    defense_diagnostics: Option<DefenseDiagnostics>,
    runner_wakeup_metrics: Option<RunnerWakeupMetrics>,
}

const fn run_error_class(error: &Error) -> &'static str {
    match error {
        Error::Timeout(_) => "timeout-v1",
        Error::Qcsd(_)
        | Error::SlotInvariant(_)
        | Error::AdapterDeadlinePreHandoff { .. }
        | Error::AdapterDeadlineLateHandoff { .. }
        | Error::ReceiveLimit(_) => "client-defense-fidelity-v1",
        Error::DefenseExecution(_) => "client-defense-execution-v1",
        Error::Argument(_)
        | Error::Http3(_)
        | Error::Io(_)
        | Error::Json(_)
        | Error::Nss(_)
        | Error::RunAborted(_)
        | Error::Transport(_) => "runner-execution-v1",
    }
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

const RUNNER_WAKEUP_METRICS_SCHEMA_VERSION: u32 = 8;
const RUNNER_WAKEUP_METRICS_SEMANTICS: &str = "actual_select_return_source; socket_wins_simultaneous_readiness; controller_subset_is_effective_earliest_deadline; scheduled_cells_are_not_wakeups; buflo_ordinary_output_admission_lead_us=10000; buflo_exact_release_guard_reserves_candidate_window; buflo_exact_release_guard_lead_us=10000; buflo_exact_release_active_wait_tail_us=10000; buflo_exact_release_guard_coincides_with_output_admission=true; buflo_exact_release_guards_are_separately_receipted_active_waits; buflo_active_defense_socket_drains_are_single_batch; buflo_active_defense_http_drains_are_single_event; buflo_ordinary_output_stops_at_admission; buflo_exact_release_guard_begins_at_guard; cs_exact_incoming_retry_phases=1/4,1/2,3/4; buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; buflo_exact_incoming_retry_drives=count_owner_endpoint_output_drive_invocations_including_immediate_and_error; buflo_exact_incoming_retry_resolutions=count_drive_invocations_clearing_at_least_one_captured_identity; buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; buflo_exact_incoming_inventory=all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss; buflo_exact_release_timing_histogram_upper_bounds_ns=50000,100000,250000,500000,1000000,2000000,5000000,overflow; buflo_exact_release_active_spin_interruption_threshold_ns=50000; buflo_exact_release_active_spin_gap_histogram_counts_one_max_gap_per_guard; buflo_exact_release_dispatch_lateness_histogram_counts_one_guard_exit_per_guard; buflo_exact_release_dispatch_at_or_after_deadline_uses_half_open_window=true; buflo_exact_release_aux_clocks=linux_clock_monotonic_raw_and_thread_cputime_id_or_unavailable; buflo_exact_release_aux_clock_unavailable_includes_missing_or_nonmonotonic_sample=true; buflo_exact_release_estimated_off_cpu_is_monotonic_elapsed_minus_thread_cpu_elapsed_saturating; buflo_exact_release_aux_clock_cannot_attribute_guest_scheduler_vs_hypervisor_steal; buflo_exact_release_worst_guard_is_max_dispatch_lateness_first_on_tie; buflo_exact_release_worst_guard_times_are_relative_to_defense_start_or_null; buflo_rolling_prearm_not_before_relative_us_rounding=ceil; buflo_rolling_prearm_deadline_relative_us_rounding=floor; buflo_exact_release_packet_timestamp_us_semantics=nominal_defense_release; buflo_exact_release_worst_guard_release_and_deadline_semantics=actual_adapter_instants; buflo_exact_release_actual_adapter_window_ns=nominal_control_interval_ns_or_nominal_minus_1000; buflo_exact_release_actual_guard_and_active_wait_lead_ns=twice_actual_adapter_window_ns; buflo_exact_release_10000us_lead_fields_are_configured_maxima=true; buflo_exact_release_active_wait_poll=poll_instant_without_arch_spin_hint";

#[cfg(target_os = "linux")]
const BUFLO_EXACT_RELEASE_AUX_CLOCK_SOURCE: &str =
    "linux-clock-gettime-monotonic-raw-and-thread-cputime-id-v1";
#[cfg(not(target_os = "linux"))]
const BUFLO_EXACT_RELEASE_AUX_CLOCK_SOURCE: &str = "unavailable-on-platform";

const BUFLO_EXACT_RELEASE_SPIN_INTERRUPTION_THRESHOLD: Duration = Duration::from_micros(50);
const BUFLO_EXACT_RELEASE_TIMING_HISTOGRAM_UPPER_BOUNDS_NANOSECONDS: [u64; 7] = [
    50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000, 5_000_000,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct BufloExactReleaseTimingHistogram {
    upper_bounds_nanoseconds: [u64; 7],
    counts: [u64; 8],
}

impl BufloExactReleaseTimingHistogram {
    const fn new() -> Self {
        Self {
            upper_bounds_nanoseconds: BUFLO_EXACT_RELEASE_TIMING_HISTOGRAM_UPPER_BOUNDS_NANOSECONDS,
            counts: [0; 8],
        }
    }

    fn record(&mut self, nanoseconds: u64) {
        let bucket = self
            .upper_bounds_nanoseconds
            .partition_point(|upper_bound| nanoseconds > *upper_bound);
        self.counts[bucket] = self.counts[bucket].saturating_add(1);
    }

    fn total(self) -> u64 {
        self.counts.into_iter().fold(0_u64, u64::saturating_add)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct BufloExactReleaseAuxClockSample {
    monotonic_raw_nanoseconds: Option<u64>,
    thread_cpu_nanoseconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufloExactReleaseWaitEvidence {
    entered_at: Instant,
    active_wait_started_at: Instant,
    dispatch_at: Instant,
    passive_sleep_calls: u64,
    passive_sleep_requested_nanoseconds: u64,
    passive_sleep_elapsed_nanoseconds: u64,
    max_passive_sleep_overrun_nanoseconds: u64,
    active_wait_iterations: u64,
    active_spin_interruptions: u64,
    active_spin_interruption_nanoseconds: u64,
    max_active_spin_gap_nanoseconds: u64,
    active_wait_start_clocks: BufloExactReleaseAuxClockSample,
    active_wait_end_clocks: BufloExactReleaseAuxClockSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct BufloExactReleaseWorstGuard {
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
    phase: &'static str,
    packet_timestamp_us: u64,
    guard_at_defense_nanoseconds: Option<u64>,
    entered_at_defense_nanoseconds: Option<u64>,
    active_wait_at_defense_nanoseconds: Option<u64>,
    active_wait_started_at_defense_nanoseconds: Option<u64>,
    release_at_defense_nanoseconds: Option<u64>,
    deadline_at_defense_nanoseconds: Option<u64>,
    dispatch_at_defense_nanoseconds: Option<u64>,
    guard_entry_lateness_nanoseconds: u64,
    passive_sleep_calls: u64,
    passive_sleep_requested_nanoseconds: u64,
    passive_sleep_elapsed_nanoseconds: u64,
    max_passive_sleep_overrun_nanoseconds: u64,
    active_wait_iterations: u64,
    active_wait_monotonic_nanoseconds: u64,
    active_wait_monotonic_raw_nanoseconds: Option<u64>,
    active_wait_thread_cpu_nanoseconds: Option<u64>,
    active_wait_estimated_off_cpu_nanoseconds: Option<u64>,
    active_wait_monotonic_raw_divergence_nanoseconds: Option<u64>,
    active_spin_interruptions: u64,
    active_spin_interruption_nanoseconds: u64,
    max_active_spin_gap_nanoseconds: u64,
    dispatch_lateness_nanoseconds: u64,
    dispatch_at_or_after_deadline: bool,
    dispatch_after_deadline_nanoseconds: u64,
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
    buflo_exact_release_guard_entries: u64,
    buflo_exact_release_guard_wait_nanoseconds: u64,
    buflo_exact_release_active_wait_nanoseconds: u64,
    buflo_exact_release_max_passive_wake_lateness_nanoseconds: u64,
    buflo_exact_release_max_guard_exit_lateness_nanoseconds: u64,
    buflo_exact_release_max_guard_entry_lateness_nanoseconds: u64,
    buflo_exact_release_passive_sleep_calls: u64,
    buflo_exact_release_passive_sleep_requested_nanoseconds: u64,
    buflo_exact_release_passive_sleep_elapsed_nanoseconds: u64,
    buflo_exact_release_max_passive_sleep_overrun_nanoseconds: u64,
    buflo_exact_release_active_wait_iterations: u64,
    buflo_exact_release_active_spin_interruptions: u64,
    buflo_exact_release_active_spin_interruption_nanoseconds: u64,
    buflo_exact_release_max_active_spin_gap_nanoseconds: u64,
    buflo_exact_release_aux_clock_source: &'static str,
    buflo_exact_release_active_wait_aux_clock_guards: u64,
    buflo_exact_release_active_wait_aux_clock_unavailable_guards: u64,
    buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards: u64,
    buflo_exact_release_active_wait_monotonic_raw_nanoseconds: u64,
    buflo_exact_release_active_wait_thread_cpu_nanoseconds: u64,
    buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds: u64,
    buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds: u64,
    buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds: u64,
    buflo_exact_release_dispatch_at_or_after_deadline_guards: u64,
    buflo_exact_release_dispatch_lateness_histogram: BufloExactReleaseTimingHistogram,
    buflo_exact_release_active_spin_gap_histogram: BufloExactReleaseTimingHistogram,
    buflo_exact_release_worst_guard: Option<BufloExactReleaseWorstGuard>,
    buflo_exact_incoming_retry_drives: u64,
    buflo_exact_incoming_retry_resolutions: u64,
    buflo_exact_incoming_retry_max_wake_lateness_nanoseconds: u64,
    cs_exact_incoming_retry_drives: u64,
    cs_exact_incoming_retry_resolutions: u64,
    cs_exact_incoming_retry_max_phase_lateness_nanoseconds: u64,
}

impl RunnerWakeupMetrics {
    const fn new() -> Self {
        Self {
            schema_version: RUNNER_WAKEUP_METRICS_SCHEMA_VERSION,
            semantics: RUNNER_WAKEUP_METRICS_SEMANTICS,
            wait_returns: 0,
            socket_readiness_wakeups: 0,
            timer_wakeups: 0,
            controller_deadline_timer_wakeups: 0,
            other_timer_wakeups: 0,
            buflo_exact_release_guard_entries: 0,
            buflo_exact_release_guard_wait_nanoseconds: 0,
            buflo_exact_release_active_wait_nanoseconds: 0,
            buflo_exact_release_max_passive_wake_lateness_nanoseconds: 0,
            buflo_exact_release_max_guard_exit_lateness_nanoseconds: 0,
            buflo_exact_release_max_guard_entry_lateness_nanoseconds: 0,
            buflo_exact_release_passive_sleep_calls: 0,
            buflo_exact_release_passive_sleep_requested_nanoseconds: 0,
            buflo_exact_release_passive_sleep_elapsed_nanoseconds: 0,
            buflo_exact_release_max_passive_sleep_overrun_nanoseconds: 0,
            buflo_exact_release_active_wait_iterations: 0,
            buflo_exact_release_active_spin_interruptions: 0,
            buflo_exact_release_active_spin_interruption_nanoseconds: 0,
            buflo_exact_release_max_active_spin_gap_nanoseconds: 0,
            buflo_exact_release_aux_clock_source: BUFLO_EXACT_RELEASE_AUX_CLOCK_SOURCE,
            buflo_exact_release_active_wait_aux_clock_guards: 0,
            buflo_exact_release_active_wait_aux_clock_unavailable_guards: 0,
            buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards: 0,
            buflo_exact_release_active_wait_monotonic_raw_nanoseconds: 0,
            buflo_exact_release_active_wait_thread_cpu_nanoseconds: 0,
            buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds: 0,
            buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds: 0,
            buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds: 0,
            buflo_exact_release_dispatch_at_or_after_deadline_guards: 0,
            buflo_exact_release_dispatch_lateness_histogram: BufloExactReleaseTimingHistogram::new(
            ),
            buflo_exact_release_active_spin_gap_histogram: BufloExactReleaseTimingHistogram::new(),
            buflo_exact_release_worst_guard: None,
            buflo_exact_incoming_retry_drives: 0,
            buflo_exact_incoming_retry_resolutions: 0,
            buflo_exact_incoming_retry_max_wake_lateness_nanoseconds: 0,
            cs_exact_incoming_retry_drives: 0,
            cs_exact_incoming_retry_resolutions: 0,
            cs_exact_incoming_retry_max_phase_lateness_nanoseconds: 0,
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

    #[expect(
        clippy::too_many_lines,
        reason = "one atomic recorder keeps every schema-7 aggregate and its bounded worst-guard evidence consistent"
    )]
    fn record_buflo_exact_release_guard(
        &mut self,
        guard: &BufloExactReleaseGuard,
        defense_start: Option<Instant>,
        evidence: &BufloExactReleaseWaitEvidence,
    ) {
        let BufloExactReleaseWaitEvidence {
            entered_at,
            active_wait_started_at,
            dispatch_at,
            passive_sleep_calls,
            passive_sleep_requested_nanoseconds,
            passive_sleep_elapsed_nanoseconds,
            max_passive_sleep_overrun_nanoseconds,
            active_wait_iterations,
            active_spin_interruptions,
            active_spin_interruption_nanoseconds,
            max_active_spin_gap_nanoseconds,
            active_wait_start_clocks,
            active_wait_end_clocks,
        } = *evidence;
        let active_wait_monotonic_nanoseconds =
            duration_as_u64_nanos(dispatch_at.saturating_duration_since(active_wait_started_at));
        let monotonic_raw_elapsed = optional_clock_elapsed(
            active_wait_start_clocks.monotonic_raw_nanoseconds,
            active_wait_end_clocks.monotonic_raw_nanoseconds,
        );
        let thread_cpu_elapsed = optional_clock_elapsed(
            active_wait_start_clocks.thread_cpu_nanoseconds,
            active_wait_end_clocks.thread_cpu_nanoseconds,
        );
        let aux_clock_complete = monotonic_raw_elapsed.is_some() && thread_cpu_elapsed.is_some();
        let aux_clock_nonmonotonic = clock_pair_is_nonmonotonic(
            active_wait_start_clocks.monotonic_raw_nanoseconds,
            active_wait_end_clocks.monotonic_raw_nanoseconds,
        ) || clock_pair_is_nonmonotonic(
            active_wait_start_clocks.thread_cpu_nanoseconds,
            active_wait_end_clocks.thread_cpu_nanoseconds,
        );
        let estimated_off_cpu = thread_cpu_elapsed
            .map(|thread_cpu| active_wait_monotonic_nanoseconds.saturating_sub(thread_cpu));
        let monotonic_raw_divergence = monotonic_raw_elapsed
            .map(|monotonic_raw| active_wait_monotonic_nanoseconds.abs_diff(monotonic_raw));
        let guard_entry_lateness =
            duration_as_u64_nanos(entered_at.saturating_duration_since(guard.guard_at));
        let dispatch_lateness =
            duration_as_u64_nanos(dispatch_at.saturating_duration_since(guard.release));
        let dispatch_after_deadline =
            duration_as_u64_nanos(dispatch_at.saturating_duration_since(guard.deadline));
        let dispatch_at_or_after_deadline = dispatch_at >= guard.deadline;

        self.buflo_exact_release_guard_entries =
            self.buflo_exact_release_guard_entries.saturating_add(1);
        self.buflo_exact_release_guard_wait_nanoseconds = self
            .buflo_exact_release_guard_wait_nanoseconds
            .saturating_add(duration_as_u64_nanos(
                dispatch_at.saturating_duration_since(entered_at),
            ));
        self.buflo_exact_release_active_wait_nanoseconds = self
            .buflo_exact_release_active_wait_nanoseconds
            .saturating_add(active_wait_monotonic_nanoseconds);
        self.buflo_exact_release_max_passive_wake_lateness_nanoseconds = self
            .buflo_exact_release_max_passive_wake_lateness_nanoseconds
            .max(duration_as_u64_nanos(
                active_wait_started_at.saturating_duration_since(guard.active_wait_at),
            ));
        self.buflo_exact_release_max_guard_exit_lateness_nanoseconds = self
            .buflo_exact_release_max_guard_exit_lateness_nanoseconds
            .max(dispatch_lateness);
        self.buflo_exact_release_max_guard_entry_lateness_nanoseconds = self
            .buflo_exact_release_max_guard_entry_lateness_nanoseconds
            .max(guard_entry_lateness);
        self.buflo_exact_release_passive_sleep_calls = self
            .buflo_exact_release_passive_sleep_calls
            .saturating_add(passive_sleep_calls);
        self.buflo_exact_release_passive_sleep_requested_nanoseconds = self
            .buflo_exact_release_passive_sleep_requested_nanoseconds
            .saturating_add(passive_sleep_requested_nanoseconds);
        self.buflo_exact_release_passive_sleep_elapsed_nanoseconds = self
            .buflo_exact_release_passive_sleep_elapsed_nanoseconds
            .saturating_add(passive_sleep_elapsed_nanoseconds);
        self.buflo_exact_release_max_passive_sleep_overrun_nanoseconds = self
            .buflo_exact_release_max_passive_sleep_overrun_nanoseconds
            .max(max_passive_sleep_overrun_nanoseconds);
        self.buflo_exact_release_active_wait_iterations = self
            .buflo_exact_release_active_wait_iterations
            .saturating_add(active_wait_iterations);
        self.buflo_exact_release_active_spin_interruptions = self
            .buflo_exact_release_active_spin_interruptions
            .saturating_add(active_spin_interruptions);
        self.buflo_exact_release_active_spin_interruption_nanoseconds = self
            .buflo_exact_release_active_spin_interruption_nanoseconds
            .saturating_add(active_spin_interruption_nanoseconds);
        self.buflo_exact_release_max_active_spin_gap_nanoseconds = self
            .buflo_exact_release_max_active_spin_gap_nanoseconds
            .max(max_active_spin_gap_nanoseconds);
        self.buflo_exact_release_active_spin_gap_histogram
            .record(max_active_spin_gap_nanoseconds);
        self.buflo_exact_release_dispatch_lateness_histogram
            .record(dispatch_lateness);
        if dispatch_at_or_after_deadline {
            self.buflo_exact_release_dispatch_at_or_after_deadline_guards = self
                .buflo_exact_release_dispatch_at_or_after_deadline_guards
                .saturating_add(1);
        }
        if aux_clock_complete {
            self.buflo_exact_release_active_wait_aux_clock_guards = self
                .buflo_exact_release_active_wait_aux_clock_guards
                .saturating_add(1);
        } else {
            self.buflo_exact_release_active_wait_aux_clock_unavailable_guards = self
                .buflo_exact_release_active_wait_aux_clock_unavailable_guards
                .saturating_add(1);
        }
        if aux_clock_nonmonotonic {
            self.buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards = self
                .buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards
                .saturating_add(1);
        }
        if let Some(monotonic_raw) = monotonic_raw_elapsed {
            self.buflo_exact_release_active_wait_monotonic_raw_nanoseconds = self
                .buflo_exact_release_active_wait_monotonic_raw_nanoseconds
                .saturating_add(monotonic_raw);
        }
        if let Some(thread_cpu) = thread_cpu_elapsed {
            self.buflo_exact_release_active_wait_thread_cpu_nanoseconds = self
                .buflo_exact_release_active_wait_thread_cpu_nanoseconds
                .saturating_add(thread_cpu);
        }
        if let Some(off_cpu) = estimated_off_cpu {
            self.buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds = self
                .buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds
                .saturating_add(off_cpu);
            self.buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds = self
                .buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds
                .max(off_cpu);
        }
        if let Some(divergence) = monotonic_raw_divergence {
            self.buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds = self
                .buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds
                .max(divergence);
        }

        let replace_worst = self
            .buflo_exact_release_worst_guard
            .is_none_or(|current| dispatch_lateness > current.dispatch_lateness_nanoseconds);
        if replace_worst {
            self.buflo_exact_release_worst_guard = Some(BufloExactReleaseWorstGuard {
                endpoint: guard.endpoint,
                slot: guard.slot,
                phase: guard.phase.as_str(),
                packet_timestamp_us: guard.packet.timestamp_us(),
                guard_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    guard.guard_at,
                    defense_start,
                ),
                entered_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    entered_at,
                    defense_start,
                ),
                active_wait_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    guard.active_wait_at,
                    defense_start,
                ),
                active_wait_started_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    active_wait_started_at,
                    defense_start,
                ),
                release_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    guard.release,
                    defense_start,
                ),
                deadline_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    guard.deadline,
                    defense_start,
                ),
                dispatch_at_defense_nanoseconds: instant_after_start_nanoseconds(
                    dispatch_at,
                    defense_start,
                ),
                guard_entry_lateness_nanoseconds: guard_entry_lateness,
                passive_sleep_calls,
                passive_sleep_requested_nanoseconds,
                passive_sleep_elapsed_nanoseconds,
                max_passive_sleep_overrun_nanoseconds,
                active_wait_iterations,
                active_wait_monotonic_nanoseconds,
                active_wait_monotonic_raw_nanoseconds: monotonic_raw_elapsed,
                active_wait_thread_cpu_nanoseconds: thread_cpu_elapsed,
                active_wait_estimated_off_cpu_nanoseconds: estimated_off_cpu,
                active_wait_monotonic_raw_divergence_nanoseconds: monotonic_raw_divergence,
                active_spin_interruptions,
                active_spin_interruption_nanoseconds,
                max_active_spin_gap_nanoseconds,
                dispatch_lateness_nanoseconds: dispatch_lateness,
                dispatch_at_or_after_deadline,
                dispatch_after_deadline_nanoseconds: dispatch_after_deadline,
            });
        }
        debug_assert!(self.buflo_exact_release_invariants_hold());
    }

    fn buflo_exact_release_invariants_hold(self) -> bool {
        let guards = self.buflo_exact_release_guard_entries;
        let worst_matches_guard_count =
            self.buflo_exact_release_worst_guard.is_some() == (guards > 0);
        let worst_matches_max_dispatch = self.buflo_exact_release_worst_guard.is_none_or(|worst| {
            worst.dispatch_lateness_nanoseconds
                == self.buflo_exact_release_max_guard_exit_lateness_nanoseconds
        });
        self.buflo_exact_release_dispatch_lateness_histogram.total() == guards
            && self.buflo_exact_release_active_spin_gap_histogram.total() == guards
            && self
                .buflo_exact_release_active_wait_aux_clock_guards
                .saturating_add(self.buflo_exact_release_active_wait_aux_clock_unavailable_guards)
                == guards
            && self.buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards
                <= self.buflo_exact_release_active_wait_aux_clock_unavailable_guards
            && self.buflo_exact_release_dispatch_at_or_after_deadline_guards <= guards
            && worst_matches_guard_count
            && worst_matches_max_dispatch
            && self.buflo_exact_release_max_passive_sleep_overrun_nanoseconds
                <= self.buflo_exact_release_passive_sleep_elapsed_nanoseconds
            && self.buflo_exact_release_max_active_spin_gap_nanoseconds
                <= self.buflo_exact_release_active_wait_nanoseconds
            && self.buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds
                <= self.buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds
            && ((self.buflo_exact_release_active_spin_interruptions == 0)
                == (self.buflo_exact_release_active_spin_interruption_nanoseconds == 0))
            && (self.buflo_exact_release_max_active_spin_gap_nanoseconds
                <= duration_as_u64_nanos(BUFLO_EXACT_RELEASE_SPIN_INTERRUPTION_THRESHOLD)
                || self.buflo_exact_release_active_spin_interruptions > 0)
    }

    fn record_cs_exact_incoming_retry_drive(&mut self, phase_at: Instant, attempted_at: Instant) {
        self.cs_exact_incoming_retry_drives = self.cs_exact_incoming_retry_drives.saturating_add(1);
        self.cs_exact_incoming_retry_max_phase_lateness_nanoseconds = self
            .cs_exact_incoming_retry_max_phase_lateness_nanoseconds
            .max(duration_as_u64_nanos(
                attempted_at.saturating_duration_since(phase_at),
            ));
    }

    fn record_buflo_exact_incoming_retry_drive(
        &mut self,
        wake_at: Instant,
        attempted_at: Instant,
        resolved: bool,
    ) {
        self.buflo_exact_incoming_retry_drives =
            self.buflo_exact_incoming_retry_drives.saturating_add(1);
        self.buflo_exact_incoming_retry_max_wake_lateness_nanoseconds = self
            .buflo_exact_incoming_retry_max_wake_lateness_nanoseconds
            .max(duration_as_u64_nanos(
                attempted_at.saturating_duration_since(wake_at),
            ));
        if resolved {
            self.buflo_exact_incoming_retry_resolutions = self
                .buflo_exact_incoming_retry_resolutions
                .saturating_add(1);
        }
        debug_assert!(
            self.buflo_exact_incoming_retry_resolutions <= self.buflo_exact_incoming_retry_drives
        );
    }

    fn record_buflo_exact_incoming_terminal_wake(
        &mut self,
        deadline: Instant,
        observed_at: Instant,
    ) {
        self.buflo_exact_incoming_retry_max_wake_lateness_nanoseconds = self
            .buflo_exact_incoming_retry_max_wake_lateness_nanoseconds
            .max(duration_as_u64_nanos(
                observed_at.saturating_duration_since(deadline),
            ));
    }

    fn record_cs_exact_incoming_retry_resolution(&mut self) {
        self.cs_exact_incoming_retry_resolutions =
            self.cs_exact_incoming_retry_resolutions.saturating_add(1);
        debug_assert!(
            self.cs_exact_incoming_retry_resolutions <= self.cs_exact_incoming_retry_drives
        );
    }
}

fn duration_as_u64_nanos(value: Duration) -> u64 {
    u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
}

fn optional_clock_elapsed(start: Option<u64>, end: Option<u64>) -> Option<u64> {
    end?.checked_sub(start?)
}

const fn clock_pair_is_nonmonotonic(start: Option<u64>, end: Option<u64>) -> bool {
    matches!((start, end), (Some(start), Some(end)) if end < start)
}

fn instant_after_start_nanoseconds(instant: Instant, start: Option<Instant>) -> Option<u64> {
    let start = start?;
    let elapsed = instant.checked_duration_since(start)?;
    Some(duration_as_u64_nanos(elapsed))
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
    /// Present only on the independently fitted 100-class study projection.
    /// The historical schema-two format remains byte-for-byte accepted.
    source_walkie_talkie_schema_version: Option<u32>,
    numeric_profile_derivation: Option<String>,
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
    /// Exact absolute adapter release for a committed rolling target. Fixed
    /// schedule targets store their action instant here and never consult it.
    /// A rolling target owns the output microstep at its nominal defense
    /// timestamp, but transport must not be driven until this (possibly
    /// sub-microsecond-later) release instant.
    not_before: Instant,
    /// Absolute adapter deadline derived from the same action timestamp and
    /// relative window passed to transport. A target is not accepted unless
    /// the committed UDP datagram reaches the OS socket before this instant.
    deadline: Instant,
    /// True only for a rolling target promoted by `CommitPrearmedPacket`. Legacy
    /// and fixed-schedule sends retain their established endpoint order.
    rolling_prearmed: bool,
}

#[derive(Clone, Copy, Debug)]
struct PrearmedOutgoing {
    slot: QcsdSlotId,
    packet: Packet,
    not_before: Instant,
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

/// Test-only transport output outcomes that cannot fabricate a datagram or
/// bypass the production socket-handoff path.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestOutputDrive {
    ProductionPath,
    Callback(Duration),
    CallbackAt(Instant),
    ErrorAt(Instant),
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
    /// Every chaff request send half opened on this endpoint. Entries remain
    /// after response retirement or typed cancellation. A stopped `BuFLO` may
    /// exclude these identities from its drain snapshot only while chaff send
    /// shaping stays enabled; neither candidate may finish before the original
    /// bytes or cancellation RESET is peer-confirmed.
    chaff_send_streams: BTreeSet<StreamId>,
    completed: Vec<StreamRecord>,
    connected: bool,
    retired_applications: Vec<(u32, ResourceRunState)>,
    deferred_data_readable: VecDeque<StreamId>,
    scheduled_outgoing: VecDeque<ScheduledOutgoing>,
    prearmed_outgoing: VecDeque<PrearmedOutgoing>,
    socket_handoff_policy: SocketHandoffPolicy,
    traffic_morphing_activation: TrafficMorphingActivation,
    /// Unit-test seam that makes an observation visible during exactly one
    /// output step, exercising the production post-output causal barrier.
    #[cfg(test)]
    test_observation_on_next_output: Option<TimestampedQcsdObservation>,
    #[cfg(test)]
    test_output_observations: Vec<TimestampedQcsdObservation>,
    #[cfg(test)]
    test_output_drives: VecDeque<TestOutputDrive>,
    #[cfg(test)]
    test_force_socket_handoff_success: bool,
    /// Inject one strict-path OS error without depending on host buffer state.
    #[cfg(test)]
    test_strict_socket_handoff_error: Option<i32>,
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
    dispatch_at: Instant,
    url: &Uri,
    headers: &[Header],
    streams: &mut HashMap<StreamId, QualifierStream>,
    next_request_index: &mut usize,
    wave_size: usize,
) -> Result<(), Error> {
    for _ in 0..wave_size {
        let request_index = *next_request_index;
        let stream_id = client.qcsd_fetch_nonblocking(dispatch_at, url, headers)?;
        let request_stream_bytes = client.qcsd_request_stream_bytes(stream_id)?;
        if request_stream_bytes == 0 {
            return Err(Error::RunAborted(
                "production nonblocking encoder produced an empty request".into(),
            ));
        }
        client.stream_close_send(stream_id, dispatch_at)?;
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
    let socket_handoff_policy = SocketHandoffPolicy::for_response_qualification(mode);
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
    let remote_addr = resolve_remote_address(&host, port)?;
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
                        match socket_handoff_policy.send(&socket, &batch) {
                            Ok(_) => break,
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
    let remote_addr = resolve_remote_address(&host, port)?;
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
                        match SocketHandoffPolicy::HistoricalBestEffort.send(&socket, &batch) {
                            Ok(_) => break,
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

fn prefix_numeric_profile_sha256(
    profile: &PrefixNumericProfile,
    domain: &[u8],
) -> Result<String, Error> {
    // This is the exact UTF-8 produced by Python's
    // json.dumps(value, sort_keys=True, separators=(",", ":")) for this
    // integer-only schema. Keeping the construction explicit makes the
    // cross-language domain separation independently auditable.
    let canonical = serde_json::to_vec(profile)?;
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(&canonical);
    sha256(&preimage)
}

fn validate_prefix_pack_spec(spec: &PrefixPackSpec) -> Result<(), Error> {
    let horizon = all_future_receiver_continuation_reserve_horizon(&spec.numeric_profile.bursts);
    let historical = spec.schema_version == 2
        && spec.artifact_type == "qcsd-walkie-talkie-prefix-pack-spec"
        && spec.source_walkie_talkie_schema_version.is_none()
        && spec.numeric_profile_derivation.is_none();
    let class_study = spec.schema_version == 3
        && spec.artifact_type == "qcsd-class-study-walkie-talkie-prefix-pack-spec"
        && spec.source_walkie_talkie_schema_version == Some(6)
        && spec.numeric_profile_derivation.as_deref()
            == Some("schema-six-runtime-bursts-verbatim-no-additional-sender-framing");
    let numeric_domain: &[u8] = if class_study {
        b"qcsd-class-study-walkie-talkie-numeric-profile-v1\0"
    } else {
        b"qcsd-walkie-talkie-numeric-profile-v1\0"
    };
    if !(historical || class_study)
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
        || prefix_numeric_profile_sha256(&spec.numeric_profile, numeric_domain)?
            != spec.numeric_profile_sha256
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
            error_class: None,
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
                error_class: Some(run_error_class(error)),
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
        Error::DefenseExecution(
            "Walkie-Talkie stalled before its application batch and byte budget completed".into(),
        )
    } else {
        Error::Timeout(timeout_seconds)
    }
}

fn ensure_defense_realizable(controller: &QcsdController) -> Result<(), Error> {
    if let Some(failure) = controller.terminal_failure() {
        return Err(Error::DefenseExecution(failure.into()));
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
    let mut last_egress_stream_backlog = None;
    let mut application_batches =
        ApplicationBatchLifecycle::new(&spec.config.defense, spec.request_policy);
    let mut runner_wakeup_metrics = RunnerWakeupMetrics::new();
    let mut cs_exact_incoming_retry_attempted = BTreeSet::new();
    let deadline = process_start + Duration::from_secs(spec.timeout_seconds);
    let bound_ordinary_work = matches!(&spec.config.defense, DefenseConfig::Buflo(_));

    let loop_result: Result<(), Error> = async {
        macro_rules! yield_to_exact_boundaries {
            ($runner:lifetime) => {
                if dispatch_due_buflo_exact_release(
                    &spec.config.defense,
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    &observation_clock,
                    defense_start,
                    deadline,
                    spec.timeout_seconds,
                    &mut runner_wakeup_metrics,
                )
                .await?
                {
                    continue $runner;
                }
                if dispatch_due_cs_exact_incoming_retry(
                    &spec.config.defense,
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    &observation_clock,
                    defense_start,
                    &mut cs_exact_incoming_retry_attempted,
                    &mut runner_wakeup_metrics,
                )
                .await?
                {
                    continue $runner;
                }
            };
        }

        'runner: loop {
            let loop_now = now();
            if loop_now >= deadline {
                return Err(deadline_error(
                    &spec.config.defense,
                    controller.is_complete(),
                    spec.timeout_seconds,
                ));
            }

            yield_to_exact_boundaries!('runner);

            let elapsed_before_http =
                defense_start.map(|start| loop_now.saturating_duration_since(start));
            for endpoint_index in 0..endpoints.len() {
                yield_to_exact_boundaries!('runner);
                // Socket activity is reduced into defense signals before a due
                // timer is polled. This lets a real packet cancel a pending
                // reactive-defense decision.
                {
                    let endpoint = &mut endpoints[endpoint_index];
                    process_input(
                        endpoint,
                        &mut controller,
                        &mut traces,
                        &observation_clock,
                        loop_now,
                        elapsed_before_http,
                        !bound_ordinary_work || defense_start.is_none(),
                    )?;
                }
                yield_to_exact_boundaries!('runner);
                {
                    let endpoint = &mut endpoints[endpoint_index];
                    handle_http_events(
                        endpoint,
                        spec,
                        loop_now,
                        &mut traces,
                        (bound_ordinary_work && defense_start.is_some()).then_some(1),
                    )?;
                }
                let endpoint = &mut endpoints[endpoint_index];
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
                yield_to_exact_boundaries!('runner);
            }
            yield_to_exact_boundaries!('runner);

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
            yield_to_exact_boundaries!('runner);

            // Refresh after input/HTTP processing: actions reduced below must
            // never be stamped before the observations that produced them.
            let barrier_now = now();
            let barrier_elapsed =
                defense_start.map(|start| barrier_now.saturating_duration_since(start));
            if let Some(barrier_elapsed) = barrier_elapsed {
                let rolling_lifecycle_before_batch =
                    rolling_output_lifecycle_active(&controller, &endpoints);
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
                    barrier_elapsed,
                )?;
                yield_to_exact_boundaries!('runner);
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
                    controller.observe(record.into_observation(), barrier_elapsed);
                }
                controller.flush_defense_observations();
                ensure_defense_realizable(&controller)?;
                yield_to_exact_boundaries!('runner);
                let reconcile_rolling = rolling_lifecycle_before_batch
                    || rolling_output_lifecycle_active(&controller, &endpoints);
                if reconcile_rolling {
                    if controller.has_rolling_outgoing_prearm()
                        || controller.has_due_rolling_reconciliation()
                    {
                        controller.reconcile_due_rolling(barrier_elapsed)?;
                        controller.flush_defense_observations();
                        ensure_defense_realizable(&controller)?;
                    }
                    apply_queued_actions(
                        &mut endpoints,
                        &mut controller,
                        spec.chaff_manifest.as_ref(),
                        &mut traces,
                        barrier_now,
                        barrier_elapsed,
                    )?;
                    yield_to_exact_boundaries!('runner);
                }
                let request_work_interrupt =
                    next_buflo_exact_release_guard(&spec.config.defense, &controller, &endpoints)?
                        .map(|guard| guard.output_admission_at);
                let started_requests = dispatch_ready_requests(
                    &mut endpoints,
                    spec,
                    &mut dependencies,
                    barrier_now,
                    &mut traces,
                    controller.can_start_application_batch(),
                    request_work_interrupt,
                )?;
                yield_to_exact_boundaries!('runner);
                let batch_started = application_batches.after_dispatch(started_requests)?;
                handle_all_qcsd_observations(
                    &mut endpoints,
                    &mut controller,
                    &mut traces,
                    barrier_elapsed,
                )?;
                if let Some(observation) = batch_started {
                    let record = observation_clock.record(observation);
                    traces.observation(None, &record)?;
                    controller.observe(record.into_observation(), barrier_elapsed);
                }
                yield_to_exact_boundaries!('runner);
            }

            let wake_base = now();
            let mut next_wakeup = absolute_wakeup(wake_base, spec.config.control_interval())
                .ok_or_else(|| Error::DefenseExecution("runner wake deadline overflow".into()))?;
            let mut controller_deadline_selected = false;
            for endpoint_index in 0..endpoints.len() {
                yield_to_exact_boundaries!('runner);
                // Flush output that was already available (including newly
                // dispatched application requests) so its Wire signals precede
                // the defense poll.
                let output_guard =
                    next_buflo_exact_release_guard(&spec.config.defense, &controller, &endpoints)?;
                let work_boundary = output_guard.map(BufloExactReleaseGuard::output_work_boundary);
                let unshaped_handoff_interrupt = output_guard.map(|guard| guard.release);
                if let Some(wakeup) = drive_endpoint_output_until(
                    endpoint_index,
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    &observation_clock,
                    defense_start,
                    work_boundary,
                    unshaped_handoff_interrupt,
                    None,
                    OutputDriveCardinality::DrainAvailable,
                )
                .await?
                    && wakeup < next_wakeup
                {
                    next_wakeup = wakeup;
                    controller_deadline_selected = false;
                }
                yield_to_exact_boundaries!('runner);
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
                yield_to_exact_boundaries!('runner);
                let candidate_defense = is_candidate_defense(&spec.config.defense);
                let exclude_stopped_buflo_chaff_sends =
                    matches!(&spec.config.defense, DefenseConfig::Buflo(_))
                        && controller.defense_diagnostics().buflo_schedule_stop_latched;
                let (egress_stream_backlog_pending, egress_backlog_pending) = if candidate_defense {
                    endpoints
                        .iter_mut()
                        .fold((false, false), |state, endpoint| {
                            let current = endpoint_candidate_egress_backlog(
                                endpoint,
                                exclude_stopped_buflo_chaff_sends,
                            );
                            (state.0 || current.0, state.1 || current.1)
                        })
                } else {
                    (
                        false,
                        endpoints
                            .iter_mut()
                            .any(|endpoint| endpoint_egress_backlog_pending(endpoint, false)),
                    )
                };
                if candidate_defense
                    && candidate_stream_snapshot_should_emit(
                        &mut last_egress_stream_backlog,
                        egress_stream_backlog_pending,
                    )
                {
                    // A false split snapshot is one-shot schedule-stop
                    // authority. Re-publish it at every candidate control
                    // barrier because transport loss can make STREAM work
                    // pending again without producing a controller event.
                    let record = observation_clock.record(QcsdObservation::EgressStreamBacklog {
                        pending: egress_stream_backlog_pending,
                    });
                    traces.observation(None, &record)?;
                    controller.observe(record.into_observation(), defense_elapsed);
                }
                if candidate_aggregate_snapshot_should_emit(
                    &mut last_egress_backlog,
                    egress_backlog_pending,
                    controller.requires_terminal_egress_backlog_snapshot(),
                ) {
                    // Terminal chaff cancellation invalidates the aggregate
                    // snapshot that authorised it. Once every CancelChaff
                    // action has crossed the adapter boundary, publish the
                    // freshly recomputed endpoint truth even when it remains
                    // false-to-false; never synthesize an empty snapshot.
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
                controller.flush_defense_observations();
                ensure_defense_realizable(&controller)?;
                yield_to_exact_boundaries!('runner);
                if controller.has_rolling_outgoing_prearm()
                    || controller.has_due_rolling_reconciliation()
                {
                    // A close or outcome reduced at the control-stage barrier
                    // must pass through the same strict rolling identity and
                    // lateness checks as an output-drive barrier.
                    controller.reconcile_due_rolling(defense_elapsed)?;
                    controller.flush_defense_observations();
                    ensure_defense_realizable(&controller)?;
                    yield_to_exact_boundaries!('runner);
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
                yield_to_exact_boundaries!('runner);
            }

            for endpoint_index in 0..endpoints.len() {
                yield_to_exact_boundaries!('runner);
                // Retain a post-action flush so newly scheduled packet targets can
                // be placed on the wire without waiting for another loop turn.
                let output_guard =
                    next_buflo_exact_release_guard(&spec.config.defense, &controller, &endpoints)?;
                let work_boundary = output_guard.map(BufloExactReleaseGuard::output_work_boundary);
                let unshaped_handoff_interrupt = output_guard.map(|guard| guard.release);
                if let Some(wakeup) = drive_endpoint_output_until(
                    endpoint_index,
                    &mut endpoints,
                    &mut controller,
                    spec.chaff_manifest.as_ref(),
                    &mut traces,
                    &observation_clock,
                    defense_start,
                    work_boundary,
                    unshaped_handoff_interrupt,
                    None,
                    OutputDriveCardinality::DrainAvailable,
                )
                .await?
                    && wakeup < next_wakeup
                {
                    next_wakeup = wakeup;
                    controller_deadline_selected = false;
                }
                yield_to_exact_boundaries!('runner);
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
                    !bound_ordinary_work || defense_start.is_none(),
                )?;
                yield_to_exact_boundaries!('runner);
            }

            if application_complete_observed
                && controller.is_complete()
                && endpoints.iter_mut().all(|endpoint| {
                    endpoint.connected
                        && matches!(endpoint.client.state(), Http3State::Connected)
                        && endpoint.scheduled_outgoing.is_empty()
                        && endpoint.prearmed_outgoing.is_empty()
                        && endpoint.client.qcsd_pending_packet_targets() == 0
                        && endpoint_send_terminal(
                            endpoint,
                            is_candidate_defense(&spec.config.defense),
                        )
                })
            {
                traces.ensure_no_pending_slots()?;
                break;
            }
            if let Some(defense_start) = defense_start
                && let Some(next_deadline) = controller.next_deadline()
            {
                let controller_wakeup =
                    defense_start.checked_add(next_deadline).ok_or_else(|| {
                        Error::DefenseExecution("controller wake deadline overflow".into())
                    })?;
                if controller_wakeup <= next_wakeup {
                    next_wakeup = controller_wakeup;
                    controller_deadline_selected = true;
                }
            }
            if let Some(guard) =
                next_buflo_exact_release_guard(&spec.config.defense, &controller, &endpoints)?
                && guard.guard_at <= next_wakeup
            {
                // Wake before the ordinary defense deadline. Any simultaneous
                // socket readiness may win this select, but the next loop turn
                // enters the guard before processing that input.
                next_wakeup = guard.guard_at;
                controller_deadline_selected = false;
            }
            let cs_retry_inventory = cs_exact_incoming_retry_inventory(
                &spec.config.defense,
                &endpoints,
                &controller,
                defense_start,
                now(),
                &mut cs_exact_incoming_retry_attempted,
            )?;
            let cs_retry_wakeup = cs_retry_inventory
                .earliest_expired_deadline
                .into_iter()
                .chain(
                    cs_retry_inventory
                        .retries
                        .first()
                        .map(|retry| retry.phase_at),
                )
                .min();
            if let Some(cs_retry_wakeup) = cs_retry_wakeup
                && cs_retry_wakeup <= next_wakeup
            {
                // The next loop turn enters the identity-bound retry seam
                // before ordinary input, HTTP, request, or output work.
                next_wakeup = cs_retry_wakeup;
                controller_deadline_selected = false;
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
        cancel_uncommitted_prearms_on_abort(
            &mut endpoints,
            &mut controller,
            &mut traces,
            ended_at,
        )?;
        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            ended_at,
            terminal_elapsed,
            miss_reason,
        )?;
        for endpoint in &mut endpoints {
            endpoint.scheduled_outgoing.clear();
            endpoint.prearmed_outgoing.clear();
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
                error_class: Some(run_error_class(&error)),
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
            error_class: None,
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
            let remote_addr = resolve_remote_address(&host, port)?;
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
                chaff_send_streams: BTreeSet::new(),
                completed: Vec::new(),
                connected: false,
                retired_applications: Vec::new(),
                deferred_data_readable: VecDeque::new(),
                scheduled_outgoing: VecDeque::new(),
                prearmed_outgoing: VecDeque::new(),
                socket_handoff_policy: SocketHandoffPolicy::for_defense(&spec.config.defense),
                traffic_morphing_activation: if matches!(
                    &spec.config.defense,
                    DefenseConfig::TrafficMorphing(_)
                ) {
                    TrafficMorphingActivation::Pending
                } else {
                    TrafficMorphingActivation::NotSelected
                },
                #[cfg(test)]
                test_observation_on_next_output: None,
                #[cfg(test)]
                test_output_observations: Vec::new(),
                #[cfg(test)]
                test_output_drives: VecDeque::new(),
                #[cfg(test)]
                test_force_socket_handoff_success: false,
                #[cfg(test)]
                test_strict_socket_handoff_error: None,
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
    dispatch_at: Instant,
    traces: &mut TraceFiles,
    defense_batch_ready: bool,
    work_interrupt: Option<Instant>,
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
            if work_interrupt.is_some_and(|interrupt| now() >= interrupt) {
                return Ok(started_requests);
            }
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
                    dispatch_at,
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
                dispatch_at,
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
                        dispatch_at,
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
            endpoint.client.stream_close_send(stream, dispatch_at)?;
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
                dispatch_at,
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

/// Backlog semantics shared by both the controller's quiet-timer observation
/// and the runner's terminal predicate. Candidate defenses exclude only the
/// non-request-causal QPACK decoder stream; historical modes retain their
/// established all-STREAM observation.
fn endpoint_egress_backlog_pending(endpoint: &mut Endpoint, candidate_defense: bool) -> bool {
    if candidate_defense {
        // Final candidate termination checks peer-confirmed send halves
        // separately. This shared predicate retains ordinary pre-termination
        // STREAM semantics and CS-BuFLO's path to typed local ET.
        endpoint_candidate_egress_backlog(endpoint, false).1
    } else {
        endpoint.client.qcsd_has_pending_stream_send()
    }
}

/// Candidate backlog split used by `BuFLO`'s stop-then-drain boundary.
///
/// Both components retain required STREAM work and unconfirmed application
/// send halves. After `BuFLO` stops its schedule, retained chaff request streams
/// are the sole exception: shaping remains enabled, so a later loss cannot
/// transmit targetlessly, and the typed terminal cancellation will replace
/// that send work after already-advertised incoming credit drains. Before the
/// stop, chaff STREAM data and retransmission remain ordinary required work.
/// The aggregate additionally retains defense receive control; the STREAM
/// component excludes that control so an already-encoded, RTT-delayed
/// `MAX_STREAM_DATA` cannot manufacture authority for another exact cell.
fn endpoint_candidate_egress_backlog(
    endpoint: &mut Endpoint,
    exclude_stopped_buflo_chaff_sends: bool,
) -> (bool, bool) {
    let allowed_chaff_requests: Vec<_> = if exclude_stopped_buflo_chaff_sends {
        endpoint.chaff_send_streams.iter().copied().collect()
    } else {
        Vec::new()
    };
    let required_stream_pending = endpoint
        .client
        .qcsd_has_pending_required_stream_send(&allowed_chaff_requests);
    let defense_control_pending = endpoint.client.qcsd_has_pending_defense_control();
    candidate_egress_backlog_components(
        required_stream_pending,
        application_send_halves_peer_confirmed(endpoint),
        defense_control_pending,
    )
}

const fn candidate_egress_backlog_components(
    required_stream_pending: bool,
    application_send_halves_peer_confirmed: bool,
    defense_control_pending: bool,
) -> (bool, bool) {
    (
        required_stream_pending || !application_send_halves_peer_confirmed,
        required_stream_pending
            || !application_send_halves_peer_confirmed
            || defense_control_pending,
    )
}

fn backlog_component_changed(previous: &mut Option<bool>, current: bool) -> bool {
    if *previous == Some(current) {
        return false;
    }
    *previous = Some(current);
    true
}

fn candidate_stream_snapshot_should_emit(previous: &mut Option<bool>, current: bool) -> bool {
    let changed = backlog_component_changed(previous, current);
    changed || !current
}

fn candidate_aggregate_snapshot_should_emit(
    previous: &mut Option<bool>,
    current: bool,
    force_fresh: bool,
) -> bool {
    backlog_component_changed(previous, current) || force_fresh
}

fn endpoint_send_terminal(endpoint: &mut Endpoint, candidate_defense: bool) -> bool {
    !candidate_defense
        || (!endpoint_egress_backlog_pending(endpoint, true)
            && application_send_halves_peer_confirmed(endpoint)
            && chaff_send_halves_peer_confirmed(endpoint))
}

fn tracked_application_send_halves_peer_confirmed(
    streams: &BTreeSet<StreamId>,
    mut peer_confirmed: impl FnMut(StreamId) -> bool,
) -> bool {
    streams.iter().copied().all(&mut peer_confirmed)
}

fn chaff_send_halves_peer_confirmed(endpoint: &Endpoint) -> bool {
    endpoint.chaff_send_streams.iter().copied().all(|stream| {
        endpoint
            .client
            .qcsd_chaff_send_stream_peer_confirmed(stream)
    })
}

fn ready_request_batch(
    defense: &DefenseConfig,
    request_policy: RequestPolicyArg,
    application_stream_in_flight: bool,
    defense_batch_ready: bool,
    dependencies: &DependencyTracker,
) -> Vec<u32> {
    if !defense_batch_ready
        || matches!(defense, DefenseConfig::WalkieTalkie(_)) && application_stream_in_flight
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
    max_events: Option<usize>,
) -> Result<(), Error> {
    let mut handled_events = 0_usize;
    loop {
        if max_events.is_some_and(|limit| handled_events >= limit) {
            break;
        }
        let event = endpoint
            .deferred_data_readable
            .pop_front()
            .map(|stream_id| Http3ClientEvent::DataReadable { stream_id })
            .or_else(|| endpoint.client.next_event());
        let Some(event) = event else {
            break;
        };
        handled_events = handled_events.saturating_add(1);
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
                    if max_events.is_some() {
                        if !endpoint.deferred_data_readable.contains(&stream_id) {
                            endpoint.deferred_data_readable.push_back(stream_id);
                        }
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
    endpoint
        .deferred_data_readable
        .retain(|candidate| *candidate != stream_id);
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
        | QcsdAction::PrearmPacket { endpoint, .. }
        | QcsdAction::CommitPrearmedPacket { endpoint, .. }
        | QcsdAction::CancelPrearmedPacket { endpoint, .. }
        | QcsdAction::RequestChaff { endpoint, .. }
        | QcsdAction::CancelChaff { endpoint, .. }
        | QcsdAction::ReleaseChaffSendShaping { endpoint }
        | QcsdAction::ReleaseApplicationSendShaping { endpoint } => Some(*endpoint),
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
        let terminal = terminal_observation_slot(observation.observation());
        let terminal_us = terminal.map(|_| duration_as_trace_micros(defense_elapsed));
        controller.observe(observation.observation().clone(), defense_elapsed);
        record_qcsd_observation(
            endpoint,
            controller,
            traces,
            &observation,
            terminal_us,
            None,
        )?;
        if let Some(slot) = terminal {
            require_controller_terminal_resolution(controller, slot, defense_elapsed)?;
        }
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
        let terminal = terminal_observation_slot(observation.observation());
        let terminal_us = terminal.map(|_| duration_as_trace_micros(defense_elapsed));
        controller.observe(observation.observation().clone(), defense_elapsed);
        record_qcsd_observation(
            &mut endpoints[endpoint_index],
            controller,
            traces,
            &observation,
            terminal_us,
            None,
        )?;
        if let Some(slot) = terminal {
            require_controller_terminal_resolution(controller, slot, defense_elapsed)?;
        }
    }
    Ok(())
}

fn take_all_qcsd_observations(
    endpoints: &mut [Endpoint],
) -> Vec<(usize, TimestampedQcsdObservation)> {
    let mut observations = Vec::new();
    for (endpoint_index, endpoint) in endpoints.iter_mut().enumerate() {
        observations.extend(
            endpoint
                .client
                .qcsd_timestamped_observations()
                .into_iter()
                .map(|observation| (endpoint_index, observation)),
        );
        #[cfg(test)]
        observations.extend(
            endpoint
                .test_output_observations
                .drain(..)
                .map(|observation| (endpoint_index, observation)),
        );
    }
    observations.sort_by_key(|(_, observation)| observation.sequence());
    observations
}

fn forward_qcsd_observation(
    controller: &mut QcsdController,
    observation: &TimestampedQcsdObservation,
    defense_elapsed: Option<Duration>,
) {
    if defense_elapsed.is_some()
        || !matches!(
            observation.observation(),
            QcsdObservation::ClassifiedDatagram { .. }
        )
    {
        controller.observe(
            observation.observation().clone(),
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
        forward_qcsd_observation(controller, &observation, None);
        record_qcsd_observation(
            &mut endpoints[endpoint_index],
            controller,
            traces,
            &observation,
            None,
            None,
        )?;
    }
    Ok(())
}

const fn terminal_observation_slot(observation: &QcsdObservation) -> Option<QcsdSlotId> {
    match observation {
        QcsdObservation::SlotSatisfied { slot, .. }
        | QcsdObservation::SlotMissed { slot, .. }
        | QcsdObservation::SlotResolved { slot, .. } => Some(*slot),
        _ => None,
    }
}

fn duration_as_trace_micros(value: Duration) -> u64 {
    u64::try_from(value.as_micros()).unwrap_or(u64::MAX)
}

fn require_controller_terminal_resolution(
    controller: &QcsdController,
    slot: QcsdSlotId,
    expected: Duration,
) -> Result<u64, Error> {
    let observed = controller.terminal_slot_resolution_at(slot).ok_or_else(|| {
        Error::SlotInvariant(format!(
            "slot {} produced terminal trace evidence without a controller resolution timestamp",
            slot.0
        ))
    })?;
    if observed != expected {
        return Err(Error::SlotInvariant(format!(
            "slot {} controller resolution time {observed:?} differs from terminal reducer time {expected:?}",
            slot.0
        )));
    }
    Ok(duration_as_trace_micros(observed))
}

fn controller_terminal_resolution_us(
    controller: &QcsdController,
    slot: QcsdSlotId,
) -> Result<u64, Error> {
    let at = controller
        .terminal_slot_resolution_at(slot)
        .ok_or_else(|| {
            Error::SlotInvariant(format!(
                "slot {} terminal action lacks a controller resolution timestamp",
                slot.0
            ))
        })?;
    Ok(duration_as_trace_micros(at))
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
    controller: &QcsdController,
    traces: &mut TraceFiles,
    record: &TimestampedQcsdObservation,
    terminal_defense_elapsed_us: Option<u64>,
    receive_credit_handoff_at: Option<Instant>,
) -> Result<(), Error> {
    let observation = record.observation();
    if terminal_observation_slot(observation).is_some() != terminal_defense_elapsed_us.is_some() {
        return Err(Error::SlotInvariant(
            "terminal observation and controller-resolution timestamp differ".into(),
        ));
    }
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
                terminal_defense_elapsed_us: terminal_defense_elapsed_us
                    .expect("terminal observation timestamp checked"),
            })?;
        }
        QcsdObservation::SlotMissed {
            slot,
            reason,
            packet,
            ..
        } => {
            let logical_endpoint = if traces.is_slot_pending(*slot) {
                traces.pending_slot_endpoint(*slot)
            } else {
                Some(endpoint.id)
            };
            let scheduled = endpoint
                .scheduled_outgoing
                .iter()
                .position(|scheduled| scheduled.slot == *slot)
                .and_then(|index| endpoint.scheduled_outgoing.remove(index));
            let scheduled_packet = scheduled.map_or(*packet, |value| value.packet);
            let miss_reason = format!("{reason:?}");
            let semantics = if matches!(
                reason,
                MissedSlotReason::EndpointClosed
                    | MissedSlotReason::KeysUnavailable
                    | MissedSlotReason::PathMtu
            ) {
                TerminalActionSemantics::ExplicitCancellation(*reason)
            } else {
                TerminalActionSemantics::OpportunityResolution
            };
            schedule_terminal_row(
                traces,
                &ScheduleTraceRow {
                    action_time_us: record.produced_monotonic_ns() / 1_000,
                    endpoint: logical_endpoint,
                    packet: scheduled_packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: &miss_reason,
                    slot: *slot,
                    qcsd: QcsdTraceColumns::default(),
                    terminal_defense_elapsed_us: terminal_defense_elapsed_us
                        .expect("terminal observation timestamp checked"),
                },
                semantics,
            )?;
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
                terminal_defense_elapsed_us: terminal_defense_elapsed_us
                    .expect("terminal observation timestamp checked"),
            })?;
        }
        QcsdObservation::EndpointClosed { .. } => {
            // Transport discards uncommitted previews without publishing a
            // slot outcome. Mirror that inert transition in runner state;
            // committed targets have their own preceding SlotMissed outcome.
            endpoint.prearmed_outgoing.clear();
        }
        _ => {}
    }
    traces.observation_after_controller(
        Some(endpoint.id),
        record,
        controller,
        receive_credit_handoff_at,
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalActionSemantics {
    OpportunityResolution,
    ExplicitCancellation(MissedSlotReason),
}

fn schedule_terminal_row(
    traces: &mut TraceFiles,
    row: &ScheduleTraceRow<'_>,
    semantics: TerminalActionSemantics,
) -> Result<(), Error> {
    match semantics {
        TerminalActionSemantics::ExplicitCancellation(reason)
            if row.terminal_defense_elapsed_us < row.packet.timestamp_us() =>
        {
            traces.schedule_future_cancellation(row, reason)
        }
        TerminalActionSemantics::OpportunityResolution
        | TerminalActionSemantics::ExplicitCancellation(_) => traces.schedule(row),
    }
}

fn record_terminal_action(
    traces: &mut TraceFiles,
    now: Instant,
    action_time_us: u64,
    terminal_defense_elapsed_us: Option<u64>,
    event_outcome: &str,
    semantics: TerminalActionSemantics,
    action: &QcsdAction,
) -> Result<bool, Error> {
    let (endpoint, packet, satisfaction, miss_reason, slot, action_reason) = match action {
        QcsdAction::SlotMissed {
            endpoint,
            packet,
            slot,
            reason,
        } => (
            *endpoint,
            *packet,
            "missed",
            format!("{reason:?}"),
            *slot,
            Some(*reason),
        ),
        QcsdAction::SlotSatisfied {
            endpoint,
            packet,
            slot,
        } => (*endpoint, *packet, "satisfied", String::new(), *slot, None),
        _ => return Ok(false),
    };
    if let TerminalActionSemantics::ExplicitCancellation(reason) = semantics
        && action_reason != Some(reason)
    {
        return Err(Error::SlotInvariant(format!(
            "slot {} explicit cancellation reason {reason:?} disagrees with terminal action",
            slot.0
        )));
    }
    schedule_terminal_row(
        traces,
        &ScheduleTraceRow {
            action_time_us,
            endpoint,
            packet,
            satisfaction,
            observed: None,
            miss_reason: &miss_reason,
            slot,
            qcsd: QcsdTraceColumns::exact(packet.length(), None),
            terminal_defense_elapsed_us: terminal_defense_elapsed_us.ok_or_else(|| {
                Error::SlotInvariant(format!(
                    "slot {} terminal action lacks an exact defense-clock resolution",
                    slot.0
                ))
            })?,
        },
        semantics,
    )?;
    traces.event(now, endpoint, "action", event_outcome, action)?;
    Ok(true)
}

#[expect(
    clippy::too_many_lines,
    reason = "abort reconciliation keeps controller, adapter, and trace cleanup in one atomic path"
)]
fn cancel_uncommitted_prearms_on_abort(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
) -> Result<(), Error> {
    let unreconciled_due = controller.rolling_reconciliation_due_packet();
    let mut controller_action = controller.take_rolling_prearm_for_abort();
    if let Some(packet) = unreconciled_due {
        traces.event(
            now,
            None,
            "action",
            "abort_cleanup_unreconciled_due_marker",
            &json!({
                "kind": "unreconciled_due_rolling_preview",
                "packet": packet,
                "reason": "run_aborted_before_successful_reconciliation",
            }),
        )?;
    }
    let runner_prearms: Vec<_> = endpoints
        .iter()
        .flat_map(|endpoint| {
            endpoint
                .prearmed_outgoing
                .iter()
                .map(move |prearm| (endpoint.id, *prearm))
        })
        .collect();
    if runner_prearms.len() > 1 {
        return Err(Error::SlotInvariant(format!(
            "rolling abort found {} runner previews",
            runner_prearms.len()
        )));
    }
    let runner_action =
        runner_prearms
            .first()
            .map(|(endpoint, prearm)| QcsdAction::CancelPrearmedPacket {
                endpoint: *endpoint,
                packet: prearm.packet,
                slot: prearm.slot,
                reason: QcsdPrearmCancellationReason::RunAborted,
            });
    let same_identity = match (&controller_action, &runner_action) {
        (
            Some(QcsdAction::CancelPrearmedPacket {
                endpoint: controller_endpoint,
                packet: controller_packet,
                slot: controller_slot,
                ..
            }),
            Some(QcsdAction::CancelPrearmedPacket {
                endpoint: runner_endpoint,
                packet: runner_packet,
                slot: runner_slot,
                ..
            }),
        ) => {
            controller_endpoint == runner_endpoint
                && controller_packet == runner_packet
                && controller_slot == runner_slot
        }
        _ => false,
    };

    // A due poll legitimately owns two provisional identities until its action
    // batch commits: runner/adapter still hold the current target while the
    // controller has already staged the following tick. Reconcile both once;
    // identity divergence here is a transition, not corruption.
    let mut cleanup = Vec::new();
    if let Some(action) = runner_action {
        if same_identity {
            cleanup.push((
                controller_action
                    .take()
                    .expect("matching controller cancellation"),
                true,
            ));
        } else {
            cleanup.push((action, true));
        }
    }
    if let Some(action) = controller_action {
        cleanup.push((action, false));
    }

    for (action, reached_adapter) in cleanup {
        let QcsdAction::CancelPrearmedPacket {
            endpoint: action_endpoint,
            slot,
            ..
        } = &action
        else {
            unreachable!("abort cleanup only contains prearm cancellations");
        };
        let action_endpoint = *action_endpoint;
        let slot = *slot;
        let outcome = if reached_adapter {
            let endpoint = endpoints
                .iter_mut()
                .find(|endpoint| endpoint.id == action_endpoint)
                .expect("runner preview endpoint inspected");
            let outcome = match endpoint.client.apply_qcsd_action(now, action.clone()) {
                Ok(None) => "abort_cleanup_applied",
                Ok(Some(_)) => {
                    return Err(Error::SlotInvariant(format!(
                        "prearm abort cleanup for slot {} created a stream",
                        slot.0
                    )));
                }
                Err(neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput))
                    if endpoint.client.qcsd_pending_packet_targets() == 0 =>
                {
                    // Connection close drops inert previews without a slot
                    // outcome. The EndpointClosed observation is the receipt for
                    // that already-retired adapter state.
                    "abort_cleanup_adapter_closed"
                }
                Err(error) => return Err(error.into()),
            };
            endpoint.prearmed_outgoing.clear();
            outcome
        } else {
            "abort_cleanup_before_adapter"
        };
        traces.event(now, Some(action_endpoint), "action", outcome, &action)?;
    }
    for endpoint in endpoints.iter_mut() {
        endpoint.prearmed_outgoing.clear();
    }
    Ok(())
}

fn terminalize_pending_slots(
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
    defense_elapsed: Duration,
    reason: MissedSlotReason,
) -> Result<(), Error> {
    record_queued_terminal_actions(
        controller,
        traces,
        now,
        TerminalActionSemantics::OpportunityResolution,
    )?;
    controller.abort_pending_slots(defense_elapsed, reason);
    record_queued_terminal_actions(
        controller,
        traces,
        now,
        TerminalActionSemantics::ExplicitCancellation(reason),
    )?;

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
        let terminal_us = controller_terminal_resolution_us(controller, slot)?;
        record_terminal_action(
            traces,
            now,
            action_time_us,
            Some(terminal_us),
            "terminalized_run_end",
            TerminalActionSemantics::ExplicitCancellation(reason),
            &action,
        )?;
    }
    Ok(())
}

fn record_queued_terminal_actions(
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
    semantics: TerminalActionSemantics,
) -> Result<(), Error> {
    let actions: Vec<_> = controller.drain_actions().collect();
    for action in actions {
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
        let terminal_us = terminal_slot
            .map(|slot| controller_terminal_resolution_us(controller, slot))
            .transpose()?;
        if !record_terminal_action(
            traces,
            now,
            action_time_us,
            terminal_us,
            "terminalized_queued",
            semantics,
            &action,
        )? && matches!(
            action,
            QcsdAction::PrearmPacket { .. }
                | QcsdAction::CommitPrearmedPacket { .. }
                | QcsdAction::CancelPrearmedPacket { .. }
        ) {
            traces.event(
                now,
                action_endpoint(&action),
                "action",
                "terminalized_queued",
                &action,
            )?;
        }
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
        | QcsdAction::CommitPrearmedPacket {
            endpoint,
            packet,
            slot,
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
            QcsdAction::SendPacket { .. } | QcsdAction::CommitPrearmedPacket { .. } => None,
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

fn validate_chaff_cancellation_target(
    streams: &HashMap<StreamId, StreamRecord>,
    stream: neqo_csdef::QcsdStreamId,
) -> Result<StreamId, Error> {
    let stream_id = StreamId::new(stream.0);
    let Some(record) = streams.get(&stream_id) else {
        return Err(Error::SlotInvariant(format!(
            "client-local defense termination targeted unknown chaff stream {}",
            stream.0
        )));
    };
    if !matches!(record.role, QcsdRequestRole::Chaff { .. }) {
        return Err(Error::SlotInvariant(format!(
            "client-local defense termination targeted application stream {}",
            stream.0
        )));
    }
    Ok(stream_id)
}

const fn chaff_cancellation_rollback_label(reason: QcsdChaffCancellationReason) -> &'static str {
    match reason {
        QcsdChaffCancellationReason::BufloTerminalSubcellTail => {
            "buflo_terminal_subcell_unencoded_rollback"
        }
        QcsdChaffCancellationReason::CsBufloLocalEarlyTermination => {
            "cs_buflo_local_et_unencoded_rollback"
        }
    }
}

const fn chaff_cancellation_receipt_outcome(reason: QcsdChaffCancellationReason) -> &'static str {
    match reason {
        QcsdChaffCancellationReason::BufloTerminalSubcellTail => {
            "buflo_terminal_subcell_tail_cancelled"
        }
        QcsdChaffCancellationReason::CsBufloLocalEarlyTermination => {
            "local_early_termination_cancelled"
        }
    }
}

fn validate_terminal_chaff_receive_identities(
    reason: QcsdChaffCancellationReason,
    identities: &[QcsdReceiveActionIdentity],
) -> Result<(), Error> {
    match reason {
        QcsdChaffCancellationReason::BufloTerminalSubcellTail if !identities.is_empty() => {
            Err(Error::SlotInvariant(format!(
                "BuFLO terminal sub-cell cancellation found accepted receive identities that should have remained terminal backlog: {identities:?}"
            )))
        }
        QcsdChaffCancellationReason::CsBufloLocalEarlyTermination
            if identities.iter().any(|identity| {
                !matches!(
                    identity,
                    QcsdReceiveActionIdentity::ParserLease { owner: None, .. }
                )
            }) =>
        {
            Err(Error::SlotInvariant(format!(
                "CS-BuFLO local early termination may roll back only unowned parser leases, not scheduled or owned receive identities: {identities:?}"
            )))
        }
        _ => Ok(()),
    }
}

/// Validate a typed client-local cancellation before touching HTTP/3, then
/// atomically roll back the narrow accepted-but-unencoded suffix permitted by
/// that terminal transition. `BuFLO` permits no suffix at its latch. `CS-BuFLO`
/// may discard only an unowned reviewed-chaff parser lease; scheduled or owned
/// bytes remain fail-closed accounting evidence.
fn prepare_chaff_cancellation(
    endpoint: &mut Endpoint,
    traces: &mut TraceFiles,
    now: Instant,
    action: &QcsdAction,
) -> Result<Option<(StreamId, QcsdChaffCancellationReason)>, Error> {
    let QcsdAction::CancelChaff { stream, reason, .. } = action else {
        return Ok(None);
    };
    let stream_id = validate_chaff_cancellation_target(&endpoint.streams, *stream)?;

    let identities: Vec<QcsdReceiveActionIdentity> = endpoint
        .client
        .qcsd_pending_receive_action_identities()
        .into_iter()
        .filter(|identity| {
            identity.endpoint() == endpoint.id && identity.stream().0 == stream_id.as_u64()
        })
        .collect();
    validate_terminal_chaff_receive_identities(*reason, &identities)?;
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
            chaff_cancellation_rollback_label(*reason),
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
    Ok(Some((stream_id, *reason)))
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
    normalize_rolling_prearm_window(
        &mut action,
        defense_elapsed,
        controller.config().control_interval(),
    )?;
    let endpoint_id = action_endpoint(&action);
    let action_time_us = traces.elapsed_us(now);
    let terminal_slot = match &action {
        QcsdAction::SlotMissed { slot, .. } | QcsdAction::SlotSatisfied { slot, .. } => Some(*slot),
        _ => None,
    };
    let terminal_us = terminal_slot
        .map(|slot| controller_terminal_resolution_us(controller, slot))
        .transpose()?;
    let terminal_semantics = match &action {
        QcsdAction::SlotMissed {
            reason: MissedSlotReason::EndpointClosed,
            ..
        } => TerminalActionSemantics::ExplicitCancellation(MissedSlotReason::EndpointClosed),
        _ => TerminalActionSemantics::OpportunityResolution,
    };
    if record_terminal_action(
        traces,
        now,
        action_time_us,
        terminal_us,
        "recorded",
        terminal_semantics,
        &action,
    )? {
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
            schedule_terminal_row(
                traces,
                &ScheduleTraceRow {
                    action_time_us: traces.elapsed_us(now),
                    endpoint: Some(endpoint),
                    packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: &miss_reason,
                    slot,
                    qcsd: QcsdTraceColumns::default(),
                    terminal_defense_elapsed_us: controller_terminal_resolution_us(
                        controller, slot,
                    )?,
                },
                TerminalActionSemantics::ExplicitCancellation(reason),
            )?;
        }
        traces.event(now, endpoint_id, "action", "missing_endpoint", &action)?;
        return Ok(());
    };
    if let QcsdAction::CancelPrearmedPacket { packet, slot, .. } = &trace_action {
        let Some(index) = endpoint
            .prearmed_outgoing
            .iter()
            .position(|prearm| prearm.slot == *slot && prearm.packet == *packet)
        else {
            return Err(Error::SlotInvariant(format!(
                "cancellation for unknown or mismatched prearmed slot {}",
                slot.0
            )));
        };
        endpoint.client.apply_qcsd_action(now, action)?;
        _ = endpoint.prearmed_outgoing.remove(index);
        traces.event(now, endpoint_id, "action", "applied", &trace_action)?;
        return Ok(());
    }
    // This is deliberately before `apply_qcsd_action`: a stale or invalid
    // CancelChaff identity must never mutate an application or unknown stream.
    let canceled_chaff = prepare_chaff_cancellation(endpoint, traces, now, &trace_action)?;
    let scheduled_packet = match &trace_action {
        QcsdAction::SendPacket {
            packet,
            slot,
            deadline_after_us,
            ..
        } => Some(ScheduledOutgoing {
            slot: *slot,
            packet: *packet,
            // Fixed/legacy targets never use the rolling adapter-release
            // selector. Avoid introducing a new overflow failure path for
            // their previously ignored `not_before_after_us` value.
            not_before: now,
            deadline: now
                .checked_add(Duration::from_micros(*deadline_after_us))
                .ok_or_else(|| {
                    Error::SlotInvariant(format!(
                        "outgoing slot {} lacked a representable handoff deadline",
                        slot.0
                    ))
                })?,
            rolling_prearmed: false,
        }),
        QcsdAction::CommitPrearmedPacket { packet, slot, .. } => {
            let Some(prearm) = endpoint
                .prearmed_outgoing
                .iter()
                .find(|prearm| prearm.slot == *slot && prearm.packet == *packet)
            else {
                return Err(Error::SlotInvariant(format!(
                    "commit for unknown or mismatched prearmed slot {}",
                    slot.0
                )));
            };
            Some(ScheduledOutgoing {
                slot: *slot,
                packet: *packet,
                not_before: prearm.not_before,
                deadline: prearm.deadline,
                rolling_prearmed: true,
            })
        }
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
            if let QcsdAction::PrearmPacket {
                packet,
                slot,
                not_before_after_us,
                deadline_after_us,
                ..
            } = &trace_action
            {
                let not_before = now
                    .checked_add(Duration::from_micros(*not_before_after_us))
                    .ok_or_else(|| {
                        Error::SlotInvariant(format!(
                            "prearmed slot {} lacked a representable adapter release",
                            slot.0
                        ))
                    })?;
                let deadline = now
                    .checked_add(Duration::from_micros(*deadline_after_us))
                    .ok_or_else(|| {
                        Error::SlotInvariant(format!(
                            "prearmed slot {} lacked a representable deadline",
                            slot.0
                        ))
                    })?;
                endpoint.prearmed_outgoing.push_back(PrearmedOutgoing {
                    slot: *slot,
                    packet: *packet,
                    not_before,
                    deadline,
                });
            }
            if let QcsdAction::CommitPrearmedPacket { packet, slot, .. } = &trace_action {
                let index = endpoint
                    .prearmed_outgoing
                    .iter()
                    .position(|prearm| prearm.slot == *slot && prearm.packet == *packet)
                    .expect("validated prearm survived successful adapter commit");
                _ = endpoint.prearmed_outgoing.remove(index);
            }
            if let Some(scheduled) = scheduled_packet {
                endpoint.scheduled_outgoing.push_back(scheduled);
            }
            if let Some(stream_id) = chaff_stream {
                endpoint.chaff_send_streams.insert(stream_id);
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
                        Error::DefenseExecution(
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
                    return Err(Error::DefenseExecution(format!(
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
            if let Some((stream_id, cancellation_reason)) = canceled_chaff {
                let Some(record) = endpoint.streams.get_mut(&stream_id) else {
                    return Err(Error::SlotInvariant(format!(
                        "client-local defense termination targeted unknown chaff stream {}",
                        stream_id.as_u64()
                    )));
                };
                if !matches!(record.role, QcsdRequestRole::Chaff { .. }) {
                    return Err(Error::SlotInvariant(format!(
                        "client-local defense termination targeted application stream {}",
                        stream_id.as_u64()
                    )));
                }
                record.outcome = chaff_cancellation_receipt_outcome(cancellation_reason);
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
                schedule_terminal_row(
                    traces,
                    &ScheduleTraceRow {
                        action_time_us: traces.elapsed_us(now),
                        endpoint: endpoint_id,
                        packet,
                        satisfaction: "missed",
                        observed: None,
                        miss_reason: &miss_reason,
                        slot,
                        qcsd: QcsdTraceColumns::default(),
                        terminal_defense_elapsed_us: controller_terminal_resolution_us(
                            controller, slot,
                        )?,
                    },
                    TerminalActionSemantics::ExplicitCancellation(reason),
                )?;
            }
            record_adapter_action_error(traces, now, &trace_action, &error)?;
            return Err(error.into());
        }
    }
    Ok(())
}

fn normalize_rolling_prearm_window(
    action: &mut QcsdAction,
    defense_elapsed: Duration,
    control_interval: Duration,
) -> Result<(), Error> {
    let QcsdAction::PrearmPacket {
        packet,
        slot,
        not_before_after_us,
        deadline_after_us,
        ..
    } = action
    else {
        return Ok(());
    };
    let absolute_deadline = packet.timestamp().saturating_add(control_interval);
    *not_before_after_us = u64::try_from(
        packet
            .timestamp()
            .saturating_sub(defense_elapsed)
            .as_nanos()
            .div_ceil(1_000),
    )
    .unwrap_or(u64::MAX);
    *deadline_after_us = u64::try_from(
        absolute_deadline
            .saturating_sub(defense_elapsed)
            .as_micros(),
    )
    .unwrap_or(u64::MAX);
    if *deadline_after_us == 0 || *not_before_after_us >= *deadline_after_us {
        return Err(Error::SlotInvariant(format!(
            "rolling prearm slot {} reached dispatch outside its absolute defense window",
            slot.0
        )));
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
            QcsdAction::SendPacket { .. } | QcsdAction::CommitPrearmedPacket { .. },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufloExactReleaseGuard {
    endpoint_index: usize,
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
    packet: Packet,
    phase: BufloExactReleasePhase,
    /// Stop admitting fresh ordinary transport work early enough that its
    /// complete realization allowance ends before the exact-release guard.
    output_admission_at: Instant,
    guard_at: Instant,
    active_wait_at: Instant,
    release: Instant,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutputWorkBoundary {
    admission_at: Instant,
    resume_at: Instant,
}

impl OutputWorkBoundary {
    const fn new(admission_at: Instant, resume_at: Instant) -> Self {
        Self {
            admission_at,
            resume_at,
        }
    }

    fn closed_wakeup(self, current: Instant) -> Option<Instant> {
        (current >= self.admission_at).then_some(self.resume_at)
    }
}

fn earliest_output_work_boundary(
    current: Option<OutputWorkBoundary>,
    candidate: OutputWorkBoundary,
) -> OutputWorkBoundary {
    current.map_or(candidate, |current| {
        if (candidate.admission_at, candidate.resume_at) < (current.admission_at, current.resume_at)
        {
            candidate
        } else {
            current
        }
    })
}

impl BufloExactReleaseGuard {
    const fn output_work_boundary(self) -> OutputWorkBoundary {
        OutputWorkBoundary::new(self.output_admission_at, self.guard_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CsExactIncomingRetryPhase {
    Quarter,
    Half,
    ThreeQuarter,
}

impl CsExactIncomingRetryPhase {
    const ALL: [Self; 3] = [Self::Quarter, Self::Half, Self::ThreeQuarter];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CsExactIncomingRetry {
    endpoint_index: usize,
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
    phase: CsExactIncomingRetryPhase,
    target: Instant,
    phase_at: Instant,
    deadline: Instant,
}

type CsExactIncomingRetryKey = (QcsdEndpointId, QcsdSlotId, CsExactIncomingRetryPhase);

fn exact_incoming_retry_times(target: Instant, deadline: Instant) -> Option<[Instant; 3]> {
    let window = deadline.checked_duration_since(target)?;
    let quarter = window / 4;
    if quarter.is_zero() {
        return None;
    }
    let quarter_at = target.checked_add(quarter)?;
    let half_at = quarter_at.checked_add(quarter)?;
    let three_quarter_at = half_at.checked_add(quarter)?;
    (target < quarter_at && three_quarter_at < deadline).then_some([
        quarter_at,
        half_at,
        three_quarter_at,
    ])
}

fn cs_exact_incoming_retry_is_due(retry: &CsExactIncomingRetry, current: Instant) -> bool {
    current >= retry.target && current >= retry.phase_at && current < retry.deadline
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BufloExactReleasePhase {
    Prearmed,
    Committed,
}

impl BufloExactReleasePhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prearmed => "prearmed",
            Self::Committed => "committed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BufloExactReleaseWaitStep {
    Passive(Duration),
    Active,
    Dispatch,
}

const BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufloExactReleaseCandidate {
    endpoint_index: usize,
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
    packet: Packet,
    phase: BufloExactReleasePhase,
    release: Instant,
    deadline: Instant,
}

fn buflo_candidate_has_queued_terminal_cancellation(
    controller: &QcsdController,
    candidate: &BufloExactReleaseCandidate,
) -> bool {
    candidate.phase == BufloExactReleasePhase::Prearmed
        && controller.rolling_outgoing_prearm_identity().is_none()
        && controller.has_queued_terminal_prearm_cancellation(
            candidate.endpoint,
            candidate.packet,
            candidate.slot,
        )
}

#[cfg(test)]
fn buflo_exact_release_guard_from_candidates(
    enabled: bool,
    candidates: impl IntoIterator<Item = BufloExactReleaseCandidate>,
    active_wait_tail: Duration,
) -> Result<Option<BufloExactReleaseGuard>, Error> {
    buflo_exact_release_guard_excluding_candidates(enabled, candidates, active_wait_tail, |_| false)
}

fn buflo_exact_release_guard_excluding_candidates(
    enabled: bool,
    candidates: impl IntoIterator<Item = BufloExactReleaseCandidate>,
    active_wait_tail: Duration,
    excluded: impl Fn(&BufloExactReleaseCandidate) -> bool,
) -> Result<Option<BufloExactReleaseGuard>, Error> {
    if !enabled {
        return Ok(None);
    }

    let candidates: Vec<_> = candidates.into_iter().collect();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.packet.direction() != Direction::Outgoing {
            return Err(Error::SlotInvariant(format!(
                "BuFLO exact-release candidate slot {} was not outgoing",
                candidate.slot.0
            )));
        }
        if candidate.release >= candidate.deadline {
            return Err(Error::SlotInvariant(format!(
                "BuFLO exact-release candidate slot {} had an empty adapter window",
                candidate.slot.0
            )));
        }
        if candidates
            .iter()
            .skip(index + 1)
            .any(|other| other.slot == candidate.slot)
        {
            return Err(Error::SlotInvariant(format!(
                "BuFLO exact-release candidate slot {} violated global runner ownership",
                candidate.slot.0
            )));
        }
    }

    let Some(candidate) = candidates
        .into_iter()
        .filter(|candidate| !excluded(candidate))
        .min_by_key(|candidate| {
            (
                candidate.release,
                candidate.deadline,
                candidate.slot,
                candidate.endpoint_index,
            )
        })
    else {
        return Ok(None);
    };
    let realization_window = candidate.deadline.duration_since(candidate.release);
    let admission_lead = realization_window.saturating_mul(2);
    let active_wait_tail = active_wait_tail.min(admission_lead);
    let active_wait_at = candidate
        .release
        .checked_sub(active_wait_tail)
        .unwrap_or(candidate.release);
    let nominal_guard_at = candidate
        .release
        .checked_sub(realization_window)
        .unwrap_or(candidate.release);
    let output_admission_at = candidate
        .release
        .checked_sub(admission_lead)
        .unwrap_or(candidate.release);
    let guard_at = nominal_guard_at.min(active_wait_at);
    Ok(Some(BufloExactReleaseGuard {
        endpoint_index: candidate.endpoint_index,
        endpoint: candidate.endpoint,
        slot: candidate.slot,
        packet: candidate.packet,
        phase: candidate.phase,
        output_admission_at,
        guard_at,
        active_wait_at,
        release: candidate.release,
        deadline: candidate.deadline,
    }))
}

fn next_buflo_exact_release_guard(
    defense: &DefenseConfig,
    controller: &QcsdController,
    endpoints: &[Endpoint],
) -> Result<Option<BufloExactReleaseGuard>, Error> {
    let guard = buflo_exact_release_guard_excluding_candidates(
        matches!(defense, DefenseConfig::Buflo(_)),
        endpoints
            .iter()
            .enumerate()
            .flat_map(|(endpoint_index, endpoint)| {
                endpoint
                    .prearmed_outgoing
                    .iter()
                    .map(move |prearm| BufloExactReleaseCandidate {
                        endpoint_index,
                        endpoint: endpoint.id,
                        slot: prearm.slot,
                        packet: prearm.packet,
                        phase: BufloExactReleasePhase::Prearmed,
                        release: prearm.not_before,
                        deadline: prearm.deadline,
                    })
                    .chain(
                        endpoint
                            .scheduled_outgoing
                            .iter()
                            .filter(|scheduled| scheduled.rolling_prearmed)
                            .map(move |scheduled| BufloExactReleaseCandidate {
                                endpoint_index,
                                endpoint: endpoint.id,
                                slot: scheduled.slot,
                                packet: scheduled.packet,
                                phase: BufloExactReleasePhase::Committed,
                                release: scheduled.not_before,
                                deadline: scheduled.deadline,
                            }),
                    )
            }),
        BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        |candidate| buflo_candidate_has_queued_terminal_cancellation(controller, candidate),
    )?;
    let Some(guard) = guard else {
        return Ok(None);
    };

    let identity = (guard.endpoint, guard.packet, guard.slot);
    match guard.phase {
        BufloExactReleasePhase::Prearmed => {
            if controller.rolling_outgoing_prearm_identity() != Some(identity) {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO runner prearm slot {} diverged from the controller identity",
                    guard.slot.0
                )));
            }
        }
        BufloExactReleasePhase::Committed => {
            if !controller
                .pending_slots()
                .iter()
                .any(|(slot, packet)| *slot == guard.slot && *packet == guard.packet)
            {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO committed runner slot {} lacked controller ownership",
                    guard.slot.0
                )));
            }
        }
    }
    Ok(Some(guard))
}

fn buflo_exact_release_wait_step(
    guard: &BufloExactReleaseGuard,
    current: Instant,
) -> BufloExactReleaseWaitStep {
    if current >= guard.release {
        BufloExactReleaseWaitStep::Dispatch
    } else if current < guard.active_wait_at {
        BufloExactReleaseWaitStep::Passive(guard.active_wait_at.duration_since(current))
    } else {
        BufloExactReleaseWaitStep::Active
    }
}

#[cfg(target_os = "linux")]
fn linux_clock_nanoseconds(clock_id: libc::clockid_t) -> Option<u64> {
    let mut value: libc::timespec = unsafe { mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &raw mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return None;
    }
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()?)
}

fn buflo_exact_release_aux_clock_sample() -> BufloExactReleaseAuxClockSample {
    #[cfg(target_os = "linux")]
    {
        BufloExactReleaseAuxClockSample {
            monotonic_raw_nanoseconds: linux_clock_nanoseconds(libc::CLOCK_MONOTONIC_RAW),
            thread_cpu_nanoseconds: linux_clock_nanoseconds(libc::CLOCK_THREAD_CPUTIME_ID),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        BufloExactReleaseAuxClockSample::default()
    }
}

fn record_active_spin_gap(
    evidence: &mut BufloExactReleaseWaitEvidence,
    previous: Instant,
    current: Instant,
) {
    let gap = duration_as_u64_nanos(current.saturating_duration_since(previous));
    evidence.max_active_spin_gap_nanoseconds = evidence.max_active_spin_gap_nanoseconds.max(gap);
    if gap > duration_as_u64_nanos(BUFLO_EXACT_RELEASE_SPIN_INTERRUPTION_THRESHOLD) {
        evidence.active_spin_interruptions = evidence.active_spin_interruptions.saturating_add(1);
        evidence.active_spin_interruption_nanoseconds = evidence
            .active_spin_interruption_nanoseconds
            .saturating_add(gap);
    }
}

fn wait_for_buflo_exact_release(guard: &BufloExactReleaseGuard) -> BufloExactReleaseWaitEvidence {
    let entered_at = now();
    let mut active_wait_started_at = None;
    let mut active_wait_start_clocks = None;
    let mut previous_active_sample_at = None;
    let mut evidence = BufloExactReleaseWaitEvidence {
        entered_at,
        active_wait_started_at: entered_at,
        dispatch_at: entered_at,
        passive_sleep_calls: 0,
        passive_sleep_requested_nanoseconds: 0,
        passive_sleep_elapsed_nanoseconds: 0,
        max_passive_sleep_overrun_nanoseconds: 0,
        active_wait_iterations: 0,
        active_spin_interruptions: 0,
        active_spin_interruption_nanoseconds: 0,
        max_active_spin_gap_nanoseconds: 0,
        active_wait_start_clocks: BufloExactReleaseAuxClockSample::default(),
        active_wait_end_clocks: BufloExactReleaseAuxClockSample::default(),
    };
    loop {
        let current = now();
        match buflo_exact_release_wait_step(guard, current) {
            BufloExactReleaseWaitStep::Passive(delay) => {
                std::thread::sleep(delay);
                let returned_at = now();
                let elapsed = duration_as_u64_nanos(returned_at.saturating_duration_since(current));
                let requested = duration_as_u64_nanos(delay);
                evidence.passive_sleep_calls = evidence.passive_sleep_calls.saturating_add(1);
                evidence.passive_sleep_requested_nanoseconds = evidence
                    .passive_sleep_requested_nanoseconds
                    .saturating_add(requested);
                evidence.passive_sleep_elapsed_nanoseconds = evidence
                    .passive_sleep_elapsed_nanoseconds
                    .saturating_add(elapsed);
                evidence.max_passive_sleep_overrun_nanoseconds = evidence
                    .max_passive_sleep_overrun_nanoseconds
                    .max(elapsed.saturating_sub(requested));
            }
            BufloExactReleaseWaitStep::Active => {
                if active_wait_started_at.is_none() {
                    active_wait_started_at = Some(current);
                    active_wait_start_clocks = Some(buflo_exact_release_aux_clock_sample());
                    // Keep auxiliary clock-read overhead out of the observed
                    // inter-iteration gaps used to identify active-spin
                    // interruptions.
                    previous_active_sample_at = Some(now());
                } else if let Some(previous) = previous_active_sample_at.replace(current) {
                    record_active_spin_gap(&mut evidence, previous, current);
                }
                evidence.active_wait_iterations = evidence.active_wait_iterations.saturating_add(1);
                // `spin_loop()` is a shared-memory synchronization hint.  On
                // AArch64 it lowers to an ISB, which needlessly serializes
                // every iteration of this deadline clock poll.  The loop
                // remains an active wait: its next iteration immediately
                // samples `Instant` again without an architecture-specific
                // processor hint.
            }
            BufloExactReleaseWaitStep::Dispatch => {
                if let Some(previous) = previous_active_sample_at {
                    record_active_spin_gap(&mut evidence, previous, current);
                }
                let (active_wait_start_clocks, active_wait_end_clocks) = active_wait_start_clocks
                    .map_or_else(
                        || {
                            let sample = buflo_exact_release_aux_clock_sample();
                            (sample, sample)
                        },
                        |start| (start, buflo_exact_release_aux_clock_sample()),
                    );
                evidence.active_wait_started_at = active_wait_started_at.unwrap_or(current);
                evidence.dispatch_at = current;
                evidence.active_wait_start_clocks = active_wait_start_clocks;
                evidence.active_wait_end_clocks = active_wait_end_clocks;
                return evidence;
            }
        }
    }
}

#[expect(
    clippy::suspicious_operation_groupings,
    reason = "slot identity deliberately compares differently named absolute release fields"
)]
fn buflo_guard_identity_matches_runner(
    guard: &BufloExactReleaseGuard,
    endpoints: &[Endpoint],
    phase: BufloExactReleasePhase,
) -> bool {
    let Some(endpoint) = endpoints.get(guard.endpoint_index) else {
        return false;
    };
    if endpoint.id != guard.endpoint {
        return false;
    }
    match phase {
        BufloExactReleasePhase::Prearmed => endpoint.prearmed_outgoing.iter().any(|prearm| {
            (prearm.slot == guard.slot)
                && (prearm.packet == guard.packet)
                && (prearm.not_before == guard.release)
                && (prearm.deadline == guard.deadline)
        }),
        BufloExactReleasePhase::Committed => endpoint.scheduled_outgoing.iter().any(|scheduled| {
            scheduled.rolling_prearmed
                && (scheduled.slot == guard.slot)
                && (scheduled.packet == guard.packet)
                && (scheduled.not_before == guard.release)
                && (scheduled.deadline == guard.deadline)
        }),
    }
}

#[derive(Debug, Default)]
struct CsExactIncomingRetryInventory {
    retries: Vec<CsExactIncomingRetry>,
    earliest_expired_deadline: Option<Instant>,
}

fn cs_exact_incoming_retry_inventory(
    defense: &DefenseConfig,
    endpoints: &[Endpoint],
    controller: &QcsdController,
    defense_start: Option<Instant>,
    current: Instant,
    attempted: &mut BTreeSet<CsExactIncomingRetryKey>,
) -> Result<CsExactIncomingRetryInventory, Error> {
    if !matches!(defense, DefenseConfig::CsBuflo(_)) {
        attempted.clear();
        return Ok(CsExactIncomingRetryInventory::default());
    }
    let Some(defense_start) = defense_start else {
        attempted.clear();
        return Ok(CsExactIncomingRetryInventory::default());
    };

    let pending_slots: BTreeMap<_, _> = controller.pending_slots().into_iter().collect();
    let mut active = BTreeMap::new();
    for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
        for identity in endpoint.client.qcsd_pending_receive_action_identities() {
            if identity.endpoint() != endpoint.id {
                return Err(Error::SlotInvariant(format!(
                    "adapter {} reported cross-endpoint pending identity {identity:?}",
                    endpoint.id.0
                )));
            }
            let Some(slot) = identity.slot() else {
                continue;
            };
            let Some(packet) = pending_slots.get(&slot).copied() else {
                // The controller can terminalize an exact slot before an
                // already-accepted adapter suffix is physically discarded.
                // It is no longer eligible for a runner retry.
                continue;
            };
            if packet.direction() != Direction::Incoming {
                return Err(Error::SlotInvariant(format!(
                    "CS-BuFLO receive identity for slot {} was bound to an outgoing packet",
                    slot.0
                )));
            }
            active.insert((endpoint.id, slot), (endpoint_index, packet));
        }
    }

    attempted.retain(|(endpoint, slot, _)| active.contains_key(&(*endpoint, *slot)));
    let mut inventory = CsExactIncomingRetryInventory::default();
    for ((endpoint, slot), (endpoint_index, packet)) in active {
        let target = defense_start
            .checked_add(packet.timestamp())
            .ok_or_else(|| {
                Error::DefenseExecution(format!(
                    "CS-BuFLO incoming slot {} target overflow",
                    slot.0
                ))
            })?;
        let deadline = target
            .checked_add(controller.config().control_interval())
            .ok_or_else(|| {
                Error::DefenseExecution(format!(
                    "CS-BuFLO incoming slot {} deadline overflow",
                    slot.0
                ))
            })?;
        let Some(phase_times) = exact_incoming_retry_times(target, deadline) else {
            return Err(Error::SlotInvariant(format!(
                "CS-BuFLO incoming slot {} had no strict interior retry instants",
                slot.0
            )));
        };
        if current >= deadline {
            inventory.earliest_expired_deadline = inventory
                .earliest_expired_deadline
                .into_iter()
                .chain([deadline])
                .min();
            continue;
        }
        for (phase, phase_at) in CsExactIncomingRetryPhase::ALL.into_iter().zip(phase_times) {
            if !attempted.contains(&(endpoint, slot, phase)) {
                inventory.retries.push(CsExactIncomingRetry {
                    endpoint_index,
                    endpoint,
                    slot,
                    phase,
                    target,
                    phase_at,
                    deadline,
                });
            }
        }
    }
    inventory
        .retries
        .sort_unstable_by_key(|retry| (retry.phase_at, retry.endpoint, retry.slot, retry.phase));
    Ok(inventory)
}

fn cs_exact_incoming_identity_is_pending(
    endpoints: &[Endpoint],
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
) -> bool {
    endpoints.iter().any(|candidate| {
        candidate.id == endpoint
            && candidate
                .client
                .qcsd_pending_receive_action_identities()
                .iter()
                .any(|identity| identity.slot() == Some(slot))
    })
}

fn expire_due_cs_exact_incoming_credit(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    defense_start: Option<Instant>,
    expired_at: Instant,
) -> Result<(), Error> {
    let started = defense_start.ok_or_else(|| {
        Error::DefenseExecution(
            "CS-BuFLO exact incoming deadline preceded the defense clock".into(),
        )
    })?;
    let elapsed = expired_at.saturating_duration_since(started);
    // Expire the half-open local-realization window before any ordinary
    // output can encode the accepted action late. This is the same normal
    // controller boundary used below, only selected with exact priority.
    handle_all_qcsd_observations(endpoints, controller, traces, elapsed)?;
    controller.poll(elapsed);
    controller.flush_defense_observations();
    ensure_defense_realizable(controller)?;
    apply_queued_actions(
        endpoints,
        controller,
        chaff_manifest,
        traces,
        expired_at,
        elapsed,
    )?;
    Ok(())
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    reason = "the current-thread runner owns each finite exact-incoming retry boundary"
)]
async fn dispatch_due_cs_exact_incoming_retry(
    defense: &DefenseConfig,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    attempted: &mut BTreeSet<CsExactIncomingRetryKey>,
    runner_wakeup_metrics: &mut RunnerWakeupMetrics,
) -> Result<bool, Error> {
    let current = now();
    let inventory = cs_exact_incoming_retry_inventory(
        defense,
        endpoints,
        controller,
        defense_start,
        current,
        attempted,
    )?;
    if inventory.earliest_expired_deadline.is_some() {
        expire_due_cs_exact_incoming_credit(
            endpoints,
            controller,
            chaff_manifest,
            traces,
            defense_start,
            current,
        )?;
        return Ok(true);
    }

    let Some(retry) = inventory.retries.first().copied() else {
        return Ok(false);
    };
    if !cs_exact_incoming_retry_is_due(&retry, current) {
        return Ok(false);
    }
    let attempted_at = now();
    if attempted_at >= retry.deadline {
        expire_due_cs_exact_incoming_credit(
            endpoints,
            controller,
            chaff_manifest,
            traces,
            defense_start,
            attempted_at,
        )?;
        return Ok(true);
    }
    debug_assert!(retry.target < retry.phase_at && retry.phase_at <= attempted_at);
    for due in inventory.retries.iter().filter(|candidate| {
        candidate.endpoint == retry.endpoint
            && candidate.slot == retry.slot
            && candidate.phase_at <= attempted_at
    }) {
        attempted.insert((due.endpoint, due.slot, due.phase));
    }
    runner_wakeup_metrics.record_cs_exact_incoming_retry_drive(retry.phase_at, attempted_at);

    _ = drive_endpoint_output_until(
        retry.endpoint_index,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        Some(OutputWorkBoundary::new(retry.deadline, retry.deadline)),
        Some(retry.deadline),
        Some(retry.deadline),
        OutputDriveCardinality::OneDatagram,
    )
    .await?;
    let completed_at = now();
    let started = defense_start.ok_or_else(|| {
        Error::DefenseExecution("CS-BuFLO retry completed without a defense clock".into())
    })?;
    let completed_elapsed = completed_at.saturating_duration_since(started);
    // Reduce a successful physical advertisement before any ordinary runner
    // work can consume the remaining half-open window. A late observation is
    // still passed at its current strict reducer instant and fails closed.
    handle_all_qcsd_observations(endpoints, controller, traces, completed_elapsed)?;
    controller.flush_defense_observations();
    ensure_defense_realizable(controller)?;
    apply_queued_actions(
        endpoints,
        controller,
        chaff_manifest,
        traces,
        completed_at,
        completed_elapsed,
    )?;
    let resolved = !cs_exact_incoming_identity_is_pending(endpoints, retry.endpoint, retry.slot);
    if resolved {
        runner_wakeup_metrics.record_cs_exact_incoming_retry_resolution();
    }
    Ok(true)
}

#[cfg(test)]
fn buflo_unadvertised_scheduled_receive_credit_endpoints(endpoints: &[Endpoint]) -> Vec<usize> {
    endpoints
        .iter()
        .enumerate()
        .filter_map(|(index, endpoint)| {
            endpoint
                .client
                .qcsd_has_unadvertised_scheduled_receive_credit()
                .then_some(index)
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufloExactIncomingIdentity {
    endpoint_index: usize,
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
    packet: Packet,
    identity: QcsdReceiveActionIdentity,
}

const fn buflo_exact_incoming_identity_key(
    candidate: &BufloExactIncomingIdentity,
) -> (u64, usize, u64, u64, u64, u8, u64) {
    let (kind, detail) = match candidate.identity {
        QcsdReceiveActionIdentity::Scheduled { .. } => (0, 0),
        QcsdReceiveActionIdentity::ParserLease { increase, .. } => (1, increase),
    };
    (
        candidate.slot.0,
        candidate.endpoint_index,
        candidate.endpoint.0,
        candidate.identity.stream().0,
        candidate.identity.absolute_limit(),
        kind,
        detail,
    )
}

fn buflo_exact_incoming_slot_packets(
    captured: &[BufloExactIncomingIdentity],
) -> Result<BTreeMap<QcsdSlotId, Packet>, Error> {
    let mut slots = BTreeMap::new();
    for candidate in captured {
        if let Some(previous) = slots.insert(candidate.slot, candidate.packet)
            && previous != candidate.packet
        {
            return Err(Error::SlotInvariant(format!(
                "BuFLO incoming slot {} retained inconsistent packet identities",
                candidate.slot.0
            )));
        }
    }
    Ok(slots)
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed inventory validates endpoint, slot, timing, and adapter ownership before mutation"
)]
fn buflo_exact_incoming_identities(
    guard: &BufloExactReleaseGuard,
    endpoints: &[Endpoint],
    controller: &QcsdController,
    defense_start: Instant,
    allowed_slots: Option<&BTreeMap<QcsdSlotId, Packet>>,
) -> Result<Vec<BufloExactIncomingIdentity>, Error> {
    let pending_slots: BTreeMap<_, _> = controller.pending_slots().into_iter().collect();
    let mut captured = Vec::new();
    for (endpoint_index, endpoint) in endpoints.iter().enumerate() {
        let mut endpoint_slot_identities = 0_usize;
        for identity in endpoint.client.qcsd_pending_receive_action_identities() {
            if identity.endpoint() != endpoint.id {
                return Err(Error::SlotInvariant(format!(
                    "adapter {} reported cross-endpoint BuFLO receive identity {identity:?}",
                    endpoint.id.0
                )));
            }
            let Some(slot) = identity.slot() else {
                continue;
            };
            endpoint_slot_identities = endpoint_slot_identities.saturating_add(1);
            // Local realization is irreversible even when unused advertised
            // parser ownership is later returned and restaged on another
            // stream. Such replacement credit belongs ordinary terminal or
            // control drain; it must neither borrow a later exact window nor
            // invalidate the already successful half-open handoff.
            if controller.incoming_slot_is_locally_realized(slot) {
                continue;
            }
            if let Some(allowed) = allowed_slots
                && !allowed.contains_key(&slot)
            {
                let detail = pending_slots.get(&slot).map_or_else(
                    || "without a live controller packet".into(),
                    |packet| {
                        if packet.timestamp() == guard.packet.timestamp() {
                            "at the captured tick".into()
                        } else {
                            format!("at mismatched tick {:?}", packet.timestamp())
                        }
                    },
                );
                return Err(Error::SlotInvariant(format!(
                    "BuFLO exact incoming retry discovered new logical slot {} {detail}",
                    slot.0
                )));
            }
            let packet = match (pending_slots.get(&slot).copied(), allowed_slots) {
                (Some(packet), Some(allowed)) => {
                    let expected = allowed[&slot];
                    if packet != expected {
                        return Err(Error::SlotInvariant(format!(
                            "BuFLO incoming slot {} changed packet identity during exact retry",
                            slot.0
                        )));
                    }
                    packet
                }
                (Some(packet), None) => packet,
                (None, Some(allowed)) if controller.terminal_slot_resolution_at(slot).is_some() => {
                    allowed[&slot]
                }
                (None, _) => {
                    return Err(Error::SlotInvariant(format!(
                        "BuFLO adapter retained receive identity for non-live slot {}",
                        slot.0
                    )));
                }
            };
            if packet.direction() != Direction::Incoming {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO receive identity for slot {} was bound to an outgoing packet",
                    slot.0
                )));
            }
            if packet.timestamp() != guard.packet.timestamp() {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO incoming slot {} at {:?} attempted to borrow outgoing slot {} window at {:?}",
                    slot.0,
                    packet.timestamp(),
                    guard.slot.0,
                    guard.packet.timestamp()
                )));
            }
            let nominal_release =
                defense_start
                    .checked_add(packet.timestamp())
                    .ok_or_else(|| {
                        Error::DefenseExecution(format!(
                            "BuFLO incoming slot {} release overflow",
                            slot.0
                        ))
                    })?;
            let release_skew = guard
                .release
                .checked_duration_since(nominal_release)
                .ok_or_else(|| {
                    Error::SlotInvariant(format!(
                        "BuFLO incoming slot {} nominal release followed its paired adapter release",
                        slot.0
                    ))
                })?;
            if release_skew >= Duration::from_micros(1) {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO incoming slot {} adapter release skew {release_skew:?} exceeded sub-microsecond normalization",
                    slot.0
                )));
            }
            let nominal_deadline = nominal_release
                .checked_add(controller.config().control_interval())
                .ok_or_else(|| {
                    Error::DefenseExecution(format!(
                        "BuFLO incoming slot {} deadline overflow",
                        slot.0
                    ))
                })?;
            let deadline_skew = nominal_deadline
                .checked_duration_since(guard.deadline)
                .ok_or_else(|| {
                    Error::SlotInvariant(format!(
                        "BuFLO incoming slot {} adapter deadline exceeded its nominal strict window",
                        slot.0
                    ))
                })?;
            if deadline_skew >= Duration::from_micros(1) || guard.release >= guard.deadline {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO incoming slot {} adapter deadline skew {deadline_skew:?} fell outside its paired sub-microsecond strict window",
                    slot.0,
                )));
            }
            let candidate = BufloExactIncomingIdentity {
                endpoint_index,
                endpoint: endpoint.id,
                slot,
                packet,
                identity,
            };
            if captured.contains(&candidate) {
                return Err(Error::SlotInvariant(format!(
                    "BuFLO adapter reported duplicate scheduled receive identity {identity:?}"
                )));
            }
            captured.push(candidate);
        }
        if endpoint
            .client
            .qcsd_has_unadvertised_scheduled_receive_credit()
            && endpoint_slot_identities == 0
        {
            return Err(Error::SlotInvariant(format!(
                "BuFLO endpoint {} reported unadvertised scheduled credit without a slot-owned identity",
                endpoint.id.0
            )));
        }
    }
    captured.sort_unstable_by_key(buflo_exact_incoming_identity_key);
    Ok(captured)
}

fn refresh_buflo_exact_incoming_identities(
    guard: &BufloExactReleaseGuard,
    endpoints: &[Endpoint],
    controller: &QcsdController,
    defense_start: Instant,
    captured: &mut Vec<BufloExactIncomingIdentity>,
) -> Result<bool, Error> {
    let allowed_slots = buflo_exact_incoming_slot_packets(captured)?;
    let current = buflo_exact_incoming_identities(
        guard,
        endpoints,
        controller,
        defense_start,
        Some(&allowed_slots),
    )?;
    let mut grew = false;
    for candidate in current {
        if captured.contains(&candidate) {
            continue;
        }
        if controller
            .terminal_slot_resolution_at(candidate.slot)
            .is_some()
        {
            return Err(Error::SlotInvariant(format!(
                "BuFLO terminal incoming slot {} staged a new adapter identity",
                candidate.slot.0
            )));
        }
        captured.push(candidate);
        grew = true;
    }
    captured.sort_unstable_by_key(buflo_exact_incoming_identity_key);
    Ok(grew)
}

fn buflo_exact_incoming_identity_is_pending(
    endpoints: &[Endpoint],
    candidate: &BufloExactIncomingIdentity,
) -> bool {
    endpoints
        .get(candidate.endpoint_index)
        .is_some_and(|endpoint| {
            endpoint.id == candidate.endpoint
                && endpoint
                    .client
                    .qcsd_pending_receive_action_identities()
                    .contains(&candidate.identity)
        })
}

fn buflo_exact_incoming_inventory_is_complete(
    controller: &QcsdController,
    captured: &[BufloExactIncomingIdentity],
) -> Result<bool, Error> {
    let slots = buflo_exact_incoming_slot_packets(captured)?;
    let mut complete = true;
    for slot in slots.keys().copied() {
        if controller.incoming_slot_is_locally_realized(slot) {
            continue;
        }
        complete = false;
    }
    Ok(complete)
}

#[expect(
    clippy::too_many_arguments,
    reason = "expiry must reconcile the exact slot, transport, controller, trace, and clock ownership boundary"
)]
fn expire_buflo_exact_incoming_credit(
    guard: &BufloExactReleaseGuard,
    captured: &mut Vec<BufloExactIncomingIdentity>,
    force_expired_slots: &BTreeSet<QcsdSlotId>,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Instant,
    expired_at: Instant,
) -> Result<Error, Error> {
    let elapsed = expired_at.saturating_duration_since(defense_start);
    // The adapter deadline is the authoritative half-open realization
    // boundary. It may precede the controller's nominal whole-microsecond
    // deadline by less than one microsecond, and a host stall may cross later
    // cadence ticks. Terminalize only these retained roots here: a broad
    // controller poll could otherwise materialize catch-up work before the
    // run aborts.
    refresh_buflo_exact_incoming_identities(guard, endpoints, controller, defense_start, captured)?;
    let slot_packets = buflo_exact_incoming_slot_packets(captured)?;
    let mut expired_slots = BTreeSet::new();
    let mut prior_terminal_times = BTreeMap::new();
    for (slot, packet) in slot_packets {
        let children: Vec<_> = captured
            .iter()
            .filter(|candidate| candidate.slot == slot)
            .collect();
        let pending_carrier = children
            .iter()
            .copied()
            .find(|candidate| buflo_exact_incoming_identity_is_pending(endpoints, candidate));
        if controller.incoming_slot_is_locally_realized(slot)
            && !force_expired_slots.contains(&slot)
        {
            continue;
        }
        expired_slots.insert(slot);
        let prior_terminal = controller.terminal_slot_resolution_at(slot);
        prior_terminal_times.insert(slot, prior_terminal);
        if prior_terminal.is_some() {
            continue;
        }
        // The ordinary case uses a still-pending physical child. A captured
        // fallback is required only when packet construction cleared the
        // adapter identity before a pre-handoff deadline or socket error; the
        // logical slot is still unrealized and must receive typed expiry.
        let carrier = pending_carrier
            .or_else(|| children.first().copied())
            .ok_or_else(|| {
                Error::SlotInvariant(format!(
                    "BuFLO incoming slot {} had no captured expiry carrier",
                    slot.0
                ))
            })?;
        let record = observation_clock.record_at(
            QcsdObservation::SlotMissed {
                endpoint: carrier.endpoint,
                slot,
                packet,
                reason: MissedSlotReason::DeadlineExpired,
            },
            expired_at,
        );
        controller.observe(record.observation().clone(), elapsed);
        record_qcsd_observation(
            &mut endpoints[carrier.endpoint_index],
            controller,
            traces,
            &record,
            Some(duration_as_trace_micros(elapsed)),
            None,
        )?;
        require_controller_terminal_resolution(controller, slot, elapsed)?;
    }
    if expired_slots.is_empty() {
        return Err(Error::SlotInvariant(
            "BuFLO exact incoming expiry ran after every captured logical slot was locally realized"
                .into(),
        ));
    }
    controller.flush_defense_observations();
    apply_queued_actions(
        endpoints,
        controller,
        chaff_manifest,
        traces,
        expired_at,
        elapsed,
    )?;
    for slot in &expired_slots {
        match prior_terminal_times.get(slot).copied().flatten() {
            Some(prior) => {
                if controller.terminal_slot_resolution_at(*slot) != Some(prior) {
                    return Err(Error::SlotInvariant(format!(
                        "BuFLO incoming slot {} changed its prior terminal resolution during exact expiry",
                        slot.0
                    )));
                }
            }
            None => {
                require_controller_terminal_resolution(controller, *slot, elapsed)?;
            }
        }
    }
    // Accepted-but-unencoded transport identities deliberately remain as
    // terminal tombstones. The propagated abort closes the endpoints without
    // another output turn, while the tombstones prevent a late advertisement
    // from being reclassified as satisfaction.
    Ok(Error::DefenseExecution(format!(
        "BuFLO incoming slots {expired_slots:?} paired with outgoing slot {} remained unadvertised at their exact realization deadline",
        guard.slot.0
    )))
}

#[expect(
    clippy::too_many_arguments,
    reason = "deadline error reconciliation owns the original failure plus exact slot, adapter, trace, and metric state"
)]
fn reconcile_buflo_exact_incoming_output_error(
    source: Error,
    guard: &BufloExactReleaseGuard,
    owner: QcsdEndpointId,
    causally_cleared_slots: &BTreeSet<QcsdSlotId>,
    captured: &mut Vec<BufloExactIncomingIdentity>,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Instant,
    runner_wakeup_metrics: &mut RunnerWakeupMetrics,
    observed_at: Instant,
) -> Error {
    if observed_at < guard.deadline {
        return source;
    }
    runner_wakeup_metrics.record_buflo_exact_incoming_terminal_wake(guard.deadline, observed_at);
    // A successful socket handoff at the adapter's exclusive boundary is
    // retained as physical evidence before its typed hard failure reaches
    // here. The controller's nominal whole-microsecond deadline can be up to
    // 999 ns later, so it may have marked the credit locally realised. The
    // adapter boundary is authoritative: force only children driven by this
    // owner when typed provenance names this guard. Do not infer provenance
    // from strings, and do not relabel an in-window handoff whose later
    // reducer work happened to fail after the deadline.
    // Keep wake/processing latency on `observed_at`, but bind terminal slot
    // evidence to the low-level instant carried by a matching typed adapter
    // failure. CSV serialization and observation reduction may happen after
    // that physical boundary and must not move it.
    if let Some(slot) = causally_cleared_slots.iter().find(|slot| {
        !captured
            .iter()
            .any(|candidate| candidate.endpoint == owner && candidate.slot == **slot)
    }) {
        return Error::SlotInvariant(format!(
            "BuFLO exact incoming output attributed cleared slot {} to unrelated endpoint {}",
            slot.0, owner.0
        ));
    }
    let causal_force_slots = || (*causally_cleared_slots).clone();
    let (force_expired_slots, expiry_at): (BTreeSet<_>, _) = match &source {
        Error::AdapterDeadlinePreHandoff {
            attempted_at,
            deadline,
        } if *deadline == guard.deadline && *attempted_at >= guard.deadline => {
            (causal_force_slots(), *attempted_at)
        }
        Error::AdapterDeadlineLateHandoff { sent_at, deadline }
            if *deadline == guard.deadline && *sent_at >= guard.deadline =>
        {
            (causal_force_slots(), *sent_at)
        }
        _ => (BTreeSet::new(), observed_at),
    };
    let needs_expiry = !force_expired_slots.is_empty()
        || captured
            .iter()
            .any(|candidate| !controller.incoming_slot_is_locally_realized(candidate.slot));
    if !needs_expiry {
        return source;
    }
    let original = source.to_string();
    match expire_buflo_exact_incoming_credit(
        guard,
        captured,
        &force_expired_slots,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        expiry_at,
    ) {
        Ok(_) => source,
        Err(expiry) => Error::SlotInvariant(format!(
            "BuFLO exact incoming output failed with {original}; typed deadline reconciliation also failed: {expiry}"
        )),
    }
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the current-thread runner owns the identity-bound post-handoff receive-credit window"
)]
async fn drive_buflo_unadvertised_scheduled_receive_credit(
    guard: &BufloExactReleaseGuard,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Instant,
    runner_wakeup_metrics: &mut RunnerWakeupMetrics,
) -> Result<(), Error> {
    // The outgoing datagram's adapter observations were forwarded before its
    // post-output rolling barrier was deferred. Flush just that controller
    // evidence now: a partial, missed, or otherwise invalid outgoing cell must
    // fail before its paired receiver-credit datagram can reach the socket.
    // The global observation/action reduction remains deferred until after
    // the direct incoming owner turn below.
    controller.flush_defense_observations();
    if let Err(source) = ensure_defense_realizable(controller) {
        return match reduce_buflo_exact_pair_barrier(
            guard,
            endpoints,
            controller,
            chaff_manifest,
            traces,
            defense_start,
        ) {
            Ok(()) => Err(source),
            Err(reduction) => Err(Error::SlotInvariant(format!(
                "BuFLO outgoing slot {} failed before paired incoming output ({source}); its deferred post-output barrier also failed ({reduction})",
                guard.slot.0
            ))),
        };
    }
    let mut captured =
        buflo_exact_incoming_identities(guard, endpoints, controller, defense_start, None)?;
    if captured.is_empty() {
        reduce_buflo_exact_pair_output(
            guard,
            endpoints,
            controller,
            chaff_manifest,
            traces,
            defense_start,
            &mut captured,
        )?;
        if captured.is_empty() {
            return Ok(());
        }
    }
    let phases = exact_incoming_retry_times(guard.release, guard.deadline).ok_or_else(|| {
        Error::SlotInvariant(format!(
            "BuFLO outgoing slot {} had no strict interior incoming retry instants",
            guard.slot.0
        ))
    })?;

    let mut retry_wake_at = None;
    loop {
        refresh_buflo_exact_incoming_identities(
            guard,
            endpoints,
            controller,
            defense_start,
            &mut captured,
        )?;
        // Physical realization is stamped at the successful socket handoff.
        // It wins even when reducer work finishes after the wall-clock
        // deadline, so completion is checked before expiry at every boundary.
        if buflo_exact_incoming_inventory_is_complete(controller, &captured)? {
            return Ok(());
        }
        let cycle_started_at = now();
        if cycle_started_at >= guard.deadline {
            runner_wakeup_metrics
                .record_buflo_exact_incoming_terminal_wake(guard.deadline, cycle_started_at);
            return Err(expire_buflo_exact_incoming_credit(
                guard,
                &mut captured,
                &BTreeSet::new(),
                endpoints,
                controller,
                chaff_manifest,
                traces,
                observation_clock,
                defense_start,
                cycle_started_at,
            )?);
        }

        let mut retained_callback = None;
        let mut new_identity_staged = false;
        let owners: BTreeSet<_> = captured
            .iter()
            .filter(|candidate| buflo_exact_incoming_identity_is_pending(endpoints, candidate))
            .map(|candidate| (candidate.endpoint_index, candidate.endpoint))
            .collect();
        for (endpoint_index, endpoint) in owners {
            let attempted_at = now();
            if attempted_at >= guard.deadline {
                break;
            }
            let pending_before: Vec<_> = captured
                .iter()
                .copied()
                .filter(|candidate| {
                    candidate.endpoint == endpoint
                        && buflo_exact_incoming_identity_is_pending(endpoints, candidate)
                })
                .collect();
            if pending_before.is_empty() {
                continue;
            }
            let planned_wake_at = retry_wake_at.unwrap_or(attempted_at);
            let drive_result = drive_buflo_exact_incoming_output(
                endpoint_index,
                endpoint,
                endpoints,
                controller,
                traces,
                observation_clock,
                defense_start,
                guard.deadline,
            )
            .await;
            let drive_completed_at = now();
            let callback = match drive_result {
                Ok(callback) => callback,
                Err(source) => {
                    let cleared_slots: BTreeSet<_> = pending_before
                        .iter()
                        .filter(|candidate| {
                            !buflo_exact_incoming_identity_is_pending(endpoints, candidate)
                        })
                        .map(|candidate| candidate.slot)
                        .collect();
                    runner_wakeup_metrics.record_buflo_exact_incoming_retry_drive(
                        planned_wake_at,
                        attempted_at,
                        !cleared_slots.is_empty(),
                    );
                    return Err(reconcile_buflo_exact_incoming_output_error(
                        source,
                        guard,
                        endpoint,
                        &cleared_slots,
                        &mut captured,
                        endpoints,
                        controller,
                        chaff_manifest,
                        traces,
                        observation_clock,
                        defense_start,
                        runner_wakeup_metrics,
                        drive_completed_at,
                    ));
                }
            };
            retained_callback = retained_callback.into_iter().chain(callback).min();

            let reduction = reduce_buflo_exact_pair_output(
                guard,
                endpoints,
                controller,
                chaff_manifest,
                traces,
                defense_start,
                &mut captured,
            );
            let cleared_slots: BTreeSet<_> = pending_before
                .iter()
                .filter(|candidate| !buflo_exact_incoming_identity_is_pending(endpoints, candidate))
                .map(|candidate| candidate.slot)
                .collect();
            runner_wakeup_metrics.record_buflo_exact_incoming_retry_drive(
                planned_wake_at,
                attempted_at,
                !cleared_slots.is_empty(),
            );
            match reduction {
                Ok(grew) => new_identity_staged |= grew,
                Err(source) => {
                    return Err(reconcile_buflo_exact_incoming_output_error(
                        source,
                        guard,
                        endpoint,
                        &cleared_slots,
                        &mut captured,
                        endpoints,
                        controller,
                        chaff_manifest,
                        traces,
                        observation_clock,
                        defense_start,
                        runner_wakeup_metrics,
                        now(),
                    ));
                }
            }
        }

        if buflo_exact_incoming_inventory_is_complete(controller, &captured)? {
            return Ok(());
        }
        let checked_at = now();
        if checked_at >= guard.deadline {
            runner_wakeup_metrics
                .record_buflo_exact_incoming_terminal_wake(guard.deadline, checked_at);
            return Err(expire_buflo_exact_incoming_credit(
                guard,
                &mut captured,
                &BTreeSet::new(),
                endpoints,
                controller,
                chaff_manifest,
                traces,
                observation_clock,
                defense_start,
                checked_at,
            )?);
        }
        if new_identity_staged {
            // A reducer may continue the same logical slot onto another
            // stream or endpoint. Drive that child immediately while the
            // captured window is still live; this is continuation, not
            // catch-up of a later logical slot.
            retry_wake_at = None;
            continue;
        }

        let fallback = phases
            .into_iter()
            .find(|phase| *phase > checked_at)
            .unwrap_or(guard.deadline);
        let wake_at = retained_callback
            .into_iter()
            .chain([fallback, guard.deadline])
            .min()
            .unwrap_or(guard.deadline);
        let wake = wait_for_activity_until(std::iter::empty::<&Socket>(), wake_at).await?;
        runner_wakeup_metrics.record(wake, false);
        retry_wake_at = Some(wake_at);
    }
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn dispatch_buflo_exact_release(
    guard: &BufloExactReleaseGuard,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    runner_wakeup_metrics: &mut RunnerWakeupMetrics,
) -> Result<(), Error> {
    let started = defense_start.ok_or_else(|| {
        Error::SlotInvariant("BuFLO release guard ran before the defense clock started".into())
    })?;
    let dispatch_at = now();
    if dispatch_at < guard.release {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact-release slot {} reached dispatch before its adapter release",
            guard.slot.0
        )));
    }
    if !buflo_guard_identity_matches_runner(guard, endpoints, guard.phase) {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact-release slot {} changed runner identity while reserved",
            guard.slot.0
        )));
    }
    let controller_identity_matches = match guard.phase {
        BufloExactReleasePhase::Prearmed => {
            controller.rolling_outgoing_prearm_identity()
                == Some((guard.endpoint, guard.packet, guard.slot))
        }
        BufloExactReleasePhase::Committed => controller
            .pending_slots()
            .iter()
            .any(|(slot, packet)| *slot == guard.slot && *packet == guard.packet),
    };
    if !controller_identity_matches {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact-release slot {} changed controller identity while reserved",
            guard.slot.0
        )));
    }
    let dispatch_elapsed = dispatch_at.saturating_duration_since(started);
    if dispatch_at >= guard.deadline {
        // Reconcile once so the defense and trace receive the typed late
        // outcome, but never build or send a catch-up packet.
        if guard.phase == BufloExactReleasePhase::Prearmed {
            controller.reconcile_due_rolling(dispatch_elapsed)?;
            controller.flush_defense_observations();
            apply_queued_actions(
                endpoints,
                controller,
                chaff_manifest,
                traces,
                dispatch_at,
                dispatch_elapsed,
            )?;
        } else {
            let record = observation_clock.record_at(
                QcsdObservation::SlotMissed {
                    endpoint: guard.endpoint,
                    slot: guard.slot,
                    packet: guard.packet,
                    reason: MissedSlotReason::DeadlineExpired,
                },
                dispatch_at,
            );
            controller.observe(record.observation().clone(), dispatch_elapsed);
            record_qcsd_observation(
                &mut endpoints[guard.endpoint_index],
                controller,
                traces,
                &record,
                Some(duration_as_trace_micros(dispatch_elapsed)),
                None,
            )?;
            require_controller_terminal_resolution(controller, guard.slot, dispatch_elapsed)?;
            controller.flush_defense_observations();
        }
        ensure_defense_realizable(controller)?;
        return Err(Error::DefenseExecution(format!(
            "BuFLO exact-release slot {} expired before transport dispatch",
            guard.slot.0
        )));
    }

    // Use the established globally ordered reducer so the outgoing commit is
    // still emitted before its paired incoming opportunity and any resulting
    // receive-limit control can be composed into this exact cell. Retaining
    // the owning endpoint here avoids an identity-free endpoint-zero drive.
    // Stop after that one physical datagram and retain the adapter's exact
    // half-open deadline: any residual receive credit belongs to the
    // identity-bound continuation below and must not escape in an unbounded
    // ordinary output loop against the rounded controller deadline.
    _ = drive_buflo_exact_release_output(
        guard.endpoint_index,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        guard.deadline,
    )
    .await?;
    if buflo_guard_identity_matches_runner(guard, endpoints, BufloExactReleasePhase::Prearmed)
        || buflo_guard_identity_matches_runner(guard, endpoints, BufloExactReleasePhase::Committed)
    {
        return Err(Error::DefenseExecution(format!(
            "BuFLO exact-release slot {} did not reach a terminal socket handoff",
            guard.slot.0
        )));
    }
    if controller
        .pending_slots()
        .iter()
        .any(|(slot, packet)| *slot == guard.slot && *packet == guard.packet)
    {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact-release slot {} remained pending after socket handoff",
            guard.slot.0
        )));
    }
    drive_buflo_unadvertised_scheduled_receive_credit(
        guard,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        started,
        runner_wakeup_metrics,
    )
    .await?;
    Ok(())
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    reason = "the current-thread runner owns every mutable exact-release boundary"
)]
async fn dispatch_due_buflo_exact_release(
    defense: &DefenseConfig,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    run_deadline: Instant,
    timeout_seconds: u64,
    runner_wakeup_metrics: &mut RunnerWakeupMetrics,
) -> Result<bool, Error> {
    let current = now();
    let Some(guard) = next_buflo_exact_release_guard(defense, controller, endpoints)? else {
        return Ok(false);
    };
    if current < guard.guard_at {
        return Ok(false);
    }

    // Tokio's current-thread timer and ordinary socket/HTTP work can otherwise
    // consume the complete half-open realization window before a due BuFLO
    // target reaches transport. Reserve the candidate at the existing
    // two-window ordinary-output admission boundary and remain runnable until
    // the exact release. The physical realization interval remains the same
    // half-open five-millisecond adapter window after release.
    // Callers invoke this boundary between every bounded unit of ordinary work
    // as well as at the loop head.
    debug_assert!(guard.release < guard.deadline);
    let exact_release_evidence = wait_for_buflo_exact_release(&guard);
    let dispatch_at = exact_release_evidence.dispatch_at;
    runner_wakeup_metrics.record_buflo_exact_release_guard(
        &guard,
        defense_start,
        &exact_release_evidence,
    );
    if dispatch_at >= run_deadline {
        return Err(deadline_error(
            defense,
            controller.is_complete(),
            timeout_seconds,
        ));
    }
    dispatch_buflo_exact_release(
        &guard,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        runner_wakeup_metrics,
    )
    .await?;
    Ok(true)
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
enum OutputDriveCardinality {
    /// Drain transport output until it returns a callback or no work.
    DrainAvailable,
    /// Stop after one datagram microstep so an exact incoming retry cannot
    /// burst unrelated or catch-up output before its identity is rechecked.
    OneDatagram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostOutputRollingBarrier {
    Apply,
    /// The selected `BuFLO` outgoing cell and its already-staged incoming
    /// opportunity share one strict adapter window. Defer only the outgoing
    /// datagram's global post-output reduction until the captured incoming
    /// owner has received its one direct output turn.
    DeferBufloExactPair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketHandoff {
    Sent(Instant),
    SentLate {
        sent_at: Instant,
        deadline: Instant,
        boundary: SocketHandoffBoundary,
    },
    RetryUnshaped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketHandoffBoundary {
    AdapterDeadline,
    RollingDefenseDeadline,
}

fn late_socket_handoff_error(
    sent_at: Instant,
    deadline: Instant,
    boundary: SocketHandoffBoundary,
) -> Error {
    match boundary {
        SocketHandoffBoundary::AdapterDeadline => {
            Error::AdapterDeadlineLateHandoff { sent_at, deadline }
        }
        SocketHandoffBoundary::RollingDefenseDeadline => Error::SlotInvariant(format!(
            "unshaped UDP datagram reached the socket at or after a rolling defense deadline ({sent_at:?} >= {deadline:?})"
        )),
    }
}

#[cfg(test)]
fn attempt_socket_handoff(
    target_deadlines: &[Instant],
    unshaped_handoff_interrupt: Option<Instant>,
    send: impl FnOnce() -> io::Result<()>,
    clock: impl FnMut() -> Instant,
) -> Result<SocketHandoff, Error> {
    attempt_socket_handoff_timestamped(
        target_deadlines,
        unshaped_handoff_interrupt,
        || send().map(|()| None),
        clock,
    )
}

fn attempt_socket_handoff_timestamped(
    target_deadlines: &[Instant],
    unshaped_handoff_interrupt: Option<Instant>,
    send: impl FnOnce() -> io::Result<Option<Instant>>,
    mut clock: impl FnMut() -> Instant,
) -> Result<SocketHandoff, Error> {
    // No batch may enter the socket syscall after its active half-open fidelity
    // window. Check before every attempt and validate the immediate low-level
    // timestamp after a successful handoff. Candidate production sends sample
    // that timestamp directly beside the socket call so caller-side scheduler
    // delay cannot create a false late receipt.
    if let Some(deadline) = target_deadlines.iter().copied().min() {
        let attempted_at = clock();
        if attempted_at >= deadline {
            return Err(Error::AdapterDeadlinePreHandoff {
                attempted_at,
                deadline,
            });
        }
    }
    let unshaped_interrupt = target_deadlines
        .is_empty()
        .then_some(unshaped_handoff_interrupt)
        .flatten();
    if let Some(interrupt) = unshaped_interrupt {
        let attempted_at = clock();
        if attempted_at >= interrupt {
            return Err(Error::SlotInvariant(format!(
                "unshaped UDP datagram retry reached or crossed a rolling defense deadline before socket handoff ({attempted_at:?} >= {interrupt:?})"
            )));
        }
    }
    match send() {
        Ok(low_level_handoff_at) => {
            // Candidate sends return an immediate timestamp from the
            // low-level successful socket call. Falling back to the outer
            // clock retains historical/test behavior, but a scheduler pause
            // while unwinding from sendmsg must never relabel an already
            // accepted candidate datagram as late.
            let sent_at = low_level_handoff_at.unwrap_or_else(&mut clock);
            if let Some(deadline) = target_deadlines
                .iter()
                .copied()
                .filter(|deadline| sent_at >= *deadline)
                .min()
            {
                return Ok(SocketHandoff::SentLate {
                    sent_at,
                    deadline,
                    boundary: SocketHandoffBoundary::AdapterDeadline,
                });
            }
            if let Some(interrupt) = unshaped_interrupt
                && sent_at >= interrupt
            {
                return Ok(SocketHandoff::SentLate {
                    sent_at,
                    deadline: interrupt,
                    boundary: SocketHandoffBoundary::RollingDefenseDeadline,
                });
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

async fn await_unshaped_socket_retry<F>(
    writable: F,
    unshaped_handoff_interrupt: Option<Instant>,
) -> Result<(), Error>
where
    F: Future<Output = io::Result<()>>,
{
    let Some(interrupt) = unshaped_handoff_interrupt else {
        writable.await?;
        return Ok(());
    };
    if now() >= interrupt {
        return Err(Error::SlotInvariant(
            "unshaped socket backpressure crossed a rolling defense deadline after transport output was built"
                .into(),
        ));
    }
    let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(interrupt));
    tokio::pin!(timer);
    tokio::pin!(writable);
    tokio::select! {
        biased;
        () = &mut timer => Err(Error::SlotInvariant(
            "unshaped socket backpressure crossed a rolling defense deadline after transport output was built"
                .into(),
        )),
        result = &mut writable => {
            result?;
            Ok(())
        }
    }
}

fn reduce_post_output_rolling_barrier(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_now: Instant,
    observation_elapsed: Duration,
    due_slots_before_output: &BTreeSet<QcsdSlotId>,
) -> Result<bool, Error> {
    handle_all_qcsd_observations(endpoints, controller, traces, observation_elapsed)?;
    controller.flush_defense_observations();
    ensure_defense_realizable(controller)?;
    if controller.has_rolling_outgoing_prearm() || controller.has_due_rolling_reconciliation() {
        // Endpoint loss at the exact release can stage a replacement preview
        // during the observation batch. Reconcile it against this same
        // timestamp before dispatch; advancing to another runner microstep
        // would manufacture a TimerLate failure.
        controller.reconcile_due_rolling(observation_elapsed)?;
        controller.flush_defense_observations();
        ensure_defense_realizable(controller)?;
    }
    apply_queued_actions(
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_now,
        observation_elapsed,
    )?;
    Ok(endpoints
        .iter()
        .flat_map(|endpoint| endpoint.scheduled_outgoing.iter())
        .filter(|scheduled| {
            scheduled.rolling_prearmed && scheduled.packet.timestamp() <= observation_elapsed
        })
        .any(|scheduled| !due_slots_before_output.contains(&scheduled.slot)))
}

fn reduce_buflo_exact_pair_output(
    guard: &BufloExactReleaseGuard,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    defense_start: Instant,
    captured: &mut Vec<BufloExactIncomingIdentity>,
) -> Result<bool, Error> {
    reduce_buflo_exact_pair_barrier(
        guard,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        defense_start,
    )?;
    refresh_buflo_exact_incoming_identities(guard, endpoints, controller, defense_start, captured)
}

fn reduce_buflo_exact_pair_barrier(
    guard: &BufloExactReleaseGuard,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    defense_start: Instant,
) -> Result<(), Error> {
    let reduced_at = now();
    let reduced_elapsed = reduced_at.saturating_duration_since(defense_start);
    let due_slots_before_output = BTreeSet::from([guard.slot]);
    if reduce_post_output_rolling_barrier(
        endpoints,
        controller,
        chaff_manifest,
        traces,
        reduced_at,
        reduced_elapsed,
        &due_slots_before_output,
    )? {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact pair for outgoing slot {} exposed a new same-tick rolling target during its deferred post-output barrier",
            guard.slot.0
        )));
    }
    ensure_defense_realizable(controller)
}

fn resolve_rolling_output_interrupt(
    defense_start: Option<Instant>,
    relative_deadlines: impl IntoIterator<Item = Duration>,
    absolute_adapter_deadlines: impl IntoIterator<Item = Instant>,
) -> Result<Option<Instant>, Error> {
    let relative_interrupt = relative_deadlines.into_iter().min();
    let relative_interrupt = match (defense_start, relative_interrupt) {
        (Some(started), Some(deadline)) => {
            Some(started.checked_add(deadline).ok_or_else(|| {
                Error::DefenseExecution("rolling output interrupt deadline overflow".into())
            })?)
        }
        _ => None,
    };
    Ok(relative_interrupt
        .into_iter()
        .chain(absolute_adapter_deadlines)
        .min())
}

fn rolling_output_interrupt(
    controller: &QcsdController,
    endpoints: &[Endpoint],
    defense_start: Option<Instant>,
) -> Result<Option<Instant>, Error> {
    if !rolling_output_lifecycle_active(controller, endpoints) {
        return Ok(None);
    }
    resolve_rolling_output_interrupt(
        defense_start,
        controller
            .next_deadline()
            .into_iter()
            .chain(endpoints.iter().flat_map(|endpoint| {
                endpoint
                    .prearmed_outgoing
                    .iter()
                    .map(|prearm| prearm.packet.timestamp())
                    .chain(
                        endpoint
                            .scheduled_outgoing
                            .iter()
                            .filter(|scheduled| scheduled.rolling_prearmed)
                            .map(|scheduled| scheduled.packet.timestamp()),
                    )
            })),
        endpoints.iter().flat_map(|endpoint| {
            endpoint
                .prearmed_outgoing
                .iter()
                .map(|prearm| prearm.deadline)
                .chain(
                    endpoint
                        .scheduled_outgoing
                        .iter()
                        .filter(|scheduled| scheduled.rolling_prearmed)
                        .map(|scheduled| scheduled.deadline),
                )
        }),
    )
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
#[cfg(test)]
async fn drive_endpoint_output(
    endpoint_index: usize,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
) -> Result<Option<Instant>, Error> {
    let mut monotonic_clock = now;
    drive_endpoint_output_with_clock_until(
        endpoint_index,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        None,
        None,
        None,
        false,
        OutputDriveCardinality::DrainAvailable,
        PostOutputRollingBarrier::Apply,
        &mut monotonic_clock,
    )
    .await
}

/// Emit the one datagram owned by an already-selected `BuFLO` exact-release
/// guard. The ordinary bounded wrapper discovers future guards, but this
/// microstep must deliberately bypass only the still-live guard that selected
/// it; rediscovering that same guard would self-interrupt before transport.
#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    reason = "the current-thread runner owns the selected exact-release identity and socket boundary"
)]
async fn drive_buflo_exact_release_output(
    endpoint_index: usize,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    deadline: Instant,
) -> Result<Option<Instant>, Error> {
    let mut monotonic_clock = now;
    drive_endpoint_output_with_clock_until(
        endpoint_index,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        Some(OutputWorkBoundary::new(deadline, deadline)),
        Some(deadline),
        Some(deadline),
        false,
        OutputDriveCardinality::OneDatagram,
        PostOutputRollingBarrier::DeferBufloExactPair,
        &mut monotonic_clock,
    )
    .await
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    reason = "the current-thread runner directly owns the captured incoming endpoint and unchanged exact deadline"
)]
async fn drive_buflo_exact_incoming_output(
    endpoint_index: usize,
    owner: QcsdEndpointId,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Instant,
    deadline: Instant,
) -> Result<Option<Instant>, Error> {
    let mut monotonic_clock = now;
    drive_buflo_exact_incoming_output_with_clock(
        endpoint_index,
        owner,
        endpoints,
        controller,
        traces,
        observation_clock,
        defense_start,
        deadline,
        &mut monotonic_clock,
    )
    .await
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    reason = "the deterministic clock seam preserves direct exact-pair socket causality"
)]
async fn drive_buflo_exact_incoming_output_with_clock(
    endpoint_index: usize,
    owner: QcsdEndpointId,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Instant,
    deadline: Instant,
    monotonic_clock: &mut impl FnMut() -> Instant,
) -> Result<Option<Instant>, Error> {
    if controller.has_due_rolling_reconciliation() {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact incoming owner {} reached its direct turn with due rolling reconciliation",
            owner.0
        )));
    }
    let endpoint = endpoints.get_mut(endpoint_index).ok_or_else(|| {
        Error::SlotInvariant(format!(
            "BuFLO exact incoming owner {} had missing endpoint index {endpoint_index}",
            owner.0
        ))
    })?;
    if endpoint.id != owner {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact incoming owner {} resolved to endpoint {} at index {endpoint_index}",
            owner.0, endpoint.id.0
        )));
    }
    if let Some(scheduled) = endpoint.scheduled_outgoing.front() {
        return Err(Error::SlotInvariant(format!(
            "BuFLO exact incoming owner {} retained committed outgoing slot {} before its direct receiver-credit turn",
            owner.0, scheduled.slot.0
        )));
    }
    let drive_now = monotonic_clock();
    if drive_now >= deadline {
        return Err(Error::AdapterDeadlinePreHandoff {
            attempted_at: drive_now,
            deadline,
        });
    }
    match process_output_once_with_clock(
        endpoint,
        controller,
        traces,
        observation_clock,
        drive_now,
        Some(defense_start),
        Some(deadline),
        Some(deadline),
        monotonic_clock,
    )
    .await?
    {
        OutputDrive::Callback(wakeup) => Ok(Some(wakeup)),
        OutputDrive::Datagram | OutputDrive::None => Ok(None),
    }
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_arguments,
    reason = "the current-thread output driver owns the exact-release interruption boundary"
)]
async fn drive_endpoint_output_until(
    endpoint_index: usize,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    work_boundary: Option<OutputWorkBoundary>,
    unshaped_handoff_interrupt: Option<Instant>,
    absolute_handoff_deadline: Option<Instant>,
    cardinality: OutputDriveCardinality,
) -> Result<Option<Instant>, Error> {
    let mut monotonic_clock = now;
    drive_endpoint_output_with_clock_until(
        endpoint_index,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        work_boundary,
        unshaped_handoff_interrupt,
        absolute_handoff_deadline,
        true,
        cardinality,
        PostOutputRollingBarrier::Apply,
        &mut monotonic_clock,
    )
    .await
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "the deterministic clock seam preserves the production output-drive boundary"
)]
async fn drive_endpoint_output_with_clock(
    endpoint_index: usize,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    monotonic_clock: &mut impl FnMut() -> Instant,
) -> Result<Option<Instant>, Error> {
    drive_endpoint_output_with_clock_until(
        endpoint_index,
        endpoints,
        controller,
        chaff_manifest,
        traces,
        observation_clock,
        defense_start,
        None,
        None,
        None,
        false,
        OutputDriveCardinality::DrainAvailable,
        PostOutputRollingBarrier::Apply,
        monotonic_clock,
    )
    .await
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the deterministic clock and interruption seams preserve output causality"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one output-drive loop preserves the exact reduce-prearm-process causality boundary"
)]
async fn drive_endpoint_output_with_clock_until(
    endpoint_index: usize,
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    chaff_manifest: Option<&RuntimeChaffManifest>,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    defense_start: Option<Instant>,
    work_boundary: Option<OutputWorkBoundary>,
    unshaped_handoff_interrupt: Option<Instant>,
    absolute_handoff_deadline: Option<Instant>,
    interrupt_new_buflo_guards: bool,
    cardinality: OutputDriveCardinality,
    post_output_rolling_barrier: PostOutputRollingBarrier,
    monotonic_clock: &mut impl FnMut() -> Instant,
) -> Result<Option<Instant>, Error> {
    let mut work_boundary = work_boundary;
    let mut unshaped_handoff_interrupt = unshaped_handoff_interrupt;
    loop {
        // One fresh timestamp governs the complete fixed-schedule microstep:
        // reconcile every event due at that instant, apply its incoming
        // actions, and only then let transport observe target eligibility.
        let mut drive_now = monotonic_clock();
        if let Some(wakeup) = work_boundary.and_then(|boundary| boundary.closed_wakeup(drive_now)) {
            return Ok(Some(wakeup));
        }
        let mut output_endpoint_index = endpoint_index;
        let mut due_rolling_slots_before_output = BTreeSet::new();
        if let Some(started) = defense_start {
            let mut reduced_rolling_barrier = false;
            if rolling_output_lifecycle_active(controller, endpoints) {
                // Input on an earlier origin can publish EndpointClosed or a
                // slot outcome immediately before this origin's output turn.
                // Reduce that production-ordered evidence before a rolling
                // preview can be committed at its release boundary.
                let observation_elapsed = drive_now.saturating_duration_since(started);
                handle_all_qcsd_observations(endpoints, controller, traces, observation_elapsed)?;
                controller.flush_defense_observations();
                ensure_defense_realizable(controller)?;
                reduced_rolling_barrier = true;
                drive_now = monotonic_clock();
            }
            let drive_elapsed = drive_now.saturating_duration_since(started);
            let reconcile_staging = controller.has_fixed_schedule_staging()
                || controller.has_rolling_outgoing_prearm()
                || controller.has_due_rolling_reconciliation();
            if reconcile_staging {
                controller.reconcile_due_rolling(drive_elapsed)?;
                controller.reconcile_due_fixed(drive_elapsed);
                controller.flush_defense_observations();
                ensure_defense_realizable(controller)?;
            }
            if reduced_rolling_barrier || reconcile_staging {
                apply_queued_actions(
                    endpoints,
                    controller,
                    chaff_manifest,
                    traces,
                    drive_now,
                    drive_elapsed,
                )?;
            }
            if interrupt_new_buflo_guards {
                let defense = controller.config().defense.clone();
                if let Some(guard) =
                    next_buflo_exact_release_guard(&defense, controller, endpoints)?
                {
                    work_boundary = Some(earliest_output_work_boundary(
                        work_boundary,
                        guard.output_work_boundary(),
                    ));
                    unshaped_handoff_interrupt = unshaped_handoff_interrupt
                        .into_iter()
                        .chain([guard.release])
                        .min();
                }
                if let Some(boundary) = work_boundary {
                    drive_now = monotonic_clock();
                    if let Some(wakeup) = boundary.closed_wakeup(drive_now) {
                        return Ok(Some(wakeup));
                    }
                }
            }
            let mut rolling_adapter_release = None;
            if rolling_output_lifecycle_active(controller, endpoints) {
                if let Some((priority, not_before)) = due_rolling_output_target(
                    endpoints.iter().enumerate().flat_map(|(index, endpoint)| {
                        endpoint
                            .scheduled_outgoing
                            .iter()
                            .map(move |scheduled| (index, scheduled))
                    }),
                    drive_elapsed,
                ) {
                    // A due committed target owns this microstep even when a
                    // different endpoint crossed the release boundary. This
                    // also prevents the newly staged next-tick preview from
                    // stealing priority from the event just committed above.
                    output_endpoint_index = priority;
                    rolling_adapter_release = Some(not_before);
                }
                due_rolling_slots_before_output = endpoints
                    .iter()
                    .flat_map(|endpoint| endpoint.scheduled_outgoing.iter())
                    .filter(|scheduled| {
                        scheduled.rolling_prearmed && scheduled.packet.timestamp() <= drive_elapsed
                    })
                    .map(|scheduled| scheduled.slot)
                    .collect();
            }
            if let Some(not_before) = rolling_adapter_release {
                // `PrearmPacket` represents the absolute release as a relative
                // whole-microsecond delay, rounded upward so transport can never
                // send early.  The nominal defense tick can therefore precede
                // the adapter release by 1--999 ns. Refresh the runner clock
                // after reconciliation/action dispatch and wait for the exact
                // adapter instant instead of allowing same-tick receiver-credit
                // control to escape as an unshaped datagram.
                drive_now = monotonic_clock();
                if drive_now < not_before {
                    return Ok(Some(not_before));
                }
            }
        }

        let rolling_lifecycle_before_output =
            rolling_output_lifecycle_active(controller, endpoints);
        // `work_boundary` is only the admission boundary for a fresh unit of
        // ordinary work. Once this output microstep has started strictly before
        // that guard, its targetless UDP handoff retains the actual rolling
        // controller/adapter release as its hard bound. Conflating the two
        // boundaries would reject a successful syscall merely for finishing in
        // the reserved pre-release tail even though no new work can start there.
        let rolling_handoff_interrupt = if rolling_lifecycle_before_output {
            rolling_output_interrupt(controller, endpoints, defense_start)?
        } else {
            None
        };
        let effective_unshaped_handoff_interrupt = rolling_handoff_interrupt
            .into_iter()
            .chain(unshaped_handoff_interrupt)
            .min();
        let output = process_output_once_with_clock(
            &mut endpoints[output_endpoint_index],
            controller,
            traces,
            observation_clock,
            drive_now,
            defense_start,
            effective_unshaped_handoff_interrupt,
            absolute_handoff_deadline,
            monotonic_clock,
        )
        .await?;
        let exact_due_slots_are_terminal = !due_rolling_slots_before_output.is_empty()
            && due_rolling_slots_before_output.iter().all(|slot| {
                controller.terminal_slot_resolution_at(*slot).is_some()
                    && endpoints.iter().all(|endpoint| {
                        endpoint
                            .scheduled_outgoing
                            .iter()
                            .all(|scheduled| scheduled.slot != *slot)
                    })
            });
        let defer_post_output_rolling_barrier = post_output_rolling_barrier
            == PostOutputRollingBarrier::DeferBufloExactPair
            && output == OutputDrive::Datagram
            && exact_due_slots_are_terminal;
        if !defer_post_output_rolling_barrier
            && let Some(started) = defense_start
            && (rolling_lifecycle_before_output
                || rolling_output_lifecycle_active(controller, endpoints))
        {
            // `process_multiple_output` can publish closure, expiry, or slot
            // observations even when it returns Callback/None. Reduce every
            // endpoint's production-ordered observations before another
            // origin is allowed to cross a rolling release boundary.
            let observation_now = monotonic_clock();
            let observation_elapsed = observation_now.saturating_duration_since(started);
            let has_new_due_rolling_target = reduce_post_output_rolling_barrier(
                endpoints,
                controller,
                chaff_manifest,
                traces,
                observation_now,
                observation_elapsed,
                &due_rolling_slots_before_output,
            )?;
            if has_new_due_rolling_target {
                // `output` predates the newly committed target and therefore
                // cannot supply its datagram or pacing callback. Re-enter the
                // drive loop immediately; the pre-output priority selector
                // will route the fresh slot to its owning endpoint.
                continue;
            }
        }
        match output {
            OutputDrive::Datagram if cardinality == OutputDriveCardinality::OneDatagram => {
                return Ok(None);
            }
            OutputDrive::Datagram => {}
            OutputDrive::Callback(wakeup) => return Ok(Some(wakeup)),
            OutputDrive::None => return Ok(None),
        }
    }
}

fn rolling_output_lifecycle_active(controller: &QcsdController, endpoints: &[Endpoint]) -> bool {
    if controller.has_fixed_schedule_staging() {
        return false;
    }
    controller.has_rolling_outgoing_prearm()
        || controller.has_due_rolling_reconciliation()
        || endpoints.iter().any(|endpoint| {
            !endpoint.prearmed_outgoing.is_empty()
                || endpoint
                    .scheduled_outgoing
                    .iter()
                    .any(|scheduled| scheduled.rolling_prearmed)
        })
}

fn due_rolling_output_target<'a>(
    scheduled: impl IntoIterator<Item = (usize, &'a ScheduledOutgoing)>,
    drive_elapsed: Duration,
) -> Option<(usize, Instant)> {
    scheduled
        .into_iter()
        .filter(|(_, scheduled)| {
            scheduled.rolling_prearmed && scheduled.packet.timestamp() <= drive_elapsed
        })
        .min_by_key(|(_, scheduled)| (scheduled.packet.timestamp(), scheduled.slot))
        .map(|(index, scheduled)| (index, scheduled.not_before))
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the deterministic handoff clock is an explicit output-causality seam"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one output microstep keeps packet-build, slot-resolution, and trace evidence atomic"
)]
async fn process_output_once_with_clock(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    observation_clock: &QcsdObservationClock,
    drive_now: Instant,
    defense_start: Option<Instant>,
    unshaped_handoff_interrupt: Option<Instant>,
    absolute_handoff_deadline: Option<Instant>,
    monotonic_clock: &mut impl FnMut() -> Instant,
) -> Result<OutputDrive, Error> {
    #[cfg(test)]
    if let Some(output) = endpoint.test_output_drives.pop_front() {
        match output {
            TestOutputDrive::ProductionPath => {}
            TestOutputDrive::Callback(delay) => {
                return absolute_wakeup(drive_now, delay)
                    .map(OutputDrive::Callback)
                    .ok_or_else(|| Error::RunAborted("test transport callback overflow".into()));
            }
            TestOutputDrive::CallbackAt(wakeup) => return Ok(OutputDrive::Callback(wakeup)),
            TestOutputDrive::ErrorAt(at) => {
                tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                return Err(Error::SlotInvariant(
                    "test output failed at the exact incoming deadline".into(),
                ));
            }
        }
    }
    #[cfg(test)]
    if let Some(observation) = endpoint.test_observation_on_next_output.take() {
        endpoint.test_output_observations.push(observation);
        return Ok(OutputDrive::None);
    }
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

    let mut target_deadlines: Vec<_> = attributed_datagrams
        .iter()
        .filter_map(|(_, satisfied, _)| satisfied.map(|target| target.deadline))
        .collect();
    target_deadlines.extend(absolute_handoff_deadline);
    let (sent_at, late_handoff) = loop {
        #[cfg(test)]
        let force_socket_handoff_success = endpoint.test_force_socket_handoff_success;
        #[cfg(test)]
        let strict_socket_handoff_error = endpoint.test_strict_socket_handoff_error.take();
        let socket_handoff_policy = endpoint.socket_handoff_policy;
        match attempt_socket_handoff_timestamped(
            &target_deadlines,
            unshaped_handoff_interrupt,
            || {
                #[cfg(test)]
                if force_socket_handoff_success {
                    return Ok(None);
                }
                #[cfg(test)]
                if socket_handoff_policy == SocketHandoffPolicy::CandidateFidelityStrict
                    && let Some(raw_os_error) = strict_socket_handoff_error
                {
                    return Err(io::Error::from_raw_os_error(raw_os_error));
                }
                socket_handoff_policy.send(&endpoint.socket, &batch)
            },
            &mut *monotonic_clock,
        )? {
            SocketHandoff::Sent(sent_at) => break (sent_at, None),
            SocketHandoff::SentLate {
                sent_at,
                deadline,
                boundary,
            } => break (sent_at, Some((deadline, boundary))),
            SocketHandoff::RetryUnshaped => {
                await_unshaped_socket_retry(endpoint.socket.writable(), unshaped_handoff_interrupt)
                    .await?;
            }
        }
    };
    let wire_elapsed = defense_start.map(|started| sent_at.saturating_duration_since(started));
    for observation in observations {
        let terminal = terminal_observation_slot(observation.observation());
        let terminal_us = match (terminal, wire_elapsed) {
            (Some(_), Some(at)) => Some(duration_as_trace_micros(at)),
            (Some(slot), None) => {
                return Err(Error::SlotInvariant(format!(
                    "slot {} reached a terminal adapter state before defense activation",
                    slot.0
                )));
            }
            (None, _) => None,
        };
        forward_qcsd_observation(controller, &observation, wire_elapsed);
        record_qcsd_observation(
            endpoint,
            controller,
            traces,
            &observation,
            terminal_us,
            Some(sent_at),
        )?;
        if let (Some(slot), Some(at)) = (terminal, wire_elapsed) {
            require_controller_terminal_resolution(controller, slot, at)?;
        }
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
    if let Some((deadline, boundary)) = late_handoff {
        // The UDP syscall already succeeded, so first preserve every packet,
        // schedule, event, and controller observation caused by the datagram.
        // Only then reject the run for the fidelity violation.
        return Err(late_socket_handoff_error(sent_at, deadline, boundary));
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
    drain_socket: bool,
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
        if !drain_socket {
            break;
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
            "schema_version": 4,
            "kind": "buflo",
            "implementation_scope": "client_only_quic",
            "paper_equivalent": false,
            "incoming_opportunity_semantics": "client_receive_credit_and_response_qualified_chaff_attempt",
            "terminal_schedule_stop_policy": "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_then_drain_already_advertised_incoming_credit",
            "terminal_subcell_policy": "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail",
            "terminal_subcell_observer_effect": "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell",
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
            "schema_version": 4,
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
            "early_termination_translation_version": diagnostics.cs_buflo_early_termination_translation_version,
            "termination_stop_policy": diagnostics.cs_buflo_termination_stop_policy,
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
        "error_class": completion.error_class,
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
        collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };

    use clap::Parser as _;
    use neqo_common::event::Provider as _;
    use neqo_csdef::{
        ChaffManifest, ChaffQualification, Defense, DefenseConfig, DefenseDiagnostics, DefenseMode,
        DefenseSignal, DependencyTracker, Direction, ExpectedChaffResponse, FrontConfig,
        IdentityChaffRequestHeaderPrimitive, MissedSlotReason, Packet, QcsdAction,
        QcsdChaffCancellationReason, QcsdChaffRequestId, QcsdConfig, QcsdCongestionReason,
        QcsdController, QcsdDatagramClass, QcsdEndpointId, QcsdObservation, QcsdObservationClock,
        QcsdParserLeaseOwner, QcsdReceiveActionIdentity, QcsdReceiveLimitError,
        QcsdReceiveLimitFatal, QcsdReceiveLimitOutcome, QcsdSendPolicy, QcsdSlotComposition,
        QcsdSlotId, QcsdSlotOutcome, QcsdStreamFinish, QcsdStreamId, QcsdStreamTransmission,
        QualifiedChaffResource, Resource, ResourceManifest, ResponseOnlyChaffManifest,
        ResponseOnlyChaffManifestV4, ResponseOnlyChaffQualification,
        ResponseOnlyChaffQualificationV4, ResponseOnlyQualifiedChaffResource,
        ResponseOnlyQualifiedChaffResourceV4, SignalKind, StaticSchedule, TamarawConfig, Trace,
        TrafficMorphingConfig, WalkieTalkieConfig, WalkieTalkieQualificationBinding, WtfPad,
        WtfPadConfig, sanitize_chaff_headers,
    };
    use neqo_udp::RecvBuf;
    use serde_json::json;

    use super::{
        ActivityWake, ApplicationBatchLifecycle, Args, BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        BufloExactReleaseAuxClockSample, BufloExactReleaseCandidate, BufloExactReleaseGuard,
        BufloExactReleasePhase, BufloExactReleaseTimingHistogram, BufloExactReleaseWaitEvidence,
        BufloExactReleaseWaitStep, ChaffRequestHeaderModeArg, CsExactIncomingRetry,
        CsExactIncomingRetryPhase, DefenseArg, Error, ExpectedChaffIdentity,
        OutputDriveCardinality, OutputWorkBoundary, PostOutputRollingBarrier, PrefixBurst,
        PrefixNumericProfile, PrefixPackSpec, PrefixStreamReceipt, PreparedExpectedResponse,
        Preset, ProfileArg, QcsdRequestRole, QualificationAcknowledgement, QualifierStream,
        RUNNER_WAKEUP_METRICS_SCHEMA_VERSION, RUNNER_WAKEUP_METRICS_SEMANTICS, RequestPolicyArg,
        ResourceRunState, ResponseQualificationMode, ResponseQualificationRequest, RunCompletion,
        RunSpec, RunnerWakeupMetrics, RuntimeChaffManifest, ScheduledOutgoing, Socket,
        SocketHandoff, SocketHandoffBoundary, SocketHandoffPolicy, StaticModeArg,
        StreamActivationStage, StreamRecord, StreamType, SustainedResponseQualificationRequest,
        TerminalActionSemantics, TestOutputDrive, TrafficMorphingActivation, absolute_wakeup,
        action_failure_reason, activate_traffic_morphing, application_send_halves_peer_confirmed,
        apply_action_batch, apply_queued_actions, attempt_socket_handoff,
        attempt_socket_handoff_timestamped, await_unshaped_socket_retry,
        bind_qualified_chaff_stream_limits, bounded_qualification_wait,
        buflo_exact_incoming_identities, buflo_exact_incoming_identity_is_pending,
        buflo_exact_release_guard_excluding_candidates, buflo_exact_release_guard_from_candidates,
        buflo_exact_release_wait_step, buflo_run_summary,
        buflo_unadvertised_scheduled_receive_credit_endpoints, cancel_uncommitted_prearms_on_abort,
        chaff_send_halves_peer_confirmed, create_endpoints, cs_buflo_run_summary,
        cs_exact_incoming_identity_is_pending, cs_exact_incoming_retry_inventory,
        cs_exact_incoming_retry_is_due, datagram_observation, deadline_error,
        defense_parameter_provenance, dispatch_buflo_exact_release,
        dispatch_due_cs_exact_incoming_retry, dispatch_ready_requests, drain_qualifier_stream_data,
        drive_buflo_exact_incoming_output_with_clock,
        drive_buflo_unadvertised_scheduled_receive_credit, drive_endpoint_output,
        drive_endpoint_output_until, drive_endpoint_output_with_clock,
        drive_endpoint_output_with_clock_until, due_rolling_output_target,
        duration_as_trace_micros, endpoint_candidate_egress_backlog,
        endpoint_egress_backlog_pending, endpoint_send_terminal, ensure_defense_realizable,
        exact_incoming_retry_times, expected_application_response_length,
        expire_buflo_exact_incoming_credit, finish_application_record, finish_chaff_record,
        finish_stream, forward_qcsd_observation, handle_all_qcsd_observations, handle_http_events,
        has_in_flight_application_stream, is_candidate_defense, is_public_network_address,
        late_socket_handoff_error, next_buflo_exact_release_guard, normalize_rolling_prearm_window,
        now, pending_receive_identity_is_reconciled, prefix_numeric_profile_sha256,
        prefix_receipts_pass, prefix_targetless_stream_bytes, preflight_receive_actions_with,
        prepare_chaff_cancellation, projected_ael, projected_identity_chaff_headers,
        qcsd_connection_parameters, qualification_content_encoding, ready_request_batch,
        reconcile_buflo_exact_incoming_output_error, record_adapter_action_error,
        record_receive_limit_error, record_terminal_action,
        refresh_buflo_exact_incoming_identities, register_action_batch, remaining_wakeup_delay,
        resolve_rolling_output_interrupt, resolve_run_config, resolve_run_config_with_workload,
        response_qualification_mode, rolling_output_lifecycle_active, run_error_class,
        sanitize_chaff_action_headers, sha256, shapes_stream_sends,
        sustained_qualification_content_encoding, sustained_representation_failure,
        sustained_requests_are_classifiable, terminalize_pending_slots,
        trace_files::{PacketTraceRow, QcsdTraceColumns, ScheduleTraceRow, TraceFiles},
        traffic_morphing_endpoint_seed, validate_chaff_cancellation_target,
        validate_chaff_manifest_defense, validate_prefix_capacity_plan, validate_prefix_pack_spec,
        validate_qualified_chaff_binding, validate_terminal_chaff_receive_identities,
        validate_walkie_talkie_chaff_precondition, wait_for_activity_until,
        walkie_talkie_qualification_binding_matches, write_run_json,
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

    #[test]
    fn public_origin_policy_matches_shared_golden_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("public-address-policy-v1.json"))
                .expect("parse public-address policy vectors");
        assert_eq!(vectors["schema_version"], 1);
        assert_eq!(vectors["policy"], "qcsd-public-network-address-v1");
        for (label, expected) in [("accepted", true), ("rejected", false)] {
            let cases = vectors[label]
                .as_array()
                .expect("public-address policy case array");
            assert!(
                cases
                    .iter()
                    .any(|value| value.as_str().is_some_and(|raw| raw.contains('.')))
            );
            assert!(
                cases
                    .iter()
                    .any(|value| value.as_str().is_some_and(|raw| raw.contains(':')))
            );
            for value in cases {
                let raw = value.as_str().expect("public-address policy string");
                let address: IpAddr = raw.parse().expect("public-address policy IP literal");
                assert_eq!(
                    is_public_network_address(address),
                    expected,
                    "{label}: {raw}"
                );
            }
        }
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
    fn chaff_cancellation_target_is_validated_before_adapter_mutation() {
        let application_stream = neqo_transport::StreamId::new(0);
        let chaff_stream = neqo_transport::StreamId::new(4);
        let streams = HashMap::from([
            (application_stream, application(Some(200), false)),
            (chaff_stream, chaff(b"cover", false)),
        ]);

        assert!(matches!(
            validate_chaff_cancellation_target(&streams, QcsdStreamId(8)),
            Err(Error::SlotInvariant(message)) if message.contains("unknown chaff stream 8")
        ));
        assert!(matches!(
            validate_chaff_cancellation_target(&streams, QcsdStreamId(0)),
            Err(Error::SlotInvariant(message)) if message.contains("application stream 0")
        ));
        assert_eq!(
            validate_chaff_cancellation_target(&streams, QcsdStreamId(4)).expect("known chaff"),
            chaff_stream
        );
        assert_eq!(streams.len(), 2, "validation is side-effect free");
    }

    #[test]
    fn terminal_chaff_receive_rollback_policy_is_reason_and_owner_specific() {
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 3).expect("packet");
        let scheduled = QcsdReceiveActionIdentity::Scheduled {
            endpoint,
            stream,
            absolute_limit: 19,
            slot: QcsdSlotId(1),
        };
        let owned = QcsdReceiveActionIdentity::ParserLease {
            endpoint,
            stream,
            absolute_limit: 22,
            increase: 3,
            owner: Some(QcsdParserLeaseOwner {
                packet,
                slot: QcsdSlotId(2),
            }),
        };
        let unowned = QcsdReceiveActionIdentity::ParserLease {
            endpoint,
            stream,
            absolute_limit: 25,
            increase: 3,
            owner: None,
        };

        validate_terminal_chaff_receive_identities(
            QcsdChaffCancellationReason::BufloTerminalSubcellTail,
            &[],
        )
        .expect("BuFLO latch with no adapter suffix");
        assert!(matches!(
            validate_terminal_chaff_receive_identities(
                QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                &[unowned],
            ),
            Err(Error::SlotInvariant(message)) if message.contains("BuFLO terminal sub-cell")
        ));
        validate_terminal_chaff_receive_identities(
            QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
            &[unowned],
        )
        .expect("CS local ET may discard one unowned parser lease");
        for invalid in [scheduled, owned] {
            assert!(matches!(
                validate_terminal_chaff_receive_identities(
                    QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
                    &[invalid],
                ),
                Err(Error::SlotInvariant(message)) if message.contains("only unowned parser leases")
            ));
        }
    }

    #[test]
    fn chaff_cancellation_reason_selects_distinct_rollback_and_receipt_labels() {
        assert_eq!(
            super::chaff_cancellation_rollback_label(
                QcsdChaffCancellationReason::BufloTerminalSubcellTail
            ),
            "buflo_terminal_subcell_unencoded_rollback"
        );
        assert_eq!(
            super::chaff_cancellation_receipt_outcome(
                QcsdChaffCancellationReason::BufloTerminalSubcellTail
            ),
            "buflo_terminal_subcell_tail_cancelled"
        );
        assert_eq!(
            super::chaff_cancellation_rollback_label(
                QcsdChaffCancellationReason::CsBufloLocalEarlyTermination
            ),
            "cs_buflo_local_et_unencoded_rollback"
        );
        assert_eq!(
            super::chaff_cancellation_receipt_outcome(
                QcsdChaffCancellationReason::CsBufloLocalEarlyTermination
            ),
            "local_early_termination_cancelled"
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the real cross-layer cancellation lifecycle is one regression oracle"
    )]
    async fn local_et_rolls_back_only_a_real_unowned_parser_lease_and_reaches_terminal_transport() {
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
        endpoint.chaff_send_streams.insert(stream);
        endpoint.streams.insert(stream, chaff(b"cover", false));
        assert!(!chaff_send_halves_peer_confirmed(&endpoint));
        assert_eq!(
            endpoint_candidate_egress_backlog(&mut endpoint, false),
            (true, true),
            "pre-stop chaff request STREAM work remains schedule-authorising backlog"
        );
        assert_eq!(
            endpoint_candidate_egress_backlog(&mut endpoint, true),
            (false, false),
            "post-stop drain excludes only the retained, still-shaped chaff request identity"
        );

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

        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let cancel = QcsdAction::CancelChaff {
            endpoint: endpoint.id,
            stream,
            reason: QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
        };
        let error = prepare_chaff_cancellation(&mut endpoint, &mut traces, started, &cancel)
            .expect_err("scheduled and owned receive bytes block local ET rollback");
        assert!(matches!(
            error,
            Error::SlotInvariant(message) if message.contains("only unowned parser leases")
        ));
        assert_eq!(
            endpoint.client.qcsd_pending_receive_action_identities(),
            expected_identities,
            "failed policy validation is atomic"
        );

        endpoint
            .client
            .preview_qcsd_receive_action_cancellation(&expected_identities)
            .expect("reset invalid fixture suffix");
        endpoint
            .client
            .commit_qcsd_receive_action_cancellation(&expected_identities)
            .expect("commit invalid fixture reset");
        let unowned = QcsdAction::LeaseParserReceive {
            endpoint: endpoint.id,
            stream,
            absolute_limit: 19,
            increase: 3,
            owner: None,
        };
        assert_eq!(
            endpoint
                .client
                .apply_qcsd_receive_action(&unowned)
                .expect("accept unowned parser lease"),
            Some(QcsdReceiveLimitOutcome::Applied)
        );
        let unowned_identity = unowned.receive_identity().expect("unowned identity");
        let buflo_cancel = QcsdAction::CancelChaff {
            endpoint: endpoint.id,
            stream,
            reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
        };
        let error = prepare_chaff_cancellation(&mut endpoint, &mut traces, started, &buflo_cancel)
            .expect_err("BuFLO tail may not erase even an unowned parser lease");
        assert!(matches!(
            error,
            Error::SlotInvariant(message) if message.contains("BuFLO terminal sub-cell")
        ));
        assert_eq!(
            endpoint.client.qcsd_pending_receive_action_identities(),
            [unowned_identity],
            "BuFLO policy failure leaves the adapter unchanged"
        );

        assert_eq!(
            prepare_chaff_cancellation(&mut endpoint, &mut traces, started, &cancel)
                .expect("prepare exact unowned local-ET rollback"),
            Some((
                neqo_transport::StreamId::new(stream.0),
                QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
            ))
        );
        assert!(
            endpoint
                .client
                .qcsd_pending_receive_action_identities()
                .is_empty(),
            "the exact unowned parser suffix is reconciled"
        );
        assert_eq!(
            endpoint
                .client
                .preview_qcsd_receive_action(&unowned, None)
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
        assert!(
            !chaff_send_halves_peer_confirmed(&endpoint),
            "a locally queued cancellation is not peer-confirmed terminal evidence"
        );
        assert!(endpoint_egress_backlog_pending(&mut endpoint, true));
        assert!(
            !endpoint_send_terminal(&mut endpoint, true),
            "candidate completion is blocked while local-ET control remains"
        );

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
        assert!(
            !endpoint.client.qcsd_has_pending_required_stream_send(&[]),
            "decoder-only transport backlog is non-request-causal and must not hold candidate completion open"
        );
        assert!(!endpoint.client.qcsd_has_pending_defense_control());
        assert!(application_send_halves_peer_confirmed(&endpoint));
        assert!(
            chaff_send_halves_peer_confirmed(&endpoint),
            "RESET_STREAM acknowledgment terminalizes the retained chaff send identity"
        );
        assert!(
            !endpoint_egress_backlog_pending(&mut endpoint, true),
            "candidate quiet state excludes only decoder-only transport backlog"
        );
        assert!(
            endpoint_egress_backlog_pending(&mut endpoint, false),
            "legacy observation retains its established all-STREAM semantics"
        );
        assert!(
            endpoint_send_terminal(&mut endpoint, false),
            "legacy completion retains its established transport-independent predicate"
        );
        assert!(endpoint_send_terminal(&mut endpoint, true));

        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert!(events.contains("cs_buflo_local_et_unencoded_rollback"));
        drop(endpoint);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic expiry oracle binds dependency closure, adapter tombstones, and absence of catch-up output"
    )]
    async fn exact_handoff_large_oversleep_terminalizes_dependents_without_materializing_next_tick()
    {
        let output = trace_output_dir("post-handoff-credit-oversleep");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );

        endpoint.client.qcsd_enable_send_shaping(false);
        let request_url = http::Uri::from_static("https://127.0.0.1:4433/controlled");
        let stream = endpoint
            .client
            .fetch(
                started,
                "GET",
                &request_url,
                &[],
                neqo_http3::Priority::default(),
            )
            .expect("create controlled request stream");
        endpoint
            .client
            .register_qcsd_stream(stream, QcsdRequestRole::Application, Some(10_000))
            .expect("register controlled response stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close request send side");
        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
        assert!(!endpoint.client.qcsd_has_pending_stream_send());
        endpoint.client.qcsd_enable_send_shaping(true);
        drop(endpoint.client.qcsd_timestamped_observations());

        let first = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("first incoming");
        let dependent =
            Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("dependent incoming");
        let next_tick = Packet::new(Duration::from_millis(20), Direction::Incoming, 100)
            .expect("next-tick incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([first, dependent, next_tick]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let scheduled: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, stream, .. } => Some((*slot, *stream)),
                _ => None,
            })
            .collect();
        assert_eq!(scheduled.len(), 2, "only the two t=0 credits are staged");
        assert_eq!(
            scheduled[0].1, scheduled[1].1,
            "the later range depends on the first"
        );

        let mut endpoints = vec![endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply dependent receive credits");

        let defense_start = now();
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: defense_start,
            guard_at: defense_start,
            active_wait_at: defense_start,
            release: defense_start,
            deadline: defense_start + Duration::from_millis(20),
        };
        let mut captured =
            buflo_exact_incoming_identities(&guard, &endpoints, &controller, defense_start, None)
                .expect("capture both dependent identities");
        assert_eq!(captured.len(), 2);
        let overslept_at = guard.deadline + Duration::from_millis(100);
        let error = expire_buflo_exact_incoming_credit(
            &guard,
            &mut captured,
            &BTreeSet::new(),
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            overslept_at,
        )
        .expect("expiry produces the propagated abort");
        assert!(matches!(error, Error::DefenseExecution(_)));
        assert!(controller.pending_slots().is_empty());
        assert_eq!(
            endpoints[0]
                .client
                .qcsd_pending_receive_action_identities()
                .len(),
            2,
            "accepted but unencoded ranges remain terminal transport tombstones"
        );

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 1, "oversleep emits no datagram");
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let mut rows = schedule.lines();
        let header: Vec<_> = rows.next().expect("schedule header").split(',').collect();
        let direction = header
            .iter()
            .position(|column| *column == "direction")
            .expect("direction column");
        let satisfaction = header
            .iter()
            .position(|column| *column == "satisfaction")
            .expect("satisfaction column");
        let miss_reason = header
            .iter()
            .position(|column| *column == "miss_reason")
            .expect("miss-reason column");
        let observed: Vec<Vec<_>> = rows.map(|row| row.split(',').collect()).collect();
        assert_eq!(observed.len(), 2, "the future tick is never materialized");
        assert!(observed.iter().all(|row| {
            row[direction] == "incoming"
                && row[satisfaction] == "missed"
                && row[miss_reason] == "DeadlineExpired"
        }));

        drop(endpoints);
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
        handle_http_events(&mut endpoint, &spec, started, &mut traces, None)
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
        let error = handle_http_events(&mut endpoint, &spec, closed_at, &mut traces, None)
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

    fn assert_runner_wakeup_receipt(metrics: &serde_json::Value) {
        assert_eq!(
            metrics["schema_version"],
            RUNNER_WAKEUP_METRICS_SCHEMA_VERSION
        );
        assert_eq!(RUNNER_WAKEUP_METRICS_SCHEMA_VERSION, 8);
        assert!(
            RUNNER_WAKEUP_METRICS_SEMANTICS.ends_with(
                "buflo_exact_release_active_wait_poll=poll_instant_without_arch_spin_hint"
            )
        );
        assert_eq!(metrics["timer_wakeups"], 2);
        assert_eq!(
            metrics["buflo_exact_release_dispatch_lateness_histogram"]["upper_bounds_nanoseconds"],
            json!([
                50_000, 100_000, 250_000, 500_000, 1_000_000, 2_000_000, 5_000_000
            ])
        );
        assert_eq!(
            metrics["buflo_exact_release_dispatch_lateness_histogram"]["counts"],
            json!([1, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            metrics["buflo_exact_release_active_spin_gap_histogram"]["counts"],
            json!([1, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(metrics["buflo_exact_release_worst_guard"]["slot"], 9);
        assert_eq!(metrics["buflo_exact_release_guard_entries"], 1);
        assert_eq!(metrics["buflo_exact_incoming_retry_drives"], 2);
        assert_eq!(metrics["cs_exact_incoming_retry_drives"], 3);
        assert_eq!(metrics["cs_exact_incoming_retry_resolutions"], 1);
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
    #[expect(
        clippy::too_many_lines,
        reason = "the receipt fixture explicitly checks the complete serialized evidence boundary"
    )]
    fn run_receipt_keeps_evidence_without_duplicate_workload_fields() {
        let output = trace_output_dir("minimal-run-receipt");
        let defense_start = now();
        let release = defense_start + Duration::from_millis(20);
        let deadline = release + Duration::from_millis(5);
        let guard_at = release
            .checked_sub(Duration::from_millis(10))
            .expect("release has a guard predecessor");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(9),
            packet: Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200)
                .expect("packet"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: guard_at,
            guard_at,
            active_wait_at: guard_at,
            release,
            deadline,
        };
        let mut runner_wakeup_metrics = RunnerWakeupMetrics {
            wait_returns: 3,
            socket_readiness_wakeups: 1,
            timer_wakeups: 2,
            controller_deadline_timer_wakeups: 1,
            other_timer_wakeups: 1,
            buflo_exact_incoming_retry_drives: 2,
            buflo_exact_incoming_retry_resolutions: 1,
            buflo_exact_incoming_retry_max_wake_lateness_nanoseconds: 3,
            cs_exact_incoming_retry_drives: 3,
            cs_exact_incoming_retry_resolutions: 1,
            cs_exact_incoming_retry_max_phase_lateness_nanoseconds: 2,
            ..RunnerWakeupMetrics::new()
        };
        runner_wakeup_metrics.record_buflo_exact_release_guard(
            &guard,
            Some(defense_start),
            &BufloExactReleaseWaitEvidence {
                entered_at: guard_at,
                active_wait_started_at: guard_at,
                dispatch_at: release + Duration::from_nanos(1),
                passive_sleep_calls: 0,
                passive_sleep_requested_nanoseconds: 0,
                passive_sleep_elapsed_nanoseconds: 0,
                max_passive_sleep_overrun_nanoseconds: 0,
                active_wait_iterations: 1,
                active_spin_interruptions: 0,
                active_spin_interruption_nanoseconds: 0,
                max_active_spin_gap_nanoseconds: 0,
                active_wait_start_clocks: BufloExactReleaseAuxClockSample::default(),
                active_wait_end_clocks: BufloExactReleaseAuxClockSample::default(),
            },
        );
        assert!(runner_wakeup_metrics.buflo_exact_release_invariants_hold());
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
                error_class: None,
                defense_start_monotonic_ns: Some(3),
                application_completion_monotonic_ns: Some(4),
                defense_diagnostics: None,
                runner_wakeup_metrics: Some(runner_wakeup_metrics),
            },
        )
        .expect("write run receipt");

        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("run.json")).expect("read run receipt"))
                .expect("parse run receipt");
        assert!(receipt.get("resolved_workload").is_none());
        assert!(receipt.get("urls").is_none());
        assert_eq!(receipt["error"], serde_json::Value::Null);
        assert_eq!(receipt["error_class"], serde_json::Value::Null);
        assert_eq!(receipt["workload_hash_sha256"], "frozen-workload-hash");
        assert_runner_wakeup_receipt(&receipt["runner_wakeup_metrics"]);
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
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "the receipt oracle checks both versioned summaries and their cross-field invariants"
    )]
    fn run_receipt_summaries_are_versioned_and_mode_specific() {
        let diagnostics = DefenseDiagnostics {
            buflo_client_only: true,
            cs_buflo_client_only: true,
            cs_buflo_early_termination_semantics: "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing",
            cs_buflo_early_termination_translation_version: 2,
            cs_buflo_termination_stop_policy: "stop_new_opportunities_at_first_eligible_padding_target_or_power_of_two_crossing_then_drain_advertised_credit_exactly_once",
            cs_buflo_incoming_termination_stop_latched: true,
            cs_buflo_incoming_termination_stop_reason: "power_of_two_crossing",
            cs_buflo_incoming_termination_stop_phase: "strict_quiet",
            cs_buflo_incoming_termination_stop_latched_at_us: 1_900_000,
            cs_buflo_incoming_termination_stop_scheduled_cells_at_stop: 13,
            cs_buflo_incoming_termination_stop_terminal_cells_at_stop: 2,
            cs_buflo_incoming_termination_stop_progress_bytes_at_stop: 1_000,
            cs_buflo_incoming_termination_stop_padding_target_bytes_at_stop: 1_024,
            cs_buflo_incoming_termination_stop_crossing_total_bytes: 1_200,
            cs_buflo_incoming_termination_stop_crossing_increment_bytes: 600,
            cs_buflo_incoming_termination_stop_provisional_invalidation_count: 1,
            cs_buflo_local_et_before_application_complete: true,
            cs_buflo_local_et_latched_at_us: 2_000_001,
            cs_buflo_local_et_application_receive_streams_handed_off: 1,
            cs_buflo_local_et_application_parser_boundaries_handed_off: 1,
            cs_buflo_local_et_application_parser_lease_bytes_handed_off: 16,
            cs_buflo_local_et_application_send_endpoints_released: 2,
            cs_buflo_post_local_et_natural_outgoing_bytes: 10,
            cs_buflo_post_local_et_natural_incoming_bytes: 11,
            ..DefenseDiagnostics::default()
        };
        let buflo = DefenseConfig::Buflo(neqo_csdef::BufloConfig {
            parameters: "buflo.json".into(),
        });
        let cs_buflo = DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
            parameters: "cs-buflo.json".into(),
        });

        let buflo_summary = buflo_run_summary(&buflo, Some(&diagnostics)).expect("BuFLO summary");
        assert_eq!(buflo_summary["schema_version"], 4);
        assert_eq!(buflo_summary["kind"], "buflo");
        assert_eq!(buflo_summary["implementation_scope"], "client_only_quic");
        assert_eq!(buflo_summary["paper_equivalent"], false);
        assert_eq!(
            buflo_summary["incoming_opportunity_semantics"],
            "client_receive_credit_and_response_qualified_chaff_attempt"
        );
        assert_eq!(
            buflo_summary["terminal_schedule_stop_policy"],
            "stop_new_opportunities_at_first_terminal_whole_cell_capacity_exhaustion_then_drain_already_advertised_incoming_credit"
        );
        assert_eq!(
            buflo_summary["terminal_subcell_policy"],
            "drain_whole_cells_then_client_local_http3_cancel_unallocatable_reviewed_chaff_tail"
        );
        assert_eq!(
            buflo_summary["terminal_subcell_observer_effect"],
            "typed_stop_sending_and_reset_stream_defense_control_may_follow_the_last_exact_cell"
        );
        assert_eq!(
            buflo_summary["unavailable_peer_properties"],
            json!([
                "scheduled_server_datagram_timing",
                "scheduled_server_datagram_size"
            ])
        );
        assert_eq!(buflo_summary["diagnostics"]["buflo_client_only"], true);
        assert_eq!(
            buflo_summary["diagnostics"]["buflo_terminal_subcell_pending_application_parser_boundaries_at_latch"],
            0
        );
        assert!(cs_buflo_run_summary(&buflo, Some(&diagnostics)).is_none());

        let cs_summary =
            cs_buflo_run_summary(&cs_buflo, Some(&diagnostics)).expect("CS-BuFLO summary");
        assert_eq!(cs_summary["schema_version"], 4);
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
            "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
        );
        assert_eq!(cs_summary["early_termination_translation_version"], 2);
        assert_eq!(
            cs_summary["termination_stop_policy"],
            "stop_new_opportunities_at_first_eligible_padding_target_or_power_of_two_crossing_then_drain_advertised_credit_exactly_once"
        );
        assert_eq!(cs_summary["diagnostics"]["cs_buflo_client_only"], true);
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_incoming_termination_stop_latched"],
            true
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_incoming_termination_stop_crossing_total_bytes"],
            1_200
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_incoming_termination_stop_reason"],
            "power_of_two_crossing"
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_incoming_termination_stop_scheduled_cells_at_stop"],
            13
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_incoming_termination_stop_provisional_invalidation_count"],
            1
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_local_et_before_application_complete"],
            true
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_local_et_application_receive_streams_handed_off"],
            1
        );
        assert_eq!(
            cs_summary["diagnostics"]["cs_buflo_post_local_et_natural_incoming_bytes"],
            11
        );
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
            forward_qcsd_observation(&mut controller, &clock.record(observation), None);
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
            &clock.record(QcsdObservation::ClassifiedDatagram {
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
                RequestPolicyArg::AsDefined,
                false,
                false,
                &tracker,
            )
            .is_empty()
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
    fn candidate_backlog_components_separate_stream_work_from_control_debt() {
        assert_eq!(
            super::candidate_egress_backlog_components(false, true, false),
            (false, false)
        );
        assert_eq!(
            super::candidate_egress_backlog_components(true, true, false),
            (true, true)
        );
        assert_eq!(
            super::candidate_egress_backlog_components(false, true, true),
            (false, true)
        );
        assert_eq!(
            super::candidate_egress_backlog_components(false, false, false),
            (true, true)
        );
    }

    #[test]
    fn candidate_backlog_required_stream_edge_is_observable_while_aggregate_stays_pending() {
        let before = super::candidate_egress_backlog_components(true, true, true);
        let after = super::candidate_egress_backlog_components(false, true, true);
        assert_eq!(before, (true, true));
        assert_eq!(after, (false, true));

        let mut last_stream = None;
        let mut last_aggregate = None;
        assert!(super::backlog_component_changed(&mut last_stream, before.0));
        assert!(super::backlog_component_changed(
            &mut last_aggregate,
            before.1
        ));

        assert!(super::backlog_component_changed(&mut last_stream, after.0));
        assert!(!super::backlog_component_changed(
            &mut last_aggregate,
            after.1
        ));
        assert_eq!(last_stream, Some(false));
        assert_eq!(last_aggregate, Some(true));
    }

    #[test]
    fn candidate_false_stream_snapshot_is_republished_at_every_control_barrier() {
        let mut previous = None;
        assert!(super::candidate_stream_snapshot_should_emit(
            &mut previous,
            false
        ));
        assert!(
            super::candidate_stream_snapshot_should_emit(&mut previous, false),
            "a retained false is not reusable stop authority"
        );
        assert!(super::candidate_stream_snapshot_should_emit(
            &mut previous,
            true
        ));
        assert!(
            !super::candidate_stream_snapshot_should_emit(&mut previous, true),
            "a retained true remains safe and edge-triggered"
        );
    }

    #[test]
    fn terminal_cancellation_can_force_a_fresh_unchanged_aggregate_snapshot() {
        let mut previous = Some(false);
        assert!(!super::candidate_aggregate_snapshot_should_emit(
            &mut previous,
            false,
            false
        ));
        assert!(super::candidate_aggregate_snapshot_should_emit(
            &mut previous,
            false,
            true
        ));
        assert_eq!(previous, Some(false));
        assert!(super::candidate_aggregate_snapshot_should_emit(
            &mut previous,
            true,
            true
        ));
        assert_eq!(previous, Some(true));
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
            Error::DefenseExecution(_)
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
            Error::DefenseExecution(message) if message == "synthetic terminal realization failure"
        ));
    }

    #[test]
    fn run_error_classes_keep_operational_aborts_retryable() {
        assert_eq!(
            run_error_class(&Error::DefenseExecution("synthetic defence defect".into())),
            "client-defense-execution-v1"
        );
        assert_eq!(
            run_error_class(&Error::SlotInvariant("synthetic fidelity defect".into())),
            "client-defense-fidelity-v1"
        );
        assert_eq!(
            run_error_class(&Error::RunAborted("origin closed".into())),
            "runner-execution-v1"
        );
        assert_eq!(run_error_class(&Error::Timeout(30)), "timeout-v1");
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
    fn trace_files_preserve_historical_prefixes_and_append_terminal_schedule_v3() {
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
                terminal_defense_elapsed_us: 77,
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
        let non_schedule_suffix =
            ",1,congestion_sensitive,600,400,100,50,75,1,100,74,23,congestion_limited,,,,,";
        assert!(
            packets
                .lines()
                .nth(1)
                .expect("packet row")
                .ends_with(non_schedule_suffix)
        );
        assert!(
            events
                .lines()
                .nth(1)
                .expect("event row")
                .ends_with(non_schedule_suffix)
        );
        assert!(schedule.lines().nth(1).expect("schedule row").ends_with(
            ",3,congestion_sensitive,600,400,100,50,75,1,100,74,23,congestion_limited,,,,,77"
        ));
        drop(traces);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn logical_slot_registration_allows_strict_incoming_continuation() {
        let output = trace_output_dir("logical-slot");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 84).expect("packet");
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
                terminal_defense_elapsed_us: 99,
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
                Some(7),
                "recorded",
                TerminalActionSemantics::OpportunityResolution,
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
        assert_eq!(fields.next(), Some("3"));
        assert_eq!(fields.next(), Some("exact"));
        assert!(schedule.contains("credit_advertised_at_us"));
        assert!(schedule.contains("credit_consumed_at_us"));
        assert!(row.ends_with(",3,3,7,7,7"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn explicit_receive_limit_receipts_preceding_parser_owner_and_scheduled_slot() {
        let output = trace_output_dir("explicit-credit-covers-parser-owner");
        let started = now();
        let clock = QcsdObservationClock::new(started);
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        let parser_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("parser packet");
        let scheduled_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 20).expect("scheduled packet");
        let parser_slot = QcsdSlotId(32);
        let scheduled_slot = QcsdSlotId(31);
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        register_action_batch(
            &mut traces,
            started + Duration::from_micros(1),
            &[QcsdAction::LeaseParserReceive {
                endpoint,
                stream,
                absolute_limit: 110,
                increase: 10,
                owner: Some(QcsdParserLeaseOwner {
                    packet: parser_packet,
                    slot: parser_slot,
                }),
            }],
        )
        .expect("preceding slot-owned parser target");
        register_action_batch(
            &mut traces,
            started + Duration::from_micros(2),
            &[QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: 120,
                packet: scheduled_packet,
                slot: scheduled_slot,
            }],
        )
        .expect("explicit scheduled target");

        // One physical MAX_STREAM_DATA frame carries the explicit scheduled
        // release and also covers the preceding parser-owned target.
        let advertisement = clock.record_at(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: 120,
                slot: Some(scheduled_slot),
            },
            started + Duration::from_micros(5),
        );
        traces
            .observation(Some(endpoint), &advertisement)
            .expect("coalesced advertisement");

        for (terminal_us, packet, slot) in [
            (7, scheduled_packet, scheduled_slot),
            (8, parser_packet, parser_slot),
        ] {
            assert!(
                record_terminal_action(
                    &mut traces,
                    started + Duration::from_micros(terminal_us),
                    terminal_us,
                    Some(terminal_us),
                    "recorded",
                    TerminalActionSemantics::OpportunityResolution,
                    &QcsdAction::SlotSatisfied {
                        endpoint: Some(endpoint),
                        packet,
                        slot,
                    },
                )
                .expect("terminal schedule")
            );
        }
        traces.flush_events().expect("flush traces");
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        let rows: HashMap<_, _> = schedule
            .lines()
            .skip(1)
            .map(|row| {
                let fields: Vec<_> = row.split(',').collect();
                (fields[8].parse::<u64>().expect("slot id"), fields)
            })
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[&scheduled_slot.0][21], "5");
        assert_eq!(rows[&scheduled_slot.0][22], "3");
        assert_eq!(rows[&parser_slot.0][21], "5");
        assert_eq!(rows[&parser_slot.0][22], "4");

        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        let event = events.lines().nth(1).expect("advertisement event");
        assert!(
            event.ends_with(",5,3,,,"),
            "the scalar event suffix remains attributed to the explicit slot: {event}"
        );
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
                terminal_defense_elapsed_us: 0,
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
    fn schedule_schema_three_rejects_controller_terminal_time_before_target() {
        let output = trace_output_dir("terminal-before-target");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let packet =
            Packet::new(Duration::from_micros(100), Direction::Outgoing, 1_200).expect("packet");
        let slot = QcsdSlotId(91);
        traces
            .register_slot(started, QcsdEndpointId(1), packet, slot)
            .expect("slot registration");

        assert!(matches!(
            traces.schedule(&ScheduleTraceRow {
                action_time_us: 0,
                endpoint: Some(QcsdEndpointId(1)),
                packet,
                satisfaction: "satisfied",
                observed: Some(1_200),
                miss_reason: "",
                slot,
                qcsd: QcsdTraceColumns::exact(1_200, Some(1_200)),
                terminal_defense_elapsed_us: 99,
            }),
            Err(Error::SlotInvariant(message)) if message.contains("predates target")
        ));
        assert!(traces.is_slot_pending(slot));
        assert!(matches!(
            traces.schedule_future_cancellation(
                &ScheduleTraceRow {
                    action_time_us: 99,
                    endpoint: Some(QcsdEndpointId(1)),
                    packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: "EndpointClosed",
                    slot,
                    qcsd: QcsdTraceColumns::default(),
                    terminal_defense_elapsed_us: 99,
                },
                MissedSlotReason::RunAborted,
            ),
            Err(Error::SlotInvariant(message)) if message.contains("matching typed miss")
        ));
        assert!(traces.is_slot_pending(slot));
        traces
            .schedule_future_cancellation(
                &ScheduleTraceRow {
                    action_time_us: 99,
                    endpoint: Some(QcsdEndpointId(1)),
                    packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: "RunAborted",
                    slot,
                    qcsd: QcsdTraceColumns::default(),
                    terminal_defense_elapsed_us: 99,
                },
                MissedSlotReason::RunAborted,
            )
            .expect("typed future-slot cancellation remains receiptable");
        assert!(traces.is_slot_terminal(slot));
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
                Some(5),
                "recorded",
                TerminalActionSemantics::OpportunityResolution,
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
                Some(6),
                "recorded",
                TerminalActionSemantics::OpportunityResolution,
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
                Some(9),
                "recorded",
                TerminalActionSemantics::OpportunityResolution,
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
    #[expect(
        clippy::too_many_lines,
        reason = "the receipt oracle crosses controller local realisation, a slotless parser replacement, and terminal trace serialization"
    )]
    fn trace_freezes_recorded_credit_boundary_before_later_slotless_parser_advertisement() {
        let output = trace_output_dir("frozen-local-realisation-parser-replacement");
        let started = now();
        let clock = QcsdObservationClock::new(started);
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
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
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let first_action = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
            .expect("scheduled receive credit");
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit: first_limit,
            slot,
            ..
        } = first_action
        else {
            unreachable!("filtered receive credit");
        };

        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        register_action_batch(
            &mut traces,
            started + Duration::from_micros(1),
            std::slice::from_ref(&first_action),
        )
        .expect("register scheduled receive credit");
        let first_advertisement = clock.record_at(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: first_limit,
                slot: Some(slot),
            },
            started + Duration::from_micros(3),
        );
        let first_handoff_at = started + Duration::from_micros(4);
        controller.observe(
            first_advertisement.observation().clone(),
            Duration::from_micros(4),
        );
        assert!(controller.incoming_slot_is_locally_realized(slot));
        assert!(matches!(
            traces.observation_after_controller(
                Some(endpoint),
                &first_advertisement,
                &controller,
                None,
            ),
            Err(Error::SlotInvariant(message))
                if message.contains("lacked a successful socket-handoff timestamp")
        ));
        traces
            .observation_after_controller(
                Some(endpoint),
                &first_advertisement,
                &controller,
                Some(first_handoff_at),
            )
            .expect("freeze first whole-slot local boundary");

        // The controller unit `unused_scheduled_parser_ownership_returns_on_stream_lifecycle`
        // proves that unconsumed advertised parser ownership can legally
        // return and acquire a later same-slot action. This trace-specific
        // oracle supplies that already-proven replacement shape so a later
        // slotless transport advertisement cannot move the frozen boundary.
        let parser_limit = first_limit.saturating_add(16);
        let parser_replacement = QcsdAction::LeaseParserReceive {
            endpoint,
            stream,
            absolute_limit: parser_limit,
            increase: 16,
            owner: Some(QcsdParserLeaseOwner { packet, slot }),
        };
        register_action_batch(
            &mut traces,
            started + Duration::from_micros(8),
            std::slice::from_ref(&parser_replacement),
        )
        .expect("register same-slot parser replacement");
        let replacement_advertisement = clock.record_at(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: parser_limit,
                slot: None,
            },
            started + Duration::from_micros(9),
        );
        traces
            .observation_after_controller(
                Some(endpoint),
                &replacement_advertisement,
                &controller,
                Some(started + Duration::from_micros(10)),
            )
            .expect("record later slotless parser advertisement");

        assert!(
            record_terminal_action(
                &mut traces,
                started + Duration::from_micros(10),
                10,
                Some(10),
                "recorded",
                TerminalActionSemantics::OpportunityResolution,
                &QcsdAction::SlotSatisfied {
                    endpoint: Some(endpoint),
                    packet,
                    slot,
                },
            )
            .expect("terminal schedule")
        );
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        let fields: Vec<_> = schedule
            .lines()
            .nth(1)
            .expect("terminal schedule row")
            .split(',')
            .collect();
        assert_eq!(
            fields[21], "4",
            "freeze the successful socket-handoff edge, not packet build"
        );
        assert_eq!(fields[22], "3", "measure from the original action time");
        assert_eq!(fields[8], slot.0.to_string());
        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        let first_event = events.lines().nth(1).expect("first advertisement event");
        assert!(first_event.starts_with("3,1,observation,recorded,"));
        assert!(first_event.contains("\"\"production_monotonic_ns\"\":3000"));
        assert!(
            first_event.ends_with(",4,3,,,"),
            "scalar receipt uses the later physical handoff: {first_event}"
        );
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn slotless_unowned_receive_advertisement_records_without_scalar_provenance() {
        let output = trace_output_dir("slotless-unowned-receive-advertisement");
        let started = now();
        let clock = QcsdObservationClock::new(started);
        let endpoint = QcsdEndpointId(1);
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let controller = QcsdController::new(QcsdConfig::default(), 0, None).expect("controller");
        let advertisement = clock.record_at(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: QcsdStreamId(0),
                absolute_limit: 16,
                slot: None,
            },
            started + Duration::from_micros(3),
        );

        traces
            .observation_after_controller(
                Some(endpoint),
                &advertisement,
                &controller,
                Some(started + Duration::from_micros(4)),
            )
            .expect("record slotless unowned receive advertisement");
        drop(traces);

        let events = fs::read_to_string(output.join("events.csv")).expect("events");
        assert_eq!(events.lines().count(), 2);
        assert!(events.lines().nth(1).is_some_and(|event| {
            event.starts_with("3,1,observation,recorded,") && event.contains("\"\"slot\"\":null")
        }));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn missing_adapter_terminalizes_an_owned_parser_lease_once() {
        let output = trace_output_dir("owned-parser-lease-missing-adapter");
        let started = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let endpoint = QcsdEndpointId(9);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let slot = QcsdSlotId(0);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
        controller.poll(Duration::ZERO);
        assert_eq!(controller.pending_slots(), [(slot, packet)]);
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
        assert_eq!(fields[8], "0");
        assert_eq!(fields.last(), Some(&"3"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[derive(Debug)]
    struct RollingOutgoingOneShot {
        event: Option<Packet>,
    }

    impl Defense for RollingOutgoingOneShot {
        fn observe(&mut self, _signal: DefenseSignal) {}

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.event.filter(|packet| packet.timestamp() <= elapsed)?;
            self.event.take()
        }

        fn next_outgoing_prearm(&self) -> Option<Packet> {
            self.event
        }

        fn next_event_at(&self) -> Option<Duration> {
            self.event.map(Packet::timestamp)
        }

        fn is_complete(&self) -> bool {
            self.event.is_none()
        }

        fn is_outgoing_complete(&self) -> bool {
            self.event.is_none()
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }
    }

    #[derive(Debug)]
    struct RollingOutgoingSequence {
        events: VecDeque<Packet>,
        exact_incoming_window: bool,
    }

    impl Defense for RollingOutgoingSequence {
        fn observe(&mut self, _signal: DefenseSignal) {}

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.events
                .front()
                .filter(|packet| packet.timestamp() <= elapsed)?;
            self.events.pop_front()
        }

        fn next_outgoing_prearm(&self) -> Option<Packet> {
            self.events.front().copied()
        }

        fn next_event_at(&self) -> Option<Duration> {
            self.events.front().copied().map(Packet::timestamp)
        }

        fn is_complete(&self) -> bool {
            self.events.is_empty()
        }

        fn is_outgoing_complete(&self) -> bool {
            self.events.is_empty()
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }

        fn incoming_slot_must_resolve_in_window(&self) -> bool {
            self.exact_incoming_window
        }
    }

    #[derive(Debug)]
    struct RollingOutgoingTerminalOnApplication {
        events: VecDeque<Packet>,
        terminal: bool,
    }

    impl Defense for RollingOutgoingTerminalOnApplication {
        fn observe(&mut self, signal: DefenseSignal) {
            self.terminal |= matches!(signal.kind, SignalKind::ApplicationComplete);
        }

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            if self.terminal {
                return None;
            }
            self.events
                .front()
                .filter(|packet| packet.timestamp() <= elapsed)?;
            self.events.pop_front()
        }

        fn next_outgoing_prearm(&self) -> Option<Packet> {
            (!self.terminal)
                .then(|| self.events.front().copied())
                .flatten()
        }

        fn next_event_at(&self) -> Option<Duration> {
            (!self.terminal)
                .then(|| self.events.front().copied().map(Packet::timestamp))
                .flatten()
        }

        fn is_complete(&self) -> bool {
            false
        }

        fn is_outgoing_complete(&self) -> bool {
            self.terminal
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }
    }

    #[derive(Debug)]
    struct RollingOutgoingOutcomeProbe {
        event: Option<Packet>,
        resolved: bool,
    }

    impl Defense for RollingOutgoingOutcomeProbe {
        fn observe(&mut self, signal: DefenseSignal) {
            if matches!(signal.kind, SignalKind::Resolved { .. }) {
                self.resolved = true;
            }
        }

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.event.filter(|packet| packet.timestamp() <= elapsed)?;
            self.event.take()
        }

        fn next_outgoing_prearm(&self) -> Option<Packet> {
            self.event
        }

        fn next_event_at(&self) -> Option<Duration> {
            self.event.map(Packet::timestamp)
        }

        fn is_complete(&self) -> bool {
            self.event.is_none()
        }

        fn is_outgoing_complete(&self) -> bool {
            self.event.is_none()
        }

        fn terminal_failure(&self) -> Option<&'static str> {
            self.resolved
                .then_some("synthetic final rolling outcome was reduced")
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }
    }

    fn rolling_abort_controller(packet: Packet) -> QcsdController {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingOneShot {
                event: Some(packet),
            }),
        )
        .expect("controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://example.com".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        assert!(controller.has_rolling_outgoing_prearm());
        controller
    }

    fn connected_runner_endpoint_with_server(
        output: &Path,
        started: std::time::Instant,
        clock: &QcsdObservationClock,
        endpoint_id: QcsdEndpointId,
        port: u16,
        control_interval_us: u64,
    ) -> (super::Endpoint, neqo_http3::Http3Server) {
        test_fixture::fixture_init();
        let config = QcsdConfig {
            control_interval_us,
            defense: DefenseConfig::Static {
                schedule: "test-only-runner-shaping.csv".into(),
                padding_only: false,
            },
            ..QcsdConfig::default()
        };
        let first_port = port.saturating_sub(u16::try_from(endpoint_id.0).unwrap_or(u16::MAX));
        let resources = (0..=endpoint_id.0)
            .map(|index| {
                request(
                    u32::try_from(index + 1).unwrap_or(u32::MAX),
                    &format!(
                        "https://127.0.0.1:{}",
                        first_port.saturating_add(u16::try_from(index).unwrap_or(u16::MAX))
                    ),
                    Vec::new(),
                )
            })
            .collect();
        let spec = RunSpec {
            method: "GET",
            workload: ResourceManifest { resources },
            workload_hash: "rolling-abort-runner".into(),
            application_workload_source: None,
            config,
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 7,
            output_dir: output.to_path_buf(),
            max_response_bytes: 1,
            timeout_seconds: 1,
        };
        let mut endpoint = create_endpoints(&spec, started, clock)
            .expect("construct runner endpoints")
            .remove(usize::try_from(endpoint_id.0).expect("test endpoint index"));
        assert_eq!(endpoint.id, endpoint_id);
        // Handshake the actual runner client so its QUIC path source address
        // is the address owned by `endpoint.socket`; synthetic fixture path
        // addresses are rejected by `sendmsg` inside a Linux container.
        let mut server = test_fixture::default_http3_server();
        let trailing = test_fixture::connect_peers(&mut endpoint.client, &mut server);
        let server_output = server.process(trailing, test_fixture::now()).dgram();
        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, server_output);
        endpoint.connected = true;
        endpoint.pending.clear();
        (endpoint, server)
    }

    fn connected_runner_endpoint(
        output: &Path,
        started: std::time::Instant,
        clock: &QcsdObservationClock,
    ) -> super::Endpoint {
        connected_runner_endpoint_with_server(
            output,
            started,
            clock,
            QcsdEndpointId(0),
            4_433,
            5_000,
        )
        .0
    }

    fn staged_exact_incoming_credit_fixture(
        output: &Path,
        started: std::time::Instant,
        observation_clock: &QcsdObservationClock,
    ) -> (
        Vec<super::Endpoint>,
        neqo_http3::Http3Server,
        QcsdController,
        QcsdSlotId,
        TraceFiles,
    ) {
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            output,
            started,
            observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );
        let stream =
            open_controlled_runner_stream(&mut endpoint, &mut server, started, 4_433, 10_000);
        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let incoming_slot = actions
            .iter()
            .find_map(|action| action.receive_identity()?.slot())
            .expect("incoming slot");
        let mut endpoints = vec![endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply receive credit");
        (endpoints, server, controller, incoming_slot, traces)
    }

    fn open_controlled_runner_stream(
        endpoint: &mut super::Endpoint,
        server: &mut neqo_http3::Http3Server,
        started: std::time::Instant,
        port: u16,
        expected_response_length: u64,
    ) -> neqo_transport::StreamId {
        endpoint.client.qcsd_enable_send_shaping(false);
        let request_url: http::Uri = format!("https://127.0.0.1:{port}/controlled")
            .parse()
            .expect("controlled request URI");
        let stream = endpoint
            .client
            .fetch(
                started,
                "GET",
                &request_url,
                &[],
                neqo_http3::Priority::default(),
            )
            .expect("create controlled request stream");
        endpoint
            .client
            .register_qcsd_stream(
                stream,
                QcsdRequestRole::Application,
                Some(expected_response_length),
            )
            .expect("register controlled response stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close request send side");
        test_fixture::exchange_packets(&mut endpoint.client, server, false, None);
        assert!(!endpoint.client.qcsd_has_pending_stream_send());
        endpoint.client.qcsd_enable_send_shaping(true);
        drop(endpoint.client.qcsd_timestamped_observations());
        stream
    }

    #[derive(Debug, Default)]
    struct RunnerBarrierLocalEtDefense {
        complete: bool,
    }

    impl Defense for RunnerBarrierLocalEtDefense {
        fn observe(&mut self, signal: DefenseSignal) {
            if matches!(signal.kind, SignalKind::Wire { .. }) {
                self.complete = true;
            }
        }

        fn next_event(&mut self, _elapsed: Duration) -> Option<Packet> {
            None
        }

        fn next_event_at(&self) -> Option<Duration> {
            None
        }

        fn is_complete(&self) -> bool {
            self.complete
        }

        fn is_outgoing_complete(&self) -> bool {
            self.complete
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }

        fn requires_terminal_chaff_drain(&self) -> bool {
            true
        }

        fn terminal_chaff_cancellation_reason(&self) -> Option<QcsdChaffCancellationReason> {
            Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination)
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected regression binds controller cancellation, real transport drain, and fresh runner evidence"
    )]
    async fn terminal_cancel_applied_to_adapter_forces_fresh_false_after_real_drain() {
        let output = trace_output_dir("terminal-cancel-fresh-false");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            5_000,
        );

        // Establish a real open chaff response whose request and critical
        // STREAM bytes are fully acknowledged. The runner's retained aggregate
        // snapshot is therefore an actual pre-cancellation false, not a
        // synthetic test value.
        endpoint.client.qcsd_enable_send_shaping(false);
        let resource = Resource {
            id: 0,
            url: "https://127.0.0.1:4433/chaff".into(),
            kind: "Other".into(),
            content_length: Some(5),
            data_length: 5,
            chaff_priority: true,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        };
        let request_id = QcsdChaffRequestId(7);
        let stream = endpoint
            .client
            .apply_qcsd_action(
                started,
                QcsdAction::RequestChaff {
                    endpoint: endpoint.id,
                    resource: resource.clone(),
                    request_id,
                },
            )
            .expect("create real chaff request")
            .expect("chaff request stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close chaff request send handler");
        endpoint.chaff_send_streams.insert(stream);
        let mut record = chaff(b"cover", false);
        record.url.clone_from(&resource.url);
        endpoint.streams.insert(stream, record);
        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
        assert!(chaff_send_halves_peer_confirmed(&endpoint));
        assert!(
            !endpoint.client.qcsd_has_pending_required_stream_send(&[]),
            "the open chaff response has no pre-cancellation request backlog"
        );
        assert!(!endpoint.client.qcsd_has_pending_defense_control());
        endpoint.client.qcsd_enable_send_shaping(true);
        drop(endpoint.client.qcsd_timestamped_observations());

        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RunnerBarrierLocalEtDefense { complete: true }),
        )
        .expect("terminal test controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: endpoint.id,
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: endpoint.id,
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Chaff {
                    resource_id: resource.id,
                    request_id: None,
                },
                expected_response_length: None,
            },
            Duration::ZERO,
        );

        let mut endpoints = vec![endpoint];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_queued_actions(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
        )
        .expect("apply manual receive configuration");
        let pre_cancel_backlog = endpoint_candidate_egress_backlog(&mut endpoints[0], false);
        assert_eq!(pre_cancel_backlog, (false, false));
        let mut last_egress_backlog = Some(pre_cancel_backlog.1);

        controller.observe(
            QcsdObservation::EgressBacklog {
                pending: pre_cancel_backlog.1,
            },
            Duration::ZERO,
        );
        controller.flush_defense_observations();
        let cancel_at = Duration::from_micros(1);
        controller.poll(cancel_at);
        assert!(!controller.is_complete());
        assert!(
            !controller.requires_terminal_egress_backlog_snapshot(),
            "a queued CancelChaff has not crossed the adapter boundary"
        );

        apply_queued_actions(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started + cancel_at,
            cancel_at,
        )
        .expect("apply terminal chaff cancellation to the real adapter");
        assert!(endpoints[0].streams.is_empty());
        assert!(endpoints[0].client.qcsd_has_pending_defense_control());
        assert!(!endpoint_send_terminal(&mut endpoints[0], true));
        assert!(controller.requires_terminal_egress_backlog_snapshot());
        assert!(!controller.is_complete());

        // Model the fast-drain production path: RESET/STOP is acknowledged
        // before the next control barrier, so the runner never observes the
        // transient true and its retained aggregate remains false.
        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, None);
        assert!(!endpoints[0].client.qcsd_has_pending_defense_control());
        assert!(chaff_send_halves_peer_confirmed(&endpoints[0]));
        assert!(endpoint_send_terminal(&mut endpoints[0], true));
        let post_cancel_backlog = endpoint_candidate_egress_backlog(&mut endpoints[0], false);
        assert_eq!(post_cancel_backlog, (false, false));
        assert_eq!(last_egress_backlog, Some(false));

        assert!(super::candidate_aggregate_snapshot_should_emit(
            &mut last_egress_backlog,
            post_cancel_backlog.1,
            controller.requires_terminal_egress_backlog_snapshot(),
        ));
        assert_eq!(last_egress_backlog, Some(false));
        let fresh_at = Duration::from_micros(2);
        controller.observe(
            QcsdObservation::EgressBacklog {
                pending: post_cancel_backlog.1,
            },
            fresh_at,
        );
        controller.flush_defense_observations();
        assert!(controller.requires_terminal_egress_backlog_snapshot());
        assert!(!controller.is_complete());

        controller.poll(fresh_at);
        assert!(!controller.requires_terminal_egress_backlog_snapshot());
        assert!(controller.is_complete());
        let completion_actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            completion_actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::DefenseComplete))
                .count(),
            1
        );

        drop(traces);
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected runner regression preserves the complete dispatch and response lifecycle"
    )]
    async fn same_barrier_local_et_blocks_dependent_until_handoff_then_completes_once() {
        let output = trace_output_dir("same-barrier-local-et-dependent");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let origin = "https://127.0.0.1:4433";
        let workload = ResourceManifest {
            resources: vec![request(1, origin, Vec::new()), request(2, origin, vec![1])],
        };
        let spec = RunSpec {
            method: "GET",
            workload: workload.clone(),
            workload_hash: "same-barrier-local-et-dependent".into(),
            application_workload_source: None,
            config: QcsdConfig {
                defense: DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
                    parameters: "test-only-cs-buflo.json".into(),
                }),
                max_udp_payload_size: 1_200,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 7,
            output_dir: output.clone(),
            max_response_bytes: 16,
            timeout_seconds: 1,
        };
        let mut endpoints = create_endpoints(&spec, started, &observation_clock)
            .expect("construct connected runner endpoint");
        let mut server = test_fixture::default_http3_server();
        let trailing = test_fixture::connect_peers(&mut endpoints[0].client, &mut server);
        let server_output = server.process(trailing, test_fixture::now()).dgram();
        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, server_output);
        endpoints[0].connected = true;
        endpoints[0]
            .pending
            .retain(|request| request.resource_id == 2);
        drop(endpoints[0].client.qcsd_timestamped_observations());

        let mut controller = QcsdController::with_defense(
            spec.config.clone(),
            None,
            Box::<RunnerBarrierLocalEtDefense>::default(),
        )
        .expect("test controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: endpoints[0].id,
                origin: origin.into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        let mut dependencies = DependencyTracker::new(workload).expect("dependency tracker");
        dependencies
            .mark_in_flight(1)
            .expect("root request started");
        let barrier = Duration::from_micros(2_000_001);
        dependencies
            .mark_succeeded(1)
            .expect("root retires and exposes its dependent");
        controller.observe(
            QcsdObservation::ResourceCompleted {
                resource_id: 1,
                success: true,
            },
            barrier,
        );
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: endpoints[0].id,
                direction: Direction::Incoming,
                length: 1_200,
                timestamp_us: 2_000_001,
            },
            barrier,
        );
        controller.flush_defense_observations();
        assert!(!controller.can_start_application_batch());

        let barrier_now = started + barrier;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        assert_eq!(
            dispatch_ready_requests(
                &mut endpoints,
                &spec,
                &mut dependencies,
                barrier_now,
                &mut traces,
                controller.can_start_application_batch(),
                None,
            )
            .expect("blocked dispatch"),
            0
        );
        assert_eq!(endpoints[0].pending.len(), 1);
        assert!(endpoints[0].streams.is_empty());

        controller.poll(barrier);
        assert!(controller.can_start_application_batch());
        apply_queued_actions(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            barrier_now,
            barrier,
        )
        .expect("apply local-ET handoff");
        assert_eq!(
            dispatch_ready_requests(
                &mut endpoints,
                &spec,
                &mut dependencies,
                barrier_now,
                &mut traces,
                controller.can_start_application_batch(),
                Some(now()),
            )
            .expect("expired work interrupt"),
            0
        );
        assert_eq!(endpoints[0].pending.len(), 1);
        assert!(endpoints[0].streams.is_empty());
        assert_eq!(
            dispatch_ready_requests(
                &mut endpoints,
                &spec,
                &mut dependencies,
                barrier_now,
                &mut traces,
                controller.can_start_application_batch(),
                None,
            )
            .expect("post-handoff dispatch"),
            1
        );
        assert_eq!(
            dispatch_ready_requests(
                &mut endpoints,
                &spec,
                &mut dependencies,
                barrier_now,
                &mut traces,
                controller.can_start_application_batch(),
                None,
            )
            .expect("duplicate dispatch probe"),
            0
        );
        assert!(endpoints[0].pending.is_empty());
        assert_eq!(endpoints[0].streams.len(), 1);

        handle_all_qcsd_observations(&mut endpoints, &mut controller, &mut traces, barrier)
            .expect("reduce dependent StreamOpened");
        controller.flush_defense_observations();
        apply_queued_actions(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            barrier_now,
            barrier,
        )
        .expect("apply dependent automatic receive");

        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, None);
        let request_stream = server
            .events()
            .find_map(|event| match event {
                neqo_http3::Http3ServerEvent::Headers { stream, fin, .. } => {
                    assert!(fin, "GET request must finish in its header block");
                    Some(stream)
                }
                _ => None,
            })
            .expect("server receives the dependent request");
        request_stream
            .send_headers(&[
                neqo_common::Header::new(":status", "200"),
                neqo_common::Header::new("content-length", "1"),
            ])
            .expect("send response headers");
        assert_eq!(
            request_stream
                .send_data(b"x", barrier_now)
                .expect("send response body"),
            1
        );
        request_stream
            .stream_close_send(barrier_now)
            .expect("finish response");
        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, None);
        handle_http_events(&mut endpoints[0], &spec, barrier_now, &mut traces, None)
            .expect("consume dependent response");
        for (resource_id, state) in endpoints[0].retired_applications.drain(..) {
            assert_eq!((resource_id, state), (2, ResourceRunState::Succeeded));
            dependencies
                .mark_succeeded(resource_id)
                .expect("retire dependent exactly once");
        }

        assert!(dependencies.is_complete());
        assert!(dependencies.is_successful());
        assert!(application_send_halves_peer_confirmed(&endpoints[0]));
        assert_eq!(endpoints[0].completed.len(), 1);
        let completed = &endpoints[0].completed[0];
        assert_eq!(completed.resource_id, 2);
        assert_eq!(completed.status, Some(200));
        assert_eq!(completed.body, b"x");
        assert!(completed.complete);
        assert_eq!(completed.outcome, "succeeded");

        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        let lines: Vec<_> = events.lines().collect();
        let release = lines
            .iter()
            .position(|line| line.contains("release_application_send_shaping"))
            .expect("handoff release trace");
        let starts: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains(",application_request,started,"))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(starts.len(), 1, "dependent dispatches exactly once");
        assert!(
            release < starts[0],
            "handoff applies before dependent dispatch"
        );

        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected response fixture proves bounded reads preserve the complete body lifecycle"
    )]
    async fn bounded_data_readable_resumes_without_losing_body_or_terminal_cleanup() {
        let output = trace_output_dir("bounded-data-readable");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let origin = "https://127.0.0.1:4433";
        let body = vec![0x5a_u8; 32 * 1024 + 1];
        let mut resource = request(1, origin, Vec::new());
        resource.content_length = Some(u64::try_from(body.len()).expect("body length"));
        resource.data_length = u64::try_from(body.len()).expect("body length");
        let workload = ResourceManifest {
            resources: vec![resource],
        };
        let spec = RunSpec {
            method: "GET",
            workload: workload.clone(),
            workload_hash: "bounded-data-readable".into(),
            application_workload_source: None,
            config: QcsdConfig {
                defense: DefenseConfig::None,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            defense_parameters: None,
            chaff_manifest: None,
            chaff_manifest_hash: None,
            request_policy: RequestPolicyArg::AsDefined,
            seed: 7,
            output_dir: output.clone(),
            max_response_bytes: u64::try_from(body.len()).expect("body length"),
            timeout_seconds: 1,
        };
        let mut endpoints =
            create_endpoints(&spec, started, &observation_clock).expect("construct endpoint");
        let mut server = test_fixture::default_http3_server();
        let trailing = test_fixture::connect_peers(&mut endpoints[0].client, &mut server);
        let server_output = server.process(trailing, test_fixture::now()).dgram();
        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, server_output);
        endpoints[0].connected = true;
        while endpoints[0].client.next_event().is_some() {}
        drop(endpoints[0].client.qcsd_timestamped_observations());

        let mut dependencies = DependencyTracker::new(workload).expect("dependency tracker");
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        assert_eq!(
            dispatch_ready_requests(
                &mut endpoints,
                &spec,
                &mut dependencies,
                started,
                &mut traces,
                true,
                None,
            )
            .expect("dispatch request"),
            1
        );
        let stream_id = *endpoints[0]
            .streams
            .keys()
            .next()
            .expect("application stream");
        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, None);
        let request_stream = server
            .events()
            .find_map(|event| match event {
                neqo_http3::Http3ServerEvent::Headers { stream, fin, .. } => {
                    assert!(fin, "GET request finishes in its header block");
                    Some(stream)
                }
                _ => None,
            })
            .expect("server receives request");
        let content_length = body.len().to_string();
        request_stream
            .send_headers(&[
                neqo_common::Header::new(":status", "200"),
                neqo_common::Header::new("content-length", content_length.as_str()),
            ])
            .expect("send response headers");
        assert_eq!(
            request_stream
                .send_data(&body, started)
                .expect("buffer response body"),
            body.len()
        );
        request_stream
            .stream_close_send(started)
            .expect("finish response");
        test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, None);

        handle_http_events(&mut endpoints[0], &spec, started, &mut traces, Some(1))
            .expect("consume response headers");
        handle_http_events(&mut endpoints[0], &spec, started, &mut traces, Some(1))
            .expect("consume first bounded data chunk");
        assert_eq!(
            endpoints[0]
                .streams
                .get(&stream_id)
                .expect("stream remains active after one chunk")
                .bytes,
            32 * 1024
        );
        assert_eq!(
            endpoints[0].deferred_data_readable,
            VecDeque::from([stream_id]),
            "the same event is retained for the next bounded runner turn"
        );
        handle_http_events(&mut endpoints[0], &spec, started, &mut traces, Some(1))
            .expect("consume final bounded data chunk");

        assert!(endpoints[0].streams.is_empty());
        assert!(endpoints[0].deferred_data_readable.is_empty());
        assert_eq!(
            endpoints[0].retired_applications,
            vec![(1, ResourceRunState::Succeeded)]
        );
        assert_eq!(endpoints[0].completed.len(), 1);
        let completed = &endpoints[0].completed[0];
        assert_eq!(
            completed.bytes,
            u64::try_from(body.len()).expect("body length")
        );
        assert_eq!(completed.body, body);
        assert!(completed.complete);
        assert_eq!(completed.outcome, "succeeded");

        drop(traces);
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    fn queue_peer_connection_close(
        endpoint: &mut super::Endpoint,
        server: &mut neqo_http3::Http3Server,
        at: std::time::Instant,
    ) {
        let connection = server
            .events()
            .find_map(|event| match event {
                neqo_http3::Http3ServerEvent::StateChange {
                    conn,
                    state: neqo_http3::Http3State::Connected,
                } => Some(conn),
                _ => None,
            })
            .expect("connected server connection");
        connection
            .borrow_mut()
            .close(at, 85, "peer close before rolling release");
        let close_datagram = server
            .process_output(at)
            .dgram()
            .expect("peer CONNECTION_CLOSE datagram");
        endpoint.client.process_input(close_datagram, at);
    }

    fn assert_single_prearm_abort_receipt(output: &Path, outcome: &str) {
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert_eq!(events.matches("cancel_prearmed_packet").count(), 1);
        assert_eq!(events.matches(outcome).count(), 1);
        assert!(events.contains("run_aborted"));
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(
            schedule.lines().count(),
            1,
            "previews are not scheduled events"
        );
    }

    #[test]
    fn rolling_abort_receipts_an_unapplied_runner_preview_once() {
        let output = trace_output_dir("rolling-abort-before-adapter");
        let started = now();
        let packet =
            Packet::new(Duration::from_millis(100), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        cancel_uncommitted_prearms_on_abort(&mut [], &mut controller, &mut traces, started)
            .expect("cancel queued preview");
        cancel_uncommitted_prearms_on_abort(&mut [], &mut controller, &mut traces, started)
            .expect("repeat cleanup is inert");
        assert!(!controller.has_rolling_outgoing_prearm());
        drop(traces);
        assert_single_prearm_abort_receipt(&output, "abort_cleanup_before_adapter");
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn rolling_abort_receipts_an_unreconciled_due_marker_once() {
        let output = trace_output_dir("rolling-abort-due-marker");
        let started = now();
        let packet =
            Packet::new(Duration::from_millis(100), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        controller.observe(
            QcsdObservation::EndpointClosed {
                endpoint: QcsdEndpointId(0),
            },
            packet.timestamp(),
        );
        assert_eq!(controller.rolling_reconciliation_due_packet(), Some(packet));
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        for _ in 0..2 {
            cancel_uncommitted_prearms_on_abort(
                &mut [],
                &mut controller,
                &mut traces,
                started + packet.timestamp(),
            )
            .expect("receipt due marker");
        }
        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert_eq!(
            events
                .matches("abort_cleanup_unreconciled_due_marker")
                .count(),
            1
        );
        assert!(events.contains("unreconciled_due_rolling_preview"));
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 1, "a preview is not an event");
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn rolling_abort_cancels_an_applied_runner_preview_once() {
        let output = trace_output_dir("rolling-abort-applied-adapter");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let packet =
            Packet::new(Duration::from_millis(100), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("preview action");
        let mut endpoints = vec![connected_runner_endpoint(&output, started, &clock)];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply preview");
        assert_eq!(endpoints[0].prearmed_outgoing.len(), 1);
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 1);

        for _ in 0..2 {
            cancel_uncommitted_prearms_on_abort(
                &mut endpoints,
                &mut controller,
                &mut traces,
                started,
            )
            .expect("abort cleanup");
        }
        assert!(!controller.has_rolling_outgoing_prearm());
        assert!(endpoints[0].prearmed_outgoing.is_empty());
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        drop(traces);
        assert_single_prearm_abort_receipt(&output, "abort_cleanup_applied");
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn rolling_abort_receipts_a_preview_already_dropped_by_connection_close_once() {
        let output = trace_output_dir("rolling-abort-adapter-closed");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let packet =
            Packet::new(Duration::from_millis(100), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("preview action");
        let mut endpoints = vec![connected_runner_endpoint(&output, started, &clock)];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply preview");
        endpoints[0]
            .client
            .close(started, 85, "abort fixture close");
        drop(
            endpoints[0]
                .client
                .process_output(started + Duration::from_secs(60)),
        );
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        assert_eq!(endpoints[0].prearmed_outgoing.len(), 1);

        for _ in 0..2 {
            cancel_uncommitted_prearms_on_abort(
                &mut endpoints,
                &mut controller,
                &mut traces,
                started + Duration::from_secs(60),
            )
            .expect("abort cleanup");
        }
        assert!(!controller.has_rolling_outgoing_prearm());
        assert!(endpoints[0].prearmed_outgoing.is_empty());
        drop(traces);
        assert_single_prearm_abort_receipt(&output, "abort_cleanup_adapter_closed");
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the runner oracle covers both overlapping rolling identities through abort reconciliation"
    )]
    async fn rolling_abort_reconciles_current_runner_and_next_controller_previews_once_each() {
        let output = trace_output_dir("rolling-abort-current-and-next");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let current =
            Packet::new(Duration::from_millis(10), Direction::Outgoing, 1_200).expect("packet");
        let next =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([current, next]),
                exact_incoming_window: false,
            }),
        )
        .expect("controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://example.com".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let current_preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { packet, .. } if *packet == current))
            .expect("current preview");
        let mut endpoints = vec![connected_runner_endpoint(&output, started, &clock)];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![current_preview],
        )
        .expect("apply current preview");

        controller
            .reconcile_due_rolling(Duration::from_millis(10))
            .expect("reconcile current rolling preview");
        let transition: Vec<_> = controller.drain_actions().collect();
        let current_slot = transition
            .iter()
            .find_map(|action| match action {
                QcsdAction::CommitPrearmedPacket { packet, slot, .. } if *packet == current => {
                    Some(*slot)
                }
                _ => None,
            })
            .expect("current commit awaiting adapter");
        let next_slot = transition
            .iter()
            .find_map(|action| match action {
                QcsdAction::PrearmPacket { packet, slot, .. } if *packet == next => Some(*slot),
                _ => None,
            })
            .expect("next preview awaiting adapter");
        assert_ne!(current_slot, next_slot);
        assert_eq!(endpoints[0].prearmed_outgoing.len(), 1);
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 1);

        for _ in 0..2 {
            cancel_uncommitted_prearms_on_abort(
                &mut endpoints,
                &mut controller,
                &mut traces,
                started + Duration::from_millis(10),
            )
            .expect("reconcile transition previews");
        }
        assert!(endpoints[0].prearmed_outgoing.is_empty());
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        assert!(!controller.has_rolling_outgoing_prearm());
        assert!(
            controller
                .pending_slots()
                .contains(&(current_slot, current))
        );
        assert!(
            !controller
                .pending_slots()
                .iter()
                .any(|(slot, _)| *slot == next_slot)
        );

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            started + Duration::from_millis(10),
            Duration::from_millis(10),
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize committed current cell");
        traces
            .ensure_no_pending_slots()
            .expect("no unresolved slot");
        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert_eq!(events.matches("cancel_prearmed_packet").count(), 2);
        assert_eq!(events.matches("abort_cleanup_applied").count(), 1);
        assert_eq!(events.matches("abort_cleanup_before_adapter").count(), 1);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("RunAborted"));
        let recorded_slots: Vec<_> = schedule
            .lines()
            .skip(1)
            .map(|line| {
                line.split(',')
                    .nth(8)
                    .expect("schedule slot column")
                    .parse::<u64>()
                    .expect("numeric schedule slot")
            })
            .collect();
        assert_eq!(recorded_slots, [current_slot.0]);
        assert!(!recorded_slots.contains(&next_slot.0));
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected two-endpoint oracle verifies close reduction and replacement prearming"
    )]
    #[expect(
        clippy::similar_names,
        reason = "endpoint0 and endpoints name distinct fixtures and the runner collection under test"
    )]
    async fn input_produced_close_rearms_a_future_preview_on_the_surviving_endpoint() {
        let output = trace_output_dir("rolling-input-close-rearm");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let control_interval_us = 100_000;
        let packet =
            Packet::new(Duration::from_secs(10), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([packet]),
                exact_incoming_window: false,
            }),
        )
        .expect("controller");
        for endpoint in [QcsdEndpointId(0), QcsdEndpointId(1)] {
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: format!("https://endpoint{}.example", endpoint.0),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let preview = controller
            .drain_actions()
            .find(|action| {
                matches!(
                    action,
                    QcsdAction::PrearmPacket {
                        endpoint: QcsdEndpointId(0),
                        packet: observed,
                        ..
                    } if *observed == packet
                )
            })
            .expect("first endpoint preview");

        let (endpoint0, mut server0) = connected_runner_endpoint_with_server(
            &output,
            started,
            &clock,
            QcsdEndpointId(0),
            4_433,
            control_interval_us,
        );
        let (endpoint1, server1) = connected_runner_endpoint_with_server(
            &output,
            started,
            &clock,
            QcsdEndpointId(1),
            4_434,
            control_interval_us,
        );
        let mut endpoints = vec![endpoint0, endpoint1];
        for endpoint in &mut endpoints {
            drop(endpoint.client.qcsd_timestamped_observations());
        }
        let action_now = now();
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            action_now,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply first preview");
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 1);

        queue_peer_connection_close(&mut endpoints[0], &mut server0, now());
        drive_endpoint_output(
            1,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &clock,
            Some(action_now),
        )
        .await
        .expect("drive survivor before release");
        assert_eq!(
            controller.rolling_outgoing_prearm_endpoint(),
            Some(QcsdEndpointId(1))
        );
        assert!(endpoints[0].prearmed_outgoing.is_empty());
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        assert_eq!(endpoints[1].prearmed_outgoing.len(), 1);
        assert_eq!(endpoints[1].client.qcsd_pending_packet_targets(), 1);
        assert!(controller.pending_slots().is_empty());

        cancel_uncommitted_prearms_on_abort(&mut endpoints, &mut controller, &mut traces, now())
            .expect("clean transferred preview");
        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        let close_index = events.find("endpoint_closed").expect("close observation");
        let replacement_index = events[close_index..]
            .find("prearm_packet")
            .map(|index| close_index + index)
            .expect("replacement prearm action");
        assert!(close_index < replacement_index);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 1);
        drop(endpoints);
        drop(server0);
        drop(server1);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected two-endpoint oracle verifies exact close, replacement, and same-microstep output"
    )]
    #[expect(
        clippy::similar_names,
        reason = "endpoint0 and endpoints name distinct fixtures and the runner collection under test"
    )]
    async fn post_output_exact_close_commits_and_redrives_the_replacement_slot() {
        let output = trace_output_dir("rolling-post-output-close-redrive");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let control_interval_us = 5_000;
        let packet =
            Packet::new(Duration::from_micros(10), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingOneShot {
                event: Some(packet),
            }),
        )
        .expect("controller");
        for endpoint in [QcsdEndpointId(0), QcsdEndpointId(1)] {
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: format!("https://endpoint{}.example", endpoint.0),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let preview = controller
            .drain_actions()
            .find(|action| {
                matches!(
                    action,
                    QcsdAction::PrearmPacket {
                        endpoint: QcsdEndpointId(0),
                        packet: observed,
                        ..
                    } if *observed == packet
                )
            })
            .expect("initial preview");

        let (endpoint0, server0) = connected_runner_endpoint_with_server(
            &output,
            started,
            &clock,
            QcsdEndpointId(0),
            4_433,
            control_interval_us,
        );
        let (endpoint1, server1) = connected_runner_endpoint_with_server(
            &output,
            started,
            &clock,
            QcsdEndpointId(1),
            4_434,
            control_interval_us,
        );
        let mut endpoints = vec![endpoint0, endpoint1];
        for endpoint in &mut endpoints {
            drop(endpoint.client.qcsd_timestamped_observations());
        }
        endpoints[1].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply preview");

        let release_at = started + packet.timestamp();
        let before_release = release_at
            .checked_sub(Duration::from_nanos(1))
            .expect("release has a predecessor");
        endpoints[0]
            .client
            .close(before_release, 85, "close during the output step");
        let closed = endpoints[0]
            .client
            .qcsd_timestamped_observations()
            .into_iter()
            .find(|record| {
                matches!(
                    record.observation(),
                    QcsdObservation::EndpointClosed {
                        endpoint: QcsdEndpointId(0)
                    }
                )
            })
            .expect("transport close observation");
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        endpoints[0].test_observation_on_next_output = Some(closed);

        // The first output step is strictly before release.  Its observation
        // becomes globally visible at the post-output timestamp exactly on the
        // release, forcing the real `continue` branch to commit and redrive the
        // replacement target before returning an older None/Callback result.
        let mut times = VecDeque::from([
            before_release,
            before_release,
            release_at,
            release_at,
            release_at,
            release_at,
            release_at,
            release_at,
        ]);
        let mut monotonic_clock = || times.pop_front().unwrap_or(release_at);
        drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &clock,
            Some(started),
            &mut monotonic_clock,
        )
        .await
        .expect("post-output close commits and redrives the replacement");

        assert!(endpoints[0].prearmed_outgoing.is_empty());
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        assert!(endpoints[1].prearmed_outgoing.is_empty());
        assert!(endpoints[1].scheduled_outgoing.is_empty());
        assert!(controller.pending_slots().is_empty());
        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert!(events.contains("endpoint_closed"));
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("satisfied"));
        assert!(!schedule.contains("TimerLate"));
        assert!(!schedule.contains("DeadlineExpired"));
        drop(endpoints);
        drop(server0);
        drop(server1);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::similar_names,
        reason = "endpoint0 and endpoints name distinct fixtures and the runner collection under test"
    )]
    async fn legacy_output_drive_does_not_globally_drain_another_endpoint_close() {
        let output = trace_output_dir("legacy-barrier-isolation");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let (endpoint0, mut server0) = connected_runner_endpoint_with_server(
            &output,
            started,
            &clock,
            QcsdEndpointId(0),
            4_433,
            100_000,
        );
        let (endpoint1, server1) = connected_runner_endpoint_with_server(
            &output,
            started,
            &clock,
            QcsdEndpointId(1),
            4_434,
            100_000,
        );
        let mut endpoints = vec![endpoint0, endpoint1];
        for endpoint in &mut endpoints {
            drop(endpoint.client.qcsd_timestamped_observations());
        }
        let mut controller =
            QcsdController::new(QcsdConfig::default(), 0, None).expect("legacy controller");
        assert!(!rolling_output_lifecycle_active(&controller, &endpoints));
        queue_peer_connection_close(&mut endpoints[0], &mut server0, now());

        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        drive_endpoint_output(
            1,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &clock,
            Some(now()),
        )
        .await
        .expect("legacy endpoint output");
        let queued = endpoints[0].client.qcsd_timestamped_observations();
        assert!(queued.iter().any(|record| matches!(
            record.observation(),
            QcsdObservation::EndpointClosed {
                endpoint: QcsdEndpointId(0)
            }
        )));
        drop(traces);
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert!(!events.contains("endpoint_closed"));
        drop(endpoints);
        drop(server0);
        drop(server1);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn final_rolling_outcome_is_reduced_by_the_same_output_microstep() {
        let output = trace_output_dir("rolling-final-outcome-barrier");
        let started = test_fixture::now();
        let clock = QcsdObservationClock::new(started);
        let control_interval_us = 500_000;
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingOutcomeProbe {
                event: Some(packet),
                resolved: false,
            }),
        )
        .expect("controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://example.com".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("preview");
        let mut endpoints = vec![
            connected_runner_endpoint_with_server(
                &output,
                started,
                &clock,
                QcsdEndpointId(0),
                4_433,
                control_interval_us,
            )
            .0,
        ];
        endpoints[0].test_force_socket_handoff_success = true;
        drop(endpoints[0].client.qcsd_timestamped_observations());
        let action_now = started;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            action_now,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply preview");
        let release_at = started + packet.timestamp();
        let mut monotonic_clock = || release_at;
        let error = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &clock,
            Some(action_now),
            &mut monotonic_clock,
        )
        .await
        .expect_err("post-output barrier reduces the final outcome immediately");
        assert!(
            matches!(
                &error,
                Error::DefenseExecution(message)
                    if message == "synthetic final rolling outcome was reduced"
            ),
            "unexpected post-output reduction error: {error:?}"
        );
        assert!(controller.pending_slots().is_empty());
        assert!(endpoints[0].scheduled_outgoing.is_empty());
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("satisfied"));
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn missing_adapter_terminalizes_a_committed_prearm_once() {
        let output = trace_output_dir("committed-prearm-missing-adapter");
        let started = now();
        let packet =
            Packet::new(Duration::from_micros(10), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingOneShot {
                event: Some(packet),
            }),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(9);
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint,
                origin: "https://missing.example".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let prearm = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("preview");
        let QcsdAction::PrearmPacket { slot, .. } = prearm else {
            unreachable!();
        };
        assert!(controller.pending_slots().is_empty());

        controller
            .reconcile_due_rolling(Duration::from_micros(10))
            .expect("reconcile rolling preview");
        let commit = controller
            .drain_actions()
            .find(|action| {
                matches!(
                    action,
                    QcsdAction::CommitPrearmedPacket {
                        slot: observed,
                        ..
                    } if *observed == slot
                )
            })
            .expect("commit");
        assert_eq!(controller.pending_slots(), [(slot, packet)]);

        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut [],
            &mut controller,
            None,
            &mut traces,
            started + Duration::from_micros(10),
            Duration::from_micros(10),
            vec![commit],
        )
        .expect("missing committed endpoint is a terminal slot outcome");
        assert!(controller.pending_slots().is_empty());
        traces
            .ensure_no_pending_slots()
            .expect("terminal trace slot");
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("EndpointClosed"));
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn due_rolling_output_selection_ignores_legacy_and_future_targets() {
        let adapter_release = now();
        let scheduled = [
            vec![ScheduledOutgoing {
                slot: QcsdSlotId(1),
                packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).expect("packet"),
                not_before: adapter_release,
                deadline: adapter_release,
                rolling_prearmed: false,
            }],
            vec![ScheduledOutgoing {
                slot: QcsdSlotId(2),
                packet: Packet::new(Duration::from_micros(20), Direction::Outgoing, 1_200)
                    .expect("packet"),
                not_before: adapter_release + Duration::from_nanos(2),
                deadline: adapter_release,
                rolling_prearmed: true,
            }],
            vec![ScheduledOutgoing {
                slot: QcsdSlotId(4),
                packet: Packet::new(Duration::from_micros(10), Direction::Outgoing, 1_200)
                    .expect("packet"),
                not_before: adapter_release + Duration::from_nanos(4),
                deadline: adapter_release,
                rolling_prearmed: true,
            }],
            vec![ScheduledOutgoing {
                slot: QcsdSlotId(3),
                packet: Packet::new(Duration::from_micros(10), Direction::Outgoing, 1_200)
                    .expect("packet"),
                not_before: adapter_release + Duration::from_nanos(3),
                deadline: adapter_release,
                rolling_prearmed: true,
            }],
        ];
        let candidates = || {
            scheduled.iter().enumerate().flat_map(|(index, endpoint)| {
                endpoint.iter().map(move |scheduled| (index, scheduled))
            })
        };

        assert_eq!(
            due_rolling_output_target(candidates(), Duration::from_micros(9)),
            None
        );
        assert_eq!(
            due_rolling_output_target(candidates(), Duration::from_micros(10)),
            Some((3, adapter_release + Duration::from_nanos(3)))
        );
        assert_eq!(
            due_rolling_output_target(candidates(), Duration::from_micros(20)),
            Some((3, adapter_release + Duration::from_nanos(3)))
        );
    }

    #[expect(
        clippy::cognitive_complexity,
        clippy::future_not_send,
        clippy::too_many_lines,
        reason = "one connected runner oracle preserves the exact prearm, paired-credit, handoff, and trace lifecycle"
    )]
    async fn assert_fractional_adapter_release_redrive(adapter_skew_ns: u64) {
        assert!((1..=999).contains(&adapter_skew_ns));
        let output = trace_output_dir(&format!(
            "fractional-adapter-release-redrive-{adapter_skew_ns}"
        ));
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let outgoing =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let incoming =
            Packet::new(Duration::from_millis(20), Direction::Incoming, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([outgoing, incoming]),
                exact_incoming_window: false,
            }),
        )
        .expect("same-tick outgoing/incoming controller");

        let (mut endpoint, server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            5_000,
        );
        // Leave a real response stream open, but drain every request/critical
        // STREAM byte before the defense starts. The only non-target output
        // staged at the nominal tick below is therefore the scheduled
        // MAX_STREAM_DATA control for the simultaneous incoming opportunity.
        endpoint.client.qcsd_enable_send_shaping(false);
        let request_url = http::Uri::from_static("https://127.0.0.1:4433/controlled");
        let stream = endpoint
            .client
            .fetch(
                started,
                "GET",
                &request_url,
                &[],
                neqo_http3::Priority::default(),
            )
            .expect("create controlled application request");
        endpoint
            .client
            .register_qcsd_stream(stream, QcsdRequestRole::Application, Some(10_000))
            .expect("register controlled application response");
        let request_stream_bytes = endpoint
            .client
            .qcsd_request_stream_bytes(stream)
            .expect("measure controlled request stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close controlled request send side");
        endpoint.application_send_streams.insert(stream);
        let mut stream_record = application(None, false);
        stream_record.url = request_url.to_string();
        stream_record.request_stream_bytes = request_stream_bytes;
        endpoint.streams.insert(stream, stream_record);
        let mut server = server;
        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
        assert!(
            !endpoint.client.qcsd_has_pending_stream_send(),
            "request and HTTP/3 critical STREAM output are preflushed"
        );
        endpoint.client.qcsd_enable_send_shaping(true);
        drop(endpoint.client.qcsd_timestamped_observations());

        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: endpoint.id,
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: endpoint.id,
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        let mut endpoints = vec![endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");

        let release_at = started + outgoing.timestamp();
        let remaining_before_tick_ns = 1_000 - adapter_skew_ns;
        let dispatch_at = release_at
            .checked_sub(Duration::from_nanos(remaining_before_tick_ns))
            .expect("release has the fractional dispatch predecessor");
        let dispatch_elapsed = dispatch_at.saturating_duration_since(started);
        controller.poll(dispatch_elapsed);
        let preview_actions: Vec<_> = controller.drain_actions().collect();
        assert!(preview_actions.iter().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                stream: configured,
                ..
            } if configured.0 == stream.as_u64()
        )));
        assert!(preview_actions.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket { packet, .. } if *packet == outgoing
        )));
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            dispatch_at,
            dispatch_elapsed,
            preview_actions,
        )
        .expect("apply fractionally delayed rolling preview");
        let adapter_release = release_at + Duration::from_nanos(adapter_skew_ns);
        assert_eq!(
            endpoints[0].prearmed_outgoing[0].not_before,
            adapter_release
        );

        // This deterministic output seam would be consumed immediately if the
        // runner drove transport with the stale nominal tick. It must remain
        // untouched while the committed target waits for its exact adapter
        // release.
        endpoints[0].test_observation_on_next_output =
            Some(observation_clock.record(QcsdObservation::EgressBacklog { pending: true }));
        let mut nominal_clock = || release_at;
        let wakeup = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut nominal_clock,
        )
        .await
        .expect("nominal tick commits without driving transport");
        assert_eq!(wakeup, Some(adapter_release));
        assert!(endpoints[0].test_observation_on_next_output.is_some());
        assert!(endpoints[0].test_output_observations.is_empty());
        assert!(endpoints[0].prearmed_outgoing.is_empty());
        assert_eq!(endpoints[0].scheduled_outgoing.len(), 1);
        let outgoing_slot = endpoints[0].scheduled_outgoing[0].slot;
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 1);
        let pending_receive = endpoints[0].client.qcsd_pending_receive_action_identities();
        assert_eq!(pending_receive.len(), 1);
        let incoming_slot = match pending_receive[0] {
            QcsdReceiveActionIdentity::Scheduled {
                endpoint,
                stream: observed_stream,
                slot,
                ..
            } => {
                assert_eq!(endpoint, endpoints[0].id);
                assert_eq!(observed_stream.0, stream.as_u64());
                slot
            }
            other @ QcsdReceiveActionIdentity::ParserLease { .. } => {
                panic!("expected scheduled same-tick receive control, got {other:?}")
            }
        };
        assert!(
            controller
                .pending_slots()
                .contains(&(incoming_slot, incoming))
        );
        assert_eq!(controller.pending_slots().len(), 2);

        let just_before_adapter = adapter_release
            .checked_sub(Duration::from_nanos(1))
            .expect("adapter release has a predecessor");
        let mut pre_adapter_clock = || just_before_adapter;
        let wakeup = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut pre_adapter_clock,
        )
        .await
        .expect("runner remains idle immediately before adapter release");
        assert_eq!(wakeup, Some(adapter_release));
        assert!(endpoints[0].test_observation_on_next_output.is_some());
        assert!(endpoints[0].test_output_observations.is_empty());
        assert_eq!(
            endpoints[0].client.qcsd_pending_receive_action_identities(),
            pending_receive
        );

        endpoints[0].test_observation_on_next_output = None;
        let mut adapter_clock = || adapter_release;
        let _wakeup = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut adapter_clock,
        )
        .await
        .expect("exact adapter release realizes the committed target");
        assert!(endpoints[0].scheduled_outgoing.is_empty());
        assert_eq!(endpoints[0].client.qcsd_pending_packet_targets(), 0);
        assert!(
            endpoints[0]
                .client
                .qcsd_pending_receive_action_identities()
                .is_empty(),
            "same-tick receive control is encoded only inside the exact target"
        );
        assert!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints).is_empty(),
            "same-endpoint credit composed into the exact cell is never selected for a duplicate follow-up drive"
        );
        assert_eq!(controller.pending_slots(), [(incoming_slot, incoming)]);

        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let mut schedule_lines = schedule.lines();
        let schedule_header: Vec<_> = schedule_lines
            .next()
            .expect("schedule header")
            .split(',')
            .collect();
        let schedule_rows: Vec<_> = schedule_lines.collect();
        assert_eq!(
            schedule_rows.len(),
            1,
            "one terminal row for the exact cell"
        );
        let schedule_fields: Vec<_> = schedule_rows[0].split(',').collect();
        assert_eq!(
            schedule_fields.len(),
            schedule_header.len(),
            "complete typed schedule row"
        );
        let schedule_field = |name: &str| {
            let index = schedule_header
                .iter()
                .position(|column| *column == name)
                .unwrap_or_else(|| panic!("missing schedule column {name}"));
            schedule_fields[index]
        };
        assert_eq!(schedule_field("direction"), "outgoing");
        assert_eq!(schedule_field("size"), "1200");
        assert_eq!(schedule_field("satisfaction"), "satisfied");
        assert_eq!(schedule_field("miss_reason"), "");
        assert_eq!(
            schedule_field("slot_id"),
            outgoing_slot.0.to_string(),
            "the committed outgoing identity terminates exactly once"
        );
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        let mut lines = packets.lines();
        let header: Vec<_> = lines.next().expect("packet header").split(',').collect();
        let packet_rows: Vec<_> = lines.collect();
        assert_eq!(packet_rows.len(), 1, "no early or catch-up datagram");
        let fields: Vec<_> = packet_rows[0].split(',').collect();
        assert_eq!(fields.len(), header.len(), "complete typed packet row");
        let field = |name: &str| {
            let index = header
                .iter()
                .position(|column| *column == name)
                .unwrap_or_else(|| panic!("missing packet column {name}"));
            fields[index]
        };
        assert_eq!(field("observed_udp_length"), "1200");
        assert_eq!(field("scheduled_target"), "1200");
        assert_eq!(field("satisfaction"), "satisfied");
        assert_eq!(field("send_policy"), "exact");
        assert!(
            field("defense_control_bytes")
                .parse::<u16>()
                .expect("defense-control composition bytes")
                > 0,
            "the exact cell carries the simultaneous receive-limit control"
        );
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn fractional_rolling_release_waits_for_the_exact_adapter_boundary() {
        for adapter_skew_ns in [1, 500, 999] {
            assert_fractional_adapter_release_redrive(adapter_skew_ns).await;
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the regression keeps the exact-release guard, transport output, and trace assertions in one causally ordered scenario"
    )]
    async fn exact_release_dispatch_stops_after_its_guard_bounded_datagram() {
        let output = trace_output_dir("exact-release-one-datagram");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let outgoing =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let control_interval_us = 500_000;
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingOneShot {
                event: Some(outgoing),
            }),
        )
        .expect("outgoing controller");
        let (endpoint, server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            control_interval_us,
        );
        let mut endpoints = vec![endpoint];
        drop(endpoints[0].client.qcsd_timestamped_observations());
        endpoints[0].test_force_socket_handoff_success = true;

        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: endpoints[0].id,
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let preview_actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            preview_actions
                .iter()
                .any(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
        );
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            preview_actions,
        )
        .expect("apply outgoing preview");

        let release = endpoints[0].prearmed_outgoing[0].not_before;
        tokio::time::sleep_until(tokio::time::Instant::from_std(release)).await;
        controller
            .reconcile_due_rolling(outgoing.timestamp())
            .expect("commit due preview");
        let commit_actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            commit_actions
                .iter()
                .any(|action| matches!(action, QcsdAction::CommitPrearmedPacket { .. }))
        );
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            release,
            outgoing.timestamp(),
            commit_actions,
        )
        .expect("apply outgoing commit");
        let scheduled = endpoints[0].scheduled_outgoing[0];
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: endpoints[0].id,
            slot: scheduled.slot,
            packet: scheduled.packet,
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: scheduled.not_before,
            guard_at: scheduled.not_before,
            active_wait_at: scheduled.not_before,
            release: scheduled.not_before,
            deadline: scheduled.deadline,
        };
        endpoints[0].test_output_drives.extend([
            TestOutputDrive::ProductionPath,
            TestOutputDrive::ErrorAt(guard.deadline),
        ]);

        let mut metrics = RunnerWakeupMetrics::new();
        dispatch_buflo_exact_release(
            &guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut metrics,
        )
        .await
        .expect("exact release emits one bounded datagram");
        assert_eq!(
            endpoints[0].test_output_drives,
            VecDeque::from([TestOutputDrive::ErrorAt(guard.deadline)]),
            "the exact dispatcher never enters a second unbounded output microstep"
        );
        assert!(controller.pending_slots().is_empty());
        assert!(endpoints[0].scheduled_outgoing.is_empty());

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 2, "one exact wire datagram");
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2, "one terminal schedule row");
        assert!(schedule.contains("satisfied"));

        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected two-origin oracle spans paired controller ordering, two socket handoffs, deferred reduction, and trace evidence"
    )]
    async fn exact_release_dispatch_orders_cross_endpoint_pair_inside_one_window() {
        let output = trace_output_dir("exact-release-cross-endpoint-pair");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut credit_endpoint, mut credit_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            5_000,
        );
        let (outgoing_endpoint, outgoing_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(1),
            4_434,
            5_000,
        );
        credit_endpoint.client.qcsd_enable_send_shaping(false);
        let stream = open_controlled_runner_stream(
            &mut credit_endpoint,
            &mut credit_server,
            started,
            4_433,
            10_000,
        );
        assert!(!credit_endpoint.client.qcsd_has_pending_stream_send());
        credit_endpoint.client.qcsd_enable_send_shaping(true);
        drop(credit_endpoint.client.qcsd_timestamped_observations());

        let tick = Duration::from_millis(20);
        let outgoing = Packet::new(tick, Direction::Outgoing, 1_200).expect("outgoing");
        let incoming = Packet::new(tick, Direction::Incoming, 1_200).expect("incoming");
        let next = Packet::new(tick * 2, Direction::Outgoing, 1_200).expect("next outgoing");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([outgoing, incoming, next]),
                exact_incoming_window: true,
            }),
        )
        .expect("paired rolling controller");
        // Independent direction cursors start from the first eligible origin.
        // Endpoint 1 is ready first for outgoing selection, while only the
        // endpoint-0 application stream is eligible for incoming credit.
        for endpoint in [QcsdEndpointId(1), QcsdEndpointId(0)] {
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: format!("https://127.0.0.1:{}", 4_433_u64 + endpoint.0),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
        }
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let setup_actions: Vec<_> = controller.drain_actions().collect();
        assert!(setup_actions.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket {
                endpoint: QcsdEndpointId(1),
                packet,
                ..
            } if *packet == outgoing
        )));

        let defense_start = now();
        let mut endpoints = vec![credit_endpoint, outgoing_endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        endpoints[1].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, defense_start).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            defense_start,
            Duration::ZERO,
            setup_actions,
        )
        .expect("apply paired setup and outgoing prearm");
        assert_eq!(endpoints[1].prearmed_outgoing.len(), 1);
        let release = endpoints[1].prearmed_outgoing[0].not_before;

        controller
            .reconcile_due_rolling(tick)
            .expect("commit paired tick");
        let tick_actions: Vec<_> = controller.drain_actions().collect();
        let outgoing_action_index = tick_actions
            .iter()
            .position(|action| {
                matches!(
                    action,
                    QcsdAction::CommitPrearmedPacket {
                        endpoint: QcsdEndpointId(1),
                        packet,
                        ..
                    } if *packet == outgoing
                )
            })
            .expect("outgoing commit");
        let incoming_action_index = tick_actions
            .iter()
            .position(|action| {
                matches!(
                    action,
                    QcsdAction::IncreaseReceiveLimit {
                        endpoint: QcsdEndpointId(0),
                        packet,
                        ..
                    } if *packet == incoming
                )
            })
            .expect("cross-endpoint incoming opportunity");
        assert!(
            outgoing_action_index < incoming_action_index,
            "controller action order remains outgoing before incoming"
        );
        assert!(tick_actions.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket { packet, .. } if *packet == next
        )));
        let incoming_slot = tick_actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. } => Some(*slot),
                _ => None,
            })
            .expect("incoming slot");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            release,
            tick,
            tick_actions,
        )
        .expect("apply outgoing-first paired tick");
        let scheduled = endpoints[1]
            .scheduled_outgoing
            .front()
            .copied()
            .expect("committed outgoing owner");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 1,
            endpoint: QcsdEndpointId(1),
            slot: scheduled.slot,
            packet: scheduled.packet,
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: scheduled.not_before,
            guard_at: scheduled.not_before,
            active_wait_at: scheduled.not_before,
            release: scheduled.not_before,
            deadline: scheduled.deadline,
        };
        assert_eq!(guard.release, release);
        assert_eq!(guard.deadline, release + Duration::from_millis(5));

        tokio::time::sleep_until(tokio::time::Instant::from_std(release)).await;
        let mut metrics = RunnerWakeupMetrics::new();
        dispatch_buflo_exact_release(
            &guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(defense_start),
            &mut metrics,
        )
        .await
        .expect("outgoing owner then incoming owner fit the same exact window");
        assert_eq!(metrics.buflo_exact_incoming_retry_drives, 1);
        assert_eq!(metrics.buflo_exact_incoming_retry_resolutions, 1);
        assert_eq!(metrics.wait_returns, 0);
        assert_eq!(metrics.timer_wakeups, 0);
        assert!(controller.incoming_slot_is_locally_realized(incoming_slot));
        assert!(!controller.has_due_rolling_reconciliation());
        assert!(controller.drain_actions().next().is_none());
        assert!(endpoints[1].scheduled_outgoing.is_empty());
        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| endpoint.prearmed_outgoing.len())
                .sum::<usize>(),
            1,
            "the next outgoing opportunity remains prearmed, not sent"
        );

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            now(),
            now().saturating_duration_since(defense_start),
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize unconsumed incoming credit");
        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        let mut packet_lines = packets.lines();
        let header: Vec<_> = packet_lines
            .next()
            .expect("packet header")
            .split(',')
            .collect();
        let rows: Vec<Vec<_>> = packet_lines.map(|line| line.split(',').collect()).collect();
        assert_eq!(rows.len(), 2, "one outgoing cell and one credit datagram");
        let column = |name: &str| {
            header
                .iter()
                .position(|column| *column == name)
                .unwrap_or_else(|| panic!("missing packet column {name}"))
        };
        assert_eq!(rows[0][column("connection")], "1");
        assert_eq!(rows[0][column("scheduled_target")], "1200");
        assert_eq!(rows[1][column("connection")], "0");
        assert_eq!(rows[1][column("satisfaction")], "unshaped");
        let release_us = duration_as_trace_micros(release.saturating_duration_since(defense_start));
        let deadline_us =
            duration_as_trace_micros(guard.deadline.saturating_duration_since(defense_start));
        for row in &rows {
            let sent_us = row[column("monotonic_us")]
                .parse::<u64>()
                .expect("packet monotonic time");
            assert!(sent_us >= release_us && sent_us < deadline_us);
        }

        drop(endpoints);
        drop(credit_server);
        drop(outgoing_server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn exact_pair_direct_incoming_handoff_uses_remaining_margin_before_reduction() {
        let output = trace_output_dir("exact-pair-direct-margin");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoints, server, mut controller, incoming_slot, mut traces) =
            staged_exact_incoming_credit_fixture(&output, started, &observation_clock);
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0]
        );
        endpoints[0]
            .test_output_observations
            .push(observation_clock.record(QcsdObservation::EgressBacklog { pending: true }));

        let defense_start = now();
        let deadline = defense_start + Duration::from_millis(5);
        let mut clock_samples = VecDeque::from([
            deadline
                .checked_sub(Duration::from_micros(750))
                .expect("deadline has 750 microseconds of remaining margin"),
            deadline
                .checked_sub(Duration::from_micros(500))
                .expect("deadline has 500 microseconds of remaining margin"),
            deadline
                .checked_sub(Duration::from_micros(250))
                .expect("deadline has 250 microseconds of remaining margin"),
        ]);
        let mut monotonic_clock = || {
            clock_samples
                .pop_front()
                .expect("direct owner handoff uses exactly three clock samples")
        };
        let callback = drive_buflo_exact_incoming_output_with_clock(
            0,
            QcsdEndpointId(0),
            &mut endpoints,
            &mut controller,
            &mut traces,
            &observation_clock,
            defense_start,
            deadline,
            &mut monotonic_clock,
        )
        .await
        .expect("direct handoff fits in the unchanged remaining adapter window");

        assert_eq!(callback, None);
        assert!(clock_samples.is_empty());
        assert!(buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints).is_empty());
        assert_eq!(
            endpoints[0].test_output_observations.len(),
            1,
            "the direct owner turn performs no intervening global rolling reduction"
        );
        controller.flush_defense_observations();
        ensure_defense_realizable(&controller).expect("exact incoming datagram remains valid");
        assert!(controller.incoming_slot_is_locally_realized(incoming_slot));

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 2, "one direct credit datagram");
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn exact_pair_direct_incoming_handoff_rejects_cross_endpoint_identity() {
        let output = trace_output_dir("exact-pair-owner-identity");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoints, server, mut controller, _incoming_slot, mut traces) =
            staged_exact_incoming_credit_fixture(&output, started, &observation_clock);
        let defense_start = now();
        let deadline = defense_start + Duration::from_millis(5);
        let mut clock_calls = 0_u8;
        let mut monotonic_clock = || {
            clock_calls = clock_calls.saturating_add(1);
            defense_start
        };

        let error = drive_buflo_exact_incoming_output_with_clock(
            0,
            QcsdEndpointId(1),
            &mut endpoints,
            &mut controller,
            &mut traces,
            &observation_clock,
            defense_start,
            deadline,
            &mut monotonic_clock,
        )
        .await
        .expect_err("a captured owner cannot borrow another endpoint index");
        assert!(matches!(
            error,
            Error::SlotInvariant(message)
                if message.contains("owner 1 resolved to endpoint 0 at index 0")
        ));
        assert_eq!(
            clock_calls, 0,
            "identity rejection precedes transport and time"
        );
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0],
            "the true owner retains its staged credit"
        );

        let committed = ScheduledOutgoing {
            slot: QcsdSlotId(700),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("committed outgoing"),
            not_before: defense_start,
            deadline,
            rolling_prearmed: true,
        };
        endpoints[0].scheduled_outgoing.push_back(committed);
        let mut monotonic_clock = || defense_start;
        let error = drive_buflo_exact_incoming_output_with_clock(
            0,
            QcsdEndpointId(0),
            &mut endpoints,
            &mut controller,
            &mut traces,
            &observation_clock,
            defense_start,
            deadline,
            &mut monotonic_clock,
        )
        .await
        .expect_err("a committed outgoing target retains output priority");
        assert!(matches!(
            error,
            Error::SlotInvariant(message)
                if message.contains("retained committed outgoing slot 700")
        ));
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0],
            "outgoing-priority rejection also leaves the incoming identity staged"
        );
        _ = endpoints[0].scheduled_outgoing.pop_back();

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 1, "identity failure sends nothing");
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn exact_pair_direct_incoming_handoff_keeps_half_open_deadline() {
        let output = trace_output_dir("exact-pair-direct-deadline");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoints, server, mut controller, _incoming_slot, mut traces) =
            staged_exact_incoming_credit_fixture(&output, started, &observation_clock);
        let defense_start = now();
        let deadline = defense_start + Duration::from_millis(5);
        let mut monotonic_clock = || deadline;

        let error = drive_buflo_exact_incoming_output_with_clock(
            0,
            QcsdEndpointId(0),
            &mut endpoints,
            &mut controller,
            &mut traces,
            &observation_clock,
            defense_start,
            deadline,
            &mut monotonic_clock,
        )
        .await
        .expect_err("the unchanged exclusive deadline rejects entry at its boundary");
        assert!(matches!(
            error,
            Error::AdapterDeadlinePreHandoff {
                attempted_at,
                deadline: observed_deadline,
            } if attempted_at == deadline && observed_deadline == deadline
        ));
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0],
            "deadline rejection leaves the identity for typed outer reconciliation"
        );

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 1, "deadline failure sends nothing");
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected two-endpoint oracle proves selective post-handoff credit output"
    )]
    async fn exact_handoff_drives_only_the_cross_endpoint_with_unadvertised_credit() {
        let output = trace_output_dir("cross-endpoint-post-handoff-credit");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut credit_endpoint, mut credit_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            5_000,
        );
        let (outgoing_endpoint, outgoing_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(1),
            4_434,
            5_000,
        );

        credit_endpoint.client.qcsd_enable_send_shaping(false);
        let request_url = http::Uri::from_static("https://127.0.0.1:4433/controlled");
        let stream = credit_endpoint
            .client
            .fetch(
                started,
                "GET",
                &request_url,
                &[],
                neqo_http3::Priority::default(),
            )
            .expect("create controlled request stream");
        credit_endpoint
            .client
            .register_qcsd_stream(stream, QcsdRequestRole::Application, Some(10_000))
            .expect("register controlled response stream");
        credit_endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close request send side");
        test_fixture::exchange_packets(
            &mut credit_endpoint.client,
            &mut credit_server,
            false,
            None,
        );
        assert!(!credit_endpoint.client.qcsd_has_pending_stream_send());
        credit_endpoint.client.qcsd_enable_send_shaping(true);
        drop(credit_endpoint.client.qcsd_timestamped_observations());

        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 50_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: false,
            }),
        )
        .expect("incoming controller");
        for endpoint in [QcsdEndpointId(0), QcsdEndpointId(1)] {
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: format!("https://127.0.0.1:{}", 4_433_u64 + endpoint.0),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
        }
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let incoming_slot = actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. } => Some(*slot),
                _ => None,
            })
            .expect("scheduled incoming slot");
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit {
                endpoint: QcsdEndpointId(0),
                ..
            }
        )));

        let mut endpoints = vec![credit_endpoint, outgoing_endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        endpoints[1].test_observation_on_next_output =
            Some(observation_clock.record(QcsdObservation::EgressBacklog { pending: true }));
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply cross-endpoint credit");
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0]
        );
        endpoints[0]
            .test_output_drives
            .push_back(TestOutputDrive::Callback(Duration::from_millis(2)));
        let cs_buflo = DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
            parameters: "test-only-cs-buflo-parameters.json".into(),
        });
        let retry_defense_start = now() + Duration::from_secs(1);
        let retry_current = now();
        let mut attempted = BTreeSet::new();
        let inventory = cs_exact_incoming_retry_inventory(
            &cs_buflo,
            &endpoints,
            &controller,
            Some(retry_defense_start),
            retry_current,
            &mut attempted,
        )
        .expect("bind exact incoming retry to its transport identity");
        assert_eq!(inventory.retries.len(), 3);
        assert!(inventory.earliest_expired_deadline.is_none());
        assert!(inventory.retries.iter().all(|retry| {
            retry.endpoint_index == 0
                && retry.endpoint == QcsdEndpointId(0)
                && retry.slot == incoming_slot
                && retry.target == retry_defense_start
        }));
        attempted.insert((
            QcsdEndpointId(0),
            incoming_slot,
            CsExactIncomingRetryPhase::Quarter,
        ));
        assert_eq!(
            cs_exact_incoming_retry_inventory(
                &cs_buflo,
                &endpoints,
                &controller,
                Some(retry_defense_start),
                retry_current,
                &mut attempted,
            )
            .expect("retain only unattempted finite phases")
            .retries
            .len(),
            2
        );

        let release = now();
        let outgoing =
            Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).expect("outgoing guard");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 1,
            endpoint: QcsdEndpointId(1),
            slot: QcsdSlotId(999),
            packet: outgoing,
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline: release + Duration::from_millis(50),
        };
        let stale_guard = BufloExactReleaseGuard {
            packet: Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200)
                .expect("later outgoing guard"),
            ..guard
        };
        assert!(matches!(
            buflo_exact_incoming_identities(
                &stale_guard,
                &endpoints,
                &controller,
                release,
                None,
            ),
            Err(Error::SlotInvariant(message))
                if message.contains("attempted to borrow")
        ));
        let mut runner_wakeup_metrics = RunnerWakeupMetrics::new();
        drive_buflo_unadvertised_scheduled_receive_credit(
            &guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            release,
            &mut runner_wakeup_metrics,
        )
        .await
        .expect("cross-endpoint receive control drive");
        assert!(buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints).is_empty());
        assert!(controller.incoming_slot_is_locally_realized(incoming_slot));
        assert_eq!(runner_wakeup_metrics.buflo_exact_incoming_retry_drives, 2);
        assert_eq!(
            runner_wakeup_metrics.buflo_exact_incoming_retry_resolutions,
            1
        );
        assert!(endpoints[0].test_output_drives.is_empty());
        assert_eq!(runner_wakeup_metrics.wait_returns, 1);
        assert_eq!(runner_wakeup_metrics.timer_wakeups, 1);
        assert!(
            cs_exact_incoming_retry_inventory(
                &cs_buflo,
                &endpoints,
                &controller,
                Some(retry_defense_start),
                retry_current,
                &mut attempted,
            )
            .expect("retire retry state after transport encodes the identity")
            .retries
            .is_empty()
        );
        assert!(attempted.is_empty());
        assert!(
            endpoints[1].test_observation_on_next_output.is_some(),
            "an unrelated endpoint receives no speculative output turn"
        );

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            now(),
            now().saturating_duration_since(started),
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize unconsumed credit");
        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(
            packets.lines().count(),
            2,
            "one callback retry emits exactly one receive-credit datagram"
        );
        drop(endpoints);
        drop(credit_server);
        drop(outgoing_server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the two-origin retry regression proves independent callback and slot ownership"
    )]
    async fn exact_handoff_fans_out_distinct_owner_callbacks_without_cross_borrowing() {
        let output = trace_output_dir("multi-owner-post-handoff-credit");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (first, first_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            50_000,
        );
        let (second, second_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(1),
            4_434,
            50_000,
        );
        let mut endpoints = vec![first, second];
        let mut servers = vec![first_server, second_server];
        let mut streams = Vec::new();
        for (index, (endpoint, server)) in endpoints.iter_mut().zip(&mut servers).enumerate() {
            endpoint.client.qcsd_enable_send_shaping(false);
            let request_url: http::Uri = format!(
                "https://127.0.0.1:{}/controlled",
                4_433_u64 + u64::try_from(index).expect("endpoint index")
            )
            .parse()
            .expect("controlled request URI");
            let stream = endpoint
                .client
                .fetch(
                    started,
                    "GET",
                    &request_url,
                    &[],
                    neqo_http3::Priority::default(),
                )
                .expect("create controlled request stream");
            endpoint
                .client
                .register_qcsd_stream(stream, QcsdRequestRole::Application, Some(10_000))
                .expect("register controlled response stream");
            endpoint
                .client
                .stream_close_send(stream, started)
                .expect("close request send side");
            test_fixture::exchange_packets(&mut endpoint.client, server, false, None);
            assert!(!endpoint.client.qcsd_has_pending_stream_send());
            endpoint.client.qcsd_enable_send_shaping(true);
            drop(endpoint.client.qcsd_timestamped_observations());
            streams.push(stream);
        }

        let first_incoming =
            Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("first incoming");
        let second_incoming =
            Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("second incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 50_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([first_incoming, second_incoming]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        for (index, stream) in streams.into_iter().enumerate() {
            let endpoint = QcsdEndpointId(u64::try_from(index).expect("endpoint index"));
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: format!(
                        "https://127.0.0.1:{}",
                        4_433_u64 + u64::try_from(index).expect("endpoint index")
                    ),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream: QcsdStreamId(stream.as_u64()),
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(10_000),
                },
                Duration::ZERO,
            );
        }
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let owners: BTreeSet<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { endpoint, .. } => Some(*endpoint),
                _ => None,
            })
            .collect();
        assert_eq!(
            owners,
            BTreeSet::from([QcsdEndpointId(0), QcsdEndpointId(1)]),
            "the two credits have distinct physical owners"
        );

        for endpoint in &mut endpoints {
            endpoint.test_force_socket_handoff_success = true;
        }
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply multi-owner receive credits");
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0, 1]
        );

        let release = now();
        let first_callback = release + Duration::from_millis(1);
        let second_callback = release + Duration::from_millis(2);
        endpoints[0]
            .test_output_drives
            .push_back(TestOutputDrive::CallbackAt(first_callback));
        endpoints[1].test_output_drives.extend([
            TestOutputDrive::CallbackAt(second_callback),
            TestOutputDrive::CallbackAt(second_callback),
        ]);
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline: release + Duration::from_millis(50),
        };
        let mut runner_wakeup_metrics = RunnerWakeupMetrics::new();
        drive_buflo_unadvertised_scheduled_receive_credit(
            &guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            release,
            &mut runner_wakeup_metrics,
        )
        .await
        .expect("both owner-bound receive credits resolve");

        assert!(buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints).is_empty());
        assert_eq!(runner_wakeup_metrics.buflo_exact_incoming_retry_drives, 5);
        assert_eq!(
            runner_wakeup_metrics.buflo_exact_incoming_retry_resolutions,
            2
        );
        assert_eq!(runner_wakeup_metrics.wait_returns, 2);
        assert!(
            endpoints
                .iter()
                .all(|endpoint| endpoint.test_output_drives.is_empty())
        );

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(
            packets.lines().count(),
            3,
            "one physical credit datagram is emitted by each owner"
        );
        drop(endpoints);
        drop(servers);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the two-origin partial-expiry oracle binds one logical slot, two adapter children, and one null-attributed terminal row"
    )]
    async fn exact_handoff_same_slot_partial_fanout_expires_once_without_false_endpoint() {
        let output = trace_output_dir("same-slot-partial-fanout-expiry");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut first, mut first_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            50_000,
        );
        let (mut second, mut second_server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(1),
            4_434,
            50_000,
        );
        let first_stream =
            open_controlled_runner_stream(&mut first, &mut first_server, started, 4_433, 616);
        let second_stream =
            open_controlled_runner_stream(&mut second, &mut second_server, started, 4_434, 616);

        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 50_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        for (endpoint, stream, port) in [
            (QcsdEndpointId(0), first_stream, 4_433),
            (QcsdEndpointId(1), second_stream, 4_434),
        ] {
            controller.observe(
                QcsdObservation::EndpointReady {
                    endpoint,
                    origin: format!("https://127.0.0.1:{port}"),
                    max_udp_payload_size: 1_200,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream: QcsdStreamId(stream.as_u64()),
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(616),
                },
                Duration::ZERO,
            );
        }
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let credits: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    slot,
                    ..
                } => Some((*endpoint, *stream, *slot)),
                _ => None,
            })
            .collect();
        assert_eq!(credits.len(), 2, "one 1,200-byte slot must split twice");
        assert_eq!(credits[0].2, credits[1].2, "both children share one slot");
        assert_eq!(
            credits
                .iter()
                .map(|credit| credit.0)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([QcsdEndpointId(0), QcsdEndpointId(1)])
        );
        let incoming_slot = credits[0].2;

        let mut endpoints = vec![first, second];
        endpoints[0].test_force_socket_handoff_success = true;
        endpoints[1].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply split receive credit");

        let release = now();
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline: release + Duration::from_millis(50),
        };
        let mut captured =
            buflo_exact_incoming_identities(&guard, &endpoints, &controller, release, None)
                .expect("capture both physical children");
        assert_eq!(captured.len(), 2);

        for _ in 0..4 {
            if !captured.iter().any(|candidate| {
                candidate.endpoint == QcsdEndpointId(0)
                    && buflo_exact_incoming_identity_is_pending(&endpoints, candidate)
            }) {
                break;
            }
            drive_endpoint_output_until(
                0,
                &mut endpoints,
                &mut controller,
                None,
                &mut traces,
                &observation_clock,
                Some(release),
                Some(OutputWorkBoundary::new(guard.deadline, guard.deadline)),
                Some(guard.deadline),
                Some(guard.deadline),
                OutputDriveCardinality::OneDatagram,
            )
            .await
            .expect("first child advertisement");
        }
        assert!(captured.iter().all(|candidate| {
            (candidate.endpoint != QcsdEndpointId(0))
                || !buflo_exact_incoming_identity_is_pending(&endpoints, candidate)
        }));
        assert!(captured.iter().any(|candidate| {
            candidate.endpoint == QcsdEndpointId(1)
                && buflo_exact_incoming_identity_is_pending(&endpoints, candidate)
        }));
        assert!(!controller.incoming_slot_is_locally_realized(incoming_slot));

        let error = expire_buflo_exact_incoming_credit(
            &guard,
            &mut captured,
            &BTreeSet::new(),
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            release,
            guard.deadline,
        )
        .expect("partial fan-out receives typed expiry");
        assert!(matches!(error, Error::DefenseExecution(_)));
        assert_eq!(
            controller.terminal_slot_resolution_at(incoming_slot),
            Some(Duration::from_millis(50))
        );

        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let mut lines = schedule.lines();
        let header: Vec<_> = lines.next().expect("schedule header").split(',').collect();
        let rows: Vec<Vec<_>> = lines.map(|line| line.split(',').collect()).collect();
        assert_eq!(rows.len(), 1, "one logical slot has one terminal row");
        let column = |name: &str| {
            header
                .iter()
                .position(|column| *column == name)
                .unwrap_or_else(|| panic!("missing schedule column {name}"))
        };
        assert_eq!(rows[0][column("slot_id")], incoming_slot.0.to_string());
        assert_eq!(rows[0][column("miss_reason")], "DeadlineExpired");
        assert_eq!(
            rows[0][column("connection")],
            "",
            "a multi-endpoint logical slot must not be attributed to its physical carrier"
        );
        let events = fs::read_to_string(output.join("events.csv")).expect("events trace");
        assert_eq!(
            events.matches("deadline_expired").count(),
            1,
            "one typed expiry observation is emitted for the logical root"
        );

        drop(endpoints);
        drop(first_server);
        drop(second_server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the dynamic-inventory oracle binds two controller slots to one already-captured adapter tick"
    )]
    async fn exact_handoff_refresh_rejects_an_unseen_same_tick_logical_slot() {
        let output = trace_output_dir("exact-incoming-refresh-new-slot");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            50_000,
        );
        let stream =
            open_controlled_runner_stream(&mut endpoint, &mut server, started, 4_433, 10_000);
        let first = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("first");
        let second = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("second");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 50_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([first, second]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let mut credits: Vec<_> = controller
            .drain_actions()
            .filter(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
            .collect();
        assert_eq!(credits.len(), 2);
        let second_credit = credits.pop().expect("second logical credit");
        let first_credit = credits.pop().expect("first logical credit");
        let first_slot = first_credit
            .receive_identity()
            .and_then(QcsdReceiveActionIdentity::slot);
        let second_slot = second_credit
            .receive_identity()
            .and_then(QcsdReceiveActionIdentity::slot);
        assert_ne!(first_slot, second_slot);

        let mut endpoints = vec![endpoint];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![first_credit],
        )
        .expect("apply first logical slot only");
        let release = now();
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline: release + Duration::from_millis(50),
        };
        let mut captured =
            buflo_exact_incoming_identities(&guard, &endpoints, &controller, release, None)
                .expect("capture first logical slot");
        assert_eq!(captured.len(), 1);
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![second_credit],
        )
        .expect("stage a second same-tick logical slot");
        assert!(matches!(
            refresh_buflo_exact_incoming_identities(
                &guard,
                &endpoints,
                &controller,
                release,
                &mut captured,
            ),
            Err(Error::SlotInvariant(message))
                if message.contains("discovered new logical slot")
                    && message.contains("at the captured tick")
        ));

        drop(traces);
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the connected exact-credit oracle spans real transport advertisement and a later guard"
    )]
    async fn exact_handoff_excludes_realized_credit_from_a_later_guard() {
        let output = trace_output_dir("exact-incoming-realized-replacement");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );
        let first_stream =
            open_controlled_runner_stream(&mut endpoint, &mut server, started, 4_433, 10_000);
        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let future =
            Packet::new(Duration::from_secs(1), Direction::Outgoing, 100).expect("future outgoing");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming, future]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(first_stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let incoming_slot = actions
            .iter()
            .find_map(|action| action.receive_identity()?.slot())
            .expect("incoming slot");
        let mut endpoints = vec![endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply first receive credit");

        let defense_start = now();
        let first_guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("first outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: defense_start,
            guard_at: defense_start,
            active_wait_at: defense_start,
            release: defense_start,
            deadline: defense_start + Duration::from_millis(20),
        };
        let mut first_metrics = RunnerWakeupMetrics::new();
        drive_buflo_unadvertised_scheduled_receive_credit(
            &first_guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            &mut first_metrics,
        )
        .await
        .expect("first credit is advertised inside its exact window");
        assert!(controller.incoming_slot_is_locally_realized(incoming_slot));
        assert_eq!(first_metrics.buflo_exact_incoming_retry_resolutions, 1);

        // The trace/controller lifecycle receipt covers parser ownership
        // return and replacement. At the runner boundary, an already locally
        // realised slot must never be captured again by a later exact guard.
        let later_tick = Duration::from_millis(20);
        let later_release = defense_start + later_tick;
        let later_guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(1_000),
            packet: Packet::new(later_tick, Direction::Outgoing, 1_200)
                .expect("later outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: later_release,
            guard_at: later_release,
            active_wait_at: later_release,
            release: later_release,
            deadline: later_release + Duration::from_millis(20),
        };
        assert!(
            buflo_exact_incoming_identities(
                &later_guard,
                &endpoints,
                &controller,
                defense_start,
                None,
            )
            .expect("already-realised replacement is ordinary drain")
            .is_empty()
        );
        let mut later_metrics = RunnerWakeupMetrics::new();
        drive_buflo_unadvertised_scheduled_receive_credit(
            &later_guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            &mut later_metrics,
        )
        .await
        .expect("later exact guard ignores ordinary realised credit");
        assert_eq!(later_metrics.buflo_exact_incoming_retry_drives, 0);

        drop(traces);
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the errored owner-drive oracle binds the original error, typed deadline expiry, and retry metrics"
    )]
    async fn exact_handoff_output_error_at_deadline_terminalizes_before_preserving_error() {
        let output = trace_output_dir("exact-incoming-error-at-deadline");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );
        let stream =
            open_controlled_runner_stream(&mut endpoint, &mut server, started, 4_433, 10_000);
        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let incoming_slot = actions
            .iter()
            .find_map(|action| {
                let identity = action.receive_identity()?;
                identity.slot()
            })
            .expect("incoming slot");
        let mut endpoints = vec![endpoint];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply receive credit");

        let release = now();
        let deadline = release + Duration::from_millis(20);
        endpoints[0]
            .test_output_drives
            .push_back(TestOutputDrive::ErrorAt(deadline));
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline,
        };
        let mut metrics = RunnerWakeupMetrics::new();
        let error = drive_buflo_unadvertised_scheduled_receive_credit(
            &guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            release,
            &mut metrics,
        )
        .await
        .expect_err("errored drive must abort after typed expiry");
        assert!(matches!(
            error,
            Error::SlotInvariant(message)
                if message == "test output failed at the exact incoming deadline"
        ));
        assert!(
            controller
                .terminal_slot_resolution_at(incoming_slot)
                .is_some_and(|resolved_at| resolved_at >= Duration::from_millis(20)),
            "the strict error is reconciled at its observed deadline-crossing instant"
        );
        assert_eq!(metrics.buflo_exact_incoming_retry_drives, 1);
        assert_eq!(metrics.buflo_exact_incoming_retry_resolutions, 0);

        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("DeadlineExpired"));
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(
            packets.lines().count(),
            1,
            "errored drive emits no datagram"
        );

        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the skew oracle binds typed late-handoff provenance, controller local realization, and adapter-boundary expiry"
    )]
    async fn exact_handoff_adapter_deadline_skew_forces_typed_expiry_after_sent_late() {
        let output = trace_output_dir("exact-incoming-adapter-deadline-skew");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );
        let stream =
            open_controlled_runner_stream(&mut endpoint, &mut server, started, 4_433, 10_000);
        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let (incoming_slot, absolute_limit) = actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    slot,
                    absolute_limit,
                    ..
                } => Some((*slot, *absolute_limit)),
                _ => None,
            })
            .expect("incoming credit");
        let mut endpoints = vec![endpoint];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply receive credit");

        let defense_start = now();
        let release = defense_start + Duration::from_nanos(999);
        let nominal_deadline = defense_start + Duration::from_millis(20);
        let deadline = nominal_deadline
            .checked_sub(Duration::from_nanos(999))
            .expect("sub-microsecond adapter deadline");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline,
        };
        let mut captured =
            buflo_exact_incoming_identities(&guard, &endpoints, &controller, defense_start, None)
                .expect("capture physical child");
        assert_eq!(captured.len(), 1);

        // The controller sees the handoff 999 ns before its nominal deadline
        // and therefore records local realization. The physical handoff is
        // nevertheless exactly at the adapter's exclusive deadline, so its
        // typed `SentLate` error must force a deadline miss instead of trusting
        // that rounded controller state.
        let sent_elapsed = deadline.saturating_duration_since(defense_start);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                absolute_limit,
                slot: Some(incoming_slot),
            },
            sent_elapsed,
        );
        assert!(controller.incoming_slot_is_locally_realized(incoming_slot));
        assert_eq!(controller.terminal_slot_resolution_at(incoming_slot), None);

        // A later reducer error alone cannot relabel a physical handoff that
        // completed inside the adapter window.
        let mut metrics = RunnerWakeupMetrics::new();
        let reducer_error = reconcile_buflo_exact_incoming_output_error(
            Error::SlotInvariant("test post-handoff reducer failure".into()),
            &guard,
            QcsdEndpointId(0),
            &BTreeSet::new(),
            &mut captured,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            &mut metrics,
            deadline + Duration::from_nanos(1),
        );
        assert!(matches!(
            reducer_error,
            Error::SlotInvariant(message) if message == "test post-handoff reducer failure"
        ));
        assert!(controller.incoming_slot_is_locally_realized(incoming_slot));
        assert_eq!(controller.terminal_slot_resolution_at(incoming_slot), None);

        let reconciliation_observed_at = deadline + Duration::from_millis(2);
        let error = reconcile_buflo_exact_incoming_output_error(
            late_socket_handoff_error(deadline, deadline, SocketHandoffBoundary::AdapterDeadline),
            &guard,
            QcsdEndpointId(0),
            &BTreeSet::from([incoming_slot]),
            &mut captured,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            &mut metrics,
            reconciliation_observed_at,
        );
        assert!(matches!(
            error,
            Error::AdapterDeadlineLateHandoff {
                sent_at,
                deadline: error_deadline,
            } if sent_at == deadline && error_deadline == deadline
        ));
        assert_eq!(
            controller.terminal_slot_resolution_at(incoming_slot),
            Some(sent_elapsed),
            "the typed adapter boundary, not the later nominal controller deadline, owns expiry"
        );
        assert!(!controller.incoming_slot_is_locally_realized(incoming_slot));
        assert_eq!(
            metrics.buflo_exact_incoming_retry_max_wake_lateness_nanoseconds, 2_000_000,
            "runner wake lateness remains measured at the later reconciliation instant"
        );

        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2, "one typed terminal row");
        assert!(schedule.contains("DeadlineExpired"));
        let terminal_row: Vec<_> = schedule
            .lines()
            .nth(1)
            .expect("terminal schedule row")
            .split(',')
            .collect();
        assert_eq!(
            terminal_row[25],
            u64::try_from(sent_elapsed.as_micros())
                .expect("test duration fits u64")
                .to_string(),
            "terminal evidence uses the low-level handoff timestamp, not later reducer work"
        );

        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the causal-force oracle binds two same-owner slots, one timely local realization, and one typed late handoff"
    )]
    async fn typed_late_reconciliation_preserves_timely_same_owner_sibling_slot() {
        let output = trace_output_dir("exact-incoming-causal-late-slot");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );
        let stream =
            open_controlled_runner_stream(&mut endpoint, &mut server, started, 4_433, 10_000);
        let first = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("first incoming");
        let second =
            Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("second incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([first, second]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let mut credits: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    slot,
                    absolute_limit,
                    ..
                } => Some((*absolute_limit, *slot)),
                _ => None,
            })
            .collect();
        credits.sort_unstable();
        assert_eq!(credits.len(), 2);
        let (timely_limit, timely_slot) = credits[0];
        let (_, late_slot) = credits[1];

        let mut endpoints = vec![endpoint];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply same-owner credits");

        let defense_start = now();
        let deadline = defense_start + Duration::from_millis(20);
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: defense_start,
            guard_at: defense_start,
            active_wait_at: defense_start,
            release: defense_start,
            deadline,
        };
        let mut captured =
            buflo_exact_incoming_identities(&guard, &endpoints, &controller, defense_start, None)
                .expect("capture both same-owner identities");
        assert_eq!(captured.len(), 2);

        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                absolute_limit: timely_limit,
                slot: Some(timely_slot),
            },
            Duration::from_millis(1),
        );
        assert!(controller.incoming_slot_is_locally_realized(timely_slot));
        assert!(!controller.incoming_slot_is_locally_realized(late_slot));

        let mut metrics = RunnerWakeupMetrics::new();
        let error = reconcile_buflo_exact_incoming_output_error(
            late_socket_handoff_error(deadline, deadline, SocketHandoffBoundary::AdapterDeadline),
            &guard,
            QcsdEndpointId(0),
            &BTreeSet::from([late_slot]),
            &mut captured,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            &mut metrics,
            deadline + Duration::from_millis(2),
        );
        assert!(matches!(
            error,
            Error::AdapterDeadlineLateHandoff {
                sent_at,
                deadline: error_deadline,
            } if sent_at == deadline && error_deadline == deadline
        ));
        assert!(controller.incoming_slot_is_locally_realized(timely_slot));
        assert_eq!(controller.terminal_slot_resolution_at(timely_slot), None);
        assert_eq!(
            controller.terminal_slot_resolution_at(late_slot),
            Some(Duration::from_millis(20))
        );

        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let rows: Vec<_> = schedule.lines().skip(1).collect();
        assert_eq!(rows.len(), 1, "only the causally late slot expires");
        let fields: Vec<_> = rows[0].split(',').collect();
        assert_eq!(fields[8], late_slot.0.to_string());
        assert_eq!(fields[7], "DeadlineExpired");

        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the live expiry regression binds transport cancellation, controller terminality, and trace uniqueness"
    )]
    async fn exact_handoff_deadline_expires_once_without_late_credit_output() {
        let output = trace_output_dir("post-handoff-credit-deadline");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            20_000,
        );

        endpoint.client.qcsd_enable_send_shaping(false);
        let request_url = http::Uri::from_static("https://127.0.0.1:4433/controlled");
        let stream = endpoint
            .client
            .fetch(
                started,
                "GET",
                &request_url,
                &[],
                neqo_http3::Priority::default(),
            )
            .expect("create controlled request stream");
        endpoint
            .client
            .register_qcsd_stream(stream, QcsdRequestRole::Application, Some(10_000))
            .expect("register controlled response stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close request send side");
        let mut server = server;
        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
        assert!(!endpoint.client.qcsd_has_pending_stream_send());
        endpoint.client.qcsd_enable_send_shaping(true);
        drop(endpoint.client.qcsd_timestamped_observations());

        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 20_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: true,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let incoming_slot = actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. } => Some(*slot),
                _ => None,
            })
            .expect("scheduled incoming slot");

        let mut endpoints = vec![endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply receive credit");
        assert_eq!(
            buflo_unadvertised_scheduled_receive_credit_endpoints(&endpoints),
            [0]
        );

        let release = now();
        let defense_start = release
            .checked_sub(Duration::from_nanos(999))
            .expect("adapter release has a sub-microsecond nominal predecessor");
        let deadline = defense_start + Duration::from_millis(20);
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(999),
            packet: Packet::new(Duration::ZERO, Direction::Outgoing, 1_200)
                .expect("outgoing guard"),
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: release,
            guard_at: release,
            active_wait_at: release,
            release,
            deadline,
        };
        // The first two absolute callbacks are already due when returned.
        // The remainder alternate between the strict deadline and an instant
        // after it. The retry loop must neither spin forever nor adopt either
        // callback as permission to drive at or beyond the half-open boundary.
        endpoints[0].test_output_drives.extend([
            TestOutputDrive::CallbackAt(release),
            TestOutputDrive::CallbackAt(release),
            TestOutputDrive::CallbackAt(deadline),
            TestOutputDrive::CallbackAt(deadline + Duration::from_millis(10)),
            TestOutputDrive::CallbackAt(deadline),
            TestOutputDrive::CallbackAt(deadline + Duration::from_millis(10)),
        ]);
        let mut runner_wakeup_metrics = RunnerWakeupMetrics::new();
        let error = drive_buflo_unadvertised_scheduled_receive_credit(
            &guard,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            defense_start,
            &mut runner_wakeup_metrics,
        )
        .await
        .expect_err("unadvertised credit must expire at the strict deadline");
        assert!(
            matches!(
                &error,
                Error::DefenseExecution(message)
                    if message.contains("remained unadvertised at their exact realization deadline")
            ),
            "unexpected expiry error: {error:?}"
        );
        assert!(controller.pending_slots().is_empty());
        assert!(!controller.incoming_slot_is_locally_realized(incoming_slot));
        assert_eq!(
            runner_wakeup_metrics.buflo_exact_incoming_retry_resolutions,
            0
        );
        let retry_drives = runner_wakeup_metrics.buflo_exact_incoming_retry_drives;
        assert!((1..=6).contains(&retry_drives));
        assert!(runner_wakeup_metrics.wait_returns <= retry_drives);
        assert!(retry_drives <= runner_wakeup_metrics.wait_returns.saturating_add(1));
        assert_eq!(
            runner_wakeup_metrics.timer_wakeups,
            runner_wakeup_metrics.wait_returns
        );
        assert_eq!(
            retry_drives
                + u64::try_from(endpoints[0].test_output_drives.len())
                    .expect("synthetic drive inventory fits u64"),
            6,
            "the real deadline may win before every synthetic callback, but each callback is consumed at most once"
        );

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(
            packets.lines().count(),
            1,
            "the helper emits no deadline or catch-up datagram"
        );
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let mut schedule_lines = schedule.lines();
        let schedule_header: Vec<_> = schedule_lines
            .next()
            .expect("schedule header")
            .split(',')
            .collect();
        let schedule_rows: Vec<_> = schedule_lines.collect();
        assert_eq!(
            schedule_rows.len(),
            1,
            "one terminal row for the credit slot"
        );
        let schedule_fields: Vec<_> = schedule_rows[0].split(',').collect();
        assert_eq!(schedule_fields.len(), schedule_header.len());
        let schedule_field = |name: &str| {
            let index = schedule_header
                .iter()
                .position(|column| *column == name)
                .unwrap_or_else(|| panic!("missing schedule column {name}"));
            schedule_fields[index]
        };
        assert_eq!(schedule_field("direction"), "incoming");
        assert_eq!(schedule_field("satisfaction"), "missed");
        assert_eq!(schedule_field("miss_reason"), "DeadlineExpired");
        assert_eq!(schedule_field("slot_id"), incoming_slot.0.to_string());

        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the production retry oracle needs one live receive action and socket handoff"
    )]
    async fn cs_exact_incoming_retry_dispatches_the_owner_once_and_receipts_resolution() {
        let output = trace_output_dir("cs-exact-incoming-retry-dispatch");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, mut server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            1_000_000,
        );
        endpoint.client.qcsd_enable_send_shaping(false);
        let request_url = http::Uri::from_static("https://127.0.0.1:4433/controlled");
        let stream = endpoint
            .client
            .fetch(
                started,
                "GET",
                &request_url,
                &[],
                neqo_http3::Priority::default(),
            )
            .expect("create controlled request stream");
        endpoint
            .client
            .register_qcsd_stream(stream, QcsdRequestRole::Application, Some(10_000))
            .expect("register controlled response stream");
        endpoint
            .client
            .stream_close_send(stream, started)
            .expect("close request send side");
        test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
        assert!(!endpoint.client.qcsd_has_pending_stream_send());
        endpoint.client.qcsd_enable_send_shaping(true);
        drop(endpoint.client.qcsd_timestamped_observations());

        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("incoming");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1_000_000,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingSequence {
                events: VecDeque::from([incoming]),
                exact_incoming_window: false,
            }),
        )
        .expect("incoming controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://127.0.0.1:4433".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(0),
                stream: QcsdStreamId(stream.as_u64()),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let incoming_slot = actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. } => Some(*slot),
                _ => None,
            })
            .expect("scheduled incoming slot");
        let mut endpoints = vec![endpoint];
        endpoints[0].test_force_socket_handoff_success = true;
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            actions,
        )
        .expect("apply exact incoming action");

        let defense = DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
            parameters: "test-only-cs-buflo-parameters.json".into(),
        });
        let defense_start = now()
            .checked_sub(Duration::from_millis(251))
            .expect("synthetic defense clock has a quarter-window predecessor");
        let mut attempted = BTreeSet::new();
        let mut metrics = RunnerWakeupMetrics::new();
        assert!(
            dispatch_due_cs_exact_incoming_retry(
                &defense,
                &mut endpoints,
                &mut controller,
                None,
                &mut traces,
                &observation_clock,
                Some(defense_start),
                &mut attempted,
                &mut metrics,
            )
            .await
            .expect("dispatch due quarter-window retry")
        );
        assert!(!cs_exact_incoming_identity_is_pending(
            &endpoints,
            QcsdEndpointId(0),
            incoming_slot
        ));
        assert_eq!(metrics.cs_exact_incoming_retry_drives, 1);
        assert_eq!(metrics.cs_exact_incoming_retry_resolutions, 1);
        assert!(
            metrics.cs_exact_incoming_retry_max_phase_lateness_nanoseconds < 100_000_000,
            "attempt-time lateness excludes the output-drive completion tail"
        );
        assert!(
            !dispatch_due_cs_exact_incoming_retry(
                &defense,
                &mut endpoints,
                &mut controller,
                None,
                &mut traces,
                &observation_clock,
                Some(defense_start),
                &mut attempted,
                &mut metrics,
            )
            .await
            .expect("resolved identity cannot rearm a retry")
        );
        assert!(attempted.is_empty());
        assert_eq!(metrics.cs_exact_incoming_retry_drives, 1);

        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            now(),
            now().saturating_duration_since(defense_start),
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize unconsumed exact credit");
        drop(traces);
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn delayed_prearm_dispatch_preserves_the_absolute_defense_window() {
        let packet =
            Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_200).expect("packet");
        let action = || QcsdAction::PrearmPacket {
            endpoint: QcsdEndpointId(1),
            packet,
            slot: QcsdSlotId(7),
            not_before_after_us: 9,
            deadline_after_us: 19,
            allow_stream_data: true,
        };

        let mut before_release = action();
        normalize_rolling_prearm_window(
            &mut before_release,
            Duration::from_nanos(35_500),
            Duration::from_micros(10),
        )
        .expect("window remains open");
        assert!(matches!(
            before_release,
            QcsdAction::PrearmPacket {
                not_before_after_us: 5,
                deadline_after_us: 14,
                ..
            }
        ));

        let mut at_release = action();
        normalize_rolling_prearm_window(
            &mut at_release,
            Duration::from_micros(40),
            Duration::from_micros(10),
        )
        .expect("release retains the original deadline");
        assert!(matches!(
            at_release,
            QcsdAction::PrearmPacket {
                not_before_after_us: 0,
                deadline_after_us: 10,
                ..
            }
        ));

        let mut expired = action();
        assert!(matches!(
            normalize_rolling_prearm_window(
                &mut expired,
                Duration::from_micros(50),
                Duration::from_micros(10),
            ),
            Err(Error::SlotInvariant(_))
        ));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the cross-clock fixture keeps normalisation, guard construction, and serialized evidence together"
    )]
    fn fractional_prearm_serializes_nominal_packet_and_actual_adapter_window() {
        let defense_start = now();
        let action_elapsed = Duration::from_millis(10) + Duration::from_nanos(456);
        let action_at = defense_start + action_elapsed;
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let mut action = QcsdAction::PrearmPacket {
            endpoint: QcsdEndpointId(3),
            packet,
            slot: QcsdSlotId(17),
            not_before_after_us: 0,
            deadline_after_us: 0,
            allow_stream_data: true,
        };
        normalize_rolling_prearm_window(&mut action, action_elapsed, Duration::from_millis(5))
            .expect("fractional prearm retains a nonempty adapter window");
        let QcsdAction::PrearmPacket {
            not_before_after_us,
            deadline_after_us,
            ..
        } = action
        else {
            unreachable!("test action remains a prearm")
        };
        assert_eq!(not_before_after_us, 10_000);
        assert_eq!(deadline_after_us, 14_999);

        let release = action_at + Duration::from_micros(not_before_after_us);
        let deadline = action_at + Duration::from_micros(deadline_after_us);
        let guard = buflo_exact_release_guard_from_candidates(
            true,
            [BufloExactReleaseCandidate {
                endpoint_index: 0,
                endpoint: QcsdEndpointId(3),
                slot: QcsdSlotId(17),
                packet,
                phase: BufloExactReleasePhase::Prearmed,
                release,
                deadline,
            }],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        )
        .expect("fractional candidate is valid")
        .expect("fractional candidate establishes a guard");
        assert_eq!(
            release.saturating_duration_since(defense_start),
            Duration::from_nanos(20_000_456)
        );
        assert_eq!(
            deadline.saturating_duration_since(defense_start),
            Duration::from_nanos(24_999_456)
        );
        assert_eq!(
            deadline.saturating_duration_since(release),
            Duration::from_micros(4_999)
        );
        assert_eq!(
            release.saturating_duration_since(guard.guard_at),
            Duration::from_micros(9_998)
        );
        assert_eq!(guard.guard_at, guard.active_wait_at);
        assert_eq!(guard.guard_at, guard.output_admission_at);

        let dispatch_at = release + Duration::from_nanos(7);
        let mut metrics = RunnerWakeupMetrics::new();
        metrics.record_buflo_exact_release_guard(
            &guard,
            Some(defense_start),
            &BufloExactReleaseWaitEvidence {
                entered_at: guard.guard_at,
                active_wait_started_at: guard.guard_at,
                dispatch_at,
                passive_sleep_calls: 0,
                passive_sleep_requested_nanoseconds: 0,
                passive_sleep_elapsed_nanoseconds: 0,
                max_passive_sleep_overrun_nanoseconds: 0,
                active_wait_iterations: 1,
                active_spin_interruptions: 0,
                active_spin_interruption_nanoseconds: 0,
                max_active_spin_gap_nanoseconds: 0,
                active_wait_start_clocks: BufloExactReleaseAuxClockSample::default(),
                active_wait_end_clocks: BufloExactReleaseAuxClockSample::default(),
            },
        );
        assert!(metrics.buflo_exact_release_invariants_hold());

        let serialized = serde_json::to_value(metrics).expect("serialize fractional metrics");
        let semantics = serialized["semantics"]
            .as_str()
            .expect("runner semantics are a string");
        for clause in [
            "buflo_rolling_prearm_not_before_relative_us_rounding=ceil",
            "buflo_rolling_prearm_deadline_relative_us_rounding=floor",
            "buflo_exact_release_packet_timestamp_us_semantics=nominal_defense_release",
            "buflo_exact_release_worst_guard_release_and_deadline_semantics=actual_adapter_instants",
            "buflo_exact_release_actual_adapter_window_ns=nominal_control_interval_ns_or_nominal_minus_1000",
            "buflo_exact_release_actual_guard_and_active_wait_lead_ns=twice_actual_adapter_window_ns",
            "buflo_exact_release_10000us_lead_fields_are_configured_maxima=true",
        ] {
            assert!(
                semantics.contains(clause),
                "missing semantics clause {clause}"
            );
        }
        let worst = &serialized["buflo_exact_release_worst_guard"];
        assert_eq!(worst["packet_timestamp_us"], 20_000);
        assert_eq!(worst["guard_at_defense_nanoseconds"], 10_002_456);
        assert_eq!(worst["active_wait_at_defense_nanoseconds"], 10_002_456);
        assert_eq!(worst["release_at_defense_nanoseconds"], 20_000_456);
        assert_eq!(worst["deadline_at_defense_nanoseconds"], 24_999_456);
        assert_eq!(worst["dispatch_at_defense_nanoseconds"], 20_000_463);
        assert_eq!(worst["dispatch_lateness_nanoseconds"], 7);
        assert_eq!(worst["dispatch_at_or_after_deadline"], false);
        assert_eq!(worst["dispatch_after_deadline_nanoseconds"], 0);
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
                terminal_defense_elapsed_us: 0,
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
                    terminal_defense_elapsed_us: 1,
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
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let slot = QcsdSlotId(0);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
        controller.poll(Duration::ZERO);
        assert_eq!(controller.pending_slots(), [(slot, packet)]);
        let first = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(9),
            stream: QcsdStreamId(0),
            absolute_limit: 116,
            packet,
            slot,
        };
        let second = QcsdAction::IncreaseReceiveLimit {
            endpoint: QcsdEndpointId(9),
            stream: QcsdStreamId(4),
            absolute_limit: 216,
            packet,
            slot,
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
    fn fixed_schedule_never_enters_the_global_rolling_barrier() {
        let controller = QcsdController::new(
            QcsdConfig {
                defense: DefenseConfig::Front(FrontConfig {
                    n_client_packets: 1,
                    n_server_packets: 1,
                    packet_size: 1_200,
                    ..FrontConfig::default()
                }),
                ..QcsdConfig::default()
            },
            7,
            None,
        )
        .expect("FRONT controller with a frozen schedule");
        assert!(controller.has_fixed_schedule_staging());
        assert!(!rolling_output_lifecycle_active(&controller, &[]));
    }

    #[test]
    fn run_abort_receipts_prearmed_future_fixed_slots() {
        let output = trace_output_dir("future-fixed-abort");
        let started = now();
        let mut controller = QcsdController::new(
            QcsdConfig {
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Front(FrontConfig {
                    n_client_packets: 4,
                    n_server_packets: 4,
                    packet_size: 1_200,
                    peak_minimum_seconds: 0.01,
                    peak_maximum_seconds: 0.02,
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("FRONT controller with deterministic future slots");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(1),
                origin: "https://front.example".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.reconcile_due_fixed(Duration::ZERO);
        let future_slots = controller.pending_slots();
        assert!(!future_slots.is_empty());
        assert!(
            future_slots
                .iter()
                .all(|(_, packet)| packet.timestamp() > Duration::ZERO)
        );

        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            started,
            Duration::ZERO,
            MissedSlotReason::RunAborted,
        )
        .expect("receipt not-yet-due fixed slots during abort");
        traces
            .ensure_no_pending_slots()
            .expect("future abort leaves no trace debt");
        drop(traces);

        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let rows: Vec<_> = schedule.lines().skip(1).collect();
        assert_eq!(rows.len(), future_slots.len());
        for row in rows {
            let fields: Vec<_> = row.split(',').collect();
            assert!(fields[0].parse::<u64>().expect("target time") > 0);
            assert_eq!(fields[5], "missed");
            assert_eq!(fields[7], "RunAborted");
            assert_eq!(fields.last(), Some(&"0"));
        }
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
        assert_eq!(fields[9], "3");
        assert_eq!(fields[10], "exact");
        assert_eq!(fields[11], "100");
        assert!(
            fields[12..fields.len() - 1]
                .iter()
                .all(|field| field.is_empty())
        );
        assert_eq!(fields.last(), Some(&"9"));
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
            Some(Path::new("schedule.csv")),
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
            Some(Path::new("matrix.json")),
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
            Some(Path::new("histograms.json")),
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
            Some(Path::new("molded.json")),
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
    fn strict_socket_handoff_is_isolated_to_candidate_evidence_paths() {
        for defense in [
            DefenseConfig::None,
            DefenseConfig::Static {
                schedule: "schedule.csv".into(),
                padding_only: false,
            },
            DefenseConfig::Front(FrontConfig::default()),
            DefenseConfig::Tamaraw(TamarawConfig::default()),
            DefenseConfig::TrafficMorphing(TrafficMorphingConfig::default()),
            DefenseConfig::WtfPad(WtfPadConfig::default()),
            DefenseConfig::WalkieTalkie(WalkieTalkieConfig::default()),
        ] {
            assert!(!is_candidate_defense(&defense));
            assert_eq!(
                SocketHandoffPolicy::for_defense(&defense),
                SocketHandoffPolicy::HistoricalBestEffort
            );
        }
        for defense in [
            DefenseConfig::Buflo(neqo_csdef::BufloConfig {
                parameters: "buflo.json".into(),
            }),
            DefenseConfig::CsBuflo(neqo_csdef::CsBufloConfig {
                parameters: "cs-buflo.json".into(),
            }),
        ] {
            assert!(is_candidate_defense(&defense));
            assert_eq!(
                SocketHandoffPolicy::for_defense(&defense),
                SocketHandoffPolicy::CandidateFidelityStrict
            );
        }
        assert_eq!(
            SocketHandoffPolicy::for_response_qualification(ResponseQualificationMode::Legacy),
            SocketHandoffPolicy::HistoricalBestEffort
        );
        assert_eq!(
            SocketHandoffPolicy::for_response_qualification(
                ResponseQualificationMode::SustainedIdentity
            ),
            SocketHandoffPolicy::CandidateFidelityStrict
        );
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
                Some(Path::new("matrix.json")),
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
                Some(Path::new("matrix.json")),
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
                Some(Path::new("matrix.json")),
                Some(Path::new("histograms.json")),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn buflo_parameter_flags_are_required_scoped_and_keep_ctsp_cpsp_distinct() {
        let buflo_path = Path::new("buflo.json");
        let ctsp_path = Path::new("cs-buflo-ctsp.json");
        let cpsp_path = Path::new("cs-buflo-cpsp.json");
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
                    Some(
                        "client_only_outgoing_observed_udp_and_incoming_consumed_credit_power_of_two_crossing"
                    )
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
    fn rolling_output_interrupt_uses_the_earliest_controller_or_adapter_boundary() {
        let started = now();
        let controller_tick = Duration::from_millis(20);
        let current_adapter_deadline = started + Duration::from_millis(15);
        let future_adapter_deadline = started + Duration::from_millis(25);
        assert_eq!(
            resolve_rolling_output_interrupt(
                Some(started),
                [controller_tick],
                [future_adapter_deadline, current_adapter_deadline],
            )
            .expect("representable rolling interrupt"),
            Some(current_adapter_deadline)
        );
        assert_eq!(
            resolve_rolling_output_interrupt(Some(started), [controller_tick], [])
                .expect("controller-only interrupt"),
            Some(started + controller_tick)
        );
    }

    #[test]
    fn admitted_unshaped_handoff_can_finish_after_guard_but_not_at_release() {
        let started = now();
        let target = Duration::from_millis(20);
        let release = started + target;
        let guard_at = release
            .checked_sub(Duration::from_millis(5))
            .expect("release has a five-millisecond guard predecessor");
        let output_admission_at = guard_at
            .checked_sub(Duration::from_millis(5))
            .expect("guard has a five-millisecond admission predecessor");
        let adapter_deadline = release + Duration::from_millis(5);
        let handoff_interrupt =
            resolve_rolling_output_interrupt(Some(started), [target], [adapter_deadline])
                .expect("rolling release is representable")
                .expect("rolling release bounds targetless handoff");
        assert_eq!(handoff_interrupt, release);

        let before_admission = output_admission_at
            .checked_sub(Duration::from_nanos(1))
            .expect("output admission has a predecessor");
        let inside_reserved_tail = guard_at + Duration::from_micros(80);
        assert!(inside_reserved_tail < release);
        let mut crossing_guard = [before_admission, inside_reserved_tail].into_iter();
        assert_eq!(
            attempt_socket_handoff(
                &[],
                Some(handoff_interrupt),
                || Ok(()),
                || crossing_guard.next().expect("pre/post handoff clock"),
            )
            .expect("an admitted targetless handoff may finish before release"),
            SocketHandoff::Sent(inside_reserved_tail)
        );

        for too_late in [release, release + Duration::from_nanos(1)] {
            let mut crossing_release = [before_admission, too_late].into_iter();
            let late = attempt_socket_handoff(
                &[],
                Some(handoff_interrupt),
                || Ok(()),
                || crossing_release.next().expect("pre/post handoff clock"),
            )
            .expect("a successful late syscall retains its terminal evidence");
            assert_eq!(
                late,
                SocketHandoff::SentLate {
                    sent_at: too_late,
                    deadline: release,
                    boundary: SocketHandoffBoundary::RollingDefenseDeadline,
                }
            );
            assert!(matches!(
                late_socket_handoff_error(
                    too_late,
                    release,
                    SocketHandoffBoundary::RollingDefenseDeadline,
                ),
                Error::SlotInvariant(message)
                    if message.contains("at or after a rolling defense deadline")
            ));
        }
    }

    #[test]
    fn target_socket_backpressure_aborts_without_retrying_committed_datagram() {
        let deadline = now() + Duration::from_millis(5);
        let mut attempts = 0;
        let error = attempt_socket_handoff(
            &[deadline],
            None,
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
                None,
                || Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                now,
            )
            .expect("unshaped datagrams retain ordinary readiness retry"),
            SocketHandoff::RetryUnshaped
        );
    }

    #[tokio::test]
    async fn rolling_deadline_bounds_an_unshaped_socket_retry_after_one_attempt() {
        let mut attempts = 0;
        assert_eq!(
            attempt_socket_handoff(
                &[],
                None,
                || {
                    attempts += 1;
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                },
                now,
            )
            .expect("unshaped WouldBlock enters the bounded readiness path"),
            SocketHandoff::RetryUnshaped
        );
        assert_eq!(attempts, 1);

        let error = await_unshaped_socket_retry(
            std::future::pending::<std::io::Result<()>>(),
            Some(now() + Duration::from_millis(1)),
        )
        .await
        .expect_err("rolling interrupt must bound an unready socket");
        assert!(matches!(
            error,
            Error::SlotInvariant(message)
                if message.contains("crossed a rolling defense deadline")
        ));

        let future_interrupt = now() + Duration::from_secs(1);
        await_unshaped_socket_retry(async { Ok(()) }, Some(future_interrupt))
            .await
            .expect("ready socket wins strictly before a future rolling interrupt");
        let error = await_unshaped_socket_retry(async { Ok(()) }, Some(now()))
            .await
            .expect_err("the biased deadline wins when readiness and release are both due");
        assert!(matches!(
            error,
            Error::SlotInvariant(message)
                if message.contains("crossed a rolling defense deadline")
        ));

        await_unshaped_socket_retry(async { Ok(()) }, None)
            .await
            .expect("legacy unshaped retry remains readiness-driven");
    }

    #[tokio::test]
    async fn unshaped_retry_and_handoff_cannot_race_across_a_rolling_interrupt() {
        let interrupt = now() + Duration::from_secs(1);
        let before = interrupt
            .checked_sub(Duration::from_nanos(1))
            .expect("interrupt has a predecessor");
        let mut attempts = 0;
        assert_eq!(
            attempt_socket_handoff(
                &[],
                Some(interrupt),
                || {
                    attempts += 1;
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                },
                || before,
            )
            .expect("pre-interrupt WouldBlock enters readiness retry"),
            SocketHandoff::RetryUnshaped
        );
        await_unshaped_socket_retry(async { Ok(()) }, Some(interrupt))
            .await
            .expect("readiness may arrive before the interrupt");
        let error = attempt_socket_handoff(
            &[],
            Some(interrupt),
            || {
                attempts += 1;
                Ok(())
            },
            || interrupt,
        )
        .expect_err("a retry at the exact interrupt must fail before the syscall");
        assert_eq!(attempts, 1, "the at-deadline retry never reaches send");
        assert!(matches!(
            error,
            Error::SlotInvariant(message)
                if message.contains("before socket handoff")
        ));

        let mut handoff_clock = [before, before].into_iter();
        assert_eq!(
            attempt_socket_handoff(
                &[],
                Some(interrupt),
                || Ok(()),
                || handoff_clock.next().expect("pre/post handoff clock"),
            )
            .expect("a handoff wholly before the interrupt is allowed"),
            SocketHandoff::Sent(before)
        );

        let mut crossing_clock = [before, interrupt].into_iter();
        assert_eq!(
            attempt_socket_handoff(
                &[],
                Some(interrupt),
                || Ok(()),
                || crossing_clock.next().expect("pre/post crossing clock"),
            )
            .expect("the successful handoff must retain its late wire receipt"),
            SocketHandoff::SentLate {
                sent_at: interrupt,
                deadline: interrupt,
                boundary: SocketHandoffBoundary::RollingDefenseDeadline,
            }
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
            attempt_socket_handoff(&[deadline], None, || Ok(()), || before_deadline)
                .expect("pre-deadline handoff"),
            SocketHandoff::Sent(before_deadline)
        );

        for attempted_at in [deadline, deadline + Duration::from_nanos(1)] {
            let mut sends = 0;
            let error = attempt_socket_handoff(
                &[deadline],
                None,
                || {
                    sends += 1;
                    Ok(())
                },
                || attempted_at,
            )
            .expect_err("an expired target window must fail before the syscall");
            assert_eq!(sends, 0);
            assert!(matches!(
                error,
                Error::AdapterDeadlinePreHandoff {
                    attempted_at: observed,
                    deadline: observed_deadline,
                } if observed == attempted_at && observed_deadline == deadline
            ));
        }

        for sent_at in [deadline, deadline + Duration::from_nanos(1)] {
            let mut handoff_clock = [before_deadline, sent_at].into_iter();
            assert_eq!(
                attempt_socket_handoff(
                    &[deadline],
                    None,
                    || Ok(()),
                    || { handoff_clock.next().expect("pre/post target handoff clock") }
                )
                .expect("the successful handoff must retain its late wire receipt"),
                SocketHandoff::SentLate {
                    sent_at,
                    deadline,
                    boundary: SocketHandoffBoundary::AdapterDeadline,
                }
            );
        }
    }

    #[test]
    fn low_level_socket_timestamp_cannot_be_relabelled_by_outer_post_send_delay() {
        let base = now();
        let deadline = base + Duration::from_millis(5);
        let low_level_handoff = deadline
            .checked_sub(Duration::from_nanos(1))
            .expect("deadline has a predecessor");
        let delayed_outer_clock = deadline + Duration::from_millis(10);
        let mut clocks = [base, delayed_outer_clock].into_iter();
        assert_eq!(
            attempt_socket_handoff_timestamped(
                &[deadline],
                None,
                || Ok(Some(low_level_handoff)),
                || clocks
                    .next()
                    .expect("only the pre-send outer clock is read"),
            )
            .expect("low-level handoff precedes the exact deadline"),
            SocketHandoff::Sent(low_level_handoff)
        );
        assert_eq!(
            clocks.next(),
            Some(delayed_outer_clock),
            "candidate fidelity never substitutes a delayed caller-side clock for the socket boundary"
        );

        let mut clocks = std::iter::once(base);
        assert_eq!(
            attempt_socket_handoff_timestamped(
                &[deadline],
                None,
                || Ok(Some(deadline)),
                || clocks.next().expect("pre-send outer clock"),
            )
            .expect("successful at-deadline handoff retains terminal evidence"),
            SocketHandoff::SentLate {
                sent_at: deadline,
                deadline,
                boundary: SocketHandoffBoundary::AdapterDeadline,
            }
        );
    }

    #[tokio::test]
    async fn exact_release_drive_bypasses_its_current_guard_and_terminalizes_the_slot() {
        let output = trace_output_dir("successful-exact-release-drive");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("rolling preview");
        let slot = match &preview {
            QcsdAction::PrearmPacket { slot, .. } => *slot,
            _ => unreachable!("selected rolling preview"),
        };
        let mut endpoints = vec![connected_runner_endpoint(
            &output,
            started,
            &observation_clock,
        )];
        endpoints[0].test_force_socket_handoff_success = true;
        drop(endpoints[0].client.qcsd_timestamped_observations());
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply rolling preview");

        let sent_at = started + packet.timestamp() + Duration::from_micros(1);
        let mut monotonic_clock = || sent_at;
        _ = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut monotonic_clock,
        )
        .await
        .expect("the exact path must reach a pre-deadline socket handoff");

        assert!(endpoints[0].prearmed_outgoing.is_empty());
        assert!(endpoints[0].scheduled_outgoing.is_empty());
        assert!(controller.pending_slots().is_empty());
        assert!(traces.is_slot_terminal(slot));
        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("satisfied"));
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 2);
        assert!(packets.contains(",satisfied,"));
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    async fn late_successful_target_handoff_records_all_trace_evidence_before_failing() {
        let output = trace_output_dir("late-successful-target-handoff");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("rolling preview");
        let mut endpoints = vec![connected_runner_endpoint(
            &output,
            started,
            &observation_clock,
        )];
        endpoints[0].test_force_socket_handoff_success = true;
        drop(endpoints[0].client.qcsd_timestamped_observations());
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply rolling preview");

        let release_at = started + packet.timestamp();
        let adapter_deadline = release_at + Duration::from_millis(5);
        let before_deadline = adapter_deadline
            .checked_sub(Duration::from_nanos(1))
            .expect("adapter deadline has a predecessor");
        let mut times = VecDeque::from([
            release_at,
            release_at,
            release_at,
            before_deadline,
            adapter_deadline,
        ]);
        let mut monotonic_clock = || times.pop_front().unwrap_or(adapter_deadline);
        let error = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut monotonic_clock,
        )
        .await
        .expect_err("an at-deadline successful handoff is a fidelity failure");
        assert!(matches!(
            error,
            Error::AdapterDeadlineLateHandoff {
                sent_at,
                deadline,
            } if sent_at == adapter_deadline && deadline == adapter_deadline
        ));
        assert!(
            endpoints[0].scheduled_outgoing.is_empty(),
            "the transport slot observation was reduced before reporting lateness"
        );
        assert!(controller.pending_slots().is_empty());

        drop(traces);
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        assert_eq!(schedule.lines().count(), 2);
        assert!(schedule.contains("satisfied"));
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(packets.lines().count(), 2);
        assert!(packets.contains(",satisfied,"));
        let events = fs::read_to_string(output.join("events.csv")).expect("event trace");
        assert!(events.contains("slot_satisfied"));
        assert!(events.contains("\"\"type\"\":\"\"datagram\"\""));
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one strict-failure oracle spans transport commit, OS error, abort cleanup, and immutable trace evidence"
    )]
    async fn candidate_runner_propagates_strict_os_handoff_errors() {
        let output = trace_output_dir("candidate-strict-socket-error");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = rolling_abort_controller(packet);
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("rolling preview");
        let preview_slot = match &preview {
            QcsdAction::PrearmPacket { slot, .. } => *slot,
            _ => unreachable!("selected rolling preview"),
        };
        let mut endpoints = vec![connected_runner_endpoint(
            &output,
            started,
            &observation_clock,
        )];
        endpoints[0].socket_handoff_policy = SocketHandoffPolicy::CandidateFidelityStrict;
        endpoints[0].test_strict_socket_handoff_error = Some(libc::EMSGSIZE);
        drop(endpoints[0].client.qcsd_timestamped_observations());
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![preview],
        )
        .expect("apply rolling preview");

        let release_at = started + packet.timestamp();
        let mut release_clock = || release_at;
        let error = drive_endpoint_output_with_clock(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            &mut release_clock,
        )
        .await
        .expect_err("candidate runner must propagate a failed OS handoff");
        assert!(matches!(
            error,
            Error::Io(source) if source.raw_os_error() == Some(libc::EMSGSIZE)
        ));
        assert_eq!(
            endpoints[0].test_strict_socket_handoff_error, None,
            "the injected OS error reaches exactly one strict send attempt"
        );
        assert_eq!(controller.pending_slots(), [(preview_slot, packet)]);
        assert_eq!(traces.pending_slots().len(), 1);
        assert!(!traces.is_slot_terminal(preview_slot));

        cancel_uncommitted_prearms_on_abort(
            &mut endpoints,
            &mut controller,
            &mut traces,
            release_at,
        )
        .expect("strict handoff abort cleanup");
        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            release_at,
            packet.timestamp(),
            MissedSlotReason::RunAborted,
        )
        .expect("terminalize strict handoff failure");
        // The production cleanup path is idempotent if error unwinding reaches
        // it again; no second terminal receipt may be written.
        terminalize_pending_slots(
            &mut controller,
            &mut traces,
            release_at,
            packet.timestamp(),
            MissedSlotReason::RunAborted,
        )
        .expect("repeat terminal cleanup remains idempotent");
        traces
            .ensure_no_pending_slots()
            .expect("strict failure leaves no unresolved trace slot");

        drop(traces);
        let packets = fs::read_to_string(output.join("packets.csv")).expect("packet trace");
        assert_eq!(
            packets.lines().count(),
            1,
            "failed OS handoff cannot write a successful packet row"
        );
        let schedule = fs::read_to_string(output.join("schedule.csv")).expect("schedule trace");
        let mut lines = schedule.lines();
        let header: Vec<_> = lines.next().expect("schedule header").split(',').collect();
        let rows: Vec<_> = lines.collect();
        assert_eq!(rows.len(), 1, "strict failure has one terminal receipt");
        let fields: Vec<_> = rows[0].split(',').collect();
        assert_eq!(fields.len(), header.len());
        let field = |name: &str| {
            let index = header
                .iter()
                .position(|column| *column == name)
                .unwrap_or_else(|| panic!("missing schedule column {name}"));
            fields[index]
        };
        assert_eq!(field("satisfaction"), "missed");
        assert_eq!(field("miss_reason"), "RunAborted");
        assert_eq!(field("slot_id"), preview_slot.0.to_string());
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
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
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "the schema fixture explicitly asserts every aggregate and partition invariant"
    )]
    fn runner_wakeup_metrics_partition_actual_select_returns() {
        let mut metrics = RunnerWakeupMetrics::new();
        metrics.record(ActivityWake::SocketReady, true);
        metrics.record(ActivityWake::Timer, false);
        metrics.record(ActivityWake::Timer, true);
        let release = now();
        let entered_at = release
            .checked_sub(Duration::from_millis(10))
            .expect("release has a guard predecessor");
        let active_wait_started_at = entered_at;
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 2,
            endpoint: QcsdEndpointId(7),
            slot: QcsdSlotId(11),
            packet,
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: entered_at,
            guard_at: entered_at,
            active_wait_at: entered_at,
            release,
            deadline: release + Duration::from_millis(5),
        };
        metrics.record_buflo_exact_release_guard(
            &guard,
            entered_at.checked_sub(Duration::from_millis(10)),
            &BufloExactReleaseWaitEvidence {
                entered_at,
                active_wait_started_at,
                dispatch_at: release + Duration::from_nanos(7),
                passive_sleep_calls: 1,
                passive_sleep_requested_nanoseconds: 5_000_000,
                passive_sleep_elapsed_nanoseconds: 5_000_013,
                max_passive_sleep_overrun_nanoseconds: 13,
                active_wait_iterations: 42,
                active_spin_interruptions: 1,
                active_spin_interruption_nanoseconds: 6_000_000,
                max_active_spin_gap_nanoseconds: 6_000_000,
                active_wait_start_clocks: BufloExactReleaseAuxClockSample {
                    monotonic_raw_nanoseconds: Some(1_000),
                    thread_cpu_nanoseconds: Some(2_000),
                },
                active_wait_end_clocks: BufloExactReleaseAuxClockSample {
                    monotonic_raw_nanoseconds: Some(10_001_010),
                    thread_cpu_nanoseconds: Some(8_002_000),
                },
            },
        );
        let retry_phase = release + Duration::from_millis(1);
        metrics.record_cs_exact_incoming_retry_drive(
            retry_phase,
            retry_phase + Duration::from_nanos(11),
        );
        metrics.record_cs_exact_incoming_retry_drive(
            retry_phase,
            retry_phase + Duration::from_nanos(7),
        );
        metrics.record_cs_exact_incoming_retry_resolution();
        let buflo_retry_wake = release + Duration::from_millis(2);
        metrics.record_buflo_exact_incoming_retry_drive(
            buflo_retry_wake,
            buflo_retry_wake + Duration::from_nanos(13),
            true,
        );
        let buflo_deadline = release + Duration::from_millis(5);
        metrics.record_buflo_exact_incoming_terminal_wake(
            buflo_deadline,
            buflo_deadline + Duration::from_nanos(17),
        );
        assert_eq!(metrics.schema_version, RUNNER_WAKEUP_METRICS_SCHEMA_VERSION);
        assert_eq!(metrics.wait_returns, 3);
        assert_eq!(metrics.socket_readiness_wakeups, 1);
        assert_eq!(metrics.timer_wakeups, 2);
        assert_eq!(metrics.controller_deadline_timer_wakeups, 1);
        assert_eq!(metrics.other_timer_wakeups, 1);
        assert_eq!(metrics.buflo_exact_release_guard_entries, 1);
        assert_eq!(
            metrics.buflo_exact_release_guard_wait_nanoseconds,
            10_000_007
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_nanoseconds,
            10_000_007
        );
        assert_eq!(
            metrics.buflo_exact_release_max_passive_wake_lateness_nanoseconds,
            0
        );
        assert_eq!(
            metrics.buflo_exact_release_max_guard_exit_lateness_nanoseconds,
            7
        );
        assert_eq!(
            metrics.buflo_exact_release_max_guard_entry_lateness_nanoseconds,
            0
        );
        assert_eq!(metrics.buflo_exact_release_passive_sleep_calls, 1);
        assert_eq!(
            metrics.buflo_exact_release_passive_sleep_requested_nanoseconds,
            5_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_passive_sleep_elapsed_nanoseconds,
            5_000_013
        );
        assert_eq!(
            metrics.buflo_exact_release_max_passive_sleep_overrun_nanoseconds,
            13
        );
        assert_eq!(metrics.buflo_exact_release_active_wait_iterations, 42);
        assert_eq!(metrics.buflo_exact_release_active_spin_interruptions, 1);
        assert_eq!(
            metrics.buflo_exact_release_active_spin_interruption_nanoseconds,
            6_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_max_active_spin_gap_nanoseconds,
            6_000_000
        );
        assert_eq!(metrics.buflo_exact_release_active_wait_aux_clock_guards, 1);
        assert!(!metrics.buflo_exact_release_aux_clock_source.is_empty());
        assert_eq!(
            metrics.buflo_exact_release_active_wait_aux_clock_unavailable_guards,
            0
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards,
            0
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_monotonic_raw_nanoseconds,
            10_000_010
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_thread_cpu_nanoseconds,
            8_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds,
            2_000_007
        );
        assert_eq!(
            metrics.buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds,
            2_000_007
        );
        assert_eq!(
            metrics.buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds,
            3
        );
        assert_eq!(
            metrics
                .buflo_exact_release_dispatch_lateness_histogram
                .counts,
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            metrics.buflo_exact_release_active_spin_gap_histogram.counts,
            [0, 0, 0, 0, 0, 0, 0, 1]
        );
        let worst = metrics
            .buflo_exact_release_worst_guard
            .expect("one guard establishes bounded worst-case evidence");
        assert_eq!(worst.endpoint, QcsdEndpointId(7));
        assert_eq!(worst.slot, QcsdSlotId(11));
        assert_eq!(worst.phase, "committed");
        assert_eq!(worst.packet_timestamp_us, 20_000);
        assert_eq!(worst.guard_at_defense_nanoseconds, Some(10_000_000));
        assert_eq!(worst.release_at_defense_nanoseconds, Some(20_000_000));
        assert_eq!(worst.dispatch_at_defense_nanoseconds, Some(20_000_007));
        assert_eq!(worst.dispatch_lateness_nanoseconds, 7);
        assert!(!worst.dispatch_at_or_after_deadline);
        assert_eq!(worst.dispatch_after_deadline_nanoseconds, 0);
        assert_eq!(metrics.cs_exact_incoming_retry_drives, 2);
        assert_eq!(metrics.cs_exact_incoming_retry_resolutions, 1);
        assert_eq!(
            metrics.cs_exact_incoming_retry_max_phase_lateness_nanoseconds,
            11
        );
        assert_eq!(metrics.buflo_exact_incoming_retry_drives, 1);
        assert_eq!(metrics.buflo_exact_incoming_retry_resolutions, 1);
        assert_eq!(
            metrics.buflo_exact_incoming_retry_max_wake_lateness_nanoseconds,
            17
        );
        assert_eq!(
            metrics.timer_wakeups,
            metrics.controller_deadline_timer_wakeups + metrics.other_timer_wakeups
        );
        assert!(
            metrics
                .semantics
                .contains("buflo_exact_release_active_wait_tail_us=10000")
        );
        assert!(
            metrics
                .semantics
                .contains("buflo_exact_release_guard_coincides_with_output_admission=true")
        );
        assert!(metrics.semantics.contains(
            "buflo_exact_release_dispatch_at_or_after_deadline_uses_half_open_window=true"
        ));
        assert!(metrics.semantics.contains(
            "buflo_exact_release_aux_clock_cannot_attribute_guest_scheduler_vs_hypervisor_steal"
        ));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic failure-signature fixture keeps phase and clock assertions together"
    )]
    fn exact_release_metrics_distinguish_late_entry_active_interruption_and_clock_elapsed() {
        let defense_start = now();
        let release = defense_start + Duration::from_millis(20);
        let deadline = release + Duration::from_millis(5);
        let guard_at = release
            .checked_sub(Duration::from_millis(10))
            .expect("release has a guard predecessor");
        let entered_at = guard_at + Duration::from_millis(2);
        let dispatch_at = release + Duration::from_millis(6);
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 1,
            endpoint: QcsdEndpointId(3),
            slot: QcsdSlotId(638),
            packet,
            phase: BufloExactReleasePhase::Prearmed,
            output_admission_at: guard_at,
            guard_at,
            active_wait_at: guard_at,
            release,
            deadline,
        };
        let mut metrics = RunnerWakeupMetrics::new();
        metrics.record_buflo_exact_release_guard(
            &guard,
            Some(defense_start),
            &BufloExactReleaseWaitEvidence {
                entered_at,
                active_wait_started_at: entered_at,
                dispatch_at,
                passive_sleep_calls: 0,
                passive_sleep_requested_nanoseconds: 0,
                passive_sleep_elapsed_nanoseconds: 0,
                max_passive_sleep_overrun_nanoseconds: 0,
                active_wait_iterations: 8_000,
                active_spin_interruptions: 1,
                active_spin_interruption_nanoseconds: 6_000_000,
                max_active_spin_gap_nanoseconds: 6_000_000,
                active_wait_start_clocks: BufloExactReleaseAuxClockSample {
                    monotonic_raw_nanoseconds: Some(10_000),
                    thread_cpu_nanoseconds: Some(20_000),
                },
                active_wait_end_clocks: BufloExactReleaseAuxClockSample {
                    monotonic_raw_nanoseconds: Some(14_010_000),
                    thread_cpu_nanoseconds: Some(8_020_000),
                },
            },
        );

        assert_eq!(
            metrics.buflo_exact_release_max_guard_entry_lateness_nanoseconds,
            2_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_max_passive_wake_lateness_nanoseconds, 2_000_000,
            "legacy v2 field remains the active-wait-transition lateness"
        );
        assert_eq!(
            metrics.buflo_exact_release_max_guard_exit_lateness_nanoseconds,
            6_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_dispatch_at_or_after_deadline_guards,
            1
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_nanoseconds,
            14_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_monotonic_raw_nanoseconds,
            14_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_thread_cpu_nanoseconds,
            8_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_estimated_off_cpu_nanoseconds,
            6_000_000
        );
        assert_eq!(
            metrics.buflo_exact_release_max_active_wait_monotonic_raw_divergence_nanoseconds,
            0
        );
        assert_eq!(
            metrics
                .buflo_exact_release_dispatch_lateness_histogram
                .counts,
            [0, 0, 0, 0, 0, 0, 0, 1]
        );
        let worst = metrics
            .buflo_exact_release_worst_guard
            .expect("late guard is retained");
        assert_eq!(worst.endpoint, QcsdEndpointId(3));
        assert_eq!(worst.slot, QcsdSlotId(638));
        assert_eq!(worst.phase, "prearmed");
        assert_eq!(worst.guard_at_defense_nanoseconds, Some(10_000_000));
        assert_eq!(worst.entered_at_defense_nanoseconds, Some(12_000_000));
        assert_eq!(worst.release_at_defense_nanoseconds, Some(20_000_000));
        assert_eq!(worst.deadline_at_defense_nanoseconds, Some(25_000_000));
        assert_eq!(worst.dispatch_at_defense_nanoseconds, Some(26_000_000));
        assert!(worst.dispatch_at_or_after_deadline);
        assert_eq!(worst.dispatch_after_deadline_nanoseconds, 1_000_000);
    }

    #[test]
    fn mixed_adapter_windows_do_not_project_aggregate_deadline_status_onto_worst_guard() {
        let defense_start = now();
        let fractional_packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let fractional_guard = buflo_exact_release_guard_from_candidates(
            true,
            [BufloExactReleaseCandidate {
                endpoint_index: 0,
                endpoint: QcsdEndpointId(0),
                slot: QcsdSlotId(1),
                packet: fractional_packet,
                phase: BufloExactReleasePhase::Committed,
                release: defense_start + Duration::from_nanos(20_000_456),
                deadline: defense_start + Duration::from_nanos(24_999_456),
            }],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        )
        .expect("fractional candidate is valid")
        .expect("fractional candidate establishes a guard");
        let aligned_packet =
            Packet::new(Duration::from_millis(40), Direction::Outgoing, 1_200).expect("packet");
        let aligned_guard = buflo_exact_release_guard_from_candidates(
            true,
            [BufloExactReleaseCandidate {
                endpoint_index: 0,
                endpoint: QcsdEndpointId(0),
                slot: QcsdSlotId(2),
                packet: aligned_packet,
                phase: BufloExactReleasePhase::Committed,
                release: defense_start + Duration::from_millis(40),
                deadline: defense_start + Duration::from_millis(45),
            }],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        )
        .expect("aligned candidate is valid")
        .expect("aligned candidate establishes a guard");
        let evidence =
            |guard: &BufloExactReleaseGuard, dispatch_at| BufloExactReleaseWaitEvidence {
                entered_at: guard.guard_at,
                active_wait_started_at: guard.guard_at,
                dispatch_at,
                passive_sleep_calls: 0,
                passive_sleep_requested_nanoseconds: 0,
                passive_sleep_elapsed_nanoseconds: 0,
                max_passive_sleep_overrun_nanoseconds: 0,
                active_wait_iterations: 1,
                active_spin_interruptions: 0,
                active_spin_interruption_nanoseconds: 0,
                max_active_spin_gap_nanoseconds: 0,
                active_wait_start_clocks: BufloExactReleaseAuxClockSample::default(),
                active_wait_end_clocks: BufloExactReleaseAuxClockSample::default(),
            };

        let fractional_dispatch = fractional_guard.release + Duration::from_nanos(4_999_500);
        assert!(fractional_dispatch >= fractional_guard.deadline);
        let aligned_dispatch = aligned_guard.release + Duration::from_nanos(4_999_800);
        assert!(aligned_dispatch < aligned_guard.deadline);
        let mut metrics = RunnerWakeupMetrics::new();
        metrics.record_buflo_exact_release_guard(
            &fractional_guard,
            Some(defense_start),
            &evidence(&fractional_guard, fractional_dispatch),
        );
        metrics.record_buflo_exact_release_guard(
            &aligned_guard,
            Some(defense_start),
            &evidence(&aligned_guard, aligned_dispatch),
        );

        assert!(metrics.buflo_exact_release_invariants_hold());
        assert_eq!(
            metrics.buflo_exact_release_dispatch_at_or_after_deadline_guards,
            1
        );
        assert_eq!(
            metrics.buflo_exact_release_max_guard_exit_lateness_nanoseconds,
            4_999_800
        );
        assert_eq!(
            metrics
                .buflo_exact_release_dispatch_lateness_histogram
                .counts,
            [0, 0, 0, 0, 0, 0, 2, 0]
        );
        let worst = metrics
            .buflo_exact_release_worst_guard
            .expect("maximum-lateness guard is retained");
        assert_eq!(worst.slot, QcsdSlotId(2));
        assert_eq!(worst.dispatch_lateness_nanoseconds, 4_999_800);
        assert!(!worst.dispatch_at_or_after_deadline);
        assert_eq!(worst.dispatch_after_deadline_nanoseconds, 0);
    }

    #[test]
    fn exact_release_metrics_treat_deadline_as_outside_and_serialize_missing_clocks_as_null() {
        let defense_start = now();
        let release = defense_start + Duration::from_millis(20);
        let deadline = release + Duration::from_millis(5);
        let guard_at = release
            .checked_sub(Duration::from_millis(10))
            .expect("release has a guard predecessor");
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let guard = BufloExactReleaseGuard {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(1),
            packet,
            phase: BufloExactReleasePhase::Committed,
            output_admission_at: guard_at,
            guard_at,
            active_wait_at: guard_at,
            release,
            deadline,
        };
        let mut metrics = RunnerWakeupMetrics::new();
        metrics.record_buflo_exact_release_guard(
            &guard,
            Some(defense_start),
            &BufloExactReleaseWaitEvidence {
                entered_at: guard_at,
                active_wait_started_at: guard_at,
                dispatch_at: deadline,
                passive_sleep_calls: 0,
                passive_sleep_requested_nanoseconds: 0,
                passive_sleep_elapsed_nanoseconds: 0,
                max_passive_sleep_overrun_nanoseconds: 0,
                active_wait_iterations: 1,
                active_spin_interruptions: 0,
                active_spin_interruption_nanoseconds: 0,
                max_active_spin_gap_nanoseconds: 0,
                active_wait_start_clocks: BufloExactReleaseAuxClockSample::default(),
                active_wait_end_clocks: BufloExactReleaseAuxClockSample::default(),
            },
        );

        assert_eq!(metrics.buflo_exact_release_guard_entries, 1);
        assert_eq!(
            metrics.buflo_exact_release_dispatch_at_or_after_deadline_guards, 1,
            "the exact deadline is outside the half-open realization window"
        );
        assert_eq!(
            metrics
                .buflo_exact_release_dispatch_lateness_histogram
                .counts,
            [0, 0, 0, 0, 0, 0, 1, 0],
            "the five-millisecond upper histogram bound remains inclusive"
        );
        assert_eq!(metrics.buflo_exact_release_active_wait_aux_clock_guards, 0);
        assert_eq!(
            metrics.buflo_exact_release_active_wait_aux_clock_unavailable_guards,
            1
        );
        assert_eq!(
            metrics.buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards,
            0
        );
        assert!(metrics.buflo_exact_release_invariants_hold());

        let serialized = serde_json::to_value(metrics).expect("serialize runner metrics");
        let worst = &serialized["buflo_exact_release_worst_guard"];
        assert_eq!(worst["dispatch_at_or_after_deadline"], true);
        assert_eq!(worst["dispatch_after_deadline_nanoseconds"], 0);
        for nullable in [
            "active_wait_monotonic_raw_nanoseconds",
            "active_wait_thread_cpu_nanoseconds",
            "active_wait_estimated_off_cpu_nanoseconds",
            "active_wait_monotonic_raw_divergence_nanoseconds",
        ] {
            assert_eq!(worst[nullable], serde_json::Value::Null, "{nullable}");
        }
    }

    #[test]
    fn exact_release_timing_histogram_has_inclusive_bounds_and_overflow() {
        let mut histogram = BufloExactReleaseTimingHistogram::new();
        for value in [0, 50_000, 50_001, 5_000_000, 5_000_001] {
            histogram.record(value);
        }
        assert_eq!(histogram.counts, [2, 1, 0, 0, 0, 0, 1, 1]);
    }

    #[test]
    fn exact_release_metric_invariants_cover_histograms_clocks_worst_guard_and_maxima() {
        let valid = RunnerWakeupMetrics::new();
        assert!(valid.buflo_exact_release_invariants_hold());

        let mut invalid_histogram = valid;
        invalid_histogram
            .buflo_exact_release_dispatch_lateness_histogram
            .counts[0] = 1;
        assert!(!invalid_histogram.buflo_exact_release_invariants_hold());

        let mut invalid_aux_partition = valid;
        invalid_aux_partition.buflo_exact_release_active_wait_aux_clock_guards = 1;
        assert!(!invalid_aux_partition.buflo_exact_release_invariants_hold());

        let mut invalid_nonmonotonic = valid;
        invalid_nonmonotonic.buflo_exact_release_active_wait_aux_clock_nonmonotonic_guards = 1;
        assert!(!invalid_nonmonotonic.buflo_exact_release_invariants_hold());

        let mut invalid_worst_presence = valid;
        invalid_worst_presence.buflo_exact_release_guard_entries = 1;
        assert!(!invalid_worst_presence.buflo_exact_release_invariants_hold());

        let mut invalid_passive_max = valid;
        invalid_passive_max.buflo_exact_release_max_passive_sleep_overrun_nanoseconds = 1;
        assert!(!invalid_passive_max.buflo_exact_release_invariants_hold());

        let mut invalid_spin_max = valid;
        invalid_spin_max.buflo_exact_release_max_active_spin_gap_nanoseconds = 1;
        assert!(!invalid_spin_max.buflo_exact_release_invariants_hold());

        let mut invalid_off_cpu_max = valid;
        invalid_off_cpu_max.buflo_exact_release_max_active_wait_estimated_off_cpu_nanoseconds = 1;
        assert!(!invalid_off_cpu_max.buflo_exact_release_invariants_hold());
    }

    #[test]
    fn buflo_terminal_deadline_lateness_is_receipted_without_a_retry_drive() {
        let mut metrics = RunnerWakeupMetrics::new();
        let deadline = now() + Duration::from_millis(5);
        metrics.record_buflo_exact_incoming_terminal_wake(
            deadline,
            deadline + Duration::from_nanos(23),
        );

        assert_eq!(metrics.buflo_exact_incoming_retry_drives, 0);
        assert_eq!(metrics.buflo_exact_incoming_retry_resolutions, 0);
        assert_eq!(
            metrics.buflo_exact_incoming_retry_max_wake_lateness_nanoseconds,
            23
        );
    }

    #[test]
    fn buflo_exact_release_guard_reserves_at_admission_and_selects_full_identity() {
        let base = now();
        let window = Duration::from_millis(5);
        let later_release = base + Duration::from_millis(40);
        let release = base + Duration::from_millis(20);
        let deadline = release + window;
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let later_packet =
            Packet::new(Duration::from_millis(40), Direction::Outgoing, 1_200).expect("packet");
        let guard = buflo_exact_release_guard_from_candidates(
            true,
            [
                BufloExactReleaseCandidate {
                    endpoint_index: 1,
                    endpoint: QcsdEndpointId(1),
                    slot: QcsdSlotId(2),
                    packet: later_packet,
                    phase: BufloExactReleasePhase::Prearmed,
                    release: later_release,
                    deadline: later_release + window,
                },
                BufloExactReleaseCandidate {
                    endpoint_index: 0,
                    endpoint: QcsdEndpointId(0),
                    slot: QcsdSlotId(1),
                    packet,
                    phase: BufloExactReleasePhase::Prearmed,
                    release,
                    deadline,
                },
            ],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        )
        .expect("valid candidate inventory")
        .expect("BuFLO exact candidate has a release guard");
        assert_eq!(guard.endpoint_index, 0);
        assert_eq!(guard.endpoint, QcsdEndpointId(0));
        assert_eq!(guard.slot, QcsdSlotId(1));
        assert_eq!(guard.packet, packet);
        assert_eq!(guard.output_admission_at, base + Duration::from_millis(10));
        assert_eq!(guard.guard_at, guard.output_admission_at);
        assert_eq!(guard.active_wait_at, guard.guard_at);
        assert_eq!(guard.release, release);
        assert_eq!(guard.deadline, deadline);
        assert!(
            buflo_exact_release_guard_from_candidates(
                false,
                [BufloExactReleaseCandidate {
                    endpoint_index: 0,
                    endpoint: QcsdEndpointId(0),
                    slot: QcsdSlotId(1),
                    packet,
                    phase: BufloExactReleasePhase::Prearmed,
                    release,
                    deadline,
                }],
                BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
            )
            .expect("disabled selector is valid")
            .is_none(),
            "non-BuFLO rolling candidates never enter the exact fast lane"
        );

        let duplicate = buflo_exact_release_guard_from_candidates(
            true,
            [
                BufloExactReleaseCandidate {
                    endpoint_index: 0,
                    endpoint: QcsdEndpointId(0),
                    slot: QcsdSlotId(7),
                    packet,
                    phase: BufloExactReleasePhase::Prearmed,
                    release,
                    deadline,
                },
                BufloExactReleaseCandidate {
                    endpoint_index: 1,
                    endpoint: QcsdEndpointId(1),
                    slot: QcsdSlotId(7),
                    packet: later_packet,
                    phase: BufloExactReleasePhase::Committed,
                    release: later_release,
                    deadline: later_release + window,
                },
            ],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        )
        .expect_err("slot ids are globally unique across endpoint runners");
        assert!(matches!(duplicate, Error::SlotInvariant(_)));
    }

    #[test]
    fn cs_exact_incoming_retries_are_finite_and_strictly_inside_the_window() {
        let target = now() + Duration::from_millis(20);
        let deadline = target + Duration::from_millis(5);
        let phases = exact_incoming_retry_times(target, deadline)
            .expect("five-millisecond window has three interior phases");
        assert_eq!(
            phases,
            [
                target + Duration::from_micros(1_250),
                target + Duration::from_micros(2_500),
                target + Duration::from_micros(3_750),
            ]
        );
        assert!(
            phases
                .into_iter()
                .all(|phase| target < phase && phase < deadline)
        );

        let retry = CsExactIncomingRetry {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(7),
            phase: CsExactIncomingRetryPhase::Quarter,
            target,
            phase_at: phases[0],
            deadline,
        };
        assert!(!cs_exact_incoming_retry_is_due(
            &retry,
            target
                .checked_sub(Duration::from_nanos(1))
                .expect("target has a predecessor")
        ));
        assert!(!cs_exact_incoming_retry_is_due(&retry, target));
        assert!(!cs_exact_incoming_retry_is_due(
            &retry,
            phases[0]
                .checked_sub(Duration::from_nanos(1))
                .expect("phase has a predecessor")
        ));
        assert!(cs_exact_incoming_retry_is_due(&retry, phases[0]));
        assert!(cs_exact_incoming_retry_is_due(
            &retry,
            deadline
                .checked_sub(Duration::from_nanos(1))
                .expect("deadline has a predecessor")
        ));
        assert!(!cs_exact_incoming_retry_is_due(&retry, deadline));
        assert!(!cs_exact_incoming_retry_is_due(
            &retry,
            deadline + Duration::from_nanos(1)
        ));
        assert!(
            exact_incoming_retry_times(target, target + Duration::from_nanos(3)).is_none(),
            "a window without three strict interior quarter points is rejected"
        );
        assert!(exact_incoming_retry_times(target, target).is_none());
    }

    #[test]
    fn buflo_exact_release_guard_filters_only_the_terminally_cancelled_preview() {
        let base = now();
        let window = Duration::from_millis(5);
        let cancelled_packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let live_packet =
            Packet::new(Duration::from_millis(40), Direction::Outgoing, 1_200).expect("packet");
        let cancelled = BufloExactReleaseCandidate {
            endpoint_index: 0,
            endpoint: QcsdEndpointId(0),
            slot: QcsdSlotId(1),
            packet: cancelled_packet,
            phase: BufloExactReleasePhase::Prearmed,
            release: base + Duration::from_millis(20),
            deadline: base + Duration::from_millis(20) + window,
        };
        let live = BufloExactReleaseCandidate {
            endpoint_index: 1,
            endpoint: QcsdEndpointId(1),
            slot: QcsdSlotId(2),
            packet: live_packet,
            phase: BufloExactReleasePhase::Prearmed,
            release: base + Duration::from_millis(40),
            deadline: base + Duration::from_millis(40) + window,
        };

        let guard = buflo_exact_release_guard_excluding_candidates(
            true,
            [cancelled, live],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
            |candidate| candidate == &cancelled,
        )
        .expect("terminal cancellation exclusion is valid")
        .expect("the other endpoint retains its exact guard");
        assert_eq!(guard.endpoint, live.endpoint);
        assert_eq!(guard.slot, live.slot);
        assert_eq!(guard.packet, live.packet);

        assert!(
            buflo_exact_release_guard_excluding_candidates(
                true,
                [cancelled],
                BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
                |candidate| candidate == &cancelled,
            )
            .expect("the exact cancelled preview is valid")
            .is_none()
        );

        let invalid_cancelled = BufloExactReleaseCandidate {
            deadline: cancelled.release,
            ..cancelled
        };
        assert!(matches!(
            buflo_exact_release_guard_excluding_candidates(
                true,
                [invalid_cancelled],
                BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
                |_| true,
            ),
            Err(Error::SlotInvariant(_))
        ));
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the production handoff, identity failures, and surviving candidate must share one controller/adapter lifecycle"
    )]
    async fn buflo_exact_release_guard_honours_the_real_terminal_cancellation_handoff() {
        let output = trace_output_dir("buflo-terminal-preview-guard");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let committed_packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let terminal_preview_packet =
            Packet::new(Duration::from_millis(40), Direction::Outgoing, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(RollingOutgoingTerminalOnApplication {
                events: VecDeque::from([committed_packet, terminal_preview_packet]),
                terminal: false,
            }),
        )
        .expect("controller");
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(0),
                origin: "https://example.com".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let first_preview = controller
            .drain_actions()
            .find(|action| {
                matches!(
                    action,
                    QcsdAction::PrearmPacket { packet, .. } if *packet == committed_packet
                )
            })
            .expect("first rolling preview");

        let mut endpoints = vec![connected_runner_endpoint(
            &output,
            started,
            &observation_clock,
        )];
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started,
            Duration::ZERO,
            vec![first_preview],
        )
        .expect("apply first preview");

        controller
            .reconcile_due_rolling(Duration::from_millis(20))
            .expect("commit first preview and arm its successor");
        let transition: Vec<_> = controller.drain_actions().collect();
        assert!(transition.iter().any(|action| matches!(
            action,
            QcsdAction::CommitPrearmedPacket { packet, .. } if *packet == committed_packet
        )));
        assert!(transition.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket { packet, .. } if *packet == terminal_preview_packet
        )));
        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started + Duration::from_millis(20),
            Duration::from_millis(20),
            transition,
        )
        .expect("apply rolling transition");
        assert_eq!(endpoints[0].scheduled_outgoing.len(), 1);
        assert_eq!(endpoints[0].prearmed_outgoing.len(), 1);
        let terminal_preview_slot = endpoints[0].prearmed_outgoing[0].slot;

        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_millis(21),
        );
        controller.flush_defense_observations();
        assert_eq!(controller.rolling_outgoing_prearm_identity(), None);
        assert!(controller.has_queued_terminal_prearm_cancellation(
            QcsdEndpointId(0),
            terminal_preview_packet,
            terminal_preview_slot,
        ));

        let buflo = DefenseConfig::Buflo(neqo_csdef::BufloConfig {
            parameters: "test-only-buflo-parameters.json".into(),
        });
        let committed = endpoints[0]
            .scheduled_outgoing
            .pop_front()
            .expect("committed candidate");
        assert!(
            next_buflo_exact_release_guard(&buflo, &controller, &endpoints)
                .expect("exact terminal cancellation is a valid handoff")
                .is_none(),
            "the adapter preview awaiting its exact terminal cancellation must not retain a guard"
        );

        endpoints[0].scheduled_outgoing.push_front(committed);
        let remaining = next_buflo_exact_release_guard(&buflo, &controller, &endpoints)
            .expect("the remaining committed candidate is valid")
            .expect("the committed candidate retains its guard");
        assert_eq!(remaining.phase, BufloExactReleasePhase::Committed);
        assert_eq!(remaining.slot, committed.slot);
        assert_eq!(remaining.packet, committed.packet);
        let committed = endpoints[0]
            .scheduled_outgoing
            .pop_front()
            .expect("remove the committed candidate for negative cases");

        endpoints[0].prearmed_outgoing[0].slot = QcsdSlotId(terminal_preview_slot.0 + 1);
        assert!(matches!(
            next_buflo_exact_release_guard(&buflo, &controller, &endpoints),
            Err(Error::SlotInvariant(_))
        ));
        endpoints[0].prearmed_outgoing[0].slot = terminal_preview_slot;

        let aborted_preview = controller
            .take_rolling_prearm_for_abort()
            .expect("normalize the queued terminal cancellation for abort");
        assert!(matches!(
            &aborted_preview,
            QcsdAction::CancelPrearmedPacket {
                endpoint: QcsdEndpointId(0),
                packet,
                slot,
                reason: neqo_csdef::QcsdPrearmCancellationReason::RunAborted,
            } if *packet == terminal_preview_packet && *slot == terminal_preview_slot
        ));
        assert!(matches!(
            next_buflo_exact_release_guard(&buflo, &controller, &endpoints),
            Err(Error::SlotInvariant(_))
        ));

        apply_action_batch(
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            started + Duration::from_millis(21),
            Duration::from_millis(21),
            vec![aborted_preview],
        )
        .expect("apply abort-normalized preview cancellation");
        assert!(endpoints[0].prearmed_outgoing.is_empty());
        endpoints[0].scheduled_outgoing.push_front(committed);

        drop(traces);
        drop(endpoints);
        fs::remove_dir_all(output).expect("remove trace test directory");
    }

    #[test]
    fn buflo_exact_release_wait_never_dispatches_before_release() {
        let base = now();
        let window = Duration::from_millis(5);
        let release = base + Duration::from_millis(20);
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let guard = buflo_exact_release_guard_from_candidates(
            true,
            [BufloExactReleaseCandidate {
                endpoint_index: 0,
                endpoint: QcsdEndpointId(0),
                slot: QcsdSlotId(1),
                packet,
                phase: BufloExactReleasePhase::Prearmed,
                release,
                deadline: release + window,
            }],
            BUFLO_EXACT_RELEASE_ACTIVE_WAIT_TAIL,
        )
        .expect("valid exact-release inventory")
        .expect("exact release guard");
        assert_eq!(
            buflo_exact_release_wait_step(&guard, guard.output_admission_at),
            BufloExactReleaseWaitStep::Active,
            "the admission boundary begins the earlier active reservation"
        );
        assert_eq!(
            buflo_exact_release_wait_step(&guard, guard.guard_at),
            BufloExactReleaseWaitStep::Active
        );
        assert_eq!(
            buflo_exact_release_wait_step(&guard, guard.active_wait_at),
            BufloExactReleaseWaitStep::Active
        );
        assert_eq!(
            buflo_exact_release_wait_step(
                &guard,
                release
                    .checked_sub(Duration::from_micros(7_056))
                    .expect("release has the v34 pre-guard chronology")
            ),
            BufloExactReleaseWaitStep::Active,
            "the v34 last-control chronology must no longer return to the reactor"
        );
        assert_eq!(
            buflo_exact_release_wait_step(
                &guard,
                release
                    .checked_sub(Duration::from_nanos(1))
                    .expect("release has a predecessor"),
            ),
            BufloExactReleaseWaitStep::Active
        );
        assert_eq!(
            buflo_exact_release_wait_step(&guard, release),
            BufloExactReleaseWaitStep::Dispatch
        );
        assert_eq!(
            buflo_exact_release_wait_step(&guard, guard.deadline),
            BufloExactReleaseWaitStep::Dispatch,
            "an expired guard reaches the existing hard deadline failure path without catch-up"
        );
    }

    #[test]
    fn exact_release_guard_helper_retains_generic_short_tail_branch() {
        let base = now();
        let window = Duration::from_millis(5);
        let tail = Duration::from_micros(250);
        let release = base + Duration::from_millis(20);
        let packet =
            Packet::new(Duration::from_millis(20), Direction::Outgoing, 1_200).expect("packet");
        let guard = buflo_exact_release_guard_from_candidates(
            true,
            [BufloExactReleaseCandidate {
                endpoint_index: 0,
                endpoint: QcsdEndpointId(0),
                slot: QcsdSlotId(1),
                packet,
                phase: BufloExactReleasePhase::Prearmed,
                release,
                deadline: release + window,
            }],
            tail,
        )
        .expect("valid generic release inventory")
        .expect("generic release guard");
        assert_eq!(
            buflo_exact_release_wait_step(&guard, guard.guard_at),
            BufloExactReleaseWaitStep::Passive(
                window
                    .checked_sub(tail)
                    .expect("generic window exceeds its short active tail")
            )
        );
        assert_eq!(
            buflo_exact_release_wait_step(&guard, guard.active_wait_at),
            BufloExactReleaseWaitStep::Active
        );
    }

    #[tokio::test]
    async fn output_work_start_at_admission_yields_to_guard_without_touching_transport() {
        let output = trace_output_dir("output-work-interrupt");
        let started = test_fixture::now();
        let observation_clock = QcsdObservationClock::new(started);
        let (mut endpoint, server) = connected_runner_endpoint_with_server(
            &output,
            started,
            &observation_clock,
            QcsdEndpointId(0),
            4_433,
            5_000,
        );
        drop(endpoint.client.qcsd_timestamped_observations());
        endpoint.test_observation_on_next_output =
            Some(observation_clock.record(QcsdObservation::EgressBacklog { pending: true }));
        let mut endpoints = vec![endpoint];
        let mut controller =
            QcsdController::new(QcsdConfig::default(), 0, None).expect("controller");
        let mut traces = TraceFiles::new(&output, started).expect("trace files");
        let output_admission_at = started + Duration::from_millis(5);
        let guard_at = output_admission_at + Duration::from_millis(5);
        let release = guard_at + Duration::from_millis(5);
        let mut monotonic_clock = || output_admission_at;

        let wakeup = drive_endpoint_output_with_clock_until(
            0,
            &mut endpoints,
            &mut controller,
            None,
            &mut traces,
            &observation_clock,
            Some(started),
            Some(OutputWorkBoundary::new(output_admission_at, guard_at)),
            Some(release),
            None,
            true,
            OutputDriveCardinality::DrainAvailable,
            PostOutputRollingBarrier::Apply,
            &mut monotonic_clock,
        )
        .await
        .expect("work interruption is a normal runner yield");

        assert_eq!(wakeup, Some(guard_at));
        assert!(
            endpoints[0].test_observation_on_next_output.is_some(),
            "transport output remains untouched at the guard boundary"
        );
        drop(traces);
        drop(endpoints);
        drop(server);
        fs::remove_dir_all(output).expect("remove trace test directory");
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
            source_walkie_talkie_schema_version: None,
            numeric_profile_derivation: None,
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
    fn prefix_spec_accepts_both_frozen_schema_two_and_class_study_schema_three() {
        let mut historical = two_stage_prefix_spec();
        historical.numeric_profile_sha256 = prefix_numeric_profile_sha256(
            &historical.numeric_profile,
            b"qcsd-walkie-talkie-numeric-profile-v1\0",
        )
        .expect("historical numeric hash");
        validate_prefix_pack_spec(&historical).expect("historical schema two");

        let mut class_study = two_stage_prefix_spec();
        class_study.schema_version = 3;
        class_study.artifact_type = "qcsd-class-study-walkie-talkie-prefix-pack-spec".into();
        class_study.source_walkie_talkie_schema_version = Some(6);
        class_study.numeric_profile_derivation =
            Some("schema-six-runtime-bursts-verbatim-no-additional-sender-framing".into());
        class_study.numeric_profile_sha256 = prefix_numeric_profile_sha256(
            &class_study.numeric_profile,
            b"qcsd-class-study-walkie-talkie-numeric-profile-v1\0",
        )
        .expect("class-study numeric hash");
        validate_prefix_pack_spec(&class_study).expect("class-study schema three");

        class_study.numeric_profile_derivation = Some("double-framed".into());
        assert!(validate_prefix_pack_spec(&class_study).is_err());
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
