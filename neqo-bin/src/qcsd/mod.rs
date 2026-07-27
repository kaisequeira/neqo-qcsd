// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Reproducible, current-thread QCSD research runner.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, VecDeque},
    fs::{self, File},
    io::{self, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant, SystemTime},
};

use clap::{Parser, Subcommand, ValueEnum};
use http::Uri;
use neqo_common::{Header, Role, event::Provider as _, qlog::Qlog};
use neqo_csdef::{
    DefenseConfig, DefenseKind, DependencyTracker, Direction, HeaderPolicy, MissedSlotReason,
    Packet, QcsdAction, QcsdConfig, QcsdController, QcsdEndpointId, QcsdObservation, QcsdProfile,
    QcsdRequestRole, QcsdSlotId, Resource, ResourceManifest, ResourceRunState, StaticMode,
};
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Priority};
use neqo_transport::{
    Connection, ConnectionParameters, OutputBatch, RandomConnectionIdGenerator, StreamId,
    StreamType,
};
use neqo_udp::RecvBuf;
use nss::{AuthenticationStatus, hash::HashAlgorithm};
use serde::Serialize;
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
    Qlog(#[from] qlog::Error),
    #[error(transparent)]
    Transport(#[from] neqo_transport::Error),
    #[error("run timed out after {0} seconds")]
    Timeout(u64),
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
}

impl From<ProfileArg> for QcsdProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Published => Self::Published,
            ProfileArg::Live => Self::Live,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DefenseArg {
    None,
    Static,
    Front,
    Tamaraw,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum StaticModeArg {
    ChaffOnly,
    ChaffAndShape,
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
    /// Run baseline, Static, FRONT, or Tamaraw from a resolved configuration.
    Run {
        /// Explicit URLs for small manual runs. Use --workload for dependency graphs.
        urls: Vec<Uri>,
        /// Versioned application workload manifest.
        #[arg(long, conflicts_with = "urls")]
        workload: Option<PathBuf>,
        /// Complete custom configuration for thesis defenses and imported runs.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Compatibility alias for the published pre-profile runner interface.
        #[arg(
            long,
            value_enum,
            conflicts_with_all = ["config", "profile", "defense", "schedule", "static_mode"]
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
        /// Chaff resource manifest; defaults to --workload for shaped runs.
        #[arg(long = "chaff-manifest", visible_alias = "manifest")]
        chaff_manifest: Option<PathBuf>,
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
                config,
                preset,
                profile,
                defense,
                schedule,
                static_mode,
                chaff_manifest,
                seed,
                output_dir,
                max_response_bytes,
                timeout_seconds,
            } => {
                let config = resolve_run_config(
                    config.as_deref(),
                    preset,
                    profile,
                    defense,
                    schedule.as_deref(),
                    static_mode,
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
                let chaff_manifest = if let Some(path) = chaff_manifest {
                    Some(ResourceManifest::from_json_file(path)?)
                } else if !matches!(config.defense, DefenseConfig::None) {
                    Some(workload.clone())
                } else {
                    None
                };
                if !matches!(config.defense, DefenseConfig::None) && chaff_manifest.is_none() {
                    return Err(Error::Argument(
                        "shaped runs require --workload or an explicit --chaff-manifest".into(),
                    ));
                }
                let spec = RunSpec {
                    method: "GET",
                    workload,
                    workload_hash,
                    config,
                    chaff_manifest,
                    seed,
                    output_dir,
                    max_response_bytes,
                    timeout_seconds,
                };
                execute_run(spec).await.map(|_| ())
            }
        }
    }
}

fn resolve_run_config(
    config: Option<&Path>,
    preset: Option<Preset>,
    profile: Option<ProfileArg>,
    defense: Option<DefenseArg>,
    schedule: Option<&Path>,
    static_mode: Option<StaticModeArg>,
) -> Result<QcsdConfig, Error> {
    if let Some(path) = config {
        if preset.is_some()
            || profile.is_some()
            || defense.is_some()
            || schedule.is_some()
            || static_mode.is_some()
        {
            return Err(Error::Argument(
                "--config cannot be combined with profile, preset, or Static options".into(),
            ));
        }
        return Ok(QcsdConfig::from_toml_file(path)?);
    }
    if let Some(preset) = preset {
        return Ok(preset.resolve()?);
    }
    let (Some(profile), Some(defense)) = (profile, defense) else {
        return Err(Error::Argument(
            "provide --config, --preset, or both --profile and --defense".into(),
        ));
    };
    let defense = match defense {
        DefenseArg::None => {
            reject_static_options(schedule, static_mode)?;
            DefenseKind::None
        }
        DefenseArg::Front => {
            reject_static_options(schedule, static_mode)?;
            DefenseKind::Front
        }
        DefenseArg::Tamaraw => {
            reject_static_options(schedule, static_mode)?;
            DefenseKind::Tamaraw
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
    };
    Ok(QcsdProfile::from(profile).resolve(defense)?)
}

fn reject_static_options(
    schedule: Option<&Path>,
    static_mode: Option<StaticModeArg>,
) -> Result<(), Error> {
    if schedule.is_some() || static_mode.is_some() {
        return Err(Error::Argument(
            "--schedule and --static-mode require --defense static".into(),
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct RunSpec {
    method: &'static str,
    workload: ResourceManifest,
    workload_hash: String,
    config: QcsdConfig,
    chaff_manifest: Option<ResourceManifest>,
    seed: u64,
    output_dir: PathBuf,
    max_response_bytes: u64,
    timeout_seconds: u64,
}

#[derive(Clone, Copy)]
struct RunCompletion<'a> {
    ended_unix_ns: Option<u128>,
    status: &'a str,
    error: Option<&'a str>,
    defense_start_monotonic_ns: Option<u64>,
    application_completion_monotonic_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct ResponseResult {
    resource_id: u32,
    url: String,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    content_length: Option<u64>,
    bytes: u64,
    body_sha256: String,
    complete: bool,
    outcome: &'static str,
}

#[derive(Debug)]
struct StreamRecord {
    resource_id: u32,
    url: String,
    role: QcsdRequestRole,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    content_length: Option<u64>,
    body: Vec<u8>,
    bytes: u64,
    complete: bool,
    outcome: &'static str,
}

#[derive(Clone, Debug)]
struct ApplicationRequest {
    resource_id: u32,
    url: Uri,
    headers: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug)]
struct ScheduledOutgoing {
    slot: QcsdSlotId,
    packet: Packet,
    action_time_us: u64,
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
        config: QcsdConfig::default(),
        chaff_manifest: None,
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
            config: QcsdConfig::default(),
            chaff_manifest: None,
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

fn positional_manifest(urls: &[Uri]) -> ResourceManifest {
    ResourceManifest {
        header_policy: HeaderPolicy::default(),
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
    if spec.output_dir.exists() && fs::read_dir(&spec.output_dir)?.next().is_some() {
        return Err(Error::Argument(format!(
            "output directory must be empty: {}",
            spec.output_dir.display()
        )));
    }
    fs::create_dir_all(&spec.output_dir)?;
    fs::create_dir_all(spec.output_dir.join("qlog"))?;
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
        },
    )?;
    let result = execute_run_inner(&spec, wall_start, process_start).await;
    if let Err(error) = &result
        && !matches!(error, Error::Timeout(_))
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
            },
        )?;
    }
    result
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
    let mut endpoints = create_endpoints(spec, process_start)?;
    let mut controller =
        QcsdController::new(spec.config.clone(), spec.seed, spec.chaff_manifest.clone())?;
    let mut dependencies = DependencyTracker::new(spec.workload.clone())?;
    let mut defense_start = None;
    let mut application_completion = None;
    let mut application_complete_observed = false;
    let deadline = process_start + Duration::from_secs(spec.timeout_seconds);

    loop {
        let loop_now = now();
        if loop_now >= deadline {
            for (slot, pending) in traces.pending_slots() {
                let observation = QcsdObservation::SlotMissed {
                    endpoint: pending.endpoint,
                    slot,
                    packet: pending.packet,
                    reason: MissedSlotReason::DeadlineExpired,
                };
                traces.event(
                    loop_now,
                    Some(pending.endpoint),
                    "observation",
                    "deadline_expired",
                    &observation,
                )?;
                traces.schedule(&ScheduleTraceRow {
                    action_time_us: pending.action_time_us,
                    endpoint: Some(pending.endpoint),
                    packet: pending.packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: "DeadlineExpired",
                    slot: Some(slot),
                })?;
            }
            for endpoint in &mut endpoints {
                endpoint.scheduled_outgoing.clear();
            }
            let responses = collect_responses(&mut endpoints)?;
            let message = format!("run timed out after {} seconds", spec.timeout_seconds);
            write_run_json(
                spec,
                &endpoints,
                &responses,
                wall_start,
                &RunCompletion {
                    ended_unix_ns: Some(unix_nanos()),
                    status: "timeout",
                    error: Some(&message),
                    defense_start_monotonic_ns: defense_start
                        .map(|instant| elapsed_ns(process_start, instant)),
                    application_completion_monotonic_ns: application_completion
                        .map(|instant| elapsed_ns(process_start, instant)),
                },
            )?;
            return Err(Error::Timeout(spec.timeout_seconds));
        }

        for endpoint in &mut endpoints {
            handle_http_events(endpoint, spec, loop_now, &mut traces)?;
            for (resource_id, state) in endpoint.retired_applications.drain(..) {
                let success = state == ResourceRunState::Succeeded;
                if success {
                    dependencies.mark_succeeded(resource_id)?;
                } else {
                    dependencies.mark_failed(resource_id)?;
                }
                controller.observe(QcsdObservation::ResourceCompleted {
                    resource_id,
                    success,
                });
            }
        }

        if defense_start.is_none() && endpoints.iter().all(|endpoint| endpoint.connected) {
            defense_start = Some(loop_now);
        }

        if let Some(defense_start) = defense_start {
            dispatch_ready_requests(
                &mut endpoints,
                spec,
                &mut dependencies,
                loop_now,
                &mut traces,
            )?;
            for endpoint in &mut endpoints {
                drop(handle_qcsd_observations(
                    endpoint,
                    &mut controller,
                    &mut traces,
                    loop_now,
                )?);
            }
            if !application_complete_observed && dependencies.is_complete() {
                application_complete_observed = true;
                application_completion = Some(loop_now);
                let observation = QcsdObservation::ApplicationComplete;
                traces.event(loop_now, None, "observation", "recorded", &observation)?;
                controller.observe(observation);
            }
            controller.poll(loop_now.duration_since(defense_start));
            while let Some(action) = controller.next_action() {
                apply_action(
                    &mut endpoints,
                    &mut controller,
                    &mut traces,
                    loop_now,
                    action,
                )?;
            }
        }

        let mut next_wakeup = spec.config.control_interval();
        for endpoint in &mut endpoints {
            if let Some(delay) =
                process_output(endpoint, &mut controller, &mut traces, loop_now).await?
            {
                next_wakeup = next_wakeup.min(delay);
            }
            process_input(endpoint, &mut controller, &mut traces, loop_now)?;
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
        if let Some(defense_start) = defense_start
            && let Some(next_deadline) = controller.next_deadline()
        {
            let mut controller_delay =
                next_deadline.saturating_sub(loop_now.duration_since(defense_start));
            if controller_delay.is_zero() {
                controller_delay = spec.config.control_interval();
            }
            next_wakeup = next_wakeup.min(controller_delay);
        }
        tokio::time::sleep(next_wakeup).await;
    }

    let responses = collect_responses(&mut endpoints)?;
    let completion_status = if dependencies.is_successful() {
        "complete"
    } else {
        "partial"
    };
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

#[expect(
    clippy::too_many_lines,
    reason = "endpoint construction keeps the socket, QUIC, HTTP/3, qlog, and QCSD parameters together"
)]
fn create_endpoints(spec: &RunSpec, start: Instant) -> Result<Vec<Endpoint>, Error> {
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
            let socket = Socket::bind(bind_addr)?;
            let local_addr = socket.local_addr()?;
            let params = if matches!(spec.config.defense, DefenseConfig::None) {
                ConnectionParameters::default()
            } else {
                ConnectionParameters::default().max_stream_data(
                    StreamType::BiDi,
                    false,
                    spec.config.initial_max_stream_data,
                )
            }
            .pmtud(true);
            let mut transport = Connection::new_client(
                &host,
                &["h3"],
                Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8))),
                local_addr,
                remote_addr,
                params,
                start,
            )?;
            transport.set_qlog(Qlog::enabled_with_file(
                spec.output_dir.join("qlog"),
                Role::Client,
                Some(format!("QCSD endpoint {index}")),
                Some("neqo-qcsd-client".into()),
                format!("endpoint-{index}"),
                start,
            )?);
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
            let shape_stream_sends = matches!(
                spec.config.defense,
                DefenseConfig::Tamaraw(_)
                    | DefenseConfig::Static {
                        padding_only: false,
                        ..
                    }
            );
            client.enable_qcsd(
                endpoint_id,
                &origin,
                spec.config.max_udp_payload_size,
                shape_stream_sends,
                Duration::from_micros(spec.config.keep_alive_lead_time_us),
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
            })
        })
        .collect()
}

fn dispatch_ready_requests(
    endpoints: &mut [Endpoint],
    spec: &RunSpec,
    dependencies: &mut DependencyTracker,
    now: Instant,
    traces: &mut TraceFiles,
) -> Result<(), Error> {
    let ready: Vec<_> = dependencies
        .ready()
        .iter()
        .map(|resource| resource.id)
        .collect();
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
            endpoint
                .client
                .register_qcsd_stream(stream, QcsdRequestRole::Application)?;
            endpoint.client.stream_close_send(stream, now)?;
            dependencies.mark_in_flight(request.resource_id)?;
            endpoint.streams.insert(
                stream,
                application_record(&request, QcsdRequestRole::Application, "in_flight"),
            );
            traces.event(
                now,
                Some(endpoint.id),
                "application_request",
                "started",
                &request.resource_id,
            )?;
        }
    }
    Ok(())
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
        response_headers: Vec::new(),
        status: None,
        content_length: None,
        body: Vec::new(),
        bytes: 0,
        complete: false,
        outcome,
    }
}

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
                    finish_stream(endpoint, stream_id);
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
                fin,
                ..
            } => {
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
                    if fin {
                        record.complete = true;
                        finish_stream(endpoint, stream_id);
                    }
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
                        }
                        record.complete |= fin;
                    }
                    if too_large {
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
                        finish_stream(endpoint, stream_id);
                        break;
                    }
                    if fin {
                        finish_stream(endpoint, stream_id);
                        break;
                    }
                    if read == 0 {
                        break;
                    }
                }
            }
            Http3ClientEvent::Reset { stream_id, .. } => finish_stream(endpoint, stream_id),
            _ => {}
        }
    }
    Ok(())
}

fn finish_stream(endpoint: &mut Endpoint, stream_id: StreamId) {
    if let Some(mut record) = endpoint.streams.remove(&stream_id) {
        if record.role == QcsdRequestRole::Application {
            let state = finish_application_record(&mut record);
            endpoint
                .retired_applications
                .push((record.resource_id, state));
        }
        endpoint.completed.push(record);
    }
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

const fn action_endpoint(action: &QcsdAction) -> Option<QcsdEndpointId> {
    match action {
        QcsdAction::ConfigureManualReceive { endpoint, .. }
        | QcsdAction::ConfigureAutomaticReceive { endpoint, .. }
        | QcsdAction::IncreaseReceiveLimit { endpoint, .. }
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
    now: Instant,
) -> Result<Vec<(QcsdSlotId, usize)>, Error> {
    let mut satisfied_datagrams = Vec::new();
    for observation in endpoint.client.qcsd_observations() {
        match &observation {
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
                    action_time_us: scheduled.action_time_us,
                    endpoint: Some(endpoint.id),
                    packet: scheduled.packet,
                    satisfaction: "satisfied",
                    observed: Some(usize::from(*observed_size)),
                    miss_reason: "",
                    slot: Some(scheduled.slot),
                })?;
                satisfied_datagrams.push((*slot, usize::from(*observed_size)));
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
                let action_time_us =
                    scheduled.map_or_else(|| traces.elapsed_us(now), |value| value.action_time_us);
                let scheduled_packet = scheduled.map_or(*packet, |value| value.packet);
                let miss_reason = format!("{reason:?}");
                traces.schedule(&ScheduleTraceRow {
                    action_time_us,
                    endpoint: Some(endpoint.id),
                    packet: scheduled_packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: &miss_reason,
                    slot: Some(*slot),
                })?;
            }
            _ => {}
        }
        traces.event(
            now,
            Some(endpoint.id),
            "observation",
            "recorded",
            &observation,
        )?;
        controller.observe(observation);
    }
    Ok(satisfied_datagrams)
}

#[expect(
    clippy::too_many_lines,
    reason = "action dispatch records every transport and trace outcome in one exhaustive reducer"
)]
fn apply_action(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
    action: QcsdAction,
) -> Result<(), Error> {
    let endpoint_id = action_endpoint(&action);
    if let QcsdAction::SlotMissed {
        endpoint,
        packet,
        slot,
        reason,
    } = &action
    {
        let miss_reason = format!("{reason:?}");
        traces.schedule(&ScheduleTraceRow {
            action_time_us: traces.elapsed_us(now),
            endpoint: *endpoint,
            packet: *packet,
            satisfaction: "missed",
            observed: None,
            miss_reason: &miss_reason,
            slot: Some(*slot),
        })?;
        traces.event(now, endpoint_id, "action", "recorded", &action)?;
        return Ok(());
    }
    if let QcsdAction::SlotSatisfied {
        endpoint,
        packet,
        slot,
    } = &action
    {
        traces.schedule(&ScheduleTraceRow {
            action_time_us: traces.elapsed_us(now),
            endpoint: *endpoint,
            packet: *packet,
            satisfaction: "credit_advertised",
            observed: None,
            miss_reason: "",
            slot: Some(*slot),
        })?;
        traces.event(now, endpoint_id, "action", "recorded", &action)?;
        return Ok(());
    }
    if matches!(&action, QcsdAction::DefenseComplete) {
        traces.event(now, endpoint_id, "action", "recorded", &action)?;
        return Ok(());
    }
    let trace_action = action.clone();
    let scheduled_action = match &trace_action {
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
        _ => None,
    };
    if let Some((endpoint, packet, slot)) = scheduled_action {
        traces.register_slot(now, endpoint, packet, slot)?;
    }
    let Some(endpoint) = endpoints
        .iter_mut()
        .find(|candidate| Some(candidate.id) == endpoint_id)
    else {
        if let Some((endpoint, packet, slot)) = scheduled_action {
            let reason = MissedSlotReason::EndpointClosed;
            controller.observe(QcsdObservation::SlotMissed {
                endpoint,
                slot,
                packet,
                reason,
            });
            let miss_reason = format!("{reason:?}");
            traces.schedule(&ScheduleTraceRow {
                action_time_us: traces.elapsed_us(now),
                endpoint: Some(endpoint),
                packet,
                satisfaction: "missed",
                observed: None,
                miss_reason: &miss_reason,
                slot: Some(slot),
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
                endpoint.scheduled_outgoing.push_back(ScheduledOutgoing {
                    slot,
                    packet,
                    action_time_us: traces.elapsed_us(now),
                });
            }
            if let Some(stream_id) = chaff_stream {
                let (resource_id, request_id, url) = match &trace_action {
                    QcsdAction::RequestChaff {
                        resource,
                        request_id,
                        ..
                    } => (resource.id, *request_id, resource.url.clone()),
                    _ => unreachable!("only chaff actions return a stream"),
                };
                endpoint.client.stream_close_send(stream_id, now)?;
                endpoint.streams.insert(
                    stream_id,
                    StreamRecord {
                        resource_id,
                        url,
                        role: QcsdRequestRole::Chaff {
                            resource_id,
                            request_id: Some(request_id),
                        },
                        request_headers: vec![("accept-encoding".into(), "identity".into())],
                        response_headers: Vec::new(),
                        status: None,
                        content_length: None,
                        body: Vec::new(),
                        bytes: 0,
                        complete: false,
                        outcome: "in_flight",
                    },
                );
                // Apply manual receive control before the newly created chaff
                // request is eligible for its first transport output.
                drop(handle_qcsd_observations(endpoint, controller, traces, now)?);
            }
            traces.event(now, endpoint_id, "action", "applied", &trace_action)?;
        }
        Err(error) => {
            drop(handle_qcsd_observations(endpoint, controller, traces, now)?);
            if let Some((_, packet, slot)) = scheduled_action
                && traces.is_slot_pending(slot)
            {
                let reason = match &error {
                    neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput) => {
                        MissedSlotReason::PathMtu
                    }
                    neqo_http3::Error::Transport(neqo_transport::Error::NotAvailable) => {
                        MissedSlotReason::KeysUnavailable
                    }
                    _ => MissedSlotReason::EndpointClosed,
                };
                controller.observe(QcsdObservation::SlotMissed {
                    endpoint: endpoint.id,
                    slot,
                    packet,
                    reason,
                });
                let miss_reason = format!("{reason:?}");
                traces.schedule(&ScheduleTraceRow {
                    action_time_us: traces.elapsed_us(now),
                    endpoint: endpoint_id,
                    packet,
                    satisfaction: "missed",
                    observed: None,
                    miss_reason: &miss_reason,
                    slot: Some(slot),
                })?;
            }
            traces.event(now, endpoint_id, "action", "failed", &error.to_string())?;
        }
    }
    Ok(())
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn process_output(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
) -> Result<Option<Duration>, Error> {
    loop {
        let output = endpoint
            .client
            .process_multiple_output(now, NonZeroUsize::MIN);
        let batch = match output {
            OutputBatch::DatagramBatch(batch) => batch,
            OutputBatch::Callback(delay) => return Ok(Some(delay)),
            OutputBatch::None => return Ok(None),
        };
        let mut satisfied_datagrams = handle_qcsd_observations(endpoint, controller, traces, now)?;
        for datagram in batch.iter() {
            let satisfied = satisfied_datagrams
                .iter()
                .position(|(_, observed_size)| *observed_size == datagram.len())
                .map(|index| satisfied_datagrams.remove(index));
            traces.packet(&PacketTraceRow {
                now,
                endpoint: endpoint.id,
                direction: "outgoing",
                observed: datagram.len(),
                scheduled: satisfied
                    .map(|(_, observed_size)| u16::try_from(observed_size).unwrap_or(u16::MAX)),
                satisfaction: satisfied.map_or("unshaped", |_| "satisfied"),
                slot: satisfied.map(|(slot, _)| slot),
            })?;
            controller.observe(QcsdObservation::Datagram {
                endpoint: endpoint.id,
                direction: Direction::Outgoing,
                length: u16::try_from(datagram.len()).unwrap_or(u16::MAX),
                timestamp_us: traces.elapsed_us(now),
            });
        }
        if let Some((slot, _)) = satisfied_datagrams.first() {
            return Err(Error::SlotInvariant(format!(
                "satisfied outgoing slot {} had no matching datagram",
                slot.0
            )));
        }
        loop {
            match endpoint.socket.send(&batch) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    endpoint.socket.writable().await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn process_input(
    endpoint: &mut Endpoint,
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
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
            controller.observe(QcsdObservation::Datagram {
                endpoint: endpoint.id,
                direction: Direction::Incoming,
                length: u16::try_from(datagram.len()).unwrap_or(u16::MAX),
                timestamp_us: traces.elapsed_us(now),
            });
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
                if record.role == QcsdRequestRole::Application && record.outcome == "in_flight" {
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

fn write_run_json(
    spec: &RunSpec,
    endpoints: &[Endpoint],
    responses: &[ResponseResult],
    started_unix_ns: u128,
    completion: &RunCompletion<'_>,
) -> Result<(), Error> {
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
        "seed": spec.seed,
        "method": spec.method,
        "workload_hash_sha256": spec.workload_hash,
        "resolved_header_policy": spec.workload.header_policy,
        "resolved_workload": spec.workload,
        "urls": spec.workload.resources.iter().map(|resource| &resource.url).collect::<Vec<_>>(),
        "max_response_bytes": spec.max_response_bytes,
        "time_anchor_unix_ns": started_unix_ns,
        "started_unix_ns": started_unix_ns,
        "ended_unix_ns": completion.ended_unix_ns,
        "defense_start_monotonic_ns": completion.defense_start_monotonic_ns,
        "application_completion_monotonic_ns": completion.application_completion_monotonic_ns,
        "completion_status": completion.status,
        "error": completion.error,
        "endpoints": endpoint_data,
        "responses": responses,
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
    use std::fs;

    use neqo_csdef::{DefenseConfig, FrontConfig, TamarawConfig};

    use super::{
        DefenseArg, Preset, ProfileArg, QcsdRequestRole, ResourceRunState, StaticModeArg,
        StreamRecord, finish_application_record, resolve_run_config,
    };

    fn application(status: Option<u16>, complete: bool) -> StreamRecord {
        StreamRecord {
            resource_id: 1,
            url: "https://example.com/resource".into(),
            role: QcsdRequestRole::Application,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            status,
            content_length: None,
            body: Vec::new(),
            bytes: 0,
            complete,
            outcome: "in_flight",
        }
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
    fn profile_cli_resolves_every_builtin_defense() {
        let front = resolve_run_config(
            None,
            None,
            Some(ProfileArg::Live),
            Some(DefenseArg::Front),
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
        )
        .expect("live Static profile");
        assert_eq!(
            static_config.defense,
            DefenseConfig::Static {
                schedule: "schedule.csv".into(),
                padding_only: true,
            }
        );
    }

    #[test]
    fn old_presets_remain_profile_aliases() {
        let front = resolve_run_config(None, Some(Preset::PublishedFront), None, None, None, None)
            .expect("compatibility preset");
        assert_eq!(front.defense, DefenseConfig::Front(FrontConfig::default()));
        let tamaraw =
            resolve_run_config(None, Some(Preset::PublishedTamaraw), None, None, None, None)
                .expect("published Tamaraw compatibility preset");
        assert_eq!(
            tamaraw.defense,
            DefenseConfig::Tamaraw(TamarawConfig::default())
        );
        let live = resolve_run_config(None, Some(Preset::ConservativeLive), None, None, None, None)
            .expect("conservative live compatibility preset");
        assert!(matches!(live.defense, DefenseConfig::Front(_)));
    }

    #[test]
    fn custom_toml_remains_available() {
        let path = std::env::temp_dir().join(format!(
            "neqo-qcsd-runner-config-{}.toml",
            std::process::id()
        ));
        fs::write(&path, "[defense]\nkind = \"none\"\n").expect("write custom config");
        let config = resolve_run_config(Some(&path), None, None, None, None, None)
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
            )
            .is_err()
        );
    }
}
