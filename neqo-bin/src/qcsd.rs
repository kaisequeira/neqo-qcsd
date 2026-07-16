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
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Priority};
use neqo_qcsd::{
    DefenseConfig, FrontConfig, MissedSlotReason, Packet, QcsdAction, QcsdConfig, QcsdController,
    QcsdEndpointId, QcsdObservation, QcsdRequestRole, Resource, ResourceManifest, TamarawConfig,
};
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
    Qcsd(#[from] neqo_qcsd::Error),
    #[error(transparent)]
    Qlog(#[from] qlog::Error),
    #[error(transparent)]
    Transport(#[from] neqo_transport::Error),
    #[error("run timed out after {0} seconds")]
    Timeout(u64),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Preset {
    PublishedFront,
    PublishedTamaraw,
    ConservativeLive,
}

impl Preset {
    fn resolve(self) -> QcsdConfig {
        match self {
            Self::PublishedFront => QcsdConfig {
                defense: DefenseConfig::Front(FrontConfig::default()),
                ..QcsdConfig::default()
            },
            Self::PublishedTamaraw => QcsdConfig {
                defense: DefenseConfig::Tamaraw(TamarawConfig::default()),
                ..QcsdConfig::default()
            },
            Self::ConservativeLive => QcsdConfig {
                max_chaff_streams: 2,
                low_watermark: 128 * 1024,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                defense: DefenseConfig::Front(FrontConfig {
                    n_client_packets: 32,
                    n_server_packets: 48,
                    packet_size: 1_200,
                    peak_minimum_seconds: 0.1,
                    peak_maximum_seconds: 1.0,
                }),
                ..QcsdConfig::default()
            },
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
        #[arg(required = true)]
        urls: Vec<Uri>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 1_048_576)]
        max_bytes: u64,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },
    /// Run baseline, Static, FRONT, or Tamaraw from a resolved configuration.
    Run {
        #[arg(required = true)]
        urls: Vec<Uri>,
        #[arg(long, conflicts_with = "preset", required_unless_present = "preset")]
        config: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            conflicts_with = "config",
            required_unless_present = "config"
        )]
        preset: Option<Preset>,
        #[arg(long)]
        manifest: Option<PathBuf>,
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
                output,
                max_bytes,
                timeout_seconds,
            } => probe(urls, &output, max_bytes, timeout_seconds).await,
            Command::Run {
                urls,
                config,
                preset,
                manifest,
                seed,
                output_dir,
                max_response_bytes,
                timeout_seconds,
            } => {
                let config = match (config, preset) {
                    (Some(path), None) => QcsdConfig::from_toml_file(path)?,
                    (None, Some(preset)) => preset.resolve(),
                    _ => {
                        return Err(Error::Argument(
                            "provide exactly one of --config or --preset".into(),
                        ));
                    }
                };
                config.validate()?;
                let manifest = manifest.map(ResourceManifest::from_json_file).transpose()?;
                if !matches!(config.defense, DefenseConfig::None) && manifest.is_none() {
                    return Err(Error::Argument(
                        "shaped runs require an explicit --manifest of same-origin chaff resources"
                            .into(),
                    ));
                }
                let spec = RunSpec {
                    urls,
                    method: "GET",
                    config,
                    manifest,
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

#[derive(Clone)]
struct RunSpec {
    urls: Vec<Uri>,
    method: &'static str,
    config: QcsdConfig,
    manifest: Option<ResourceManifest>,
    seed: u64,
    output_dir: PathBuf,
    max_response_bytes: u64,
    timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ResponseResult {
    url: String,
    status: Option<u16>,
    content_length: Option<u64>,
    bytes: u64,
    body_sha256: String,
    complete: bool,
}

#[derive(Debug)]
struct StreamRecord {
    url: String,
    role: QcsdRequestRole,
    status: Option<u16>,
    content_length: Option<u64>,
    body: Vec<u8>,
    bytes: u64,
    complete: bool,
}

struct Endpoint {
    id: QcsdEndpointId,
    origin: Uri,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    socket: Socket,
    recv_buf: RecvBuf,
    client: Http3Client,
    urls: VecDeque<Uri>,
    streams: HashMap<StreamId, StreamRecord>,
    completed: Vec<StreamRecord>,
    connected: bool,
    requests_started: bool,
    scheduled_outgoing: VecDeque<Packet>,
}

struct TraceFiles {
    packets: File,
    events: File,
    start: Instant,
}

impl TraceFiles {
    fn new(output_dir: &Path, start: Instant) -> Result<Self, Error> {
        let mut packets = File::create(output_dir.join("packets.csv"))?;
        writeln!(
            packets,
            "direction,monotonic_us,connection,observed_udp_length,scheduled_target,satisfaction"
        )?;
        let mut events = File::create(output_dir.join("events.csv"))?;
        writeln!(events, "monotonic_us,connection,event,outcome,details")?;
        Ok(Self {
            packets,
            events,
            start,
        })
    }

    fn elapsed_us(&self, now: Instant) -> u64 {
        u64::try_from(now.duration_since(self.start).as_micros()).unwrap_or(u64::MAX)
    }

    fn packet(
        &mut self,
        now: Instant,
        endpoint: QcsdEndpointId,
        direction: &str,
        observed: usize,
        scheduled: Option<u16>,
        satisfaction: &str,
    ) -> Result<(), Error> {
        writeln!(
            self.packets,
            "{direction},{},{},{observed},{},{satisfaction}",
            self.elapsed_us(now),
            endpoint.0,
            scheduled.map_or_else(String::new, |value| value.to_string())
        )?;
        Ok(())
    }

    fn event(
        &mut self,
        now: Instant,
        endpoint: Option<QcsdEndpointId>,
        event: &str,
        outcome: &str,
        details: &impl Serialize,
    ) -> Result<(), Error> {
        let details = serde_json::to_string(details)?.replace('"', "\"\"");
        writeln!(
            self.events,
            "{},{},{event},{outcome},\"{details}\"",
            self.elapsed_us(now),
            endpoint.map_or_else(String::new, |value| value.0.to_string())
        )?;
        Ok(())
    }
}

#[expect(
    clippy::future_not_send,
    reason = "the binary deliberately uses Tokio's current-thread runtime"
)]
async fn probe(
    urls: Vec<Uri>,
    output: &Path,
    max_bytes: u64,
    timeout_seconds: u64,
) -> Result<(), Error> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("manifest");
    let head_dir = parent.join(format!("{stem}.probe-head"));
    let head = execute_run(RunSpec {
        urls: urls.clone(),
        method: "HEAD",
        config: QcsdConfig::default(),
        manifest: None,
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
        .filter_map(|response| response.url.parse().ok())
        .collect();
    let fallback = if missing.is_empty() {
        Vec::new()
    } else {
        execute_run(RunSpec {
            urls: missing,
            method: "GET",
            config: QcsdConfig::default(),
            manifest: None,
            seed: 0,
            output_dir: parent.join(format!("{stem}.probe-get")),
            max_response_bytes: max_bytes,
            timeout_seconds,
        })
        .await?
    };
    let fallback: HashMap<_, _> = fallback
        .into_iter()
        .map(|response| (response.url.clone(), response))
        .collect();
    let resources = head
        .into_iter()
        .enumerate()
        .map(|(id, response)| {
            let response = fallback.get(&response.url).unwrap_or(&response);
            Resource {
                id: u32::try_from(id).unwrap_or(u32::MAX),
                url: response.url.clone(),
                kind: "Unknown".into(),
                content_length: response
                    .content_length
                    .or_else(|| (response.bytes > 0).then_some(response.bytes)),
                data_length: response.bytes,
                chaff_priority: false,
                known_valid: response
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
                    && response.complete,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }
        })
        .collect();
    let manifest = ResourceManifest {
        schema_version: 1,
        resources,
    };
    manifest.validate()?;
    fs::write(output, manifest.to_json_pretty()?)?;
    Ok(())
}

#[expect(
    clippy::future_not_send,
    clippy::too_many_lines,
    reason = "the current-thread runner keeps the connection and controller lifecycle in one event loop"
)]
async fn execute_run(spec: RunSpec) -> Result<Vec<ResponseResult>, Error> {
    validate_urls(&spec.urls)?;
    if spec.output_dir.exists() && fs::read_dir(&spec.output_dir)?.next().is_some() {
        return Err(Error::Argument(format!(
            "output directory must be empty: {}",
            spec.output_dir.display()
        )));
    }
    fs::create_dir_all(&spec.output_dir)?;
    fs::create_dir_all(spec.output_dir.join("qlog"))?;
    let wall_start = unix_millis();
    let process_start = now();
    let mut traces = TraceFiles::new(&spec.output_dir, process_start)?;
    let mut endpoints = create_endpoints(&spec, process_start)?;
    let mut controller =
        QcsdController::new(spec.config.clone(), spec.seed, spec.manifest.clone())?;
    let mut defense_start = None;
    let mut application_complete_observed = false;
    let deadline = process_start + Duration::from_secs(spec.timeout_seconds);

    loop {
        let loop_now = now();
        if loop_now >= deadline {
            for endpoint in &mut endpoints {
                while let Some(packet) = endpoint.scheduled_outgoing.pop_front() {
                    let observation = QcsdObservation::SlotMissed {
                        endpoint: endpoint.id,
                        packet,
                        reason: MissedSlotReason::CongestionLimited,
                    };
                    traces.event(
                        loop_now,
                        Some(endpoint.id),
                        "observation",
                        "deadline_expired",
                        &observation,
                    )?;
                }
            }
            write_run_json(&spec, &endpoints, &[], wall_start, unix_millis(), "timeout")?;
            return Err(Error::Timeout(spec.timeout_seconds));
        }

        for endpoint in &mut endpoints {
            handle_http_events(endpoint, &spec, loop_now, &mut traces)?;
        }

        if defense_start.is_none() && endpoints.iter().all(|endpoint| endpoint.connected) {
            defense_start = Some(loop_now);
            for endpoint in &mut endpoints {
                start_requests(endpoint, &spec, loop_now)?;
            }
        }

        if let Some(defense_start) = defense_start {
            for endpoint in &mut endpoints {
                for observation in endpoint.client.qcsd_observations() {
                    traces.event(
                        loop_now,
                        Some(endpoint.id),
                        "observation",
                        "recorded",
                        &observation,
                    )?;
                    controller.observe(observation);
                }
            }
            if !application_complete_observed && applications_done(&endpoints) {
                application_complete_observed = true;
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

    let mut responses = Vec::new();
    for endpoint in &mut endpoints {
        endpoint
            .completed
            .extend(endpoint.streams.drain().map(|(_, value)| value));
        for record in &endpoint.completed {
            if record.role == QcsdRequestRole::Application {
                responses.push(response_result(record)?);
            }
        }
    }
    write_run_json(
        &spec,
        &endpoints,
        &responses,
        wall_start,
        unix_millis(),
        "complete",
    )?;
    Ok(responses)
}

fn validate_urls(urls: &[Uri]) -> Result<(), Error> {
    if urls.is_empty() {
        return Err(Error::Argument("at least one URL is required".into()));
    }
    for url in urls {
        if url.scheme_str() != Some("https") || url.authority().is_none() {
            return Err(Error::Argument(format!(
                "URL must be absolute HTTPS: {url}"
            )));
        }
    }
    Ok(())
}

fn create_endpoints(spec: &RunSpec, start: Instant) -> Result<Vec<Endpoint>, Error> {
    let mut grouped = BTreeMap::<(String, u16), VecDeque<Uri>>::new();
    for url in &spec.urls {
        let authority = url.authority().expect("validated");
        grouped
            .entry((
                authority.host().to_owned(),
                authority.port_u16().unwrap_or(443),
            ))
            .or_default()
            .push_back(url.clone());
    }
    grouped
        .into_iter()
        .enumerate()
        .map(|(index, ((host, port), urls))| {
            let remote_addr = format!("{host}:{port}")
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| Error::Argument(format!("could not resolve {host}:{port}")))?;
            let bind_addr = match remote_addr {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
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
                urls.front()
                    .expect("nonempty")
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
            )?;
            Ok(Endpoint {
                id: endpoint_id,
                origin,
                remote_addr,
                local_addr,
                socket,
                recv_buf: RecvBuf::default(),
                client,
                urls,
                streams: HashMap::new(),
                completed: Vec::new(),
                connected: false,
                requests_started: false,
                scheduled_outgoing: VecDeque::new(),
            })
        })
        .collect()
}

fn start_requests(endpoint: &mut Endpoint, spec: &RunSpec, now: Instant) -> Result<(), Error> {
    if endpoint.requests_started {
        return Ok(());
    }
    endpoint.requests_started = true;
    while let Some(url) = endpoint.urls.pop_front() {
        let stream = endpoint
            .client
            .fetch(now, spec.method, &url, &[], Priority::default())?;
        endpoint
            .client
            .register_qcsd_stream(stream, QcsdRequestRole::Application)?;
        endpoint.client.stream_close_send(stream, now)?;
        endpoint.streams.insert(
            stream,
            StreamRecord {
                url: url.to_string(),
                role: QcsdRequestRole::Application,
                status: None,
                content_length: None,
                body: Vec::new(),
                bytes: 0,
                complete: false,
            },
        );
    }
    Ok(())
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
            }
            Http3ClientEvent::HeaderReady {
                stream_id,
                headers,
                fin,
                ..
            } => {
                if let Some(record) = endpoint.streams.get_mut(&stream_id) {
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
    if let Some(record) = endpoint.streams.remove(&stream_id) {
        endpoint.completed.push(record);
    }
}

fn header_u64(headers: &[Header], name: &str) -> Option<u64> {
    headers
        .iter()
        .find(|header| header.name().eq_ignore_ascii_case(name))
        .and_then(|header| header.value_utf8().ok())
        .and_then(|value| value.parse().ok())
}

fn applications_done(endpoints: &[Endpoint]) -> bool {
    endpoints.iter().all(|endpoint| {
        endpoint.requests_started
            && endpoint.urls.is_empty()
            && !endpoint
                .streams
                .values()
                .any(|record| record.role == QcsdRequestRole::Application)
    })
}

const fn action_endpoint(action: &QcsdAction) -> Option<QcsdEndpointId> {
    match action {
        QcsdAction::ConfigureManualReceive { endpoint, .. }
        | QcsdAction::ConfigureAutomaticReceive { endpoint, .. }
        | QcsdAction::IncreaseReceiveLimit { endpoint, .. }
        | QcsdAction::IncreaseSendBudget { endpoint, .. }
        | QcsdAction::SendPacket { endpoint, .. }
        | QcsdAction::RequestChaff { endpoint, .. }
        | QcsdAction::KeepAlive { endpoint } => Some(*endpoint),
        QcsdAction::SlotMissed { endpoint, .. } => *endpoint,
        QcsdAction::DefenseComplete => None,
    }
}

fn apply_action(
    endpoints: &mut [Endpoint],
    controller: &mut QcsdController,
    traces: &mut TraceFiles,
    now: Instant,
    action: QcsdAction,
) -> Result<(), Error> {
    let endpoint_id = action_endpoint(&action);
    if let QcsdAction::SlotMissed { .. } | QcsdAction::DefenseComplete = &action {
        traces.event(now, endpoint_id, "action", "recorded", &action)?;
        return Ok(());
    }
    let Some(endpoint) = endpoints
        .iter_mut()
        .find(|candidate| Some(candidate.id) == endpoint_id)
    else {
        traces.event(now, endpoint_id, "action", "missing_endpoint", &action)?;
        return Ok(());
    };
    let trace_action = action.clone();
    let scheduled_packet = match &trace_action {
        QcsdAction::SendPacket { packet, .. } => Some(*packet),
        _ => None,
    };
    match endpoint.client.apply_qcsd_action(now, action) {
        Ok(chaff_stream) => {
            if let Some(packet) = scheduled_packet {
                endpoint.scheduled_outgoing.push_back(packet);
            }
            if let Some(stream_id) = chaff_stream {
                let (resource_id, url) = match &trace_action {
                    QcsdAction::RequestChaff { resource, .. } => {
                        (resource.id, resource.url.clone())
                    }
                    _ => unreachable!("only chaff actions return a stream"),
                };
                endpoint.client.stream_close_send(stream_id, now)?;
                endpoint.streams.insert(
                    stream_id,
                    StreamRecord {
                        url,
                        role: QcsdRequestRole::Chaff { resource_id },
                        status: None,
                        content_length: None,
                        body: Vec::new(),
                        bytes: 0,
                        complete: false,
                    },
                );
                // Apply manual receive control before the newly created chaff
                // request is eligible for its first transport output.
                for observation in endpoint.client.qcsd_observations() {
                    traces.event(
                        now,
                        Some(endpoint.id),
                        "observation",
                        "recorded",
                        &observation,
                    )?;
                    controller.observe(observation);
                }
            }
            traces.event(now, endpoint_id, "action", "applied", &trace_action)?;
        }
        Err(error) => {
            let reason = match (&trace_action, &error) {
                (
                    QcsdAction::SendPacket { .. },
                    neqo_http3::Error::Transport(neqo_transport::Error::InvalidInput),
                ) => MissedSlotReason::PathMtu,
                _ => MissedSlotReason::EndpointClosed,
            };
            if let QcsdAction::SendPacket { packet, .. }
            | QcsdAction::IncreaseReceiveLimit { packet, .. }
            | QcsdAction::IncreaseSendBudget { packet, .. } = trace_action
            {
                controller.observe(QcsdObservation::SlotMissed {
                    endpoint: endpoint.id,
                    packet,
                    reason,
                });
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
        for datagram in batch.iter() {
            let scheduled = endpoint.scheduled_outgoing.front().copied();
            let satisfaction = scheduled.map_or("unshaped", |packet| {
                if usize::from(packet.length()) == datagram.len() {
                    "satisfied"
                } else {
                    "deferred"
                }
            });
            traces.packet(
                now,
                endpoint.id,
                "outgoing",
                datagram.len(),
                scheduled.map(Packet::length),
                satisfaction,
            )?;
            controller.observe(QcsdObservation::Datagram {
                endpoint: endpoint.id,
                direction: neqo_qcsd::Direction::Outgoing,
                length: u16::try_from(datagram.len()).unwrap_or(u16::MAX),
                timestamp_us: traces.elapsed_us(now),
            });
            if satisfaction == "satisfied" {
                endpoint.scheduled_outgoing.pop_front();
            }
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
            traces.packet(
                now,
                endpoint.id,
                "incoming",
                datagram.len(),
                None,
                "observed",
            )?;
            controller.observe(QcsdObservation::Datagram {
                endpoint: endpoint.id,
                direction: neqo_qcsd::Direction::Incoming,
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
        url: record.url.clone(),
        status: record.status,
        content_length: record.content_length,
        bytes: record.bytes,
        body_sha256: hex::encode(nss::hash::hash(&HashAlgorithm::SHA2_256, &record.body)?),
        complete: record.complete,
    })
}

fn write_run_json(
    spec: &RunSpec,
    endpoints: &[Endpoint],
    responses: &[ResponseResult],
    started_unix_ms: u128,
    ended_unix_ms: u128,
    status: &str,
) -> Result<(), Error> {
    let endpoint_data: Vec<_> = endpoints
        .iter()
        .map(|endpoint| {
            json!({
                "id": endpoint.id.0,
                "origin": endpoint.origin.to_string(),
                "remote_address": endpoint.remote_addr.to_string(),
                "negotiated_protocol": endpoint.client.tls_info().and_then(|info| info.alpn()),
                "transport_stats": format!("{:?}", endpoint.client.transport_stats()),
            })
        })
        .collect();
    let run = json!({
        "schema_version": 1,
        "neqo_version": env!("CARGO_PKG_VERSION"),
        "neqo_base_commit": NEQO_BASE_COMMIT,
        "published_qcsd_commit": PUBLISHED_QCSD_COMMIT,
        "migration_commit": option_env!("NEQO_QCSD_GIT_COMMIT").unwrap_or("working-tree"),
        "resolved_configuration": spec.config,
        "seed": spec.seed,
        "method": spec.method,
        "urls": spec.urls.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "max_response_bytes": spec.max_response_bytes,
        "started_unix_ms": started_unix_ms,
        "ended_unix_ms": ended_unix_ms,
        "completion_status": status,
        "endpoints": endpoint_data,
        "responses": responses,
    });
    fs::write(
        spec.output_dir.join("run.json"),
        serde_json::to_string_pretty(&run)?,
    )?;
    Ok(())
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

fn now() -> Instant {
    #![expect(
        clippy::disallowed_methods,
        reason = "research traces require monotonic wall time"
    )]
    Instant::now()
}
