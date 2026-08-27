// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

mod control_loop;

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::Duration,
};

use control_loop::{ControlLoop, PendingClaim, PendingCredit, PendingIncoming, PendingOutgoing};

use crate::{
    Buflo, Capacity, CapacityAdjustment, CsBuflo, Defense, DefenseConfig, DefenseDiagnostics,
    DefenseMode, DefenseSignal, Direction, EventOutcome, Front, MissedSlotReason, QcsdAction,
    QcsdChaffCancellationReason, QcsdConfig, QcsdEndpointId, QcsdObservation, QcsdParserLeaseOwner,
    QcsdPrearmCancellationReason, QcsdReceiveActionIdentity, QcsdRequestRole, QcsdSlotId,
    QcsdStreamId, ResourceManifest, Result, RoundRobinScheduler, SignalKind, StaticSchedule,
    Tamaraw, TrafficMorphing, WalkieTalkie, WtfPad, chaff_manager::ChaffManager,
    stream::StreamRegistry,
};

/// Exact controller bookkeeping canceled after a typed receive-lifecycle rejection.
///
/// Canceled slots remain non-terminal and can be reassigned unless the
/// configured drop policy explicitly terminalizes them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QcsdReceiveCancellation {
    canceled_actions: Vec<QcsdReceiveActionIdentity>,
    canceled_slots: Vec<QcsdSlotId>,
}

/// Pure, opaque transaction for canceling one or more unavailable receive streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QcsdReceiveCancellationPlan {
    rejections: Vec<(QcsdEndpointId, QcsdStreamId, Vec<QcsdReceiveActionIdentity>)>,
    cancellation: QcsdReceiveCancellation,
    restored_limits: Vec<(QcsdEndpointId, QcsdStreamId, u64)>,
    retained_actions: Vec<QcsdReceiveActionIdentity>,
    canceled_configurations: Vec<QcsdAction>,
}

impl QcsdReceiveCancellationPlan {
    /// Exact action identities the transaction will cancel.
    #[must_use]
    pub fn canceled_actions(&self) -> &[QcsdReceiveActionIdentity] {
        self.cancellation.canceled_actions()
    }

    /// Complete transitive slot closure the transaction will return or retire.
    #[must_use]
    pub fn canceled_slots(&self) -> &[QcsdSlotId] {
        self.cancellation.canceled_slots()
    }

    /// Per-stream absolute receive boundary after the planned rollback.
    #[must_use]
    pub fn restored_limits(&self) -> &[(QcsdEndpointId, QcsdStreamId, u64)] {
        &self.restored_limits
    }

    /// Unadvertised prefix identities retained on transitively affected streams.
    #[must_use]
    pub fn retained_actions(&self) -> &[QcsdReceiveActionIdentity] {
        &self.retained_actions
    }

    /// Queued receive configurations removed for directly rejected streams.
    #[must_use]
    pub fn canceled_configurations(&self) -> &[QcsdAction] {
        &self.canceled_configurations
    }
}

const fn receive_configuration_target(
    action: &QcsdAction,
) -> Option<(QcsdEndpointId, QcsdStreamId)> {
    match action {
        QcsdAction::ConfigureManualReceive {
            endpoint, stream, ..
        }
        | QcsdAction::ConfigureAutomaticReceive {
            endpoint, stream, ..
        } => Some((*endpoint, *stream)),
        _ => None,
    }
}

impl QcsdReceiveCancellation {
    /// Exact action identities removed from the controller ledger and queue.
    #[must_use]
    pub fn canceled_actions(&self) -> &[QcsdReceiveActionIdentity] {
        &self.canceled_actions
    }

    /// Logical slots whose credit or claims were returned or retired.
    #[must_use]
    pub fn canceled_slots(&self) -> &[QcsdSlotId] {
        &self.canceled_slots
    }
}

#[derive(Clone, Copy, Debug)]
enum QueuedDefenseObservation {
    Signal(DefenseSignal),
    ApplicationBytes {
        at: Duration,
        direction: Direction,
        bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StagedFixedEvent {
    packet: crate::Packet,
    slot: QcsdSlotId,
}

#[derive(Debug)]
struct FixedScheduleStaging {
    events: VecDeque<StagedFixedEvent>,
    outgoing_prearmed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RollingOutgoingPrearm {
    endpoint: QcsdEndpointId,
    packet: crate::Packet,
    slot: QcsdSlotId,
}

fn duration_as_ceil_micros(duration: Duration) -> u64 {
    let micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
    if duration.subsec_nanos().is_multiple_of(1_000) {
        micros
    } else {
        micros.saturating_add(1)
    }
}

fn duration_as_floor_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl QueuedDefenseObservation {
    const fn at(self) -> Duration {
        match self {
            Self::Signal(signal) => signal.at,
            Self::ApplicationBytes { at, .. } => at,
        }
    }
}

fn covered_range_bytes(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().fold(0_u64, |total, (start, end)| {
        total.saturating_add(end.saturating_sub(*start))
    })
}

fn merge_ranges(ranges: &mut Vec<(u64, u64)>) {
    if ranges.is_empty() {
        return;
    }
    let mut merged_index = 0;
    for candidate_index in 1..ranges.len() {
        let candidate = ranges[candidate_index];
        if candidate.0 <= ranges[merged_index].1 {
            ranges[merged_index].1 = ranges[merged_index].1.max(candidate.1);
        } else {
            merged_index += 1;
            ranges[merged_index] = candidate;
        }
    }
    ranges.truncate(merged_index + 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdvertisedIncomingCredit {
    slot: QcsdSlotId,
    start: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParserLeaseRange {
    start: u64,
    end: u64,
    owner: Option<QcsdParserLeaseOwner>,
    unowned: bool,
    advertised: bool,
}

impl ParserLeaseRange {
    const fn bytes(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

impl AdvertisedIncomingCredit {
    const fn bytes(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Clone, Copy, Debug)]
enum UnadvertisedReceiveRange {
    Scheduled(PendingCredit),
    Parser {
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        range: ParserLeaseRange,
    },
}

impl UnadvertisedReceiveRange {
    const fn endpoint(self) -> QcsdEndpointId {
        match self {
            Self::Scheduled(credit) => credit.endpoint,
            Self::Parser { endpoint, .. } => endpoint,
        }
    }

    const fn stream(self) -> QcsdStreamId {
        match self {
            Self::Scheduled(credit) => credit.stream,
            Self::Parser { stream, .. } => stream,
        }
    }

    const fn start(self) -> u64 {
        match self {
            Self::Scheduled(credit) => credit.absolute_limit.saturating_sub(credit.increase),
            Self::Parser { range, .. } => range.start,
        }
    }

    const fn absolute_limit(self) -> u64 {
        match self {
            Self::Scheduled(credit) => credit.absolute_limit,
            Self::Parser { range, .. } => range.end,
        }
    }

    const fn identity(self) -> QcsdReceiveActionIdentity {
        match self {
            Self::Scheduled(credit) => QcsdReceiveActionIdentity::Scheduled {
                endpoint: credit.endpoint,
                stream: credit.stream,
                absolute_limit: credit.absolute_limit,
                slot: credit.slot,
            },
            Self::Parser {
                endpoint,
                stream,
                range,
            } => QcsdReceiveActionIdentity::ParserLease {
                endpoint,
                stream,
                absolute_limit: range.end,
                increase: range.bytes(),
                owner: range.owner,
            },
        }
    }

    const fn slot(self) -> Option<QcsdSlotId> {
        self.identity().slot()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IncomingCreditLedger {
    packet: crate::Packet,
    endpoint: Option<QcsdEndpointId>,
    multiple_endpoints: bool,
    advertised: u64,
    local_realization_emitted: bool,
    consumed: u64,
    retired: u64,
}

impl IncomingCreditLedger {
    const fn new(packet: crate::Packet) -> Self {
        Self {
            packet,
            endpoint: None,
            multiple_endpoints: false,
            advertised: 0,
            local_realization_emitted: false,
            consumed: 0,
            retired: 0,
        }
    }

    fn requested(self) -> u64 {
        u64::from(self.packet.length())
    }

    fn unresolved(self) -> u64 {
        self.requested()
            .saturating_sub(self.consumed)
            .saturating_sub(self.retired)
    }

    fn assign_endpoint(&mut self, endpoint: QcsdEndpointId) {
        match self.endpoint {
            None if !self.multiple_endpoints => self.endpoint = Some(endpoint),
            Some(current) if current != endpoint => {
                self.endpoint = None;
                self.multiple_endpoints = true;
            }
            None | Some(_) => {}
        }
    }

    const fn action_endpoint(self) -> Option<QcsdEndpointId> {
        if self.multiple_endpoints {
            None
        } else {
            self.endpoint
        }
    }
}

/// Orchestrates one defense across one or more client connections.
///
/// This is the single-owner modern equivalent of the published `FlowShaper`.
/// It deliberately contains no Neqo types or synchronization primitives.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "The booleans are independent controller lifecycle proofs, not one shared state machine."
)]
pub struct QcsdController {
    config: QcsdConfig,
    defense: Box<dyn Defense>,
    scheduler: RoundRobinScheduler,
    endpoint_origins: HashMap<QcsdEndpointId, String>,
    streams: StreamRegistry,
    chaff: Option<ChaffManager>,
    control: ControlLoop,
    actions: VecDeque<QcsdAction>,
    observations: VecDeque<QueuedDefenseObservation>,
    application_stream_ranges: HashMap<(QcsdEndpointId, QcsdStreamId), Vec<(u64, u64)>>,
    chaff_stream_ranges: HashMap<(QcsdEndpointId, QcsdStreamId), Vec<(u64, u64)>>,
    advertised_incoming_credit:
        HashMap<(QcsdEndpointId, QcsdStreamId), Vec<AdvertisedIncomingCredit>>,
    /// Physically slotless receive ranges granted solely to keep the HTTP/3
    /// parser live. A post-cap range can carry provisional scheduling
    /// ownership internally, but the public action remains slotless and only
    /// consumed overlap can realize that owner. Merely granting or advertising
    /// a lease never satisfies scheduled work.
    parser_lease_ranges: HashMap<(QcsdEndpointId, QcsdStreamId), Vec<ParserLeaseRange>>,
    incoming_credit_ledger: HashMap<QcsdSlotId, IncomingCreditLedger>,
    scheduled_incoming_requested_bytes: u64,
    /// Scheduled ownership currently backed by physically advertised receive
    /// capacity. Unconsumed parser ownership is removed again if its stream
    /// closes and the same slot must be retried elsewhere.
    scheduled_incoming_advertised_bytes: u64,
    scheduled_incoming_consumed_bytes: u64,
    scheduled_incoming_retired_bytes: u64,
    last_capacity: Option<Capacity>,
    last_delivered_observation_at: Option<Duration>,
    pending_slots: HashMap<QcsdSlotId, crate::Packet>,
    application_complete: bool,
    /// Whether the application-complete signal has crossed the ordered
    /// defense-observation boundary.  `application_complete` is set when the
    /// runner queues the observation, which is intentionally too early to
    /// decide whether a preceding signal latched CS-BuFLO local termination.
    application_complete_delivered_to_defense: bool,
    adapter_egress_backlog_pending: bool,
    last_effective_egress_backlog_pending: Option<bool>,
    buflo_terminal_subcell_pending_request_cancellations: u64,
    buflo_terminal_subcell_stream_cancellations: u64,
    buflo_terminal_subcell_exact_capacity_bytes_cancelled: u64,
    buflo_terminal_subcell_latched_at_us: Option<u64>,
    buflo_terminal_subcell_open_streams_at_latch: u64,
    buflo_terminal_subcell_parser_lease_bytes_at_latch: u64,
    buflo_terminal_subcell_pending_parser_boundaries_at_latch: u64,
    buflo_terminal_subcell_pending_application_parser_boundaries_at_latch: u64,
    cs_buflo_local_et_pending_request_cancellations: u64,
    cs_buflo_local_et_stream_cancellations: u64,
    cs_buflo_application_passthrough: bool,
    cs_buflo_local_et_before_application_complete: bool,
    cs_buflo_local_et_application_receive_streams_handed_off: u64,
    cs_buflo_local_et_application_parser_boundaries_handed_off: u64,
    cs_buflo_local_et_application_parser_lease_bytes_handed_off: u64,
    cs_buflo_local_et_application_send_endpoints_released: u64,
    completion_emitted: bool,
    completion_due: Option<Duration>,
    released_chaff_send_shaping: HashSet<QcsdEndpointId>,
    released_application_send_shaping: HashSet<QcsdEndpointId>,
    /// FRONT-only frozen schedule. Outgoing targets are publicly staged, but
    /// incoming entries remain private here until their exact release time.
    fixed_schedule: Option<FixedScheduleStaging>,
    /// One pure future `BuFLO` preview staged in transport. It is not a defense
    /// event or pending slot until committed at its release boundary.
    rolling_outgoing_prearm: Option<RollingOutgoingPrearm>,
    /// A closed endpoint abandoned a preview at or after its release. The
    /// runner consumes this marker only after its complete globally ordered
    /// observation batch has reached the controller.
    rolling_reconcile_due: Option<crate::Packet>,
}

impl QcsdController {
    /// Construct a controller from a built-in resolved configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, manifests, or schedules.
    pub fn new(config: QcsdConfig, seed: u64, resources: Option<ResourceManifest>) -> Result<Self> {
        config.validate()?;
        let enable_chaff = !matches!(config.defense, DefenseConfig::None);
        let max_udp_payload_size = config.max_udp_payload_size;
        let max_stream_data_excess = config.max_stream_data_excess;
        let defense: Box<dyn Defense> = match &config.defense {
            DefenseConfig::None => Box::new(StaticSchedule::new(crate::Trace::default(), true)),
            DefenseConfig::Static {
                schedule,
                padding_only,
            } => Box::new(StaticSchedule::from_legacy_csv(schedule, *padding_only)?),
            DefenseConfig::Front(front) => Box::new(Front::new(front, seed)),
            DefenseConfig::Tamaraw(tamaraw) => Box::new(Tamaraw::new(tamaraw)),
            DefenseConfig::Buflo(config) => Box::new(Buflo::new(config, max_udp_payload_size)?),
            DefenseConfig::CsBuflo(config) => {
                Box::new(CsBuflo::new(config, seed, max_udp_payload_size)?)
            }
            DefenseConfig::TrafficMorphing(config) => {
                Box::new(TrafficMorphing::new(config, seed, max_udp_payload_size)?)
            }
            DefenseConfig::WtfPad(config) => {
                Box::new(WtfPad::new(config, seed, max_udp_payload_size)?)
            }
            DefenseConfig::WalkieTalkie(config) => Box::new(WalkieTalkie::new(
                config,
                max_udp_payload_size,
                max_stream_data_excess,
            )?),
        };
        Self::build(config, resources, defense, enable_chaff)
    }

    /// Construct a controller around a programmatic defense implementation.
    ///
    /// This keeps new research defenses independent of [`DefenseConfig`]. The
    /// supplied configuration still controls the common flow shaper policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid common configuration or resource input.
    pub fn with_defense(
        config: QcsdConfig,
        resources: Option<ResourceManifest>,
        defense: Box<dyn Defense>,
    ) -> Result<Self> {
        config.validate()?;
        Self::build(config, resources, defense, true)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Explicitly initializing every controller proof and counter makes the fail-closed defaults auditable."
    )]
    fn build(
        config: QcsdConfig,
        resources: Option<ResourceManifest>,
        defense: Box<dyn Defense>,
        enable_chaff: bool,
    ) -> Result<Self> {
        if let Some(resources) = &resources {
            resources.validate()?;
        }
        let max_reserve_horizon = defense.max_receiver_continuation_reserve_horizon();
        if max_reserve_horizon > 0 {
            if config.use_empty_resources {
                return Err(crate::Error::InvalidConfig(
                    "Walkie-Talkie receiver continuations require positive-length chaff resources; use_empty_resources is unsupported".into(),
                ));
            }
            let continuation_bytes =
                defense.receiver_continuation_cell_bytes().ok_or_else(|| {
                    crate::Error::InvalidConfig(
                        "receiver-continuation defense did not expose its exact cell size".into(),
                    )
                })?;
            if !resources.as_ref().is_some_and(|manifest| {
                manifest.has_structural_initial_chaff_candidate(continuation_bytes)
            }) {
                return Err(crate::Error::InvalidConfig(format!(
                    "Walkie-Talkie manifest must contain an initially eligible chaff response of at least {continuation_bytes} bytes"
                )));
            }
        }
        let chaff = resources
            .filter(|_| enable_chaff)
            .map(|manifest| ChaffManager::new(manifest, config.use_empty_resources));
        let required_chaff_streams = max_reserve_horizon.checked_add(1).ok_or_else(|| {
            crate::Error::InvalidConfig(
                "Walkie-Talkie receiver-continuation reserve horizon overflows usize".into(),
            )
        })?;
        if max_reserve_horizon > 0 && required_chaff_streams > config.max_chaff_streams {
            return Err(crate::Error::InvalidConfig(format!(
                "Walkie-Talkie receiver-continuation reserve horizon {max_reserve_horizon} requires at least {required_chaff_streams} configured chaff streams, but max_chaff_streams is {}",
                config.max_chaff_streams
            )));
        }
        let mut control = ControlLoop::default();
        let fixed_schedule = defense.fixed_schedule_snapshot().map(|packets| {
            let events = packets
                .into_iter()
                .map(|packet| StagedFixedEvent {
                    packet,
                    slot: control.next_slot(),
                })
                .collect();
            FixedScheduleStaging {
                events,
                outgoing_prearmed: false,
            }
        });
        Ok(Self {
            config,
            defense,
            scheduler: RoundRobinScheduler::empty(),
            endpoint_origins: HashMap::new(),
            streams: StreamRegistry::default(),
            chaff,
            control,
            actions: VecDeque::new(),
            observations: VecDeque::new(),
            application_stream_ranges: HashMap::new(),
            chaff_stream_ranges: HashMap::new(),
            advertised_incoming_credit: HashMap::new(),
            parser_lease_ranges: HashMap::new(),
            incoming_credit_ledger: HashMap::new(),
            scheduled_incoming_requested_bytes: 0,
            scheduled_incoming_advertised_bytes: 0,
            scheduled_incoming_consumed_bytes: 0,
            scheduled_incoming_retired_bytes: 0,
            last_capacity: None,
            last_delivered_observation_at: None,
            pending_slots: HashMap::new(),
            application_complete: false,
            application_complete_delivered_to_defense: false,
            adapter_egress_backlog_pending: true,
            last_effective_egress_backlog_pending: None,
            buflo_terminal_subcell_pending_request_cancellations: 0,
            buflo_terminal_subcell_stream_cancellations: 0,
            buflo_terminal_subcell_exact_capacity_bytes_cancelled: 0,
            buflo_terminal_subcell_latched_at_us: None,
            buflo_terminal_subcell_open_streams_at_latch: 0,
            buflo_terminal_subcell_parser_lease_bytes_at_latch: 0,
            buflo_terminal_subcell_pending_parser_boundaries_at_latch: 0,
            buflo_terminal_subcell_pending_application_parser_boundaries_at_latch: 0,
            cs_buflo_local_et_pending_request_cancellations: 0,
            cs_buflo_local_et_stream_cancellations: 0,
            cs_buflo_application_passthrough: false,
            cs_buflo_local_et_before_application_complete: false,
            cs_buflo_local_et_application_receive_streams_handed_off: 0,
            cs_buflo_local_et_application_parser_boundaries_handed_off: 0,
            cs_buflo_local_et_application_parser_lease_bytes_handed_off: 0,
            cs_buflo_local_et_application_send_endpoints_released: 0,
            completion_emitted: false,
            completion_due: None,
            released_chaff_send_shaping: HashSet::new(),
            released_application_send_shaping: HashSet::new(),
            fixed_schedule,
            rolling_outgoing_prearm: None,
            rolling_reconcile_due: None,
        })
    }

    /// Resolved configuration used for the run.
    #[must_use]
    pub const fn config(&self) -> &QcsdConfig {
        &self.config
    }

    /// Defense-specific runtime counters for the run artifact.
    #[must_use]
    pub fn defense_diagnostics(&self) -> DefenseDiagnostics {
        let mut diagnostics = self.defense.diagnostics();
        let unresolved = self
            .incoming_credit_ledger
            .values()
            .fold(0_u64, |total, ledger| {
                total.saturating_add(ledger.unresolved())
            });
        debug_assert_eq!(
            self.scheduled_incoming_requested_bytes,
            self.scheduled_incoming_consumed_bytes
                .saturating_add(self.scheduled_incoming_retired_bytes)
                .saturating_add(unresolved),
            "scheduled incoming-credit accounting must conserve bytes"
        );
        debug_assert!(
            self.scheduled_incoming_advertised_bytes <= self.scheduled_incoming_requested_bytes,
            "advertised scheduled incoming credit cannot exceed requested credit"
        );
        debug_assert!(
            self.scheduled_incoming_consumed_bytes <= self.scheduled_incoming_advertised_bytes,
            "consumed scheduled incoming credit must have been locally advertised"
        );
        debug_assert!(
            self.incoming_credit_ledger
                .values()
                .all(|ledger| ledger.consumed <= ledger.advertised),
            "each live incoming slot must advertise scheduled credit before consuming it"
        );
        diagnostics.scheduled_incoming_requested_bytes = self.scheduled_incoming_requested_bytes;
        diagnostics.scheduled_incoming_advertised_bytes = self.scheduled_incoming_advertised_bytes;
        diagnostics.scheduled_incoming_consumed_bytes = self.scheduled_incoming_consumed_bytes;
        diagnostics.scheduled_incoming_retired_bytes = self.scheduled_incoming_retired_bytes;
        diagnostics.scheduled_incoming_unresolved_bytes = unresolved;
        diagnostics.buflo_terminal_subcell_pending_request_cancellations =
            self.buflo_terminal_subcell_pending_request_cancellations;
        diagnostics.buflo_terminal_subcell_stream_cancellations =
            self.buflo_terminal_subcell_stream_cancellations;
        diagnostics.buflo_terminal_subcell_exact_capacity_bytes_cancelled =
            self.buflo_terminal_subcell_exact_capacity_bytes_cancelled;
        diagnostics.buflo_terminal_subcell_latched =
            self.buflo_terminal_subcell_latched_at_us.is_some();
        diagnostics.buflo_terminal_subcell_latched_at_us = self
            .buflo_terminal_subcell_latched_at_us
            .unwrap_or_default();
        diagnostics.buflo_terminal_subcell_open_streams_at_latch =
            self.buflo_terminal_subcell_open_streams_at_latch;
        diagnostics.buflo_terminal_subcell_parser_lease_bytes_at_latch =
            self.buflo_terminal_subcell_parser_lease_bytes_at_latch;
        diagnostics.buflo_terminal_subcell_pending_parser_boundaries_at_latch =
            self.buflo_terminal_subcell_pending_parser_boundaries_at_latch;
        diagnostics.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch =
            self.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch;
        diagnostics.cs_buflo_local_et_pending_request_cancellations =
            self.cs_buflo_local_et_pending_request_cancellations;
        diagnostics.cs_buflo_local_et_stream_cancellations =
            self.cs_buflo_local_et_stream_cancellations;
        diagnostics.cs_buflo_local_et_before_application_complete =
            self.cs_buflo_local_et_before_application_complete;
        diagnostics.cs_buflo_local_et_application_receive_streams_handed_off =
            self.cs_buflo_local_et_application_receive_streams_handed_off;
        diagnostics.cs_buflo_local_et_application_parser_boundaries_handed_off =
            self.cs_buflo_local_et_application_parser_boundaries_handed_off;
        diagnostics.cs_buflo_local_et_application_parser_lease_bytes_handed_off =
            self.cs_buflo_local_et_application_parser_lease_bytes_handed_off;
        diagnostics.cs_buflo_local_et_application_send_endpoints_released =
            self.cs_buflo_local_et_application_send_endpoints_released;
        diagnostics
    }

    /// Whether the selected defense permits opening another application batch.
    #[must_use]
    pub fn can_start_application_batch(&self) -> bool {
        // A CS-BuFLO quiet-time decision is irreversible.  Do not admit a
        // dependent request in the interval between causally reducing the
        // observation that latched local termination and polling the
        // controller actions that hand application traffic back to Neqo.
        if self.defense.is_complete()
            && self.defense.terminal_chaff_cancellation_reason()
                == Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination)
            && !self.cs_buflo_application_passthrough
        {
            return false;
        }
        self.defense.can_start_application_batch()
    }

    /// Reduce every queued defense observation without polling for new work.
    ///
    /// The runner uses this boundary before application dispatch so a terminal
    /// realization failure caused by stream retirement cannot admit a later
    /// application batch in the same event-loop turn.
    pub fn flush_defense_observations(&mut self) {
        self.drain_observations();
    }

    /// Purely plan one atomic multi-stream receive-lifecycle cancellation.
    ///
    /// # Errors
    ///
    /// Returns an invariant error without mutation for an unknown/duplicate
    /// stream or action identity, or a non-contiguous receive ledger.
    #[expect(
        clippy::too_many_lines,
        reason = "global receive cancellation validates ownership, transitive closure, and every mixed ledger before publishing one atomic plan"
    )]
    pub fn plan_receive_streams_unavailable(
        &self,
        rejections: &[(QcsdEndpointId, QcsdStreamId, Vec<QcsdReceiveActionIdentity>)],
    ) -> Result<QcsdReceiveCancellationPlan> {
        if rejections.is_empty() {
            return Err(crate::Error::ControllerInvariant(
                "receive cancellation requires at least one rejected stream".into(),
            ));
        }
        let mut canceled_actions = Vec::new();
        let mut canceled_slots = Vec::new();
        let mut restored_limits = Vec::new();
        for (rejection_index, (endpoint, stream, roots)) in rejections.iter().enumerate() {
            if rejections[..rejection_index]
                .iter()
                .any(|(other_endpoint, other_stream, _)| {
                    other_endpoint == endpoint && other_stream == stream
                })
            {
                return Err(crate::Error::ControllerInvariant(format!(
                    "receive cancellation repeats stream {}:{}",
                    endpoint.0, stream.0
                )));
            }
            for (index, root) in roots.iter().enumerate() {
                if root.endpoint() != *endpoint || root.stream() != *stream {
                    return Err(crate::Error::ControllerInvariant(format!(
                        "receive cancellation root {index} targets a different stream"
                    )));
                }
                if roots[..index].contains(root) {
                    return Err(crate::Error::ControllerInvariant(format!(
                        "receive cancellation root {index} duplicates an earlier identity"
                    )));
                }
            }
            if !self.streams.receive_actions_available(*endpoint, *stream) {
                return Err(crate::Error::ControllerInvariant(format!(
                    "receive cancellation targets unknown or unavailable controller stream {}:{}",
                    endpoint.0, stream.0
                )));
            }
            let ranges = self.receive_stream_cancellation_ranges(*endpoint, *stream, roots)?;
            let Some((advertised_limit, _)) = self.streams.receive_limits(*endpoint, *stream)
            else {
                return Err(crate::Error::ControllerInvariant(format!(
                    "receive cancellation lost controlled limits for {}:{}",
                    endpoint.0, stream.0
                )));
            };
            restored_limits.push((*endpoint, *stream, advertised_limit));
            for range in ranges {
                let identity = range.identity();
                if canceled_actions.contains(&identity) {
                    return Err(crate::Error::ControllerInvariant(format!(
                        "receive cancellation repeats action identity {identity:?}"
                    )));
                }
                canceled_actions.push(identity);
                if let Some(slot) = range.slot()
                    && !canceled_slots.contains(&slot)
                {
                    canceled_slots.push(slot);
                }
            }
            for claim in self
                .control
                .claims
                .iter()
                .filter(|claim| claim.endpoint == *endpoint && claim.stream == *stream)
            {
                if !canceled_slots.contains(&claim.slot) {
                    canceled_slots.push(claim.slot);
                }
            }
        }

        if self.config.drop_unsatisfied_events {
            let roots: HashSet<_> = canceled_slots.iter().copied().collect();
            let affected = self.dependent_unadvertised_slots(&roots);
            for range in self.failed_receive_ranges(&affected) {
                let identity = range.identity();
                if !canceled_actions.contains(&identity) {
                    canceled_actions.push(identity);
                }
                if let Some((_, _, restored)) =
                    restored_limits.iter_mut().find(|(endpoint, stream, _)| {
                        *endpoint == range.endpoint() && *stream == range.stream()
                    })
                {
                    *restored = (*restored).min(range.start());
                } else {
                    restored_limits.push((range.endpoint(), range.stream(), range.start()));
                }
            }
            canceled_slots = affected.into_iter().collect();
        }
        canceled_actions.sort_unstable_by_key(|identity| {
            (
                identity.endpoint(),
                identity.stream(),
                identity.absolute_limit(),
            )
        });
        canceled_slots.sort_unstable();
        canceled_slots.dedup();
        restored_limits.sort_unstable_by_key(|(endpoint, stream, _)| (*endpoint, *stream));
        let mut retained_actions = Vec::new();
        for &(endpoint, stream, cutoff) in &restored_limits {
            // Transitive streams did not necessarily appear in `rejections`.
            // Validate their complete mixed scheduled/parser ledger too; a
            // cutoff derived from a failed range must never conceal a gap,
            // overlap, duplicate, or stranded suffix.
            for range in self.receive_stream_cancellation_ranges(endpoint, stream, &[])? {
                let identity = range.identity();
                let is_canceled = canceled_actions.contains(&identity);
                if range.absolute_limit() > cutoff {
                    if !is_canceled {
                        return Err(crate::Error::ControllerInvariant(format!(
                            "receive cancellation omitted suffix action {identity:?} above restored limit {cutoff}"
                        )));
                    }
                } else if is_canceled {
                    return Err(crate::Error::ControllerInvariant(format!(
                        "receive cancellation included retained action {identity:?} at or below restored limit {cutoff}"
                    )));
                } else {
                    retained_actions.push(identity);
                }
            }
        }
        retained_actions.sort_unstable_by_key(|identity| {
            (
                identity.endpoint(),
                identity.stream(),
                identity.absolute_limit(),
            )
        });
        let canceled_configurations = self
            .actions
            .iter()
            .filter(|action| {
                receive_configuration_target(action).is_some_and(|target| {
                    rejections
                        .iter()
                        .any(|(endpoint, stream, _)| (*endpoint, *stream) == target)
                })
            })
            .cloned()
            .collect();
        Ok(QcsdReceiveCancellationPlan {
            rejections: rejections.to_vec(),
            cancellation: QcsdReceiveCancellation {
                canceled_actions,
                canceled_slots,
            },
            restored_limits,
            retained_actions,
            canceled_configurations,
        })
    }

    /// Atomically commit an unchanged pure multi-stream cancellation plan.
    ///
    /// # Errors
    ///
    /// Returns an invariant error before mutation if controller state no longer
    /// matches the plan.
    pub fn commit_receive_streams_unavailable(
        &mut self,
        plan: &QcsdReceiveCancellationPlan,
        at: Duration,
    ) -> Result<QcsdReceiveCancellation> {
        let refreshed = self.plan_receive_streams_unavailable(&plan.rejections)?;
        if refreshed != *plan {
            return Err(crate::Error::ControllerInvariant(
                "receive cancellation plan changed before commit".into(),
            ));
        }

        // Complete every fallible lookup and ledger validation before the
        // first mutation.  The prepared ranges make the commit phase
        // structurally infallible rather than relying on sequential `?` or a
        // debug-only postcondition after partial rollback.
        let mut prepared = Vec::with_capacity(plan.rejections.len());
        for (endpoint, stream, roots) in &plan.rejections {
            prepared.push((
                *endpoint,
                *stream,
                self.receive_stream_cancellation_ranges(*endpoint, *stream, roots)?,
            ));
        }

        let mut direct_slots = Vec::new();
        for (endpoint, stream, ranges) in prepared {
            let cancellation = self.commit_receive_stream_suffix(endpoint, stream, &ranges);
            direct_slots.extend(cancellation.canceled_slots);
            self.commit_receive_stream_unavailable(endpoint, stream);
        }
        self.actions
            .retain(|action| !plan.canceled_configurations.contains(action));
        if self.config.drop_unsatisfied_events {
            let root_slots: HashSet<_> = direct_slots.into_iter().collect();
            let (_affected_slots, _transitive_actions) = self.fail_incoming_slots(
                &root_slots,
                MissedSlotReason::ReceiveCreditRetired,
                at,
                true,
            );
        }
        Ok(plan.cancellation.clone())
    }

    /// Compatibility wrapper for one rejected receive stream.
    ///
    /// # Errors
    ///
    /// Returns an invariant error if planning or commit fails.
    pub fn mark_receive_stream_unavailable(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        roots: &[QcsdReceiveActionIdentity],
        at: Duration,
    ) -> Result<QcsdReceiveCancellation> {
        let plan = self.plan_receive_streams_unavailable(&[(endpoint, stream, roots.to_vec())])?;
        self.commit_receive_streams_unavailable(&plan, at)
    }

    /// Describe an unrecoverable failure reported by the selected defense.
    #[must_use]
    pub fn terminal_failure(&self) -> Option<&'static str> {
        self.defense.terminal_failure()
    }

    /// Snapshot every defense event that has not reached a terminal outcome.
    ///
    /// The runner uses this at abnormal termination so events that never
    /// reached an adapter still receive one terminal trace record.
    #[must_use]
    pub fn pending_slots(&self) -> Vec<(QcsdSlotId, crate::Packet)> {
        let mut pending: Vec<_> = self
            .pending_slots
            .iter()
            .map(|(slot, packet)| (*slot, *packet))
            .collect();
        pending.sort_unstable_by_key(|(slot, _)| *slot);
        pending
    }

    /// Terminalize every outstanding scheduled slot after a run aborts.
    ///
    /// Incoming slots retire every unresolved scheduled offset before their
    /// typed failure is delivered. Buffered defense signals are reduced
    /// immediately so terminal diagnostics include reactive-defense state,
    /// without polling the defense and creating replacement work during
    /// shutdown.
    pub fn abort_pending_slots(&mut self, at: Duration, reason: MissedSlotReason) {
        if let Some(action) = self.take_rolling_prearm_for_abort() {
            self.actions.push_back(action);
        }
        // Parser leases are slotless liveness actions.  Once the run aborts
        // they must not escape after every scheduled slot has terminalized.
        self.actions
            .retain(|action| !matches!(action, QcsdAction::LeaseParserReceive { .. }));
        self.return_all_parser_lease_ownership();
        self.streams.clear_parser_boundaries();
        let pending = self.pending_slots();
        let incoming: HashSet<_> = self.incoming_credit_ledger.keys().copied().collect();
        // Roll back the complete unadvertised set before terminalizing any
        // individual slot.  A later release on the same stream depends on all
        // earlier absolute limits, so per-slot ascending cancellation is not
        // safe even when every individual release is still unadvertised.
        self.fail_incoming_slots(&incoming, reason, at, true);

        let outgoing: HashSet<_> = pending
            .iter()
            .filter_map(|(slot, _)| (!incoming.contains(slot)).then_some(*slot))
            .collect();
        self.actions.retain(|action| {
            !matches!(action, QcsdAction::SendPacket { slot, .. } if outgoing.contains(slot))
        });
        self.control.outgoing.clear();
        self.control.incoming.clear();
        self.control.receiver_continuation_reserves.clear();
        self.control.receiver_continuation_survivor_gate_open = false;
        self.defense
            .observe_capacity_adjustment(CapacityAdjustment {
                reserved_chaff_bytes: 0,
            });

        for (slot, packet) in pending {
            if !incoming.contains(&slot) && self.pending_slots.contains_key(&slot) {
                self.actions.push_back(QcsdAction::SlotMissed {
                    endpoint: None,
                    packet,
                    slot,
                    reason,
                });
                self.resolve_slot(at, slot, EventOutcome::Missed(reason));
            }
        }
        self.drain_observations();

        debug_assert!(self.pending_slots.is_empty());
        debug_assert!(self.incoming_credit_ledger.is_empty());
        debug_assert!(self.control.credit.is_empty());
        debug_assert!(self.control.claims.is_empty());
        debug_assert!(self.control.receiver_continuations.is_empty());
        debug_assert!(self.advertised_incoming_credit.is_empty());
    }

    /// Consume one endpoint, HTTP/3, or transport observation.
    ///
    /// `at` is relative to defense start. Callers may use zero for
    /// pre-defense observations that cannot produce a [`DefenseSignal`].
    fn receive_stream_cancellation_ranges(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        roots: &[QcsdReceiveActionIdentity],
    ) -> Result<Vec<UnadvertisedReceiveRange>> {
        let Some((advertised_limit, requested_limit)) =
            self.streams.receive_limits(endpoint, stream)
        else {
            return Err(crate::Error::ControllerInvariant(format!(
                "receive cancellation lacks controlled limits for {}:{}",
                endpoint.0, stream.0
            )));
        };
        let mut ranges: Vec<_> = self
            .control
            .credit
            .iter()
            .copied()
            .filter(|credit| credit.endpoint == endpoint && credit.stream == stream)
            .map(UnadvertisedReceiveRange::Scheduled)
            .collect();
        if let Some(parser_ranges) = self.parser_lease_ranges.get(&(endpoint, stream)) {
            let mut saw_unadvertised = false;
            for range in parser_ranges {
                if range.advertised {
                    if saw_unadvertised {
                        return Err(crate::Error::ControllerInvariant(format!(
                            "advertised parser range follows an unadvertised range on {}:{}",
                            endpoint.0, stream.0
                        )));
                    }
                } else {
                    saw_unadvertised = true;
                    ranges.push(UnadvertisedReceiveRange::Parser {
                        endpoint,
                        stream,
                        range: *range,
                    });
                }
            }
        }
        ranges.sort_unstable_by_key(|range| (range.start(), range.absolute_limit()));
        let mut next_start = advertised_limit;
        let mut identities = Vec::with_capacity(ranges.len());
        for range in &ranges {
            let start = range.start();
            let end = range.absolute_limit();
            if start != next_start || end <= start {
                return Err(crate::Error::ControllerInvariant(format!(
                    "receive cancellation range [{start}, {end}) does not continue {next_start} on {}:{}",
                    endpoint.0, stream.0
                )));
            }
            next_start = end;
            let identity = range.identity();
            if identities.contains(&identity) {
                return Err(crate::Error::ControllerInvariant(format!(
                    "receive cancellation ledger repeats absolute limit {} on {}:{}",
                    identity.absolute_limit(),
                    endpoint.0,
                    stream.0
                )));
            }
            identities.push(identity);
        }
        if next_start != requested_limit {
            return Err(crate::Error::ControllerInvariant(format!(
                "receive cancellation suffix ends at {next_start}, requested limit is {requested_limit} on {}:{}",
                endpoint.0, stream.0
            )));
        }
        for (index, root) in roots.iter().enumerate() {
            let matches = identities
                .iter()
                .filter(|identity| *identity == root)
                .count();
            if matches != 1 {
                return Err(crate::Error::ControllerInvariant(format!(
                    "receive cancellation root {index} matched {matches} ledger actions"
                )));
            }
        }
        Ok(ranges)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the exhaustive observation reducer makes every state transition auditable"
    )]
    pub fn observe(&mut self, observation: QcsdObservation, at: Duration) {
        match observation {
            QcsdObservation::EndpointReady {
                endpoint, origin, ..
            } => {
                self.scheduler.add_endpoint(endpoint);
                self.endpoint_origins.insert(endpoint, origin);
                self.release_chaff_send_shaping_for(endpoint);
                self.release_application_send_shaping_for(endpoint);
            }
            QcsdObservation::EndpointClosed { endpoint } => {
                let abandoned_prearm = self.abandon_closed_endpoint_prearm(endpoint);
                self.actions.retain(|action| {
                    !matches!(action, QcsdAction::LeaseParserReceive { endpoint: candidate, .. } if *candidate == endpoint)
                });
                self.return_endpoint_parser_lease_ownership(endpoint);
                self.return_endpoint_claims(endpoint);
                self.return_endpoint_credit(endpoint, at);
                self.scheduler.remove_endpoint(endpoint);
                self.endpoint_origins.remove(&endpoint);
                self.streams.remove_endpoint(endpoint);
                self.application_stream_ranges
                    .retain(|(candidate, _), _| *candidate != endpoint);
                self.chaff_stream_ranges
                    .retain(|(candidate, _), _| *candidate != endpoint);
                debug_assert!(
                    !self
                        .parser_lease_ranges
                        .keys()
                        .any(|(candidate, _)| *candidate == endpoint)
                );
                self.retire_endpoint_advertised_credit(endpoint, at);
                self.control.reassign_endpoint(endpoint);
                self.released_chaff_send_shaping.remove(&endpoint);
                self.released_application_send_shaping.remove(&endpoint);
                // An uncommitted rolling preview is not a defense event. If
                // another origin survives, transfer the same event at the
                // close observation's causal instant. A close reduced at or
                // just after release must materialize immediately rather than
                // stranding the exact cell until the outer control poll.
                self.recover_abandoned_rolling_prearm(abandoned_prearm, at);
            }
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role,
                expected_response_length,
            } => self.open_stream(endpoint, stream, role, expected_response_length),
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining,
                awaiting_data_frame,
            } => {
                self.streams
                    .header_progress(endpoint, stream, min_remaining, awaiting_data_frame);
                self.release_exact_claims(endpoint, stream);
                self.try_parser_lease(endpoint, stream, awaiting_data_frame);
            }
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream,
                frame_bytes,
                status,
                content_length,
                ..
            } => {
                self.streams.clear_pre_header_blocked(endpoint, stream);
                if let Some(state) = self.streams.get_mut(endpoint, stream) {
                    if status.is_some() {
                        state.status = status;
                    }
                    state.receive.response_headers(frame_bytes, content_length);
                }
                self.release_exact_claims(endpoint, stream);
            }
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                frame_header_bytes,
                data_bytes,
                ..
            } => {
                self.streams.clear_pre_header_blocked(endpoint, stream);
                if let Some(state) = self.streams.get_mut(endpoint, stream) {
                    state.receive.data_frame(frame_header_bytes, data_bytes);
                }
                self.release_exact_claims(endpoint, stream);
            }
            QcsdObservation::PushPromiseFrame {
                endpoint,
                stream,
                frame_bytes,
            }
            | QcsdObservation::IgnoredRequestStreamFrame {
                endpoint,
                stream,
                frame_bytes,
            } => {
                self.streams.clear_pre_header_blocked(endpoint, stream);
                if let Some(state) = self.streams.get_mut(endpoint, stream) {
                    state.receive.framing(frame_bytes);
                }
                self.release_exact_claims(endpoint, stream);
            }
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes,
            } => {
                if bytes > 0 {
                    self.streams.clear_pre_header_blocked(endpoint, stream);
                }
                if let Some((cover, consumed_start, consumed_end)) =
                    self.streams.get_mut(endpoint, stream).map(|state| {
                        let consumed_start = state.receive.consumed();
                        let cover = matches!(state.role, QcsdRequestRole::Chaff { .. });
                        state.receive.bytes_read(bytes);
                        (cover, consumed_start, state.receive.consumed())
                    })
                {
                    self.push_signal(
                        at,
                        SignalKind::PayloadBytes {
                            direction: Direction::Incoming,
                            bytes,
                            cover,
                        },
                    );
                    // Attribute natural request-stream offsets while the
                    // receive event still belongs to its incoming mould
                    // component. Consuming the final scheduled credit can
                    // advance Walkie-Talkie into the next outgoing component.
                    if !cover {
                        self.push_application_bytes(at, Direction::Incoming, bytes);
                    }
                    self.consume_parser_lease_claims(
                        endpoint,
                        stream,
                        consumed_start,
                        consumed_end,
                        at,
                    );
                    self.consume_advertised_credit(
                        endpoint,
                        stream,
                        consumed_start,
                        consumed_end,
                        at,
                    );
                }
            }
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream,
                blocked_at,
            } => {
                if self
                    .streams
                    .record_pre_header_blocked(endpoint, stream, blocked_at)
                {
                    self.try_pre_header_bootstrap(endpoint, stream);
                }
            }
            // Application and qualified-chaff resources occupy distinct
            // namespaces. Only a real chaff request stream completion can
            // mutate chaff resource state.
            QcsdObservation::ResourceCompleted { .. } => {}
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot,
            } => self.credit_advertised(endpoint, stream, absolute_limit, slot, at),
            QcsdObservation::StreamFinished {
                endpoint,
                stream,
                finish,
            } => self.close_stream(endpoint, stream, finish, at),
            QcsdObservation::ChaffRequestFailed {
                resource_id,
                request_id,
            } => {
                if let Some(chaff) = &mut self.chaff {
                    chaff.request_failed(resource_id, request_id);
                }
            }
            QcsdObservation::ApplicationBatchStarted => {
                self.push_signal(at, SignalKind::ApplicationBatchStarted);
            }
            QcsdObservation::ApplicationBatchCompleted => {
                self.push_signal(at, SignalKind::ApplicationBatchCompleted);
            }
            QcsdObservation::ApplicationComplete => {
                if !self.application_complete {
                    self.application_complete = true;
                    self.push_signal(at, SignalKind::ApplicationComplete);
                }
            }
            QcsdObservation::EgressBacklog { pending } => {
                if self.defense.requires_terminal_chaff_drain() {
                    self.adapter_egress_backlog_pending = pending;
                } else {
                    self.push_signal(at, SignalKind::EgressBacklog { pending });
                }
            }
            QcsdObservation::Datagram {
                direction, length, ..
            } => self.push_signal(at, SignalKind::Wire { direction, length }),
            QcsdObservation::ClassifiedDatagram {
                direction,
                length,
                class,
                ..
            } => self.push_signal(
                at,
                SignalKind::ClassifiedWire {
                    direction,
                    length,
                    class,
                },
            ),
            QcsdObservation::TrafficMorphingEgress {
                source_udp_size,
                outcome,
                ..
            } => self.push_signal(
                at,
                SignalKind::TrafficMorphingEgress {
                    source: source_udp_size,
                    outcome,
                },
            ),
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream,
                role,
                offset,
                bytes,
                ..
            } => {
                let cover = matches!(role, QcsdRequestRole::Chaff { .. });
                let payload_bytes = if cover && self.defense.deduplicate_chaff_payload_offsets() {
                    self.record_chaff_stream_range(endpoint, stream, offset, bytes)
                } else {
                    bytes
                };
                self.push_signal(
                    at,
                    SignalKind::PayloadBytes {
                        direction: Direction::Outgoing,
                        bytes: payload_bytes,
                        cover,
                    },
                );
                if !cover {
                    let unique =
                        self.record_application_stream_range(endpoint, stream, offset, bytes);
                    self.push_application_bytes(at, Direction::Outgoing, unique);
                }
            }
            QcsdObservation::StreamDataAcknowledged {
                endpoint,
                stream,
                role,
                offset,
                bytes,
                fin,
            } => {
                self.streams.record_chaff_request_acknowledgment(
                    endpoint, stream, role, offset, bytes, fin,
                );
            }
            QcsdObservation::SlotSatisfied {
                slot,
                observed_size,
                ..
            } => {
                self.resolve_slot(
                    at,
                    slot,
                    EventOutcome::Satisfied {
                        observed: observed_size,
                    },
                );
            }
            QcsdObservation::SlotMissed { slot, reason, .. } => {
                if self.incoming_credit_ledger.contains_key(&slot) {
                    self.fail_incoming_slot(slot, reason, at, false);
                } else {
                    self.resolve_slot(at, slot, EventOutcome::Missed(reason));
                }
            }
            QcsdObservation::SlotResolved { slot, outcome, .. } => {
                let outcome = match outcome {
                    crate::QcsdSlotOutcome::Full { composition } => {
                        EventOutcome::FullySatisfied { composition }
                    }
                    crate::QcsdSlotOutcome::Partial {
                        composition,
                        reason,
                    } => EventOutcome::PartiallySatisfied {
                        composition,
                        reason,
                    },
                    crate::QcsdSlotOutcome::Suppressed {
                        composition,
                        reason,
                    } => EventOutcome::Suppressed {
                        composition,
                        reason,
                    },
                };
                self.resolve_slot(at, slot, outcome);
            }
        }
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "signals are Copy values reduced into a single-owner queue"
    )]
    fn push_signal(&mut self, at: Duration, kind: SignalKind) {
        self.observations
            .push_back(QueuedDefenseObservation::Signal(DefenseSignal { at, kind }));
    }

    fn push_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
        if bytes > 0 {
            self.observations
                .push_back(QueuedDefenseObservation::ApplicationBytes {
                    at,
                    direction,
                    bytes,
                });
        }
    }

    fn record_application_stream_range(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        offset: u64,
        bytes: u64,
    ) -> u64 {
        let end = offset.saturating_add(bytes);
        if end <= offset {
            return 0;
        }
        let ranges = self
            .application_stream_ranges
            .entry((endpoint, stream))
            .or_default();
        let before = covered_range_bytes(ranges);
        ranges.push((offset, end));
        ranges.sort_unstable();
        merge_ranges(ranges);
        covered_range_bytes(ranges).saturating_sub(before)
    }

    fn record_chaff_stream_range(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        offset: u64,
        bytes: u64,
    ) -> u64 {
        let end = offset.saturating_add(bytes);
        if end <= offset {
            return 0;
        }
        let ranges = self
            .chaff_stream_ranges
            .entry((endpoint, stream))
            .or_default();
        let before = covered_range_bytes(ranges);
        ranges.push((offset, end));
        ranges.sort_unstable();
        merge_ranges(ranges);
        covered_range_bytes(ranges).saturating_sub(before)
    }

    fn resolve_slot(&mut self, at: Duration, slot: QcsdSlotId, outcome: EventOutcome) {
        let Some(packet) = self.pending_slots.remove(&slot) else {
            return;
        };
        self.control.receiver_continuations.remove(&slot);
        if packet.direction() == Direction::Incoming
            && self.defense.split_incoming_credit_lifecycle()
        {
            self.push_signal(
                at,
                SignalKind::IncomingCreditResolved {
                    slot,
                    packet,
                    outcome,
                },
            );
        } else {
            self.push_signal(at, SignalKind::Resolved { packet, outcome });
        }
    }

    fn open_stream(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
        expected_response_length: Option<u64>,
    ) {
        let expected = match role {
            QcsdRequestRole::Application => expected_response_length.unwrap_or(0),
            QcsdRequestRole::Chaff {
                resource_id,
                request_id,
            } => self.chaff.as_mut().map_or(0, |chaff| {
                chaff.request_opened(request_id);
                chaff.estimate(resource_id)
            }),
        };
        let controlled = self.controls(role);
        let initial_limit = self.config.effective_initial_max_stream_data();
        self.streams.open(
            endpoint,
            stream,
            role,
            controlled,
            initial_limit,
            self.config.max_stream_data_excess,
            expected,
        );
        if controlled {
            self.actions.push_back(QcsdAction::ConfigureManualReceive {
                endpoint,
                stream,
                initial_limit,
            });
        } else if self.cs_buflo_application_passthrough
            || !matches!(self.config.defense, DefenseConfig::None)
        {
            self.actions
                .push_back(QcsdAction::ConfigureAutomaticReceive {
                    endpoint,
                    stream,
                    window: self.config.automatic_receive_window,
                });
        }
    }

    fn close_stream(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        finish: crate::QcsdStreamFinish,
        at: Duration,
    ) {
        self.actions.retain(|action| {
            !matches!(action, QcsdAction::LeaseParserReceive { endpoint: candidate_endpoint, stream: candidate_stream, .. }
                if *candidate_endpoint == endpoint && *candidate_stream == stream)
        });
        if !self.defense.retain_stream_offset_provenance_after_close() {
            self.application_stream_ranges.remove(&(endpoint, stream));
            self.chaff_stream_ranges.remove(&(endpoint, stream));
        }
        self.return_stream_parser_lease_ownership(endpoint, stream);
        self.return_stream_claims(endpoint, stream);
        self.return_stream_credit(endpoint, stream, at);
        let Some((state, data_length, _unadvertised)) = self.streams.close(endpoint, stream) else {
            return;
        };
        self.retire_stream_advertised_credit(endpoint, stream, at);
        if let QcsdRequestRole::Chaff { resource_id, .. } = state.role {
            let success = finish == crate::QcsdStreamFinish::Fin
                && state
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
                && data_length > 0;
            if let Some(chaff) = &mut self.chaff {
                chaff.resource_completed(resource_id, success, data_length);
            }
        }
    }

    fn credit_advertised(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        slot: Option<QcsdSlotId>,
        at: Duration,
    ) {
        if let Some(state) = self.streams.get_mut(endpoint, stream) {
            state.receive.advertised(absolute_limit);
        }
        let mut advertised_parser_owners = BTreeMap::new();
        if let Some(ranges) = self.parser_lease_ranges.get_mut(&(endpoint, stream)) {
            for range in ranges {
                let newly_advertised = !range.advertised && range.end <= absolute_limit;
                range.advertised |= newly_advertised;
                if newly_advertised && let Some(owner) = range.owner {
                    let total = advertised_parser_owners.entry(owner.slot).or_insert(0_u64);
                    *total = total.saturating_add(range.bytes());
                }
            }
        }
        let mut advertised_ranges = Vec::new();
        let mut advertised_by_slot = BTreeMap::new();
        self.control.credit.retain(|credit| {
            let same_release = credit.endpoint == endpoint
                && credit.stream == stream
                && credit.absolute_limit <= absolute_limit
                && slot.is_none_or(|slot| credit.slot == slot);
            if same_release {
                let total = advertised_by_slot.entry(credit.slot).or_insert(0_u64);
                *total = total.saturating_add(credit.increase);
                advertised_ranges.push(AdvertisedIncomingCredit {
                    slot: credit.slot,
                    start: credit.absolute_limit.saturating_sub(credit.increase),
                    end: credit.absolute_limit,
                });
            }
            !same_release
        });
        if !advertised_ranges.is_empty() {
            let ranges = self
                .advertised_incoming_credit
                .entry((endpoint, stream))
                .or_default();
            ranges.append(&mut advertised_ranges);
            ranges.sort_unstable_by_key(|range| (range.start, range.end, range.slot));
        }
        for (slot, advertised) in advertised_by_slot {
            self.record_advertised_credit(slot, advertised, at);
        }
        // A post-cap parser lease is physically slotless, but can already
        // carry explicit scheduling ownership. Count that ownership only once
        // the transport proves the lease was advertised; consuming it remains
        // the separate terminal transition below.
        for (slot, advertised) in advertised_parser_owners {
            self.record_advertised_credit(slot, advertised, at);
        }
        // A pristine typed parser boundary may have first exposed exact
        // scheduled capacity.  That release had to be encoded before a
        // slotless tail could be appended safely; retry the retained boundary
        // now that requested and advertised limits can agree.
        self.try_pre_header_bootstrap(endpoint, stream);
        self.try_parser_lease(endpoint, stream, true);
    }

    /// Attribute physically advertised receive capacity to one scheduled
    /// incoming slot. Ordinary exact releases arrive here directly. Parser
    /// leases arrive either with an explicit owner at advertisement time or
    /// when consumed bytes acquire ownership from an older live claim.
    fn record_advertised_credit(&mut self, slot: QcsdSlotId, bytes: u64, at: Duration) {
        let (invalid, completed) = {
            let Some(ledger) = self.incoming_credit_ledger.get_mut(&slot) else {
                return;
            };
            let remaining = ledger.requested().saturating_sub(ledger.advertised);
            if bytes > remaining {
                (true, None)
            } else {
                ledger.advertised = ledger.advertised.saturating_add(bytes);
                self.scheduled_incoming_advertised_bytes = self
                    .scheduled_incoming_advertised_bytes
                    .saturating_add(bytes);
                let completed = (ledger.advertised == ledger.requested()
                    && !ledger.local_realization_emitted)
                    .then(|| {
                        ledger.local_realization_emitted = true;
                        ledger.packet
                    });
                (false, completed)
            }
        };
        if invalid {
            self.fail_incoming_slot(slot, MissedSlotReason::RunAborted, at, true);
        } else if let Some(packet) = completed
            && self.defense.split_incoming_credit_lifecycle()
        {
            self.push_signal(at, SignalKind::IncomingCreditAdvertised { slot, packet });
        }
    }

    /// Remove unconsumed advertised parser capacity before its provisional
    /// owner is returned to the allocator. The original local realization is
    /// retained: retrying bytes from the same slot must not emit a second
    /// opportunity, but its replacement credit must be able to restore the
    /// byte ledger without being mistaken for over-advertisement.
    fn return_advertised_credit(&mut self, slot: QcsdSlotId, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let Some(ledger) = self.incoming_credit_ledger.get_mut(&slot) else {
            return;
        };
        let remaining = ledger
            .advertised
            .checked_sub(bytes)
            .expect("returned parser ownership exceeds its scheduled advertisement");
        assert!(
            remaining >= ledger.consumed,
            "returned parser ownership must be unconsumed scheduled advertisement"
        );
        assert!(
            self.scheduled_incoming_advertised_bytes >= bytes,
            "returned parser ownership exceeds the global scheduled advertisement"
        );
        ledger.advertised = remaining;
        self.scheduled_incoming_advertised_bytes -= bytes;
    }

    fn try_pre_header_bootstrap(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId) {
        let live_scheduled_prefix = self.live_advertised_scheduled_prefix(endpoint, stream);
        let Some(lease) =
            self.streams
                .pre_header_bootstrap_lease(endpoint, stream, live_scheduled_prefix)
        else {
            return;
        };
        debug_assert!(!lease.scheduled);
        self.parser_lease_ranges
            .entry((endpoint, stream))
            .or_default()
            .push(ParserLeaseRange {
                start: lease.absolute_limit.saturating_sub(lease.increase),
                end: lease.absolute_limit,
                owner: None,
                unowned: true,
                advertised: false,
            });
        self.actions.push_back(QcsdAction::LeaseParserReceive {
            endpoint,
            stream,
            absolute_limit: lease.absolute_limit,
            increase: lease.increase,
            owner: None,
        });
    }

    fn try_parser_lease(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        pristine_data_boundary: bool,
    ) {
        if !pristine_data_boundary || !self.streams.has_pending_parser_boundary(endpoint, stream) {
            return;
        }

        // Exact capacity always has priority over parser-only growth. New
        // scheduled ownership is assigned only by `process_incoming`, which
        // enforces the current control boundary, endpoint round-robin order,
        // and application-before-chaff policy. This per-stream retry may use
        // an existing same-stream claim but must never steal global backlog.
        self.release_exact_claims(endpoint, stream);

        let backing = self
            .control
            .claims
            .iter()
            .filter(|claim| claim.endpoint == endpoint && claim.stream == stream)
            .min_by_key(|claim| claim.slot)
            .map_or(0, |claim| claim.remaining);
        let incoming_terminal = self.defense.is_incoming_complete()
            && self.defense.pending_receiver_continuation().is_none()
            && self.control.incoming.is_empty()
            && self.control.receiver_continuations.is_empty();
        let terminal_advertised_tail = if incoming_terminal && backing == 0 {
            self.streams
                .consumed(endpoint, stream)
                .and_then(|consumed| {
                    self.contiguous_advertised_tail_from(endpoint, stream, consumed)
                })
        } else {
            None
        };
        let Some(lease) = self.streams.parser_lease(
            endpoint,
            stream,
            pristine_data_boundary,
            backing,
            terminal_advertised_tail,
        ) else {
            return;
        };
        let owner = lease
            .scheduled
            .then(|| self.take_parser_lease_owner(endpoint, stream, lease.increase))
            .flatten();
        assert_eq!(owner.is_some(), lease.scheduled);
        self.parser_lease_ranges
            .entry((endpoint, stream))
            .or_default()
            .push(ParserLeaseRange {
                start: lease.absolute_limit.saturating_sub(lease.increase),
                end: lease.absolute_limit,
                owner,
                unowned: !lease.scheduled,
                advertised: false,
            });
        self.actions.push_back(QcsdAction::LeaseParserReceive {
            endpoint,
            stream,
            absolute_limit: lease.absolute_limit,
            increase: lease.increase,
            owner,
        });
    }

    fn take_parser_lease_owner(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        amount: u64,
    ) -> Option<QcsdParserLeaseOwner> {
        let index = self
            .control
            .claims
            .iter()
            .enumerate()
            .filter(|(_, claim)| claim.endpoint == endpoint && claim.stream == stream)
            .min_by_key(|(_, claim)| claim.slot)
            .map(|(index, _)| index)?;
        let claim = &mut self.control.claims[index];
        assert!(claim.remaining >= amount);
        claim.remaining -= amount;
        let owner = QcsdParserLeaseOwner {
            slot: claim.slot,
            packet: claim.packet,
        };
        if claim.remaining == 0 {
            self.control.claims.remove(index);
        }
        Some(owner)
    }

    /// Convert newly exact receive capacity into continuations owned by the
    /// same slot that provisionally claimed it.  Claims are consumed in slot
    /// order and never create more advertised work than the stream reports as
    /// exact capacity.
    fn release_exact_claims(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId) {
        if !self.streams.receive_actions_available(endpoint, stream) {
            return;
        }
        let Some(state) = self.streams.get_mut(endpoint, stream) else {
            return;
        };
        let mut available = state.receive.available();
        if available == 0 {
            return;
        }
        let mut indices: Vec<_> = self
            .control
            .claims
            .iter()
            .enumerate()
            .filter_map(|(index, claim)| {
                (claim.endpoint == endpoint && claim.stream == stream).then_some(index)
            })
            .collect();
        indices.sort_unstable_by_key(|index| self.control.claims[*index].slot);
        for index in indices {
            if available == 0 {
                break;
            }
            let requested = self.control.claims[index].remaining.min(available);
            let Some((absolute_limit, increase)) = state.receive.release(requested) else {
                break;
            };
            let claim = &mut self.control.claims[index];
            claim.remaining -= increase;
            available -= increase;
            state.receive.restore_claim(increase);
            let credit = PendingCredit {
                slot: claim.slot,
                packet: claim.packet,
                endpoint,
                stream,
                absolute_limit,
                increase,
            };
            self.control.credit.push(credit);
            self.actions.push_back(QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit,
                packet: claim.packet,
                slot: claim.slot,
            });
        }
        self.control.claims.retain(|claim| claim.remaining > 0);
    }

    fn consume_advertised_credit(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        start: u64,
        end: u64,
        at: Duration,
    ) {
        let key = (endpoint, stream);
        let mut consumed_by_slot = BTreeMap::new();
        let remove_stream = self
            .advertised_incoming_credit
            .get_mut(&key)
            .is_some_and(|ranges| {
                for range in &mut *ranges {
                    let overlap_start = range.start.max(start);
                    let overlap_end = range.end.min(end);
                    let consumed = overlap_end.saturating_sub(overlap_start);
                    if consumed > 0 {
                        let total = consumed_by_slot.entry(range.slot).or_insert(0_u64);
                        *total = total.saturating_add(consumed);
                    }
                    if range.start < end {
                        range.start = end.min(range.end);
                    }
                }
                ranges.retain(|range| range.start < range.end);
                ranges.is_empty()
            });
        if remove_stream {
            self.advertised_incoming_credit.remove(&key);
        }
        for (slot, bytes) in consumed_by_slot {
            self.record_consumed_credit(slot, bytes, at);
        }
    }

    /// Debit consumed parser-liveness offsets against scheduling ownership
    /// that was already reserved on this stream. This preserves the public
    /// raw request-stream byte domain: the lease bytes remain observable, but
    /// displace an equal amount of later exact/chaff credit instead of growing
    /// the mould. Unowned lease overlap remains raw overflow.
    fn consume_parser_lease_claims(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        start: u64,
        end: u64,
        at: Duration,
    ) {
        let key = (endpoint, stream);
        let mut unowned_overlap = 0_u64;
        let mut owned_by_slot = BTreeMap::new();
        let remove_stream = self
            .parser_lease_ranges
            .get_mut(&key)
            .is_some_and(|ranges| {
                for range in &mut *ranges {
                    let overlap_start = range.start.max(start);
                    let overlap_end = range.end.min(end);
                    let overlap = overlap_end.saturating_sub(overlap_start);
                    if overlap > 0 {
                        if let Some(owner) = range.owner {
                            let total = owned_by_slot.entry(owner.slot).or_insert(0_u64);
                            *total = total.saturating_add(overlap);
                        } else if range.unowned {
                            unowned_overlap = unowned_overlap.saturating_add(overlap);
                        }
                    }
                    if range.start < end {
                        range.start = end.min(range.end);
                    }
                }
                ranges.retain(|range| range.bytes() > 0);
                ranges.is_empty()
            });
        if remove_stream {
            self.parser_lease_ranges.remove(&key);
        }

        let owned: u64 = owned_by_slot.values().copied().sum();
        if owned > 0 {
            assert_eq!(
                self.streams
                    .schedule_parser_lease_bytes(endpoint, stream, owned, false,),
                owned
            );
        }

        // A lease that was originally unowned may acquire scheduling
        // ownership only when its raw bytes are actually consumed. Debit the
        // oldest same-stream claims and recycle exactly that overlap; any
        // remainder stays permanently charged to the lifetime unowned cap.
        let mut reclassified = 0_u64;
        let mut reclassified_by_slot = BTreeMap::new();
        if unowned_overlap > 0 {
            let mut indices: Vec<_> = self
                .control
                .claims
                .iter()
                .enumerate()
                .filter_map(|(index, claim)| {
                    (claim.endpoint == endpoint && claim.stream == stream).then_some(index)
                })
                .collect();
            indices.sort_unstable_by_key(|index| self.control.claims[*index].slot);
            for index in indices {
                if unowned_overlap == 0 {
                    break;
                }
                let claim = &mut self.control.claims[index];
                let consumed = unowned_overlap.min(claim.remaining);
                claim.remaining -= consumed;
                unowned_overlap -= consumed;
                reclassified = reclassified.saturating_add(consumed);
                if consumed > 0 {
                    let total = owned_by_slot.entry(claim.slot).or_insert(0_u64);
                    *total = total.saturating_add(consumed);
                    let advertised = reclassified_by_slot.entry(claim.slot).or_insert(0_u64);
                    *advertised = advertised.saturating_add(consumed);
                }
            }
        }
        self.control.claims.retain(|claim| claim.remaining > 0);
        if reclassified > 0 {
            assert_eq!(
                self.streams
                    .schedule_parser_lease_bytes(endpoint, stream, reclassified, true,),
                reclassified
            );
        }
        // These bytes came from a parser lease that the transport had already
        // advertised without an owner. Consumption converts the oldest live
        // same-stream claim into scheduled ownership, so the same physical
        // bytes must enter both the scheduled-advertised and scheduled-consumed
        // ledgers. Counting only consumption leaves split cells permanently
        // short by the parser bytes displaced at stream hand-off.
        for (slot, advertised) in reclassified_by_slot {
            self.record_advertised_credit(slot, advertised, at);
        }
        for (slot, consumed) in owned_by_slot {
            self.record_consumed_credit(slot, consumed, at);
        }

        // Consuming a scheduled parser continuation can expose the next
        // pristine boundary with replenished reservation capacity. The HTTP/3
        // typed observation still authorizes the next lease; this call only
        // uses a boundary that remains explicitly retained by ReceiveState.
        self.try_parser_lease(endpoint, stream, true);
    }

    fn record_consumed_credit(&mut self, slot: QcsdSlotId, bytes: u64, at: Duration) {
        let Some(ledger) = self.incoming_credit_ledger.get_mut(&slot) else {
            return;
        };
        let consumed = bytes.min(ledger.unresolved());
        if consumed == 0 {
            return;
        }
        debug_assert!(
            ledger.consumed.saturating_add(consumed) <= ledger.advertised,
            "scheduled credit must be advertised before it is consumed"
        );
        ledger.consumed = ledger.consumed.saturating_add(consumed);
        self.scheduled_incoming_consumed_bytes = self
            .scheduled_incoming_consumed_bytes
            .saturating_add(consumed);
        self.push_signal(at, SignalKind::ReceiveCreditConsumed { bytes: consumed });
        self.finish_incoming_slot_if_resolved(slot, at);
    }

    fn retire_stream_advertised_credit(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        at: Duration,
    ) {
        let Some(ranges) = self.advertised_incoming_credit.remove(&(endpoint, stream)) else {
            return;
        };
        let mut retired_by_slot = BTreeMap::new();
        for range in ranges {
            let total = retired_by_slot.entry(range.slot).or_insert(0_u64);
            *total = total.saturating_add(range.bytes());
        }
        for (slot, bytes) in retired_by_slot {
            self.record_retired_credit(slot, bytes, at);
        }
    }

    fn retire_endpoint_advertised_credit(&mut self, endpoint: QcsdEndpointId, at: Duration) {
        let mut streams: Vec<_> = self
            .advertised_incoming_credit
            .keys()
            .filter_map(|(candidate, stream)| (*candidate == endpoint).then_some(*stream))
            .collect();
        streams.sort_unstable();
        for stream in streams {
            self.retire_stream_advertised_credit(endpoint, stream, at);
        }
    }

    fn record_retired_credit(&mut self, slot: QcsdSlotId, bytes: u64, at: Duration) {
        let Some(ledger) = self.incoming_credit_ledger.get_mut(&slot) else {
            return;
        };
        let retired = bytes.min(ledger.unresolved());
        if retired == 0 {
            return;
        }
        ledger.retired = ledger.retired.saturating_add(retired);
        self.scheduled_incoming_retired_bytes = self
            .scheduled_incoming_retired_bytes
            .saturating_add(retired);
        self.push_signal(at, SignalKind::ReceiveCreditRetired { bytes: retired });
        self.finish_incoming_slot_if_resolved(slot, at);
    }

    fn finish_incoming_slot_if_resolved(&mut self, slot: QcsdSlotId, at: Duration) {
        if self
            .incoming_credit_ledger
            .get(&slot)
            .is_none_or(|ledger| ledger.unresolved() > 0)
        {
            return;
        }
        let Some(ledger) = self.incoming_credit_ledger.remove(&slot) else {
            return;
        };
        if !self.control.terminal_incoming.insert(slot) {
            return;
        }
        let outcome = if ledger.retired == 0 {
            self.actions.push_back(QcsdAction::SlotSatisfied {
                endpoint: ledger.action_endpoint(),
                packet: ledger.packet,
                slot,
            });
            EventOutcome::Satisfied {
                observed: ledger.packet.length(),
            }
        } else {
            let reason = MissedSlotReason::ReceiveCreditRetired;
            self.actions.push_back(QcsdAction::SlotMissed {
                endpoint: ledger.action_endpoint(),
                packet: ledger.packet,
                slot,
                reason,
            });
            EventOutcome::Missed(reason)
        };
        self.resolve_slot(at, slot, outcome);
    }

    fn commit_receive_stream_suffix(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        ranges: &[UnadvertisedReceiveRange],
    ) -> QcsdReceiveCancellation {
        let identities: Vec<_> = ranges.iter().map(|range| range.identity()).collect();

        let mut returned_credit = Vec::new();
        let mut returned_owners = Vec::new();
        for range in ranges.iter().rev().copied() {
            match range {
                UnadvertisedReceiveRange::Scheduled(credit) => {
                    assert!(
                        self.streams.cancel_release(
                            credit.endpoint,
                            credit.stream,
                            credit.absolute_limit,
                            credit.increase,
                        ),
                        "pure plan guarantees scheduled LIFO rollback"
                    );
                    returned_credit.push(credit);
                }
                UnadvertisedReceiveRange::Parser { range, .. } => {
                    assert!(
                        self.streams.cancel_parser_lease(
                            endpoint,
                            stream,
                            range.end,
                            range.bytes(),
                            range.unowned,
                        ),
                        "pure plan guarantees parser LIFO rollback"
                    );
                    if let Some(owner) = range.owner {
                        returned_owners.push((owner, range.bytes()));
                    }
                }
            }
        }

        self.control.credit.retain(|credit| {
            !identities.contains(&QcsdReceiveActionIdentity::Scheduled {
                endpoint: credit.endpoint,
                stream: credit.stream,
                absolute_limit: credit.absolute_limit,
                slot: credit.slot,
            })
        });
        if let Some(parser_ranges) = self.parser_lease_ranges.get_mut(&(endpoint, stream)) {
            parser_ranges.retain(|range| range.advertised);
            if parser_ranges.is_empty() {
                self.parser_lease_ranges.remove(&(endpoint, stream));
            }
        }
        self.actions.retain(|action| {
            action
                .receive_identity()
                .is_none_or(|identity| !identities.contains(&identity))
        });

        let mut canceled_slots: Vec<_> = ranges.iter().filter_map(|range| range.slot()).collect();
        for credit in returned_credit {
            self.return_claim(&PendingClaim {
                slot: credit.slot,
                packet: credit.packet,
                endpoint,
                stream,
                remaining: credit.increase,
            });
        }
        for (owner, bytes) in returned_owners {
            self.streams.restore_claim(endpoint, stream, bytes);
            self.return_claim(&PendingClaim {
                slot: owner.slot,
                packet: owner.packet,
                endpoint,
                stream,
                remaining: bytes,
            });
        }

        let claims: Vec<_> = self
            .control
            .claims
            .iter()
            .copied()
            .filter(|claim| claim.endpoint == endpoint && claim.stream == stream)
            .collect();
        self.control
            .claims
            .retain(|claim| claim.endpoint != endpoint || claim.stream != stream);
        for claim in claims {
            canceled_slots.push(claim.slot);
            self.streams
                .restore_claim(endpoint, stream, claim.remaining);
            self.return_claim(&claim);
        }

        QcsdReceiveCancellation {
            canceled_actions: identities,
            canceled_slots,
        }
    }

    fn commit_receive_stream_unavailable(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) {
        assert!(
            self.streams.mark_receive_unavailable(endpoint, stream),
            "pure receive cancellation plan guarantees stream availability"
        );
    }

    fn return_stream_credit(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        at: Duration,
    ) {
        self.return_matching_credit(
            |credit| credit.endpoint == endpoint && credit.stream == stream,
            at,
        );
    }

    fn return_stream_claims(&mut self, endpoint: QcsdEndpointId, stream: QcsdStreamId) {
        let mut returned = Vec::new();
        self.control.claims.retain(|claim| {
            if claim.endpoint == endpoint && claim.stream == stream {
                returned.push(*claim);
                false
            } else {
                true
            }
        });
        for claim in returned {
            self.return_claim(&claim);
        }
    }

    fn return_stream_parser_lease_ownership(
        &mut self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) {
        let Some(mut ranges) = self.parser_lease_ranges.remove(&(endpoint, stream)) else {
            return;
        };
        // Every unadvertised parser range is a monotonic suffix. Roll it back
        // before the stream disappears so no queued transport action can
        // target a closed stream and no reservation is stranded.
        while ranges.last().is_some_and(|range| !range.advertised) {
            let range = ranges.pop().expect("checked parser suffix");
            assert!(self.streams.cancel_parser_lease(
                endpoint,
                stream,
                range.end,
                range.bytes(),
                range.unowned,
            ));
            if let Some(owner) = range.owner {
                self.streams.restore_claim(endpoint, stream, range.bytes());
                self.return_claim(&PendingClaim {
                    slot: owner.slot,
                    packet: owner.packet,
                    endpoint,
                    stream,
                    remaining: range.bytes(),
                });
            }
        }
        for range in ranges {
            let Some(owner) = range.owner else {
                continue;
            };
            let remaining = range.bytes();
            if remaining == 0 || !self.incoming_credit_ledger.contains_key(&owner.slot) {
                continue;
            }
            self.return_advertised_credit(owner.slot, remaining);
            self.streams.restore_claim(endpoint, stream, remaining);
            self.return_claim(&PendingClaim {
                slot: owner.slot,
                packet: owner.packet,
                endpoint,
                stream,
                remaining,
            });
        }
    }

    fn return_endpoint_parser_lease_ownership(&mut self, endpoint: QcsdEndpointId) {
        let mut streams: Vec<_> = self
            .parser_lease_ranges
            .keys()
            .filter_map(|(candidate, stream)| (*candidate == endpoint).then_some(*stream))
            .collect();
        streams.sort_unstable();
        streams.dedup();
        for stream in streams {
            self.return_stream_parser_lease_ownership(endpoint, stream);
        }
    }

    fn return_all_parser_lease_ownership(&mut self) {
        let mut streams: Vec<_> = self.parser_lease_ranges.keys().copied().collect();
        streams.sort_unstable();
        for (endpoint, stream) in streams {
            self.return_stream_parser_lease_ownership(endpoint, stream);
        }
    }

    fn return_endpoint_claims(&mut self, endpoint: QcsdEndpointId) {
        let mut returned = Vec::new();
        self.control.claims.retain(|claim| {
            if claim.endpoint == endpoint {
                returned.push(*claim);
                false
            } else {
                true
            }
        });
        for claim in returned {
            self.return_claim(&claim);
        }
    }

    fn return_claim(&mut self, claim: &PendingClaim) {
        if let Some(pending) = self
            .control
            .incoming
            .iter_mut()
            .find(|pending| pending.slot == claim.slot)
        {
            pending.remaining = pending.remaining.saturating_add(claim.remaining);
            pending.endpoint = None;
        } else {
            self.control.incoming.push(PendingIncoming {
                slot: claim.slot,
                packet: claim.packet,
                endpoint: None,
                remaining: claim.remaining,
            });
        }
    }

    fn return_endpoint_credit(&mut self, endpoint: QcsdEndpointId, at: Duration) {
        self.return_matching_credit(|credit| credit.endpoint == endpoint, at);
    }

    fn return_matching_credit(&mut self, matches: impl Fn(&PendingCredit) -> bool, at: Duration) {
        let returned: Vec<_> = self
            .control
            .credit
            .iter()
            .copied()
            .filter(&matches)
            .collect();
        if returned.is_empty() {
            return;
        }
        if self.config.drop_unsatisfied_events {
            let roots: HashSet<_> = returned.iter().map(|credit| credit.slot).collect();
            self.fail_incoming_slots(&roots, MissedSlotReason::EndpointClosed, at, true);
            return;
        }

        let mut rollback = returned.clone();
        rollback.sort_unstable_by(|left, right| {
            left.endpoint
                .cmp(&right.endpoint)
                .then_with(|| left.stream.cmp(&right.stream))
                .then_with(|| right.absolute_limit.cmp(&left.absolute_limit))
        });
        for credit in &rollback {
            assert!(self.streams.cancel_release(
                credit.endpoint,
                credit.stream,
                credit.absolute_limit,
                credit.increase,
            ));
        }
        let returned_keys: HashSet<_> = returned
            .iter()
            .map(|credit| {
                (
                    credit.endpoint,
                    credit.stream,
                    credit.absolute_limit,
                    credit.slot,
                )
            })
            .collect();
        self.actions.retain(|action| {
            !matches!(action, QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit,
                slot,
                ..
            } if returned_keys.contains(&(*endpoint, *stream, *absolute_limit, *slot)))
        });
        self.control.credit.retain(|credit| {
            !returned_keys.contains(&(
                credit.endpoint,
                credit.stream,
                credit.absolute_limit,
                credit.slot,
            ))
        });
        for credit in returned {
            if let Some(pending) = self
                .control
                .incoming
                .iter_mut()
                .find(|pending| pending.slot == credit.slot)
            {
                pending.remaining = pending.remaining.saturating_add(credit.increase);
                pending.endpoint = None;
            } else {
                self.control.incoming.push(PendingIncoming {
                    slot: credit.slot,
                    packet: credit.packet,
                    endpoint: None,
                    remaining: credit.increase,
                });
            }
        }
    }

    fn fail_incoming_slot(
        &mut self,
        slot: QcsdSlotId,
        reason: MissedSlotReason,
        at: Duration,
        emit_action: bool,
    ) {
        self.fail_incoming_slots(&HashSet::from([slot]), reason, at, emit_action);
    }

    /// Fail one or more incoming slots without leaving holes in a stream's
    /// monotonically increasing receive limit.
    ///
    /// If a root slot owns an older unadvertised release, every later release
    /// on that stream is dependent on it. Those slots join the failure set;
    /// the closure is repeated because a dependent slot can itself own credit
    /// on another stream. The complete set is rolled back in descending
    /// absolute-limit order before any records or actions are removed.
    fn unadvertised_receive_ranges(&self) -> Vec<UnadvertisedReceiveRange> {
        let mut ranges: Vec<_> = self
            .control
            .credit
            .iter()
            .copied()
            .map(UnadvertisedReceiveRange::Scheduled)
            .collect();
        ranges.extend(self.parser_lease_ranges.iter().flat_map(
            |(&(endpoint, stream), parser_ranges)| {
                parser_ranges.iter().filter_map(move |range| {
                    (!range.advertised).then_some(UnadvertisedReceiveRange::Parser {
                        endpoint,
                        stream,
                        range: *range,
                    })
                })
            },
        ));
        ranges
    }

    fn dependent_unadvertised_slots(&self, roots: &HashSet<QcsdSlotId>) -> HashSet<QcsdSlotId> {
        let ranges = self.unadvertised_receive_ranges();
        let mut affected = roots.clone();
        loop {
            let mut cutoffs = HashMap::new();
            for range in &ranges {
                if range.slot().is_some_and(|slot| affected.contains(&slot)) {
                    cutoffs
                        .entry((range.endpoint(), range.stream()))
                        .and_modify(|cutoff: &mut u64| *cutoff = (*cutoff).min(range.start()))
                        .or_insert_with(|| range.start());
                }
            }
            let before = affected.len();
            for range in &ranges {
                if cutoffs
                    .get(&(range.endpoint(), range.stream()))
                    .is_some_and(|cutoff| range.absolute_limit() > *cutoff)
                    && let Some(slot) = range.slot()
                {
                    affected.insert(slot);
                }
            }
            if affected.len() == before {
                return affected;
            }
        }
    }

    /// Roll back the complete mixed scheduled/parser suffix for failed slots.
    /// Selection is computed before mutation and cancellation is globally LIFO
    /// per stream, so an interleaved parser range can never strand a later
    /// ordinary release.
    fn failed_receive_ranges(
        &self,
        affected: &HashSet<QcsdSlotId>,
    ) -> Vec<UnadvertisedReceiveRange> {
        let ranges = self.unadvertised_receive_ranges();
        let mut cutoffs = HashMap::new();
        for range in &ranges {
            if range.slot().is_some_and(|slot| affected.contains(&slot)) {
                cutoffs
                    .entry((range.endpoint(), range.stream()))
                    .and_modify(|cutoff: &mut u64| *cutoff = (*cutoff).min(range.start()))
                    .or_insert_with(|| range.start());
            }
        }
        let mut rollback: Vec<_> = ranges
            .into_iter()
            .filter(|range| {
                cutoffs
                    .get(&(range.endpoint(), range.stream()))
                    .is_some_and(|cutoff| range.absolute_limit() > *cutoff)
            })
            .collect();
        rollback.sort_unstable_by(|left, right| {
            left.endpoint()
                .cmp(&right.endpoint())
                .then_with(|| left.stream().cmp(&right.stream()))
                .then_with(|| right.absolute_limit().cmp(&left.absolute_limit()))
        });
        rollback
    }

    #[expect(
        clippy::too_many_lines,
        reason = "mixed-range LIFO rollback and ownership reconciliation form one transaction"
    )]
    fn rollback_failed_receive_ranges(
        &mut self,
        affected: &HashSet<QcsdSlotId>,
    ) -> Vec<QcsdReceiveActionIdentity> {
        let rollback = self.failed_receive_ranges(affected);

        let identities: Vec<_> = rollback.iter().map(|range| range.identity()).collect();
        let mut returned_parser_owners = Vec::new();
        for range in rollback {
            match range {
                UnadvertisedReceiveRange::Scheduled(credit) => {
                    assert!(
                        affected.contains(&credit.slot),
                        "dependent scheduled suffix slot must join failure closure"
                    );
                    assert!(self.streams.cancel_release(
                        credit.endpoint,
                        credit.stream,
                        credit.absolute_limit,
                        credit.increase,
                    ));
                }
                UnadvertisedReceiveRange::Parser {
                    endpoint,
                    stream,
                    range,
                } => {
                    assert!(self.streams.cancel_parser_lease(
                        endpoint,
                        stream,
                        range.end,
                        range.bytes(),
                        range.unowned,
                    ));
                    if let Some(owner) = range.owner {
                        returned_parser_owners.push((endpoint, stream, owner, range.bytes()));
                    }
                }
            }
        }

        self.control.credit.retain(|credit| {
            !identities.contains(&QcsdReceiveActionIdentity::Scheduled {
                endpoint: credit.endpoint,
                stream: credit.stream,
                absolute_limit: credit.absolute_limit,
                slot: credit.slot,
            })
        });
        let mut parser_streams: Vec<_> = self.parser_lease_ranges.keys().copied().collect();
        parser_streams.sort_unstable();
        let mut empty_parser_streams = Vec::new();
        for (endpoint, stream) in parser_streams {
            let Some(parser_ranges) = self.parser_lease_ranges.get_mut(&(endpoint, stream)) else {
                continue;
            };
            parser_ranges.retain(|range| {
                !identities.contains(&QcsdReceiveActionIdentity::ParserLease {
                    endpoint,
                    stream,
                    absolute_limit: range.end,
                    increase: range.bytes(),
                    owner: range.owner,
                })
            });
            if parser_ranges.is_empty() {
                empty_parser_streams.push((endpoint, stream));
            }
        }
        for key in empty_parser_streams {
            self.parser_lease_ranges.remove(&key);
        }
        self.actions.retain(|action| {
            action
                .receive_identity()
                .is_none_or(|identity| !identities.contains(&identity))
        });

        for (endpoint, stream, owner, bytes) in returned_parser_owners {
            self.streams.restore_claim(endpoint, stream, bytes);
            if !affected.contains(&owner.slot) {
                self.return_claim(&PendingClaim {
                    slot: owner.slot,
                    packet: owner.packet,
                    endpoint,
                    stream,
                    remaining: bytes,
                });
            }
        }

        let mut parser_streams: Vec<_> = self.parser_lease_ranges.keys().copied().collect();
        parser_streams.sort_unstable();
        let mut advertised_owners = Vec::new();
        for (endpoint, stream) in parser_streams {
            let Some(parser_ranges) = self.parser_lease_ranges.get_mut(&(endpoint, stream)) else {
                continue;
            };
            for range in parser_ranges {
                if let Some(owner) = range.owner
                    && affected.contains(&owner.slot)
                {
                    debug_assert!(range.advertised);
                    advertised_owners.push((endpoint, stream, range.bytes()));
                    range.owner = None;
                    range.unowned = false;
                }
            }
        }
        for (endpoint, stream, bytes) in advertised_owners {
            self.streams.restore_claim(endpoint, stream, bytes);
        }
        identities
    }

    fn fail_incoming_slots(
        &mut self,
        roots: &HashSet<QcsdSlotId>,
        reason: MissedSlotReason,
        at: Duration,
        emit_root_actions: bool,
    ) -> (HashSet<QcsdSlotId>, Vec<QcsdReceiveActionIdentity>) {
        if roots.is_empty() {
            return (HashSet::new(), Vec::new());
        }

        let affected = self.dependent_unadvertised_slots(roots);
        let canceled_actions = self.rollback_failed_receive_ranges(&affected);

        let claims: Vec<_> = self
            .control
            .claims
            .iter()
            .copied()
            .filter(|claim| affected.contains(&claim.slot))
            .collect();
        self.control
            .claims
            .retain(|claim| !affected.contains(&claim.slot));
        for claim in claims {
            self.streams
                .restore_claim(claim.endpoint, claim.stream, claim.remaining);
        }
        self.control
            .incoming
            .retain(|incoming| !affected.contains(&incoming.slot));
        self.advertised_incoming_credit.retain(|_, ranges| {
            ranges.retain(|range| !affected.contains(&range.slot));
            !ranges.is_empty()
        });

        let mut slots: Vec<_> = affected.iter().copied().collect();
        slots.sort_unstable();
        for slot in slots {
            let Some(mut ledger) = self.incoming_credit_ledger.remove(&slot) else {
                continue;
            };
            let retired = ledger.unresolved();
            ledger.retired = ledger.retired.saturating_add(retired);
            self.scheduled_incoming_retired_bytes = self
                .scheduled_incoming_retired_bytes
                .saturating_add(retired);
            if retired > 0 {
                self.push_signal(at, SignalKind::ReceiveCreditRetired { bytes: retired });
            }
            self.control.terminal_incoming.insert(slot);
            if emit_root_actions || !roots.contains(&slot) {
                self.actions.push_back(QcsdAction::SlotMissed {
                    endpoint: ledger.action_endpoint(),
                    packet: ledger.packet,
                    slot,
                    reason,
                });
            }
            self.resolve_slot(at, slot, EventOutcome::Missed(reason));
        }
        (affected, canceled_actions)
    }

    /// Advance the published control loop to `elapsed` and queue due actions.
    pub fn poll(&mut self, elapsed: Duration) {
        if self.fixed_schedule.is_some() {
            self.reconcile_due_fixed(elapsed);
            self.release_chaff_send_shaping_if_needed();
            self.update_completion(elapsed);
            return;
        }

        self.drain_observations();
        let candidate_terminal_drain = self.defense.requires_terminal_chaff_drain();
        if !candidate_terminal_drain {
            self.request_chaff_if_needed(true);
        }
        self.refresh_receiver_continuation_reserves();
        self.emit_capacity_signal(elapsed);
        self.sync_candidate_egress_backlog(elapsed);
        // Capacity is controller-generated rather than a transport callback.
        // Deliver it now so due events use the freshly reserve-adjusted value.
        self.drain_observations();
        self.collect_due_events(elapsed);
        self.cancel_closed_rolling_prearm();
        if candidate_terminal_drain {
            // Candidate quiet termination observes the backlog that existed at
            // the timer boundary. Proactive low-watermark replenishment must
            // not manufacture new work immediately before that decision.
            self.request_chaff_if_needed(true);
        }
        self.process_outgoing(elapsed);
        self.release_chaff_send_shaping_if_needed();

        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        if self.defense.incoming_slot_must_resolve_in_window() {
            // Exact-window opportunities can occur anywhere inside the
            // controller's legacy control interval (CS-BuFLO deliberately
            // jitters them).  Handle each due event at the current instant;
            // rounding it to the next interval can move the first allocation
            // attempt beyond its exclusive deadline.  Exact-window failures
            // are terminal, so this cannot create a retry or catch-up loop.
            self.process_incoming(elapsed_us, elapsed);
        } else {
            let boundary_us = ControlLoop::boundary_us(elapsed_us, self.config.control_interval_us);
            if self.control.should_process_incoming(boundary_us) {
                self.process_incoming(boundary_us, elapsed);
            }
        }
        self.retry_pending_parser_leases();

        self.request_chaff_if_needed(false);
        if candidate_terminal_drain {
            self.sync_candidate_egress_backlog(elapsed);
            self.drain_observations();
        }
        self.update_completion(elapsed);
        self.arm_next_rolling_outgoing(elapsed);
    }

    /// Whether this controller opted into fixed-schedule outgoing prearming.
    #[must_use]
    pub const fn has_fixed_schedule_staging(&self) -> bool {
        self.fixed_schedule.is_some()
    }

    /// Whether a pure future outgoing preview is staged in the adapter.
    #[must_use]
    pub const fn has_rolling_outgoing_prearm(&self) -> bool {
        self.rolling_outgoing_prearm.is_some()
    }

    /// Whether endpoint-loss recovery requires one post-observation-barrier
    /// reconciliation even when no survivor could own a replacement preview.
    #[must_use]
    pub const fn has_due_rolling_reconciliation(&self) -> bool {
        self.rolling_reconcile_due.is_some()
    }

    /// Exact preview identity retained for fail-closed abort evidence when a
    /// due endpoint-loss reconciliation cannot be completed.
    #[must_use]
    pub const fn rolling_reconciliation_due_packet(&self) -> Option<crate::Packet> {
        self.rolling_reconcile_due
    }

    /// Endpoint owning the currently staged rolling preview, if any.
    #[must_use]
    pub const fn rolling_outgoing_prearm_endpoint(&self) -> Option<QcsdEndpointId> {
        match self.rolling_outgoing_prearm_identity() {
            Some((endpoint, _, _)) => Some(endpoint),
            None => None,
        }
    }

    /// Exact identity of the currently staged rolling preview, if any.
    ///
    /// The runner uses the complete identity at a fidelity-sensitive release
    /// boundary.  Endpoint-only matching is insufficient because a stale
    /// adapter preview could otherwise be confused with a later slot owned by
    /// the same connection.
    #[must_use]
    pub const fn rolling_outgoing_prearm_identity(
        &self,
    ) -> Option<(QcsdEndpointId, crate::Packet, QcsdSlotId)> {
        match self.rolling_outgoing_prearm {
            Some(prearm) => Some((prearm.endpoint, prearm.packet, prearm.slot)),
            None => None,
        }
    }

    /// Retract the controller's provisional rolling target during abnormal
    /// shutdown and return its single typed adapter reconciliation action.
    ///
    /// The returned preview is not a defense event. Callers that own an
    /// adapter must either apply the cancellation or receipt that the preview
    /// never reached (or was already discarded by) that adapter.
    pub fn take_rolling_prearm_for_abort(&mut self) -> Option<QcsdAction> {
        self.rolling_reconcile_due = None;
        if let Some(prearm) = self.rolling_outgoing_prearm.take() {
            self.actions.retain(|action| {
                !matches!(
                    action,
                    QcsdAction::PrearmPacket {
                        endpoint,
                        packet,
                        slot,
                        ..
                    } if *endpoint == prearm.endpoint && *packet == prearm.packet && *slot == prearm.slot
                )
            });
            return Some(QcsdAction::CancelPrearmedPacket {
                endpoint: prearm.endpoint,
                packet: prearm.packet,
                slot: prearm.slot,
                reason: QcsdPrearmCancellationReason::RunAborted,
            });
        }

        // A terminal/failure poll can already have transferred ownership into
        // a queued DefenseTerminal cancellation before the runner notices the
        // enclosing abort. Consume and reason-normalize that same identity so
        // cleanup produces exactly one lifecycle receipt.
        let index = self
            .actions
            .iter()
            .position(|action| matches!(action, QcsdAction::CancelPrearmedPacket { .. }))?;
        let QcsdAction::CancelPrearmedPacket {
            endpoint,
            packet,
            slot,
            ..
        } = self.actions.remove(index)?
        else {
            return None;
        };
        Some(QcsdAction::CancelPrearmedPacket {
            endpoint,
            packet,
            slot,
            reason: QcsdPrearmCancellationReason::RunAborted,
        })
    }

    /// Reconcile a due rolling preview before transport can build output.
    ///
    /// The runner invokes this at the start of every output drive. Calling the
    /// ordinary poll preserves observation/capacity/terminal ordering while
    /// ensuring commit or cancellation is applied before target eligibility.
    ///
    /// # Errors
    ///
    /// Returns an error if the staged rolling identity diverges from the
    /// defense oracle or if a due event cannot be materialized exactly once.
    pub fn reconcile_due_rolling(&mut self, elapsed: Duration) -> Result<()> {
        // Keep the marker live until reconciliation succeeds. A controller
        // invariant must not erase the abandoned preview identity before the
        // runner records explicit fail-closed abort evidence.
        let abandoned_due = self.rolling_reconcile_due;
        if let Some(packet) = abandoned_due {
            let deadline = packet
                .timestamp()
                .saturating_add(self.config.control_interval());
            if (elapsed > packet.timestamp()
                || duration_as_floor_micros(deadline.saturating_sub(elapsed)) == 0)
                && !self.defense.is_complete()
                && self.defense.terminal_failure().is_none()
            {
                self.fail_late_abandoned_rolling(packet, elapsed)?;
                self.rolling_reconcile_due = None;
                return Ok(());
            }
        }
        let ordinary_due = self
            .rolling_outgoing_prearm
            .filter(|prearm| prearm.packet.timestamp() <= elapsed)
            .map(|prearm| prearm.packet);
        let expected_due = match (abandoned_due, ordinary_due) {
            (Some(abandoned), Some(prearmed)) if abandoned != prearmed => {
                return Err(crate::Error::ControllerInvariant(format!(
                    "due abandoned rolling identity {abandoned:?} conflicts with live preview {prearmed:?}"
                )));
            }
            (Some(packet), _) | (None, Some(packet)) => Some(packet),
            (None, None) => None,
        };
        if let Some(expected) = expected_due {
            let enforce_identity =
                !self.defense.is_complete() && self.defense.terminal_failure().is_none();
            if enforce_identity {
                let preview = self.defense.next_outgoing_prearm();
                if preview != Some(expected) {
                    return Err(crate::Error::ControllerInvariant(format!(
                        "due rolling identity {expected:?} diverged from the defense preview {preview:?}"
                    )));
                }
            }
            self.poll(elapsed);
            let still_active =
                !self.defense.is_complete() && self.defense.terminal_failure().is_none();
            if enforce_identity && still_active && !self.rolling_event_has_receipt(expected) {
                return Err(crate::Error::ControllerInvariant(format!(
                    "defense did not materialize due rolling identity {expected:?}"
                )));
            }
            self.rolling_reconcile_due = None;
        }
        Ok(())
    }

    fn rolling_event_has_receipt(&self, packet: crate::Packet) -> bool {
        self.pending_slots
            .values()
            .any(|pending| *pending == packet)
            || self.actions.iter().any(|action| match action {
                QcsdAction::CommitPrearmedPacket {
                    packet: observed, ..
                }
                | QcsdAction::SendPacket {
                    packet: observed, ..
                }
                | QcsdAction::SlotMissed {
                    packet: observed, ..
                }
                | QcsdAction::SlotSatisfied {
                    packet: observed, ..
                } => *observed == packet,
                _ => false,
            })
    }

    fn arm_next_rolling_outgoing(&mut self, elapsed: Duration) {
        if self.fixed_schedule.is_some()
            || self.rolling_outgoing_prearm.is_some()
            || self.defense.is_complete()
            || self.defense.terminal_failure().is_some()
            || self.scheduler.endpoints().is_empty()
        {
            return;
        }
        let Some(packet) = self.defense.next_outgoing_prearm() else {
            return;
        };
        if packet.direction() != Direction::Outgoing || packet.timestamp() <= elapsed {
            return;
        }
        let deadline = packet
            .timestamp()
            .saturating_add(self.config.control_interval());
        let not_before_after_us =
            duration_as_ceil_micros(packet.timestamp().saturating_sub(elapsed));
        let deadline_after_us = duration_as_floor_micros(deadline.saturating_sub(elapsed));
        if deadline_after_us == 0 || not_before_after_us >= deadline_after_us {
            return;
        }
        let Some(endpoint) = self.scheduler.next_outgoing() else {
            return;
        };
        let slot = self.control.next_slot();
        self.rolling_outgoing_prearm = Some(RollingOutgoingPrearm {
            endpoint,
            packet,
            slot,
        });
        self.actions.push_back(QcsdAction::PrearmPacket {
            endpoint,
            packet,
            slot,
            not_before_after_us,
            deadline_after_us,
            allow_stream_data: self.defense.mode() == DefenseMode::ChaffAndShape,
        });
    }

    fn cancel_closed_rolling_prearm(&mut self) {
        if self.rolling_outgoing_prearm.is_none()
            || (!self.defense.is_complete() && self.defense.terminal_failure().is_none())
        {
            return;
        }
        let prearm = self
            .rolling_outgoing_prearm
            .take()
            .expect("rolling prearm inspected");
        let queued_index = self.actions.iter().position(|action| {
            matches!(
                action,
                QcsdAction::PrearmPacket {
                    endpoint,
                    packet,
                    slot,
                    ..
                } if *endpoint == prearm.endpoint && *packet == prearm.packet && *slot == prearm.slot
            )
        });
        if let Some(index) = queued_index {
            _ = self.actions.remove(index);
        } else {
            self.actions.push_back(QcsdAction::CancelPrearmedPacket {
                endpoint: prearm.endpoint,
                packet: prearm.packet,
                slot: prearm.slot,
                reason: QcsdPrearmCancellationReason::DefenseTerminal,
            });
        }
    }

    fn abandon_closed_endpoint_prearm(
        &mut self,
        endpoint: QcsdEndpointId,
    ) -> Option<RollingOutgoingPrearm> {
        let prearm = self
            .rolling_outgoing_prearm
            .filter(|prearm| prearm.endpoint == endpoint)?;
        self.rolling_outgoing_prearm = None;
        self.actions.retain(|action| {
            !matches!(
                action,
                QcsdAction::PrearmPacket {
                    endpoint: candidate,
                    packet,
                    slot,
                    ..
                } if *candidate == endpoint && *packet == prearm.packet && *slot == prearm.slot
            )
        });
        Some(prearm)
    }

    fn recover_abandoned_rolling_prearm(
        &mut self,
        abandoned: Option<RollingOutgoingPrearm>,
        elapsed: Duration,
    ) {
        let Some(abandoned) = abandoned else {
            return;
        };
        if abandoned.packet.timestamp() > elapsed {
            self.arm_next_rolling_outgoing(elapsed);
            return;
        }

        self.rolling_reconcile_due = Some(abandoned.packet);

        let deadline = abandoned
            .packet
            .timestamp()
            .saturating_add(self.config.control_interval());
        let deadline_after_us = duration_as_floor_micros(deadline.saturating_sub(elapsed));
        if deadline_after_us > 0
            && self.defense.terminal_failure().is_none()
            && let Some(endpoint) = self.scheduler.next_outgoing()
        {
            let slot = self.control.next_slot();
            self.rolling_outgoing_prearm = Some(RollingOutgoingPrearm {
                endpoint,
                packet: abandoned.packet,
                slot,
            });
            self.actions.push_back(QcsdAction::PrearmPacket {
                endpoint,
                packet: abandoned.packet,
                slot,
                not_before_after_us: 0,
                deadline_after_us,
                allow_stream_data: self.defense.mode() == DefenseMode::ChaffAndShape,
            });
        }

        // Do not poll here: `EndpointClosed` can be followed by later records
        // in the same globally ordered observation batch. The runner consumes
        // `rolling_reconcile_due` only after that complete causal prefix and
        // all resulting defense signals have been reduced.
    }

    fn fail_late_abandoned_rolling(
        &mut self,
        packet: crate::Packet,
        elapsed: Duration,
    ) -> Result<()> {
        let replacement = match self.rolling_outgoing_prearm {
            Some(prearm) if prearm.packet == packet => Some(prearm),
            Some(prearm) => {
                return Err(crate::Error::ControllerInvariant(format!(
                    "late abandoned rolling identity {packet:?} conflicts with live preview {:?}",
                    prearm.packet
                )));
            }
            None => None,
        };

        let defense_preview = self.defense.next_outgoing_prearm();
        if defense_preview != Some(packet) {
            return Err(crate::Error::ControllerInvariant(format!(
                "late abandoned rolling identity {packet:?} diverged from the defense preview {defense_preview:?}"
            )));
        }

        // Consume the exact outgoing event at its logical release so BuFLO's
        // no-catch-up guard cannot erase its terminal identity. Validate the
        // oracle result before mutating the live preview or queued adapter
        // action; any divergence is fatal and remains available to abort
        // reconciliation.
        let realized = self.defense.next_event(packet.timestamp()).ok_or_else(|| {
            crate::Error::ControllerInvariant(format!(
                "defense returned no event for late abandoned rolling identity {packet:?}"
            ))
        })?;
        if realized != packet {
            return Err(crate::Error::ControllerInvariant(format!(
                "defense returned {realized:?} for late abandoned rolling identity {packet:?}"
            )));
        }

        if let Some(prearm) = replacement {
            self.rolling_outgoing_prearm = None;
            self.actions.retain(|action| {
                !matches!(
                    action,
                    QcsdAction::PrearmPacket {
                        endpoint,
                        packet: queued_packet,
                        slot,
                        ..
                    } if *endpoint == prearm.endpoint
                        && *queued_packet == prearm.packet
                        && *slot == prearm.slot
                )
            });
        }
        let slot = replacement.map_or_else(|| self.control.next_slot(), |prearm| prearm.slot);
        let deadline = packet
            .timestamp()
            .saturating_add(self.config.control_interval());
        let reason = if elapsed >= deadline {
            MissedSlotReason::DeadlineExpired
        } else {
            MissedSlotReason::TimerLate
        };
        self.pending_slots.insert(slot, packet);
        self.actions.push_back(QcsdAction::SlotMissed {
            endpoint: None,
            packet,
            slot,
            reason,
        });
        self.resolve_slot(elapsed, slot, EventOutcome::Missed(reason));

        // Preserve outgoing-before-incoming at the abandoned tick, then give
        // the paired incoming opportunity its own typed late/deadline failure.
        self.collect_due_events(packet.timestamp());
        let incoming_slots: Vec<_> = self
            .pending_slots
            .iter()
            .filter_map(|(slot, candidate)| {
                (candidate.timestamp() == packet.timestamp()
                    && candidate.direction() == Direction::Incoming)
                    .then_some(*slot)
            })
            .collect();
        for incoming_slot in incoming_slots {
            self.fail_incoming_slot(incoming_slot, reason, elapsed, true);
        }
        self.drain_observations();
        self.cancel_closed_rolling_prearm();
        self.update_completion(elapsed);
        Ok(())
    }

    /// Reconcile every due fixed event before an eligible prearmed output flush.
    ///
    /// This is intentionally a FRONT-only microstep. Outgoing targets are
    /// staged once with frozen endpoints; incoming events become controller
    /// state only after they are due, in the original global trace order.
    pub fn reconcile_due_fixed(&mut self, elapsed: Duration) {
        if self.fixed_schedule.is_none() {
            return;
        }

        self.drain_observations();
        self.request_chaff_if_needed(true);
        self.refresh_receiver_continuation_reserves();
        self.emit_capacity_signal(elapsed);
        self.sync_candidate_egress_backlog(elapsed);
        self.drain_observations();
        self.prearm_fixed_outgoing(elapsed);
        self.materialize_due_fixed(elapsed);

        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let boundary_us = ControlLoop::boundary_us(elapsed_us, self.config.control_interval_us);
        // Fixed schedules retry at the exact current instant, including more
        // than once within one control interval.  Advance only the watermark
        // used by `next_deadline`; gating the retry would let a newly due
        // fixed event cross a same-interval outgoing flush.
        self.control.last_incoming_boundary_us = Some(boundary_us);
        self.process_incoming(elapsed_us, elapsed);
        self.retry_pending_parser_leases();
        self.request_chaff_if_needed(false);
        self.sync_candidate_egress_backlog(elapsed);
        self.drain_observations();
    }

    fn prearm_fixed_outgoing(&mut self, elapsed: Duration) {
        let Some(staging) = self.fixed_schedule.as_mut() else {
            return;
        };
        if staging.outgoing_prearmed || self.scheduler.endpoints().is_empty() {
            return;
        }
        staging.outgoing_prearmed = true;
        let outgoing: Vec<_> = staging
            .events
            .iter()
            .copied()
            .filter(|event| event.packet.direction() == Direction::Outgoing)
            .collect();

        for event in outgoing {
            self.pending_slots.insert(event.slot, event.packet);
            let deadline = event
                .packet
                .timestamp()
                .saturating_add(self.config.control_interval());
            let not_before_after_us =
                duration_as_ceil_micros(event.packet.timestamp().saturating_sub(elapsed));
            let deadline_after_us = duration_as_floor_micros(deadline.saturating_sub(elapsed));
            if elapsed >= deadline
                || deadline_after_us == 0
                || not_before_after_us >= deadline_after_us
            {
                self.actions.push_back(QcsdAction::SlotMissed {
                    endpoint: None,
                    packet: event.packet,
                    slot: event.slot,
                    reason: MissedSlotReason::DeadlineExpired,
                });
                self.resolve_slot(
                    elapsed,
                    event.slot,
                    EventOutcome::Missed(MissedSlotReason::DeadlineExpired),
                );
                continue;
            }
            let Some(endpoint) = self.scheduler.next_outgoing() else {
                debug_assert!(false, "fixed prearming requires a ready endpoint");
                continue;
            };
            self.actions.push_back(QcsdAction::SendPacket {
                endpoint,
                packet: event.packet,
                slot: event.slot,
                not_before_after_us,
                // Rounding the release upward prevents an early send; rounding
                // the deadline downward preserves the strict half-open window.
                deadline_after_us,
                allow_stream_data: self.defense.mode() == DefenseMode::ChaffAndShape,
                send_policy: self.defense.outgoing_send_policy(),
            });
        }
    }

    fn materialize_due_fixed(&mut self, elapsed: Duration) {
        while let Some(event) = self
            .fixed_schedule
            .as_ref()
            .and_then(|staging| staging.events.front())
            .copied()
            .filter(|event| event.packet.timestamp() <= elapsed)
        {
            let Some(packet) = self.defense.next_event(elapsed) else {
                debug_assert!(false, "fixed snapshot diverged from defense output");
                break;
            };
            debug_assert_eq!(packet, event.packet);
            _ = self
                .fixed_schedule
                .as_mut()
                .and_then(|staging| staging.events.pop_front());

            if packet.direction() == Direction::Incoming {
                self.materialize_incoming(event.slot, packet, elapsed);
            }
        }
    }

    fn refresh_receiver_continuation_reserves(&mut self) {
        // An allocated tagged continuation is no longer in `control.incoming`,
        // so removing its oldest reserve cannot refill it on a later poll.
        // Only a failed unadvertised allocation is requeued here; in that case
        // rebuilding the full current horizon is the required rollback.
        let Some(disposition) = self.defense.pending_receiver_continuation().or_else(|| {
            self.control.incoming.iter().find_map(|pending| {
                self.control
                    .receiver_continuations
                    .get(&pending.slot)
                    .copied()
            })
        }) else {
            return;
        };
        let endpoint_order = self.scheduler.incoming_order();
        _ = self.ensure_receiver_continuation_reserves(
            &endpoint_order,
            self.defense.receiver_continuation_reserve_horizon(),
            disposition.cell_bytes,
            disposition.parser_ceiling_bytes,
        );
    }

    fn emit_capacity_signal(&mut self, at: Duration) {
        let capacity = self.streams.aggregate_capacity();
        self.defense
            .observe_capacity_adjustment(CapacityAdjustment {
                reserved_chaff_bytes: self
                    .streams
                    .reserved_exact_capacity(&self.control.receiver_continuation_reserves),
            });
        if self.last_capacity != Some(capacity) {
            self.last_capacity = Some(capacity);
            self.push_signal(at, SignalKind::Capacity(capacity));
        }
    }

    fn retry_pending_parser_leases(&mut self) {
        for (endpoint, stream) in self.streams.pending_parser_boundaries() {
            self.try_parser_lease(endpoint, stream, true);
        }
    }

    /// Preserve whether CS-BuFLO's irreversible local termination preceded
    /// the ordered application-complete signal.  The runner can enqueue both
    /// observations in one barrier, so the eager controller flag alone cannot
    /// represent their causal order.
    fn record_cs_buflo_local_et_ordering(&mut self) {
        if !self.cs_buflo_local_et_before_application_complete
            && !self.application_complete_delivered_to_defense
            && self.defense.is_complete()
            && self.defense.terminal_failure().is_none()
            && self.defense.terminal_chaff_cancellation_reason()
                == Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination)
        {
            self.cs_buflo_local_et_before_application_complete = true;
        }
    }

    fn drain_observations(&mut self) {
        let mut pending: Vec<_> = self.observations.drain(..).collect();
        pending.sort_by_key(|observation| observation.at());
        for observation in pending {
            let at = self
                .last_delivered_observation_at
                .map_or_else(|| observation.at(), |last| observation.at().max(last));
            self.last_delivered_observation_at = Some(at);
            match observation {
                QueuedDefenseObservation::Signal(mut signal) => {
                    signal.at = at;
                    if matches!(signal.kind, SignalKind::ApplicationComplete) {
                        // Mark this before delivery: a termination transition
                        // caused by onLoad itself is not a pre-onLoad latch.
                        self.application_complete_delivered_to_defense = true;
                    }
                    self.defense.observe(signal);
                }
                QueuedDefenseObservation::ApplicationBytes {
                    direction, bytes, ..
                } => self.defense.observe_application_bytes(at, direction, bytes),
            }
            self.record_cs_buflo_local_et_ordering();
        }
    }

    fn collect_due_events(&mut self, elapsed: Duration) {
        while let Some(packet) = self.defense.next_event(elapsed) {
            let receiver_continuation = self.defense.last_incoming_event_receiver_continuation();
            let prearmed = (packet.direction() == Direction::Outgoing)
                .then_some(self.rolling_outgoing_prearm)
                .flatten()
                .filter(|prearm| prearm.packet == packet);
            let slot = prearmed.map_or_else(|| self.control.next_slot(), |prearm| prearm.slot);
            self.pending_slots.insert(slot, packet);
            match packet.direction() {
                Direction::Outgoing => {
                    if let Some(prearm) = prearmed {
                        self.rolling_outgoing_prearm = None;
                        self.actions.push_back(QcsdAction::CommitPrearmedPacket {
                            endpoint: prearm.endpoint,
                            packet,
                            slot,
                        });
                    } else {
                        self.control.outgoing.push(PendingOutgoing { slot, packet });
                    }
                }
                Direction::Incoming => self.materialize_incoming_with_disposition(
                    slot,
                    packet,
                    elapsed,
                    receiver_continuation,
                ),
            }
        }
    }

    fn materialize_incoming(&mut self, slot: QcsdSlotId, packet: crate::Packet, elapsed: Duration) {
        let receiver_continuation = self.defense.last_incoming_event_receiver_continuation();
        self.pending_slots.insert(slot, packet);
        self.materialize_incoming_with_disposition(slot, packet, elapsed, receiver_continuation);
    }

    fn materialize_incoming_with_disposition(
        &mut self,
        slot: QcsdSlotId,
        packet: crate::Packet,
        elapsed: Duration,
        receiver_continuation: Option<crate::ReceiverContinuationDisposition>,
    ) {
        if let Some(disposition) = receiver_continuation {
            self.control
                .receiver_continuations
                .insert(slot, disposition);
        }
        self.incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        self.scheduled_incoming_requested_bytes = self
            .scheduled_incoming_requested_bytes
            .saturating_add(u64::from(packet.length()));
        self.push_signal(elapsed, SignalKind::ReceiveCreditRequested { packet });
        if self.defense.split_incoming_credit_lifecycle() {
            self.push_signal(
                elapsed,
                SignalKind::IncomingCreditScheduled { slot, packet },
            );
        }
        self.control.incoming.push(PendingIncoming {
            slot,
            packet,
            endpoint: None,
            remaining: u64::from(packet.length()),
        });
    }

    fn process_outgoing(&mut self, elapsed: Duration) {
        let pending = std::mem::take(&mut self.control.outgoing);
        for outgoing in pending {
            let send_policy = self.defense.outgoing_send_policy();
            let deadline = outgoing
                .packet
                .timestamp()
                .saturating_add(self.config.control_interval());
            if send_policy != crate::QcsdSendPolicy::CongestionSensitive && elapsed >= deadline {
                self.actions.push_back(QcsdAction::SlotMissed {
                    endpoint: None,
                    packet: outgoing.packet,
                    slot: outgoing.slot,
                    reason: MissedSlotReason::DeadlineExpired,
                });
                self.resolve_slot(
                    elapsed,
                    outgoing.slot,
                    EventOutcome::Missed(MissedSlotReason::DeadlineExpired),
                );
                continue;
            }
            let Some(endpoint) = self.scheduler.next_outgoing() else {
                if self.config.drop_unsatisfied_events
                    || send_policy == crate::QcsdSendPolicy::CongestionSensitive
                {
                    self.actions.push_back(QcsdAction::SlotMissed {
                        endpoint: None,
                        packet: outgoing.packet,
                        slot: outgoing.slot,
                        reason: MissedSlotReason::NoEndpoint,
                    });
                    self.resolve_slot(
                        elapsed,
                        outgoing.slot,
                        EventOutcome::Missed(MissedSlotReason::NoEndpoint),
                    );
                } else {
                    self.control.outgoing.push(outgoing);
                }
                continue;
            };
            // A congestion-sensitive CS-BuFLO event is a one-shot transport
            // opportunity, not a fixed historical slot. Once its timer is
            // handled, give that opportunity one complete controller window;
            // retaining the packet timestamp still exposes timer wakeup delay
            // in the schedule/action trace without converting it into an
            // artificial deadline miss or a queued catch-up cadence.
            let deadline_after_us = if send_policy == crate::QcsdSendPolicy::CongestionSensitive {
                self.config.control_interval_us
            } else {
                u64::try_from(deadline.saturating_sub(elapsed).as_micros()).unwrap_or(u64::MAX)
            };
            self.actions.push_back(QcsdAction::SendPacket {
                endpoint,
                packet: outgoing.packet,
                slot: outgoing.slot,
                not_before_after_us: 0,
                deadline_after_us,
                allow_stream_data: self.defense.mode() == DefenseMode::ChaffAndShape,
                send_policy,
            });
        }
    }

    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "atomic staged allocation keeps exact credit, claims, rollback, and promotion auditable"
    )]
    fn process_incoming(&mut self, boundary_us: u64, elapsed: Duration) {
        let pending = std::mem::take(&mut self.control.incoming);
        let pending_len = pending.len();
        let exact_window = self.defense.incoming_slot_must_resolve_in_window();
        let terminal_chaff_incoming = self.defense.mode() == DefenseMode::ChaffOnly
            && self.defense.is_incoming_complete()
            && self.defense.pending_receiver_continuation().is_none();
        let initial_survivor_gate_disposition =
            self.defense.pending_receiver_continuation().or_else(|| {
                pending.iter().find_map(|pending| {
                    self.control
                        .receiver_continuations
                        .get(&pending.slot)
                        .copied()
                })
            });
        for (pending_index, mut incoming) in pending.into_iter().enumerate() {
            if incoming.packet.timestamp_us() > boundary_us {
                self.control.incoming.push(incoming);
                continue;
            }
            if exact_window
                && elapsed
                    >= incoming
                        .packet
                        .timestamp()
                        .saturating_add(self.config.control_interval())
            {
                self.fail_incoming_slot(
                    incoming.slot,
                    MissedSlotReason::DeadlineExpired,
                    elapsed,
                    true,
                );
                continue;
            }
            let endpoint_order = self.scheduler.next_incoming_order();
            let miss_reason = if endpoint_order.is_empty() {
                MissedSlotReason::NoEndpoint
            } else {
                MissedSlotReason::InsufficientIncomingCapacity
            };
            let tagged_disposition = self
                .control
                .receiver_continuations
                .get(&incoming.slot)
                .copied();
            let reserve_disposition = self
                .defense
                .pending_receiver_continuation()
                .or(tagged_disposition)
                .or(if self.control.receiver_continuation_survivor_gate_open {
                    None
                } else {
                    initial_survivor_gate_disposition
                });
            let reserve_horizon = self.defense.receiver_continuation_reserve_horizon();
            if let Some(disposition) = reserve_disposition {
                if !self.ensure_receiver_continuation_reserves(
                    &endpoint_order,
                    reserve_horizon,
                    disposition.cell_bytes,
                    disposition.parser_ceiling_bytes,
                ) {
                    // Reservation is part of the causal allocation precondition
                    // and therefore follows the configured terminal/drop policy.
                    self.causal_unsatisfied_incoming(incoming, miss_reason, elapsed);
                    continue;
                }
                if !self.control.receiver_continuation_survivor_gate_open {
                    let required_survivors = reserve_horizon.saturating_add(1);
                    let survivors = endpoint_order.iter().fold(0_usize, |total, endpoint| {
                        total.saturating_add(
                            self.streams
                                .receiver_continuation_reserve_opportunities(
                                    *endpoint,
                                    disposition.cell_bytes,
                                    disposition.parser_ceiling_bytes,
                                )
                                .len(),
                        )
                    });
                    if survivors < required_survivors {
                        // The first base or early tagged-continuation allocation
                        // latches only after the full H+1 pre-outgoing cohort
                        // survives peer acknowledgment. The incomplete event
                        // follows the configured terminal/drop policy.
                        self.causal_unsatisfied_incoming(incoming, miss_reason, elapsed);
                        continue;
                    }
                    self.control.receiver_continuation_survivor_gate_open = true;
                }
            }
            if let Some(disposition) = tagged_disposition {
                let required = incoming.remaining;
                assert_eq!(
                    required, disposition.cell_bytes,
                    "a receiver continuation must retain its exact whole-cell size"
                );
                let live_base_outstanding = self
                    .incoming_credit_ledger
                    .iter()
                    .filter(|(slot, _)| **slot != incoming.slot)
                    .fold(0_u64, |total, (_, ledger)| {
                        total.saturating_add(ledger.unresolved())
                    });
                // Preserve the established coalesced-tail path when all live
                // base debt fits on one nonreserve stream below the parser
                // ceiling. If that exact tail has been requested locally but
                // its `MAX_STREAM_DATA` action is still pending, retain this
                // tagged event until the advertisement observation makes the
                // prefix atomically extensible. Only when neither state exists
                // does the exact oldest pristine reserve provide a distinct
                // fallback prefix.
                let coalesced = (live_base_outstanding > 0
                    && live_base_outstanding <= disposition.parser_ceiling_bytes)
                    .then(|| {
                        endpoint_order.iter().find_map(|endpoint| {
                            self.streams
                                .receiver_continuation_opportunities(
                                    *endpoint,
                                    required,
                                    live_base_outstanding,
                                    disposition.parser_ceiling_bytes,
                                )
                                .into_iter()
                                .find(|opportunity| {
                                    !self
                                        .control
                                        .receiver_continuation_reserves
                                        .contains(&(opportunity.endpoint, opportunity.stream))
                                        && self.advertised_unresolved_on_stream(
                                            opportunity.endpoint,
                                            opportunity.stream,
                                        ) == live_base_outstanding
                                })
                        })
                    })
                    .flatten();
                if coalesced.is_none()
                    && self.has_pending_receiver_continuation_tail(
                        &endpoint_order,
                        incoming.slot,
                        required,
                        live_base_outstanding,
                        disposition.parser_ceiling_bytes,
                    )
                {
                    self.causal_unsatisfied_incoming(incoming, miss_reason, elapsed);
                    continue;
                }
                let opportunity = coalesced.or_else(|| {
                    let &(reserved_endpoint, reserved_stream) =
                        self.control.receiver_continuation_reserves.first()?;
                    self.streams
                        .receiver_continuation_opportunities(
                            reserved_endpoint,
                            required,
                            0,
                            disposition.parser_ceiling_bytes,
                        )
                        .into_iter()
                        .find(|opportunity| {
                            opportunity.stream == reserved_stream
                                && self.advertised_unresolved_on_stream(
                                    opportunity.endpoint,
                                    opportunity.stream,
                                ) == 0
                        })
                });
                if let Some(opportunity) = opportunity {
                    let release = self
                        .streams
                        .release_stream(opportunity.endpoint, opportunity.stream, required)
                        .expect("snapshotted pristine chaff capacity remains available");
                    assert_eq!(
                        release.increase, required,
                        "a receiver continuation must be released as one whole cell"
                    );
                    incoming.remaining = 0;
                    if let Some(ledger) = self.incoming_credit_ledger.get_mut(&incoming.slot) {
                        ledger.assign_endpoint(release.endpoint);
                    }
                    self.actions.push_back(QcsdAction::IncreaseReceiveLimit {
                        endpoint: release.endpoint,
                        stream: release.stream,
                        absolute_limit: release.absolute_limit,
                        packet: incoming.packet,
                        slot: incoming.slot,
                    });
                    self.control.credit.push(PendingCredit {
                        slot: incoming.slot,
                        packet: incoming.packet,
                        endpoint: release.endpoint,
                        stream: release.stream,
                        absolute_limit: release.absolute_limit,
                        increase: release.increase,
                    });
                    // Each component consumes one horizon reservation even if
                    // a positive coalesced base tail was extended elsewhere.
                    assert!(
                        !self.control.receiver_continuation_reserves.is_empty(),
                        "a held continuation must retain its component reserve"
                    );
                    self.control.receiver_continuation_reserves.remove(0);
                } else {
                    // This event is a causal receiver continuation, not an
                    // ordinary best-effort scheduling slot, but an unavailable
                    // whole-cell precondition still obeys terminal/drop policy.
                    self.causal_unsatisfied_incoming(incoming, miss_reason, elapsed);
                }
                continue;
            }
            let prefer_pristine_terminal_chaff = terminal_chaff_incoming
                && pending_index.saturating_add(1) == pending_len
                && tagged_disposition.is_none()
                && reserve_disposition.is_none()
                && self.incoming_slot_is_untouched(&incoming);
            let terminal_opportunity = prefer_pristine_terminal_chaff
                .then(|| {
                    endpoint_order.iter().find_map(|endpoint| {
                        self.streams
                            .pristine_terminal_chaff_opportunities(
                                *endpoint,
                                incoming.remaining,
                                self.config.effective_initial_max_stream_data(),
                            )
                            .into_iter()
                            .find(|opportunity| {
                                !self
                                    .control
                                    .receiver_continuation_reserves
                                    .contains(&(opportunity.endpoint, opportunity.stream))
                            })
                    })
                })
                .flatten();
            if let Some(opportunity) = terminal_opportunity {
                let required = incoming.remaining;
                let release = self
                    .streams
                    .release_stream(opportunity.endpoint, opportunity.stream, required)
                    .expect("snapshotted pristine terminal chaff capacity remains available");
                assert_eq!(
                    release.increase, required,
                    "a terminal chaff-only slot must remain whole"
                );
                incoming.remaining = 0;
                if let Some(ledger) = self.incoming_credit_ledger.get_mut(&incoming.slot) {
                    ledger.assign_endpoint(release.endpoint);
                }
                self.actions.push_back(QcsdAction::IncreaseReceiveLimit {
                    endpoint: release.endpoint,
                    stream: release.stream,
                    absolute_limit: release.absolute_limit,
                    packet: incoming.packet,
                    slot: incoming.slot,
                });
                self.control.credit.push(PendingCredit {
                    slot: incoming.slot,
                    packet: incoming.packet,
                    endpoint: release.endpoint,
                    stream: release.stream,
                    absolute_limit: release.absolute_limit,
                    increase: release.increase,
                });
                continue;
            }
            let mut staged_credit = Vec::new();
            let mut staged_claims = Vec::new();
            let mut opportunities = Vec::new();
            for endpoint in endpoint_order {
                opportunities.extend(self.streams.allocation_opportunities_excluding(
                    endpoint,
                    self.defense.mode(),
                    &self.control.receiver_continuation_reserves,
                    self.defense.base_chaff_requires_peer_acknowledgment(),
                ));
            }
            // Preserve the cyclic endpoint order within each class, but always
            // exhaust every application stream (exact then its own bounded
            // claim) before any chaff stream.
            opportunities.sort_by_key(|opportunity| {
                matches!(opportunity.role, QcsdRequestRole::Chaff { .. })
            });
            for opportunity in opportunities {
                if incoming.remaining == 0 {
                    break;
                }
                if opportunity.exact > 0 {
                    let release = self
                        .streams
                        .release_stream(
                            opportunity.endpoint,
                            opportunity.stream,
                            incoming.remaining.min(opportunity.exact),
                        )
                        .expect("snapshotted exact stream capacity remains available");
                    incoming.remaining = incoming.remaining.saturating_sub(release.increase);
                    staged_credit.push(PendingCredit {
                        slot: incoming.slot,
                        packet: incoming.packet,
                        endpoint: opportunity.endpoint,
                        stream: opportunity.stream,
                        absolute_limit: release.absolute_limit,
                        increase: release.increase,
                    });
                }
                if !exact_window && incoming.remaining > 0 && opportunity.claimable > 0 {
                    let amount = self.streams.claim_stream(
                        opportunity.endpoint,
                        opportunity.stream,
                        incoming.remaining.min(opportunity.claimable),
                    );
                    incoming.remaining = incoming.remaining.saturating_sub(amount);
                    if amount > 0 {
                        staged_claims.push(PendingClaim {
                            slot: incoming.slot,
                            packet: incoming.packet,
                            endpoint: opportunity.endpoint,
                            stream: opportunity.stream,
                            remaining: amount,
                        });
                    }
                }
            }

            if incoming.remaining == 0 || (!exact_window && !self.config.drop_unsatisfied_events) {
                for credit in staged_credit {
                    if let Some(ledger) = self.incoming_credit_ledger.get_mut(&incoming.slot) {
                        ledger.assign_endpoint(credit.endpoint);
                    }
                    self.actions.push_back(QcsdAction::IncreaseReceiveLimit {
                        endpoint: credit.endpoint,
                        stream: credit.stream,
                        absolute_limit: credit.absolute_limit,
                        packet: credit.packet,
                        slot: credit.slot,
                    });
                    self.control.credit.push(credit);
                }
                for claim in staged_claims {
                    if let Some(ledger) = self.incoming_credit_ledger.get_mut(&incoming.slot) {
                        ledger.assign_endpoint(claim.endpoint);
                    }
                    self.control.claims.push(claim);
                }
            } else {
                for credit in staged_credit.into_iter().rev() {
                    assert!(self.streams.cancel_release(
                        credit.endpoint,
                        credit.stream,
                        credit.absolute_limit,
                        credit.increase,
                    ));
                }
                for claim in staged_claims {
                    self.streams
                        .restore_claim(claim.endpoint, claim.stream, claim.remaining);
                }
            }
            if incoming.remaining > 0 {
                self.unsatisfied_incoming(incoming, miss_reason, elapsed);
            }
        }
    }

    fn ensure_receiver_continuation_reserves(
        &mut self,
        endpoint_order: &[QcsdEndpointId],
        horizon: usize,
        required: u64,
        parser_ceiling: u64,
    ) -> bool {
        self.control
            .receiver_continuation_reserves
            .retain(|(endpoint, stream)| {
                self.streams.is_receiver_continuation_reserve(
                    *endpoint,
                    *stream,
                    required,
                    parser_ceiling,
                )
            });
        if self.control.receiver_continuation_reserves.len() > horizon {
            self.control
                .receiver_continuation_reserves
                .truncate(horizon);
        }
        if self.control.receiver_continuation_reserves.len() == horizon {
            return true;
        }
        for endpoint in endpoint_order {
            // Keep the allocator's earliest stable stream available for a
            // possible positive base tail; reserve the latest pristine stream
            // within each endpoint deterministically.
            for opportunity in self
                .streams
                .receiver_continuation_reserve_opportunities(*endpoint, required, parser_ceiling)
                .into_iter()
                .rev()
            {
                let key = (opportunity.endpoint, opportunity.stream);
                if !self.control.receiver_continuation_reserves.contains(&key) {
                    self.control.receiver_continuation_reserves.push(key);
                    if self.control.receiver_continuation_reserves.len() == horizon {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn advertised_unresolved_on_stream(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> u64 {
        self.advertised_incoming_credit
            .get(&(endpoint, stream))
            .into_iter()
            .flatten()
            .fold(0_u64, |total, range| total.saturating_add(range.bytes()))
    }

    /// Prove one positive, contiguous, still-live scheduled prefix beginning
    /// at the configured initial receive limit. This proof is intentionally
    /// separate from `ReceiveState`: parser liveness must not infer or create
    /// scheduling ownership from an absolute receive limit alone.
    fn live_advertised_scheduled_prefix(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
    ) -> Option<(u64, u64)> {
        let start = self.config.effective_initial_max_stream_data();
        let ranges = self.advertised_incoming_credit.get(&(endpoint, stream))?;
        let mut end = start;
        for range in ranges {
            if range.end <= end {
                continue;
            }
            if range.start > end
                || self
                    .incoming_credit_ledger
                    .get(&range.slot)
                    .is_none_or(|ledger| ledger.unresolved() == 0)
            {
                return None;
            }
            end = range.end;
        }
        (end > start).then_some((start, end))
    }

    /// Return the complete contiguous advertised scheduled suffix beginning
    /// at `start`. A gap rejects the proof instead of summing unrelated
    /// ownership ranges across parser-only offsets.
    fn contiguous_advertised_tail_from(
        &self,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        start: u64,
    ) -> Option<u64> {
        let ranges = self.advertised_incoming_credit.get(&(endpoint, stream))?;
        let mut end = start;
        for range in ranges {
            if range.end <= end {
                continue;
            }
            if range.start > end {
                return None;
            }
            end = range.end;
        }
        (end > start).then_some(end.saturating_sub(start))
    }

    fn incoming_slot_is_untouched(&self, incoming: &PendingIncoming) -> bool {
        let requested = u64::from(incoming.packet.length());
        if requested == 0
            || incoming.remaining != requested
            || incoming.endpoint.is_some()
            || self
                .control
                .credit
                .iter()
                .any(|credit| credit.slot == incoming.slot)
            || self
                .control
                .claims
                .iter()
                .any(|claim| claim.slot == incoming.slot)
            || self
                .advertised_incoming_credit
                .values()
                .flatten()
                .any(|range| range.slot == incoming.slot)
        {
            return false;
        }
        self.incoming_credit_ledger
            .get(&incoming.slot)
            .is_some_and(|ledger| {
                ledger.packet == incoming.packet
                    && ledger.endpoint.is_none()
                    && !ledger.multiple_endpoints
                    && ledger.consumed == 0
                    && ledger.retired == 0
                    && ledger.unresolved() == requested
            })
    }

    fn has_pending_receiver_continuation_tail(
        &self,
        endpoint_order: &[QcsdEndpointId],
        continuation_slot: QcsdSlotId,
        required: u64,
        live_base_outstanding: u64,
        parser_ceiling: u64,
    ) -> bool {
        if live_base_outstanding == 0 || live_base_outstanding > parser_ceiling {
            return false;
        }
        let pending_by_stream = self
            .control
            .credit
            .iter()
            .filter(|credit| credit.slot != continuation_slot)
            .fold(BTreeMap::new(), |mut pending, credit| {
                let total = pending
                    .entry((credit.endpoint, credit.stream))
                    .or_insert(0_u64);
                *total = total.saturating_add(credit.increase);
                pending
            });
        endpoint_order.iter().any(|endpoint| {
            pending_by_stream
                .iter()
                .any(|((candidate, stream), pending)| {
                    candidate == endpoint
                        && !self
                            .control
                            .receiver_continuation_reserves
                            .contains(&(*candidate, *stream))
                        && self.streams.is_pending_receiver_continuation_tail(
                            *candidate,
                            *stream,
                            required,
                            live_base_outstanding,
                            *pending,
                            parser_ceiling,
                        )
                })
        })
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the pending event is deliberately transferred back into the queue"
    )]
    fn unsatisfied_incoming(
        &mut self,
        incoming: PendingIncoming,
        reason: MissedSlotReason,
        at: Duration,
    ) {
        if self.config.drop_unsatisfied_events
            || self.defense.incoming_slot_must_resolve_in_window()
        {
            self.fail_incoming_slot(incoming.slot, reason, at, true);
        } else {
            self.control.incoming.push(incoming);
        }
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the pending causal event is deliberately transferred or terminalized"
    )]
    fn causal_unsatisfied_incoming(
        &mut self,
        incoming: PendingIncoming,
        reason: MissedSlotReason,
        at: Duration,
    ) {
        if self.defense.incoming_slot_must_resolve_in_window()
            || (self.config.drop_unsatisfied_events
                && !self.defense.retain_causal_incoming_until_ready())
        {
            self.fail_incoming_slot(incoming.slot, reason, at, true);
        } else {
            self.control.incoming.push(incoming);
        }
    }

    fn candidate_defense_control_backlog_pending(&self) -> bool {
        let terminal_parser_backlog = self.defense.terminal_chaff_backlog_cell_bytes().is_some()
            && (!self.parser_lease_ranges.is_empty()
                || self.streams.has_pending_application_parser_boundary());
        let open_chaff_schedule_backlog = self.streams.open_chaff_count() > 0
            && self
                .defense
                .terminal_chaff_backlog_cell_bytes()
                .map_or_else(
                    || self.defense.terminal_chaff_cancellation_reason().is_none(),
                    |required| {
                        self.defense.accepts_new_chaff_requests()
                            || self.streams.aggregate_capacity().chaff_incoming >= required
                    },
                );
        !self.pending_slots.is_empty()
            || !self.control.incoming.is_empty()
            || !self.control.outgoing.is_empty()
            || !self.control.credit.is_empty()
            || !self.control.claims.is_empty()
            || !self.control.receiver_continuations.is_empty()
            || !self.incoming_credit_ledger.is_empty()
            || terminal_parser_backlog
            || open_chaff_schedule_backlog
            || self
                .chaff
                .as_ref()
                .is_some_and(|chaff| chaff.pending_count() > 0)
            || self.actions.iter().any(|action| {
                matches!(
                    action,
                    QcsdAction::RequestChaff { .. }
                        | QcsdAction::CancelChaff { .. }
                        | QcsdAction::ConfigureManualReceive { .. }
                        | QcsdAction::ConfigureAutomaticReceive { .. }
                        | QcsdAction::SendPacket { .. }
                        | QcsdAction::IncreaseReceiveLimit { .. }
                        | QcsdAction::LeaseParserReceive { .. }
                        | QcsdAction::ReleaseApplicationSendShaping { .. }
                )
            })
    }

    fn sync_candidate_egress_backlog(&mut self, at: Duration) {
        if !self.defense.requires_terminal_chaff_drain() {
            return;
        }
        let pending =
            self.adapter_egress_backlog_pending || self.candidate_defense_control_backlog_pending();
        // Candidate termination is irreversible. BuFLO terminal-tail closure
        // and CS-BuFLO pre-onLoad quiet termination therefore consume a fresh
        // aggregate `false` snapshot, never a value retained across later
        // observations. Re-emit it while either candidate remains open even
        // when the effective boolean did not change.
        let fresh_candidate_terminal_snapshot = !pending
            && !self.defense.is_complete()
            && (self.defense.terminal_chaff_backlog_cell_bytes().is_some()
                || self.defense.terminal_chaff_cancellation_reason().is_some());
        if self.last_effective_egress_backlog_pending != Some(pending)
            || fresh_candidate_terminal_snapshot
        {
            self.last_effective_egress_backlog_pending = Some(pending);
            self.push_signal(at, SignalKind::EgressBacklog { pending });
        }
    }

    fn terminalize_local_chaff(&mut self, at: Duration) {
        if !self.defense.is_complete() || self.defense.terminal_failure().is_some() {
            return;
        }
        let Some(reason) = self.defense.terminal_chaff_cancellation_reason() else {
            return;
        };
        if reason == QcsdChaffCancellationReason::BufloTerminalSubcellTail
            && self.buflo_terminal_subcell_latched_at_us.is_none()
        {
            self.buflo_terminal_subcell_latched_at_us =
                Some(u64::try_from(at.as_micros()).unwrap_or(u64::MAX));
            self.buflo_terminal_subcell_open_streams_at_latch =
                u64::try_from(self.streams.open_chaff_count()).unwrap_or(u64::MAX);
            self.buflo_terminal_subcell_exact_capacity_bytes_cancelled =
                self.streams.aggregate_capacity().chaff_incoming;
            self.buflo_terminal_subcell_parser_lease_bytes_at_latch = self
                .parser_lease_ranges
                .values()
                .flatten()
                .fold(0_u64, |total, range| total.saturating_add(range.bytes()));
            self.buflo_terminal_subcell_pending_parser_boundaries_at_latch =
                u64::try_from(self.streams.pending_parser_boundaries().len()).unwrap_or(u64::MAX);
            self.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch =
                u64::try_from(self.streams.pending_application_parser_boundary_count())
                    .unwrap_or(u64::MAX);
        }

        let queued = std::mem::take(&mut self.actions);
        for action in queued {
            if let QcsdAction::RequestChaff {
                resource,
                request_id,
                ..
            } = action
            {
                if let Some(chaff) = &mut self.chaff {
                    chaff.request_failed(resource.id, Some(request_id));
                }
                match reason {
                    QcsdChaffCancellationReason::BufloTerminalSubcellTail => {
                        self.buflo_terminal_subcell_pending_request_cancellations = self
                            .buflo_terminal_subcell_pending_request_cancellations
                            .saturating_add(1);
                    }
                    QcsdChaffCancellationReason::CsBufloLocalEarlyTermination => {
                        self.cs_buflo_local_et_pending_request_cancellations = self
                            .cs_buflo_local_et_pending_request_cancellations
                            .saturating_add(1);
                    }
                }
            } else {
                self.actions.push_back(action);
            }
        }

        for (endpoint, stream) in self.streams.open_chaff_streams() {
            self.actions.push_back(QcsdAction::CancelChaff {
                endpoint,
                stream,
                reason,
            });
            self.close_stream(endpoint, stream, crate::QcsdStreamFinish::LocalError, at);
            match reason {
                QcsdChaffCancellationReason::BufloTerminalSubcellTail => {
                    self.buflo_terminal_subcell_stream_cancellations = self
                        .buflo_terminal_subcell_stream_cancellations
                        .saturating_add(1);
                }
                QcsdChaffCancellationReason::CsBufloLocalEarlyTermination => {
                    self.cs_buflo_local_et_stream_cancellations = self
                        .cs_buflo_local_et_stream_cancellations
                        .saturating_add(1);
                }
            }
        }
    }

    /// Transfer application traffic back to ordinary Neqo flow control after
    /// CS-BuFLO terminates locally before the client onLoad analogue.
    ///
    /// Chaff cancellation is queued first by `terminalize_local_chaff`. This
    /// transition then atomically replaces any still-queued manual application
    /// configuration with automatic receive and releases only Important
    /// application sends. Scheduled or unadvertised receive ownership keeps
    /// the transition fail-closed until a later poll.  Aggregate adapter
    /// egress backlog cannot block this post-latch transition: pending
    /// application data or retransmission is precisely the work that the send
    /// release must allow to drain, while the quiet-time latch already consumed
    /// a fresh pre-latch aggregate backlog snapshot.
    fn handoff_cs_buflo_application_after_local_et(&mut self) {
        if !self.cs_buflo_local_et_before_application_complete
            || self.cs_buflo_application_passthrough
            || !self.defense.is_complete()
            || self.defense.terminal_failure().is_some()
            || self.defense.terminal_chaff_cancellation_reason()
                != Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination)
            || !self.control.incoming.is_empty()
            || !self.control.outgoing.is_empty()
            || !self.control.credit.is_empty()
            || !self.control.claims.is_empty()
            || !self.control.receiver_continuations.is_empty()
            || !self.incoming_credit_ledger.is_empty()
            || !self.advertised_incoming_credit.is_empty()
            || !self.pending_slots.is_empty()
        {
            return;
        }

        let has_nontransferable_application_action =
            self.actions.iter().any(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint, stream, ..
                }
                | QcsdAction::LeaseParserReceive {
                    endpoint, stream, ..
                }
                | QcsdAction::ConfigureAutomaticReceive {
                    endpoint, stream, ..
                } => self.streams.is_application_stream(*endpoint, *stream),
                _ => false,
            });
        if has_nontransferable_application_action {
            return;
        }

        let application_parser_keys: Vec<_> = self
            .parser_lease_ranges
            .keys()
            .copied()
            .filter(|(endpoint, stream)| self.streams.is_application_stream(*endpoint, *stream))
            .collect();
        if application_parser_keys.iter().any(|key| {
            self.parser_lease_ranges.get(key).is_some_and(|ranges| {
                ranges
                    .iter()
                    .any(|range| range.owner.is_some() || !range.unowned || !range.advertised)
            })
        }) {
            return;
        }

        let parser_boundaries = self.streams.pending_application_parser_boundary_count();
        let Ok(streams) = self.streams.handoff_application_receive_to_automatic() else {
            return;
        };
        let parser_lease_bytes = application_parser_keys
            .into_iter()
            .filter_map(|key| self.parser_lease_ranges.remove(&key))
            .flatten()
            .fold(0_u64, |total, range| total.saturating_add(range.bytes()));

        self.actions.retain(|action| {
            !matches!(
                action,
                QcsdAction::ConfigureManualReceive {
                    endpoint,
                    stream,
                    ..
                } if self.streams.is_application_stream(*endpoint, *stream)
            )
        });
        self.cs_buflo_application_passthrough = true;
        self.cs_buflo_local_et_application_receive_streams_handed_off =
            u64::try_from(streams.len()).unwrap_or(u64::MAX);
        self.cs_buflo_local_et_application_parser_boundaries_handed_off =
            u64::try_from(parser_boundaries).unwrap_or(u64::MAX);
        self.cs_buflo_local_et_application_parser_lease_bytes_handed_off = parser_lease_bytes;

        for (endpoint, stream) in streams {
            self.actions
                .push_back(QcsdAction::ConfigureAutomaticReceive {
                    endpoint,
                    stream,
                    window: self.config.automatic_receive_window,
                });
        }
        let endpoints = self.scheduler.endpoints().to_vec();
        for endpoint in endpoints {
            self.release_application_send_shaping_for(endpoint);
        }
    }

    /// Release application sends after an onLoad-first CS-BuFLO completion so
    /// lost request bytes or FIN can still be retransmitted and peer-confirmed.
    /// This is transport cleanup, not the pre-onLoad automatic-receive
    /// handoff, and therefore does not mutate any early-termination counters.
    fn release_cs_buflo_application_send_cleanup_if_needed(&mut self) {
        if !self.application_complete_delivered_to_defense
            || !self.defense.is_complete()
            || self.defense.terminal_failure().is_some()
            || self.defense.terminal_chaff_cancellation_reason()
                != Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination)
        {
            return;
        }
        let endpoints = self.scheduler.endpoints().to_vec();
        for endpoint in endpoints {
            self.release_application_send_shaping_for(endpoint);
        }
    }

    fn update_completion(&mut self, elapsed: Duration) {
        // `next_event` can itself perform CS-BuFLO's strict-quiet decision, so
        // reconcile the ordering even when no transport observation caused the
        // transition.
        self.record_cs_buflo_local_et_ordering();
        self.terminalize_local_chaff(elapsed);
        self.handoff_cs_buflo_application_after_local_et();
        self.release_cs_buflo_application_send_cleanup_if_needed();
        let has_backlog = self.control.incoming_backlog() > 0
            || self.control.claim_backlog() > 0
            || !self.control.receiver_continuations.is_empty()
            || !self.control.outgoing.is_empty()
            || !self.control.credit.is_empty()
            || !self.incoming_credit_ledger.is_empty()
            || !self.advertised_incoming_credit.is_empty()
            || !self.pending_slots.is_empty()
            || !self.observations.is_empty()
            || (self.defense.terminal_chaff_cancellation_reason()
                == Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination)
                && self.cs_buflo_local_et_before_application_complete
                && !self.cs_buflo_application_passthrough)
            || (self.defense.requires_terminal_chaff_drain()
                && (self.actions.iter().any(|action| {
                    matches!(
                        action,
                        QcsdAction::RequestChaff { .. }
                            | QcsdAction::CancelChaff { .. }
                            | QcsdAction::CancelPrearmedPacket { .. }
                            | QcsdAction::ConfigureManualReceive { .. }
                            | QcsdAction::ConfigureAutomaticReceive { .. }
                            | QcsdAction::ReleaseApplicationSendShaping { .. }
                    )
                }) || self
                    .chaff
                    .as_ref()
                    .is_some_and(|chaff| chaff.pending_count() > 0)
                    || (self.defense.terminal_chaff_cancellation_reason().is_none()
                        && self.streams.open_chaff_count() > 0)));
        if self.defense.is_complete() && self.defense.terminal_failure().is_none() && !has_backlog {
            let due = *self.completion_due.get_or_insert_with(|| {
                elapsed.saturating_add(Duration::from_micros(self.config.tail_wait_us))
            });
            if !self.completion_emitted && elapsed >= due {
                self.completion_emitted = true;
                self.actions.push_back(QcsdAction::DefenseComplete);
            }
        } else {
            self.completion_due = None;
        }
    }

    fn release_chaff_send_shaping_if_needed(&mut self) {
        if self.defense.mode() != DefenseMode::ChaffAndShape
            || !self.defense.can_release_chaff_send_shaping()
            || (self.defense.is_complete()
                && self.control.incoming_backlog() == 0
                && self.control.claim_backlog() == 0
                && self.control.credit.is_empty())
        {
            return;
        }
        let endpoints = self.scheduler.endpoints().to_vec();
        for endpoint in endpoints {
            self.release_chaff_send_shaping_for(endpoint);
        }
    }

    fn release_chaff_send_shaping_for(&mut self, endpoint: QcsdEndpointId) {
        if self.defense.mode() == DefenseMode::ChaffAndShape
            && self.defense.can_release_chaff_send_shaping()
            && (!self.defense.is_complete()
                || self.control.incoming_backlog() > 0
                || self.control.claim_backlog() > 0
                || !self.control.credit.is_empty())
            && self.released_chaff_send_shaping.insert(endpoint)
        {
            self.actions
                .push_back(QcsdAction::ReleaseChaffSendShaping { endpoint });
        }
    }

    fn release_application_send_shaping_for(&mut self, endpoint: QcsdEndpointId) {
        let early_handoff = self.cs_buflo_application_passthrough;
        let post_onload_cleanup = self.application_complete_delivered_to_defense
            && self.defense.is_complete()
            && self.defense.terminal_failure().is_none()
            && self.defense.terminal_chaff_cancellation_reason()
                == Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination);
        if (early_handoff || post_onload_cleanup)
            && self.released_application_send_shaping.insert(endpoint)
        {
            if early_handoff {
                self.cs_buflo_local_et_application_send_endpoints_released = self
                    .cs_buflo_local_et_application_send_endpoints_released
                    .saturating_add(1);
            }
            self.actions
                .push_back(QcsdAction::ReleaseApplicationSendShaping { endpoint });
        }
    }

    /// Earliest time at which [`Self::poll`] can produce another action.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Duration> {
        let mut candidates = Vec::new();
        if !self.observations.is_empty() {
            candidates.push(Duration::ZERO);
        }
        if let Some(next) = self.defense.next_event_at() {
            candidates.push(next);
        }
        if !self.control.outgoing.is_empty() {
            candidates.push(Duration::ZERO);
        }
        if !self.control.incoming.is_empty() {
            let earliest = self
                .control
                .incoming
                .iter()
                .map(|pending| pending.packet.timestamp_us())
                .min()
                .unwrap_or(0);
            let interval = self.config.control_interval_us;
            let next = if earliest == 0 {
                0
            } else {
                earliest.div_ceil(interval).saturating_mul(interval)
            };
            let next_unprocessed = self
                .control
                .last_incoming_boundary_us
                .filter(|last| next <= *last)
                .map_or(next, |last| last.saturating_add(interval));
            candidates.push(Duration::from_micros(next_unprocessed));
        }
        if let Some(due) = self.completion_due.filter(|_| !self.completion_emitted) {
            candidates.push(due);
        }
        candidates.into_iter().min()
    }

    /// Remove the next queued action.
    pub fn next_action(&mut self) -> Option<QcsdAction> {
        self.actions.pop_front()
    }

    /// Drain all queued actions in order.
    pub fn drain_actions(&mut self) -> impl Iterator<Item = QcsdAction> + '_ {
        self.actions.drain(..)
    }

    /// Exact typed receive identities still queued inside the controller.
    #[must_use]
    pub fn queued_receive_action_identities(&self) -> Vec<QcsdReceiveActionIdentity> {
        self.actions
            .iter()
            .filter_map(QcsdAction::receive_identity)
            .collect()
    }

    /// Whether the defense emitted its terminal action.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completion_emitted
    }

    fn controls(&self, role: QcsdRequestRole) -> bool {
        matches!(role, QcsdRequestRole::Chaff { .. })
            || (self.defense.mode() == DefenseMode::ChaffAndShape
                && !(self.cs_buflo_application_passthrough && role == QcsdRequestRole::Application))
    }

    fn request_chaff_if_needed(&mut self, before_due_outgoing: bool) {
        // A terminal defense cannot provide another shaped outgoing cell for
        // a newly opened chaff request.  Enqueuing one here could place
        // RequestChaff immediately before DefenseComplete and leave a gated
        // request stream permanently open.
        if !self.defense.accepts_new_chaff_requests()
            || self.defense.requires_terminal_chaff_drain() && self.defense.is_complete()
        {
            return;
        }
        let Some(chaff) = &mut self.chaff else {
            return;
        };
        let endpoints: Vec<_> = self
            .scheduler
            .endpoints()
            .iter()
            .filter_map(|endpoint| {
                self.endpoint_origins
                    .get(endpoint)
                    .map(|origin| (*endpoint, origin.clone()))
            })
            .collect();
        let requests = if self.defense.preprovision_chaff_once_to_stream_limit() {
            if !before_due_outgoing
                || self.control.chaff_preprovisioned_to_stream_limit
                || endpoints.is_empty()
            {
                return;
            }
            let requests = chaff.preprovision_to_limit(
                self.streams.open_chaff_count(),
                self.config.max_chaff_streams,
                &endpoints,
            );
            if !requests.is_empty() {
                self.control.chaff_preprovisioned_to_stream_limit = true;
            }
            requests
        } else {
            chaff.replenish(
                self.streams.aggregate_capacity().chaff_incoming,
                self.streams.open_chaff_count(),
                self.config.max_chaff_streams,
                self.config.low_watermark,
                &endpoints,
            )
        };
        for request in requests {
            self.actions.push_back(QcsdAction::RequestChaff {
                endpoint: request.endpoint,
                resource: request.resource,
                request_id: request.request_id,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{BTreeSet, VecDeque},
        rc::Rc,
        time::Duration,
    };

    use super::{
        AdvertisedIncomingCredit, IncomingCreditLedger, ParserLeaseRange, PendingClaim,
        PendingCredit, PendingIncoming, QcsdController, duration_as_ceil_micros,
        duration_as_floor_micros,
    };
    use crate::{
        Buflo, BufloParameters, CsBuflo, CsBufloEarlyTermination, CsBufloPaddingMode,
        CsBufloParameters, Defense, DefenseConfig, DefenseDiagnostics, DefenseMode, DefenseSignal,
        Direction, EventOutcome, FrontConfig, MissedSlotReason, Packet, QcsdAction,
        QcsdChaffCancellationReason, QcsdConfig, QcsdDatagramClass, QcsdEndpointId,
        QcsdImplementationScope, QcsdObservation, QcsdParserLeaseOwner,
        QcsdPrearmCancellationReason, QcsdReceiveActionIdentity, QcsdRequestRole, QcsdSendPolicy,
        QcsdSlotComposition, QcsdSlotId, QcsdSlotOutcome, QcsdStreamFinish, QcsdStreamId, Resource,
        ResourceManifest, SignalKind, StaticSchedule, TamarawConfig, Trace, TrafficMorphing,
        TrafficMorphingConfig, WalkieTalkie, WalkieTalkieConfig, WtfPad, WtfPadConfig,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecordedCall {
        Signal(DefenseSignal),
        ApplicationBytes {
            at: Duration,
            direction: Direction,
            bytes: u64,
        },
        NextEvent(Duration),
    }

    #[derive(Debug)]
    struct RecordingDefense {
        events: VecDeque<Packet>,
        mode: DefenseMode,
        deduplicate_chaff_payload_offsets: bool,
        split_incoming_credit_lifecycle: bool,
        calls: Rc<RefCell<Vec<RecordedCall>>>,
    }

    impl RecordingDefense {
        fn new(
            events: impl IntoIterator<Item = Packet>,
            mode: DefenseMode,
        ) -> (Self, Rc<RefCell<Vec<RecordedCall>>>) {
            let calls = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    events: events.into_iter().collect(),
                    mode,
                    deduplicate_chaff_payload_offsets: false,
                    split_incoming_credit_lifecycle: false,
                    calls: Rc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl Defense for RecordingDefense {
        fn observe(&mut self, signal: DefenseSignal) {
            self.calls.borrow_mut().push(RecordedCall::Signal(signal));
        }

        fn observe_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
            self.calls
                .borrow_mut()
                .push(RecordedCall::ApplicationBytes {
                    at,
                    direction,
                    bytes,
                });
        }

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.calls
                .borrow_mut()
                .push(RecordedCall::NextEvent(elapsed));
            self.events
                .front()
                .copied()
                .filter(|packet| packet.timestamp() <= elapsed)?;
            self.events.pop_front()
        }

        fn next_event_at(&self) -> Option<Duration> {
            self.events.front().map(|packet| packet.timestamp())
        }

        fn is_complete(&self) -> bool {
            self.events.is_empty()
        }

        fn is_outgoing_complete(&self) -> bool {
            !self
                .events
                .iter()
                .any(|packet| packet.direction() == Direction::Outgoing)
        }

        fn mode(&self) -> DefenseMode {
            self.mode
        }

        fn deduplicate_chaff_payload_offsets(&self) -> bool {
            self.deduplicate_chaff_payload_offsets
        }

        fn retain_stream_offset_provenance_after_close(&self) -> bool {
            self.deduplicate_chaff_payload_offsets
        }

        fn split_incoming_credit_lifecycle(&self) -> bool {
            self.split_incoming_credit_lifecycle
        }
    }

    #[derive(Debug)]
    struct DivergentRollingDefense {
        preview: Packet,
        event: Option<Packet>,
    }

    impl Defense for DivergentRollingDefense {
        fn observe(&mut self, _signal: DefenseSignal) {}

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.event.filter(|packet| packet.timestamp() <= elapsed)?;
            self.event.take()
        }

        fn next_outgoing_prearm(&self) -> Option<Packet> {
            Some(self.preview)
        }

        fn next_event_at(&self) -> Option<Duration> {
            Some(self.preview.timestamp())
        }

        fn is_complete(&self) -> bool {
            false
        }

        fn is_outgoing_complete(&self) -> bool {
            false
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }
    }

    #[derive(Debug)]
    struct CongestionSensitiveOneShot {
        event: Option<Packet>,
    }

    impl Defense for CongestionSensitiveOneShot {
        fn observe(&mut self, _signal: DefenseSignal) {}

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.event.filter(|packet| packet.timestamp() <= elapsed)?;
            self.event.take()
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

        fn outgoing_send_policy(&self) -> QcsdSendPolicy {
            QcsdSendPolicy::CongestionSensitive
        }

        fn requires_terminal_chaff_drain(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    struct CompleteLocalEtDefense;

    impl Defense for CompleteLocalEtDefense {
        fn observe(&mut self, _signal: DefenseSignal) {}

        fn next_event(&mut self, _elapsed: Duration) -> Option<Packet> {
            None
        }

        fn next_event_at(&self) -> Option<Duration> {
            None
        }

        fn is_complete(&self) -> bool {
            true
        }

        fn is_outgoing_complete(&self) -> bool {
            true
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

    #[derive(Debug, Default)]
    struct BacklogLatchedLocalEtDefense {
        complete: bool,
    }

    impl Defense for BacklogLatchedLocalEtDefense {
        fn observe(&mut self, signal: DefenseSignal) {
            if matches!(
                signal.kind,
                SignalKind::EgressBacklog { pending: false } | SignalKind::Wire { .. }
            ) {
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

    #[derive(Debug)]
    struct BacklogProbeDefense {
        states: Rc<RefCell<Vec<bool>>>,
        terminal_reason: Option<QcsdChaffCancellationReason>,
    }

    impl Defense for BacklogProbeDefense {
        fn observe(&mut self, signal: DefenseSignal) {
            if let SignalKind::EgressBacklog { pending } = signal.kind {
                self.states.borrow_mut().push(pending);
            }
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

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }

        fn requires_terminal_chaff_drain(&self) -> bool {
            true
        }

        fn terminal_chaff_cancellation_reason(&self) -> Option<QcsdChaffCancellationReason> {
            self.terminal_reason
        }
    }

    #[derive(Debug)]
    struct ExactIncomingOneShot {
        event: Option<Packet>,
        outcomes: Rc<RefCell<Vec<EventOutcome>>>,
    }

    impl ExactIncomingOneShot {
        fn new(packet: Packet) -> (Self, Rc<RefCell<Vec<EventOutcome>>>) {
            let outcomes = Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    event: Some(packet),
                    outcomes: Rc::clone(&outcomes),
                },
                outcomes,
            )
        }
    }

    impl Defense for ExactIncomingOneShot {
        fn observe(&mut self, signal: DefenseSignal) {
            if let SignalKind::Resolved { outcome, .. } = signal.kind {
                self.outcomes.borrow_mut().push(outcome);
            }
        }

        fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
            self.event.filter(|packet| packet.timestamp() <= elapsed)?;
            self.event.take()
        }

        fn next_event_at(&self) -> Option<Duration> {
            self.event.map(Packet::timestamp)
        }

        fn is_complete(&self) -> bool {
            self.event.is_none()
        }

        fn is_outgoing_complete(&self) -> bool {
            true
        }

        fn mode(&self) -> DefenseMode {
            DefenseMode::ChaffAndShape
        }

        fn incoming_slot_must_resolve_in_window(&self) -> bool {
            true
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ReplayTerminal {
        endpoint: Option<QcsdEndpointId>,
        packet: Packet,
        slot: QcsdSlotId,
        outcome: EventOutcome,
    }

    #[derive(Debug, Default, Eq, PartialEq)]
    struct ControllerReplay {
        actions: Vec<QcsdAction>,
        terminals: Vec<ReplayTerminal>,
        diagnostics: DefenseDiagnostics,
        pending_slots: Vec<(QcsdSlotId, Packet)>,
        complete: bool,
    }

    fn replay_wire(at_us: u64, direction: Direction, length: u16) -> (Duration, QcsdObservation) {
        (
            Duration::from_micros(at_us),
            QcsdObservation::ClassifiedDatagram {
                endpoint: QcsdEndpointId(1),
                direction,
                length,
                class: QcsdDatagramClass::Natural,
                composition: None,
            },
        )
    }

    fn satisfy_replay_incoming(
        controller: &mut QcsdController,
        at: Duration,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        absolute_limit: u64,
        packet: Packet,
        slot: QcsdSlotId,
    ) {
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            at,
        );
        let consumed = controller
            .streams
            .get_mut(endpoint, stream)
            .map_or(0, |state| state.receive.consumed());
        // Model the coalesced MAX_STREAM_DATA control datagram and the
        // corresponding observed cover response at the terminal instant.
        for (direction, length) in [
            (Direction::Outgoing, 80),
            (Direction::Incoming, packet.length()),
        ] {
            controller.observe(
                QcsdObservation::Datagram {
                    endpoint,
                    direction,
                    length,
                    timestamp_us: u64::try_from(at.as_micros()).unwrap_or(u64::MAX),
                },
                at,
            );
            controller.observe(
                QcsdObservation::ClassifiedDatagram {
                    endpoint,
                    direction,
                    length,
                    class: QcsdDatagramClass::DefenseCover,
                    composition: None,
                },
                at,
            );
        }
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                // A stream's initial allowance precedes defense-scheduled
                // offsets. Model receipt through the newly advertised limit
                // so the replay consumes the exact tagged range.
                bytes: absolute_limit.saturating_sub(consumed),
            },
            at,
        );
    }

    fn resolve_replay_actions(
        controller: &mut QcsdController,
        at: Duration,
        replay: &mut ControllerReplay,
    ) {
        while let Some(action) = controller.next_action() {
            replay.actions.push(action.clone());
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
                } => {
                    replay.terminals.push(ReplayTerminal {
                        endpoint: Some(endpoint),
                        packet,
                        slot,
                        outcome: EventOutcome::Satisfied {
                            observed: packet.length(),
                        },
                    });
                    controller.observe(
                        QcsdObservation::SlotSatisfied {
                            endpoint,
                            slot,
                            observed_size: packet.length(),
                        },
                        at,
                    );
                    controller.observe(
                        QcsdObservation::Datagram {
                            endpoint,
                            direction: Direction::Outgoing,
                            length: packet.length(),
                            timestamp_us: u64::try_from(at.as_micros()).unwrap_or(u64::MAX),
                        },
                        at,
                    );
                }
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                } => satisfy_replay_incoming(
                    controller,
                    at,
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                ),
                QcsdAction::SlotSatisfied {
                    endpoint,
                    packet,
                    slot,
                } => replay.terminals.push(ReplayTerminal {
                    endpoint,
                    packet,
                    slot,
                    outcome: EventOutcome::Satisfied {
                        observed: packet.length(),
                    },
                }),
                QcsdAction::SlotMissed {
                    endpoint,
                    packet,
                    slot,
                    reason,
                } => replay.terminals.push(ReplayTerminal {
                    endpoint,
                    packet,
                    slot,
                    outcome: EventOutcome::Missed(reason),
                }),
                QcsdAction::DefenseComplete => replay.complete = true,
                QcsdAction::ConfigureManualReceive { .. }
                | QcsdAction::ConfigureAutomaticReceive { .. }
                | QcsdAction::LeaseParserReceive { .. }
                | QcsdAction::ReleaseChaffSendShaping { .. }
                | QcsdAction::ReleaseApplicationSendShaping { .. }
                | QcsdAction::RequestChaff { .. }
                | QcsdAction::CancelChaff { .. }
                | QcsdAction::PrearmPacket { .. }
                | QcsdAction::CancelPrearmedPacket { .. } => {}
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "full replay preserves every controller action and terminal transition"
    )]
    fn replay_controller(
        configured_defense: DefenseConfig,
        defense: Box<dyn Defense>,
        role: QcsdRequestRole,
        script: impl IntoIterator<Item = (Duration, QcsdObservation)>,
    ) -> ControllerReplay {
        let resources = defense
            .receiver_continuation_cell_bytes()
            .map(|cell_bytes| ResourceManifest {
                resources: [7, 8]
                    .into_iter()
                    .map(|id| Resource {
                        id,
                        url: format!("https://replay.example/{id}"),
                        kind: "Image".into(),
                        content_length: Some(cell_bytes),
                        data_length: cell_bytes,
                        chaff_priority: false,
                        known_valid: true,
                        depends_on: Vec::new(),
                        headers: Vec::new(),
                    })
                    .collect(),
            });
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 100,
                max_stream_data_excess: 4_096,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                tail_wait_us: 0,
                defense: configured_defense,
                ..QcsdConfig::default()
            },
            resources,
            defense,
        )
        .expect("replay controller");
        let endpoint = QcsdEndpointId(1);
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint,
                origin: "https://replay.example".into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: QcsdStreamId(4),
                role,
                expected_response_length: None,
            },
            Duration::ZERO,
        );

        let mut script: VecDeque<_> = script.into_iter().collect();
        assert!(
            script
                .make_contiguous()
                .windows(2)
                .all(|window| matches!(window, [left, right] if left.0 <= right.0)),
            "virtual observations must be time ordered"
        );
        let mut replay = ControllerReplay::default();
        let mut now = Duration::ZERO;
        for _step in 0..512 {
            resolve_replay_actions(&mut controller, now, &mut replay);
            if replay.complete {
                break;
            }

            let external_at = script.front().map(|(at, _)| *at);
            let deadline = controller.next_deadline().map(|at| at.max(now));
            let next = match (external_at, deadline) {
                (Some(external), Some(internal)) if external <= internal => external,
                (Some(_) | None, Some(internal)) => internal,
                (Some(external), None) => external,
                (None, None) => panic!("replay controller stalled before completion"),
            };
            now = next;
            while script.front().is_some_and(|(at, _)| *at == now) {
                let (_, observation) = script.pop_front().expect("checked front");
                controller.observe(observation, now);
            }
            controller.poll(now);
        }

        resolve_replay_actions(&mut controller, now, &mut replay);
        replay.diagnostics = controller.defense_diagnostics();
        replay.pending_slots = controller.pending_slots();
        replay.complete = controller.is_complete();

        let action_slots: BTreeSet<_> = replay
            .actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. }
                | QcsdAction::SendPacket { slot, .. }
                | QcsdAction::CommitPrearmedPacket { slot, .. }
                | QcsdAction::SlotMissed { slot, .. }
                | QcsdAction::SlotSatisfied { slot, .. } => Some(*slot),
                QcsdAction::ConfigureManualReceive { .. }
                | QcsdAction::ConfigureAutomaticReceive { .. }
                | QcsdAction::LeaseParserReceive { .. }
                | QcsdAction::ReleaseChaffSendShaping { .. }
                | QcsdAction::ReleaseApplicationSendShaping { .. }
                | QcsdAction::RequestChaff { .. }
                | QcsdAction::CancelChaff { .. }
                | QcsdAction::PrearmPacket { .. }
                | QcsdAction::CancelPrearmedPacket { .. }
                | QcsdAction::DefenseComplete => None,
            })
            .collect();
        let terminal_slots: BTreeSet<_> = replay
            .terminals
            .iter()
            .map(|terminal| terminal.slot)
            .collect();
        assert!(
            script.is_empty(),
            "replay completed before consuming its input"
        );
        assert!(
            replay.complete,
            "replay did not reach DefenseComplete: {replay:#?}"
        );
        assert!(replay.pending_slots.is_empty());
        assert_eq!(terminal_slots, action_slots);
        assert_eq!(replay.terminals.len(), terminal_slots.len());
        replay
    }

    fn traffic_morphing_replay(seed: u64) -> ControllerReplay {
        let config = TrafficMorphingConfig {
            matrix: "inline-controller-replay.json".into(),
            workload_id: "controller replay source".into(),
            ingress_packet_size: 200,
            max_ingress_deficit_bytes: 200,
        };
        let matrix = r#"{
            "adaptation": "qcsd-client-only",
            "schema_version": 2,
            "generated_by": "controller test",
            "paper_equivalent": false,
            "udp_payload_ceiling": 200,
            "buckets": [64, 100, 200],
            "profiles": [{
                "source": "controller replay source",
                "target": "controller replay target",
                "outgoing": {
                    "expected_added_bytes": 78.8,
                    "l1_distance": 0.0,
                    "source_distribution": [1.0, 0.0, 0.0],
                    "target_distribution": [0.2, 0.3, 0.5],
                    "realized_distribution": [0.2, 0.3, 0.5],
                    "rows": [
                        [0.2, 0.3, 0.5],
                        [0.0, 0.4, 0.6],
                        [0.0, 0.0, 1.0]
                    ]
                },
                "incoming": {
                    "expected_added_bytes": 136.0,
                    "l1_distance": 0.0,
                    "source_distribution": [1.0, 0.0, 0.0],
                    "target_distribution": [0.0, 0.0, 1.0],
                    "realized_distribution": [0.0, 0.0, 1.0],
                    "rows": [
                        [0.0, 0.0, 1.0],
                        [0.0, 0.0, 1.0],
                        [0.0, 0.0, 1.0]
                    ]
                }
            }]
        }"#;
        let defense =
            TrafficMorphing::from_json(&config, seed, 200, matrix).expect("replay matrix");
        let mut script = vec![
            replay_wire(10, Direction::Outgoing, 64),
            (
                Duration::from_micros(11),
                QcsdObservation::TrafficMorphingEgress {
                    endpoint: QcsdEndpointId(1),
                    source_udp_size: 64,
                    outcome: crate::TrafficMorphingOutcome::Morphed {
                        target_udp_size: 200,
                    },
                },
            ),
            replay_wire(12, Direction::Incoming, 64),
            replay_wire(12, Direction::Incoming, 64),
            replay_wire(12, Direction::Incoming, 64),
            replay_wire(14, Direction::Outgoing, 80),
            replay_wire(16, Direction::Incoming, 80),
        ];
        script.push((
            Duration::from_micros(30),
            QcsdObservation::ApplicationComplete,
        ));
        replay_controller(
            DefenseConfig::TrafficMorphing(config),
            Box::new(defense),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            script,
        )
    }

    fn wtf_pad_replay(seed: u64) -> ControllerReplay {
        let config = WtfPadConfig {
            histograms: "inline-controller-replay.json".into(),
            packet_size: 100,
            max_padding_events: 32,
        };
        let defense = WtfPad::from_json(
            &config,
            seed,
            1_200,
            include_str!("../../tests/data/wtf-pad-golden.json"),
        )
        .expect("replay histograms");
        let mut script = vec![
            replay_wire(4, Direction::Outgoing, 80),
            replay_wire(12, Direction::Incoming, 90),
            replay_wire(13, Direction::Incoming, 95),
        ];
        script.push((
            Duration::from_micros(40),
            QcsdObservation::ApplicationComplete,
        ));
        replay_controller(
            DefenseConfig::WtfPad(config),
            Box::new(defense),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            script,
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the schema-six replay keeps both activated reserve cohorts explicit"
    )]
    fn walkie_talkie_replay() -> ControllerReplay {
        let config = WalkieTalkieConfig {
            molded: "walkie-talkie-golden.json".into(),
            workload_id: "real page".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json(
            &config,
            1_200,
            include_str!("../../tests/data/walkie-talkie-golden.json"),
        )
        .expect("replay molded sequence");
        replay_controller(
            DefenseConfig::WalkieTalkie(config),
            Box::new(defense),
            QcsdRequestRole::Application,
            [
                (
                    Duration::ZERO,
                    QcsdObservation::StreamOpened {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(8),
                        role: QcsdRequestRole::Chaff {
                            resource_id: 7,
                            request_id: None,
                        },
                        expected_response_length: None,
                    },
                ),
                (
                    Duration::ZERO,
                    QcsdObservation::StreamDataAcknowledged {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(8),
                        role: QcsdRequestRole::Chaff {
                            resource_id: 7,
                            request_id: None,
                        },
                        offset: 0,
                        bytes: 100,
                        fin: true,
                    },
                ),
                (Duration::ZERO, QcsdObservation::ApplicationBatchStarted),
                (
                    Duration::from_micros(1),
                    QcsdObservation::ApplicationBatchCompleted,
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamFinished {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(4),
                        finish: QcsdStreamFinish::Fin,
                    },
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamOpened {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(12),
                        role: QcsdRequestRole::Application,
                        expected_response_length: None,
                    },
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamOpened {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(16),
                        role: QcsdRequestRole::Chaff {
                            resource_id: 8,
                            request_id: None,
                        },
                        expected_response_length: None,
                    },
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamDataAcknowledged {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(16),
                        role: QcsdRequestRole::Chaff {
                            resource_id: 8,
                            request_id: None,
                        },
                        offset: 0,
                        bytes: 100,
                        fin: true,
                    },
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamOpened {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(20),
                        role: QcsdRequestRole::Chaff {
                            resource_id: 7,
                            request_id: None,
                        },
                        expected_response_length: None,
                    },
                ),
                (
                    Duration::from_micros(200),
                    QcsdObservation::StreamDataAcknowledged {
                        endpoint: QcsdEndpointId(1),
                        stream: QcsdStreamId(20),
                        role: QcsdRequestRole::Chaff {
                            resource_id: 7,
                            request_id: None,
                        },
                        offset: 0,
                        bytes: 100,
                        fin: true,
                    },
                ),
                (
                    Duration::from_micros(201),
                    QcsdObservation::ApplicationBatchStarted,
                ),
                (
                    Duration::from_micros(202),
                    QcsdObservation::ApplicationBatchCompleted,
                ),
                (
                    Duration::from_micros(203),
                    QcsdObservation::ApplicationComplete,
                ),
            ],
        )
    }

    #[test]
    fn traffic_morphing_full_controller_replay_is_exact_at_the_same_seed() {
        let replay = traffic_morphing_replay(0x5eed);
        assert_eq!(traffic_morphing_replay(0x5eed), replay);
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(
            replay
                .terminals
                .iter()
                .all(|terminal| matches!(terminal.outcome, EventOutcome::Satisfied { .. }))
        );
        assert!(replay.diagnostics.suppressed_cover_feedback > 0);
        assert_eq!(replay.diagnostics.morphing_egress_packets, 1);
        assert_eq!(replay.diagnostics.morphing_ingress_shortfall_bytes, 328);
        assert_eq!(
            replay.diagnostics.scheduled_incoming_requested_bytes,
            replay.diagnostics.scheduled_incoming_consumed_bytes
        );
        assert_eq!(replay.diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(replay.diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn wtf_pad_full_controller_replay_is_exact_at_the_same_seed() {
        let replay = wtf_pad_replay(0x5eed);
        assert_eq!(wtf_pad_replay(0x5eed), replay);
        assert!(replay.diagnostics.padding_events > 0);
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(
            replay
                .terminals
                .iter()
                .all(|terminal| matches!(terminal.outcome, EventOutcome::Satisfied { .. }))
        );
        assert!(replay.diagnostics.suppressed_cover_feedback > 0);
        assert!(replay.diagnostics.wtf_pad_incoming_desired_bytes > 0);
        assert_eq!(
            replay.diagnostics.wtf_pad_incoming_received_bytes,
            replay.diagnostics.wtf_pad_incoming_desired_bytes
        );
        assert_eq!(replay.diagnostics.wtf_pad_incoming_shortfall_bytes, 0);
        assert!(replay.diagnostics.wtf_pad_incoming_observed_events > 0);
        assert_eq!(
            replay.diagnostics.scheduled_incoming_requested_bytes,
            replay.diagnostics.scheduled_incoming_consumed_bytes
        );
        assert_eq!(replay.diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(replay.diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn walkie_talkie_full_controller_replay_is_exact_for_identical_signals() {
        let replay = walkie_talkie_replay();
        assert_eq!(walkie_talkie_replay(), replay);
        assert!(replay.actions.iter().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit: 0,
                ..
            }
        )));
        assert!(!replay.actions.iter().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit,
                ..
            } if *initial_limit > 0
        )));
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            replay
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(
            replay
                .terminals
                .iter()
                .all(|terminal| matches!(terminal.outcome, EventOutcome::Satisfied { .. }))
        );
        assert_eq!(replay.diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(replay.diagnostics.retried_outgoing_events, 0);
        assert_eq!(
            replay.diagnostics.scheduled_incoming_requested_bytes,
            replay.diagnostics.scheduled_incoming_consumed_bytes
        );
        assert_eq!(replay.diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(replay.diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the regression keeps the cross-layer receive-credit ordering explicit"
    )]
    fn horizon_two_reserves_survive_across_a_positive_outgoing_component() {
        let molded = r#"{
            "adaptation": "qcsd-client-only",
            "burst_definition": "global-application-batch-direction-transitions",
            "cell_byte_domain": "http3-request-stream-offset.bytes",
            "schema_version": 6,
            "generated_by": "controller ordering test",
            "matching_algorithm": "minimum-base-symmetric-mold-padding-cost-one-to-one",
            "paper_equivalent": false,
            "packet_size": 1200,
            "receiver_continuation": {
                "allocation_policy": "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell",
                "application_order": "after-symmetric-elementwise-mold",
                "base_allocation_policy": "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;exact-capacity-before-bounded-framing-claims",
                "batch_end_release_policy": "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate",
                "causal_capacity_precondition": "every-molded-component-outgoing>0;effective-configured-max-chaff-streams>=total-receiver-continuation-reserve-horizon+1;schema-two-stateful-stage-capacity-recurrence-proves-higher-priority-due-application-stream-frames-plus-cumulative-one-shot-chaff-request-stream-frames-through-fin-fit-within-each-exact-full-molded-outgoing-target-through-final-component",
                "cells_per_nonzero_incoming_component": 1,
                "formula": "symmetric_incoming=adapted_incoming-1-if-adapted_incoming>0-else-0",
                "parser_allowance_ceiling_bytes": 1000,
                "prefix_consumability_precondition": "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable",
                "post_outgoing_loss_liveness_limitation": "loss-of-required-initial-peer-acknowledged-survivor-after-initial-request-chaff-batch-holds-base-and-continuation-allocation;no-new-chaff-request-replenishment-or-generic-post-loss-liveness-guarantee",
                "provisioning_policy": "fill-effective-configured-max-chaff-streams-once-before-first-due-molded-outgoing-actions;never-replenish-after-initial-request-chaff-batch",
                "raw_headroom_bytes_per_nonzero_incoming_component": 1200,
                "sender_framing_cells_per_nonzero_outgoing_component": 1,
                "sender_framing_formula": "symmetric_outgoing=adapted_outgoing-1-if-adapted_outgoing>0-else-0",
                "sender_framing_policy": "one-full-cell-per-positive-symmetric-outgoing-component-reserved-for-quic-http3-stream-framing-and-mandatory-control-overhead",
                "release_policy": "after-issued-base-events-controller-requested-and-request-signals-observed;batch-gate-open;release-when-all-base-events-issued-or-real-reported-nonreserved-capacity-is-below-one-cell;recompute-live-unconsumed-base-each-retry;retain-single-coalescible-unadvertised-positive-outstanding-at-or-below-parser-ceiling-until-max-stream-data-advertised;prefer-single-coalesced-advertised-positive-outstanding-at-or-below-parser-ceiling-on-peer-acknowledged-nonreserved-header-blocked-stream;otherwise-release-whole-cell-to-oldest-retained-peer-acknowledged-pristine-reserve-regardless-of-live-base-debt;remove-oldest-reserve-once",
                "request_activation_policy": "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-molded-outgoing-cells",
                "request_prefix_delivery_precondition": "before-first-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-chaff-request-survivors>=total-receiver-continuation-reserve-horizon+1;initial-survivor-gate-remains-latched-across-complete-schedule",
                "resource_precondition": "schema-two-qualified-manifest-selects-known-valid-same-origin-source-resource;derived-selected-resource-projection-dependency-free-with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component;required-chaff-streams-defines-effective-configured-max-chaff-streams",
                "reserve_lifecycle_policy": "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-from-initial-peer-acknowledged-preprovisioned-cohort-for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-corresponding-all-future-horizon-reserve-before-further-base-allocation",
                "reserve_policy": "reserve-deterministic-acknowledged-pristine-candidates-for-all-remaining-nonzero-incoming-components-before-first-base-allocation-and-retain-distinct-reserves-across-later-positive-outgoing-components",
                "qualified_chaff_manifest_policy": "schema-two-qualified-navigation-root-and-selected-source-resource;explicit-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams;selected-source-resource-known-valid-same-origin;derived-selected-resource-projection-dependency-free;exact-lowercase-accept-accept-encoding-accept-language-projection;application-request-headers-unchanged",
                "qualified_chaff_response_policy": "three-independent-staged-qualified-parallel-chaff-streams=max-five-and-walkie-talkie-required-chaff-streams-concurrent-unshaped-production-nonblocking-qpack-qualifications-derive-selected-resource-compact-status-normalized-content-encoding-body-bytes-body-sha256;one-shot-controller-config-uses-exact-walkie-talkie-required-chaff-streams;runtime-complete-responses-must-match-derived-identity;runtime-partial-responses-have-null-identity-match-fields",
                "staged_prefix_pack_precondition": "schema-two-every-component-staged-prefix-pack-after-peer-settings-and-drained-h3-control-qpack-warmup;each-molded-component-is-an-exact-declared-full-packet-target;opens-exact-bound-application-resources-and-cumulative-copies-of-selected-qualified-resource;active-chaff-cohort-is-nondecreasing-and-zero-delta-stages-are-allowed;all-post-cutoff-stream-transmissions-owned-by-one-of-exact-declared-stage-targets;each-stage-gate-requires-cumulative-application-requests-transmitted-contiguously-through-fin-and-required-active-chaff-requests-transmitted-contiguously-through-fin-and-peer-acknowledged-before-dependent-base-allocation;no-pending-request-causal-h3-control-or-qpack-encoder-stream-output;post-warmup-qpack-decoder-stream-output-recorded-and-excluded;zero-targetless-stream-bytes",
                "qualification_binding_policy": "schema-six-raw-sha256-per-workload-binds-schema-two-chaff-qualification-sidecar-prefix-pack-spec-and-qualified-chaff-manifest;runtime-requires-exact-current-artifact-hashes-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams"
            },
            "qualification_bindings": [
                {
                    "workload_id": "real page",
                    "chaff_qualification_sidecar_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "prefix_pack_spec_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "qualified_chaff_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 5
                },
                {
                    "workload_id": "decoy page",
                    "chaff_qualification_sidecar_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "prefix_pack_spec_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "qualified_chaff_manifest_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 5
                }
            ],
            "profiles": [{
                "real": "real page",
                "decoy": "decoy page",
                "matching_cost_packets": 8,
                "training_inputs": {
                    "real": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                    "decoy": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                },
                "variation": {
                    "real": {"visit_count": 1, "varying_components": 0, "maximum_component_spread": 0},
                    "decoy": {"visit_count": 1, "varying_components": 0, "maximum_component_spread": 0}
                },
                "source_envelopes": {
                    "real": [
                        {"outgoing": 1, "incoming": 1},
                        {"outgoing": 1, "incoming": 1}
                    ],
                    "decoy": [
                        {"outgoing": 1, "incoming": 1},
                        {"outgoing": 1, "incoming": 1}
                    ]
                },
                "batch_ends": {"real": [1], "decoy": [1]},
                "molded_batch_ends": [1],
                "total_scheduled_bytes": 9600,
                "bursts": [
                    {"outgoing": 2, "incoming": 2},
                    {"outgoing": 2, "incoming": 2}
                ]
            }]
        }"#;
        let config = WalkieTalkieConfig {
            molded: "inline-ordering-test.json".into(),
            workload_id: "real page".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json(&config, 1_200, molded).expect("valid mould");
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/continuation".into(),
                kind: "Image".into(),
                content_length: Some(2_400),
                data_length: 2_400,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 0,
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        let nonreserved_chaff_stream = QcsdStreamId(4);
        let continuation_stream = QcsdStreamId(8);
        let later_continuation_stream = QcsdStreamId(12);
        ready(&mut controller, 1, "https://example.com");
        for (stream, role, expected_response_length) in [
            (stream, QcsdRequestRole::Application, Some(2_400)),
            (
                nonreserved_chaff_stream,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                Some(2_400),
            ),
            (
                continuation_stream,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                Some(2_400),
            ),
            (
                later_continuation_stream,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                Some(2_400),
            ),
        ] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length,
                },
                Duration::ZERO,
            );
        }
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            endpoint,
            nonreserved_chaff_stream,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            endpoint,
            continuation_stream,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            endpoint,
            later_continuation_stream,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit: 0,
                ..
            }
        )));
        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.poll(Duration::ZERO);
        satisfy_outgoing_actions(&mut controller, Duration::ZERO, 2);
        controller.poll(Duration::from_micros(1));
        let credits: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    absolute_limit,
                    slot,
                    ..
                } => Some((absolute_limit, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(credits.len(), 1);
        assert_eq!(credits[0].0, 1_200);

        for (absolute_limit, slot) in credits {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(2),
            );
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 1_200,
                },
                Duration::from_micros(2),
            );
        }
        controller.poll(Duration::from_micros(3));

        let (continuation_limit, continuation_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } if stream == later_continuation_stream => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("non-batch-end continuation is released before the next outgoing turn");
        assert_eq!(continuation_limit, 1_200);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: later_continuation_stream,
                absolute_limit: continuation_limit,
                slot: Some(continuation_slot),
            },
            Duration::from_micros(3),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: later_continuation_stream,
                bytes: 1_200,
            },
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));
        assert!(controller.control.receiver_continuation_survivor_gate_open);
        assert_eq!(
            controller.control.receiver_continuation_reserves,
            [(endpoint, continuation_stream)],
            "the distinct later-component reserve survives the first continuation"
        );

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 1_200);
        assert_eq!(
            diagnostics.walkie_talkie_application_stream_crossing_bytes,
            0
        );
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        satisfy_outgoing_actions(&mut controller, Duration::from_micros(4), 2);
        controller.poll(Duration::from_micros(4));
        let (second_base_limit, second_base_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream: candidate,
                    absolute_limit,
                    slot,
                    ..
                } if candidate == stream => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("second component base credit");
        assert_eq!(second_base_limit, 2_400);
        assert_eq!(
            controller.control.receiver_continuation_reserves,
            [(endpoint, continuation_stream)],
            "the future reserve stays pristine across the later positive outgoing component"
        );
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: second_base_limit,
                slot: Some(second_base_slot),
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 1_200,
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(5),
        );
        controller.poll(Duration::from_micros(5));
        let second_continuation_stream = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream: candidate, ..
                } if candidate == continuation_stream => Some(candidate),
                _ => None,
            })
            .expect("second component consumes its original distinct reserve");
        assert_eq!(second_continuation_stream, continuation_stream);
        assert!(controller.control.receiver_continuation_reserves.is_empty());
        assert!(controller.control.receiver_continuation_survivor_gate_open);
    }

    #[test]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "the production-shaped held continuation and next-batch gate remain explicit"
    )]
    fn receiver_continuation_realizes_bootstrap_shaped_application_and_chaff_credit() {
        const EXPECTED_BODY: u64 = 17_109;
        const APPLICATION_RAW: u64 = 17_667;
        const CHAFF_RAW: u64 = 1_533;
        const TARGET_INCOMING: u64 = 16 * 1_200;

        let config = WalkieTalkieConfig {
            molded: "walkie-talkie-continuation.json".into(),
            workload_id: "bootstrap-like-real".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json_with_max_stream_data_excess(
            &config,
            1_200,
            1_000,
            include_str!("../../tests/data/walkie-talkie-continuation.json"),
        )
        .expect("production-shaped receiver continuation fixture");
        let manifest = ResourceManifest {
            resources: vec![
                Resource {
                    id: 7,
                    url: "https://example.com/base-tail".into(),
                    kind: "Image".into(),
                    content_length: Some(EXPECTED_BODY),
                    data_length: EXPECTED_BODY,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 8,
                    url: "https://example.com/continuation".into(),
                    kind: "Image".into(),
                    content_length: Some(EXPECTED_BODY),
                    data_length: EXPECTED_BODY,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
            ],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                low_watermark: 0,
                max_udp_payload_size: 1_200,
                tail_wait_us: 0,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(0);
        let base_tail_chaff = QcsdStreamId(4);
        let continuation_chaff = QcsdStreamId(8);
        ready(&mut controller, 1, "https://example.com");
        for (stream, role, expected_response_length) in [
            (
                application,
                QcsdRequestRole::Application,
                Some(EXPECTED_BODY),
            ),
            (
                base_tail_chaff,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
            (
                continuation_chaff,
                QcsdRequestRole::Chaff {
                    resource_id: 8,
                    request_id: None,
                },
                None,
            ),
        ] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length,
                },
                Duration::ZERO,
            );
        }
        for (stream, resource_id) in [(base_tail_chaff, 7), (continuation_chaff, 8)] {
            acknowledge_chaff_request(
                &mut controller,
                Duration::ZERO,
                endpoint,
                stream,
                QcsdRequestRole::Chaff {
                    resource_id,
                    request_id: None,
                },
            );
        }
        controller.drain_actions().for_each(drop);

        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: application,
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 1_200,
                fin: false,
                slot: None,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        satisfy_outgoing_actions(&mut controller, Duration::from_micros(1), 2);
        controller.poll(Duration::from_micros(1));

        let credits: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } => Some((stream, absolute_limit, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(credits.len(), 15);
        assert_eq!(credits[14].0, application);
        assert_eq!(credits[14].1, 17_109);
        assert_eq!(controller.control.claims.len(), 1);
        assert_eq!(controller.control.claims[0].remaining, 891);

        for (stream, absolute_limit, slot) in &credits {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream: *stream,
                    absolute_limit: *absolute_limit,
                    slot: Some(*slot),
                },
                Duration::from_micros(2),
            );
        }
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream: application,
                frame_bytes: APPLICATION_RAW - EXPECTED_BODY,
                status: Some(200),
                content_length: Some(EXPECTED_BODY),
            },
            Duration::from_micros(2),
        );
        let (framing_limit, framing_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } if stream == application => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("discovered framing converts application claim to exact credit");
        assert_eq!(framing_limit, APPLICATION_RAW);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: application,
                absolute_limit: framing_limit,
                slot: Some(framing_slot),
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: application,
                bytes: APPLICATION_RAW,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: application,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));

        let reassigned: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } => Some((stream, absolute_limit, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(reassigned.len(), 1);
        assert_eq!(reassigned[0].0, base_tail_chaff);
        assert_eq!(reassigned[0].1, 333);
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));

        assert!(controller.drain_actions().all(|action| !matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::SlotMissed { .. }
        )));
        assert_eq!(
            controller.control.receiver_continuation_reserves,
            [(endpoint, continuation_chaff)],
            "the reserve remains protected while the coalescible base tail awaits advertisement"
        );
        assert_eq!(controller.control.receiver_continuations.len(), 1);
        assert_eq!(controller.control.incoming.len(), 1);

        for (stream, absolute_limit, slot) in &reassigned {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream: *stream,
                    absolute_limit: *absolute_limit,
                    slot: Some(*slot),
                },
                Duration::from_micros(4),
            );
        }
        controller.poll(Duration::from_micros(4));

        let (continuation_limit, continuation_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } if stream == base_tail_chaff => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("held continuation extends the coalesced base tail");
        assert_eq!(continuation_limit, CHAFF_RAW);
        assert!(
            controller.control.receiver_continuation_reserves.is_empty(),
            "positive-tail release discharges its separate reserve exactly once"
        );
        controller.poll(Duration::from_micros(4));
        assert!(
            controller.control.receiver_continuation_reserves.is_empty(),
            "allocated continuation credit must not immediately relock its discharged reserve"
        );
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: base_tail_chaff,
                absolute_limit: continuation_limit,
                slot: Some(continuation_slot),
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream: base_tail_chaff,
                frame_bytes: 511,
                status: Some(200),
                content_length: Some(EXPECTED_BODY),
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::DataFrame {
                endpoint,
                stream: base_tail_chaff,
                frame_header_bytes: 3,
                data_bytes: EXPECTED_BODY,
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: base_tail_chaff,
                bytes: CHAFF_RAW,
            },
            Duration::from_micros(5),
        );
        controller.poll(Duration::from_micros(5));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(
            diagnostics.scheduled_incoming_requested_bytes,
            TARGET_INCOMING
        );
        assert_eq!(
            diagnostics.scheduled_incoming_consumed_bytes,
            TARGET_INCOMING
        );
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 16);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 16);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(
            diagnostics.walkie_talkie_natural_incoming_bytes,
            APPLICATION_RAW
        );
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, CHAFF_RAW);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(controller.can_start_application_batch());

        controller.observe(
            QcsdObservation::ApplicationBatchStarted,
            Duration::from_micros(6),
        );
        controller.poll(Duration::from_micros(6));
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SendPacket { packet, .. }
                if packet.direction() == Direction::Outgoing
        )));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "H-only hold and H+1 release stay in one causal controller oracle"
    )]
    fn receiver_continuation_first_base_waits_for_horizon_plus_one_acked_survivors() {
        let config = WalkieTalkieConfig {
            molded: "walkie-talkie-continuation.json".into(),
            workload_id: "bootstrap-like-real".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json_with_max_stream_data_excess(
            &config,
            1_200,
            1_000,
            include_str!("../../tests/data/walkie-talkie-continuation.json"),
        )
        .expect("schema-six mould");
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_200),
                data_length: 1_200,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 1_200,
                max_stream_data_excess: 1_000,
                max_udp_payload_size: 1_450,
                max_chaff_streams: 2,
                drop_unsatisfied_events: true,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("H+1 configuration");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(0);
        let reserve = QcsdStreamId(4);
        let spare = QcsdStreamId(8);
        ready(&mut controller, 1, "https://example.com");
        for (stream, role, expected_response_length) in [
            (application, QcsdRequestRole::Application, Some(1_200)),
            (
                reserve,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
        ] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length,
                },
                Duration::ZERO,
            );
        }
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            endpoint,
            reserve,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        controller.drain_actions().for_each(drop);
        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.push_application_bytes(Duration::ZERO, Direction::Outgoing, 1);
        controller.poll(Duration::ZERO);
        satisfy_outgoing_actions(&mut controller, Duration::from_micros(1), 2);
        controller.poll(Duration::from_micros(1));
        assert_eq!(
            controller.control.receiver_continuation_reserves,
            [(endpoint, reserve)]
        );
        assert!(controller.drain_actions().all(|action| !matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::SlotMissed { .. }
        )));
        assert!(
            !controller.control.incoming.is_empty(),
            "H survivors alone hold the complete base queue even in drop mode"
        );

        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));
        assert_eq!(
            controller.control.receiver_continuations.len(),
            1,
            "the low-capacity continuation is tagged while H+1 remains unsatisfied"
        );
        assert!(controller.drain_actions().all(|action| !matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::SlotMissed { .. }
        )));
        assert!(
            !controller.control.incoming.is_empty(),
            "tagged work cannot bypass the initial survivor gate"
        );

        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: spare,
                role: QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                expected_response_length: None,
            },
            Duration::from_micros(3),
        );
        acknowledge_chaff_request(
            &mut controller,
            Duration::from_micros(3),
            endpoint,
            spare,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        controller.poll(Duration::from_micros(3));
        let released: Vec<_> = controller.drain_actions().collect();
        assert!(released.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { stream, .. } if *stream == application
        )));
        assert!(released.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { stream, .. } if *stream == reserve
        )));
        assert!(controller.control.receiver_continuation_survivor_gate_open);
        assert!(
            controller.control.receiver_continuation_reserves.is_empty(),
            "the tagged continuation discharges its exact reserve only after H+1 latches"
        );
    }

    #[test]
    fn receiver_continuation_build_validates_horizon_and_structural_resource_capacity() {
        let build = |max_chaff_streams, use_empty_resources, resources: Option<Vec<Resource>>| {
            let walkie = WalkieTalkieConfig {
                molded: "walkie-talkie-continuation.json".into(),
                workload_id: "bootstrap-like-real".into(),
                packet_size: 1_200,
            };
            let defense = WalkieTalkie::from_json_with_max_stream_data_excess(
                &walkie,
                1_450,
                1_000,
                include_str!("../../tests/data/walkie-talkie-continuation.json"),
            )
            .expect("schema-six mould");
            QcsdController::with_defense(
                QcsdConfig {
                    max_udp_payload_size: 1_450,
                    max_stream_data_excess: 1_000,
                    max_chaff_streams,
                    use_empty_resources,
                    defense: DefenseConfig::WalkieTalkie(walkie),
                    ..QcsdConfig::default()
                },
                resources.map(|resources| ResourceManifest { resources }),
                Box::new(defense),
            )
        };
        let resource = |id, length, known_valid, depends_on| Resource {
            id,
            url: format!("https://example.com/{id}"),
            kind: "Image".into(),
            content_length: Some(length),
            data_length: length,
            chaff_priority: false,
            known_valid,
            depends_on,
            headers: Vec::new(),
        };

        assert!(build(2, false, None).is_err());
        assert!(build(2, false, Some(Vec::new())).is_err());
        assert!(build(2, false, Some(vec![resource(7, 1_199, true, Vec::new())])).is_err());
        assert!(build(2, false, Some(vec![resource(7, 1_200, false, Vec::new())])).is_err());
        assert!(build(2, false, Some(vec![resource(7, 1_200, true, vec![6])])).is_err());
        assert!(build(2, true, Some(vec![resource(7, 0, true, Vec::new())])).is_err());
        assert!(build(1, false, Some(vec![resource(7, 1_200, true, Vec::new())])).is_err());
        build(2, false, Some(vec![resource(7, 1_200, true, Vec::new())]))
            .expect("H+1 streams and one reusable exact-cell root are sufficient structurally");
        build(
            2,
            false,
            Some(vec![
                Resource {
                    chaff_priority: true,
                    ..resource(7, 1_199, true, Vec::new())
                },
                resource(8, 1_200, true, Vec::new()),
            ]),
        )
        .expect("build cannot false-reject before the complete endpoint-origin set is known");
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one-shot provisioning and continuation rollback are one causal lifecycle oracle"
    )]
    fn walkie_talkie_one_shot_batch_survives_unadvertised_reserve_loss_and_rollback() {
        const CELL: u64 = 1_200;
        let mut molded: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/data/walkie-talkie-continuation.json"
        ))
        .expect("receiver-continuation fixture");
        let profile = &mut molded["profiles"][0];
        profile["source_envelopes"] = serde_json::json!({
            "real": [{"outgoing": 1, "incoming": 1}],
            "decoy": [{"outgoing": 1, "incoming": 1}]
        });
        profile["batch_ends"] = serde_json::json!({"real": [0], "decoy": [0]});
        profile["molded_batch_ends"] = serde_json::json!([0]);
        profile["matching_cost_packets"] = serde_json::json!(4);
        profile["total_scheduled_bytes"] = serde_json::json!(4_800);
        profile["bursts"] = serde_json::json!([{"outgoing": 2, "incoming": 2}]);

        let config = WalkieTalkieConfig {
            molded: "one-shot-rollback.json".into(),
            workload_id: "bootstrap-like-real".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json(&config, 1_200, &molded.to_string())
            .expect("one-component Walkie-Talkie mould");
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Image".into(),
                content_length: Some(2 * CELL),
                data_length: 2 * CELL,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                low_watermark: 0,
                max_chaff_streams: 3,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: false,
                tail_wait_us: 0,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(0);
        let chaff_streams = [QcsdStreamId(4), QcsdStreamId(8), QcsdStreamId(12)];
        ready(&mut controller, 1, "https://example.com");
        controller.request_chaff_if_needed(true);
        let request_ids: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::RequestChaff {
                    resource,
                    request_id,
                    ..
                } => {
                    assert_eq!(resource.id, 7);
                    Some(request_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(request_ids.len(), 3);
        assert!(controller.control.chaff_preprovisioned_to_stream_limit);

        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: application,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(CELL),
            },
            Duration::ZERO,
        );
        for (stream, request_id) in chaff_streams.into_iter().zip(request_ids) {
            let role = QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: Some(request_id),
            };
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length: None,
                },
                Duration::ZERO,
            );
            acknowledge_chaff_request(&mut controller, Duration::ZERO, endpoint, stream, role);
        }
        controller.drain_actions().for_each(drop);
        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: application,
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 1,
                fin: false,
                slot: None,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        satisfy_outgoing_actions(&mut controller, Duration::from_micros(1), 2);
        controller.poll(Duration::from_micros(1));
        let (base_limit, base_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } if stream == application => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("base credit");
        assert_eq!(base_limit, CELL);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: application,
                absolute_limit: base_limit,
                slot: Some(base_slot),
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: application,
                bytes: CELL,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));
        let (first_stream, first_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { stream, slot, .. } => Some((stream, slot)),
                _ => None,
            })
            .expect("first reserve release");
        assert_eq!(first_stream, QcsdStreamId(12));

        // Losing the unadvertised selected stream rolls its whole cell back
        // and requeues the same tagged continuation. The next poll selects an
        // older member of the initial cohort without requesting new chaff.
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: first_stream,
                finish: QcsdStreamFinish::Reset,
            },
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));
        let retry_actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            !retry_actions
                .iter()
                .any(|action| matches!(action, QcsdAction::RequestChaff { .. }))
        );
        assert!(retry_actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit {
                stream: QcsdStreamId(8),
                slot,
                ..
            } if *slot == first_slot
        )));
        assert!(controller.control.chaff_preprovisioned_to_stream_limit);
    }

    #[test]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "the literal Cloudflare one-byte-tail geometry remains explicit"
    )]
    fn receiver_continuation_skips_active_cloudflare_chaff_and_retries_fresh() {
        const APPLICATION_BYTES: u64 = 100;
        const BULK_CHAFF_BYTES: u64 = 52_007;
        const ACTIVE_OFFSET: u64 = 3_093;
        const CELL: u64 = 1_200;
        const BASE_BYTES: u64 = 46 * CELL;
        const TARGET_INCOMING: u64 = 47 * CELL;
        const RESOURCE_BODY: u64 = 13_390;
        const ACTIVE_KNOWN_LIMIT: u64 = 13_522;

        let mut molded: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/data/walkie-talkie-continuation.json"
        ))
        .expect("receiver-continuation fixture");
        molded["qualification_bindings"][0]["workload_id"] = serde_json::json!("cloudflare-real");
        molded["qualification_bindings"][1]["workload_id"] = serde_json::json!("cloudflare-decoy");
        let profile = &mut molded["profiles"][0];
        profile["real"] = serde_json::json!("cloudflare-real");
        profile["decoy"] = serde_json::json!("cloudflare-decoy");
        profile["source_envelopes"] = serde_json::json!({
            "real": [{"outgoing": 1, "incoming": 46}],
            "decoy": [{"outgoing": 1, "incoming": 46}]
        });
        profile["batch_ends"] = serde_json::json!({"real": [0], "decoy": [0]});
        profile["molded_batch_ends"] = serde_json::json!([0]);
        profile["matching_cost_packets"] = serde_json::json!(4);
        profile["total_scheduled_bytes"] = serde_json::json!(58_800);
        profile["bursts"] = serde_json::json!([{"outgoing": 2, "incoming": 47}]);
        let config = WalkieTalkieConfig {
            molded: "literal-cloudflare-controller-geometry.json".into(),
            workload_id: "cloudflare-real".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json(&config, 1_200, &molded.to_string())
            .expect("47-cell Cloudflare-shaped mould");
        let manifest = ResourceManifest {
            resources: vec![
                Resource {
                    id: 6,
                    url: "https://example.com/bulk".into(),
                    kind: "Image".into(),
                    content_length: Some(BULK_CHAFF_BYTES),
                    data_length: BULK_CHAFF_BYTES,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 7,
                    url: "https://example.com/active".into(),
                    kind: "Image".into(),
                    content_length: Some(RESOURCE_BODY),
                    data_length: RESOURCE_BODY,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 8,
                    url: "https://example.com/pristine".into(),
                    kind: "Image".into(),
                    content_length: Some(RESOURCE_BODY),
                    data_length: RESOURCE_BODY,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
            ],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                max_stream_data_excess: 0,
                low_watermark: 0,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                tail_wait_us: 0,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(0);
        let bulk = QcsdStreamId(16);
        let active = QcsdStreamId(20);
        let replacement = QcsdStreamId(24);
        let initial_reserve = QcsdStreamId(28);
        ready(&mut controller, 1, "https://example.com");
        for (stream, role, expected_response_length) in [
            (
                application,
                QcsdRequestRole::Application,
                Some(APPLICATION_BYTES),
            ),
            (
                bulk,
                QcsdRequestRole::Chaff {
                    resource_id: 6,
                    request_id: None,
                },
                None,
            ),
            (
                active,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
            (
                replacement,
                QcsdRequestRole::Chaff {
                    resource_id: 8,
                    request_id: None,
                },
                None,
            ),
            (
                initial_reserve,
                QcsdRequestRole::Chaff {
                    resource_id: 8,
                    request_id: None,
                },
                None,
            ),
        ] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length,
                },
                Duration::ZERO,
            );
        }
        for (stream, resource_id) in [
            (bulk, 6),
            (active, 7),
            (replacement, 8),
            (initial_reserve, 8),
        ] {
            acknowledge_chaff_request(
                &mut controller,
                Duration::ZERO,
                endpoint,
                stream,
                QcsdRequestRole::Chaff {
                    resource_id,
                    request_id: None,
                },
            );
        }
        controller.drain_actions().for_each(drop);
        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: application,
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: APPLICATION_BYTES,
                fin: false,
                slot: None,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        satisfy_outgoing_actions(&mut controller, Duration::from_micros(1), 2);
        controller.poll(Duration::from_micros(1));

        // In the failed Cloudflare trace, final slot 62 owned disjoint base
        // ranges 0..741 and 3708..4167 (1200 bytes total). Holding that slot
        // leaves the preceding 46 base events at exactly offset 3093. This
        // reduced replay proves the same cutoff through ordinary allocation:
        // 52,107 bytes precede stream 20, then the 46 base cells leave 3,093.
        let base_credits: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                    ..
                } => Some((stream, absolute_limit, packet, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(
            base_credits
                .iter()
                .map(|(_, _, _, slot)| *slot)
                .collect::<BTreeSet<_>>()
                .len(),
            46
        );
        assert!(
            base_credits
                .iter()
                .all(|(_, _, packet, _)| u64::from(packet.length()) == CELL)
        );
        for (stream, expected_limit) in [
            (application, APPLICATION_BYTES),
            (bulk, BULK_CHAFF_BYTES),
            (active, ACTIVE_OFFSET),
        ] {
            assert_eq!(
                base_credits
                    .iter()
                    .filter(|(candidate, _, _, _)| *candidate == stream)
                    .map(|(_, absolute_limit, _, _)| *absolute_limit)
                    .max(),
                Some(expected_limit)
            );
        }
        assert_eq!(
            APPLICATION_BYTES + BULK_CHAFF_BYTES + ACTIVE_OFFSET,
            BASE_BYTES
        );
        assert_eq!(
            controller.control.receiver_continuation_reserves,
            [(endpoint, initial_reserve)],
            "the latest pre-ACKed pristine stream is the initial reserve"
        );
        assert!(controller.control.receiver_continuations.is_empty());
        for (stream, absolute_limit, _, slot) in base_credits {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(2),
            );
        }
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream: active,
                frame_bytes: 123,
                status: Some(200),
                content_length: Some(RESOURCE_BODY),
            },
            Duration::from_micros(2),
        );
        for data_bytes in [615, 981, 1_574] {
            controller.observe(
                QcsdObservation::DataFrame {
                    endpoint,
                    stream: active,
                    frame_header_bytes: 3,
                    data_bytes,
                },
                Duration::from_micros(2),
            );
        }
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: application,
                bytes: APPLICATION_BYTES,
            },
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));
        assert!(controller.drain_actions().all(|action| !matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::SlotMissed { .. }
        )));

        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: initial_reserve,
                finish: QcsdStreamFinish::Reset,
            },
            Duration::from_micros(3),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));
        let continuation_slots = controller
            .control
            .receiver_continuations
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let [continuation_slot] = continuation_slots.as_slice() else {
            panic!("the real Walkie-Talkie hook must tag exactly one continuation")
        };
        let continuation_slot = *continuation_slot;
        assert!(controller.control.incoming.is_empty());
        assert_eq!(
            controller
                .incoming_credit_ledger
                .get(&continuation_slot)
                .map(|ledger| ledger.unresolved()),
            Some(CELL)
        );
        // Stream 24 was already fully peer-ACKed before the sole outgoing
        // target.  Closing reserve 28 during the incoming turn can therefore
        // replace it without inventing a targetless request transmission.
        let (continuation_stream, continuation_limit, continuation_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } => Some((stream, absolute_limit, slot)),
                _ => None,
            })
            .expect("held continuation is released whole");
        assert_eq!(continuation_stream, replacement);
        assert_eq!(continuation_limit, CELL);
        let live_base_outstanding = controller
            .incoming_credit_ledger
            .iter()
            .filter(|(slot, _)| **slot != continuation_slot)
            .fold(0_u64, |total, (_, ledger)| {
                total.saturating_add(ledger.unresolved())
            });
        assert_eq!(
            live_base_outstanding,
            BASE_BYTES.saturating_sub(APPLICATION_BYTES)
        );
        assert!(live_base_outstanding > 1_000);
        assert!(
            controller
                .control
                .receiver_continuations
                .contains_key(&continuation_slot)
        );
        for (stream, bytes) in [(bulk, BULK_CHAFF_BYTES), (active, ACTIVE_OFFSET)] {
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes,
                },
                Duration::from_micros(4),
            );
        }
        let active_state = controller
            .streams
            .get_mut(endpoint, active)
            .expect("active chaff remains registered");
        assert!(matches!(
            active_state.receive,
            crate::stream::ReceiveState::ReceivingData {
                advertised_limit: ACTIVE_OFFSET,
                requested_limit: ACTIVE_OFFSET,
                known_limit: ACTIVE_KNOWN_LIMIT,
                consumed: ACTIVE_OFFSET,
                ..
            }
        ));
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: replacement,
                absolute_limit: continuation_limit,
                slot: Some(continuation_slot),
            },
            Duration::from_micros(5),
        );
        for observation in [
            QcsdObservation::BytesRead {
                endpoint,
                stream: replacement,
                bytes: 123,
            },
            QcsdObservation::ResponseHeaders {
                endpoint,
                stream: replacement,
                frame_bytes: 123,
                status: Some(200),
                content_length: Some(RESOURCE_BODY),
            },
            QcsdObservation::BytesRead {
                endpoint,
                stream: replacement,
                bytes: 3,
            },
            QcsdObservation::DataFrame {
                endpoint,
                stream: replacement,
                frame_header_bytes: 3,
                data_bytes: 615,
            },
            QcsdObservation::BytesRead {
                endpoint,
                stream: replacement,
                bytes: 615,
            },
            QcsdObservation::BytesRead {
                endpoint,
                stream: replacement,
                bytes: 3,
            },
            QcsdObservation::DataFrame {
                endpoint,
                stream: replacement,
                frame_header_bytes: 3,
                data_bytes: 981,
            },
            QcsdObservation::BytesRead {
                endpoint,
                stream: replacement,
                bytes: 456,
            },
        ] {
            controller.observe(observation, Duration::from_micros(5));
        }
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(5),
        );
        controller.poll(Duration::from_micros(5));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(
            diagnostics.scheduled_incoming_requested_bytes,
            TARGET_INCOMING
        );
        assert_eq!(
            diagnostics.scheduled_incoming_consumed_bytes,
            TARGET_INCOMING
        );
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_target_outgoing_cells, 2);
        assert_eq!(diagnostics.walkie_talkie_observed_outgoing_cells, 2);
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 47);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 47);
        assert_eq!(
            diagnostics.walkie_talkie_natural_incoming_bytes,
            APPLICATION_BYTES
        );
        assert_eq!(
            diagnostics.walkie_talkie_incoming_chaff_bytes,
            BULK_CHAFF_BYTES + ACTIVE_OFFSET + CELL
        );
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(
            !controller
                .control
                .receiver_continuations
                .contains_key(&continuation_slot)
        );

        // An unadvertised held continuation follows the same terminal cleanup
        // path when a run aborts: its marker, queue entry, and ledger disappear
        // together, and its complete cell is retired exactly once.
        let abort_packet =
            Packet::new(Duration::from_micros(6), Direction::Incoming, 1_200).expect("packet");
        let abort_slot = controller.control.next_slot();
        controller.pending_slots.insert(abort_slot, abort_packet);
        controller
            .incoming_credit_ledger
            .insert(abort_slot, IncomingCreditLedger::new(abort_packet));
        controller.scheduled_incoming_requested_bytes = controller
            .scheduled_incoming_requested_bytes
            .saturating_add(CELL);
        controller.control.receiver_continuations.insert(
            abort_slot,
            crate::ReceiverContinuationDisposition {
                cell_bytes: CELL,
                parser_ceiling_bytes: 1_000,
            },
        );
        controller.control.incoming.push(PendingIncoming {
            slot: abort_slot,
            packet: abort_packet,
            endpoint: None,
            remaining: CELL,
        });
        controller.abort_pending_slots(Duration::from_micros(6), MissedSlotReason::RunAborted);
        assert!(controller.control.receiver_continuations.is_empty());
        assert!(controller.control.incoming.is_empty());
        assert!(!controller.incoming_credit_ledger.contains_key(&abort_slot));
        assert!(!controller.pending_slots.contains_key(&abort_slot));
        let aborted = controller.defense_diagnostics();
        assert_eq!(
            aborted.scheduled_incoming_requested_bytes,
            TARGET_INCOMING + CELL
        );
        assert_eq!(aborted.scheduled_incoming_consumed_bytes, TARGET_INCOMING);
        assert_eq!(aborted.scheduled_incoming_retired_bytes, CELL);
        assert_eq!(aborted.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the two-endpoint Walkie-Talkie realization is kept explicit"
    )]
    fn walkie_talkie_one_logical_incoming_cell_fans_out_across_origins() {
        let molded = r#"{
            "adaptation": "qcsd-client-only",
            "burst_definition": "global-application-batch-direction-transitions",
            "cell_byte_domain": "http3-request-stream-offset.bytes",
            "schema_version": 6,
            "generated_by": "controller multi-origin test",
            "matching_algorithm": "minimum-base-symmetric-mold-padding-cost-one-to-one",
            "paper_equivalent": false,
            "packet_size": 1200,
            "receiver_continuation": {
                "allocation_policy": "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell",
                "application_order": "after-symmetric-elementwise-mold",
                "base_allocation_policy": "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;exact-capacity-before-bounded-framing-claims",
                "batch_end_release_policy": "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate",
                "causal_capacity_precondition": "every-molded-component-outgoing>0;effective-configured-max-chaff-streams>=total-receiver-continuation-reserve-horizon+1;schema-two-stateful-stage-capacity-recurrence-proves-higher-priority-due-application-stream-frames-plus-cumulative-one-shot-chaff-request-stream-frames-through-fin-fit-within-each-exact-full-molded-outgoing-target-through-final-component",
                "cells_per_nonzero_incoming_component": 1,
                "formula": "symmetric_incoming=adapted_incoming-1-if-adapted_incoming>0-else-0",
                "parser_allowance_ceiling_bytes": 1000,
                "prefix_consumability_precondition": "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable",
                "post_outgoing_loss_liveness_limitation": "loss-of-required-initial-peer-acknowledged-survivor-after-initial-request-chaff-batch-holds-base-and-continuation-allocation;no-new-chaff-request-replenishment-or-generic-post-loss-liveness-guarantee",
                "provisioning_policy": "fill-effective-configured-max-chaff-streams-once-before-first-due-molded-outgoing-actions;never-replenish-after-initial-request-chaff-batch",
                "raw_headroom_bytes_per_nonzero_incoming_component": 1200,
                "sender_framing_cells_per_nonzero_outgoing_component": 1,
                "sender_framing_formula": "symmetric_outgoing=adapted_outgoing-1-if-adapted_outgoing>0-else-0",
                "sender_framing_policy": "one-full-cell-per-positive-symmetric-outgoing-component-reserved-for-quic-http3-stream-framing-and-mandatory-control-overhead",
                "release_policy": "after-issued-base-events-controller-requested-and-request-signals-observed;batch-gate-open;release-when-all-base-events-issued-or-real-reported-nonreserved-capacity-is-below-one-cell;recompute-live-unconsumed-base-each-retry;retain-single-coalescible-unadvertised-positive-outstanding-at-or-below-parser-ceiling-until-max-stream-data-advertised;prefer-single-coalesced-advertised-positive-outstanding-at-or-below-parser-ceiling-on-peer-acknowledged-nonreserved-header-blocked-stream;otherwise-release-whole-cell-to-oldest-retained-peer-acknowledged-pristine-reserve-regardless-of-live-base-debt;remove-oldest-reserve-once",
                "request_activation_policy": "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-molded-outgoing-cells",
                "request_prefix_delivery_precondition": "before-first-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-chaff-request-survivors>=total-receiver-continuation-reserve-horizon+1;initial-survivor-gate-remains-latched-across-complete-schedule",
                "resource_precondition": "schema-two-qualified-manifest-selects-known-valid-same-origin-source-resource;derived-selected-resource-projection-dependency-free-with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component;required-chaff-streams-defines-effective-configured-max-chaff-streams",
                "reserve_lifecycle_policy": "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-from-initial-peer-acknowledged-preprovisioned-cohort-for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-corresponding-all-future-horizon-reserve-before-further-base-allocation",
                "reserve_policy": "reserve-deterministic-acknowledged-pristine-candidates-for-all-remaining-nonzero-incoming-components-before-first-base-allocation-and-retain-distinct-reserves-across-later-positive-outgoing-components",
                "qualified_chaff_manifest_policy": "schema-two-qualified-navigation-root-and-selected-source-resource;explicit-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams;selected-source-resource-known-valid-same-origin;derived-selected-resource-projection-dependency-free;exact-lowercase-accept-accept-encoding-accept-language-projection;application-request-headers-unchanged",
                "qualified_chaff_response_policy": "three-independent-staged-qualified-parallel-chaff-streams=max-five-and-walkie-talkie-required-chaff-streams-concurrent-unshaped-production-nonblocking-qpack-qualifications-derive-selected-resource-compact-status-normalized-content-encoding-body-bytes-body-sha256;one-shot-controller-config-uses-exact-walkie-talkie-required-chaff-streams;runtime-complete-responses-must-match-derived-identity;runtime-partial-responses-have-null-identity-match-fields",
                "staged_prefix_pack_precondition": "schema-two-every-component-staged-prefix-pack-after-peer-settings-and-drained-h3-control-qpack-warmup;each-molded-component-is-an-exact-declared-full-packet-target;opens-exact-bound-application-resources-and-cumulative-copies-of-selected-qualified-resource;active-chaff-cohort-is-nondecreasing-and-zero-delta-stages-are-allowed;all-post-cutoff-stream-transmissions-owned-by-one-of-exact-declared-stage-targets;each-stage-gate-requires-cumulative-application-requests-transmitted-contiguously-through-fin-and-required-active-chaff-requests-transmitted-contiguously-through-fin-and-peer-acknowledged-before-dependent-base-allocation;no-pending-request-causal-h3-control-or-qpack-encoder-stream-output;post-warmup-qpack-decoder-stream-output-recorded-and-excluded;zero-targetless-stream-bytes",
                "qualification_binding_policy": "schema-six-raw-sha256-per-workload-binds-schema-two-chaff-qualification-sidecar-prefix-pack-spec-and-qualified-chaff-manifest;runtime-requires-exact-current-artifact-hashes-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams"
            },
            "qualification_bindings": [
                {
                    "workload_id": "real page",
                    "chaff_qualification_sidecar_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "prefix_pack_spec_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "qualified_chaff_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 5
                },
                {
                    "workload_id": "decoy page",
                    "chaff_qualification_sidecar_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "prefix_pack_spec_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "qualified_chaff_manifest_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "application_resource_id": 0,
                    "selected_chaff_resource_id": 0,
                    "qualified_parallel_chaff_streams": 5,
                    "walkie_talkie_required_chaff_streams": 5
                }
            ],
            "profiles": [{
                "real": "real page",
                "decoy": "decoy page",
                "matching_cost_packets": 4,
                "training_inputs": {
                    "real": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                    "decoy": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                },
                "variation": {
                    "real": {"visit_count": 1, "varying_components": 0, "maximum_component_spread": 0},
                    "decoy": {"visit_count": 1, "varying_components": 0, "maximum_component_spread": 0}
                },
                "source_envelopes": {
                    "real": [{"outgoing": 1, "incoming": 1}],
                    "decoy": [{"outgoing": 1, "incoming": 1}]
                },
                "batch_ends": {"real": [0], "decoy": [0]},
                "molded_batch_ends": [0],
                "total_scheduled_bytes": 4800,
                "bursts": [{"outgoing": 2, "incoming": 2}]
            }]
        }"#;
        let config = WalkieTalkieConfig {
            molded: "inline-multi-origin-test.json".into(),
            workload_id: "real page".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json(&config, 1_200, molded).expect("valid mould");
        let manifest = ResourceManifest {
            resources: vec![
                Resource {
                    id: 7,
                    url: "https://1.example/chaff".into(),
                    kind: "Image".into(),
                    content_length: Some(600),
                    data_length: 600,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 8,
                    url: "https://2.example/chaff".into(),
                    kind: "Image".into(),
                    content_length: Some(1_800),
                    data_length: 1_800,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 9,
                    url: "https://1.example/reserve".into(),
                    kind: "Image".into(),
                    content_length: Some(1_800),
                    data_length: 1_800,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
            ],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 0,
                max_udp_payload_size: 1_200,
                tail_wait_us: 0,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        for (endpoint_id, stream_id, resource_id) in [(1, 0, 7), (1, 4, 9), (2, 4, 8), (2, 8, 8)] {
            ready(
                &mut controller,
                endpoint_id,
                &format!("https://{endpoint_id}.example"),
            );
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint: QcsdEndpointId(endpoint_id),
                    stream: QcsdStreamId(stream_id),
                    role: QcsdRequestRole::Chaff {
                        resource_id,
                        request_id: None,
                    },
                    expected_response_length: None,
                },
                Duration::ZERO,
            );
        }
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            QcsdEndpointId(1),
            QcsdStreamId(0),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            QcsdEndpointId(1),
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 9,
                request_id: None,
            },
        );
        for stream in [QcsdStreamId(4), QcsdStreamId(8)] {
            acknowledge_chaff_request(
                &mut controller,
                Duration::ZERO,
                QcsdEndpointId(2),
                stream,
                QcsdRequestRole::Chaff {
                    resource_id: 8,
                    request_id: None,
                },
            );
        }
        controller.drain_actions().for_each(drop);
        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.push_application_bytes(Duration::ZERO, Direction::Outgoing, 1);
        controller.poll(Duration::ZERO);
        satisfy_outgoing_actions(&mut controller, Duration::ZERO, 2);
        controller.poll(Duration::from_micros(1));
        assert_eq!(
            controller.control.receiver_continuation_reserves,
            [(QcsdEndpointId(1), QcsdStreamId(4))],
            "ordinary base allocation must protect the activated pristine reserve"
        );
        let credits: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } => Some((endpoint, stream, absolute_limit, slot)),
                _ => None,
            })
            .collect();
        let [
            (first_endpoint, first_stream, first_limit, first_slot),
            (second_endpoint, second_stream, second_limit, second_slot),
        ] = credits.as_slice()
        else {
            panic!("the base logical credit must fan out twice: {credits:#?}");
        };
        assert_eq!(
            (*first_endpoint, *first_stream, *first_limit),
            (QcsdEndpointId(1), QcsdStreamId(0), 600)
        );
        assert_eq!(
            (*second_endpoint, *second_stream, *second_limit),
            (QcsdEndpointId(2), QcsdStreamId(4), 600)
        );
        assert_eq!(first_slot, second_slot);
        for (endpoint, stream, absolute_limit, slot) in &credits {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint: *endpoint,
                    stream: *stream,
                    absolute_limit: *absolute_limit,
                    slot: Some(*slot),
                },
                Duration::from_micros(1),
            );
        }
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint: *first_endpoint,
                stream: *first_stream,
                bytes: 600,
            },
            Duration::from_micros(1),
        );
        controller.push_application_bytes(Duration::from_micros(1), Direction::Incoming, 1);
        controller.poll(Duration::from_micros(1));
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { slot, .. } if slot != *first_slot
        )));
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));
        let (continuation_endpoint, continuation_stream, continuation_limit, continuation_slot) =
            controller
                .drain_actions()
                .find_map(|action| match action {
                    QcsdAction::IncreaseReceiveLimit {
                        endpoint,
                        stream,
                        absolute_limit,
                        slot,
                        ..
                    } if slot != *first_slot => Some((endpoint, stream, absolute_limit, slot)),
                    _ => None,
                })
                .expect("endpoint-two base tail receives the whole continuation");
        assert_eq!(
            (
                continuation_endpoint,
                continuation_stream,
                continuation_limit
            ),
            (QcsdEndpointId(2), QcsdStreamId(4), 1_800)
        );
        assert_ne!(continuation_slot, *first_slot);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint: continuation_endpoint,
                stream: continuation_stream,
                absolute_limit: continuation_limit,
                slot: Some(continuation_slot),
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint: continuation_endpoint,
                stream: continuation_stream,
                bytes: 1_800,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 2_400);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 2_400);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 2);
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, 2_400);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(controller.is_complete());
    }

    #[test]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "the regression preserves FIN retirement and terminal accounting end to end"
    )]
    fn walkie_talkie_fin_residual_credit_is_terminal_and_never_retried() {
        let config = WalkieTalkieConfig {
            molded: "walkie-talkie-golden.json".into(),
            workload_id: "real page".into(),
            packet_size: 1_200,
        };
        let defense = WalkieTalkie::from_json(
            &config,
            1_200,
            include_str!("../../tests/data/walkie-talkie-golden.json"),
        )
        .expect("two-batch Walkie-Talkie fixture");
        let manifest = ResourceManifest {
            resources: vec![
                Resource {
                    id: 7,
                    url: "https://example.com/chaff".into(),
                    kind: "Image".into(),
                    content_length: Some(7_200),
                    data_length: 7_200,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
                Resource {
                    id: 8,
                    url: "https://spare.example/chaff".into(),
                    kind: "Image".into(),
                    content_length: Some(1),
                    data_length: 1,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                },
            ],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 1,
                initial_max_stream_data: 16,
                max_stream_data_excess: 16,
                low_watermark: 0,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                tail_wait_us: 0,
                defense: DefenseConfig::WalkieTalkie(config),
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        ready(&mut controller, 1, "https://example.com");
        for (stream, role, expected_response_length) in [
            (QcsdStreamId(0), QcsdRequestRole::Application, Some(300)),
            (
                QcsdStreamId(4),
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
            (
                QcsdStreamId(8),
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
            (
                QcsdStreamId(12),
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                None,
            ),
        ] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length,
                },
                Duration::ZERO,
            );
        }
        for stream in [QcsdStreamId(4), QcsdStreamId(8), QcsdStreamId(12)] {
            acknowledge_chaff_request(
                &mut controller,
                Duration::ZERO,
                endpoint,
                stream,
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
            );
        }
        let initial_actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            initial_actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::ConfigureManualReceive { .. }))
                .count(),
            4
        );
        assert!(initial_actions.iter().all(|action| !matches!(
            action,
            QcsdAction::ConfigureManualReceive {
                initial_limit,
                ..
            } if *initial_limit != 0
        )));

        controller.observe(QcsdObservation::ApplicationBatchStarted, Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint,
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 100,
                fin: false,
                slot: None,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let first_outgoing: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::SendPacket { packet, slot, .. } => Some((packet, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(first_outgoing.len(), 3);
        for (packet, slot) in first_outgoing {
            controller.observe(
                QcsdObservation::SlotSatisfied {
                    endpoint,
                    slot,
                    observed_size: packet.length(),
                },
                Duration::from_micros(1),
            );
        }
        controller.poll(Duration::from_micros(1));
        let first_credits: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                    ..
                } => Some((stream, absolute_limit, packet, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(first_credits.len(), 3);
        assert!(
            first_credits
                .iter()
                .all(|credit| credit.2.length() == 1_200)
        );
        assert_eq!(
            first_credits
                .iter()
                .map(|(stream, absolute_limit, _, _)| (*stream, *absolute_limit))
                .collect::<Vec<_>>(),
            [
                (QcsdStreamId(0), 300),
                (QcsdStreamId(4), 884),
                (QcsdStreamId(4), 2_084),
            ]
        );
        for (stream, absolute_limit, _, slot) in first_credits {
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(3),
            );
        }
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: QcsdStreamId(0),
                bytes: 250,
            },
            Duration::from_micros(3),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(0),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(3),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));
        let terminal_actions: Vec<_> = controller.drain_actions().collect();
        assert!(terminal_actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit {
                stream: QcsdStreamId(4),
                absolute_limit: 2_100,
                ..
            }
        )));
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(4),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));
        let retired_actions: Vec<_> = controller.drain_actions().collect();
        assert!(retired_actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::ReceiveCreditRetired,
                ..
            }
        )));
        assert!(!controller.can_start_application_batch());
        assert_eq!(
            controller.terminal_failure(),
            Some("Walkie-Talkie receive credit retired before the incoming mould was realized")
        );
        assert_eq!(controller.next_deadline(), None);
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 2_400);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 250);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 2_150);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 5_750);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 1);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 250);
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, 0);
        assert_eq!(
            diagnostics.walkie_talkie_application_stream_crossing_bytes,
            0
        );
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
    }

    fn tamaraw_controller() -> QcsdController {
        QcsdController::new(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Tamaraw(TamarawConfig {
                    incoming_interval_us: 5_000,
                    outgoing_interval_us: 20_000,
                    packet_size: 1_200,
                    modulo: 4,
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller")
    }

    fn ready(controller: &mut QcsdController, endpoint: u64, origin: &str) {
        controller.observe(
            QcsdObservation::EndpointReady {
                endpoint: QcsdEndpointId(endpoint),
                origin: origin.into(),
                max_udp_payload_size: 1_200,
            },
            Duration::ZERO,
        );
    }

    fn front_prearm_controller() -> QcsdController {
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://front.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_000_000),
                data_length: 1_000_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        QcsdController::new(
            QcsdConfig {
                control_interval_us: 5_000,
                max_chaff_streams: 1,
                low_watermark: 0,
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
            Some(manifest),
        )
        .expect("FRONT prearm controller")
    }

    #[test]
    fn fixed_prearm_preserves_global_slots_and_keeps_future_incoming_private() {
        let mut controller = front_prearm_controller();
        let frozen: Vec<_> = controller
            .fixed_schedule
            .as_ref()
            .expect("FRONT opts into fixed staging")
            .events
            .iter()
            .copied()
            .collect();
        assert!(
            frozen
                .iter()
                .any(|event| event.packet.direction() == Direction::Incoming)
        );
        assert!(
            frozen
                .iter()
                .any(|event| event.packet.direction() == Direction::Outgoing)
        );
        assert!(
            frozen
                .iter()
                .enumerate()
                .all(|(index, event)| event.slot == QcsdSlotId(u64::try_from(index).unwrap()))
        );

        ready(&mut controller, 1, "https://front.example");
        controller.reconcile_due_fixed(Duration::ZERO);
        let sends: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::SendPacket {
                    endpoint,
                    packet,
                    slot,
                    not_before_after_us,
                    deadline_after_us,
                    ..
                } => Some((
                    endpoint,
                    packet,
                    slot,
                    not_before_after_us,
                    deadline_after_us,
                )),
                _ => None,
            })
            .collect();
        let expected_outgoing: Vec<_> = frozen
            .iter()
            .copied()
            .filter(|event| event.packet.direction() == Direction::Outgoing)
            .collect();
        assert_eq!(sends.len(), expected_outgoing.len());
        for (send, expected) in sends.iter().zip(&expected_outgoing) {
            assert_eq!(send.0, QcsdEndpointId(1));
            assert_eq!((send.1, send.2), (expected.packet, expected.slot));
            assert_eq!(send.3, expected.packet.timestamp_us());
            assert_eq!(send.4.saturating_sub(send.3), 5_000);
        }

        assert!(controller.incoming_credit_ledger.is_empty());
        assert!(controller.control.incoming.is_empty());
        assert_eq!(controller.scheduled_incoming_requested_bytes, 0);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_requested_bytes,
            0
        );
        assert_eq!(
            controller.pending_slots(),
            expected_outgoing
                .iter()
                .map(|event| (event.slot, event.packet))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            controller
                .fixed_schedule
                .as_ref()
                .expect("staging remains")
                .events
                .len(),
            frozen.len()
        );
    }

    #[test]
    fn fixed_due_reconciliation_materializes_incoming_before_outgoing_flush() {
        let mut controller = front_prearm_controller();
        let endpoint = QcsdEndpointId(1);
        ready(&mut controller, endpoint.0, "https://front.example");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                expected_response_length: Some(1_000_000),
            },
            Duration::ZERO,
        );
        _ = controller.drain_actions().collect::<Vec<_>>();
        controller.reconcile_due_fixed(Duration::ZERO);
        let prearmed: Vec<_> = controller.drain_actions().collect();
        assert!(
            prearmed
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );

        let (due, incoming_slot) = controller
            .fixed_schedule
            .as_ref()
            .expect("FRONT staging")
            .events
            .iter()
            .find_map(|event| {
                (event.packet.direction() == Direction::Incoming)
                    .then_some((event.packet.timestamp(), event.slot))
            })
            .expect("incoming FRONT event");
        controller.reconcile_due_fixed(due);
        let due_actions: Vec<_> = controller.drain_actions().collect();
        assert!(due_actions.iter().any(|action| {
            matches!(
                action,
                QcsdAction::IncreaseReceiveLimit { slot, .. } if *slot == incoming_slot
            )
        }));
        assert!(
            !due_actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            controller
                .incoming_credit_ledger
                .contains_key(&incoming_slot)
        );
        assert_eq!(
            controller.scheduled_incoming_requested_bytes,
            u64::from(
                controller
                    .pending_slots
                    .get(&incoming_slot)
                    .expect("due incoming is public")
                    .length()
            )
        );
    }

    #[test]
    fn fixed_unallocatable_incoming_advances_retry_deadline_without_mutation() {
        let mut controller = front_prearm_controller();
        ready(&mut controller, 1, "https://front.example");
        controller.reconcile_due_fixed(Duration::ZERO);
        _ = controller.drain_actions().collect::<Vec<_>>();

        let final_event_at = controller
            .fixed_schedule
            .as_ref()
            .expect("FRONT staging")
            .events
            .back()
            .expect("frozen FRONT event")
            .packet
            .timestamp();
        controller.reconcile_due_fixed(final_event_at);
        assert!(
            controller
                .fixed_schedule
                .as_ref()
                .expect("FRONT staging")
                .events
                .is_empty()
        );

        let pending_before: Vec<_> = controller
            .control
            .incoming
            .iter()
            .map(|incoming| (incoming.slot, incoming.packet, incoming.remaining))
            .collect();
        assert!(!pending_before.is_empty());
        assert!(pending_before.iter().all(|(_, packet, remaining)| {
            packet.direction() == Direction::Incoming && *remaining == u64::from(packet.length())
        }));
        let public_before = controller.pending_slots();
        let actions_before_retry: Vec<_> = controller.drain_actions().collect();
        assert!(!actions_before_retry.iter().any(|action| {
            matches!(
                action,
                QcsdAction::SlotSatisfied { .. } | QcsdAction::SlotMissed { .. }
            )
        }));
        controller.flush_defense_observations();

        let first_elapsed_us = u64::try_from(final_event_at.as_micros()).unwrap();
        let first_watermark = (first_elapsed_us / controller.config.control_interval_us)
            * controller.config.control_interval_us;
        assert_eq!(
            controller.control.last_incoming_boundary_us,
            Some(first_watermark)
        );
        let first_retry = controller.next_deadline().expect("pending retry deadline");
        assert!(
            first_retry > final_event_at,
            "retry {first_retry:?} did not advance past reconciliation {final_event_at:?} at watermark {first_watermark}",
        );

        let retry_at = final_event_at.saturating_add(controller.config.control_interval());
        controller.reconcile_due_fixed(retry_at);
        let pending_after: Vec<_> = controller
            .control
            .incoming
            .iter()
            .map(|incoming| (incoming.slot, incoming.packet, incoming.remaining))
            .collect();
        assert_eq!(pending_after, pending_before);
        assert_eq!(controller.pending_slots(), public_before);
        assert!(!controller.drain_actions().any(|action| {
            matches!(
                action,
                QcsdAction::IncreaseReceiveLimit { .. }
                    | QcsdAction::SlotSatisfied { .. }
                    | QcsdAction::SlotMissed { .. }
            )
        }));

        let second_elapsed_us = u64::try_from(retry_at.as_micros()).unwrap();
        let second_watermark = (second_elapsed_us / controller.config.control_interval_us)
            * controller.config.control_interval_us;
        assert!(second_watermark > first_watermark);
        assert_eq!(
            controller.control.last_incoming_boundary_us,
            Some(second_watermark)
        );
        controller.flush_defense_observations();
        let second_retry = controller.next_deadline().expect("advanced retry deadline");
        assert!(second_retry > retry_at);
        assert!(second_retry > first_retry);
    }

    #[test]
    fn fixed_prearm_does_not_advance_terminal_tail_or_completion() {
        let mut controller = front_prearm_controller();
        ready(&mut controller, 1, "https://front.example");
        controller.reconcile_due_fixed(Duration::ZERO);
        let outgoing: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::SendPacket {
                    endpoint,
                    packet,
                    slot,
                    ..
                } => Some((endpoint, packet, slot)),
                _ => None,
            })
            .collect();
        for (endpoint, packet, slot) in outgoing {
            controller.observe(
                QcsdObservation::SlotSatisfied {
                    endpoint,
                    slot,
                    observed_size: packet.length(),
                },
                Duration::ZERO,
            );
        }
        controller.poll(Duration::ZERO);
        assert!(!controller.is_complete());
        assert_eq!(controller.completion_due, None);
        assert_eq!(controller.scheduled_incoming_requested_bytes, 0);
        assert!(controller.incoming_credit_ledger.is_empty());
        assert!(controller.defense.next_event_at().is_some());
    }

    #[test]
    fn dynamic_defense_does_not_prearm() {
        let future =
            Packet::new(Duration::from_millis(10), Direction::Outgoing, 1_200).expect("packet");
        let (defense, _) = RecordingDefense::new([future], DefenseMode::ChaffOnly);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("dynamic controller");
        ready(&mut controller, 1, "https://dynamic.example");
        assert!(!controller.has_fixed_schedule_staging());
        controller.poll(Duration::ZERO);
        assert!(controller.pending_slots().is_empty());
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );

        controller.poll(Duration::from_millis(10));
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SendPacket {
                packet,
                not_before_after_us: 0,
                deadline_after_us: 5_000,
                ..
            }) if packet == future
        ));
    }

    #[test]
    fn static_schedule_does_not_prearm() {
        let future =
            Packet::new(Duration::from_millis(10), Direction::Outgoing, 1_200).expect("packet");
        let defense = StaticSchedule::new(Trace::new([future]), false);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("static controller");
        ready(&mut controller, 1, "https://static.example");
        assert!(!controller.has_fixed_schedule_staging());
        controller.poll(Duration::ZERO);
        assert!(controller.pending_slots().is_empty());
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );

        controller.poll(Duration::from_millis(10));
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SendPacket {
                packet,
                not_before_after_us: 0,
                deadline_after_us: 5_000,
                ..
            }) if packet == future
        ));
    }

    #[test]
    fn fixed_prearm_rounds_release_up_and_deadline_down_to_micros() {
        assert_eq!(duration_as_ceil_micros(Duration::from_nanos(1)), 1);
        assert_eq!(duration_as_ceil_micros(Duration::from_micros(1)), 1);
        assert_eq!(duration_as_ceil_micros(Duration::from_nanos(1_001)), 2);
        assert_eq!(duration_as_floor_micros(Duration::from_nanos(1)), 0);
        assert_eq!(duration_as_floor_micros(Duration::from_micros(1)), 1);
        assert_eq!(duration_as_floor_micros(Duration::from_nanos(1_001)), 1);
    }

    #[test]
    fn fixed_prearm_rejects_a_window_collapsed_by_inward_rounding() {
        let mut controller = front_prearm_controller();
        controller.config.control_interval_us = 1;
        let event = controller
            .fixed_schedule
            .as_ref()
            .expect("FRONT staging")
            .events
            .iter()
            .copied()
            .find(|event| event.packet.direction() == Direction::Outgoing)
            .expect("outgoing FRONT event");
        let elapsed = event
            .packet
            .timestamp()
            .checked_sub(Duration::from_nanos(500))
            .expect("FRONT event is after the fixture epoch");
        ready(&mut controller, 1, "https://front.example");

        controller.reconcile_due_fixed(elapsed);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                slot,
                reason: MissedSlotReason::DeadlineExpired,
                ..
            } if *slot == event.slot
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket { slot, .. } if *slot == event.slot
        )));
        assert!(!controller.pending_slots.contains_key(&event.slot));
    }

    fn satisfy_outgoing_actions(
        controller: &mut QcsdController,
        at: Duration,
        expected_count: usize,
    ) {
        let outgoing: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::SendPacket {
                    endpoint,
                    packet,
                    slot,
                    ..
                } => Some((endpoint, packet, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(outgoing.len(), expected_count);
        for (endpoint, packet, slot) in outgoing {
            controller.observe(
                QcsdObservation::SlotSatisfied {
                    endpoint,
                    slot,
                    observed_size: packet.length(),
                },
                at,
            );
        }
    }

    fn acknowledge_chaff_request(
        controller: &mut QcsdController,
        at: Duration,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
    ) {
        controller.observe(
            QcsdObservation::StreamDataAcknowledged {
                endpoint,
                stream,
                role,
                offset: 0,
                bytes: 100,
                fin: true,
            },
            at,
        );
    }

    fn terminal_chaff_shape_controller(
        defense: Box<dyn Defense>,
        acknowledge_fresh: bool,
    ) -> QcsdController {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            defense,
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let role = QcsdRequestRole::Chaff {
            resource_id: 7,
            request_id: None,
        };
        ready(&mut controller, 1, "https://example.com");
        controller
            .streams
            .open(endpoint, QcsdStreamId(64), role, true, 16, 1_000, 1_024);
        controller
            .streams
            .open(endpoint, QcsdStreamId(68), role, true, 16, 1_000, 38_376);
        if acknowledge_fresh {
            acknowledge_chaff_request(
                &mut controller,
                Duration::ZERO,
                endpoint,
                QcsdStreamId(68),
                role,
            );
        }
        controller
    }

    fn incoming_packet(at: Duration) -> Packet {
        Packet::new(at, Direction::Incoming, 1_200).expect("incoming packet")
    }

    fn outgoing_packet(at: Duration) -> Packet {
        Packet::new(at, Direction::Outgoing, 1_200).expect("outgoing packet")
    }

    #[test]
    fn final_front_slot_prefers_one_acked_pristine_whole_stream() {
        let incoming = incoming_packet(Duration::ZERO);
        let future_outgoing = outgoing_packet(Duration::from_millis(1));
        let defense = StaticSchedule::with_mode(
            Trace::new([incoming, future_outgoing]),
            DefenseMode::ChaffOnly,
        );
        let mut controller = terminal_chaff_shape_controller(Box::new(defense), true);

        let opportunities = controller
            .streams
            .allocation_opportunities(QcsdEndpointId(1), DefenseMode::ChaffOnly);
        assert_eq!(opportunities[0].stream, QcsdStreamId(64));
        assert_eq!(opportunities[0].exact, 1_008);
        assert_eq!(opportunities[0].claimable, 1_000);
        assert_eq!(opportunities[1].stream, QcsdStreamId(68));
        assert!(opportunities[1].exact >= 1_200);

        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        let receive: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                } => Some((*endpoint, *stream, *absolute_limit, *packet, *slot)),
                _ => None,
            })
            .collect();
        assert_eq!(receive.len(), 1);
        let (endpoint, stream, absolute_limit, packet, slot) = receive[0];
        assert_eq!(stream, QcsdStreamId(68));
        assert_eq!(absolute_limit, 1_216);
        assert_eq!(packet, incoming);
        assert!(controller.control.claims.is_empty());
        assert_eq!(controller.control.credit.len(), 1);
        assert_eq!(controller.control.credit[0].increase, 1_200);

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
                bytes: absolute_limit,
            },
            Duration::from_micros(2),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied { slot: satisfied, .. }) if satisfied == slot
        ));
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(3),
        );
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn final_front_whole_stream_preference_precedes_an_older_tail_bridge() {
        let incoming = incoming_packet(Duration::ZERO);
        let future_outgoing = outgoing_packet(Duration::from_millis(1));
        let defense = StaticSchedule::with_mode(
            Trace::new([incoming, future_outgoing]),
            DefenseMode::ChaffOnly,
        );
        let mut controller = terminal_chaff_shape_controller(Box::new(defense), true);
        let endpoint = QcsdEndpointId(1);
        let tail_stream = QcsdStreamId(64);
        let fresh_stream = QcsdStreamId(68);
        let old_slot = QcsdSlotId(900);
        let old_packet = incoming_packet(Duration::ZERO);

        let receive = &mut controller
            .streams
            .get_mut(endpoint, tail_stream)
            .expect("tail stream")
            .receive;
        receive.data_frame(3, 1_024);
        assert_eq!(receive.release(100), Some((116, 100)));
        receive.advertised(116);
        receive.bytes_read(114);
        controller.pending_slots.insert(old_slot, old_packet);
        controller.incoming_credit_ledger.insert(
            old_slot,
            IncomingCreditLedger {
                packet: old_packet,
                endpoint: Some(endpoint),
                multiple_endpoints: false,
                advertised: 1_200,
                local_realization_emitted: true,
                consumed: 1_198,
                retired: 0,
            },
        );
        controller.scheduled_incoming_requested_bytes = 1_200;
        controller.scheduled_incoming_advertised_bytes = 1_200;
        controller.scheduled_incoming_consumed_bytes = 1_198;
        controller.advertised_incoming_credit.insert(
            (endpoint, tail_stream),
            vec![AdvertisedIncomingCredit {
                slot: old_slot,
                start: 114,
                end: 116,
            }],
        );

        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream: tail_stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(controller.next_action().is_none());

        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit {
                stream,
                absolute_limit: 1_216,
                packet,
                ..
            } if *stream == fresh_stream && *packet == incoming
        )));
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::LeaseParserReceive {
                stream,
                absolute_limit: 132,
                increase: 16,
                owner: None,
                ..
            } if *stream == tail_stream
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { stream, .. } if *stream == tail_stream
        )));
        assert_eq!(controller.control.credit.len(), 1);
        assert_eq!(controller.control.credit[0].stream, fresh_stream);
        assert_eq!(controller.control.credit[0].increase, 1_200);
    }

    #[test]
    fn terminal_whole_stream_preference_requires_chaff_only_and_proven_incoming_completion() {
        let build_packets = || {
            [
                incoming_packet(Duration::ZERO),
                outgoing_packet(Duration::from_millis(1)),
            ]
        };
        let static_shaped =
            StaticSchedule::with_mode(Trace::new(build_packets()), DefenseMode::ChaffAndShape);
        let static_nonterminal = StaticSchedule::with_mode(
            Trace::new([
                incoming_packet(Duration::ZERO),
                incoming_packet(Duration::from_millis(1)),
            ]),
            DefenseMode::ChaffOnly,
        );
        let (dynamic_chaff, _) = RecordingDefense::new(build_packets(), DefenseMode::ChaffOnly);
        for defense in [
            Box::new(static_shaped) as Box<dyn Defense>,
            Box::new(static_nonterminal) as Box<dyn Defense>,
            Box::new(dynamic_chaff) as Box<dyn Defense>,
        ] {
            let mut controller = terminal_chaff_shape_controller(defense, true);
            controller.poll(Duration::ZERO);
            let receive: Vec<_> = controller
                .drain_actions()
                .filter_map(|action| match action {
                    QcsdAction::IncreaseReceiveLimit {
                        stream,
                        absolute_limit,
                        ..
                    } => Some((stream, absolute_limit)),
                    _ => None,
                })
                .collect();
            assert_eq!(receive, [(QcsdStreamId(64), 1_024)]);
            assert_eq!(controller.control.claims.len(), 1);
            assert_eq!(controller.control.claims[0].remaining, 192);
        }
    }

    #[test]
    fn only_the_last_local_incoming_event_gets_terminal_whole_stream_preference() {
        let first = incoming_packet(Duration::ZERO);
        let second = incoming_packet(Duration::ZERO);
        let future_outgoing = outgoing_packet(Duration::from_millis(1));
        let defense = StaticSchedule::with_mode(
            Trace::new([first, second, future_outgoing]),
            DefenseMode::ChaffOnly,
        );
        let mut controller = terminal_chaff_shape_controller(Box::new(defense), true);

        controller.poll(Duration::ZERO);
        let receive: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } => Some((stream, absolute_limit, slot)),
                _ => None,
            })
            .collect();
        assert_eq!(receive.len(), 2);
        assert_eq!((receive[0].0, receive[0].1), (QcsdStreamId(64), 1_024));
        assert_eq!((receive[1].0, receive[1].1), (QcsdStreamId(68), 1_216));
        assert_ne!(receive[0].2, receive[1].2);
        assert_eq!(controller.control.claims.len(), 1);
        assert_eq!(controller.control.claims[0].slot, receive[0].2);
        assert_eq!(controller.control.claims[0].remaining, 192);
    }

    fn controller_with_application_length_hint(
        expected_response_length: Option<u64>,
    ) -> QcsdController {
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Image".into(),
                content_length: Some(4_000),
                data_length: 4_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 500).expect("incoming packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 16,
                low_watermark: 0,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller
    }

    #[test]
    fn application_length_hint_schedules_application_credit_before_chaff() {
        // The body estimate is exact capacity; the 1,000 framing allowance is
        // retained only as a non-advertised scheduling reservation.
        let mut controller = controller_with_application_length_hint(Some(12_445));
        assert_eq!(
            controller
                .streams
                .capacity(QcsdEndpointId(1))
                .application_incoming,
            12_429
        );
        controller.poll(Duration::ZERO);
        let stream = controller.drain_actions().find_map(|action| match action {
            QcsdAction::IncreaseReceiveLimit { stream, .. } => Some(stream),
            _ => None,
        });
        assert_eq!(stream, Some(QcsdStreamId(0)));
    }

    #[test]
    fn claim_only_application_origin_precedes_exact_chaff_on_another_origin() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 100,
                low_watermark: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://application.example");
        ready(&mut controller, 2, "https://chaff.example");
        controller.streams.open(
            QcsdEndpointId(1),
            QcsdStreamId(0),
            QcsdRequestRole::Application,
            true,
            16,
            100,
            16,
        );
        controller.streams.open(
            QcsdEndpointId(2),
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            100,
            1_000,
        );

        controller.poll(Duration::ZERO);
        assert!(controller.control.credit.is_empty());
        assert_eq!(controller.control.claims.len(), 1);
        assert_eq!(controller.control.claims[0].endpoint, QcsdEndpointId(1));
        assert_eq!(controller.control.claims[0].stream, QcsdStreamId(0));
        assert_eq!(controller.control.claims[0].remaining, 100);
        assert_eq!(
            controller
                .streams
                .capacity(QcsdEndpointId(2))
                .chaff_incoming,
            984
        );
    }

    #[test]
    fn omitted_application_length_hint_retains_zero_capacity() {
        let mut controller = controller_with_application_length_hint(None);
        assert_eq!(
            controller
                .streams
                .capacity(QcsdEndpointId(1))
                .application_incoming,
            0
        );
        controller.poll(Duration::ZERO);
        let stream = controller.drain_actions().find_map(|action| match action {
            QcsdAction::IncreaseReceiveLimit { stream, .. } => Some(stream),
            _ => None,
        });
        assert_eq!(stream, Some(QcsdStreamId(4)));
    }

    #[test]
    fn partial_drop_rolls_back_staged_credit_and_claims_atomically() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 100,
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(500),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            484
        );

        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(controller.control.credit.is_empty());
        assert!(controller.control.claims.is_empty());
        // The exact 484 bytes and the bounded 100-byte claim remain reusable;
        // staged allocation did not advance requested state or leak ownership.
        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            484
        );
        assert_eq!(
            controller
                .streams
                .allocation_opportunities(endpoint, DefenseMode::ChaffAndShape)[0]
                .claimable,
            100
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "FIN return, chaff reassignment, and exact ledger settlement are one lifecycle oracle"
    )]
    fn early_fin_returns_unused_claim_to_chaff_even_when_unsatisfied_events_drop() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1_000).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 1_000,
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(0);
        let chaff = QcsdStreamId(4);
        ready(&mut controller, 1, "https://example.com");
        controller.streams.open(
            endpoint,
            application,
            QcsdRequestRole::Application,
            true,
            1,
            1_000,
            1_000,
        );
        controller.streams.open(
            endpoint,
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            1,
            1_000,
            2_000,
        );
        acknowledge_chaff_request(
            &mut controller,
            Duration::ZERO,
            endpoint,
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        assert_eq!(
            controller
                .streams
                .get_mut(endpoint, application)
                .expect("application")
                .receive
                .claim(969),
            969
        );
        let slot = QcsdSlotId(10);
        controller.pending_slots.insert(slot, packet);
        controller.incoming_credit_ledger.insert(
            slot,
            IncomingCreditLedger {
                packet,
                endpoint: Some(endpoint),
                multiple_endpoints: false,
                advertised: 31,
                local_realization_emitted: false,
                consumed: 31,
                retired: 0,
            },
        );
        controller.scheduled_incoming_requested_bytes = 1_000;
        controller.scheduled_incoming_advertised_bytes = 31;
        controller.scheduled_incoming_consumed_bytes = 31;
        controller.control.claims.push(PendingClaim {
            slot,
            packet,
            endpoint,
            stream: application,
            remaining: 969,
        });

        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: application,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::ZERO,
        );
        assert_eq!(controller.control.incoming_backlog(), 969);
        controller.poll(Duration::ZERO);
        let (stream, absolute_limit, continued_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } => Some((stream, absolute_limit, slot)),
                _ => None,
            })
            .expect("claim remainder flows to chaff");
        assert_eq!((stream, absolute_limit, continued_slot), (chaff, 970, slot));
        assert_eq!(
            controller.control.claims.len(),
            0,
            "a returned partial slot keeps legacy exact reassignment even when fresh chaff is ACKed"
        );
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: chaff,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: chaff,
                bytes: 970,
            },
            Duration::from_micros(2),
        );
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_000);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_000);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn abort_clears_claims_actions_and_restores_stream_allowance() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            1,
            1_000,
            100,
        );
        assert_eq!(
            controller
                .streams
                .get_mut(endpoint, stream)
                .expect("stream")
                .receive
                .claim(100),
            100
        );
        let slot = QcsdSlotId(7);
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 100;
        controller.control.claims.push(PendingClaim {
            slot,
            packet,
            endpoint,
            stream,
            remaining: 100,
        });
        controller.abort_pending_slots(Duration::ZERO, MissedSlotReason::RunAborted);
        assert!(controller.control.claims.is_empty());
        assert!(controller.control.credit.is_empty());
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert_eq!(
            controller
                .streams
                .allocation_opportunities(endpoint, DefenseMode::ChaffAndShape)[0]
                .claimable,
            1_000
        );
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    fn seed_unadvertised_credit(
        controller: &mut QcsdController,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        slot: QcsdSlotId,
        packet: Packet,
        increase: u64,
    ) -> u64 {
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = controller
            .scheduled_incoming_requested_bytes
            .saturating_add(u64::from(packet.length()));
        let release = controller
            .streams
            .release_stream(endpoint, stream, increase)
            .expect("exact receive capacity");
        controller.control.credit.push(PendingCredit {
            slot,
            packet,
            endpoint,
            stream,
            absolute_limit: release.absolute_limit,
            increase: release.increase,
        });
        controller
            .actions
            .push_back(QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                packet,
                slot,
            });
        release.absolute_limit
    }

    #[test]
    fn abort_atomically_rolls_back_two_same_stream_releases() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            1_000,
            216,
        );
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        assert_eq!(
            seed_unadvertised_credit(
                &mut controller,
                endpoint,
                stream,
                QcsdSlotId(0),
                packet,
                100,
            ),
            116
        );
        assert_eq!(
            seed_unadvertised_credit(
                &mut controller,
                endpoint,
                stream,
                QcsdSlotId(1),
                packet,
                100,
            ),
            216
        );
        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            0
        );

        controller.abort_pending_slots(Duration::ZERO, MissedSlotReason::RunAborted);

        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            200
        );
        assert!(controller.control.credit.is_empty());
        assert_eq!(controller.scheduled_incoming_retired_bytes, 200);
    }

    #[test]
    fn failing_older_release_cascades_same_stream_suffix_but_not_another_stream() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let first_stream = QcsdStreamId(0);
        let independent_stream = QcsdStreamId(4);
        for stream in [first_stream, independent_stream] {
            controller.streams.open(
                endpoint,
                stream,
                QcsdRequestRole::Application,
                true,
                16,
                1_000,
                216,
            );
        }
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        seed_unadvertised_credit(
            &mut controller,
            endpoint,
            first_stream,
            QcsdSlotId(0),
            packet,
            100,
        );
        seed_unadvertised_credit(
            &mut controller,
            endpoint,
            first_stream,
            QcsdSlotId(1),
            packet,
            100,
        );
        seed_unadvertised_credit(
            &mut controller,
            endpoint,
            independent_stream,
            QcsdSlotId(2),
            packet,
            100,
        );

        controller.fail_incoming_slot(
            QcsdSlotId(0),
            MissedSlotReason::RunAborted,
            Duration::ZERO,
            false,
        );

        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            300
        );
        assert_eq!(controller.control.credit.len(), 1);
        assert_eq!(controller.control.credit[0].slot, QcsdSlotId(2));
        assert_eq!(controller.control.credit[0].absolute_limit, 116);
        assert!(
            !controller
                .incoming_credit_ledger
                .contains_key(&QcsdSlotId(0))
        );
        assert!(
            !controller
                .incoming_credit_ledger
                .contains_key(&QcsdSlotId(1))
        );
        assert!(
            controller
                .incoming_credit_ledger
                .contains_key(&QcsdSlotId(2))
        );
        let missed: BTreeSet<_> = controller
            .actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::SlotMissed { slot, .. } => Some(*slot),
                _ => None,
            })
            .collect();
        // The adapter already emitted the root miss. The dependent suffix is
        // terminalized exactly once without duplicating that root action.
        assert_eq!(missed, BTreeSet::from([QcsdSlotId(1)]));
    }

    #[test]
    fn exhausted_extent_does_not_turn_stream_data_blocked_into_speculative_credit() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            0,
            1_000,
            100,
        );
        assert_eq!(
            controller
                .streams
                .release_stream(endpoint, stream, 100)
                .expect("prepared extent")
                .absolute_limit,
            100
        );
        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            0
        );

        controller.observe(
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream,
                blocked_at: 100,
            },
            Duration::ZERO,
        );

        // STREAM_DATA_BLOCKED can race with FIN/reset, while Neqo needs at
        // least three bytes to start another DATA frame. Neither one nor three
        // bytes is proof-safe, so a mismatched prepared extent remains a
        // bounded typed/time-out failure instead of being over-advertised.
        assert_eq!(
            controller.streams.capacity(endpoint).application_incoming,
            0
        );
        assert!(controller.actions.is_empty());
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the helper reproduces one complete cross-stream scheduled-credit lifecycle"
    )]
    fn returned_residual_pre_header_controller(
        residual: u16,
    ) -> (
        QcsdController,
        QcsdEndpointId,
        QcsdStreamId,
        QcsdSlotId,
        Packet,
        u64,
    ) {
        const CELL: u16 = 1_200;
        const INITIAL: u64 = 16;
        const LARGE_FLOOR: u64 = 38_376;

        let packet = Packet::new(Duration::ZERO, Direction::Incoming, CELL).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: INITIAL,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), true)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let source = QcsdStreamId(0);
        let target = QcsdStreamId(4);
        ready(&mut controller, 1, "https://example.com");

        let source_scheduled = u64::from(CELL - residual);
        let source_limit = INITIAL + source_scheduled;
        controller.streams.open(
            endpoint,
            source,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            INITIAL,
            1_000,
            source_limit,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let (advertised_source_limit, slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint: observed_endpoint,
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } if observed_endpoint == endpoint && stream == source => {
                    Some((absolute_limit, slot))
                }
                _ => None,
            })
            .expect("source scheduled prefix");
        assert_eq!(advertised_source_limit, source_limit);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: source,
                absolute_limit: source_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: source,
                bytes: source_limit,
            },
            Duration::from_micros(2),
        );
        assert_eq!(
            controller
                .incoming_credit_ledger
                .get(&slot)
                .map(|ledger| ledger.unresolved()),
            Some(u64::from(residual))
        );

        // Closing the first stream returns only its untouched claim. The same
        // slot and packet must survive reassignment of that residual.
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: source,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(3),
        );
        controller.streams.open(
            endpoint,
            target,
            QcsdRequestRole::Chaff {
                resource_id: 8,
                request_id: None,
            },
            true,
            INITIAL,
            1_000,
            LARGE_FLOOR,
        );
        controller.drain_actions().for_each(drop);
        controller.observe(
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream: target,
                blocked_at: INITIAL,
            },
            Duration::from_micros(4),
        );
        assert!(controller.next_action().is_none());

        controller.poll(Duration::from_millis(5));
        let target_limit = INITIAL + u64::from(residual);
        let (reassigned_limit, reassigned_slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint: observed_endpoint,
                    stream,
                    absolute_limit,
                    slot,
                    ..
                } if observed_endpoint == endpoint && stream == target => {
                    Some((absolute_limit, slot))
                }
                _ => None,
            })
            .expect("reassigned scheduled residual");
        assert_eq!((reassigned_limit, reassigned_slot), (target_limit, slot));
        (controller, endpoint, target, slot, packet, target_limit)
    }

    #[test]
    fn returned_scheduled_residual_bootstraps_large_pre_header_floor() {
        const INITIAL: u64 = 16;
        const ATOMIC_HEADERS: u64 = 647;

        for residual in [310, 322, 325] {
            let (mut controller, endpoint, stream, slot, packet, target_limit) =
                returned_residual_pre_header_controller(residual);

            // The retained SDB is still inert while the reassigned scheduled
            // prefix is only requested locally.
            assert!(controller.next_action().is_none());
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit: target_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(5_001),
            );
            let QcsdAction::LeaseParserReceive {
                endpoint: lease_endpoint,
                stream: lease_stream,
                absolute_limit,
                increase,
                owner,
            } = controller.next_action().expect("large-floor bootstrap")
            else {
                panic!("expected slotless parser lease");
            };
            assert_eq!((lease_endpoint, lease_stream), (endpoint, stream));
            assert_eq!((absolute_limit, increase), (1_000, 1_000 - target_limit));
            assert_eq!(owner, None);

            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
            assert_eq!(
                diagnostics.scheduled_incoming_consumed_bytes,
                1_200 - u64::from(residual)
            );
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(
                diagnostics.scheduled_incoming_unresolved_bytes,
                u64::from(residual)
            );
            assert_eq!(controller.pending_slots(), [(slot, packet)]);

            // Advertising the ownerless parser suffix cannot satisfy or
            // reclassify any scheduled byte.
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: None,
                },
                Duration::from_micros(5_002),
            );
            assert!(controller.next_action().is_none());
            assert_eq!(
                controller
                    .defense_diagnostics()
                    .scheduled_incoming_unresolved_bytes,
                u64::from(residual)
            );
            assert_eq!(controller.pending_slots(), [(slot, packet)]);

            // A realistic atomic HEADERS extent crosses both domains. Only
            // overlap with [16,target_limit) settles the returned slot; the
            // ownerless [target_limit,1000) suffix remains parser overflow.
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: INITIAL,
                },
                Duration::from_micros(5_003),
            );
            assert!(controller.next_action().is_none());
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: ATOMIC_HEADERS - INITIAL,
                },
                Duration::from_micros(5_004),
            );
            assert!(matches!(
                controller.next_action(),
                Some(QcsdAction::SlotSatisfied {
                    slot: satisfied,
                    ..
                }) if satisfied == slot
            ));
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_200);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
            assert!(controller.pending_slots().is_empty());
        }
    }

    #[test]
    fn large_floor_bootstrap_requires_live_contiguous_scheduled_prefix() {
        const INITIAL: u64 = 16;
        const REQUESTED: u64 = 326;
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 310).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: INITIAL,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            INITIAL,
            1_000,
            38_376,
        );
        assert!(
            controller
                .streams
                .record_pre_header_blocked(endpoint, stream, INITIAL)
        );
        assert_eq!(
            controller
                .streams
                .release_stream(endpoint, stream, REQUESTED - INITIAL)
                .map(|release| release.absolute_limit),
            Some(REQUESTED)
        );
        controller
            .streams
            .get_mut(endpoint, stream)
            .expect("stream")
            .receive
            .advertised(REQUESTED);

        controller.try_pre_header_bootstrap(endpoint, stream);
        assert!(
            controller.actions.is_empty(),
            "absolute credit is not proof"
        );

        let slot = QcsdSlotId(0);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.advertised_incoming_credit.insert(
            (endpoint, stream),
            vec![AdvertisedIncomingCredit {
                slot,
                start: INITIAL + 1,
                end: REQUESTED,
            }],
        );
        controller.try_pre_header_bootstrap(endpoint, stream);
        assert!(controller.actions.is_empty(), "a prefix gap fails closed");

        controller.advertised_incoming_credit.insert(
            (endpoint, stream),
            vec![AdvertisedIncomingCredit {
                slot,
                start: INITIAL,
                end: REQUESTED,
            }],
        );
        controller.incoming_credit_ledger.remove(&slot);
        controller.try_pre_header_bootstrap(endpoint, stream);
        assert!(controller.actions.is_empty(), "stale ownership is not live");

        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.try_pre_header_bootstrap(endpoint, stream);
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::LeaseParserReceive {
                absolute_limit: 1_000,
                increase: 674,
                owner: None,
                ..
            })
        ));
    }

    #[test]
    fn returned_residual_bootstrap_rolls_back_and_retires_once_on_close() {
        let (mut controller, endpoint, stream, slot, _, target_limit) =
            returned_residual_pre_header_controller(310);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: target_limit,
                slot: Some(slot),
            },
            Duration::from_micros(5_001),
        );
        assert!(matches!(
            controller.actions.front(),
            Some(QcsdAction::LeaseParserReceive {
                absolute_limit: 1_000,
                increase: 674,
                owner: None,
                ..
            })
        ));

        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream,
                finish: QcsdStreamFinish::Reset,
            },
            Duration::from_micros(5_002),
        );
        assert!(controller.parser_lease_ranges.is_empty());
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::LeaseParserReceive { .. }))
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::SlotMissed {
                        slot: observed,
                        reason: MissedSlotReason::ReceiveCreditRetired,
                        ..
                    } if *observed == slot
                ))
                .count(),
            1
        );
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 890);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 310);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        assert!(controller.pending_slots().is_empty());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "both stream roles and the complete atomic-HEADERS accounting path form one oracle"
    )]
    fn pre_header_bootstrap_handles_atomic_headers_for_application_and_chaff() {
        const FLOOR: u64 = 250;
        const INITIAL: u64 = 16;
        const SCHEDULED: u16 = 234;
        for (stream, role) in [
            (QcsdStreamId(0), QcsdRequestRole::Application),
            (
                QcsdStreamId(4),
                QcsdRequestRole::Chaff {
                    resource_id: 7,
                    request_id: None,
                },
            ),
        ] {
            let packet =
                Packet::new(Duration::ZERO, Direction::Incoming, SCHEDULED).expect("packet");
            let manifest = ResourceManifest {
                resources: vec![Resource {
                    id: 7,
                    url: "https://example.com/chaff".into(),
                    kind: "Image".into(),
                    content_length: Some(FLOOR),
                    data_length: FLOOR,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                }],
            };
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: INITIAL,
                    max_stream_data_excess: 1_000,
                    low_watermark: 1,
                    ..QcsdConfig::default()
                },
                Some(manifest),
                Box::new(StaticSchedule::new(Trace::new([packet]), false)),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(1);
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role,
                    expected_response_length: matches!(role, QcsdRequestRole::Application)
                        .then_some(FLOOR),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);

            // Serde's early proof is retained while the exact floor is still
            // only known locally. It cannot grow credit on its own.
            controller.observe(
                QcsdObservation::StreamDataBlocked {
                    endpoint,
                    stream,
                    blocked_at: INITIAL,
                },
                Duration::ZERO,
            );
            assert!(controller.next_action().is_none());

            controller.poll(Duration::ZERO);
            let actions: Vec<_> = controller.drain_actions().collect();
            let (floor_limit, slot) = actions
                .iter()
                .find_map(|action| match action {
                    QcsdAction::IncreaseReceiveLimit {
                        endpoint: observed_endpoint,
                        stream: observed_stream,
                        absolute_limit,
                        slot,
                        ..
                    } if (*observed_endpoint, *observed_stream) == (endpoint, stream) => {
                        Some((*absolute_limit, *slot))
                    }
                    _ => None,
                })
                .expect("prepared floor action");
            assert_eq!(floor_limit, FLOOR);
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, QcsdAction::LeaseParserReceive { .. }))
            );

            // Encoding the exact floor activates the retained proof. The
            // lease ends at absolute 1000, carries no owner, and does not
            // resolve the scheduled range on grant.
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit: floor_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(1),
            );
            let QcsdAction::LeaseParserReceive {
                absolute_limit: lease_limit,
                increase,
                owner,
                ..
            } = controller.next_action().expect("pre-header bootstrap")
            else {
                panic!("expected slotless parser lease");
            };
            assert_eq!((lease_limit, increase, owner), (1_000, 750, None));
            assert_eq!(controller.pending_slots(), [(slot, packet)]);
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(
                diagnostics.scheduled_incoming_requested_bytes,
                u64::from(SCHEDULED)
            );
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(
                diagnostics.scheduled_incoming_unresolved_bytes,
                u64::from(SCHEDULED)
            );

            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit: lease_limit,
                    slot: None,
                },
                Duration::from_micros(2),
            );
            assert!(controller.next_action().is_none());
            assert_eq!(controller.pending_slots(), [(slot, packet)]);

            // Duplicate and stale blocked reports cannot issue a second
            // bootstrap or turn generic SDB into speculative capacity.
            for blocked_at in [FLOOR, lease_limit] {
                controller.observe(
                    QcsdObservation::StreamDataBlocked {
                        endpoint,
                        stream,
                        blocked_at,
                    },
                    Duration::from_micros(3),
                );
            }
            assert!(controller.next_action().is_none());

            // One atomic HEADERS frame can now exceed the 250-byte body floor.
            // Only the already scheduled [16,250) range resolves the slot;
            // the parser tail remains raw, unowned overflow.
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 400,
                },
                Duration::from_micros(4),
            );
            assert!(matches!(
                controller.next_action(),
                Some(QcsdAction::SlotSatisfied { slot: satisfied, .. }) if satisfied == slot
            ));
            controller.observe(
                QcsdObservation::ResponseHeaders {
                    endpoint,
                    stream,
                    frame_bytes: 400,
                    status: Some(200),
                    content_length: Some(FLOOR),
                },
                Duration::from_micros(4),
            );
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(
                diagnostics.scheduled_incoming_requested_bytes,
                u64::from(SCHEDULED)
            );
            assert_eq!(
                diagnostics.scheduled_incoming_consumed_bytes,
                u64::from(SCHEDULED)
            );
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
            assert!(controller.pending_slots().is_empty());

            controller.observe(
                QcsdObservation::StreamFinished {
                    endpoint,
                    stream,
                    finish: QcsdStreamFinish::Fin,
                },
                Duration::from_micros(5),
            );
            assert!(controller.parser_lease_ranges.is_empty());
        }
    }

    #[test]
    fn pre_header_bootstrap_rolls_back_on_fin_and_reset_with_closed_ledger() {
        for finish in [QcsdStreamFinish::Fin, QcsdStreamFinish::Reset] {
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 234).expect("packet");
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
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(0);
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(250),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller.observe(
                QcsdObservation::StreamDataBlocked {
                    endpoint,
                    stream,
                    blocked_at: 16,
                },
                Duration::ZERO,
            );
            controller.poll(Duration::ZERO);
            let (absolute_limit, slot) = controller
                .drain_actions()
                .find_map(|action| match action {
                    QcsdAction::IncreaseReceiveLimit {
                        absolute_limit,
                        slot,
                        ..
                    } => Some((absolute_limit, slot)),
                    _ => None,
                })
                .expect("floor action");
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_micros(1),
            );
            assert!(matches!(
                controller.actions.front(),
                Some(QcsdAction::LeaseParserReceive {
                    absolute_limit: 1_000,
                    increase: 750,
                    owner: None,
                    ..
                })
            ));

            // Closing before the lease reaches the adapter removes and rolls
            // back its suffix. The already-advertised scheduled floor retires
            // normally and closes the one ledger exactly once.
            controller.observe(
                QcsdObservation::StreamFinished {
                    endpoint,
                    stream,
                    finish,
                },
                Duration::from_micros(2),
            );
            assert!(controller.parser_lease_ranges.is_empty());
            let actions: Vec<_> = controller.drain_actions().collect();
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, QcsdAction::LeaseParserReceive { .. }))
            );
            assert_eq!(
                actions
                    .iter()
                    .filter(|action| matches!(
                        action,
                        QcsdAction::SlotMissed {
                            slot: observed,
                            reason: MissedSlotReason::ReceiveCreditRetired,
                            ..
                        } if *observed == slot
                    ))
                    .count(),
                1
            );
            assert!(controller.pending_slots().is_empty());
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 234);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 234);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        }
    }

    #[test]
    fn aborted_exhausting_pre_header_bootstrap_rejects_duplicate_blocked_proof() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 234).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 750,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::new([packet]), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(250),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.observe(
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream,
                blocked_at: 16,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let (floor_limit, slot) = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    absolute_limit,
                    slot,
                    ..
                } => Some((absolute_limit, slot)),
                _ => None,
            })
            .expect("prepared floor action");
        assert_eq!(floor_limit, 250);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: floor_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        assert!(matches!(
            controller.actions.front(),
            Some(QcsdAction::LeaseParserReceive {
                absolute_limit: 1_000,
                increase: 750,
                owner: None,
                ..
            })
        ));

        controller.abort_pending_slots(Duration::from_micros(2), MissedSlotReason::RunAborted);
        controller.drain_actions().for_each(drop);
        assert!(controller.parser_lease_ranges.is_empty());
        controller.observe(
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream,
                blocked_at: floor_limit,
            },
            Duration::from_micros(3),
        );
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::LeaseParserReceive { .. })),
            "sticky exhaustion prevents a second unowned bootstrap after abort rollback"
        );
    }

    #[test]
    fn tamaraw_controls_application_and_emits_both_directions() {
        let mut controller = tamaraw_controller();
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureManualReceive {
                initial_limit: 16,
                ..
            })
        ));
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                frame_bytes: 10,
                status: Some(200),
                content_length: Some(5_000),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
    }

    #[test]
    fn front_leaves_application_receive_automatic() {
        let mut controller = QcsdController::new(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Front(FrontConfig {
                    packet_size: 1_200,
                    ..FrontConfig::default()
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureAutomaticReceive { .. })
        ));
    }

    #[test]
    fn independent_direction_cursors_start_at_the_first_endpoint() {
        let mut controller = tamaraw_controller();
        ready(&mut controller, 1, "https://one.example");
        ready(&mut controller, 2, "https://two.example");
        for (endpoint, stream) in [(1, 0), (2, 4)] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint: QcsdEndpointId(endpoint),
                    stream: QcsdStreamId(stream),
                    role: QcsdRequestRole::Application,
                    expected_response_length: None,
                },
                Duration::ZERO,
            );
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket {
                endpoint: QcsdEndpointId(1),
                ..
            }
        )));
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit {
                endpoint: QcsdEndpointId(1),
                ..
            }
        )));
    }

    type CandidateEndpoint = (QcsdEndpointId, QcsdStreamId, &'static str);

    #[derive(Default)]
    struct CandidateExerciseState {
        scheduled_slots: BTreeSet<QcsdSlotId>,
        outgoing_endpoints: Vec<QcsdEndpointId>,
        incoming_streams: Vec<(QcsdEndpointId, QcsdStreamId)>,
    }

    #[derive(Default)]
    struct CandidateTick {
        terminal_observations: Vec<QcsdObservation>,
        incoming_slots: Vec<(QcsdSlotId, QcsdEndpointId, Packet)>,
    }

    fn candidate_endpoints() -> [CandidateEndpoint; 2] {
        [
            (QcsdEndpointId(1), QcsdStreamId(0), "https://one.example"),
            (QcsdEndpointId(2), QcsdStreamId(4), "https://two.example"),
        ]
    }

    fn prepare_candidate_across_two_endpoints(
        defense: Box<dyn Defense>,
        packet_size: u16,
    ) -> (QcsdController, [CandidateEndpoint; 2]) {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            defense,
        )
        .expect("candidate controller");
        let endpoints = candidate_endpoints();
        for (endpoint, stream, origin) in endpoints {
            ready(&mut controller, endpoint.0, origin);
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(10_000),
                },
                Duration::ZERO,
            );
        }
        let configured: Vec<_> = controller
            .drain_actions()
            .map(|action| match action {
                QcsdAction::ConfigureManualReceive {
                    endpoint, stream, ..
                } => (endpoint, stream),
                _ => panic!("unexpected endpoint setup action: {action:?}"),
            })
            .collect();
        assert_eq!(
            configured,
            [
                (QcsdEndpointId(1), QcsdStreamId(0)),
                (QcsdEndpointId(2), QcsdStreamId(4)),
            ]
        );
        for (endpoint, _, origin) in endpoints {
            assert_eq!(
                controller
                    .endpoint_origins
                    .get(&endpoint)
                    .map(String::as_str),
                Some(origin)
            );
            assert!(
                controller.streams.capacity(endpoint).application_incoming
                    >= u64::from(packet_size) * 2
            );
        }
        (controller, endpoints)
    }

    fn successful_candidate_send(
        send_policy: QcsdSendPolicy,
        endpoint: QcsdEndpointId,
        slot: QcsdSlotId,
        packet: Packet,
    ) -> QcsdObservation {
        match send_policy {
            QcsdSendPolicy::Exact => QcsdObservation::SlotSatisfied {
                endpoint,
                slot,
                observed_size: packet.length(),
            },
            QcsdSendPolicy::CongestionSensitive => QcsdObservation::SlotResolved {
                endpoint,
                slot,
                packet,
                outcome: QcsdSlotOutcome::Full {
                    composition: QcsdSlotComposition {
                        desired_udp_bytes: packet.length(),
                        observed_udp_bytes: packet.length(),
                        defense_control_bytes: 1,
                        quic_padding_bytes: packet.length() - 1,
                        ..QcsdSlotComposition::default()
                    },
                },
            },
        }
    }

    fn record_candidate_action(
        controller: &QcsdController,
        endpoints: &[CandidateEndpoint],
        expected_packet_size: u16,
        expected_send_policy: QcsdSendPolicy,
        state: &mut CandidateExerciseState,
        tick: &mut CandidateTick,
        action: &QcsdAction,
    ) {
        match action {
            QcsdAction::SendPacket {
                endpoint,
                packet,
                slot,
                allow_stream_data,
                send_policy,
                ..
            } => {
                assert!(endpoints.iter().any(|candidate| candidate.0 == *endpoint));
                assert_eq!(packet.direction(), Direction::Outgoing);
                assert_eq!(packet.length(), expected_packet_size);
                assert!(*allow_stream_data);
                assert_eq!(*send_policy, expected_send_policy);
                assert!(
                    state.scheduled_slots.insert(*slot),
                    "slot identity was reused"
                );
                state.outgoing_endpoints.push(*endpoint);
                tick.terminal_observations.push(successful_candidate_send(
                    *send_policy,
                    *endpoint,
                    *slot,
                    *packet,
                ));
            }
            QcsdAction::CommitPrearmedPacket {
                endpoint,
                packet,
                slot,
            } => {
                assert_eq!(expected_send_policy, QcsdSendPolicy::Exact);
                assert!(endpoints.iter().any(|candidate| candidate.0 == *endpoint));
                assert_eq!(packet.direction(), Direction::Outgoing);
                assert_eq!(packet.length(), expected_packet_size);
                assert!(
                    state.scheduled_slots.insert(*slot),
                    "slot identity was reused"
                );
                state.outgoing_endpoints.push(*endpoint);
                tick.terminal_observations.push(successful_candidate_send(
                    QcsdSendPolicy::Exact,
                    *endpoint,
                    *slot,
                    *packet,
                ));
            }
            QcsdAction::PrearmPacket { .. } => {}
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit,
                packet,
                slot,
            } => {
                assert!(
                    endpoints
                        .iter()
                        .any(|candidate| candidate.0 == *endpoint && candidate.1 == *stream)
                );
                assert_eq!(packet.direction(), Direction::Incoming);
                assert_eq!(packet.length(), expected_packet_size);
                assert!(
                    state.scheduled_slots.insert(*slot),
                    "slot identity was reused"
                );
                state.incoming_streams.push((*endpoint, *stream));
                tick.incoming_slots.push((*slot, *endpoint, *packet));
                tick.terminal_observations
                    .push(QcsdObservation::ReceiveLimitAdvertised {
                        endpoint: *endpoint,
                        stream: *stream,
                        absolute_limit: *absolute_limit,
                        slot: Some(*slot),
                    });
                let consumed = controller
                    .streams
                    .consumed(*endpoint, *stream)
                    .expect("registered application stream");
                let bytes = absolute_limit.saturating_sub(consumed);
                assert!(bytes >= u64::from(packet.length()));
                tick.terminal_observations.push(QcsdObservation::BytesRead {
                    endpoint: *endpoint,
                    stream: *stream,
                    bytes,
                });
            }
            QcsdAction::SlotMissed { reason, .. } => {
                panic!("candidate opportunity was missed: {reason:?}");
            }
            _ => panic!("unexpected candidate action: {action:?}"),
        }
    }

    fn settle_candidate_tick(controller: &mut QcsdController, at: Duration, tick: CandidateTick) {
        for observation in tick.terminal_observations {
            controller.observe(observation, at);
        }
        controller.drain_observations();
        let terminal_actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(terminal_actions.len(), tick.incoming_slots.len());
        for action in terminal_actions {
            let QcsdAction::SlotSatisfied {
                endpoint: Some(endpoint),
                packet,
                slot,
            } = action
            else {
                panic!("unexpected incoming terminal action: {action:?}");
            };
            assert_eq!(packet.direction(), Direction::Incoming);
            assert!(tick.incoming_slots.iter().any(|candidate| {
                candidate.0 == slot && candidate.1 == endpoint && candidate.2 == packet
            }));
        }
    }

    fn assert_candidate_settled(
        controller: &QcsdController,
        packet_size: u16,
        state: &CandidateExerciseState,
    ) {
        assert_eq!(
            state.outgoing_endpoints.get(..2),
            Some(&[QcsdEndpointId(1), QcsdEndpointId(2)][..])
        );
        assert_eq!(
            state.incoming_streams.get(..2),
            Some(
                &[
                    (QcsdEndpointId(1), QcsdStreamId(0)),
                    (QcsdEndpointId(2), QcsdStreamId(4)),
                ][..]
            )
        );
        assert_eq!(
            state.scheduled_slots.len(),
            state.outgoing_endpoints.len() + state.incoming_streams.len()
        );
        assert!(controller.pending_slots().is_empty());
        assert!(controller.control.outgoing.is_empty());
        assert!(controller.control.incoming.is_empty());
        assert!(controller.control.credit.is_empty());
        assert!(controller.control.claims.is_empty());
        assert!(controller.incoming_credit_ledger.is_empty());
        assert_eq!(controller.terminal_failure(), None);
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(
            diagnostics.scheduled_incoming_requested_bytes,
            u64::try_from(state.incoming_streams.len()).expect("incoming count")
                * u64::from(packet_size)
        );
        assert_eq!(
            diagnostics.scheduled_incoming_advertised_bytes,
            diagnostics.scheduled_incoming_requested_bytes
        );
        assert_eq!(
            diagnostics.scheduled_incoming_consumed_bytes,
            diagnostics.scheduled_incoming_requested_bytes
        );
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    fn exercise_candidate_across_two_endpoints(
        defense: Box<dyn Defense>,
        packet_size: u16,
        expected_send_policy: QcsdSendPolicy,
    ) -> (
        QcsdController,
        Vec<QcsdEndpointId>,
        Vec<(QcsdEndpointId, QcsdStreamId)>,
    ) {
        let (mut controller, endpoints) =
            prepare_candidate_across_two_endpoints(defense, packet_size);
        let mut at = Duration::ZERO;
        let mut state = CandidateExerciseState::default();
        for _ in 0..64 {
            let deadline = controller
                .next_deadline()
                .expect("candidate retains a next opportunity");
            at = at.max(deadline);
            controller.poll(at);
            let mut tick = CandidateTick::default();
            let actions: Vec<_> = controller.drain_actions().collect();
            for action in &actions {
                record_candidate_action(
                    &controller,
                    &endpoints,
                    packet_size,
                    expected_send_policy,
                    &mut state,
                    &mut tick,
                    action,
                );
            }
            settle_candidate_tick(&mut controller, at, tick);
            if state.outgoing_endpoints.len() >= 2 && state.incoming_streams.len() >= 2 {
                break;
            }
        }
        assert_candidate_settled(&controller, packet_size, &state);
        (controller, state.outgoing_endpoints, state.incoming_streams)
    }

    #[test]
    fn buflo_settles_exact_cells_across_two_endpoint_origins() {
        let defense = Buflo::from_parameters(BufloParameters {
            schema_version: 1,
            interval_us: 5_000,
            minimum_duration_us: 20_000,
            packet_size: 1_200,
            max_events: 100,
            implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
            paper_equivalent: false,
        });
        let (controller, outgoing, incoming) = exercise_candidate_across_two_endpoints(
            Box::new(defense),
            1_200,
            QcsdSendPolicy::Exact,
        );
        let diagnostics = controller.defense_diagnostics();
        assert!(diagnostics.buflo_client_only);
        assert!(!diagnostics.buflo_paper_equivalent);
        assert_eq!(
            diagnostics.buflo_scheduled_outgoing_cells,
            outgoing.len() as u64
        );
        assert_eq!(
            diagnostics.buflo_scheduled_incoming_cells,
            incoming.len() as u64
        );
        assert_eq!(diagnostics.buflo_full_outgoing_cells, outgoing.len() as u64);
        assert_eq!(diagnostics.buflo_partial_outgoing_cells, 0);
        assert_eq!(diagnostics.buflo_suppressed_outgoing_cells, 0);
        assert_eq!(diagnostics.buflo_missed_outgoing_cells, 0);
        assert_eq!(diagnostics.buflo_missed_incoming_cells, 0);
        assert_eq!(diagnostics.buflo_catch_up_outgoing_cells, 0);
        assert_eq!(diagnostics.buflo_catch_up_incoming_cells, 0);
        assert_eq!(diagnostics.buflo_outgoing_unresolved_cells, 0);
        assert_eq!(diagnostics.buflo_incoming_unresolved_cells, 0);
    }

    #[test]
    fn cs_buflo_settles_one_shot_opportunities_across_two_endpoint_origins() {
        let defense = CsBuflo::from_parameters(
            CsBufloParameters {
                schema_version: 1,
                packet_size: 600,
                initial_interval_us: 8_192,
                minimum_interval_us: 4_096,
                maximum_interval_us: 32_768,
                initial_adaptation_boundary_bytes: 16_384,
                quiet_time_us: 2_000_000,
                outgoing_padding_mode: CsBufloPaddingMode::Total,
                incoming_padding_mode: CsBufloPaddingMode::Payload,
                timing_sample_limit: 1_000,
                jitter_denominator: 100,
                jitter_max_numerator: 200,
                early_termination: CsBufloEarlyTermination::Local,
                max_events: 1_000,
                implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
                paper_equivalent: false,
            },
            42,
        );
        let (controller, outgoing, incoming) = exercise_candidate_across_two_endpoints(
            Box::new(defense),
            600,
            QcsdSendPolicy::CongestionSensitive,
        );
        let diagnostics = controller.defense_diagnostics();
        assert!(diagnostics.cs_buflo_client_only);
        assert!(!diagnostics.cs_buflo_paper_equivalent);
        assert_eq!(
            diagnostics.cs_buflo_scheduled_outgoing_cells,
            outgoing.len() as u64
        );
        assert_eq!(
            diagnostics.cs_buflo_scheduled_incoming_cells,
            incoming.len() as u64
        );
        assert_eq!(
            diagnostics.cs_buflo_full_outgoing_cells,
            outgoing.len() as u64
        );
        assert_eq!(diagnostics.cs_buflo_partial_outgoing_cells, 0);
        assert_eq!(diagnostics.cs_buflo_suppressed_outgoing_cells, 0);
        assert_eq!(diagnostics.cs_buflo_missed_outgoing_cells, 0);
        assert_eq!(diagnostics.cs_buflo_missed_incoming_cells, 0);
        assert_eq!(
            diagnostics.cs_buflo_desired_udp_bytes,
            outgoing.len() as u64 * 600
        );
        assert_eq!(
            diagnostics.cs_buflo_realized_udp_bytes,
            diagnostics.cs_buflo_desired_udp_bytes
        );
        assert_eq!(diagnostics.cs_buflo_application_stream_bytes, 0);
        assert_eq!(diagnostics.cs_buflo_retransmission_stream_bytes, 0);
        assert_eq!(diagnostics.cs_buflo_chaff_stream_bytes, 0);
        assert_eq!(
            diagnostics.cs_buflo_defense_control_bytes,
            outgoing.len() as u64
        );
        assert_eq!(
            diagnostics.cs_buflo_quic_padding_bytes,
            outgoing.len() as u64 * 599
        );
        assert_eq!(diagnostics.cs_buflo_other_quic_bytes, 0);
        assert_eq!(diagnostics.cs_buflo_lateness_us_total, 0);
        assert_eq!(diagnostics.cs_buflo_lateness_us_max, 0);
        assert_eq!(
            diagnostics.cs_buflo_incoming_local_realized_cells,
            incoming.len() as u64
        );
        assert_eq!(diagnostics.cs_buflo_outgoing_unresolved_cells, 0);
        assert_eq!(diagnostics.cs_buflo_incoming_unresolved_cells, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "cross-origin continuation and ledger settlement form one lifecycle oracle"
    )]
    fn same_stream_bounded_claim_precedes_cross_origin_fanout() {
        let mut controller = QcsdController::new(
            QcsdConfig {
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                defense: DefenseConfig::Tamaraw(TamarawConfig {
                    incoming_interval_us: 5_000,
                    outgoing_interval_us: 20_000,
                    packet_size: 1_200,
                    modulo: 4,
                }),
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller");
        ready(&mut controller, 1, "https://one.example");
        ready(&mut controller, 2, "https://two.example");
        // The first endpoint reproduces the Chromium config.json case:
        // 1,143 known bytes minus the 16-byte initial limit leaves only
        // 1,127 bytes for a 1,200-byte Tamaraw slot. The second endpoint has
        // enough exact capacity for the remaining 73 bytes. The first stream's
        // bounded framing claim must retain that work instead of spilling it to
        // the second origin.
        for (endpoint, stream, expected_response_length) in [(1, 0, 1_143), (2, 4, 5_000)] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint: QcsdEndpointId(endpoint),
                    stream: QcsdStreamId(stream),
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(expected_response_length),
                },
                Duration::ZERO,
            );
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
        let credits: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit,
                    packet,
                    slot,
                } => Some((*endpoint, *stream, *absolute_limit, *packet, *slot)),
                _ => None,
            })
            .collect();
        assert_eq!(credits.len(), 1);
        assert_eq!(
            credits
                .iter()
                .map(|(endpoint, _, absolute_limit, _, _)| (*endpoint, *absolute_limit))
                .collect::<Vec<_>>(),
            [(QcsdEndpointId(1), 1_143)]
        );
        let (endpoint, stream, absolute_limit, _, slot) = credits[0];
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
                bytes: absolute_limit,
            },
            Duration::from_micros(2),
        );
        assert!(controller.next_action().is_none());
        controller.observe(
            QcsdObservation::PushPromiseFrame {
                endpoint,
                stream,
                frame_bytes: 73,
            },
            Duration::from_micros(3),
        );
        let Some(QcsdAction::IncreaseReceiveLimit {
            endpoint: continued_endpoint,
            stream: continued_stream,
            absolute_limit: continued_limit,
            slot: continued_slot,
            ..
        }) = controller.next_action()
        else {
            panic!("exact framing must continue its owning slot");
        };
        assert_eq!((continued_endpoint, continued_stream), (endpoint, stream));
        assert_eq!(continued_limit, 1_216);
        assert_eq!(continued_slot, slot);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: continued_limit,
                slot: Some(slot),
            },
            Duration::from_micros(4),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 73,
            },
            Duration::from_micros(5),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied { slot: satisfied, .. }) if satisfied == slot
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn chaff_repeats_a_large_same_origin_resource() {
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 1,
                url: "https://one.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(250),
                data_length: 250,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::new(
            QcsdConfig {
                max_chaff_streams: 4,
                low_watermark: 1_000,
                max_udp_payload_size: 1_200,
                defense: DefenseConfig::Front(FrontConfig {
                    packet_size: 1_200,
                    ..FrontConfig::default()
                }),
                ..QcsdConfig::default()
            },
            42,
            Some(manifest),
        )
        .expect("valid controller");
        ready(&mut controller, 1, "https://one.example");
        controller.poll(Duration::ZERO);
        let request_count = controller
            .drain_actions()
            .filter(|action| matches!(action, QcsdAction::RequestChaff { .. }))
            .count();
        assert_eq!(request_count, 4);
    }

    #[test]
    fn exhausted_chaff_misses_incoming_slots_explicitly() {
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 1,
                url: "https://one.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_200),
                data_length: 1_200,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Incoming, 1_200).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                max_chaff_streams: 1,
                low_watermark: 1_200,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(StaticSchedule::new(trace, true)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://one.example");
        controller.poll(Duration::ZERO);
        let request_id = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::RequestChaff { request_id, .. } => Some(request_id),
                _ => None,
            })
            .expect("initial chaff request");
        controller.observe(
            QcsdObservation::ChaffRequestFailed {
                resource_id: 1,
                request_id: Some(request_id),
            },
            Duration::ZERO,
        );
        controller.poll(Duration::from_millis(5));
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
    }

    #[test]
    fn chaff_redirect_is_failed_and_never_promoted() {
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 1,
                url: "https://one.example/chaff".into(),
                kind: "Image".into(),
                content_length: Some(1_200),
                data_length: 1_200,
                chaff_priority: false,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Incoming, 1_200).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                max_chaff_streams: 1,
                low_watermark: 1_200,
                max_udp_payload_size: 1_200,
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(StaticSchedule::new(trace, true)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://one.example");
        controller.poll(Duration::ZERO);
        let request_id = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::RequestChaff { request_id, .. } => Some(request_id),
                _ => None,
            })
            .expect("initial chaff request");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Chaff {
                    resource_id: 1,
                    request_id: Some(request_id),
                },
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::ResponseHeaders {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                frame_bytes: 40,
                status: Some(302),
                content_length: Some(1_200),
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::from_millis(5));
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::RequestChaff { .. }))
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
    }

    #[test]
    fn application_id_collision_cannot_mutate_the_distinct_chaff_namespace() {
        for application_success in [false, true] {
            let manifest = ResourceManifest {
                resources: vec![Resource {
                    id: 0,
                    url: "https://one.example/".into(),
                    kind: "Document".into(),
                    content_length: Some(1_200),
                    data_length: 1_200,
                    chaff_priority: true,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                }],
            };
            let trace =
                Trace::new([
                    Packet::new(Duration::from_millis(1), Direction::Incoming, 1_200)
                        .expect("packet"),
                ]);
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    max_chaff_streams: 1,
                    low_watermark: 1_200,
                    max_udp_payload_size: 1_200,
                    ..QcsdConfig::default()
                },
                Some(manifest),
                Box::new(StaticSchedule::new(trace, true)),
            )
            .expect("controller");
            ready(&mut controller, 1, "https://one.example");
            controller.observe(
                QcsdObservation::ResourceCompleted {
                    resource_id: 0,
                    success: application_success,
                },
                Duration::ZERO,
            );
            controller.poll(Duration::ZERO);
            assert!(controller.drain_actions().any(|action| matches!(
                action,
                QcsdAction::RequestChaff {
                    resource: Resource { id: 0, .. },
                    ..
                }
            )));
        }
    }

    #[test]
    fn interim_final_and_trailer_headers_preserve_the_final_status() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(10),
            },
            Duration::ZERO,
        );
        for (frame_bytes, status) in [(7, Some(103)), (11, Some(200)), (5, None)] {
            controller.observe(
                QcsdObservation::ResponseHeaders {
                    endpoint,
                    stream,
                    frame_bytes,
                    status,
                    content_length: Some(10).filter(|_| status == Some(200)),
                },
                Duration::ZERO,
            );
        }
        assert_eq!(
            controller
                .streams
                .get_mut(endpoint, stream)
                .expect("open stream")
                .status,
            Some(200)
        );
    }

    #[test]
    fn completion_waits_for_tail() {
        let mut controller = QcsdController::new(
            QcsdConfig {
                tail_wait_us: 100,
                ..QcsdConfig::default()
            },
            42,
            None,
        )
        .expect("valid controller");
        controller.poll(Duration::ZERO);
        assert_eq!(controller.next_deadline(), Some(Duration::from_micros(100)));
        controller.poll(Duration::from_micros(100));
        assert!(controller.is_complete());
    }

    #[test]
    fn incoming_events_are_aggregated_at_control_interval_boundaries() {
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Incoming, 100).expect("packet"),
            Packet::new(Duration::from_millis(2), Direction::Incoming, 100).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::from_millis(2));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );

        controller.poll(Duration::from_millis(5));
        let released: u64 = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { packet, .. } => Some(u64::from(packet.length())),
                _ => None,
            })
            .sum();
        assert_eq!(released, 200);
    }

    #[test]
    fn incoming_slot_is_satisfied_only_after_advertised_credit_is_consumed() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let trace = Trace::new([packet]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let action = controller.next_action().expect("credit action");
        let QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit,
            slot,
            ..
        } = action
        else {
            panic!("expected attributed receive credit");
        };
        assert!(controller.next_action().is_none());

        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::ZERO,
        );
        assert!(controller.next_action().is_none());
        assert_eq!(controller.pending_slots(), [(slot, packet)]);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_unresolved_bytes,
            100
        );
        controller.poll(Duration::ZERO);
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::DefenseComplete))
        );

        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: absolute_limit,
            },
            Duration::from_micros(1),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: observed_slot,
                ..
            }) if observed_slot == slot
        ));
        controller.poll(Duration::from_micros(1));
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::DefenseComplete)
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn split_incoming_fanout_realizes_once_then_terminalizes_after_consumption() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).expect("packet");
        let slot = QcsdSlotId(600);
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let (mut defense, calls) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
        defense.split_incoming_credit_lifecycle = true;
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 600;
        controller.control.credit.extend([
            PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: 300,
                increase: 300,
            },
            PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: 600,
                increase: 300,
            },
        ]);

        controller.credit_advertised(endpoint, stream, 300, Some(slot), Duration::from_micros(1));
        controller.drain_observations();
        assert!(!calls.borrow().iter().any(|call| matches!(
            call,
            RecordedCall::Signal(DefenseSignal {
                kind: SignalKind::IncomingCreditAdvertised { .. },
                ..
            })
        )));
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            300
        );

        controller.credit_advertised(endpoint, stream, 600, Some(slot), Duration::from_micros(2));
        controller.drain_observations();
        let realized_count = || {
            calls
                .borrow()
                .iter()
                .filter(|call| {
                    matches!(
                        call,
                        RecordedCall::Signal(DefenseSignal {
                            kind: SignalKind::IncomingCreditAdvertised {
                                slot: observed,
                                packet: observed_packet,
                            },
                            ..
                        }) if *observed == slot && *observed_packet == packet
                    )
                })
                .count()
        };
        assert_eq!(realized_count(), 1);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            600
        );

        // A duplicate transport observation has no retained PendingCredit and
        // therefore cannot re-arm the defense or double-count bytes.
        controller.credit_advertised(endpoint, stream, 600, Some(slot), Duration::from_micros(3));
        controller.drain_observations();
        assert_eq!(realized_count(), 1);
        assert_eq!(controller.pending_slots(), [(slot, packet)]);

        controller.consume_advertised_credit(endpoint, stream, 0, 600, Duration::from_millis(50));
        controller.drain_observations();
        assert!(calls.borrow().iter().any(|call| matches!(
            call,
            RecordedCall::Signal(DefenseSignal {
                at,
                kind: SignalKind::IncomingCreditResolved {
                    slot: observed,
                    packet: observed_packet,
                    outcome: EventOutcome::Satisfied { observed: 600 },
                },
            }) if *at == Duration::from_millis(50)
                && *observed == slot
                && *observed_packet == packet
        )));
        assert!(controller.pending_slots().is_empty());
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 600);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 600);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 600);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "split advertisement, consumption, and terminal ordering form one lifecycle oracle"
    )]
    fn reclassified_parser_credit_realizes_split_lifecycle_once_before_terminal() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 4).expect("packet");
        let slot = QcsdSlotId(604);
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let (mut defense, calls) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
        defense.split_incoming_credit_lifecycle = true;
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller
            .streams
            .get_mut(endpoint, stream)
            .expect("stream")
            .receive
            .bytes_read(1);
        assert_eq!(controller.streams.claim_stream(endpoint, stream, 4), 4);
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 4;
        controller.control.claims.push(PendingClaim {
            slot,
            packet,
            endpoint,
            stream,
            remaining: 4,
        });
        controller.parser_lease_ranges.insert(
            (endpoint, stream),
            vec![ParserLeaseRange {
                start: 1,
                end: 5,
                owner: None,
                unowned: true,
                advertised: true,
            }],
        );

        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 4,
            },
            Duration::from_micros(7),
        );
        controller.drain_observations();

        let calls = calls.borrow();
        let advertised: Vec<_> = calls
            .iter()
            .enumerate()
            .filter_map(|(index, call)| {
                matches!(
                    call,
                    RecordedCall::Signal(DefenseSignal {
                        kind: SignalKind::IncomingCreditAdvertised {
                            slot: observed,
                            packet: observed_packet,
                        },
                        ..
                    }) if *observed == slot && *observed_packet == packet
                )
                .then_some(index)
            })
            .collect();
        let consumed: Vec<_> = calls
            .iter()
            .enumerate()
            .filter_map(|(index, call)| {
                matches!(
                    call,
                    RecordedCall::Signal(DefenseSignal {
                        kind: SignalKind::ReceiveCreditConsumed { bytes: 4 },
                        ..
                    })
                )
                .then_some(index)
            })
            .collect();
        let resolved: Vec<_> = calls
            .iter()
            .enumerate()
            .filter_map(|(index, call)| {
                matches!(
                    call,
                    RecordedCall::Signal(DefenseSignal {
                        kind: SignalKind::IncomingCreditResolved {
                            slot: observed,
                            packet: observed_packet,
                            outcome: EventOutcome::Satisfied { observed: 4 },
                        },
                        ..
                    }) if *observed == slot && *observed_packet == packet
                )
                .then_some(index)
            })
            .collect();
        assert_eq!(advertised.len(), 1);
        assert_eq!(consumed.len(), 1);
        assert_eq!(resolved.len(), 1);
        assert!(advertised[0] < consumed[0] && consumed[0] < resolved[0]);
        drop(calls);

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    fn advertised_tail_controller(
        mode: DefenseMode,
        excess: u64,
        advertised_ranges: &[(u64, u64)],
        trace: Trace,
    ) -> (
        QcsdController,
        QcsdEndpointId,
        QcsdStreamId,
        QcsdSlotId,
        Packet,
    ) {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: excess,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::with_mode(trace, mode)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(20);
        let slot = QcsdSlotId(1_371);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("packet");
        let role = match mode {
            DefenseMode::ChaffOnly => QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            DefenseMode::ChaffAndShape => QcsdRequestRole::Application,
        };

        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);
        controller
            .streams
            .open(endpoint, stream, role, true, 16, excess, 4_096);
        let receive = &mut controller
            .streams
            .get_mut(endpoint, stream)
            .expect("stream")
            .receive;
        receive.data_frame(3, 4_096);
        assert_eq!(receive.release(100), Some((116, 100)));
        receive.advertised(116);
        receive.bytes_read(114);

        controller.pending_slots.insert(slot, packet);
        controller.incoming_credit_ledger.insert(
            slot,
            IncomingCreditLedger {
                packet,
                endpoint: Some(endpoint),
                multiple_endpoints: false,
                advertised: 1_200,
                local_realization_emitted: true,
                consumed: 1_198,
                retired: 0,
            },
        );
        controller.scheduled_incoming_requested_bytes = 1_200;
        controller.scheduled_incoming_advertised_bytes = 1_200;
        controller.scheduled_incoming_consumed_bytes = 1_198;
        controller.advertised_incoming_credit.insert(
            (endpoint, stream),
            advertised_ranges
                .iter()
                .map(|&(start, end)| AdvertisedIncomingCredit { slot, start, end })
                .collect(),
        );

        (controller, endpoint, stream, slot, packet)
    }

    #[test]
    fn terminal_full_advertised_tail_gets_one_bounded_mode_agnostic_bridge() {
        for mode in [DefenseMode::ChaffOnly, DefenseMode::ChaffAndShape] {
            let future_outgoing = Packet::new(Duration::from_secs(1), Direction::Outgoing, 1_200)
                .expect("future outgoing");
            let (mut controller, endpoint, stream, slot, packet) = advertised_tail_controller(
                mode,
                1_000,
                &[(114, 115), (115, 116)],
                Trace::new([future_outgoing]),
            );

            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
            assert!(matches!(
                controller.next_action(),
                Some(QcsdAction::LeaseParserReceive {
                    endpoint: observed_endpoint,
                    stream: observed_stream,
                    absolute_limit: 132,
                    increase: 16,
                    owner: None,
                }) if observed_endpoint == endpoint && observed_stream == stream
            ));
            assert!(controller.next_action().is_none());

            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_198);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 2);
            assert_eq!(controller.pending_slots(), [(slot, packet)]);

            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit: 132,
                    slot: None,
                },
                Duration::from_micros(1),
            );
            assert!(controller.next_action().is_none());
            assert_eq!(
                controller
                    .defense_diagnostics()
                    .scheduled_incoming_consumed_bytes,
                1_198
            );

            // Two scheduled tail bytes plus one unowned bridge byte complete
            // the next frame header. Only the scheduled prefix settles work.
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 3,
                },
                Duration::from_micros(2),
            );
            assert!(matches!(
                controller.next_action(),
                Some(QcsdAction::SlotSatisfied {
                    slot: observed, ..
                }) if observed == slot
            ));
            assert!(controller.next_action().is_none());
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_200);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);

            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 15,
                },
                Duration::from_micros(3),
            );
            assert!(
                controller
                    .drain_actions()
                    .all(|action| !matches!(action, QcsdAction::SlotSatisfied { .. }))
            );
        }
    }

    #[test]
    fn terminal_parser_bridge_requires_complete_contiguous_advertised_ownership() {
        for advertised_ranges in [&[(114, 115)][..], &[(114, 115), (116, 117)][..]] {
            let (mut controller, endpoint, stream, slot, packet) = advertised_tail_controller(
                DefenseMode::ChaffOnly,
                1_000,
                advertised_ranges,
                Trace::default(),
            );
            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
            assert!(controller.next_action().is_none());
            assert_eq!(controller.pending_slots(), [(slot, packet)]);
            assert_eq!(
                controller
                    .defense_diagnostics()
                    .scheduled_incoming_unresolved_bytes,
                2
            );
        }
    }

    #[test]
    fn terminal_parser_bridge_waits_for_terminal_unqueued_incoming_work() {
        let future = Packet::new(Duration::from_secs(1), Direction::Incoming, 1_200)
            .expect("future incoming");
        let (mut nonterminal, endpoint, stream, _, _) = advertised_tail_controller(
            DefenseMode::ChaffOnly,
            1_000,
            &[(114, 116)],
            Trace::new([future]),
        );
        nonterminal.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(nonterminal.next_action().is_none());

        let (mut queued, endpoint, stream, _, _) = advertised_tail_controller(
            DefenseMode::ChaffOnly,
            1_000,
            &[(114, 116)],
            Trace::default(),
        );
        queued.control.incoming.push(PendingIncoming {
            slot: QcsdSlotId(1_372),
            packet: future,
            endpoint: None,
            remaining: 1_200,
        });
        queued.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(queued.next_action().is_none());
        queued.control.incoming.clear();
        queued.poll(Duration::ZERO);
        assert!(queued.drain_actions().any(|action| matches!(
            action,
            QcsdAction::LeaseParserReceive {
                endpoint: observed_endpoint,
                stream: observed_stream,
                absolute_limit: 132,
                increase: 16,
                owner: None,
            } if observed_endpoint == endpoint && observed_stream == stream
        )));

        let (mut continuation, endpoint, stream, _, _) = advertised_tail_controller(
            DefenseMode::ChaffAndShape,
            1_000,
            &[(114, 116)],
            Trace::default(),
        );
        continuation.control.receiver_continuations.insert(
            QcsdSlotId(1_373),
            crate::ReceiverContinuationDisposition {
                cell_bytes: 1_200,
                parser_ceiling_bytes: 1_000,
            },
        );
        continuation.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(continuation.next_action().is_none());
    }

    #[test]
    fn terminal_advertised_tail_does_not_bypass_exhausted_parser_allowance() {
        let (mut controller, endpoint, stream, slot, packet) =
            advertised_tail_controller(DefenseMode::ChaffOnly, 0, &[(114, 116)], Trace::default());
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(controller.next_action().is_none());
        assert_eq!(controller.pending_slots(), [(slot, packet)]);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_unresolved_bytes,
            2
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the parser-lease and scheduled-range lifecycle is one accounting oracle"
    )]
    fn final_data_zero_data_and_fin_use_a_disjoint_parser_lease() {
        const BODY: u64 = 131_072;
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 1_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(BODY),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        let slot = QcsdSlotId(112);
        let state = controller
            .streams
            .get_mut(endpoint, stream)
            .expect("application stream");
        state.receive.response_headers(11, Some(BODY));
        state.receive.data_frame(22, BODY - 2);
        assert_eq!(
            state.receive.release(BODY + 32),
            Some((BODY + 33, BODY + 32))
        );
        state.receive.advertised(BODY + 33);
        state.receive.bytes_read(BODY + 31);
        assert_eq!(state.receive.consumed(), 131_103);

        controller.pending_slots.insert(slot, packet);
        controller.incoming_credit_ledger.insert(
            slot,
            IncomingCreditLedger {
                packet,
                endpoint: Some(endpoint),
                multiple_endpoints: false,
                advertised: 1_200,
                local_realization_emitted: true,
                consumed: 1_198,
                retired: 0,
            },
        );
        controller.scheduled_incoming_requested_bytes = 1_200;
        controller.scheduled_incoming_advertised_bytes = 1_200;
        controller.scheduled_incoming_consumed_bytes = 1_198;
        controller.advertised_incoming_credit.insert(
            (endpoint, stream),
            vec![AdvertisedIncomingCredit {
                slot,
                start: BODY + 31,
                end: BODY + 33,
            }],
        );

        // Exact retained live boundary: raw consumed=131,103 while the
        // scheduled RAW range [131,103, 131,105) is already advertised. The
        // parser tail is appended after it; StreamDataBlocked is irrelevant.
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(1),
        );
        let QcsdAction::LeaseParserReceive {
            absolute_limit: lease_limit,
            increase,
            ..
        } = controller.next_action().expect("parser liveness lease")
        else {
            panic!("expected parser-only receive credit");
        };
        assert_eq!(lease_limit, BODY + 49);
        assert_eq!(increase, 16);

        // The same raw boundary is idempotent even if HTTP/3 reports it again
        // before the transport encodes the lease.
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(1),
        );
        controller.observe(
            QcsdObservation::StreamDataBlocked {
                endpoint,
                stream,
                blocked_at: BODY + 33,
            },
            Duration::from_micros(1),
        );
        assert!(controller.next_action().is_none());

        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: lease_limit,
                slot: None,
            },
            Duration::from_micros(2),
        );

        // Under the established request-stream RAW-offset contract, the two
        // already-scheduled bytes carry the DATA(2) header and satisfy the
        // slot. The following payload is lease-owned and cannot count twice.
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 2,
            },
            Duration::from_micros(3),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: satisfied,
                ..
            }) if satisfied == slot
        ));
        controller.observe(
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                frame_header_bytes: 2,
                data_bytes: 2,
            },
            Duration::from_micros(3),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 2,
            },
            Duration::from_micros(3),
        );
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);

        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(4),
        );
        let QcsdAction::LeaseParserReceive {
            absolute_limit: zero_data_limit,
            increase: 16,
            ..
        } = controller.next_action().expect("DATA(0) parser lease")
        else {
            panic!("expected DATA(0) parser lease");
        };
        assert_eq!(zero_data_limit, BODY + 65);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: zero_data_limit,
                slot: None,
            },
            Duration::from_micros(4),
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 2,
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                frame_header_bytes: 2,
                data_bytes: 0,
            },
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(6),
        );
        assert!(controller.next_action().is_none());
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 1_200);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "deferred advertisement and abort rollback are one parser-lease lifecycle oracle"
    )]
    fn parser_lease_retries_after_scheduled_advertisement_and_abort_clears_it() {
        let build = || {
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 1).expect("packet");
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: 1,
                    max_stream_data_excess: 16,
                    ..QcsdConfig::default()
                },
                None,
                Box::new(StaticSchedule::new(Trace::default(), false)),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(0);
            let slot = QcsdSlotId(7);
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(2),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            let state = controller
                .streams
                .get_mut(endpoint, stream)
                .expect("application stream");
            state.receive.bytes_read(1);
            assert_eq!(state.receive.release(1), Some((2, 1)));

            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
            controller.scheduled_incoming_requested_bytes = 1;
            let credit = PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: 2,
                increase: 1,
            };
            controller.control.credit.push(credit);
            controller
                .actions
                .push_back(QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit: 2,
                    packet,
                    slot,
                });
            (controller, endpoint, stream, slot)
        };

        let (mut controller, endpoint, stream, slot) = build();
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::IncreaseReceiveLimit { slot: observed, .. }) if observed == slot
        ));
        assert!(
            controller.next_action().is_none(),
            "unadvertised suffix blocks lease"
        );
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: 2,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::LeaseParserReceive {
                absolute_limit: 18,
                increase: 16,
                ..
            })
        ));
        assert!(
            controller.next_action().is_none(),
            "retained boundary leases once"
        );

        // A second stream has an independent pristine boundary and lease cap.
        let other = QcsdStreamId(4);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: other,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1),
            },
            Duration::from_micros(1),
        );
        controller.drain_actions().for_each(drop);
        controller
            .streams
            .get_mut(endpoint, other)
            .expect("other stream")
            .receive
            .bytes_read(1);
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream: other,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(2),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::LeaseParserReceive {
                stream: observed,
                ..
            }) if observed == other
        ));
        assert!(controller.next_action().is_none());

        let (mut aborted, endpoint, stream, slot) = build();
        aborted.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        aborted.abort_pending_slots(Duration::ZERO, MissedSlotReason::DeadlineExpired);
        assert!(
            aborted
                .drain_actions()
                .all(|action| !matches!(action, QcsdAction::LeaseParserReceive { .. }))
        );
        aborted.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: 2,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        assert!(
            aborted
                .drain_actions()
                .all(|action| !matches!(action, QcsdAction::LeaseParserReceive { .. }))
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "raw lease/scheduled overlap accounting is intentionally explicit"
    )]
    fn consumed_parser_lease_debits_a_claim_and_reduces_its_later_release() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 4).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 100,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        let slot = QcsdSlotId(9);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        let state = controller
            .streams
            .get_mut(endpoint, stream)
            .expect("application stream");
        state.receive.bytes_read(1);
        state.receive.header_progress(100, false);
        assert_eq!(state.receive.release(100), Some((101, 100)));
        state.receive.advertised(101);
        state.receive.bytes_read(100);
        assert_eq!(state.receive.claim(4), 4);

        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 4;
        controller.control.claims.push(PendingClaim {
            slot,
            packet,
            endpoint,
            stream,
            remaining: 4,
        });

        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(1),
        );
        let QcsdAction::LeaseParserReceive {
            absolute_limit: lease_limit,
            increase: 16,
            owner,
            ..
        } = controller.next_action().expect("parser lease")
        else {
            panic!("expected parser lease");
        };
        assert_eq!(
            owner, None,
            "pre-cap lease acquires ownership on consumption"
        );
        assert_eq!(lease_limit, 117);
        assert_eq!(controller.control.claims[0].remaining, 4);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_consumed_bytes,
            0
        );
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: lease_limit,
                slot: None,
            },
            Duration::from_micros(2),
        );
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            0,
            "an unowned parser lease is not scheduled merely by advertisement"
        );

        // Encoding the lease did not realize scheduled work. Reading its
        // two-byte prefix does: those raw bytes spend two bytes of the
        // pre-owned claim, leaving only two bytes for a later exact release.
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 2,
            },
            Duration::from_micros(3),
        );
        assert_eq!(controller.control.claims[0].remaining, 2);
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 2);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 2);
        controller.observe(
            QcsdObservation::DataFrame {
                endpoint,
                stream,
                frame_header_bytes: 2,
                data_bytes: 20,
            },
            Duration::from_micros(3),
        );
        assert_eq!(
            controller
                .streams
                .get_mut(endpoint, stream)
                .expect("stream")
                .receive
                .claimable(),
            100,
            "exact conversion restores the provisional reservation"
        );
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit: scheduled_limit,
            slot: scheduled_slot,
            ..
        } = controller
            .next_action()
            .expect("exact scheduled continuation")
        else {
            panic!("expected scheduled continuation");
        };
        assert_eq!(scheduled_slot, slot);
        assert_eq!(scheduled_limit, 119);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: scheduled_limit,
                slot: Some(slot),
            },
            Duration::from_micros(4),
        );

        // One coalesced read crosses fourteen unowned lease bytes and the two
        // scheduled raw bytes. Only the scheduled suffix is newly attributed;
        // excess lease bytes remain observable raw overflow.
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 16,
            },
            Duration::from_micros(5),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: satisfied,
                ..
            }) if satisfied == slot
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "advertise, stream return, retry, and consumption form one ownership oracle"
    )]
    fn unused_scheduled_parser_ownership_returns_on_stream_lifecycle() {
        for (finish, consumed_before_close) in [QcsdStreamFinish::Fin, QcsdStreamFinish::Reset]
            .into_iter()
            .flat_map(|finish| [(finish, 0_u64), (finish, 4_u64)])
        {
            let (mut defense, calls) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
            defense.split_incoming_credit_lifecycle = true;
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: 1,
                    max_stream_data_excess: 32,
                    ..QcsdConfig::default()
                },
                None,
                Box::new(defense),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(4);
            let retry_stream = QcsdStreamId(8);
            let slot = QcsdSlotId(5);
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(1),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            assert_eq!(controller.streams.claim_stream(endpoint, stream, 10), 10);
            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
            controller.scheduled_incoming_requested_bytes = 10;
            controller.parser_lease_ranges.insert(
                (endpoint, stream),
                vec![ParserLeaseRange {
                    start: 1,
                    end: 11,
                    owner: Some(QcsdParserLeaseOwner { packet, slot }),
                    unowned: false,
                    advertised: false,
                }],
            );
            controller.credit_advertised(endpoint, stream, 11, None, Duration::ZERO);
            controller.drain_observations();
            let local_realizations = || {
                calls
                    .borrow()
                    .iter()
                    .filter(|call| {
                        matches!(
                            call,
                            RecordedCall::Signal(DefenseSignal {
                                kind: SignalKind::IncomingCreditAdvertised {
                                    slot: observed,
                                    packet: observed_packet,
                                },
                                ..
                            }) if *observed == slot && *observed_packet == packet
                        )
                    })
                    .count()
            };
            assert_eq!(local_realizations(), 1);
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
            assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 10);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);

            if consumed_before_close > 0 {
                controller.observe(
                    QcsdObservation::BytesRead {
                        endpoint,
                        stream,
                        bytes: 1 + consumed_before_close,
                    },
                    Duration::from_micros(1),
                );
                assert!(controller.next_action().is_none());
                let diagnostics = controller.defense_diagnostics();
                assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 10);
                assert_eq!(
                    diagnostics.scheduled_incoming_consumed_bytes,
                    consumed_before_close
                );
            }

            controller.observe(
                QcsdObservation::StreamFinished {
                    endpoint,
                    stream,
                    finish,
                },
                Duration::from_micros(1),
            );
            assert!(controller.parser_lease_ranges.is_empty());
            assert!(controller.control.claims.is_empty());
            assert_eq!(controller.control.incoming.len(), 1);
            assert_eq!(controller.control.incoming[0].slot, slot);
            assert_eq!(
                controller.control.incoming[0].remaining,
                10 - consumed_before_close
            );
            assert_eq!(controller.control.incoming[0].endpoint, None);
            assert_eq!(controller.pending_slots(), [(slot, packet)]);
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
            assert_eq!(
                diagnostics.scheduled_incoming_advertised_bytes,
                consumed_before_close
            );
            assert_eq!(
                diagnostics.scheduled_incoming_consumed_bytes,
                consumed_before_close
            );
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(
                diagnostics.scheduled_incoming_unresolved_bytes,
                10 - consumed_before_close
            );

            // The same slot can move to another stream without its replacement
            // advertisement being counted as an overflow or producing a
            // duplicate local realization.
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream: retry_stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(11),
                },
                Duration::from_micros(2),
            );
            controller.drain_actions().for_each(drop);
            controller.poll(Duration::from_millis(5));
            let QcsdAction::IncreaseReceiveLimit {
                stream: observed_stream,
                absolute_limit,
                slot: observed_slot,
                ..
            } = controller
                .drain_actions()
                .find(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
                .expect("replacement receive credit")
            else {
                panic!("expected replacement receive credit");
            };
            assert_eq!(observed_stream, retry_stream);
            assert_eq!(observed_slot, slot);
            assert_eq!(absolute_limit, 11 - consumed_before_close);
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream: retry_stream,
                    absolute_limit,
                    slot: Some(slot),
                },
                Duration::from_millis(5),
            );
            controller.drain_observations();
            assert_eq!(local_realizations(), 1);
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 10);
            assert_eq!(
                diagnostics.scheduled_incoming_consumed_bytes,
                consumed_before_close
            );
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream: retry_stream,
                    bytes: 11 - consumed_before_close,
                },
                Duration::from_millis(6),
            );
            assert!(controller.drain_actions().any(|action| matches!(
                action,
                QcsdAction::SlotSatisfied {
                    slot: observed,
                    ..
                } if observed == slot
            )));
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
            assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 10);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 10);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "mixed rollback, identity reconciliation, and advertised ownership form one atomic oracle"
    )]
    fn unavailable_stream_rolls_back_mixed_suffix_and_preserves_advertised_bytes() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 64,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            64,
            64,
        );

        let scheduled_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 13).expect("scheduled packet");
        let later_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("later packet");
        let advertised_packet =
            Packet::new(Duration::ZERO, Direction::Incoming, 3).expect("advertised packet");
        let scheduled_slot = QcsdSlotId(7);
        let later_slot = QcsdSlotId(8);
        let advertised_slot = QcsdSlotId(6);
        for (slot, packet) in [
            (advertised_slot, advertised_packet),
            (scheduled_slot, scheduled_packet),
            (later_slot, later_packet),
        ] {
            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
        }
        controller.scheduled_incoming_requested_bytes = 26;

        assert_eq!(controller.streams.claim_stream(endpoint, stream, 6), 6);
        let first = controller
            .streams
            .release_stream(endpoint, stream, 10)
            .expect("first scheduled release");
        let parser = controller
            .streams
            .release_stream(endpoint, stream, 3)
            .expect("parser release");
        let later = controller
            .streams
            .release_stream(endpoint, stream, 10)
            .expect("later scheduled release");
        assert_eq!(
            (
                first.absolute_limit,
                parser.absolute_limit,
                later.absolute_limit
            ),
            (26, 29, 39)
        );

        controller.control.credit.extend([
            PendingCredit {
                slot: scheduled_slot,
                packet: scheduled_packet,
                endpoint,
                stream,
                absolute_limit: first.absolute_limit,
                increase: first.increase,
            },
            PendingCredit {
                slot: later_slot,
                packet: later_packet,
                endpoint,
                stream,
                absolute_limit: later.absolute_limit,
                increase: later.increase,
            },
        ]);
        let parser_owner = QcsdParserLeaseOwner {
            packet: scheduled_packet,
            slot: scheduled_slot,
        };
        controller.parser_lease_ranges.insert(
            (endpoint, stream),
            vec![
                ParserLeaseRange {
                    start: 13,
                    end: 16,
                    owner: Some(QcsdParserLeaseOwner {
                        packet: advertised_packet,
                        slot: advertised_slot,
                    }),
                    unowned: false,
                    advertised: false,
                },
                ParserLeaseRange {
                    start: 26,
                    end: 29,
                    owner: Some(parser_owner),
                    unowned: false,
                    advertised: false,
                },
            ],
        );
        controller.credit_advertised(endpoint, stream, 16, None, Duration::ZERO);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            3
        );
        let actions = [
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: 26,
                packet: scheduled_packet,
                slot: scheduled_slot,
            },
            QcsdAction::LeaseParserReceive {
                endpoint,
                stream,
                absolute_limit: 29,
                increase: 3,
                owner: Some(parser_owner),
            },
            QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: 39,
                packet: later_packet,
                slot: later_slot,
            },
        ];
        controller.actions.extend(actions.clone());
        let roots: Vec<_> = actions
            .iter()
            .filter_map(QcsdAction::receive_identity)
            .collect();

        let invalid = QcsdReceiveActionIdentity::Scheduled {
            endpoint,
            stream,
            absolute_limit: 40,
            slot: QcsdSlotId(99),
        };
        assert!(
            controller
                .mark_receive_stream_unavailable(endpoint, stream, &[invalid], Duration::ZERO)
                .is_err()
        );
        assert_eq!(
            controller.streams.receive_limits(endpoint, stream),
            Some((16, 39))
        );
        assert_eq!(controller.actions.len(), 3);

        let cancellation = controller
            .mark_receive_stream_unavailable(endpoint, stream, &roots, Duration::ZERO)
            .expect("atomic cancellation");
        assert_eq!(cancellation.canceled_actions(), roots);
        assert_eq!(cancellation.canceled_slots(), &[scheduled_slot, later_slot]);
        assert_eq!(
            controller.streams.receive_limits(endpoint, stream),
            Some((16, 16))
        );
        assert!(
            !controller
                .streams
                .receive_actions_available(endpoint, stream)
        );
        assert!(controller.control.credit.is_empty());
        assert!(controller.actions.is_empty());
        assert_eq!(controller.parser_lease_ranges[&(endpoint, stream)].len(), 1);
        assert!(controller.parser_lease_ranges[&(endpoint, stream)][0].advertised);
        assert!(
            controller
                .control
                .incoming
                .iter()
                .any(|pending| pending.slot == scheduled_slot && pending.remaining == 13)
        );
        assert!(
            controller
                .control
                .incoming
                .iter()
                .any(|pending| pending.slot == later_slot && pending.remaining == 10)
        );
        assert!(controller.control.terminal_incoming.is_empty());

        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 16,
            },
            Duration::from_micros(1),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: observed, ..
            }) if observed == advertised_slot
        ));
        assert!(
            !controller
                .control
                .terminal_incoming
                .contains(&scheduled_slot)
        );
        assert!(!controller.control.terminal_incoming.contains(&later_slot));
    }

    #[test]
    fn unavailable_stream_drop_policy_emits_one_explicit_retirement() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                initial_max_stream_data: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        let slot = QcsdSlotId(7);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            16,
            32,
        );
        let release = controller
            .streams
            .release_stream(endpoint, stream, 10)
            .expect("release");
        controller.control.credit.push(PendingCredit {
            slot,
            packet,
            endpoint,
            stream,
            absolute_limit: release.absolute_limit,
            increase: release.increase,
        });
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 10;
        let action = QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit: release.absolute_limit,
            packet,
            slot,
        };
        controller.actions.push_back(action.clone());
        let identity = action.receive_identity().expect("receive identity");

        let cancellation = controller
            .mark_receive_stream_unavailable(
                endpoint,
                stream,
                &[identity],
                Duration::from_micros(1),
            )
            .expect("drop cancellation");
        assert_eq!(cancellation.canceled_actions(), &[identity]);
        assert_eq!(cancellation.canceled_slots(), &[slot]);
        assert!(controller.control.incoming.is_empty());
        assert!(controller.incoming_credit_ledger.is_empty());
        assert!(controller.control.terminal_incoming.contains(&slot));
        assert_eq!(
            controller
                .actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::SlotMissed { slot: observed, reason: MissedSlotReason::ReceiveCreditRetired, .. } if *observed == slot))
                .count(),
            1
        );
        assert!(!controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotSatisfied { slot: observed, .. } if *observed == slot
        )));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 10);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn global_plan_cancels_cross_batch_suffix_from_later_root() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 64,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            64,
            64,
        );
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let mut identities = Vec::new();
        for slot in [QcsdSlotId(1), QcsdSlotId(2)] {
            let release = controller
                .streams
                .release_stream(endpoint, stream, 10)
                .expect("release");
            let action = QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                packet,
                slot,
            };
            identities.push(action.receive_identity().expect("identity"));
            controller.actions.push_back(action);
            controller.control.credit.push(PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                increase: release.increase,
            });
        }
        let plan = controller
            .plan_receive_streams_unavailable(&[(endpoint, stream, vec![identities[1]])])
            .expect("pure cross-batch plan");
        assert_eq!(plan.canceled_actions(), identities);
        assert_eq!(plan.restored_limits(), &[(endpoint, stream, 16)]);
        assert_eq!(
            controller.streams.receive_limits(endpoint, stream),
            Some((16, 36)),
            "planning is pure"
        );
        let cancellation = controller
            .commit_receive_streams_unavailable(&plan, Duration::ZERO)
            .expect("commit");
        assert_eq!(cancellation.canceled_actions(), identities);
        assert_eq!(
            controller.streams.receive_limits(endpoint, stream),
            Some((16, 16))
        );
    }

    #[test]
    fn global_plan_terminalizes_shared_slot_once_for_two_rejected_streams() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                initial_max_stream_data: 16,
                max_stream_data_excess: 32,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let streams = [QcsdStreamId(4), QcsdStreamId(8)];
        let slot = QcsdSlotId(7);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let mut identities = Vec::new();
        for stream in streams {
            controller.streams.open(
                endpoint,
                stream,
                QcsdRequestRole::Application,
                true,
                16,
                32,
                32,
            );
            let release = controller
                .streams
                .release_stream(endpoint, stream, 10)
                .expect("release");
            let action = QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                packet,
                slot,
            };
            identities.push(action.receive_identity().expect("identity"));
            controller.actions.push_back(action);
            controller.control.credit.push(PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                increase: release.increase,
            });
        }
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 10;
        let plan = controller
            .plan_receive_streams_unavailable(&[
                (endpoint, streams[0], vec![identities[0]]),
                (endpoint, streams[1], vec![identities[1]]),
            ])
            .expect("global shared-slot plan");
        assert_eq!(plan.canceled_slots(), &[slot]);
        assert!(!controller.control.terminal_incoming.contains(&slot));
        controller
            .commit_receive_streams_unavailable(&plan, Duration::ZERO)
            .expect("one-shot commit");
        assert!(controller.control.terminal_incoming.contains(&slot));
        assert_eq!(
            controller
                .actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::SlotMissed { slot: observed, .. } if *observed == slot))
                .count(),
            1
        );
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_retired_bytes,
            10
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "retained-prefix and canceled-suffix ownership form one transitive rollback oracle"
    )]
    fn transitive_rollback_preserves_accepted_unencoded_prefix() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                initial_max_stream_data: 16,
                max_stream_data_excess: 64,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let rejected = QcsdStreamId(4);
        let transitive = QcsdStreamId(8);
        for stream in [rejected, transitive] {
            controller.streams.open(
                endpoint,
                stream,
                QcsdRequestRole::Application,
                true,
                16,
                64,
                64,
            );
        }
        let failed_slot = QcsdSlotId(10);
        let retained_slot = QcsdSlotId(11);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let rejected_release = controller
            .streams
            .release_stream(endpoint, rejected, 10)
            .expect("rejected release");
        let prefix_release = controller
            .streams
            .release_stream(endpoint, transitive, 10)
            .expect("prefix release");
        let suffix_release = controller
            .streams
            .release_stream(endpoint, transitive, 10)
            .expect("suffix release");
        let rejected_action = QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream: rejected,
            absolute_limit: rejected_release.absolute_limit,
            packet,
            slot: failed_slot,
        };
        let prefix_action = QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream: transitive,
            absolute_limit: prefix_release.absolute_limit,
            packet,
            slot: retained_slot,
        };
        let suffix_action = QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream: transitive,
            absolute_limit: suffix_release.absolute_limit,
            packet,
            slot: failed_slot,
        };
        for (action, release, slot, stream) in [
            (&rejected_action, rejected_release, failed_slot, rejected),
            (&prefix_action, prefix_release, retained_slot, transitive),
            (&suffix_action, suffix_release, failed_slot, transitive),
        ] {
            controller.actions.push_back(action.clone());
            controller.control.credit.push(PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                increase: release.increase,
            });
        }
        for slot in [failed_slot, retained_slot] {
            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
        }
        controller.scheduled_incoming_requested_bytes = 20;
        let rejected_identity = rejected_action
            .receive_identity()
            .expect("rejected identity");
        let prefix_identity = prefix_action.receive_identity().expect("prefix identity");
        let suffix_identity = suffix_action.receive_identity().expect("suffix identity");
        let plan = controller
            .plan_receive_streams_unavailable(&[(endpoint, rejected, vec![rejected_identity])])
            .expect("transitive plan");
        assert!(plan.canceled_actions().contains(&rejected_identity));
        assert!(plan.canceled_actions().contains(&suffix_identity));
        assert!(!plan.canceled_actions().contains(&prefix_identity));
        assert_eq!(plan.retained_actions(), &[prefix_identity]);
        assert!(plan.restored_limits().contains(&(endpoint, transitive, 26)));
        controller
            .commit_receive_streams_unavailable(&plan, Duration::ZERO)
            .expect("transitive commit");
        assert_eq!(
            controller.streams.receive_limits(endpoint, transitive),
            Some((16, 26))
        );
        assert!(
            controller
                .streams
                .receive_actions_available(endpoint, transitive)
        );
        assert!(controller.actions.contains(&prefix_action));
        assert!(!controller.actions.contains(&suffix_action));
    }

    fn controller_with_invalid_transitive_ledger(
        duplicate_suffix: bool,
    ) -> (
        QcsdController,
        QcsdEndpointId,
        QcsdStreamId,
        QcsdStreamId,
        QcsdReceiveActionIdentity,
    ) {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                initial_max_stream_data: 16,
                max_stream_data_excess: 64,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let rejected = QcsdStreamId(4);
        let transitive = QcsdStreamId(8);
        for stream in [rejected, transitive] {
            controller.streams.open(
                endpoint,
                stream,
                QcsdRequestRole::Application,
                true,
                16,
                64,
                64,
            );
        }
        let failed_slot = QcsdSlotId(10);
        let retained_slot = QcsdSlotId(11);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let rejected_release = controller
            .streams
            .release_stream(endpoint, rejected, 10)
            .expect("rejected release");
        let prefix_release = controller
            .streams
            .release_stream(endpoint, transitive, 10)
            .expect("prefix release");
        let suffix_release = controller
            .streams
            .release_stream(endpoint, transitive, if duplicate_suffix { 10 } else { 14 })
            .expect("suffix release");
        let rejected_credit = PendingCredit {
            slot: failed_slot,
            packet,
            endpoint,
            stream: rejected,
            absolute_limit: rejected_release.absolute_limit,
            increase: rejected_release.increase,
        };
        let rejected_identity = QcsdReceiveActionIdentity::Scheduled {
            endpoint,
            stream: rejected,
            absolute_limit: rejected_credit.absolute_limit,
            slot: rejected_credit.slot,
        };
        let prefix_credit = PendingCredit {
            slot: retained_slot,
            packet,
            endpoint,
            stream: transitive,
            absolute_limit: prefix_release.absolute_limit,
            increase: prefix_release.increase,
        };
        let suffix_credit = PendingCredit {
            slot: failed_slot,
            packet,
            endpoint,
            stream: transitive,
            absolute_limit: suffix_release.absolute_limit,
            // Gap case deliberately records [30, 40) after [16, 26).
            increase: if duplicate_suffix {
                suffix_release.increase
            } else {
                10
            },
        };
        controller
            .control
            .credit
            .extend([rejected_credit, prefix_credit, suffix_credit]);
        if duplicate_suffix {
            controller.control.credit.push(suffix_credit);
        }
        (
            controller,
            endpoint,
            rejected,
            transitive,
            rejected_identity,
        )
    }

    fn assert_invalid_transitive_plan_is_pure(duplicate_suffix: bool) {
        let (controller, endpoint, rejected, transitive, rejected_identity) =
            controller_with_invalid_transitive_ledger(duplicate_suffix);
        let credit_snapshot = |credit: &PendingCredit| {
            (
                credit.slot,
                credit.packet,
                credit.endpoint,
                credit.stream,
                credit.absolute_limit,
                credit.increase,
            )
        };
        let credit_before: Vec<_> = controller
            .control
            .credit
            .iter()
            .map(credit_snapshot)
            .collect();
        let limits_before = controller.streams.receive_limits(endpoint, transitive);
        let actions_before = controller.actions.clone();
        let available_before = controller
            .streams
            .receive_actions_available(endpoint, transitive);
        let error = controller
            .plan_receive_streams_unavailable(&[(endpoint, rejected, vec![rejected_identity])])
            .expect_err("malformed transitive ledger must fail pure planning");
        assert!(matches!(error, crate::Error::ControllerInvariant(_)));
        assert_eq!(
            controller
                .control
                .credit
                .iter()
                .map(credit_snapshot)
                .collect::<Vec<_>>(),
            credit_before
        );
        assert_eq!(
            controller.streams.receive_limits(endpoint, transitive),
            limits_before
        );
        assert_eq!(controller.actions, actions_before);
        assert_eq!(
            controller
                .streams
                .receive_actions_available(endpoint, transitive),
            available_before
        );
    }

    #[test]
    fn transitive_gap_fails_pure_plan_without_mutation() {
        assert_invalid_transitive_plan_is_pure(false);
    }

    #[test]
    fn transitive_duplicate_identity_fails_pure_plan_without_mutation() {
        assert_invalid_transitive_plan_is_pure(true);
    }

    #[test]
    fn configure_only_plan_marks_stream_unavailable_and_removes_queued_config() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Application,
            true,
            16,
            16,
            16,
        );
        let configure = QcsdAction::ConfigureManualReceive {
            endpoint,
            stream,
            initial_limit: 16,
        };
        controller.actions.push_back(configure.clone());
        let plan = controller
            .plan_receive_streams_unavailable(&[(endpoint, stream, Vec::new())])
            .expect("configure-only plan");
        assert_eq!(plan.canceled_configurations(), &[configure]);
        assert!(plan.canceled_actions().is_empty());
        controller
            .commit_receive_streams_unavailable(&plan, Duration::ZERO)
            .expect("configure-only commit");
        assert!(controller.actions.is_empty());
        assert!(
            !controller
                .streams
                .receive_actions_available(endpoint, stream)
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "cross-stream failure and delayed detached-range consumption are one ownership oracle"
    )]
    fn sibling_credit_failure_detaches_advertised_parser_owner() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let parser_stream = QcsdStreamId(0);
        let sibling_stream = QcsdStreamId(4);
        ready(&mut controller, 1, "https://example.com");
        for stream in [parser_stream, sibling_stream] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(if stream == parser_stream { 1 } else { 5 }),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
        }

        // Exhaust the unowned parser budget so the next continuation must
        // carry explicit slot ownership.
        controller
            .streams
            .get_mut(endpoint, parser_stream)
            .expect("parser stream")
            .receive
            .bytes_read(1);
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream: parser_stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        let QcsdAction::LeaseParserReceive {
            absolute_limit: 17, ..
        } = controller.next_action().expect("unowned lease")
        else {
            panic!("expected unowned lease");
        };
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: parser_stream,
                absolute_limit: 17,
                slot: None,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: parser_stream,
                bytes: 16,
            },
            Duration::ZERO,
        );

        let failed_slot = QcsdSlotId(7);
        let failed_packet = Packet::new(Duration::ZERO, Direction::Incoming, 4).expect("packet");
        controller.pending_slots.insert(failed_slot, failed_packet);
        controller
            .incoming_credit_ledger
            .insert(failed_slot, IncomingCreditLedger::new(failed_packet));
        controller.scheduled_incoming_requested_bytes = 4;
        assert_eq!(
            controller.streams.claim_stream(endpoint, parser_stream, 4),
            4
        );
        controller.control.claims.push(PendingClaim {
            slot: failed_slot,
            packet: failed_packet,
            endpoint,
            stream: parser_stream,
            remaining: 4,
        });
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream: parser_stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        let QcsdAction::LeaseParserReceive {
            absolute_limit: 21,
            increase: 4,
            ..
        } = controller.next_action().expect("owned parser continuation")
        else {
            panic!("expected owned parser continuation");
        };
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream: parser_stream,
                absolute_limit: 21,
                slot: None,
            },
            Duration::ZERO,
        );

        let sibling_release = controller
            .streams
            .release_stream(endpoint, sibling_stream, 4)
            .expect("sibling release");
        controller.control.credit.push(PendingCredit {
            slot: failed_slot,
            packet: failed_packet,
            endpoint,
            stream: sibling_stream,
            absolute_limit: sibling_release.absolute_limit,
            increase: sibling_release.increase,
        });
        controller
            .actions
            .push_back(QcsdAction::IncreaseReceiveLimit {
                endpoint,
                stream: sibling_stream,
                absolute_limit: sibling_release.absolute_limit,
                packet: failed_packet,
                slot: failed_slot,
            });
        controller.fail_incoming_slot(
            failed_slot,
            MissedSlotReason::EndpointClosed,
            Duration::from_micros(1),
            true,
        );
        assert_eq!(
            controller
                .streams
                .get_mut(endpoint, parser_stream)
                .expect("parser stream")
                .receive
                .claimable(),
            16,
            "failed advertised owner restores its reservation"
        );
        assert!(controller.control.credit.is_empty());
        assert!(controller.control.claims.is_empty());
        assert!(controller.drain_actions().all(|action| !matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { slot, .. } if slot == failed_slot
        )));
        let range = controller
            .parser_lease_ranges
            .get(&(endpoint, parser_stream))
            .and_then(|ranges| ranges.last())
            .expect("advertised physical range remains");
        assert_eq!(range.owner, None);
        assert!(!range.unowned, "failed ownership is explicitly detached");

        // A later claim on the same stream cannot inherit bytes consumed from
        // the detached old range.
        let next_slot = QcsdSlotId(8);
        let next_packet = Packet::new(Duration::ZERO, Direction::Incoming, 4).expect("packet");
        controller.pending_slots.insert(next_slot, next_packet);
        controller
            .incoming_credit_ledger
            .insert(next_slot, IncomingCreditLedger::new(next_packet));
        controller.scheduled_incoming_requested_bytes += 4;
        assert_eq!(
            controller.streams.claim_stream(endpoint, parser_stream, 4),
            4
        );
        controller.control.claims.push(PendingClaim {
            slot: next_slot,
            packet: next_packet,
            endpoint,
            stream: parser_stream,
            remaining: 4,
        });
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream: parser_stream,
                bytes: 4,
            },
            Duration::from_micros(2),
        );
        assert_eq!(controller.control.claims[0].remaining, 4);
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 8);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 4);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 4);
    }

    #[test]
    fn close_rolls_back_unadvertised_credit_before_removing_stream_state() {
        for close_kind in [QcsdStreamFinish::Fin, QcsdStreamFinish::Reset] {
            for drop_unsatisfied_events in [false, true] {
                let mut controller = QcsdController::with_defense(
                    QcsdConfig {
                        initial_max_stream_data: 1,
                        max_stream_data_excess: 16,
                        drop_unsatisfied_events,
                        ..QcsdConfig::default()
                    },
                    None,
                    Box::new(StaticSchedule::new(Trace::default(), false)),
                )
                .expect("controller");
                let endpoint = QcsdEndpointId(1);
                let stream = QcsdStreamId(0);
                let slot = QcsdSlotId(3);
                let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
                ready(&mut controller, 1, "https://example.com");
                controller.observe(
                    QcsdObservation::StreamOpened {
                        endpoint,
                        stream,
                        role: QcsdRequestRole::Application,
                        expected_response_length: Some(11),
                    },
                    Duration::ZERO,
                );
                controller.drain_actions().for_each(drop);
                let release = controller
                    .streams
                    .release_stream(endpoint, stream, 10)
                    .expect("unadvertised release");
                controller.pending_slots.insert(slot, packet);
                controller
                    .incoming_credit_ledger
                    .insert(slot, IncomingCreditLedger::new(packet));
                controller.scheduled_incoming_requested_bytes = 10;
                controller.control.credit.push(PendingCredit {
                    slot,
                    packet,
                    endpoint,
                    stream,
                    absolute_limit: release.absolute_limit,
                    increase: release.increase,
                });
                controller
                    .actions
                    .push_back(QcsdAction::IncreaseReceiveLimit {
                        endpoint,
                        stream,
                        absolute_limit: release.absolute_limit,
                        packet,
                        slot,
                    });

                controller.observe(
                    QcsdObservation::StreamFinished {
                        endpoint,
                        stream,
                        finish: close_kind,
                    },
                    Duration::from_micros(1),
                );
                assert!(controller.control.credit.is_empty());
                assert!(controller.drain_actions().all(|action| !matches!(
                    action,
                    QcsdAction::IncreaseReceiveLimit { slot: observed, .. } if observed == slot
                )));
                let diagnostics = controller.defense_diagnostics();
                assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
                assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
                if drop_unsatisfied_events {
                    assert!(controller.control.incoming.is_empty());
                    assert!(controller.pending_slots().is_empty());
                    assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 10);
                    assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
                } else {
                    assert_eq!(controller.control.incoming.len(), 1);
                    assert_eq!(controller.control.incoming[0].slot, slot);
                    assert_eq!(controller.control.incoming[0].remaining, 10);
                    assert_eq!(controller.control.incoming[0].endpoint, None);
                    assert_eq!(controller.pending_slots(), [(slot, packet)]);
                    assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
                    assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 10);
                }
            }
        }
    }

    #[test]
    fn endpoint_close_rolls_back_unadvertised_credit_before_removing_stream_state() {
        for drop_unsatisfied_events in [false, true] {
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: 1,
                    max_stream_data_excess: 16,
                    drop_unsatisfied_events,
                    ..QcsdConfig::default()
                },
                None,
                Box::new(StaticSchedule::new(Trace::default(), false)),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(0);
            let slot = QcsdSlotId(3);
            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(11),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            let release = controller
                .streams
                .release_stream(endpoint, stream, 10)
                .expect("unadvertised release");
            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
            controller.scheduled_incoming_requested_bytes = 10;
            controller.control.credit.push(PendingCredit {
                slot,
                packet,
                endpoint,
                stream,
                absolute_limit: release.absolute_limit,
                increase: release.increase,
            });
            controller
                .actions
                .push_back(QcsdAction::IncreaseReceiveLimit {
                    endpoint,
                    stream,
                    absolute_limit: release.absolute_limit,
                    packet,
                    slot,
                });
            controller.observe(
                QcsdObservation::EndpointClosed { endpoint },
                Duration::from_micros(1),
            );
            assert!(controller.control.credit.is_empty());
            assert!(controller.drain_actions().all(|action| !matches!(
                action,
                QcsdAction::IncreaseReceiveLimit { slot: observed, .. } if observed == slot
            )));
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
            if drop_unsatisfied_events {
                assert!(controller.control.incoming.is_empty());
                assert!(controller.pending_slots().is_empty());
                assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 10);
                assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
            } else {
                assert_eq!(controller.control.incoming.len(), 1);
                assert_eq!(controller.control.incoming[0].slot, slot);
                assert_eq!(controller.control.incoming[0].remaining, 10);
                assert_eq!(controller.control.incoming[0].endpoint, None);
                assert_eq!(controller.pending_slots(), [(slot, packet)]);
                assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
                assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 10);
            }
        }
    }

    #[test]
    fn parser_lease_claim_debit_is_lexical_claim_only_and_bounded_by_ownership() {
        let (defense, _) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(100),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller
            .streams
            .get_mut(endpoint, stream)
            .expect("stream")
            .receive
            .bytes_read(100);

        let early = QcsdSlotId(3);
        let late = QcsdSlotId(9);
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 4).expect("packet");
        for slot in [early, late] {
            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
        }
        controller.scheduled_incoming_requested_bytes = 8;
        // Reverse insertion proves allocation is by slot identity, not Vec order.
        controller.control.claims.push(PendingClaim {
            slot: late,
            packet,
            endpoint,
            stream,
            remaining: 4,
        });
        controller.control.claims.push(PendingClaim {
            slot: early,
            packet,
            endpoint,
            stream,
            remaining: 4,
        });
        controller.parser_lease_ranges.insert(
            (endpoint, stream),
            vec![ParserLeaseRange {
                start: 100,
                end: 110,
                owner: None,
                unowned: true,
                advertised: true,
            }],
        );

        // Ten physical lease bytes exist, but only eight claimed bytes can be
        // scheduled. Both claim-only slots terminalize exactly once in lexical
        // order; the final two bytes remain raw-only overflow.
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 10,
            },
            Duration::from_micros(1),
        );
        let terminals: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::SlotSatisfied { slot, .. } => Some(slot),
                _ => None,
            })
            .collect();
        assert_eq!(terminals, [early, late]);
        assert!(controller.control.claims.is_empty());
        assert!(controller.pending_slots().is_empty());
        assert!(controller.parser_lease_ranges.is_empty());
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 8);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 8);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 8);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "cap exhaustion, persisted demand, and exact conservation form one liveness oracle"
    )]
    fn exhausted_unowned_parser_cap_continues_only_with_scheduled_demand() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 32,
                control_interval_us: 1,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller
            .streams
            .get_mut(endpoint, stream)
            .expect("controlled stream")
            .receive
            .bytes_read(1);

        for expected_limit in [17, 33] {
            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
            let QcsdAction::LeaseParserReceive {
                absolute_limit,
                increase: 16,
                owner,
                ..
            } = controller.next_action().expect("unowned parser lease")
            else {
                panic!("expected unowned parser lease");
            };
            assert_eq!(owner, None);
            assert_eq!(absolute_limit, expected_limit);
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit,
                    slot: None,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 16,
                },
                Duration::ZERO,
            );
        }

        // The lifetime unowned allowance is exhausted. Repeated typed
        // boundaries and non-authoritative blocked observations cannot grow
        // the receive limit without due scheduled ownership.
        for _ in 0..2 {
            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::StreamDataBlocked {
                    endpoint,
                    stream,
                    blocked_at: 33,
                },
                Duration::ZERO,
            );
        }
        assert!(controller.next_action().is_none());

        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let slot = QcsdSlotId(91);
        controller.pending_slots.insert(slot, packet);
        controller
            .incoming_credit_ledger
            .insert(slot, IncomingCreditLedger::new(packet));
        controller.scheduled_incoming_requested_bytes = 10;
        controller.control.incoming.push(PendingIncoming {
            slot,
            packet,
            endpoint: None,
            remaining: 10,
        });

        // The boundary persists until the next control pass assigns the due
        // slot. Its continuation is physically slotless but carries explicit
        // provisional ownership and cannot satisfy on grant or advertisement.
        controller.poll(Duration::ZERO);
        let lease = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::LeaseParserReceive {
                    endpoint: observed_endpoint,
                    stream: observed_stream,
                    absolute_limit,
                    increase,
                    owner,
                } => Some((
                    observed_endpoint,
                    observed_stream,
                    absolute_limit,
                    increase,
                    owner,
                )),
                _ => None,
            })
            .expect("scheduled parser continuation");
        assert_eq!(
            lease,
            (
                endpoint,
                stream,
                43,
                10,
                Some(QcsdParserLeaseOwner { packet, slot }),
            )
        );
        assert_eq!(controller.pending_slots(), [(slot, packet)]);
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_consumed_bytes,
            0
        );
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: lease.2,
                slot: None,
            },
            Duration::from_micros(1),
        );
        assert!(controller.next_action().is_none());
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 10);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 10);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: lease.2,
                slot: None,
            },
            Duration::from_micros(1),
        );
        assert_eq!(
            controller
                .defense_diagnostics()
                .scheduled_incoming_advertised_bytes,
            10,
            "a duplicate slotless advertisement cannot double-count its owner"
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 10,
            },
            Duration::from_micros(2),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: observed, ..
            }) if observed == slot
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 10);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 10);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 10);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    fn retain_post_cap_parser_boundary(
        controller: &mut QcsdController,
        endpoint: QcsdEndpointId,
        stream: QcsdStreamId,
        role: QcsdRequestRole,
    ) {
        controller
            .streams
            .open(endpoint, stream, role, true, 1, 16, 1);
        controller
            .streams
            .get_mut(endpoint, stream)
            .expect("controlled stream")
            .receive
            .bytes_read(1);
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(matches!(
            controller
                .drain_actions()
                .find(|action| matches!(action, QcsdAction::LeaseParserReceive { .. })),
            Some(QcsdAction::LeaseParserReceive {
                absolute_limit: 17,
                increase: 16,
                owner: None,
                ..
            })
        ));
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit: 17,
                slot: None,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 16,
            },
            Duration::ZERO,
        );
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream,
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::ZERO,
        );
        assert!(
            controller
                .drain_actions()
                .all(|action| !matches!(action, QcsdAction::LeaseParserReceive { .. }))
        );
    }

    #[test]
    fn retained_parser_boundary_waits_for_the_next_control_interval() {
        let packet =
            Packet::new(Duration::from_millis(6), Direction::Incoming, 10).expect("packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 16,
                control_interval_us: 5_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        ready(&mut controller, 1, "https://example.com");
        retain_post_cap_parser_boundary(
            &mut controller,
            endpoint,
            stream,
            QcsdRequestRole::Application,
        );

        // The defense event exists at 7.5 ms, but its deterministic incoming
        // allocation boundary is 10 ms. A per-stream parser retry must not
        // steal it from the normal allocator at the earlier 5 ms boundary.
        controller.poll(Duration::from_micros(7_500));
        assert!(
            controller
                .drain_actions()
                .all(|action| !matches!(action, QcsdAction::LeaseParserReceive { .. }))
        );
        assert!(controller.control.claims.is_empty());
        assert_eq!(controller.control.incoming_backlog(), 10);
        // The requested-credit observation is delivered on one immediate
        // reducer pass. Re-polling at the same wall time still cannot advance
        // the rounded incoming boundary or bind the retained stream.
        assert_eq!(controller.next_deadline(), Some(Duration::ZERO));
        controller.poll(Duration::from_micros(7_500));
        assert!(
            controller
                .drain_actions()
                .all(|action| !matches!(action, QcsdAction::LeaseParserReceive { .. }))
        );
        assert!(controller.control.claims.is_empty());
        assert_eq!(controller.control.incoming_backlog(), 10);
        assert_eq!(controller.next_deadline(), Some(Duration::from_millis(10)));

        controller.poll(Duration::from_millis(10));
        assert!(matches!(
            controller
                .drain_actions()
                .find(|action| matches!(action, QcsdAction::LeaseParserReceive { .. })),
            Some(QcsdAction::LeaseParserReceive {
                endpoint: observed_endpoint,
                stream: observed_stream,
                absolute_limit: 27,
                increase: 10,
                owner: Some(QcsdParserLeaseOwner { packet: observed, .. }),
            }) if observed_endpoint == endpoint && observed_stream == stream && observed == packet
        ));
        assert!(controller.control.incoming.is_empty());
        assert!(controller.control.claims.is_empty());
    }

    #[test]
    fn retained_parser_boundaries_follow_multi_endpoint_round_robin() {
        let first = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("first packet");
        let second =
            Packet::new(Duration::from_millis(5), Direction::Incoming, 10).expect("second");
        let (defense, _) = RecordingDefense::new([first, second], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 16,
                control_interval_us: 5_000,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        for (endpoint, stream) in [
            (QcsdEndpointId(1), QcsdStreamId(4)),
            (QcsdEndpointId(2), QcsdStreamId(8)),
        ] {
            ready(
                &mut controller,
                endpoint.0,
                &format!("https://{}.example.com", endpoint.0),
            );
            retain_post_cap_parser_boundary(
                &mut controller,
                endpoint,
                stream,
                QcsdRequestRole::Application,
            );
        }

        for (at, expected_endpoint, expected_packet) in [
            (Duration::ZERO, QcsdEndpointId(1), first),
            (Duration::from_millis(5), QcsdEndpointId(2), second),
        ] {
            controller.poll(at);
            let lease = controller
                .drain_actions()
                .find_map(|action| match action {
                    QcsdAction::LeaseParserReceive {
                        endpoint,
                        owner: Some(owner),
                        ..
                    } => Some((endpoint, owner.packet)),
                    _ => None,
                })
                .expect("scheduled parser continuation");
            assert_eq!(lease, (expected_endpoint, expected_packet));
        }
    }

    #[test]
    fn retained_parser_boundaries_keep_application_before_chaff() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 10).expect("packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let chaff_endpoint = QcsdEndpointId(1);
        let application_endpoint = QcsdEndpointId(2);
        ready(&mut controller, 1, "https://chaff.example.com");
        ready(&mut controller, 2, "https://application.example.com");
        retain_post_cap_parser_boundary(
            &mut controller,
            chaff_endpoint,
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        retain_post_cap_parser_boundary(
            &mut controller,
            application_endpoint,
            QcsdStreamId(8),
            QcsdRequestRole::Application,
        );

        controller.poll(Duration::ZERO);
        let endpoint = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::LeaseParserReceive {
                    endpoint,
                    owner: Some(_),
                    ..
                } => Some(endpoint),
                _ => None,
            })
            .expect("scheduled parser continuation");
        assert_eq!(endpoint, application_endpoint);
        assert!(controller.control.incoming.is_empty());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the shared FRONT/WTF and Tamaraw/WT allocation modes use one repeated-frame oracle"
    )]
    fn repeated_post_estimate_frames_recycle_only_scheduled_parser_bytes() {
        for mode in [DefenseMode::ChaffOnly, DefenseMode::ChaffAndShape] {
            let manifest = ResourceManifest {
                resources: vec![Resource {
                    id: 0,
                    url: "https://example.com/chaff".into(),
                    kind: "Document".into(),
                    content_length: Some(1),
                    data_length: 1,
                    chaff_priority: false,
                    known_valid: true,
                    depends_on: Vec::new(),
                    headers: Vec::new(),
                }],
            };
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    initial_max_stream_data: 1,
                    max_stream_data_excess: 16,
                    control_interval_us: 1,
                    ..QcsdConfig::default()
                },
                Some(manifest),
                Box::new(StaticSchedule::with_mode(Trace::default(), mode)),
            )
            .expect("controller");
            let endpoint = QcsdEndpointId(1);
            let stream = QcsdStreamId(4);
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Chaff {
                        resource_id: 0,
                        request_id: None,
                    },
                    expected_response_length: None,
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller
                .streams
                .get_mut(endpoint, stream)
                .expect("chaff stream")
                .receive
                .bytes_read(1);

            // One genuinely unowned frame consumes the complete configured
            // allowance. It is never recycled because no slot owned it.
            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
            let QcsdAction::LeaseParserReceive {
                absolute_limit: 17,
                increase: 16,
                ..
            } = controller.next_action().expect("unowned lease")
            else {
                panic!("expected complete unowned allowance");
            };
            controller.observe(
                QcsdObservation::ReceiveLimitAdvertised {
                    endpoint,
                    stream,
                    absolute_limit: 17,
                    slot: None,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::BytesRead {
                    endpoint,
                    stream,
                    bytes: 16,
                },
                Duration::ZERO,
            );
            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
            assert!(controller.next_action().is_none());

            let packet = Packet::new(Duration::ZERO, Direction::Incoming, 64).expect("packet");
            let slot = QcsdSlotId(44);
            controller.pending_slots.insert(slot, packet);
            controller
                .incoming_credit_ledger
                .insert(slot, IncomingCreditLedger::new(packet));
            controller.scheduled_incoming_requested_bytes = 64;
            controller.control.incoming.push(PendingIncoming {
                slot,
                packet,
                endpoint: None,
                remaining: 64,
            });
            controller.poll(Duration::ZERO);

            for part in 0_u64..4 {
                let lease = controller
                    .drain_actions()
                    .find_map(|action| match action {
                        QcsdAction::LeaseParserReceive {
                            absolute_limit,
                            increase,
                            ..
                        } => Some((absolute_limit, increase)),
                        _ => None,
                    })
                    .expect("scheduled continuation");
                assert_eq!(lease, (33 + part * 16, 16));
                controller.observe(
                    QcsdObservation::ReceiveLimitAdvertised {
                        endpoint,
                        stream,
                        absolute_limit: lease.0,
                        slot: None,
                    },
                    Duration::from_micros(part + 1),
                );
                controller.observe(
                    QcsdObservation::BytesRead {
                        endpoint,
                        stream,
                        bytes: 16,
                    },
                    Duration::from_micros(part + 1),
                );
                if part < 3 {
                    controller.observe(
                        QcsdObservation::HeaderProgress {
                            endpoint,
                            stream,
                            min_remaining: 1,
                            awaiting_data_frame: true,
                        },
                        Duration::from_micros(part + 1),
                    );
                    // Remaining scheduled work is assigned only on the next
                    // normal control boundary; the retained parser boundary
                    // is retried immediately after that allocation.
                    controller.poll(Duration::from_micros(part + 1));
                }
            }
            assert!(matches!(
                controller.next_action(),
                Some(QcsdAction::SlotSatisfied {
                    slot: observed, ..
                }) if observed == slot
            ));
            assert!(controller.control.incoming.is_empty());
            assert!(controller.control.claims.is_empty());
            assert!(controller.parser_lease_ranges.is_empty());
            let diagnostics = controller.defense_diagnostics();
            assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 64);
            assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 64);
            assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
            assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "stream and endpoint closure are one parser-lease lifecycle oracle"
    )]
    fn parser_lease_actions_are_removed_on_stream_and_endpoint_close() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 1,
                max_stream_data_excess: 16,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(Trace::default(), false)),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        ready(&mut controller, 1, "https://example.com");
        for stream in [QcsdStreamId(0), QcsdStreamId(4)] {
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint,
                    stream,
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(1),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);
            controller
                .streams
                .get_mut(endpoint, stream)
                .expect("opened stream")
                .receive
                .bytes_read(1);
            controller.observe(
                QcsdObservation::HeaderProgress {
                    endpoint,
                    stream,
                    min_remaining: 1,
                    awaiting_data_frame: true,
                },
                Duration::ZERO,
            );
        }
        assert_eq!(controller.parser_lease_ranges.len(), 2);

        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream: QcsdStreamId(0),
                finish: QcsdStreamFinish::Reset,
            },
            Duration::from_micros(1),
        );
        assert!(
            !controller
                .parser_lease_ranges
                .contains_key(&(endpoint, QcsdStreamId(0)))
        );
        assert!(
            controller
                .parser_lease_ranges
                .contains_key(&(endpoint, QcsdStreamId(4)))
        );
        let leases: Vec<_> = controller
            .drain_actions()
            .filter_map(|action| match action {
                QcsdAction::LeaseParserReceive { stream, .. } => Some(stream),
                _ => None,
            })
            .collect();
        assert_eq!(leases, [QcsdStreamId(4)]);

        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream: QcsdStreamId(4),
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(2),
        );
        // The duplicate boundary is capped/idempotent and creates no action.
        assert!(controller.next_action().is_none());
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream: QcsdStreamId(8),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1),
            },
            Duration::from_micros(2),
        );
        controller.drain_actions().for_each(drop);
        controller
            .streams
            .get_mut(endpoint, QcsdStreamId(8))
            .expect("opened stream")
            .receive
            .bytes_read(1);
        controller.observe(
            QcsdObservation::HeaderProgress {
                endpoint,
                stream: QcsdStreamId(8),
                min_remaining: 1,
                awaiting_data_frame: true,
            },
            Duration::from_micros(2),
        );
        assert!(matches!(
            controller.actions.front(),
            Some(QcsdAction::LeaseParserReceive {
                stream: QcsdStreamId(8),
                ..
            })
        ));
        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(3),
        );
        assert!(controller.next_action().is_none());
        assert!(controller.parser_lease_ranges.is_empty());
    }

    #[test]
    fn unsatisfied_credit_is_only_retried_at_the_next_interval() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 1_200).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 100,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );

        controller.observe(
            QcsdObservation::DataFrame {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                frame_header_bytes: 2,
                data_bytes: 2_000,
            },
            Duration::from_millis(1),
        );
        controller.poll(Duration::from_millis(1));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        controller.poll(Duration::from_millis(5));
        assert!(
            controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
    }

    #[test]
    fn late_outgoing_slot_is_missed_before_transport() {
        let trace = Trace::new([
            Packet::new(Duration::from_millis(1), Direction::Outgoing, 1_200).expect("packet"),
        ]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.poll(Duration::from_millis(10));
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                slot: QcsdSlotId(0),
                reason: MissedSlotReason::DeadlineExpired,
                ..
            })
        ));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
    }

    #[test]
    fn delayed_congestion_sensitive_one_shot_gets_one_fresh_transport_window() {
        let packet =
            Packet::new(Duration::from_millis(1), Direction::Outgoing, 600).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(CongestionSensitiveOneShot {
                event: Some(packet),
            }),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");

        // The timer was handled well after a fixed slot would have expired.
        // A CS one-shot keeps its original timestamp for trace provenance but
        // is activated once with a fresh transport-resolution window.
        controller.poll(Duration::from_millis(10));
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket {
                packet: observed,
                deadline_after_us: 5_000,
                send_policy: QcsdSendPolicy::CongestionSensitive,
                ..
            } if *observed == packet
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::DeadlineExpired,
                ..
            }
        )));
    }

    #[test]
    fn congestion_sensitive_no_endpoint_is_terminal_once_when_generic_retry_is_enabled() {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 600).expect("packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: false,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(CongestionSensitiveOneShot {
                event: Some(packet),
            }),
        )
        .expect("controller");

        controller.poll(Duration::ZERO);
        let first: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            first
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::SlotMissed {
                        reason: MissedSlotReason::NoEndpoint,
                        ..
                    }
                ))
                .count(),
            1
        );
        assert!(controller.control.outgoing.is_empty());
        assert!(controller.pending_slots().is_empty());

        controller.poll(Duration::from_millis(1));
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::NoEndpoint,
                ..
            }
        )));
    }

    #[test]
    fn candidate_completion_waits_for_queued_chaff_request_terminalization() {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 600).expect("packet");
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Other".into(),
                content_length: Some(1_000),
                data_length: 1_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                low_watermark: 1_000,
                max_chaff_streams: 1,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(CongestionSensitiveOneShot {
                event: Some(packet),
            }),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);

        controller.request_chaff_if_needed(true);
        assert_eq!(controller.defense.next_event(Duration::ZERO), Some(packet));
        controller.update_completion(Duration::ZERO);
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| { matches!(action, QcsdAction::DefenseComplete) })
        );

        let request_id = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::RequestChaff { request_id, .. } => Some(request_id),
                _ => None,
            })
            .expect("queued chaff request");
        controller.observe(
            QcsdObservation::ChaffRequestFailed {
                resource_id: 7,
                request_id: Some(request_id),
            },
            Duration::ZERO,
        );
        controller.update_completion(Duration::ZERO);
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::DefenseComplete)
        ));
    }

    #[test]
    fn buflo_terminal_drain_does_not_open_replacement_chaff() {
        let mut defense = Buflo::from_parameters(BufloParameters {
            schema_version: 1,
            interval_us: 10,
            minimum_duration_us: 30,
            packet_size: 1_200,
            max_events: 100,
            implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
            paper_equivalent: false,
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });
        for at in [0, 10, 20, 30] {
            while defense.next_event(Duration::from_micros(at)).is_some() {}
        }
        assert!(!defense.accepts_new_chaff_requests());
        assert!(!defense.is_complete());

        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Other".into(),
                content_length: Some(10_000),
                data_length: 10_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                low_watermark: 1_000,
                max_chaff_streams: 1,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);

        controller.request_chaff_if_needed(true);

        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::RequestChaff { .. }))
        );
        assert_eq!(
            controller
                .chaff
                .as_ref()
                .map_or(0, super::ChaffManager::pending_count),
            0
        );
    }

    fn resolved_buflo_terminal_defense(application_complete: bool) -> Buflo {
        let mut defense = Buflo::from_parameters(BufloParameters {
            schema_version: 1,
            interval_us: 10,
            minimum_duration_us: 30,
            packet_size: 1_200,
            max_events: 100,
            implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
            paper_equivalent: false,
        });
        if application_complete {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(5),
                kind: SignalKind::ApplicationComplete,
            });
        }
        let mut scheduled = Vec::new();
        for at in [0, 10, 20, 30] {
            while let Some(packet) = defense.next_event(Duration::from_micros(at)) {
                scheduled.push(packet);
            }
        }
        for packet in scheduled {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(30),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: EventOutcome::Satisfied { observed: 1_200 },
                },
            });
        }
        assert_eq!(defense.accepts_new_chaff_requests(), !application_complete);
        assert!(!defense.is_complete());
        defense
    }

    fn buflo_terminal_capacity_controller(expected_raw_bytes: u64) -> QcsdController {
        let defense = resolved_buflo_terminal_defense(true);

        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 10,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        ready(&mut controller, endpoint.0, "https://example.com");
        controller.drain_actions().for_each(drop);
        controller.streams.open(
            endpoint,
            QcsdStreamId(4),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            expected_raw_bytes,
        );
        controller
    }

    fn open_additional_terminal_chaff(
        controller: &mut QcsdController,
        stream: u64,
        expected_raw_bytes: u64,
    ) {
        controller.streams.open(
            QcsdEndpointId(1),
            QcsdStreamId(stream),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            expected_raw_bytes,
        );
    }

    #[test]
    fn buflo_terminal_capacity_is_aggregated_across_open_streams() {
        let mut subcell = buflo_terminal_capacity_controller(616);
        open_additional_terminal_chaff(&mut subcell, 8, 615);
        subcell.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        subcell.poll(Duration::from_micros(31));
        assert!(subcell.defense.is_complete());
        assert_eq!(subcell.streams.open_chaff_count(), 0);
        assert_eq!(
            subcell
                .actions
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::CancelChaff {
                        reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                        ..
                    }
                ))
                .count(),
            2
        );
        let diagnostics = subcell.defense_diagnostics();
        assert_eq!(diagnostics.buflo_terminal_subcell_open_streams_at_latch, 2);
        assert_eq!(diagnostics.buflo_terminal_subcell_stream_cancellations, 2);
        assert_eq!(
            diagnostics.buflo_terminal_subcell_exact_capacity_bytes_cancelled,
            1_199
        );

        let mut whole = buflo_terminal_capacity_controller(616);
        open_additional_terminal_chaff(&mut whole, 8, 616);
        whole.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        whole.poll(Duration::from_micros(31));
        assert!(!whole.defense.is_complete());
        assert_eq!(
            whole.defense.next_event_at(),
            Some(Duration::from_micros(40))
        );
        assert!(
            !whole
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::CancelChaff { .. }))
        );
        whole.poll(Duration::from_micros(40));
        let next_pair: Vec<_> = whole.drain_actions().collect();
        assert_eq!(
            next_pair
                .iter()
                .filter(|action| {
                    matches!(
                        action,
                        QcsdAction::SendPacket { .. } | QcsdAction::CommitPrearmedPacket { .. }
                    )
                })
                .count(),
            1
        );
        let advertised: Vec<_> = next_pair
            .iter()
            .filter_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { absolute_limit, .. } => Some(*absolute_limit),
                _ => None,
            })
            .collect();
        assert_eq!(advertised, [616, 616]);
        assert_eq!(
            advertised.iter().map(|limit| limit - 16).sum::<u64>(),
            1_200
        );
    }

    #[test]
    fn buflo_terminal_failure_never_receipts_a_subcell_cancellation() {
        let parameters = BufloParameters {
            schema_version: 1,
            interval_us: 10,
            minimum_duration_us: 30,
            packet_size: 1_200,
            max_events: 1,
            implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
            paper_equivalent: false,
        };
        let mut defense = Buflo::from_parameters(parameters);
        while defense.next_event(Duration::ZERO).is_some() {}
        assert_eq!(defense.next_event(Duration::from_micros(10)), None);
        assert!(defense.terminal_failure().is_some());
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);
        open_additional_terminal_chaff(&mut controller, 4, 1_215);

        controller.terminalize_local_chaff(Duration::from_micros(31));

        assert_eq!(controller.streams.open_chaff_count(), 1);
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::CancelChaff { .. }))
        );
        let diagnostics = controller.defense_diagnostics();
        assert!(!diagnostics.buflo_terminal_subcell_latched);
        assert_eq!(diagnostics.buflo_terminal_subcell_stream_cancellations, 0);
    }

    #[test]
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "both sides of the exact 1,200-byte terminal boundary share one proof"
    )]
    fn buflo_terminal_open_chaff_backlog_requires_a_whole_cell() {
        // known_limit - requested_limit = 1,199: no exact cell exists.
        let mut subcell = buflo_terminal_capacity_controller(1_215);
        subcell.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        subcell.poll(Duration::from_micros(31));
        assert!(subcell.defense.is_complete());
        assert_eq!(subcell.defense.next_event_at(), None);
        assert_eq!(subcell.streams.open_chaff_count(), 0);
        let first_actions: Vec<_> = subcell.drain_actions().collect();
        assert_eq!(
            first_actions
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::CancelChaff {
                        reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                        ..
                    }
                ))
                .count(),
            1
        );
        assert!(
            !first_actions
                .iter()
                .any(|action| matches!(action, QcsdAction::DefenseComplete))
        );
        assert!(!first_actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket { .. }
                | QcsdAction::IncreaseReceiveLimit { .. }
                | QcsdAction::SlotMissed { .. }
        )));
        let diagnostics = subcell.defense_diagnostics();
        assert_eq!(diagnostics.buflo_terminal_subcell_stream_cancellations, 1);
        assert!(diagnostics.buflo_terminal_subcell_latched);
        assert_eq!(diagnostics.buflo_terminal_subcell_latched_at_us, 31);
        assert_eq!(diagnostics.buflo_terminal_subcell_open_streams_at_latch, 1);
        assert_eq!(
            diagnostics.buflo_terminal_subcell_parser_lease_bytes_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_parser_boundaries_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_exact_capacity_bytes_cancelled,
            1_199
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_request_cancellations,
            0
        );
        assert_eq!(diagnostics.cs_buflo_local_et_stream_cancellations, 0);
        assert_eq!(
            diagnostics.cs_buflo_local_et_pending_request_cancellations,
            0
        );
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);

        subcell.poll(Duration::from_micros(40));
        assert!(
            subcell
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::DefenseComplete))
        );

        // Exactly one full 1,200-byte opportunity remains: it is backlog and
        // must produce the next pair instead of being terminalized.
        let mut whole = buflo_terminal_capacity_controller(1_216);
        whole.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        whole.poll(Duration::from_micros(31));
        assert!(!whole.defense.is_complete());
        assert_eq!(
            whole.defense.next_event_at(),
            Some(Duration::from_micros(40))
        );
        whole.poll(Duration::from_micros(40));
        let next_pair: Vec<_> = whole.drain_actions().collect();
        assert_eq!(
            next_pair
                .iter()
                .filter(|action| {
                    matches!(
                        action,
                        QcsdAction::SendPacket { .. } | QcsdAction::CommitPrearmedPacket { .. }
                    )
                })
                .count(),
            1
        );
        assert_eq!(
            next_pair
                .iter()
                .filter(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
                .count(),
            1,
            "actions: {next_pair:?}"
        );
        assert!(!next_pair.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff { .. } | QcsdAction::SlotMissed { .. }
        )));
    }

    #[test]
    fn buflo_terminal_cancellation_backlog_cannot_reopen_schedule() {
        let mut controller = buflo_terminal_capacity_controller(1_215);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        assert!(controller.defense.is_complete());
        assert!(controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff {
                reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                ..
            }
        )));

        // The queued STOP_SENDING/RESET work makes effective backlog true on
        // this poll. The first eligible terminal boundary remains irreversible.
        controller.poll(Duration::from_micros(32));
        assert!(controller.defense.is_complete());
        assert_eq!(controller.defense.next_event_at(), None);
        controller.poll(Duration::from_micros(40));
        assert!(!controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket { .. }
                | QcsdAction::IncreaseReceiveLimit { .. }
                | QcsdAction::SlotMissed { .. }
        )));
    }

    #[test]
    fn buflo_terminal_waits_for_an_in_flight_parser_lease() {
        let mut controller = buflo_terminal_capacity_controller(1_215);
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        controller.parser_lease_ranges.insert(
            (endpoint, stream),
            vec![ParserLeaseRange {
                start: 16,
                end: 17,
                owner: None,
                unowned: true,
                advertised: true,
            }],
        );
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        assert!(!controller.defense.is_complete());
        assert!(!controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff { .. } | QcsdAction::DefenseComplete
        )));

        controller.parser_lease_ranges.remove(&(endpoint, stream));
        controller.poll(Duration::from_micros(32));
        assert!(controller.defense.is_complete());
        assert!(controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff {
                reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                ..
            }
        )));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.buflo_terminal_subcell_latched_at_us, 32);
        assert_eq!(
            diagnostics.buflo_terminal_subcell_parser_lease_bytes_at_latch,
            0
        );
    }

    #[test]
    fn buflo_terminal_rechecks_backlog_after_stale_false_before_onload() {
        let defense = resolved_buflo_terminal_defense(false);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 10,
                initial_max_stream_data: 16,
                max_stream_data_excess: 1_000,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        ready(&mut controller, endpoint.0, "https://example.com");
        controller.drain_actions().for_each(drop);

        // Establish the exact stale state involved in the race: the previous
        // controller snapshot was false while onLoad was not yet eligible.
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(30),
        );
        controller.poll(Duration::from_micros(30));
        assert_eq!(
            controller.last_effective_egress_backlog_pending,
            Some(false)
        );
        assert!(!controller.defense.is_complete());

        // Parser work appears between polls, before ApplicationComplete is
        // reduced. A stale false must not irreversibly latch and cancel it.
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_215,
        );
        controller.parser_lease_ranges.insert(
            (endpoint, stream),
            vec![ParserLeaseRange {
                start: 16,
                end: 17,
                owner: None,
                unowned: true,
                advertised: true,
            }],
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        assert!(!controller.defense.is_complete());
        assert!(
            controller
                .parser_lease_ranges
                .contains_key(&(endpoint, stream))
        );
        assert!(!controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff {
                reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                ..
            }
        )));

        controller.parser_lease_ranges.remove(&(endpoint, stream));
        controller.poll(Duration::from_micros(32));
        assert!(controller.defense.is_complete());
        assert!(controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff {
                reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                ..
            }
        )));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.buflo_terminal_subcell_latched_at_us, 32);
        assert_eq!(
            diagnostics.buflo_terminal_subcell_parser_lease_bytes_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_parser_boundaries_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch,
            0
        );
    }

    #[test]
    fn buflo_terminal_waits_for_a_retained_parser_boundary_without_a_live_lease() {
        let mut controller = buflo_terminal_capacity_controller(1_215);
        retain_post_cap_parser_boundary(
            &mut controller,
            QcsdEndpointId(1),
            QcsdStreamId(8),
            QcsdRequestRole::Application,
        );
        assert!(controller.parser_lease_ranges.is_empty());
        assert!(controller.streams.has_any_pending_parser_boundary());
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        assert!(!controller.defense.is_complete());
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::CancelChaff { .. }))
        );

        controller.streams.clear_parser_boundaries();
        controller.poll(Duration::from_micros(32));
        assert!(controller.defense.is_complete());
        assert!(controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelChaff {
                reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                ..
            }
        )));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_parser_boundaries_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch,
            0
        );
    }

    #[test]
    fn buflo_terminal_cancels_a_retained_chaff_boundary_with_a_subcell_tail() {
        // initial limit 16 leaves the exact 624-byte tail observed in the
        // canonical live regression (640 - 16). A second exhausted chaff
        // stream retains the HTTP/3 `awaiting_data_frame` parser boundary
        // which previously kept aggregate backlog true forever.
        let mut controller = buflo_terminal_capacity_controller(640);
        retain_post_cap_parser_boundary(
            &mut controller,
            QcsdEndpointId(1),
            QcsdStreamId(8),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
        );
        assert!(controller.parser_lease_ranges.is_empty());
        assert!(controller.streams.has_any_pending_parser_boundary());
        assert!(!controller.streams.has_pending_application_parser_boundary());

        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));

        assert!(controller.defense.is_complete());
        assert_eq!(controller.streams.open_chaff_count(), 0);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::CancelChaff {
                        reason: QcsdChaffCancellationReason::BufloTerminalSubcellTail,
                        ..
                    }
                ))
                .count(),
            2
        );
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::SendPacket { .. }
                | QcsdAction::IncreaseReceiveLimit { .. }
                | QcsdAction::SlotMissed { .. }
        )));
        let diagnostics = controller.defense_diagnostics();
        assert!(diagnostics.buflo_terminal_subcell_latched);
        assert_eq!(diagnostics.buflo_terminal_subcell_latched_at_us, 31);
        assert_eq!(diagnostics.buflo_terminal_subcell_open_streams_at_latch, 2);
        assert_eq!(
            diagnostics.buflo_terminal_subcell_exact_capacity_bytes_cancelled,
            624
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_parser_boundaries_at_latch,
            1
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_pending_application_parser_boundaries_at_latch,
            0
        );
        assert_eq!(
            diagnostics.buflo_terminal_subcell_parser_lease_bytes_at_latch,
            0
        );
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn buflo_rolling_prearm_commits_once_before_the_due_incoming_action() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        let preview_actions: Vec<_> = controller.drain_actions().collect();
        let preview_slot = preview_actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::PrearmPacket { packet, slot, .. } => {
                    assert_eq!(packet.timestamp(), Duration::from_micros(40));
                    Some(*slot)
                }
                _ => None,
            })
            .expect("future outgoing preview");
        assert!(controller.pending_slots().is_empty());
        assert_eq!(
            controller
                .defense_diagnostics()
                .buflo_scheduled_outgoing_cells,
            4
        );

        controller
            .reconcile_due_rolling(Duration::from_micros(40))
            .expect("reconcile due rolling preview");
        let due_actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            due_actions
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::CommitPrearmedPacket { slot, .. } if *slot == preview_slot
                ))
                .count(),
            1
        );
        assert!(
            !due_actions
                .iter()
                .any(|action| matches!(action, QcsdAction::SendPacket { .. }))
        );
        let incoming_slot = due_actions
            .iter()
            .find_map(|action| match action {
                QcsdAction::IncreaseReceiveLimit { slot, .. } => Some(*slot),
                _ => None,
            })
            .expect("due incoming action");
        assert!(preview_slot < incoming_slot);
        assert_eq!(
            controller
                .defense_diagnostics()
                .buflo_scheduled_outgoing_cells,
            5
        );
        assert_eq!(
            controller
                .defense_diagnostics()
                .buflo_scheduled_incoming_cells,
            5
        );

        controller
            .reconcile_due_rolling(Duration::from_micros(40))
            .expect("repeat rolling reconciliation is inert");
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::CommitPrearmedPacket { slot, .. } if slot == preview_slot
        )));
    }

    #[test]
    fn queued_buflo_miss_cancels_the_due_preview_without_materializing_the_next_cell() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        controller.drain_actions().for_each(drop);

        controller
            .reconcile_due_rolling(Duration::from_micros(40))
            .expect("reconcile current rolling event");
        let first_due: Vec<_> = controller.drain_actions().collect();
        let (realized_slot, realized_packet) = first_due
            .iter()
            .find_map(|action| match action {
                QcsdAction::CommitPrearmedPacket { packet, slot, .. }
                    if packet.timestamp() == Duration::from_micros(40) =>
                {
                    Some((*slot, *packet))
                }
                _ => None,
            })
            .expect("current exact cell commit");
        let (next_slot, next_packet) = first_due
            .iter()
            .find_map(|action| match action {
                QcsdAction::PrearmPacket { packet, slot, .. }
                    if packet.timestamp() == Duration::from_micros(50) =>
                {
                    Some((*slot, *packet))
                }
                _ => None,
            })
            .expect("following preview");

        controller.observe(
            QcsdObservation::SlotMissed {
                endpoint: QcsdEndpointId(1),
                slot: realized_slot,
                packet: realized_packet,
                reason: MissedSlotReason::DeadlineExpired,
            },
            Duration::from_micros(50),
        );
        controller
            .reconcile_due_rolling(Duration::from_micros(50))
            .expect("cancel following rolling preview");
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelPrearmedPacket {
                slot,
                packet,
                reason: QcsdPrearmCancellationReason::DefenseTerminal,
                ..
            } if *slot == next_slot && *packet == next_packet
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::CommitPrearmedPacket { slot, .. } if *slot == next_slot
        )));
        assert!(
            !controller
                .pending_slots()
                .iter()
                .any(|(slot, _)| *slot == next_slot)
        );
        assert!(controller.terminal_failure().is_some());
        assert_eq!(
            controller
                .defense_diagnostics()
                .buflo_scheduled_outgoing_cells,
            5,
            "the failed 40us cell must not materialize the 50us cell"
        );
    }

    #[test]
    fn closed_endpoint_preview_rearms_without_becoming_an_event() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        ready(&mut controller, 2, "https://second.example.com");
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::from_micros(31));
        let first = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("first endpoint preview");
        let QcsdAction::PrearmPacket {
            endpoint,
            packet,
            slot: first_slot,
            ..
        } = first
        else {
            unreachable!();
        };
        assert_eq!(endpoint, QcsdEndpointId(1));
        assert_eq!(packet.timestamp(), Duration::from_micros(40));
        assert_eq!(
            controller.rolling_outgoing_prearm_identity(),
            Some((endpoint, packet, first_slot))
        );

        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(32),
        );
        assert_eq!(
            controller.rolling_outgoing_prearm_endpoint(),
            Some(QcsdEndpointId(2))
        );
        controller.poll(Duration::from_micros(32));
        let actions: Vec<_> = controller.drain_actions().collect();
        let replacement = actions
            .iter()
            .find(|action| {
                matches!(
                    action,
                    QcsdAction::PrearmPacket {
                        endpoint: QcsdEndpointId(2),
                        packet: observed,
                        ..
                    } if *observed == packet
                )
            })
            .expect("preview rearmed on surviving endpoint");
        let QcsdAction::PrearmPacket {
            slot: replacement_slot,
            ..
        } = replacement
        else {
            unreachable!();
        };
        assert_ne!(*replacement_slot, first_slot);
        assert_eq!(
            controller.rolling_outgoing_prearm_endpoint(),
            Some(QcsdEndpointId(2))
        );
        assert_eq!(
            controller.rolling_outgoing_prearm_identity(),
            Some((QcsdEndpointId(2), packet, *replacement_slot))
        );
        assert!(controller.pending_slots().is_empty());
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::CommitPrearmedPacket { .. }
                | QcsdAction::CancelPrearmedPacket { .. }
                | QcsdAction::SlotMissed { .. }
                | QcsdAction::SlotSatisfied { .. }
        )));
        assert_eq!(
            controller
                .defense_diagnostics()
                .buflo_scheduled_outgoing_cells,
            4
        );
    }

    fn divergent_abandoned_rolling_controller(
        event: Option<Packet>,
        include_survivor: bool,
    ) -> (QcsdController, Packet) {
        let expected = Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_200)
            .expect("expected rolling packet");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 10,
                ..QcsdConfig::default()
            },
            None,
            Box::new(DivergentRollingDefense {
                preview: expected,
                event,
            }),
        )
        .expect("divergent rolling controller");
        ready(&mut controller, 1, "https://first.example.com");
        if include_survivor {
            ready(&mut controller, 2, "https://second.example.com");
        }
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::from_micros(31));
        let endpoint = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::PrearmPacket {
                    endpoint, packet, ..
                } if packet == expected => Some(endpoint),
                _ => None,
            })
            .expect("initial divergent preview");
        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(41),
        );
        controller.flush_defense_observations();
        assert!(controller.has_due_rolling_reconciliation());
        (controller, expected)
    }

    #[test]
    fn divergent_late_rolling_events_fail_closed_without_erasing_the_due_marker() {
        let wrong = Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_199)
            .expect("wrong rolling packet");
        for (event, expected_message) in [
            (None, "returned no event"),
            (Some(wrong), "for late abandoned rolling identity"),
        ] {
            let (mut controller, expected) = divergent_abandoned_rolling_controller(event, false);
            let error = controller
                .reconcile_due_rolling(Duration::from_micros(41))
                .expect_err("divergent defense must fail closed");
            assert!(matches!(
                error,
                crate::Error::ControllerInvariant(message)
                    if message.contains(expected_message)
            ));
            assert_eq!(
                controller.rolling_reconciliation_due_packet(),
                Some(expected)
            );
            assert!(controller.pending_slots().is_empty());
            assert!(matches!(
                controller.reconcile_due_rolling(Duration::from_micros(41)),
                Err(crate::Error::ControllerInvariant(_))
            ));
            assert_eq!(
                controller.rolling_reconciliation_due_packet(),
                Some(expected)
            );
        }
    }

    #[test]
    fn divergent_ordinary_due_events_leave_the_live_preview_abort_cancelable() {
        let expected = Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_200)
            .expect("expected rolling packet");
        let wrong = Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_199)
            .expect("wrong rolling packet");
        for event in [None, Some(wrong)] {
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    control_interval_us: 10,
                    ..QcsdConfig::default()
                },
                None,
                Box::new(DivergentRollingDefense {
                    preview: expected,
                    event,
                }),
            )
            .expect("divergent rolling controller");
            ready(&mut controller, 1, "https://first.example.com");
            controller.drain_actions().for_each(drop);
            controller.poll(Duration::from_micros(31));
            controller.drain_actions().for_each(drop);

            assert!(matches!(
                controller.reconcile_due_rolling(Duration::from_micros(40)),
                Err(crate::Error::ControllerInvariant(message))
                    if message.contains("did not materialize due rolling identity")
            ));
            assert_eq!(controller.rolling_outgoing_prearm.unwrap().packet, expected);
            assert!(matches!(
                controller.take_rolling_prearm_for_abort(),
                Some(QcsdAction::CancelPrearmedPacket {
                    packet,
                    reason: QcsdPrearmCancellationReason::RunAborted,
                    ..
                }) if packet == expected
            ));
        }
    }

    #[test]
    fn mismatched_live_replacement_fails_before_preview_or_action_is_consumed() {
        let expected = Packet::new(Duration::from_micros(40), Direction::Outgoing, 1_200)
            .expect("expected rolling packet");
        let (mut controller, _) = divergent_abandoned_rolling_controller(Some(expected), true);
        let wrong = Packet::new(Duration::from_micros(41), Direction::Outgoing, 1_200)
            .expect("wrong replacement packet");
        controller
            .rolling_outgoing_prearm
            .as_mut()
            .expect("replacement preview")
            .packet = wrong;

        assert!(matches!(
            controller.reconcile_due_rolling(Duration::from_micros(41)),
            Err(crate::Error::ControllerInvariant(message))
                if message.contains("conflicts with live preview")
        ));
        assert_eq!(
            controller.rolling_reconciliation_due_packet(),
            Some(expected)
        );
        assert_eq!(
            controller
                .rolling_outgoing_prearm
                .expect("mismatched preview retained")
                .packet,
            wrong
        );
        assert!(controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket { packet, .. } if *packet == expected
        )));
    }

    #[test]
    fn closed_endpoint_preview_transfers_and_commits_at_exact_release() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        ready(&mut controller, 2, "https://second.example.com");
        controller.streams.open(
            QcsdEndpointId(2),
            QcsdStreamId(8),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_216,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::from_micros(31));
        let first = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("first endpoint preview");
        let QcsdAction::PrearmPacket {
            endpoint,
            packet,
            slot: first_slot,
            ..
        } = first
        else {
            unreachable!();
        };

        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(40),
        );
        controller.flush_defense_observations();
        controller
            .reconcile_due_rolling(Duration::from_micros(40))
            .expect("transfer due rolling preview");
        let actions: Vec<_> = controller.drain_actions().collect();
        let (prearm_index, replacement_slot) = actions
            .iter()
            .enumerate()
            .find_map(|(index, action)| match action {
                QcsdAction::PrearmPacket {
                    endpoint: QcsdEndpointId(2),
                    packet: observed,
                    slot,
                    not_before_after_us: 0,
                    deadline_after_us: 10,
                    ..
                } if *observed == packet => Some((index, *slot)),
                _ => None,
            })
            .expect("due preview transferred to survivor");
        let commit_index = actions
            .iter()
            .position(|action| {
                matches!(
                    action,
                    QcsdAction::CommitPrearmedPacket {
                        endpoint: QcsdEndpointId(2),
                        packet: observed,
                        slot,
                    } if *observed == packet && *slot == replacement_slot
                )
            })
            .expect("transferred preview committed in the same microstep");
        assert!(prearm_index < commit_index);
        assert_ne!(replacement_slot, first_slot);
        assert!(
            controller
                .pending_slots()
                .contains(&(replacement_slot, packet))
        );
    }

    #[test]
    fn closed_endpoint_preview_one_microsecond_late_is_a_typed_fidelity_failure() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        ready(&mut controller, 2, "https://second.example.com");
        controller.streams.open(
            QcsdEndpointId(2),
            QcsdStreamId(8),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_216,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::from_micros(31));
        let first = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("first endpoint preview");
        let QcsdAction::PrearmPacket {
            endpoint, packet, ..
        } = first
        else {
            unreachable!();
        };

        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(41),
        );
        controller.flush_defense_observations();
        controller
            .reconcile_due_rolling(Duration::from_micros(41))
            .expect("terminalize late rolling preview");
        let actions: Vec<_> = controller.drain_actions().collect();
        let misses: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::SlotMissed {
                    packet,
                    reason: MissedSlotReason::TimerLate,
                    ..
                } if packet.timestamp() == Duration::from_micros(40) => Some(packet.direction()),
                _ => None,
            })
            .collect();
        assert_eq!(misses, [Direction::Outgoing, Direction::Incoming]);
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::CommitPrearmedPacket {
                packet: observed, ..
            } if *observed == packet
        )));
        assert!(controller.terminal_failure().is_some());
        controller
            .reconcile_due_rolling(Duration::from_micros(41))
            .expect("repeat late reconciliation is inert");
        assert!(controller.drain_actions().next().is_none());
    }

    #[test]
    fn later_observation_in_close_batch_precedes_due_preview_reconciliation() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        ready(&mut controller, 2, "https://second.example.com");
        controller.streams.open(
            QcsdEndpointId(2),
            QcsdStreamId(8),
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_216,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::from_micros(31));
        let first = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("first endpoint preview");
        let QcsdAction::PrearmPacket {
            endpoint, packet, ..
        } = first
        else {
            unreachable!();
        };

        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(40),
        );
        assert!(controller.has_due_rolling_reconciliation());
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(2),
                stream: QcsdStreamId(8),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(40),
        );
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(40),
        );
        controller.flush_defense_observations();
        controller
            .reconcile_due_rolling(Duration::from_micros(40))
            .expect("reconcile after complete observation batch");
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(controller.defense.is_complete());
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::CommitPrearmedPacket {
                packet: observed, ..
            } if *observed == packet
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket {
                packet: observed, ..
            } if *observed == packet
        )));
        assert!(
            !controller
                .pending_slots()
                .iter()
                .any(|(_, observed)| *observed == packet)
        );
    }

    #[test]
    fn expired_abandoned_preview_gets_immediate_typed_deadline_misses() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("preview");
        let QcsdAction::PrearmPacket { endpoint, .. } = preview else {
            unreachable!();
        };

        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(50),
        );
        assert!(controller.has_due_rolling_reconciliation());
        assert!(!controller.has_rolling_outgoing_prearm());
        controller.flush_defense_observations();
        controller
            .reconcile_due_rolling(Duration::from_micros(50))
            .expect("terminalize expired rolling preview");
        let actions: Vec<_> = controller.drain_actions().collect();
        let misses: Vec<_> = actions
            .iter()
            .filter_map(|action| match action {
                QcsdAction::SlotMissed {
                    packet,
                    reason: MissedSlotReason::DeadlineExpired,
                    ..
                } if packet.timestamp() == Duration::from_micros(40) => Some(packet.direction()),
                _ => None,
            })
            .collect();
        assert_eq!(misses, [Direction::Outgoing, Direction::Incoming]);
        assert!(controller.terminal_failure().is_some());
        assert!(!controller.has_due_rolling_reconciliation());
    }

    #[test]
    fn buflo_terminal_snapshot_cancels_an_applied_preview_without_an_event_outcome() {
        let defense = resolved_buflo_terminal_defense(true);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 10,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::from_micros(31));
        let prearm = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("preview staged while adapter backlog remained true");
        let QcsdAction::PrearmPacket { slot, packet, .. } = prearm else {
            unreachable!();
        };
        assert!(controller.pending_slots().is_empty());

        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(32),
        );
        controller.poll(Duration::from_micros(32));
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::CancelPrearmedPacket {
                slot: observed_slot,
                packet: observed_packet,
                reason: QcsdPrearmCancellationReason::DefenseTerminal,
                ..
            } if *observed_slot == slot && *observed_packet == packet
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed { .. }
                | QcsdAction::SlotSatisfied { .. }
                | QcsdAction::CommitPrearmedPacket { .. }
        )));
        assert!(controller.pending_slots().is_empty());
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.buflo_scheduled_outgoing_cells, 4);
        assert_eq!(diagnostics.buflo_missed_outgoing_cells, 0);
        assert_eq!(diagnostics.buflo_outgoing_unresolved_cells, 0);
    }

    #[test]
    fn rolling_prearm_abort_removes_an_unapplied_preview_and_returns_one_cancellation() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));

        let preview = controller
            .actions
            .iter()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .cloned()
            .expect("queued preview");
        let QcsdAction::PrearmPacket {
            endpoint,
            packet,
            slot,
            ..
        } = preview
        else {
            unreachable!();
        };
        assert_eq!(
            controller.take_rolling_prearm_for_abort(),
            Some(QcsdAction::CancelPrearmedPacket {
                endpoint,
                packet,
                slot,
                reason: QcsdPrearmCancellationReason::RunAborted,
            })
        );
        assert!(!controller.has_rolling_outgoing_prearm());
        assert!(!controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::PrearmPacket { .. } | QcsdAction::CancelPrearmedPacket { .. }
        )));
        assert!(controller.take_rolling_prearm_for_abort().is_none());
    }

    #[test]
    fn rolling_prearm_abort_returns_one_cancellation_after_adapter_handoff() {
        let mut controller = buflo_terminal_capacity_controller(1_216);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(31),
        );
        controller.poll(Duration::from_micros(31));
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("adapter-bound preview");
        let QcsdAction::PrearmPacket {
            endpoint,
            packet,
            slot,
            ..
        } = preview
        else {
            unreachable!();
        };

        assert_eq!(
            controller.take_rolling_prearm_for_abort(),
            Some(QcsdAction::CancelPrearmedPacket {
                endpoint,
                packet,
                slot,
                reason: QcsdPrearmCancellationReason::RunAborted,
            })
        );
        assert!(controller.take_rolling_prearm_for_abort().is_none());
    }

    #[test]
    fn abort_normalizes_an_already_queued_terminal_preview_cancellation_once() {
        let defense = resolved_buflo_terminal_defense(true);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 10,
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::from_micros(31));
        let preview = controller
            .drain_actions()
            .find(|action| matches!(action, QcsdAction::PrearmPacket { .. }))
            .expect("adapter-bound preview");
        let QcsdAction::PrearmPacket {
            endpoint,
            packet,
            slot,
            ..
        } = preview
        else {
            unreachable!();
        };

        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(32),
        );
        controller.poll(Duration::from_micros(32));
        assert_eq!(
            controller
                .actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::CancelPrearmedPacket { .. }))
                .count(),
            1
        );
        assert_eq!(
            controller.take_rolling_prearm_for_abort(),
            Some(QcsdAction::CancelPrearmedPacket {
                endpoint,
                packet,
                slot,
                reason: QcsdPrearmCancellationReason::RunAborted,
            })
        );
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::CancelPrearmedPacket { .. }))
        );
        assert!(controller.take_rolling_prearm_for_abort().is_none());
    }

    #[test]
    fn local_et_cancels_an_open_chaff_stream_before_defense_complete() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(CompleteLocalEtDefense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(4);
        ready(&mut controller, 1, "https://example.com");
        controller.streams.open(
            endpoint,
            stream,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_000,
        );
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::ZERO,
        );

        controller.update_completion(Duration::ZERO);
        assert_eq!(controller.streams.open_chaff_count(), 0);
        assert_eq!(
            controller
                .actions
                .iter()
                .filter(|action| matches!(
                    action,
                    QcsdAction::CancelChaff {
                        endpoint: observed_endpoint,
                        stream: observed_stream,
                        reason: QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
                    } if *observed_endpoint == endpoint && *observed_stream == stream
                ))
                .count(),
            1
        );
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::DefenseComplete))
        );
        assert_eq!(
            controller
                .defense_diagnostics()
                .cs_buflo_local_et_stream_cancellations,
            1
        );

        controller.drain_actions().for_each(drop);
        controller.update_completion(Duration::ZERO);
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::DefenseComplete)
        ));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "This single scenario verifies the complete atomic local-termination handoff and its diagnostics."
    )]
    fn local_et_atomically_cancels_chaff_and_hands_application_traffic_to_neqo() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                automatic_receive_window: 65_535,
                ..QcsdConfig::default()
            },
            None,
            Box::new(CompleteLocalEtDefense),
        )
        .expect("controller");
        let first_endpoint = QcsdEndpointId(1);
        let second_endpoint = QcsdEndpointId(2);
        let application = QcsdStreamId(4);
        let chaff = QcsdStreamId(8);
        ready(&mut controller, 1, "https://one.example");
        ready(&mut controller, 2, "https://two.example");
        controller.open_stream(
            first_endpoint,
            application,
            QcsdRequestRole::Application,
            Some(2_000),
        );
        controller
            .streams
            .header_progress(first_endpoint, application, 0, true);
        let parser_release = controller
            .streams
            .release_stream(first_endpoint, application, 16)
            .expect("transferable parser range");
        controller
            .streams
            .get_mut(first_endpoint, application)
            .expect("application state")
            .receive
            .advertised(parser_release.absolute_limit);
        controller.parser_lease_ranges.insert(
            (first_endpoint, application),
            vec![ParserLeaseRange {
                start: parser_release.absolute_limit - parser_release.increase,
                end: parser_release.absolute_limit,
                owner: None,
                unowned: true,
                advertised: true,
            }],
        );
        controller.streams.open(
            first_endpoint,
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_000,
        );
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::from_micros(2_000_001),
        );

        controller.update_completion(Duration::from_micros(2_000_001));
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(matches!(
            actions.as_slice(),
            [
                QcsdAction::CancelChaff {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(8),
                    reason: QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
                },
                QcsdAction::ConfigureAutomaticReceive {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(4),
                    window: 65_535,
                },
                QcsdAction::ReleaseApplicationSendShaping {
                    endpoint: QcsdEndpointId(1),
                },
                QcsdAction::ReleaseApplicationSendShaping {
                    endpoint: QcsdEndpointId(2),
                },
            ]
        ));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::DefenseComplete))
        );
        assert!(controller.parser_lease_ranges.is_empty());
        let diagnostics = controller.defense_diagnostics();
        assert!(diagnostics.cs_buflo_local_et_before_application_complete);
        assert_eq!(
            diagnostics.cs_buflo_local_et_application_receive_streams_handed_off,
            1
        );
        assert_eq!(
            diagnostics.cs_buflo_local_et_application_parser_boundaries_handed_off,
            1
        );
        assert_eq!(
            diagnostics.cs_buflo_local_et_application_parser_lease_bytes_handed_off,
            16
        );
        assert_eq!(
            diagnostics.cs_buflo_local_et_application_send_endpoints_released,
            2
        );

        let dependent = QcsdStreamId(12);
        controller.open_stream(
            second_endpoint,
            dependent,
            QcsdRequestRole::Application,
            Some(500),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ConfigureAutomaticReceive {
                endpoint: QcsdEndpointId(2),
                stream: QcsdStreamId(12),
                window: 65_535,
            })
        ));
        assert!(
            !controller
                .actions
                .iter()
                .any(|action| matches!(action, QcsdAction::ConfigureManualReceive { .. }))
        );

        controller.observe(
            QcsdObservation::EndpointClosed {
                endpoint: second_endpoint,
            },
            Duration::from_micros(2_000_002),
        );
        ready(&mut controller, 2, "https://two.example");
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::ReleaseApplicationSendShaping {
                endpoint: QcsdEndpointId(2),
            })
        ));
    }

    #[test]
    fn pre_dispatch_local_et_latch_blocks_the_race_then_releases_backlogged_application() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                automatic_receive_window: 65_535,
                ..QcsdConfig::default()
            },
            None,
            Box::<BacklogLatchedLocalEtDefense>::default(),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(4);
        let chaff = QcsdStreamId(8);
        ready(&mut controller, 1, "https://one.example");
        assert!(controller.can_start_application_batch());

        // This is the runner's pre-dispatch causal boundary: queuing the
        // observation does not mutate the defense, but reducing it latches
        // local ET and must close the dispatch gate before controller.poll().
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 1_200,
                timestamp_us: 2_000_001,
            },
            Duration::from_micros(2_000_001),
        );
        assert!(controller.can_start_application_batch());
        controller.flush_defense_observations();
        assert!(!controller.can_start_application_batch());
        assert!(
            controller
                .defense_diagnostics()
                .cs_buflo_local_et_before_application_complete
        );

        // Force the exact request that the gate prevents, proving that even a
        // pre-existing/manual application backlog cannot deadlock the
        // post-latch handoff.  ApplicationComplete is delivered only after the
        // latch and therefore must not erase the historical ordering proof.
        controller.open_stream(
            endpoint,
            application,
            QcsdRequestRole::Application,
            Some(2_000),
        );
        controller.streams.open(
            endpoint,
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 7,
                request_id: None,
            },
            true,
            16,
            1_000,
            1_000,
        );
        controller.observe(
            QcsdObservation::EgressBacklog { pending: true },
            Duration::from_micros(2_000_002),
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(2_000_003),
        );
        controller.flush_defense_observations();
        controller.update_completion(Duration::from_micros(2_000_003));

        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(matches!(
            actions.as_slice(),
            [
                QcsdAction::CancelChaff {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(8),
                    reason: QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
                },
                QcsdAction::ConfigureAutomaticReceive {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(4),
                    window: 65_535,
                },
                QcsdAction::ReleaseApplicationSendShaping {
                    endpoint: QcsdEndpointId(1),
                },
            ]
        ));
        assert!(controller.cs_buflo_application_passthrough);
        assert!(controller.can_start_application_batch());
        assert!(
            controller
                .defense_diagnostics()
                .cs_buflo_local_et_before_application_complete
        );
    }

    #[test]
    fn application_complete_delivered_before_local_et_is_not_misreported_as_early() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::<BacklogLatchedLocalEtDefense>::default(),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://one.example");
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(2_000_001),
        );
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 1_200,
                timestamp_us: 2_000_001,
            },
            Duration::from_micros(2_000_001),
        );
        controller.flush_defense_observations();
        controller.update_completion(Duration::from_micros(2_000_001));

        let diagnostics = controller.defense_diagnostics();
        assert!(!diagnostics.cs_buflo_local_et_before_application_complete);
        assert_eq!(
            diagnostics.cs_buflo_local_et_application_send_endpoints_released,
            0
        );
        assert!(!controller.cs_buflo_application_passthrough);
        assert!(controller.actions.iter().any(|action| matches!(
            action,
            QcsdAction::ReleaseApplicationSendShaping {
                endpoint: QcsdEndpointId(1)
            }
        )));
    }

    #[test]
    fn equal_timestamp_local_et_before_application_complete_preserves_production_order() {
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                automatic_receive_window: 65_535,
                ..QcsdConfig::default()
            },
            None,
            Box::<BacklogLatchedLocalEtDefense>::default(),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let application = QcsdStreamId(4);
        ready(&mut controller, 1, "https://one.example");
        controller.open_stream(
            endpoint,
            application,
            QcsdRequestRole::Application,
            Some(2_000),
        );

        let barrier = Duration::from_micros(2_000_001);
        controller.observe(
            QcsdObservation::Datagram {
                endpoint,
                direction: Direction::Incoming,
                length: 1_200,
                timestamp_us: 2_000_001,
            },
            barrier,
        );
        controller.observe(QcsdObservation::ApplicationComplete, barrier);
        controller.flush_defense_observations();

        assert!(!controller.can_start_application_batch());
        assert!(
            controller
                .defense_diagnostics()
                .cs_buflo_local_et_before_application_complete
        );
        controller.update_completion(barrier);
        assert!(controller.cs_buflo_application_passthrough);
        assert_eq!(
            controller
                .defense_diagnostics()
                .cs_buflo_local_et_application_send_endpoints_released,
            1
        );
        assert!(matches!(
            controller.drain_actions().collect::<Vec<_>>().as_slice(),
            [
                QcsdAction::ConfigureAutomaticReceive {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(4),
                    window: 65_535,
                },
                QcsdAction::ReleaseApplicationSendShaping {
                    endpoint: QcsdEndpointId(1),
                },
            ]
        ));
    }

    #[test]
    fn queued_chaff_request_is_part_of_candidate_egress_backlog() {
        let manifest = ResourceManifest {
            resources: vec![Resource {
                id: 7,
                url: "https://example.com/chaff".into(),
                kind: "Other".into(),
                content_length: Some(1_000),
                data_length: 1_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        };
        let states = Rc::new(RefCell::new(Vec::new()));
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                low_watermark: 1_000,
                max_chaff_streams: 1,
                ..QcsdConfig::default()
            },
            Some(manifest),
            Box::new(BacklogProbeDefense {
                states: Rc::clone(&states),
                terminal_reason: None,
            }),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.request_chaff_if_needed(true);
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::ZERO,
        );

        controller.poll(Duration::ZERO);
        assert_eq!(&*states.borrow(), &[true]);
        let request_id = controller
            .drain_actions()
            .find_map(|action| match action {
                QcsdAction::RequestChaff { request_id, .. } => Some(request_id),
                _ => None,
            })
            .expect("pending request action");

        controller.observe(
            QcsdObservation::ChaffRequestFailed {
                resource_id: 7,
                request_id: Some(request_id),
            },
            Duration::from_micros(1),
        );
        controller.poll(Duration::from_micros(1));
        assert_eq!(&*states.borrow(), &[true, false]);
    }

    #[test]
    fn candidate_quiet_termination_receives_repeated_fresh_false_snapshots() {
        let states = Rc::new(RefCell::new(Vec::new()));
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(BacklogProbeDefense {
                states: Rc::clone(&states),
                terminal_reason: Some(QcsdChaffCancellationReason::CsBufloLocalEarlyTermination),
            }),
        )
        .expect("controller");
        controller.observe(
            QcsdObservation::EgressBacklog { pending: false },
            Duration::ZERO,
        );

        controller.poll(Duration::ZERO);
        assert_eq!(&*states.borrow(), &[false, false]);
        controller.poll(Duration::from_micros(1));
        assert_eq!(&*states.borrow(), &[false, false, false, false]);
    }

    #[test]
    fn exact_incoming_no_capacity_is_terminal_once_without_requeue() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, outcomes) = ExactIncomingOneShot::new(packet);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                drop_unsatisfied_events: false,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
        assert!(controller.control.incoming.is_empty());
        assert!(controller.pending_slots().is_empty());

        controller.poll(Duration::from_micros(1));
        controller.poll(Duration::from_millis(10));
        assert_eq!(
            outcomes.borrow().as_slice(),
            [EventOutcome::Missed(
                MissedSlotReason::InsufficientIncomingCapacity
            )]
        );
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SlotMissed { .. } | QcsdAction::SlotSatisfied { .. }
        )));
    }

    #[test]
    fn exact_incoming_partial_capacity_rolls_back_and_never_fragments() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, outcomes) = ExactIncomingOneShot::new(packet);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 100,
                drop_unsatisfied_events: false,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(50),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::ZERO);
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::InsufficientIncomingCapacity,
                ..
            }
        )));
        assert!(controller.control.incoming.is_empty());
        assert!(controller.control.credit.is_empty());
        assert!(controller.control.claims.is_empty());
        controller.poll(Duration::from_micros(1));
        assert_eq!(outcomes.borrow().len(), 1);
    }

    #[test]
    fn exact_incoming_credit_allocated_in_window_can_be_consumed_after_rtt() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, outcomes) = ExactIncomingOneShot::new(packet);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 1_000,
                drop_unsatisfied_events: false,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1_000),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("whole credit action")
        else {
            panic!("expected receive credit");
        };
        controller.drain_actions().for_each(drop);
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(1),
        );
        // The allocation/advertisement opportunity was exact and in-window.
        // Peer consumption remains a separately accounted realization and is
        // allowed after an arbitrary RTT; the client-only ingress adapter does
        // not claim server timing authority.
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: absolute_limit,
            },
            Duration::from_millis(50),
        );
        controller.poll(Duration::from_millis(50));
        assert!(controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SlotSatisfied {
                slot: observed,
                ..
            } if observed == slot
        )));
        controller.poll(Duration::from_micros(50_001));
        assert_eq!(
            outcomes.borrow().as_slice(),
            [EventOutcome::Satisfied { observed: 100 }]
        );
        controller.poll(Duration::from_millis(60));
        assert_eq!(outcomes.borrow().len(), 1);
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::SlotMissed { .. } | QcsdAction::SlotSatisfied { .. }
        )));
    }

    #[test]
    fn exact_incoming_inside_processed_bucket_is_allocated_at_due_instant() {
        // Include every within-bucket offset observed in the failed live
        // cohort, plus one event close to the next legacy boundary.
        for due_us in [50, 76, 202, 384, 597, 836, 4_900] {
            let due = Duration::from_micros(due_us);
            let packet = Packet::new(due, Direction::Incoming, 100).expect("packet");
            let (defense, _) = ExactIncomingOneShot::new(packet);
            let mut controller = QcsdController::with_defense(
                QcsdConfig {
                    control_interval_us: 5_000,
                    max_stream_data_excess: 1_000,
                    drop_unsatisfied_events: false,
                    ..QcsdConfig::default()
                },
                None,
                Box::new(defense),
            )
            .expect("controller");
            ready(&mut controller, 1, "https://example.com");
            controller.observe(
                QcsdObservation::StreamOpened {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(0),
                    role: QcsdRequestRole::Application,
                    expected_response_length: Some(1_000),
                },
                Duration::ZERO,
            );
            controller.drain_actions().for_each(drop);

            // Mark the containing legacy bucket as processed before the
            // jittered event becomes due. Exact-window defenses must not
            // inherit that bucket's gate when the event appears later in the
            // same interval.
            controller.poll(Duration::from_micros(due_us - 1));
            assert_eq!(controller.next_deadline(), Some(due));
            assert!(controller.control.incoming.is_empty());

            controller.poll(due);
            let actions: Vec<_> = controller.drain_actions().collect();
            assert!(actions.iter().any(|action| matches!(
                action,
                QcsdAction::IncreaseReceiveLimit {
                    packet: observed,
                    ..
                } if *observed == packet
            )));
            assert!(
                !actions
                    .iter()
                    .any(|action| matches!(action, QcsdAction::SlotMissed { .. }))
            );
            assert!(controller.control.incoming.is_empty());
        }
    }

    #[test]
    fn exact_incoming_first_handled_at_exclusive_deadline_is_missed_once() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, outcomes) = ExactIncomingOneShot::new(packet);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                control_interval_us: 5_000,
                max_stream_data_excess: 1_000,
                drop_unsatisfied_events: false,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: Some(1_000),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::from_millis(5));
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(
            action,
            QcsdAction::SlotMissed {
                reason: MissedSlotReason::DeadlineExpired,
                ..
            }
        )));
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, QcsdAction::IncreaseReceiveLimit { .. }))
        );
        assert!(controller.control.incoming.is_empty());
        assert!(controller.pending_slots().is_empty());
        controller.poll(Duration::from_micros(5_001));
        controller.poll(Duration::from_millis(10));
        assert_eq!(
            outcomes.borrow().as_slice(),
            [EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]
        );
    }

    #[test]
    fn incoming_only_tail_releases_chaff_send_shaping_once() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        let actions: Vec<_> = controller.drain_actions().collect();
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, QcsdAction::ReleaseChaffSendShaping { .. }))
                .count(),
            1
        );
        controller.poll(Duration::ZERO);
        controller.poll(Duration::from_millis(1));
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::ReleaseChaffSendShaping { .. }))
        );
    }

    #[test]
    fn failed_receive_action_terminates_its_pending_slot() {
        let trace =
            Trace::new([Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet")]);
        let mut controller = QcsdController::with_defense(
            QcsdConfig::default(),
            None,
            Box::new(StaticSchedule::new(trace, false)),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit { slot, packet, .. } =
            controller.next_action().expect("credit action")
        else {
            panic!("expected receive action");
        };
        controller.observe(
            QcsdObservation::SlotMissed {
                endpoint: QcsdEndpointId(1),
                slot,
                packet,
                reason: MissedSlotReason::EndpointClosed,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::from_millis(5));
        assert!(!controller.drain_actions().any(|action| matches!(
            action,
            QcsdAction::IncreaseReceiveLimit { slot: candidate, .. } if candidate == slot
        )));
    }

    #[test]
    fn signals_are_sorted_and_delivered_before_due_events() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 200,
                timestamp_us: 999,
            },
            Duration::from_micros(20),
        );
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(2),
                direction: Direction::Outgoing,
                length: 100,
                timestamp_us: 1,
            },
            Duration::from_micros(10),
        );

        controller.poll(Duration::from_micros(20));

        assert_eq!(
            *calls.borrow(),
            [
                RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(10),
                    kind: SignalKind::Wire {
                        direction: Direction::Outgoing,
                        length: 100,
                    },
                }),
                RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(20),
                    kind: SignalKind::Wire {
                        direction: Direction::Incoming,
                        length: 200,
                    },
                }),
                RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(20),
                    kind: SignalKind::Capacity(crate::Capacity::default()),
                }),
                RecordedCall::NextEvent(Duration::from_micros(20)),
            ]
        );
    }

    #[test]
    fn stale_signal_times_are_clamped_across_polls() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Outgoing,
                length: 100,
                timestamp_us: 10,
            },
            Duration::from_micros(10),
        );
        controller.poll(Duration::from_micros(10));
        calls.borrow_mut().clear();

        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 200,
                timestamp_us: 5,
            },
            Duration::from_micros(5),
        );
        controller.poll(Duration::from_micros(11));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(10),
                    kind: SignalKind::Wire {
                        direction: Direction::Incoming,
                        length: 200,
                    },
                }))
        );
    }

    #[test]
    fn application_complete_signal_is_idempotent() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(10),
        );
        controller.observe(
            QcsdObservation::ApplicationComplete,
            Duration::from_micros(11),
        );
        controller.poll(Duration::from_micros(11));

        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| {
                    matches!(
                        call,
                        RecordedCall::Signal(DefenseSignal {
                            kind: SignalKind::ApplicationComplete,
                            ..
                        })
                    )
                })
                .count(),
            1
        );
    }

    #[test]
    fn application_batch_lifecycle_is_delivered_in_order() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        assert!(controller.can_start_application_batch());
        controller.observe(
            QcsdObservation::ApplicationBatchStarted,
            Duration::from_micros(5),
        );
        controller.observe(
            QcsdObservation::ApplicationBatchCompleted,
            Duration::from_micros(10),
        );
        controller.poll(Duration::from_micros(10));

        let lifecycle: Vec<_> = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::Signal(signal)
                    if matches!(
                        signal.kind,
                        SignalKind::ApplicationBatchStarted | SignalKind::ApplicationBatchCompleted
                    ) =>
                {
                    Some(*signal)
                }
                RecordedCall::Signal(_)
                | RecordedCall::ApplicationBytes { .. }
                | RecordedCall::NextEvent(_) => None,
            })
            .collect();
        assert_eq!(
            lifecycle,
            [
                DefenseSignal {
                    at: Duration::from_micros(5),
                    kind: SignalKind::ApplicationBatchStarted,
                },
                DefenseSignal {
                    at: Duration::from_micros(10),
                    kind: SignalKind::ApplicationBatchCompleted,
                },
            ]
        );
    }

    #[test]
    fn transmitted_stream_ranges_preserve_wire_bytes_and_deduplicate_natural_bytes() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(4),
                role: QcsdRequestRole::Application,
                offset: 10,
                bytes: 25,
                fin: false,
                slot: None,
            },
            Duration::from_micros(7),
        );
        for at in [8, 9] {
            controller.observe(
                QcsdObservation::StreamDataTransmitted {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(4),
                    role: QcsdRequestRole::Application,
                    offset: 20,
                    bytes: 20,
                    fin: false,
                    slot: None,
                },
                Duration::from_micros(at),
            );
        }
        controller.poll(Duration::from_micros(9));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(7),
                    kind: SignalKind::PayloadBytes {
                        direction: Direction::Outgoing,
                        bytes: 25,
                        cover: false,
                    },
                }))
        );
        let application_bytes: Vec<_> = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::ApplicationBytes {
                    at,
                    direction,
                    bytes,
                } => Some((*at, *direction, *bytes)),
                RecordedCall::Signal(_) | RecordedCall::NextEvent(_) => None,
            })
            .collect();
        assert_eq!(
            application_bytes,
            [
                (Duration::from_micros(7), Direction::Outgoing, 25),
                (Duration::from_micros(8), Direction::Outgoing, 5),
            ]
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one end-to-end provenance test keeps every overlap and retransmission assertion causal"
    )]
    fn cs_payload_counter_deduplicates_retransmitted_chaff_offsets() {
        let (mut defense, calls) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
        defense.deduplicate_chaff_payload_offsets = true;
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");

        for (at, offset, bytes) in [(7, 10, 25), (8, 20, 20)] {
            controller.observe(
                QcsdObservation::StreamDataTransmitted {
                    endpoint: QcsdEndpointId(1),
                    stream: QcsdStreamId(8),
                    role: QcsdRequestRole::Chaff {
                        resource_id: 1,
                        request_id: None,
                    },
                    offset,
                    bytes,
                    fin: false,
                    slot: None,
                },
                Duration::from_micros(at),
            );
        }
        // Response completion can precede ACK/loss recovery of the request
        // bytes. Keep the offset provenance until endpoint teardown so such a
        // late retransmission cannot re-enter the CPSP payload basis.
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(8),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(8),
        );
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(8),
                role: QcsdRequestRole::Chaff {
                    resource_id: 1,
                    request_id: None,
                },
                offset: 20,
                bytes: 20,
                fin: false,
                slot: None,
            },
            Duration::from_micros(9),
        );
        controller.poll(Duration::from_micros(9));

        let unique_cover_bytes: u64 = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::Signal(DefenseSignal {
                    kind:
                        SignalKind::PayloadBytes {
                            direction: Direction::Outgoing,
                            bytes,
                            cover: true,
                        },
                    ..
                }) => Some(*bytes),
                RecordedCall::Signal(_)
                | RecordedCall::ApplicationBytes { .. }
                | RecordedCall::NextEvent(_) => None,
            })
            .sum();
        assert_eq!(unique_cover_bytes, 30);

        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(12),
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 25,
                fin: true,
                slot: None,
            },
            Duration::from_micros(10),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(12),
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(10),
        );
        controller.observe(
            QcsdObservation::StreamDataTransmitted {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(12),
                role: QcsdRequestRole::Application,
                offset: 0,
                bytes: 25,
                fin: true,
                slot: None,
            },
            Duration::from_micros(11),
        );
        controller.poll(Duration::from_micros(11));
        let unique_application_bytes: u64 = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::ApplicationBytes {
                    direction: Direction::Outgoing,
                    bytes,
                    ..
                } => Some(*bytes),
                RecordedCall::Signal(_)
                | RecordedCall::ApplicationBytes { .. }
                | RecordedCall::NextEvent(_) => None,
            })
            .sum();
        assert_eq!(unique_application_bytes, 25);
    }

    #[test]
    fn capacity_signal_is_emitted_only_when_the_aggregate_changes() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.poll(Duration::ZERO);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::from_micros(1),
        );
        controller.poll(Duration::from_micros(1));
        controller.poll(Duration::from_micros(2));

        let capacities: Vec<_> = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                RecordedCall::Signal(DefenseSignal {
                    kind: SignalKind::Capacity(capacity),
                    ..
                }) => Some(*capacity),
                RecordedCall::Signal(_)
                | RecordedCall::ApplicationBytes { .. }
                | RecordedCall::NextEvent(_) => None,
            })
            .collect();
        assert_eq!(capacities.len(), 2);
        assert_eq!(capacities[0], crate::Capacity::default());
        assert!(capacities[1].application_incoming > 0);
    }

    #[test]
    fn outgoing_slot_resolution_is_atomic_and_wakes_controller() {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                tail_wait_us: 0,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::SendPacket { slot, .. } = controller.next_action().expect("send action")
        else {
            panic!("expected outgoing slot");
        };
        assert!(!controller.is_complete());
        controller.observe(
            QcsdObservation::SlotSatisfied {
                endpoint: QcsdEndpointId(1),
                slot,
                observed_size: 1_180,
            },
            Duration::from_micros(100),
        );
        assert_eq!(controller.next_deadline(), Some(Duration::ZERO));
        controller.poll(Duration::from_micros(100));

        assert!(controller.pending_slots.is_empty());
        assert!(controller.is_complete());
        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(100),
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Satisfied { observed: 1_180 },
                    },
                }))
        );

        calls.borrow_mut().clear();
        controller.observe(
            QcsdObservation::SlotSatisfied {
                endpoint: QcsdEndpointId(1),
                slot,
                observed_size: 1_180,
            },
            Duration::from_micros(101),
        );
        controller.poll(Duration::from_micros(101));
        assert!(!calls.borrow().iter().any(|call| matches!(
            call,
            RecordedCall::Signal(DefenseSignal {
                kind: SignalKind::Resolved { .. },
                ..
            })
        )));
    }

    #[test]
    fn controller_generated_miss_resolves_and_clears_slot() {
        let packet =
            Packet::new(Duration::from_millis(1), Direction::Outgoing, 1_200).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.drain_actions().for_each(drop);

        controller.poll(Duration::from_millis(10));
        assert!(controller.pending_slots.is_empty());
        assert_eq!(controller.next_deadline(), Some(Duration::ZERO));
        controller.poll(Duration::from_millis(10));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_millis(10),
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Missed(MissedSlotReason::DeadlineExpired),
                    },
                }))
        );
    }

    #[test]
    fn incoming_credit_resolution_reports_scheduled_credit() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint: QcsdEndpointId(1),
                stream: QcsdStreamId(0),
                role: QcsdRequestRole::Application,
                expected_response_length: None,
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            endpoint,
            stream,
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
        controller.observe(
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint,
                stream,
                absolute_limit,
                slot: Some(slot),
            },
            Duration::from_micros(50),
        );
        controller.poll(Duration::from_micros(50));

        assert_eq!(controller.pending_slots(), [(slot, packet)]);
        assert!(!calls.borrow().iter().any(|call| matches!(
            call,
            RecordedCall::Signal(DefenseSignal {
                kind: SignalKind::Resolved { packet: resolved, .. },
                ..
            }) if *resolved == packet
        )));
        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: absolute_limit,
            },
            Duration::from_micros(75),
        );
        controller.poll(Duration::from_micros(75));

        assert!(controller.pending_slots.is_empty());
        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(75),
                    kind: SignalKind::Resolved {
                        packet,
                        outcome: EventOutcome::Satisfied { observed: 100 },
                    },
                }))
        );
    }

    #[test]
    fn controller_generated_incoming_miss_is_reported_once() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                drop_unsatisfied_events: true,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");

        controller.poll(Duration::ZERO);
        assert!(controller.pending_slots.is_empty());
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                reason: MissedSlotReason::NoEndpoint,
                ..
            })
        ));
        controller.poll(Duration::ZERO);

        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| {
                    matches!(
                        call,
                        RecordedCall::Signal(DefenseSignal {
                            kind: SignalKind::Resolved {
                                packet: resolved,
                                outcome: EventOutcome::Missed(MissedSlotReason::NoEndpoint),
                            },
                            ..
                        }) if *resolved == packet
                    )
                })
                .count(),
            1
        );
        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ReceiveCreditRequested { packet },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ReceiveCreditRetired { bytes: 100 },
        })));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn abort_retires_pending_incoming_credit_and_delivers_reactive_signals() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        controller.poll(Duration::ZERO);
        assert_eq!(controller.pending_slots(), [(QcsdSlotId(0), packet)]);

        let at = Duration::from_micros(9);
        controller.abort_pending_slots(at, MissedSlotReason::RunAborted);

        assert!(controller.pending_slots().is_empty());
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                endpoint: None,
                packet: missed_packet,
                slot: QcsdSlotId(0),
                reason: MissedSlotReason::RunAborted,
            }) if missed_packet == packet
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);

        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ReceiveCreditRequested { packet },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at,
            kind: SignalKind::ReceiveCreditRetired { bytes: 100 },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at,
            kind: SignalKind::Resolved {
                packet,
                outcome: EventOutcome::Missed(MissedSlotReason::RunAborted),
            },
        })));
    }

    #[test]
    fn abort_updates_wtf_pad_terminal_shortfall_without_polling_retries() {
        let config = WtfPadConfig {
            histograms: "inline-abort-test.json".into(),
            packet_size: 100,
            max_padding_events: 32,
        };
        let defense = WtfPad::from_json(
            &config,
            0x5eed,
            1_200,
            include_str!("../../tests/data/wtf-pad-golden.json"),
        )
        .expect("WTF-PAD histograms");
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                defense: DefenseConfig::WtfPad(config),
                max_udp_payload_size: 1_200,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        controller.observe(
            QcsdObservation::ClassifiedDatagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 90,
                class: QcsdDatagramClass::Natural,
                composition: None,
            },
            Duration::ZERO,
        );
        controller.poll(Duration::ZERO);
        let deadline = controller.next_deadline().expect("incoming padding timer");
        controller.poll(deadline);
        assert_eq!(controller.pending_slots().len(), 1);
        assert_eq!(
            controller.pending_slots()[0].1.direction(),
            Direction::Incoming
        );

        controller.abort_pending_slots(deadline, MissedSlotReason::RunAborted);

        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        assert_eq!(diagnostics.wtf_pad_incoming_desired_bytes, 100);
        assert_eq!(diagnostics.wtf_pad_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.wtf_pad_incoming_received_bytes, 0);
        assert_eq!(diagnostics.wtf_pad_incoming_shortfall_bytes, 100);
        assert_eq!(controller.pending_slots(), []);
    }

    #[test]
    fn pending_slot_snapshot_includes_controller_only_retry_backlog() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, _) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");

        controller.poll(Duration::ZERO);

        assert_eq!(controller.pending_slots(), [(QcsdSlotId(0), packet)]);
        assert!(
            !controller
                .drain_actions()
                .any(|action| matches!(action, QcsdAction::SlotMissed { .. }))
        );
    }

    #[test]
    fn classified_wire_is_additive_to_raw_wire_evidence() {
        let (defense, calls) = RecordingDefense::new([], DefenseMode::ChaffOnly);
        let mut controller =
            QcsdController::with_defense(QcsdConfig::default(), None, Box::new(defense))
                .expect("controller");
        let at = Duration::from_micros(7);
        controller.observe(
            QcsdObservation::Datagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 123,
                timestamp_us: 7,
            },
            at,
        );
        controller.observe(
            QcsdObservation::ClassifiedDatagram {
                endpoint: QcsdEndpointId(1),
                direction: Direction::Incoming,
                length: 123,
                class: QcsdDatagramClass::DefenseCover,
                composition: None,
            },
            at,
        );
        controller.poll(at);

        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at,
            kind: SignalKind::Wire {
                direction: Direction::Incoming,
                length: 123,
            },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at,
            kind: SignalKind::ClassifiedWire {
                direction: Direction::Incoming,
                length: 123,
                class: QcsdDatagramClass::DefenseCover,
            },
        })));
    }

    #[test]
    fn initial_allowance_is_excluded_from_consumed_scheduled_credit() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 116,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(116),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
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
                bytes: 100,
            },
            Duration::from_micros(2),
        );
        controller.poll(Duration::from_micros(2));

        assert!(
            calls
                .borrow()
                .contains(&RecordedCall::Signal(DefenseSignal {
                    at: Duration::from_micros(2),
                    kind: SignalKind::ReceiveCreditConsumed { bytes: 84 },
                }))
        );
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 84);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 0);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 16);
        assert_eq!(controller.pending_slots(), [(slot, packet)]);

        controller.observe(
            QcsdObservation::BytesRead {
                endpoint,
                stream,
                bytes: 16,
            },
            Duration::from_micros(3),
        );
        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotSatisfied {
                slot: satisfied,
                ..
            }) if satisfied == slot
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_advertised_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
    }

    #[test]
    fn endpoint_close_retires_every_remaining_advertised_offset() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 116,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(116),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
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
                bytes: 40,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::EndpointClosed { endpoint },
            Duration::from_micros(3),
        );
        controller.poll(Duration::from_micros(3));

        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                endpoint: Some(closed),
                slot: missed,
                reason: MissedSlotReason::ReceiveCreditRetired,
                ..
            }) if closed == endpoint && missed == slot
        ));
        assert_eq!(controller.pending_slots(), []);
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 24);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 76);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 24 },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditRetired { bytes: 76 },
        })));
    }

    #[test]
    fn stream_close_retires_only_its_unconsumed_scheduled_offsets() {
        let packet = Packet::new(Duration::ZERO, Direction::Incoming, 100).expect("packet");
        let (defense, calls) = RecordingDefense::new([packet], DefenseMode::ChaffAndShape);
        let mut controller = QcsdController::with_defense(
            QcsdConfig {
                initial_max_stream_data: 16,
                max_stream_data_excess: 116,
                ..QcsdConfig::default()
            },
            None,
            Box::new(defense),
        )
        .expect("controller");
        ready(&mut controller, 1, "https://example.com");
        let endpoint = QcsdEndpointId(1);
        let stream = QcsdStreamId(0);
        controller.observe(
            QcsdObservation::StreamOpened {
                endpoint,
                stream,
                role: QcsdRequestRole::Application,
                expected_response_length: Some(116),
            },
            Duration::ZERO,
        );
        controller.drain_actions().for_each(drop);
        controller.poll(Duration::ZERO);
        let QcsdAction::IncreaseReceiveLimit {
            absolute_limit,
            slot,
            ..
        } = controller.next_action().expect("credit action")
        else {
            panic!("expected receive credit");
        };
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
                bytes: 60,
            },
            Duration::from_micros(2),
        );
        controller.observe(
            QcsdObservation::StreamFinished {
                endpoint,
                stream,
                finish: QcsdStreamFinish::Fin,
            },
            Duration::from_micros(3),
        );

        assert!(matches!(
            controller.next_action(),
            Some(QcsdAction::SlotMissed {
                endpoint: Some(closed),
                slot: missed,
                reason: MissedSlotReason::ReceiveCreditRetired,
                ..
            }) if closed == endpoint && missed == slot
        ));
        let diagnostics = controller.defense_diagnostics();
        assert_eq!(diagnostics.scheduled_incoming_requested_bytes, 100);
        assert_eq!(diagnostics.scheduled_incoming_consumed_bytes, 44);
        assert_eq!(diagnostics.scheduled_incoming_retired_bytes, 56);
        assert_eq!(diagnostics.scheduled_incoming_unresolved_bytes, 0);
        controller.poll(Duration::from_micros(3));
        let calls = calls.borrow();
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditRetired { bytes: 56 },
        })));
        assert!(calls.contains(&RecordedCall::Signal(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::Resolved {
                packet,
                outcome: EventOutcome::Missed(MissedSlotReason::ReceiveCreditRetired),
            },
        })));
    }
}
