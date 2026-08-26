// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use super::{
    CsBufloRateTransitionDiagnostics, Defense, DefenseDiagnostics, DefenseMode, DefenseSignal,
    EventOutcome, SignalKind,
};
use crate::{
    CsBufloConfig, CsBufloPaddingMode, CsBufloParameters, Direction, Packet, QcsdSendPolicy,
    QcsdSlotComposition, QcsdSlotId, Result, SplitMix64, derive,
};

const OUTGOING: usize = 0;
const INCOMING: usize = 1;
const REFERENCE_TCP_WRITE_SIZE_BYTES: u64 = 548;
const REFERENCE_NOMINAL_TCP_PACKET_SIZE_BYTES: u64 = 600;
const EARLY_TERMINATION_SEMANTICS: &str = "udp_client_only_observed_udp_power_of_two_crossing";
const RATE_BOUNDARY_COUNTER_SEMANTICS: &str = "client_only_quic_fresh_application_stream_bytes_outgoing_retransmission_excluded_and_consumed_application_offsets_incoming";
const AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS: &str =
    "per_direction_actually_transmitted_real_plus_junk_bytes";

const fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::Outgoing => OUTGOING,
        Direction::Incoming => INCOMING,
    }
}

const fn floor_power_of_two(value: u64) -> u64 {
    if value == 0 {
        0
    } else {
        1_u64 << (u64::BITS - 1 - value.leading_zeros())
    }
}

fn ceiling_power_of_two(value: u64) -> u64 {
    if value <= 1 {
        value
    } else {
        value.checked_next_power_of_two().unwrap_or(u64::MAX)
    }
}

fn payload_padding_target(real_bytes: u64, junk_bytes: u64) -> u64 {
    let current = real_bytes.saturating_add(junk_bytes);
    if current == 0 {
        return 0;
    }
    // CPSP chooses a power-of-two quantum from the real payload, then pads
    // the already-sent real+junk total to the next multiple of that quantum.
    // This is distinct from CTSP's next power of two of total wire bytes.
    let quantum = ceiling_power_of_two(real_bytes.max(1));
    current.div_ceil(quantum).saturating_mul(quantum)
}

const fn crossed_power_of_two(total: u64, latest_increment: u64) -> bool {
    if total == 0 || latest_increment == 0 || latest_increment > total {
        return false;
    }
    let previous = total - latest_increment;
    previous.leading_zeros() > total.leading_zeros()
}

fn outgoing_termination_increment(composition: QcsdSlotComposition) -> u64 {
    // Algorithm 4 advances by the actual transmitted opportunity. In the QUIC
    // adaptation this is the observed UDP payload, including QUIC bytes which
    // cannot be attributed to a more specific composition category.
    u64::from(composition.observed_udp_bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingIncomingOpportunity {
    packet: Packet,
    at_minimum_interval: bool,
    locally_realized: bool,
}

/// Clean-room, client-only `CS-BuFLO` adaptation.
///
/// Client egress uses one-shot congestion-sensitive transport attempts.
/// Client ingress remains a receive-credit approximation and is separately
/// identified in terminal diagnostics.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the immutable terminal receipt keeps independent algorithm and fidelity latches explicit"
)]
pub struct CsBuflo {
    parameters: CsBufloParameters,
    rng: SplitMix64,
    next_us: [u64; 2],
    current_interval_us: [u64; 2],
    scheduled: [u64; 2],
    terminal: [u64; 2],
    in_flight: [bool; 2],
    in_flight_at_minimum_interval: [bool; 2],
    pending_incoming: HashMap<QcsdSlotId, PendingIncomingOpportunity>,
    incoming_local_realized: u64,
    minimum_interval_scheduled: [u64; 2],
    minimum_interval_incoming_local_realized: u64,
    minimum_interval_terminal: [u64; 2],
    minimum_interval_full: [u64; 2],
    realized_total: [u64; 2],
    cover_payload: [u64; 2],
    natural: [u64; 2],
    real_bearing_bytes: [u64; 2],
    termination_accounted_bytes: [u64; 2],
    last_termination_increment_bytes: [u64; 2],
    last_natural_us: [Option<u64>; 2],
    estimator_last_us: [Option<u64>; 2],
    estimator_direction: Option<Direction>,
    iat_samples_us: [VecDeque<u64>; 2],
    padding_basis_natural: [Option<u64>; 2],
    padding_basis_cover: [Option<u64>; 2],
    padding_basis_total: [Option<u64>; 2],
    padding_targets: [Option<u64>; 2],
    completion_at_us: Option<u64>,
    local_termination_latched: bool,
    latest_elapsed_us: u64,
    egress_backlog_pending: bool,
    full_outgoing: u64,
    partial_outgoing: u64,
    suppressed_outgoing: u64,
    missed_outgoing: u64,
    missed_incoming: u64,
    desired_udp_bytes: u64,
    application_stream_bytes: u64,
    retransmission_stream_bytes: u64,
    chaff_stream_bytes: u64,
    defense_control_bytes: u64,
    quic_padding_bytes: u64,
    other_quic_bytes: u64,
    lateness_us_total: u64,
    lateness_us_max: u64,
    next_adaptation_boundary_bytes: [u64; 2],
    rate_adaptations: [u64; 2],
    rate_transitions: Vec<CsBufloRateTransitionDiagnostics>,
    event_guard_triggered: bool,
    realization_failed: bool,
}

impl CsBuflo {
    /// Load one immutable parameter receipt and construct the state machine.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt is missing, malformed, or invalid for
    /// the configured UDP-payload ceiling.
    pub fn new(config: &CsBufloConfig, seed: u64, max_udp_payload_size: u16) -> Result<Self> {
        let parameters =
            CsBufloParameters::from_json_file(&config.parameters, max_udp_payload_size)?;
        Ok(Self::from_parameters(parameters, seed))
    }

    /// Construct from already validated parameters.
    #[must_use]
    pub fn from_parameters(parameters: CsBufloParameters, seed: u64) -> Self {
        let interval = parameters.initial_interval_us;
        let boundary = parameters.initial_adaptation_boundary_bytes;
        let mut defense = Self {
            parameters,
            rng: derive(seed, "cs-buflo"),
            next_us: [0; 2],
            current_interval_us: [interval; 2],
            scheduled: [0; 2],
            terminal: [0; 2],
            in_flight: [false; 2],
            in_flight_at_minimum_interval: [false; 2],
            pending_incoming: HashMap::new(),
            incoming_local_realized: 0,
            minimum_interval_scheduled: [0; 2],
            minimum_interval_incoming_local_realized: 0,
            minimum_interval_terminal: [0; 2],
            minimum_interval_full: [0; 2],
            realized_total: [0; 2],
            cover_payload: [0; 2],
            natural: [0; 2],
            real_bearing_bytes: [0; 2],
            termination_accounted_bytes: [0; 2],
            last_termination_increment_bytes: [0; 2],
            last_natural_us: [None; 2],
            estimator_last_us: [None; 2],
            estimator_direction: None,
            iat_samples_us: std::array::from_fn(|_| VecDeque::new()),
            padding_basis_natural: [None; 2],
            padding_basis_cover: [None; 2],
            padding_basis_total: [None; 2],
            padding_targets: [None; 2],
            completion_at_us: None,
            local_termination_latched: false,
            latest_elapsed_us: 0,
            egress_backlog_pending: true,
            full_outgoing: 0,
            partial_outgoing: 0,
            suppressed_outgoing: 0,
            missed_outgoing: 0,
            missed_incoming: 0,
            desired_udp_bytes: 0,
            application_stream_bytes: 0,
            retransmission_stream_bytes: 0,
            chaff_stream_bytes: 0,
            defense_control_bytes: 0,
            quic_padding_bytes: 0,
            other_quic_bytes: 0,
            lateness_us_total: 0,
            lateness_us_max: 0,
            next_adaptation_boundary_bytes: [boundary; 2],
            rate_adaptations: [0; 2],
            rate_transitions: Vec::new(),
            event_guard_triggered: false,
            realization_failed: false,
        };
        defense.next_us[OUTGOING] = defense.randomized_delay_us(Direction::Outgoing);
        defense.next_us[INCOMING] = defense.randomized_delay_us(Direction::Incoming);
        defense
    }

    const fn randomized_delay_us(&mut self, direction: Direction) -> u64 {
        let numerator = self
            .rng
            .uniform_us(0, self.parameters.jitter_max_numerator.saturating_add(1));
        self.current_interval_us[direction_index(direction)]
            .saturating_mul(numerator)
            .saturating_div(self.parameters.jitter_denominator)
    }

    const fn application_complete(&self) -> bool {
        self.completion_at_us.is_some()
    }

    const fn padding_mode(&self, direction: Direction) -> CsBufloPaddingMode {
        match direction {
            Direction::Outgoing => self.parameters.outgoing_padding_mode,
            Direction::Incoming => self.parameters.incoming_padding_mode,
        }
    }

    fn freeze_padding_target(&mut self, direction: Direction) {
        let index = direction_index(direction);
        if self.padding_targets[index].is_some() {
            return;
        }
        self.padding_basis_natural[index] = Some(self.natural[index]);
        self.padding_basis_cover[index] = Some(self.cover_payload[index]);
        self.padding_basis_total[index] = Some(self.realized_total[index]);
        self.padding_targets[index] = Some(match self.padding_mode(direction) {
            CsBufloPaddingMode::Total => ceiling_power_of_two(self.realized_total[index]),
            CsBufloPaddingMode::Payload => {
                payload_padding_target(self.natural[index], self.cover_payload[index])
            }
        });
    }

    fn freeze_padding_targets(&mut self, at_us: u64) {
        for direction in [Direction::Outgoing, Direction::Incoming] {
            self.freeze_padding_target(direction);
        }
        self.completion_at_us = Some(at_us);
    }

    fn freeze_strict_quiet_targets(&mut self) {
        // Pending application or defense-control egress can later create both
        // outgoing bytes and peer responses.  A quiet timer must not freeze an
        // irreversible pre-backlog target for either direction.
        if self.egress_backlog_pending {
            return;
        }
        for direction in [Direction::Outgoing, Direction::Incoming] {
            if self.channel_idle(direction) {
                self.freeze_padding_target(direction);
            }
        }
    }

    const fn progress(&self, direction: Direction) -> u64 {
        let index = direction_index(direction);
        match self.padding_mode(direction) {
            CsBufloPaddingMode::Total => self.realized_total[index],
            CsBufloPaddingMode::Payload => {
                self.natural[index].saturating_add(self.cover_payload[index])
            }
        }
    }

    fn quiet_deadline_us(&self, direction: Direction) -> Option<u64> {
        if self.application_complete() {
            return None;
        }
        self.last_natural_us[direction_index(direction)]
            .map(|last| {
                // The pinned implementation uses a strict `now > last + 2s`
                // predicate, so the first eligible microsecond is one later.
                last.saturating_add(self.parameters.quiet_time_us)
                    .saturating_add(1)
            })
            .filter(|deadline| self.latest_elapsed_us < *deadline)
    }

    fn channel_idle(&self, direction: Direction) -> bool {
        if self.application_complete() {
            // The local ApplicationComplete observation is the client-side
            // onLoad analogue and satisfies idleness immediately.
            return true;
        }
        self.last_natural_us[direction_index(direction)].is_some_and(|last| {
            self.latest_elapsed_us > last.saturating_add(self.parameters.quiet_time_us)
        })
    }

    fn direction_complete(&self, direction: Direction) -> bool {
        if self.local_termination_latched {
            return true;
        }
        let index = direction_index(direction);
        if direction == Direction::Outgoing
            && self.egress_backlog_pending
            && !self.application_complete()
        {
            return false;
        }
        self.channel_idle(direction)
            && self.terminal[index] == self.scheduled[index]
            && (self.padding_targets[index]
                .is_some_and(|target| self.progress(direction) >= target)
                || crossed_power_of_two(
                    self.termination_accounted_bytes[index],
                    self.last_termination_increment_bytes[index],
                ))
    }

    fn maybe_latch_local_termination(&mut self) {
        if !self.local_termination_latched
            && !self.event_guard_triggered
            && !self.realization_failed
            && self.direction_complete(Direction::Outgoing)
            && self.direction_complete(Direction::Incoming)
        {
            self.local_termination_latched = true;
        }
    }

    const fn total_scheduled(&self) -> u64 {
        self.scheduled[OUTGOING].saturating_add(self.scheduled[INCOMING])
    }

    const fn record_termination_increment(&mut self, index: usize, increment: u64) {
        if increment == 0 {
            return;
        }
        self.termination_accounted_bytes[index] =
            self.termination_accounted_bytes[index].saturating_add(increment);
        self.last_termination_increment_bytes[index] = increment;
    }

    fn record_estimator_sample(&mut self, at_us: u64, direction: Direction) {
        let index = direction_index(direction);
        if self.estimator_direction != Some(direction) {
            // An opposite-direction observation is a separator, not an IAT.
            self.estimator_direction = Some(direction);
            self.estimator_last_us[index] = None;
        }
        if let Some(previous) = self.estimator_last_us[index] {
            let interval = at_us.saturating_sub(previous).clamp(
                self.parameters.minimum_interval_us,
                self.parameters.maximum_interval_us,
            );
            let samples = &mut self.iat_samples_us[index];
            if samples.len() == self.parameters.timing_sample_limit {
                samples.pop_front();
            }
            samples.push_back(interval);
        }
        self.estimator_last_us[index] = Some(at_us);
    }

    fn median_interval_us(&self, index: usize) -> Option<u64> {
        let mut samples: Vec<_> = self.iat_samples_us[index].iter().copied().collect();
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        // The pinned prototype selects the upper middle element for an even
        // sample count rather than averaging or selecting the lower median.
        Some(samples[samples.len() / 2])
    }

    fn adapt_rate_if_due(&mut self, at_us: u64, direction: Direction) {
        let index = direction_index(direction);
        while self.real_bearing_bytes[index] >= self.next_adaptation_boundary_bytes[index] {
            let boundary_bytes = self.next_adaptation_boundary_bytes[index];
            let eligible_samples =
                u64::try_from(self.iat_samples_us[index].len()).unwrap_or(u64::MAX);
            let median_interval_us = self.median_interval_us(index);
            let previous_interval_us = self.current_interval_us[index];
            if let Some(median) = median_interval_us {
                self.current_interval_us[index] = floor_power_of_two(median.max(1)).clamp(
                    self.parameters.minimum_interval_us,
                    self.parameters.maximum_interval_us,
                );
            }
            self.rate_transitions
                .push(CsBufloRateTransitionDiagnostics {
                    schema_version: 1,
                    direction: match direction {
                        Direction::Outgoing => "outgoing",
                        Direction::Incoming => "incoming",
                    },
                    at_us,
                    boundary_bytes,
                    real_bearing_bytes: self.real_bearing_bytes[index],
                    eligible_samples,
                    median_interval_us,
                    previous_interval_us,
                    resulting_interval_us: self.current_interval_us[index],
                    retained_current_interval: median_interval_us.is_none(),
                });
            self.iat_samples_us[index].clear();
            self.rate_adaptations[index] = self.rate_adaptations[index].saturating_add(1);
            let next = self.next_adaptation_boundary_bytes[index].saturating_mul(2);
            if next == self.next_adaptation_boundary_bytes[index] {
                break;
            }
            self.next_adaptation_boundary_bytes[index] = next;
        }
    }

    fn record_composition(&mut self, at_us: u64, composition: QcsdSlotComposition) {
        self.record_termination_increment(OUTGOING, outgoing_termination_increment(composition));
        self.realized_total[OUTGOING] =
            self.realized_total[OUTGOING].saturating_add(u64::from(composition.observed_udp_bytes));
        self.application_stream_bytes = self
            .application_stream_bytes
            .saturating_add(u64::from(composition.application_stream_bytes));
        self.retransmission_stream_bytes = self
            .retransmission_stream_bytes
            .saturating_add(u64::from(composition.retransmission_stream_bytes));
        self.chaff_stream_bytes = self
            .chaff_stream_bytes
            .saturating_add(u64::from(composition.chaff_stream_bytes));
        self.defense_control_bytes = self
            .defense_control_bytes
            .saturating_add(u64::from(composition.defense_control_bytes));
        self.quic_padding_bytes = self
            .quic_padding_bytes
            .saturating_add(u64::from(composition.quic_padding_bytes));
        self.other_quic_bytes = self
            .other_quic_bytes
            .saturating_add(u64::from(composition.other_quic_bytes));
        self.lateness_us_total = self
            .lateness_us_total
            .saturating_add(composition.lateness_us);
        self.lateness_us_max = self.lateness_us_max.max(composition.lateness_us);

        if composition.application_stream_bytes > 0 {
            // Only a freshly real-bearing datagram is an eligible IAT sample
            // and boundary increment. Retransmission-only and cover-only
            // opportunities do not advance the source estimator analogue. The
            // adaptation boundary counts exact fresh application STREAM bytes,
            // never the surrounding UDP cell or defense-added bytes.
            self.record_estimator_sample(at_us, Direction::Outgoing);
            self.real_bearing_bytes[OUTGOING] = self.real_bearing_bytes[OUTGOING]
                .saturating_add(u64::from(composition.application_stream_bytes));
            self.adapt_rate_if_due(at_us, Direction::Outgoing);
        }
    }

    fn record_outcome(&mut self, at_us: u64, packet: Packet, outcome: EventOutcome) {
        debug_assert_eq!(packet.direction(), Direction::Outgoing);
        let at_minimum_interval = self.in_flight_at_minimum_interval[OUTGOING];
        self.terminal[OUTGOING] = self.terminal[OUTGOING].saturating_add(1);
        if at_minimum_interval {
            self.minimum_interval_terminal[OUTGOING] =
                self.minimum_interval_terminal[OUTGOING].saturating_add(1);
            if matches!(
                outcome,
                EventOutcome::Satisfied { .. } | EventOutcome::FullySatisfied { .. }
            ) {
                self.minimum_interval_full[OUTGOING] =
                    self.minimum_interval_full[OUTGOING].saturating_add(1);
            }
        }
        self.desired_udp_bytes = self
            .desired_udp_bytes
            .saturating_add(u64::from(packet.length()));
        match outcome {
            EventOutcome::FullySatisfied { composition } => {
                self.full_outgoing = self.full_outgoing.saturating_add(1);
                self.record_composition(at_us, composition);
            }
            EventOutcome::PartiallySatisfied { composition, .. } => {
                self.partial_outgoing = self.partial_outgoing.saturating_add(1);
                self.record_composition(at_us, composition);
            }
            EventOutcome::Suppressed { composition, .. } => {
                self.suppressed_outgoing = self.suppressed_outgoing.saturating_add(1);
                self.record_composition(at_us, composition);
            }
            EventOutcome::Satisfied { observed } => {
                self.full_outgoing = self.full_outgoing.saturating_add(1);
                self.record_termination_increment(OUTGOING, u64::from(observed));
                self.realized_total[OUTGOING] =
                    self.realized_total[OUTGOING].saturating_add(u64::from(observed));
            }
            EventOutcome::Missed(_) => {
                self.missed_outgoing = self.missed_outgoing.saturating_add(1);
                self.realization_failed = true;
            }
        }
        self.in_flight[OUTGOING] = false;
        self.in_flight_at_minimum_interval[OUTGOING] = false;
        let delay = self.randomized_delay_us(Direction::Outgoing);
        self.next_us[OUTGOING] = at_us.saturating_add(delay);
        self.maybe_latch_local_termination();
    }

    fn record_incoming_scheduled(&mut self, slot: QcsdSlotId, packet: Packet) {
        if packet.direction() != Direction::Incoming
            || !self.in_flight[INCOMING]
            || self.pending_incoming.contains_key(&slot)
            || self
                .pending_incoming
                .values()
                .any(|pending| !pending.locally_realized)
        {
            self.realization_failed = true;
            return;
        }
        self.pending_incoming.insert(
            slot,
            PendingIncomingOpportunity {
                packet,
                at_minimum_interval: self.in_flight_at_minimum_interval[INCOMING],
                locally_realized: false,
            },
        );
    }

    fn record_incoming_advertised(&mut self, at_us: u64, slot: QcsdSlotId, packet: Packet) {
        let Some(pending) = self.pending_incoming.get_mut(&slot) else {
            self.realization_failed = true;
            return;
        };
        if packet.direction() != Direction::Incoming
            || pending.packet != packet
            || pending.locally_realized
            || !self.in_flight[INCOMING]
        {
            self.realization_failed = true;
            return;
        }
        pending.locally_realized = true;
        self.incoming_local_realized = self.incoming_local_realized.saturating_add(1);
        if pending.at_minimum_interval {
            self.minimum_interval_incoming_local_realized = self
                .minimum_interval_incoming_local_realized
                .saturating_add(1);
        }
        self.in_flight[INCOMING] = false;
        self.in_flight_at_minimum_interval[INCOMING] = false;
        let delay = self.randomized_delay_us(Direction::Incoming);
        self.next_us[INCOMING] = at_us.saturating_add(delay);
        self.maybe_latch_local_termination();
    }

    fn record_incoming_outcome(&mut self, slot: QcsdSlotId, packet: Packet, outcome: EventOutcome) {
        let pending = self.pending_incoming.remove(&slot);
        let pending_matches = pending.is_some_and(|pending| pending.packet == packet);
        let locally_realized = pending.is_some_and(|pending| pending.locally_realized);
        let at_minimum_interval = pending.is_some_and(|pending| pending.at_minimum_interval);
        if packet.direction() != Direction::Incoming || !pending_matches {
            self.realization_failed = true;
        }
        self.terminal[INCOMING] = self.terminal[INCOMING].saturating_add(1);
        if at_minimum_interval {
            self.minimum_interval_terminal[INCOMING] =
                self.minimum_interval_terminal[INCOMING].saturating_add(1);
            if matches!(
                outcome,
                EventOutcome::Satisfied { .. } | EventOutcome::FullySatisfied { .. }
            ) {
                self.minimum_interval_full[INCOMING] =
                    self.minimum_interval_full[INCOMING].saturating_add(1);
            }
        }
        match outcome {
            EventOutcome::Satisfied { observed } => {
                if !locally_realized {
                    self.realization_failed = true;
                }
                self.record_termination_increment(INCOMING, u64::from(observed));
                self.realized_total[INCOMING] =
                    self.realized_total[INCOMING].saturating_add(u64::from(observed));
            }
            EventOutcome::FullySatisfied { composition } => {
                if !locally_realized {
                    self.realization_failed = true;
                }
                self.record_termination_increment(
                    INCOMING,
                    u64::from(composition.observed_udp_bytes),
                );
                self.realized_total[INCOMING] = self.realized_total[INCOMING]
                    .saturating_add(u64::from(composition.observed_udp_bytes));
            }
            EventOutcome::Missed(_)
            | EventOutcome::PartiallySatisfied { .. }
            | EventOutcome::Suppressed { .. } => {
                self.missed_incoming = self.missed_incoming.saturating_add(1);
                self.realization_failed = true;
            }
        }
        if !locally_realized {
            self.in_flight[INCOMING] = false;
            self.in_flight_at_minimum_interval[INCOMING] = false;
        }
        self.maybe_latch_local_termination();
    }

    fn pop_direction(&mut self, elapsed_us: u64, direction: Direction) -> Option<Packet> {
        let index = direction_index(direction);
        if self.in_flight[index]
            || self.direction_complete(direction)
            || self.event_guard_triggered
            || self.realization_failed
        {
            return None;
        }
        if self.total_scheduled() >= self.parameters.max_events {
            self.event_guard_triggered = true;
            return None;
        }
        if self.next_us[index] > elapsed_us {
            return None;
        }
        // A CS opportunity is a one-shot timer firing, not a fixed cadence
        // slot. Timestamp it at actual handling so OS wakeup delay cannot turn
        // the opportunity into an already-expired controller window. The next
        // timer is armed only after this opportunity terminalizes.
        let timestamp_us = elapsed_us;
        let packet = Packet::new(
            Duration::from_micros(timestamp_us),
            direction,
            self.parameters.packet_size,
        )
        .ok()?;
        self.scheduled[index] = self.scheduled[index].saturating_add(1);
        self.in_flight[index] = true;
        self.in_flight_at_minimum_interval[index] =
            self.current_interval_us[index] == self.parameters.minimum_interval_us;
        if self.in_flight_at_minimum_interval[index] {
            self.minimum_interval_scheduled[index] =
                self.minimum_interval_scheduled[index].saturating_add(1);
        }
        Some(packet)
    }
}

impl Defense for CsBuflo {
    fn observe(&mut self, signal: DefenseSignal) {
        let at_us = u64::try_from(signal.at.as_micros()).unwrap_or(u64::MAX);
        self.latest_elapsed_us = self.latest_elapsed_us.max(at_us);
        match signal.kind {
            SignalKind::ApplicationComplete => self.freeze_padding_targets(at_us),
            SignalKind::EgressBacklog { pending } => self.egress_backlog_pending = pending,
            SignalKind::PayloadBytes {
                direction,
                bytes,
                cover: true,
            } => {
                let index = direction_index(direction);
                self.cover_payload[index] = self.cover_payload[index].saturating_add(bytes);
            }
            SignalKind::Resolved { packet, outcome } => {
                self.record_outcome(at_us, packet, outcome);
            }
            SignalKind::IncomingCreditScheduled { slot, packet } => {
                self.record_incoming_scheduled(slot, packet);
            }
            SignalKind::IncomingCreditAdvertised { slot, packet } => {
                self.record_incoming_advertised(at_us, slot, packet);
            }
            SignalKind::IncomingCreditResolved {
                slot,
                packet,
                outcome,
            } => self.record_incoming_outcome(slot, packet, outcome),
            _ => {}
        }
        self.maybe_latch_local_termination();
    }

    fn observe_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
        let at_us = u64::try_from(at.as_micros()).unwrap_or(u64::MAX);
        self.latest_elapsed_us = self.latest_elapsed_us.max(at_us);
        let index = direction_index(direction);
        self.natural[index] = self.natural[index].saturating_add(bytes);
        self.last_natural_us[index] = Some(at_us);
        if direction == Direction::Incoming {
            // No cooperating peer exposes incoming packet composition. The
            // client-only approximation therefore samples consumed real
            // request-stream offsets and advances its directional boundary.
            self.record_estimator_sample(at_us, direction);
            self.real_bearing_bytes[index] = self.real_bearing_bytes[index].saturating_add(bytes);
            self.adapt_rate_if_due(at_us, direction);
        }
    }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        if self.local_termination_latched {
            return None;
        }
        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.latest_elapsed_us = self.latest_elapsed_us.max(elapsed_us);
        self.freeze_strict_quiet_targets();
        let first = if self.next_us[OUTGOING] <= self.next_us[INCOMING] {
            Direction::Outgoing
        } else {
            Direction::Incoming
        };
        let event = self.pop_direction(elapsed_us, first).or_else(|| {
            self.pop_direction(
                elapsed_us,
                match first {
                    Direction::Outgoing => Direction::Incoming,
                    Direction::Incoming => Direction::Outgoing,
                },
            )
        });
        if event.is_none() {
            self.maybe_latch_local_termination();
        }
        event
    }

    fn next_event_at(&self) -> Option<Duration> {
        if self.is_complete() || self.realization_failed {
            return None;
        }
        let mut candidates = Vec::with_capacity(4);
        for direction in [Direction::Outgoing, Direction::Incoming] {
            if !self.direction_complete(direction) {
                let index = direction_index(direction);
                if !self.in_flight[index] {
                    candidates.push(self.next_us[index]);
                }
                if let Some(quiet) = self.quiet_deadline_us(direction) {
                    candidates.push(quiet);
                }
            }
        }
        candidates.into_iter().min().map(Duration::from_micros)
    }

    fn is_complete(&self) -> bool {
        self.event_guard_triggered
            || self.local_termination_latched
            || (self.direction_complete(Direction::Outgoing)
                && self.direction_complete(Direction::Incoming))
    }

    fn is_outgoing_complete(&self) -> bool {
        self.event_guard_triggered || self.direction_complete(Direction::Outgoing)
    }

    fn terminal_failure(&self) -> Option<&'static str> {
        if self.event_guard_triggered {
            Some("CS-BuFLO event guard exhausted before normal completion")
        } else if self.realization_failed {
            Some("CS-BuFLO adapter produced a non-congestion realization failure")
        } else {
            None
        }
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffAndShape
    }

    fn outgoing_send_policy(&self) -> QcsdSendPolicy {
        QcsdSendPolicy::CongestionSensitive
    }

    fn incoming_slot_must_resolve_in_window(&self) -> bool {
        true
    }

    fn split_incoming_credit_lifecycle(&self) -> bool {
        true
    }

    fn requires_terminal_chaff_drain(&self) -> bool {
        true
    }

    fn cancel_open_chaff_on_completion(&self) -> bool {
        true
    }

    fn deduplicate_chaff_payload_offsets(&self) -> bool {
        true
    }

    fn retain_stream_offset_provenance_after_close(&self) -> bool {
        true
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the immutable CS-BuFLO terminal receipt keeps every comparison field explicit"
    )]
    fn diagnostics(&self) -> DefenseDiagnostics {
        let targets = self.padding_targets.map(|value| value.unwrap_or(0));
        let basis_natural = self.padding_basis_natural.map(|value| value.unwrap_or(0));
        let basis_cover = self.padding_basis_cover.map(|value| value.unwrap_or(0));
        let basis_total = self.padding_basis_total.map(|value| value.unwrap_or(0));
        DefenseDiagnostics {
            cs_buflo_paper_equivalent: false,
            cs_buflo_client_only: true,
            cs_buflo_payload_padding: self.parameters.outgoing_padding_mode
                == CsBufloPaddingMode::Payload
                && self.parameters.incoming_padding_mode == CsBufloPaddingMode::Payload,
            cs_buflo_total_padding: self.parameters.outgoing_padding_mode
                == CsBufloPaddingMode::Total
                && self.parameters.incoming_padding_mode == CsBufloPaddingMode::Payload,
            cs_buflo_scheduled_outgoing_cells: self.scheduled[OUTGOING],
            cs_buflo_scheduled_incoming_cells: self.scheduled[INCOMING],
            cs_buflo_full_outgoing_cells: self.full_outgoing,
            cs_buflo_partial_outgoing_cells: self.partial_outgoing,
            cs_buflo_suppressed_outgoing_cells: self.suppressed_outgoing,
            cs_buflo_missed_outgoing_cells: self.missed_outgoing,
            cs_buflo_missed_incoming_cells: self.missed_incoming,
            cs_buflo_desired_udp_bytes: self.desired_udp_bytes,
            cs_buflo_realized_udp_bytes: self.realized_total[OUTGOING],
            cs_buflo_application_stream_bytes: self.application_stream_bytes,
            cs_buflo_retransmission_stream_bytes: self.retransmission_stream_bytes,
            cs_buflo_chaff_stream_bytes: self.chaff_stream_bytes,
            cs_buflo_defense_control_bytes: self.defense_control_bytes,
            cs_buflo_quic_padding_bytes: self.quic_padding_bytes,
            cs_buflo_other_quic_bytes: self.other_quic_bytes,
            cs_buflo_lateness_us_total: self.lateness_us_total,
            cs_buflo_lateness_us_max: self.lateness_us_max,
            cs_buflo_natural_outgoing_bytes: self.natural[OUTGOING],
            cs_buflo_natural_incoming_bytes: self.natural[INCOMING],
            cs_buflo_cover_outgoing_bytes: self.cover_payload[OUTGOING],
            cs_buflo_cover_incoming_bytes: self.cover_payload[INCOMING],
            cs_buflo_realized_incoming_credit_bytes: self.realized_total[INCOMING],
            cs_buflo_outgoing_padding_basis_natural_bytes: basis_natural[OUTGOING],
            cs_buflo_incoming_padding_basis_natural_bytes: basis_natural[INCOMING],
            cs_buflo_outgoing_padding_basis_cover_bytes: basis_cover[OUTGOING],
            cs_buflo_incoming_padding_basis_cover_bytes: basis_cover[INCOMING],
            cs_buflo_outgoing_padding_basis_total_bytes: basis_total[OUTGOING],
            cs_buflo_incoming_padding_basis_total_bytes: basis_total[INCOMING],
            cs_buflo_early_termination_semantics: EARLY_TERMINATION_SEMANTICS,
            cs_buflo_reference_tcp_write_size_bytes: REFERENCE_TCP_WRITE_SIZE_BYTES,
            cs_buflo_reference_nominal_tcp_packet_size_bytes:
                REFERENCE_NOMINAL_TCP_PACKET_SIZE_BYTES,
            cs_buflo_runtime_udp_packet_size_bytes: u64::from(self.parameters.packet_size),
            cs_buflo_outgoing_termination_accounted_bytes: self.termination_accounted_bytes
                [OUTGOING],
            cs_buflo_incoming_termination_accounted_bytes: self.termination_accounted_bytes
                [INCOMING],
            cs_buflo_outgoing_last_termination_increment_bytes: self
                .last_termination_increment_bytes[OUTGOING],
            cs_buflo_incoming_last_termination_increment_bytes: self
                .last_termination_increment_bytes[INCOMING],
            cs_buflo_outgoing_power_of_two_crossed: crossed_power_of_two(
                self.termination_accounted_bytes[OUTGOING],
                self.last_termination_increment_bytes[OUTGOING],
            ),
            cs_buflo_incoming_power_of_two_crossed: crossed_power_of_two(
                self.termination_accounted_bytes[INCOMING],
                self.last_termination_increment_bytes[INCOMING],
            ),
            cs_buflo_real_bearing_outgoing_bytes: self.real_bearing_bytes[OUTGOING],
            cs_buflo_real_bearing_incoming_bytes: self.real_bearing_bytes[INCOMING],
            cs_buflo_outgoing_padding_target_bytes: targets[OUTGOING],
            cs_buflo_incoming_padding_target_bytes: targets[INCOMING],
            cs_buflo_outgoing_interval_us: self.current_interval_us[OUTGOING],
            cs_buflo_incoming_interval_us: self.current_interval_us[INCOMING],
            cs_buflo_outgoing_rate_adaptations: self.rate_adaptations[OUTGOING],
            cs_buflo_incoming_rate_adaptations: self.rate_adaptations[INCOMING],
            cs_buflo_rate_boundary_translation_version: 2,
            cs_buflo_rate_boundary_counter_semantics: RATE_BOUNDARY_COUNTER_SEMANTICS,
            cs_buflo_author_rate_boundary_counter_semantics: AUTHOR_RATE_BOUNDARY_COUNTER_SEMANTICS,
            cs_buflo_rate_transitions: self.rate_transitions.clone(),
            cs_buflo_outgoing_minimum_interval_opportunities: self.minimum_interval_scheduled
                [OUTGOING],
            cs_buflo_incoming_minimum_interval_opportunities: self.minimum_interval_scheduled
                [INCOMING],
            cs_buflo_incoming_minimum_interval_local_realized: self
                .minimum_interval_incoming_local_realized,
            cs_buflo_outgoing_minimum_interval_terminal: self.minimum_interval_terminal[OUTGOING],
            cs_buflo_incoming_minimum_interval_terminal: self.minimum_interval_terminal[INCOMING],
            cs_buflo_outgoing_minimum_interval_full: self.minimum_interval_full[OUTGOING],
            cs_buflo_incoming_minimum_interval_full: self.minimum_interval_full[INCOMING],
            cs_buflo_incoming_local_realized_cells: self.incoming_local_realized,
            cs_buflo_next_outgoing_adaptation_boundary_bytes: self.next_adaptation_boundary_bytes
                [OUTGOING],
            cs_buflo_next_incoming_adaptation_boundary_bytes: self.next_adaptation_boundary_bytes
                [INCOMING],
            cs_buflo_outgoing_estimator_samples: u64::try_from(self.iat_samples_us[OUTGOING].len())
                .unwrap_or(u64::MAX),
            cs_buflo_incoming_estimator_samples: u64::try_from(self.iat_samples_us[INCOMING].len())
                .unwrap_or(u64::MAX),
            cs_buflo_outgoing_unresolved_cells: self.scheduled[OUTGOING]
                .saturating_sub(self.terminal[OUTGOING]),
            cs_buflo_incoming_unresolved_cells: self.scheduled[INCOMING]
                .saturating_sub(self.terminal[INCOMING]),
            cs_buflo_egress_backlog_pending: self.egress_backlog_pending,
            cs_buflo_application_complete: self.application_complete(),
            cs_buflo_quiet_time_reached: [Direction::Outgoing, Direction::Incoming]
                .into_iter()
                .all(|direction| self.channel_idle(direction)),
            cs_buflo_local_termination_latched: self.local_termination_latched,
            cs_buflo_event_guard_triggered: self.event_guard_triggered,
            ..DefenseDiagnostics::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, time::Duration};

    use super::{
        CsBuflo, INCOMING, OUTGOING, crossed_power_of_two, floor_power_of_two,
        outgoing_termination_increment, payload_padding_target,
    };
    use crate::{
        CsBufloEarlyTermination, CsBufloPaddingMode, CsBufloParameters, Defense as _,
        DefenseSignal, Direction, EventOutcome, MissedSlotReason, Packet, QcsdImplementationScope,
        QcsdSendPolicy, QcsdSlotComposition, QcsdSlotId, SignalKind,
    };

    fn parameters(outgoing: CsBufloPaddingMode) -> CsBufloParameters {
        CsBufloParameters {
            schema_version: 1,
            packet_size: 600,
            initial_interval_us: 8_192,
            minimum_interval_us: 4_096,
            maximum_interval_us: 32_768,
            initial_adaptation_boundary_bytes: 16_384,
            quiet_time_us: 2_000_000,
            outgoing_padding_mode: outgoing,
            incoming_padding_mode: CsBufloPaddingMode::Payload,
            timing_sample_limit: 1_000,
            jitter_denominator: 100,
            jitter_max_numerator: 200,
            early_termination: CsBufloEarlyTermination::Local,
            max_events: 1_000,
            implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
            paper_equivalent: false,
        }
    }

    fn oracle_direction_index(direction: Direction) -> usize {
        match direction {
            Direction::Outgoing => 0,
            Direction::Incoming => 1,
        }
    }

    fn oracle_floor_power_of_two(value: u64) -> u64 {
        let mut rounded = 1_u64;
        while rounded <= value / 2 {
            rounded *= 2;
        }
        rounded
    }

    fn oracle_ceiling_power_of_two(value: u64) -> u64 {
        if value <= 1 {
            return value;
        }
        let mut rounded = 1_u64;
        while rounded < value {
            rounded *= 2;
        }
        rounded
    }

    fn oracle_payload_target(real: u64, cover: u64) -> u64 {
        let current = real + cover;
        if current == 0 {
            return 0;
        }
        let quantum = oracle_ceiling_power_of_two(real.max(1));
        current.div_ceil(quantum) * quantum
    }

    fn oracle_crossed(total: u64, increment: u64) -> bool {
        if total == 0 || increment == 0 || increment > total {
            return false;
        }
        let previous = total - increment;
        let previous_width = if previous == 0 {
            0
        } else {
            u64::from(u64::BITS - previous.leading_zeros())
        };
        let total_width = u64::from(u64::BITS - total.leading_zeros());
        previous_width < total_width
    }

    #[derive(Debug)]
    struct EstimatorOracle {
        current_interval_us: [u64; 2],
        next_boundary: [u64; 2],
        real_bearing: [u64; 2],
        adaptations: [u64; 2],
        samples: [VecDeque<u64>; 2],
        last_at: [Option<u64>; 2],
        last_direction: Option<Direction>,
    }

    impl EstimatorOracle {
        fn new(parameters: &CsBufloParameters) -> Self {
            Self {
                current_interval_us: [parameters.initial_interval_us; 2],
                next_boundary: [parameters.initial_adaptation_boundary_bytes; 2],
                real_bearing: [0; 2],
                adaptations: [0; 2],
                samples: std::array::from_fn(|_| VecDeque::new()),
                last_at: [None; 2],
                last_direction: None,
            }
        }

        fn observe(
            &mut self,
            at_us: u64,
            direction: Direction,
            boundary_increment: u64,
            parameters: &CsBufloParameters,
        ) {
            let index = oracle_direction_index(direction);
            if self.last_direction != Some(direction) {
                self.last_direction = Some(direction);
                self.last_at[index] = None;
            }
            if let Some(previous) = self.last_at[index] {
                let sample = at_us.saturating_sub(previous).clamp(
                    parameters.minimum_interval_us,
                    parameters.maximum_interval_us,
                );
                if self.samples[index].len() == parameters.timing_sample_limit {
                    self.samples[index].pop_front();
                }
                self.samples[index].push_back(sample);
            }
            self.last_at[index] = Some(at_us);
            self.real_bearing[index] = self.real_bearing[index].saturating_add(boundary_increment);
            while self.real_bearing[index] >= self.next_boundary[index] {
                if !self.samples[index].is_empty() {
                    let mut sorted: Vec<_> = self.samples[index].iter().copied().collect();
                    sorted.sort_unstable();
                    let median = sorted[sorted.len() / 2];
                    self.current_interval_us[index] = oracle_floor_power_of_two(median.max(1))
                        .clamp(
                            parameters.minimum_interval_us,
                            parameters.maximum_interval_us,
                        );
                }
                self.samples[index].clear();
                self.adaptations[index] += 1;
                self.next_boundary[index] *= 2;
            }
        }
    }

    #[test]
    fn paper_interval_rounding_is_power_of_two_and_bounded() {
        assert_eq!(floor_power_of_two(9_999), 8_192);
        assert_eq!(floor_power_of_two(4_096), 4_096);
    }

    #[test]
    fn estimator_uses_clamped_zero_intervals_and_the_upper_even_median() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 5);
        defense.current_interval_us[OUTGOING] = 4_096;
        for at in [0, 5_000, 15_000] {
            defense.record_estimator_sample(at, Direction::Outgoing);
        }
        assert_eq!(defense.median_interval_us(OUTGOING), Some(10_000));
        defense.real_bearing_bytes[OUTGOING] = 16_384;
        defense.adapt_rate_if_due(15_000, Direction::Outgoing);
        assert_eq!(defense.current_interval_us[OUTGOING], 8_192);
        assert_eq!(defense.rate_transitions.len(), 1);
        let transition = &defense.rate_transitions[0];
        assert_eq!(transition.schema_version, 1);
        assert_eq!(transition.direction, "outgoing");
        assert_eq!(transition.at_us, 15_000);
        assert_eq!(transition.boundary_bytes, 16_384);
        assert_eq!(transition.real_bearing_bytes, 16_384);
        assert_eq!(transition.eligible_samples, 2);
        assert_eq!(transition.median_interval_us, Some(10_000));
        assert_eq!(transition.previous_interval_us, 4_096);
        assert_eq!(transition.resulting_interval_us, 8_192);
        assert!(!transition.retained_current_interval);

        let mut zero_interval = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 6);
        zero_interval.record_estimator_sample(10, Direction::Outgoing);
        zero_interval.record_estimator_sample(10, Direction::Outgoing);
        assert_eq!(
            zero_interval.iat_samples_us[OUTGOING].front().copied(),
            Some(4_096)
        );
    }

    #[test]
    fn ctsp_is_total_only_on_outgoing_while_cpsp_is_payload_both_directions() {
        let mut payload_variant =
            CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Payload), 7);
        let mut total_variant = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 7);
        for defense in [&mut payload_variant, &mut total_variant] {
            defense.natural = [1_000, 1_000];
            defense.cover_payload = [1_100, 1_100];
            defense.realized_total = [2_100, 2_100];
            defense.observe(DefenseSignal {
                at: Duration::from_millis(1),
                kind: SignalKind::ApplicationComplete,
            });
        }
        assert_eq!(payload_padding_target(1_000, 24), 1_024);
        assert_eq!(payload_padding_target(1_000, 1_100), 3_072);
        assert_eq!(payload_variant.padding_targets, [Some(3_072), Some(3_072)]);
        assert_eq!(total_variant.padding_targets, [Some(4_096), Some(3_072)]);
        let diagnostics = total_variant.diagnostics();
        assert_eq!(
            diagnostics.cs_buflo_outgoing_padding_basis_natural_bytes,
            1_000
        );
        assert_eq!(
            diagnostics.cs_buflo_incoming_padding_basis_natural_bytes,
            1_000
        );
        assert_eq!(
            diagnostics.cs_buflo_outgoing_padding_basis_cover_bytes,
            1_100
        );
        assert_eq!(
            diagnostics.cs_buflo_incoming_padding_basis_cover_bytes,
            1_100
        );
        assert_eq!(
            diagnostics.cs_buflo_outgoing_padding_basis_total_bytes,
            2_100
        );
        assert_eq!(
            diagnostics.cs_buflo_incoming_padding_basis_total_bytes,
            2_100
        );
        assert_eq!(diagnostics.cs_buflo_cover_outgoing_bytes, 1_100);
        assert_eq!(diagnostics.cs_buflo_cover_incoming_bytes, 1_100);
        assert_eq!(diagnostics.cs_buflo_realized_incoming_credit_bytes, 2_100);
    }

    #[test]
    fn onload_is_immediately_idle_but_quiet_fallback_is_strict() {
        let mut quiet = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Payload), 8);
        quiet.last_natural_us = [Some(0), Some(0)];
        quiet.latest_elapsed_us = 2_000_000;
        assert!(!quiet.channel_idle(Direction::Outgoing));
        assert!(!quiet.channel_idle(Direction::Incoming));
        quiet.latest_elapsed_us = 2_000_001;
        assert!(quiet.channel_idle(Direction::Outgoing));
        assert!(quiet.channel_idle(Direction::Incoming));

        let mut onload = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Payload), 9);
        onload.natural = [1_000, 1_000];
        onload.cover_payload = [24, 24];
        onload.realized_total = [1_024, 1_024];
        onload.egress_backlog_pending = false;
        onload.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ApplicationComplete,
        });
        assert!(onload.channel_idle(Direction::Outgoing));
        assert!(onload.channel_idle(Direction::Incoming));
        assert!(onload.is_complete());
        assert!(onload.diagnostics().cs_buflo_quiet_time_reached);
    }

    #[test]
    fn quiet_fallback_never_freezes_a_target_while_egress_is_backlogged() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Payload), 90);
        defense.next_us = [u64::MAX; 2];
        defense.natural = [100, 100];
        defense.cover_payload = [24, 24];
        defense.realized_total = [124, 124];
        defense.last_natural_us = [Some(0), Some(0)];

        assert_eq!(defense.next_event(Duration::from_micros(2_000_001)), None);
        assert_eq!(defense.padding_targets, [None, None]);

        defense.observe_application_bytes(
            Duration::from_micros(2_000_002),
            Direction::Outgoing,
            900,
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2_000_002),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        assert_eq!(defense.next_event(Duration::from_micros(4_000_003)), None);
        assert_eq!(defense.padding_basis_natural, [Some(1_000), Some(100)]);
        assert_eq!(defense.padding_targets, [Some(1_024), Some(128)]);
    }

    #[test]
    fn zero_application_completion_freezes_zero_targets_and_terminates_without_cells() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 10);
        defense.egress_backlog_pending = false;
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ApplicationComplete,
        });

        assert_eq!(defense.padding_targets, [Some(0), Some(0)]);
        assert_eq!(defense.scheduled, [0, 0]);
        assert_eq!(defense.terminal, [0, 0]);
        assert!(defense.is_complete());
        assert_eq!(defense.next_event(Duration::ZERO), None);
    }

    #[test]
    fn estimator_is_direction_specific_separated_and_bounded() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 9);
        defense.next_adaptation_boundary_bytes = [u64::MAX; 2];
        let real = QcsdSlotComposition {
            desired_udp_bytes: 600,
            observed_udp_bytes: 600,
            application_stream_bytes: 1,
            ..QcsdSlotComposition::default()
        };
        defense.record_composition(10, real);
        defense.record_composition(20, real);
        defense.observe_application_bytes(Duration::from_micros(30), Direction::Incoming, 1);
        defense.record_composition(40, real);
        assert_eq!(
            defense.iat_samples_us[OUTGOING]
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [4_096]
        );
        assert!(defense.iat_samples_us[INCOMING].is_empty());
        for at in 41..=1_100 {
            defense.record_composition(at, real);
        }
        assert_eq!(defense.iat_samples_us[OUTGOING].len(), 1_000);
    }

    #[test]
    fn adaptation_boundary_counts_exact_fresh_application_stream_bytes() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 11);
        let cover_only = QcsdSlotComposition {
            desired_udp_bytes: 600,
            observed_udp_bytes: 600,
            chaff_stream_bytes: 100,
            ..QcsdSlotComposition::default()
        };
        for at in 0..30 {
            defense.record_composition(at, cover_only);
        }
        assert_eq!(defense.rate_adaptations[OUTGOING], 0);
        assert!(defense.iat_samples_us[OUTGOING].is_empty());
        let retransmission_only = QcsdSlotComposition {
            desired_udp_bytes: 600,
            observed_udp_bytes: 600,
            retransmission_stream_bytes: 1,
            ..QcsdSlotComposition::default()
        };
        defense.record_composition(30, retransmission_only);
        assert_eq!(defense.real_bearing_bytes[OUTGOING], 0);
        assert!(defense.iat_samples_us[OUTGOING].is_empty());
        let full_real = QcsdSlotComposition {
            desired_udp_bytes: 600,
            observed_udp_bytes: 600,
            application_stream_bytes: 600,
            ..QcsdSlotComposition::default()
        };
        for at in 31..58 {
            defense.record_composition(at, full_real);
        }
        defense.record_composition(
            58,
            QcsdSlotComposition {
                desired_udp_bytes: 600,
                observed_udp_bytes: 600,
                application_stream_bytes: 183,
                ..QcsdSlotComposition::default()
            },
        );
        assert_eq!(defense.real_bearing_bytes[OUTGOING], 16_383);
        assert_eq!(defense.rate_adaptations[OUTGOING], 0);
        defense.record_composition(
            59,
            QcsdSlotComposition {
                desired_udp_bytes: 600,
                observed_udp_bytes: 600,
                application_stream_bytes: 1,
                ..QcsdSlotComposition::default()
            },
        );
        assert_eq!(defense.rate_adaptations[OUTGOING], 1);
        assert_eq!(defense.next_adaptation_boundary_bytes[OUTGOING], 32_768);
        assert!(defense.iat_samples_us[OUTGOING].is_empty());
    }

    #[test]
    fn cs_buflo_requests_congestion_sensitive_attempts() {
        let defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 9);
        assert_eq!(
            defense.outgoing_send_policy(),
            QcsdSendPolicy::CongestionSensitive
        );
    }

    #[test]
    fn crossing_uses_observed_udp_including_other_quic_and_partial_datagrams() {
        assert!(!crossed_power_of_two(1_800, 600));
        assert!(crossed_power_of_two(1_200, 600));
        assert!(crossed_power_of_two(1_050, 200));
        assert!(!crossed_power_of_two(1_050, 0));

        let composition = QcsdSlotComposition {
            desired_udp_bytes: 600,
            observed_udp_bytes: 300,
            application_stream_bytes: 100,
            chaff_stream_bytes: 50,
            defense_control_bytes: 1,
            quic_padding_bytes: 49,
            other_quic_bytes: 100,
            ..QcsdSlotComposition::default()
        };
        assert_eq!(outgoing_termination_increment(composition), 300);
        assert!(!oracle_crossed(950, 200));
        assert!(oracle_crossed(1_050, 300));

        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 12);
        // The specifically classified 200 bytes reach only 950. The extra 100
        // `other_quic_bytes` are what carry observed UDP across 1,024.
        defense.termination_accounted_bytes[OUTGOING] = 750;
        defense.scheduled[OUTGOING] = 1;
        defense.in_flight[OUTGOING] = true;
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 600).expect("packet");
        defense.record_outcome(
            10,
            packet,
            EventOutcome::PartiallySatisfied {
                composition,
                reason: crate::QcsdCongestionReason::CongestionLimited,
            },
        );
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.cs_buflo_partial_outgoing_cells, 1);
        assert_eq!(diagnostics.cs_buflo_realized_udp_bytes, 300);
        assert_eq!(
            diagnostics.cs_buflo_outgoing_termination_accounted_bytes,
            1_050
        );
        assert_eq!(
            diagnostics.cs_buflo_outgoing_last_termination_increment_bytes,
            300
        );
        assert!(diagnostics.cs_buflo_outgoing_power_of_two_crossed);
        assert_eq!(
            diagnostics.cs_buflo_early_termination_semantics,
            "udp_client_only_observed_udp_power_of_two_crossing"
        );
        assert_eq!(diagnostics.cs_buflo_reference_tcp_write_size_bytes, 548);
        assert_eq!(
            diagnostics.cs_buflo_reference_nominal_tcp_packet_size_bytes,
            600
        );
        assert_eq!(diagnostics.cs_buflo_runtime_udp_packet_size_bytes, 600);
    }

    #[test]
    fn onload_crossing_completes_only_after_backlog_and_both_terminal_outcomes() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 13);
        defense.natural = [1_000, 1_000];
        defense.cover_payload = [100, 100];
        defense.realized_total = [1_100, 1_100];
        defense.scheduled = [1, 1];
        defense.in_flight = [true, true];
        defense.egress_backlog_pending = false;
        defense.observe(DefenseSignal {
            at: Duration::from_micros(100),
            kind: SignalKind::ApplicationComplete,
        });
        assert_eq!(defense.padding_targets, [Some(2_048), Some(2_048)]);
        assert!(!defense.is_complete());

        let outgoing = Packet::new(Duration::ZERO, Direction::Outgoing, 600).expect("outgoing");
        defense.observe(DefenseSignal {
            at: Duration::from_micros(110),
            kind: SignalKind::Resolved {
                packet: outgoing,
                outcome: EventOutcome::FullySatisfied {
                    composition: QcsdSlotComposition {
                        desired_udp_bytes: 600,
                        observed_udp_bytes: 600,
                        application_stream_bytes: 100,
                        chaff_stream_bytes: 100,
                        quic_padding_bytes: 400,
                        ..QcsdSlotComposition::default()
                    },
                },
            },
        });
        assert!(!defense.is_complete());

        let incoming = Packet::new(Duration::ZERO, Direction::Incoming, 600).expect("incoming");
        let incoming_slot = QcsdSlotId(1);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(105),
            kind: SignalKind::IncomingCreditScheduled {
                slot: incoming_slot,
                packet: incoming,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(115),
            kind: SignalKind::IncomingCreditAdvertised {
                slot: incoming_slot,
                packet: incoming,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(120),
            kind: SignalKind::IncomingCreditResolved {
                slot: incoming_slot,
                packet: incoming,
                outcome: EventOutcome::Satisfied { observed: 600 },
            },
        });
        assert!(defense.progress(Direction::Outgoing) < 2_048);
        assert!(defense.progress(Direction::Incoming) < 2_048);
        assert_eq!(defense.terminal, [1, 1]);
        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert!(diagnostics.cs_buflo_outgoing_power_of_two_crossed);
        assert!(diagnostics.cs_buflo_incoming_power_of_two_crossed);
        assert_eq!(diagnostics.cs_buflo_outgoing_unresolved_cells, 0);
        assert_eq!(diagnostics.cs_buflo_incoming_unresolved_cells, 0);
    }

    #[test]
    fn strict_quiet_fallback_freezes_directional_targets_and_completes_without_onload() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 14);
        defense.natural = [1_000, 1_000];
        defense.cover_payload = [100, 100];
        defense.realized_total = [1_100, 1_100];
        defense.termination_accounted_bytes = [1_200, 1_200];
        defense.last_termination_increment_bytes = [600, 600];
        defense.scheduled = [1, 1];
        defense.terminal = [1, 1];
        defense.last_natural_us = [Some(0), Some(0)];
        defense.egress_backlog_pending = false;
        defense.latest_elapsed_us = 2_000_000;
        assert!(!defense.is_complete());
        assert_eq!(defense.padding_targets, [None, None]);

        assert_eq!(defense.next_event(Duration::from_micros(2_000_001)), None);
        assert!(!defense.application_complete());
        assert_eq!(defense.padding_targets, [Some(2_048), Some(2_048)]);
        assert_eq!(defense.padding_basis_natural, [Some(1_000), Some(1_000)]);
        assert!(defense.is_complete());
        assert!(defense.local_termination_latched);

        let scheduled = defense.scheduled;
        defense.observe_application_bytes(
            Duration::from_micros(2_000_100),
            Direction::Outgoing,
            10,
        );
        assert!(defense.is_complete(), "local ET is irreversible");
        assert_eq!(defense.next_event(Duration::from_millis(2_100)), None);
        assert_eq!(defense.scheduled, scheduled);
        assert!(defense.diagnostics().cs_buflo_local_termination_latched);
    }

    #[test]
    fn delayed_wakeup_keeps_one_opportunity_in_flight_and_anchors_the_next_to_resolution() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 15);
        defense.next_us = [0, 0];
        let delayed = Duration::from_secs(1);
        let outgoing = defense.next_event(delayed).expect("outgoing opportunity");
        let incoming = defense.next_event(delayed).expect("incoming opportunity");
        assert_eq!(outgoing.direction(), Direction::Outgoing);
        assert_eq!(incoming.direction(), Direction::Incoming);
        assert_eq!(outgoing.timestamp(), delayed);
        assert_eq!(incoming.timestamp(), delayed);
        assert_eq!(defense.next_event(delayed), None);
        assert_eq!(defense.scheduled, [1, 1]);
        assert_eq!(defense.in_flight, [true, true]);

        // Force the valid inclusive zero-jitter cohort: it becomes eligible
        // only after the current opportunity terminalizes, at the actual
        // resolution time rather than at a theoretical historical cadence.
        defense.current_interval_us[OUTGOING] = 0;
        defense.observe(DefenseSignal {
            at: delayed,
            kind: SignalKind::Resolved {
                packet: outgoing,
                outcome: EventOutcome::FullySatisfied {
                    composition: QcsdSlotComposition {
                        desired_udp_bytes: 600,
                        observed_udp_bytes: 600,
                        quic_padding_bytes: 600,
                        ..QcsdSlotComposition::default()
                    },
                },
            },
        });
        assert_eq!(defense.terminal[OUTGOING], 1);
        assert_eq!(defense.next_us[OUTGOING], 1_000_000);
        let zero_jitter = defense
            .next_event(delayed)
            .expect("zero-jitter opportunity");
        assert_eq!(zero_jitter.direction(), Direction::Outgoing);
        assert_eq!(zero_jitter.timestamp(), delayed);
        assert_eq!(defense.next_event(delayed), None);
        assert_eq!(defense.scheduled, [2, 1]);
        assert_eq!(defense.terminal, [1, 0]);
    }

    #[test]
    fn incoming_cadence_rearms_at_local_advertisement_not_peer_consumption() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 0x15);
        defense.next_us = [u64::MAX, 0];
        let first = defense
            .next_event(Duration::ZERO)
            .expect("first incoming opportunity");
        assert_eq!(first.direction(), Direction::Incoming);
        let first_slot = QcsdSlotId(101);
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::IncomingCreditScheduled {
                slot: first_slot,
                packet: first,
            },
        });

        // Force the inclusive zero-jitter draw so the causal anchor itself is
        // directly observable without depending on a pinned RNG sample.
        defense.current_interval_us[INCOMING] = 0;
        let advertised_at = Duration::from_millis(1);
        defense.observe(DefenseSignal {
            at: advertised_at,
            kind: SignalKind::IncomingCreditAdvertised {
                slot: first_slot,
                packet: first,
            },
        });
        assert_eq!(defense.next_us[INCOMING], 1_000);
        assert_eq!(defense.terminal[INCOMING], 0);
        assert_eq!(defense.incoming_local_realized, 1);

        let second = defense
            .next_event(advertised_at)
            .expect("next opportunity is armed by the local advertisement");
        assert_eq!(second.direction(), Direction::Incoming);
        assert_eq!(second.timestamp(), advertised_at);
        let next_before_consumption = defense.next_us[INCOMING];

        defense.observe(DefenseSignal {
            at: Duration::from_millis(50),
            kind: SignalKind::IncomingCreditResolved {
                slot: first_slot,
                packet: first,
                outcome: EventOutcome::Satisfied { observed: 600 },
            },
        });
        assert_eq!(defense.terminal[INCOMING], 1);
        assert_eq!(defense.next_us[INCOMING], next_before_consumption);
        assert!(
            defense.in_flight[INCOMING],
            "the second local attempt remains pending"
        );
    }

    #[test]
    fn overlapping_incoming_outcomes_keep_slot_exact_minimum_classification() {
        let mut defense = CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 0x16);
        defense.current_interval_us[INCOMING] = 4_096;
        defense.next_us[INCOMING] = 0;

        let minimum = defense
            .pop_direction(0, Direction::Incoming)
            .expect("minimum-interval incoming opportunity");
        let minimum_slot = QcsdSlotId(201);
        defense.record_incoming_scheduled(minimum_slot, minimum);
        defense.record_incoming_advertised(10, minimum_slot, minimum);

        defense.current_interval_us[INCOMING] = 8_192;
        defense.next_us[INCOMING] = 20;
        let ordinary = defense
            .pop_direction(20, Direction::Incoming)
            .expect("ordinary incoming opportunity");
        let ordinary_slot = QcsdSlotId(202);
        defense.record_incoming_scheduled(ordinary_slot, ordinary);
        defense.record_incoming_advertised(30, ordinary_slot, ordinary);
        assert_eq!(defense.pending_incoming.len(), 2);

        defense.record_incoming_outcome(
            ordinary_slot,
            ordinary,
            EventOutcome::Satisfied { observed: 600 },
        );
        assert_eq!(defense.minimum_interval_terminal[INCOMING], 0);
        assert_eq!(defense.minimum_interval_full[INCOMING], 0);

        defense.record_incoming_outcome(
            minimum_slot,
            minimum,
            EventOutcome::Satisfied { observed: 600 },
        );
        assert_eq!(defense.minimum_interval_terminal[INCOMING], 1);
        assert_eq!(defense.minimum_interval_full[INCOMING], 1);
        assert_eq!(defense.minimum_interval_incoming_local_realized, 1);
        assert!(defense.pending_incoming.is_empty());
    }

    #[test]
    fn event_guard_is_typed_terminal_failure() {
        let mut parameters = parameters(CsBufloPaddingMode::Total);
        parameters.max_events = 1;
        let mut defense = CsBuflo::from_parameters(parameters, 16);
        defense.next_us = [0, 0];

        let outgoing = defense
            .next_event(Duration::ZERO)
            .expect("first guarded opportunity");
        assert_eq!(outgoing.direction(), Direction::Outgoing);
        assert_eq!(defense.next_event(Duration::ZERO), None);

        assert_eq!(defense.scheduled, [1, 0]);
        assert!(defense.is_complete());
        assert_eq!(
            defense.terminal_failure(),
            Some("CS-BuFLO event guard exhausted before normal completion")
        );
        assert!(defense.diagnostics().cs_buflo_event_guard_triggered);
    }

    #[test]
    fn incoming_miss_is_a_typed_terminal_realization_failure() {
        let mut defense =
            CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 0x0123_4567_89ab_cdef);
        defense.next_us = [0, 0];
        let outgoing = defense
            .next_event(Duration::ZERO)
            .expect("outgoing opportunity");
        assert_eq!(outgoing.direction(), Direction::Outgoing);
        let incoming = defense
            .next_event(Duration::ZERO)
            .expect("incoming opportunity");
        assert_eq!(incoming.direction(), Direction::Incoming);
        let slot = QcsdSlotId(7);
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::IncomingCreditScheduled {
                slot,
                packet: incoming,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::IncomingCreditResolved {
                slot,
                packet: incoming,
                outcome: EventOutcome::Missed(MissedSlotReason::ReceiveCreditRetired),
            },
        });
        assert_eq!(defense.diagnostics().cs_buflo_missed_incoming_cells, 1);
        let scheduled = defense.scheduled;
        assert_eq!(defense.next_event(Duration::from_secs(1)), None);
        assert_eq!(
            defense.scheduled, scheduled,
            "a hard miss cannot arm a successor"
        );
        assert_eq!(
            defense.terminal_failure(),
            Some("CS-BuFLO adapter produced a non-congestion realization failure")
        );
    }

    #[test]
    fn minimum_interval_opportunities_are_causal_and_terminally_classified() {
        let mut defense =
            CsBuflo::from_parameters(parameters(CsBufloPaddingMode::Total), 0xfeed_face_cafe_beef);
        defense.current_interval_us = [4_096, 4_096];
        defense.next_us = [0, 0];
        let outgoing = defense
            .next_event(Duration::ZERO)
            .expect("minimum-interval outgoing opportunity");
        let incoming = defense
            .next_event(Duration::ZERO)
            .expect("minimum-interval incoming opportunity");
        let scheduled = defense.diagnostics();
        assert_eq!(
            scheduled.cs_buflo_outgoing_minimum_interval_opportunities,
            1
        );
        assert_eq!(
            scheduled.cs_buflo_incoming_minimum_interval_opportunities,
            1
        );
        assert_eq!(scheduled.cs_buflo_outgoing_minimum_interval_terminal, 0);
        assert_eq!(scheduled.cs_buflo_incoming_minimum_interval_terminal, 0);

        let incoming_slot = QcsdSlotId(9);
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::IncomingCreditScheduled {
                slot: incoming_slot,
                packet: incoming,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::IncomingCreditAdvertised {
                slot: incoming_slot,
                packet: incoming,
            },
        });

        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::Resolved {
                packet: outgoing,
                outcome: EventOutcome::FullySatisfied {
                    composition: QcsdSlotComposition {
                        desired_udp_bytes: 600,
                        observed_udp_bytes: 600,
                        other_quic_bytes: 600,
                        ..QcsdSlotComposition::default()
                    },
                },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::IncomingCreditResolved {
                slot: incoming_slot,
                packet: incoming,
                outcome: EventOutcome::Satisfied { observed: 600 },
            },
        });
        let terminal = defense.diagnostics();
        assert_eq!(terminal.cs_buflo_outgoing_minimum_interval_terminal, 1);
        assert_eq!(terminal.cs_buflo_incoming_minimum_interval_terminal, 1);
        assert_eq!(terminal.cs_buflo_outgoing_minimum_interval_full, 1);
        assert_eq!(terminal.cs_buflo_incoming_minimum_interval_full, 1);
        assert_eq!(
            terminal.cs_buflo_incoming_minimum_interval_local_realized,
            1
        );
        assert_eq!(terminal.cs_buflo_incoming_local_realized_cells, 1);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the single trace loop deliberately exercises every coupled oracle state"
    )]
    fn deterministic_high_volume_estimator_trace_matches_independent_oracle() {
        let parameters = parameters(CsBufloPaddingMode::Total);
        let mut production = CsBuflo::from_parameters(parameters.clone(), 0x51);
        let mut oracle = EstimatorOracle::new(&parameters);
        let mut natural = [0_u64; 2];
        let mut cover = [0_u64; 2];
        let mut realized_outgoing = 0_u64;
        let mut termination_outgoing = 0_u64;
        let mut latest_termination_increment = 0_u64;
        let mut state = 0xbb67_ae85_84ca_a73b_u64;
        let mut now_us = 0_u64;

        for _ in 0..50_000 {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            now_us = now_us.saturating_add((state >> 17) % 50_001);
            if state & 1 == 0 {
                let observed = u16::try_from((state >> 3) % 600 + 1).expect("bounded");
                let class = (state >> 13) % 5;
                let application = if class <= 1 {
                    u16::try_from((state >> 23) % u64::from(observed) + 1).expect("bounded")
                } else {
                    0
                };
                let remaining = observed.saturating_sub(application);
                let retransmission = if class == 2 { remaining.min(17) } else { 0 };
                let remaining = remaining.saturating_sub(retransmission);
                let chaff = if class == 3 { remaining.min(19) } else { 0 };
                let remaining = remaining.saturating_sub(chaff);
                let defense_control = if class == 4 { remaining.min(7) } else { 0 };
                let remaining = remaining.saturating_sub(defense_control);
                let padding = remaining / 2;
                let composition = QcsdSlotComposition {
                    desired_udp_bytes: 600,
                    observed_udp_bytes: observed,
                    application_stream_bytes: application,
                    retransmission_stream_bytes: retransmission,
                    chaff_stream_bytes: chaff,
                    defense_control_bytes: defense_control,
                    quic_padding_bytes: padding,
                    other_quic_bytes: remaining.saturating_sub(padding),
                    lateness_us: (state >> 31) % 500,
                };
                if application > 0 {
                    production.observe_application_bytes(
                        Duration::from_micros(now_us),
                        Direction::Outgoing,
                        u64::from(application),
                    );
                    natural[OUTGOING] += u64::from(application);
                }
                if chaff > 0 {
                    production.observe(DefenseSignal {
                        at: Duration::from_micros(now_us),
                        kind: SignalKind::PayloadBytes {
                            direction: Direction::Outgoing,
                            bytes: u64::from(chaff),
                            cover: true,
                        },
                    });
                    cover[OUTGOING] += u64::from(chaff);
                }
                production.record_composition(now_us, composition);
                realized_outgoing += u64::from(observed);
                let increment = u64::from(observed);
                if increment > 0 {
                    termination_outgoing += increment;
                    latest_termination_increment = increment;
                }
                if application > 0 {
                    oracle.observe(
                        now_us,
                        Direction::Outgoing,
                        u64::from(application),
                        &parameters,
                    );
                }
            } else if state & 6 == 0 {
                let bytes = (state >> 9) % 1_000 + 1;
                production.observe(DefenseSignal {
                    at: Duration::from_micros(now_us),
                    kind: SignalKind::PayloadBytes {
                        direction: Direction::Incoming,
                        bytes,
                        cover: true,
                    },
                });
                cover[INCOMING] += bytes;
            } else {
                let bytes = (state >> 9) % 1_000 + 1;
                production.observe_application_bytes(
                    Duration::from_micros(now_us),
                    Direction::Incoming,
                    bytes,
                );
                natural[INCOMING] += bytes;
                oracle.observe(now_us, Direction::Incoming, bytes, &parameters);
            }
        }

        assert_eq!(production.current_interval_us, oracle.current_interval_us);
        assert_eq!(
            production.next_adaptation_boundary_bytes,
            oracle.next_boundary
        );
        assert_eq!(production.real_bearing_bytes, oracle.real_bearing);
        assert_eq!(production.rate_adaptations, oracle.adaptations);
        assert_eq!(production.iat_samples_us, oracle.samples);
        assert_eq!(production.natural, natural);
        assert_eq!(production.cover_payload, cover);
        assert_eq!(production.realized_total[OUTGOING], realized_outgoing);
        assert_eq!(
            production.termination_accounted_bytes[OUTGOING],
            termination_outgoing
        );
        assert_eq!(
            production.last_termination_increment_bytes[OUTGOING],
            latest_termination_increment
        );

        // Hold adaptation beyond reach and prove the independent sliding
        // window never retains more than the configured 1,000 eligible IATs.
        let mut bounded = CsBuflo::from_parameters(parameters.clone(), 0x52);
        let mut bounded_oracle = EstimatorOracle::new(&parameters);
        bounded.next_adaptation_boundary_bytes = [u64::MAX; 2];
        bounded_oracle.next_boundary = [u64::MAX; 2];
        for index in 0..10_000_u64 {
            let at = index * 5_000;
            let composition = QcsdSlotComposition {
                observed_udp_bytes: 600,
                application_stream_bytes: 1,
                ..QcsdSlotComposition::default()
            };
            bounded.record_composition(at, composition);
            bounded_oracle.observe(at, Direction::Outgoing, 1, &parameters);
        }
        assert_eq!(bounded.iat_samples_us, bounded_oracle.samples);
        assert_eq!(bounded.iat_samples_us[OUTGOING].len(), 1_000);
    }

    #[test]
    fn randomized_padding_crossing_idle_and_termination_match_independent_oracle() {
        let mut state = 0x3c6e_f372_fe94_f82b_u64;
        let mut draw = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for case in 0..10_000_u64 {
            let total = draw() % 2_000_000;
            let increment = match case % 4 {
                0 => 0,
                1 => total,
                2 => total.saturating_sub(oracle_floor_power_of_two(total.max(1)) - 1),
                _ => draw() % total.saturating_add(1),
            };
            assert_eq!(
                crossed_power_of_two(total, increment),
                oracle_crossed(total, increment),
                "crossing case {case}: total={total}, increment={increment}"
            );
        }

        for case in 0..2_048_u64 {
            let outgoing_mode = if case & 1 == 0 {
                CsBufloPaddingMode::Total
            } else {
                CsBufloPaddingMode::Payload
            };
            let parameters = parameters(outgoing_mode);
            let mut defense = CsBuflo::from_parameters(parameters.clone(), case);
            let natural = [draw() % 1_000_000, draw() % 1_000_000];
            let cover = [draw() % 1_000_000, draw() % 1_000_000];
            let realized = [
                natural[OUTGOING]
                    .saturating_add(cover[OUTGOING])
                    .saturating_add(draw() % 1_000),
                natural[INCOMING]
                    .saturating_add(cover[INCOMING])
                    .saturating_add(draw() % 1_000),
            ];
            defense.natural = natural;
            defense.cover_payload = cover;
            defense.realized_total = realized;
            defense.observe(DefenseSignal {
                at: Duration::from_micros(case),
                kind: SignalKind::ApplicationComplete,
            });
            let expected_targets = [
                match outgoing_mode {
                    CsBufloPaddingMode::Total => oracle_ceiling_power_of_two(realized[OUTGOING]),
                    CsBufloPaddingMode::Payload => {
                        oracle_payload_target(natural[OUTGOING], cover[OUTGOING])
                    }
                },
                oracle_payload_target(natural[INCOMING], cover[INCOMING]),
            ];
            assert_eq!(defense.padding_targets, expected_targets.map(Some));

            // The generated state below independently exercises the completion
            // predicate rather than the irreversible result of the preceding
            // onLoad transition.
            defense.local_termination_latched = false;

            defense.scheduled = [draw() % 10, draw() % 10];
            defense.terminal = [draw() % 10, draw() % 10];
            defense.egress_backlog_pending = draw() & 1 != 0;
            defense.termination_accounted_bytes = [draw() % 1_000_000, draw() % 1_000_000];
            defense.last_termination_increment_bytes = [
                draw() % defense.termination_accounted_bytes[OUTGOING].saturating_add(1),
                draw() % defense.termination_accounted_bytes[INCOMING].saturating_add(1),
            ];
            for direction in [Direction::Outgoing, Direction::Incoming] {
                let index = oracle_direction_index(direction);
                let progress = match defense.padding_mode(direction) {
                    CsBufloPaddingMode::Total => defense.realized_total[index],
                    CsBufloPaddingMode::Payload => {
                        defense.natural[index] + defense.cover_payload[index]
                    }
                };
                let expected = (direction == Direction::Incoming
                    || defense.application_complete()
                    || !defense.egress_backlog_pending)
                    && defense.terminal[index] == defense.scheduled[index]
                    && (progress >= expected_targets[index]
                        || oracle_crossed(
                            defense.termination_accounted_bytes[index],
                            defense.last_termination_increment_bytes[index],
                        ));
                assert_eq!(defense.direction_complete(direction), expected);
            }

            let last = draw() % 1_000_000;
            let after_quiet = case & 2 != 0;
            let mut quiet = CsBuflo::from_parameters(parameters, case ^ 0xa5a5);
            quiet.last_natural_us = [Some(last), Some(last)];
            quiet.latest_elapsed_us =
                last + quiet.parameters.quiet_time_us + u64::from(after_quiet);
            quiet.egress_backlog_pending = case & 4 != 0;
            quiet.in_flight = [true, true];
            assert_eq!(quiet.channel_idle(Direction::Outgoing), after_quiet);
            assert_eq!(quiet.channel_idle(Direction::Incoming), after_quiet);
            quiet.freeze_strict_quiet_targets();
            assert_eq!(
                quiet.padding_targets.iter().all(Option::is_some),
                after_quiet && !quiet.egress_backlog_pending
            );
        }
    }
}
