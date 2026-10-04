// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::time::Duration;

use super::{
    BufloIncomingStartupDiagnostics, Defense, DefenseDiagnostics, DefenseMode, DefenseSignal,
    EventOutcome, SignalKind,
};
use crate::{
    BufloConfig, BufloParameters, Direction, Packet, QcsdChaffCancellationReason, QcsdSlotId,
    Result,
};

/// Clean-room, client-only `BuFLO` schedule adaptation.
///
/// This preserves the constant cell size, constant interval, and minimum
/// duration state machine. Incoming events are client receive-credit requests,
/// so this type deliberately makes no paper-equivalence claim.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "explicit terminal and fidelity flags are independently serialized diagnostics"
)]
pub struct Buflo {
    parameters: BufloParameters,
    next_incoming_us: u64,
    next_outgoing_us: u64,
    incoming_startup: Option<BufloIncomingStartupDiagnostics>,
    scheduled_incoming: u64,
    scheduled_outgoing: u64,
    full_outgoing: u64,
    partial_outgoing: u64,
    suppressed_outgoing: u64,
    missed_outgoing: u64,
    missed_incoming: u64,
    catch_up_incoming: u64,
    catch_up_outgoing: u64,
    terminal_incoming: u64,
    terminal_outgoing: u64,
    latest_elapsed_us: u64,
    application_complete: bool,
    egress_backlog_pending: bool,
    event_guard_triggered: bool,
    catch_up_failure_triggered: bool,
    realization_failed: bool,
    terminal_primary_partial: Option<QcsdSlotId>,
    schedule_stop_latched: bool,
    schedule_stop_latched_at_us: u64,
    schedule_stop_available_bytes: u64,
    schedule_stop_required_bytes: u64,
    schedule_stop_scheduled_incoming: u64,
    schedule_stop_scheduled_outgoing: u64,
    schedule_stop_terminal_incoming: u64,
    schedule_stop_terminal_outgoing: u64,
    terminal_latched: bool,
}

impl Buflo {
    /// Load one immutable parameter receipt and construct the state machine.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt is missing, malformed, or invalid for
    /// the configured UDP-payload ceiling.
    pub fn new(config: &BufloConfig, max_udp_payload_size: u16) -> Result<Self> {
        let parameters = BufloParameters::from_json_file(&config.parameters, max_udp_payload_size)?;
        Ok(Self::from_parameters(parameters))
    }

    /// Construct from already validated parameters.
    #[must_use]
    pub const fn from_parameters(parameters: BufloParameters) -> Self {
        Self {
            parameters,
            next_incoming_us: 0,
            next_outgoing_us: 0,
            incoming_startup: None,
            scheduled_incoming: 0,
            scheduled_outgoing: 0,
            full_outgoing: 0,
            partial_outgoing: 0,
            suppressed_outgoing: 0,
            missed_outgoing: 0,
            missed_incoming: 0,
            catch_up_incoming: 0,
            catch_up_outgoing: 0,
            terminal_incoming: 0,
            terminal_outgoing: 0,
            latest_elapsed_us: 0,
            application_complete: false,
            egress_backlog_pending: true,
            event_guard_triggered: false,
            catch_up_failure_triggered: false,
            realization_failed: false,
            terminal_primary_partial: None,
            schedule_stop_latched: false,
            schedule_stop_latched_at_us: 0,
            schedule_stop_available_bytes: 0,
            schedule_stop_required_bytes: 0,
            schedule_stop_scheduled_incoming: 0,
            schedule_stop_scheduled_outgoing: 0,
            schedule_stop_terminal_incoming: 0,
            schedule_stop_terminal_outgoing: 0,
            terminal_latched: false,
        }
    }

    const fn minimum_schedule_emitted(&self) -> bool {
        !self.incoming_waiting_for_ack()
            && self.next_incoming_us > self.parameters.minimum_duration_us
            && self.next_outgoing_us > self.parameters.minimum_duration_us
    }

    const fn incoming_waiting_for_ack(&self) -> bool {
        matches!(self.incoming_startup, Some(startup) if !startup.armed)
    }

    const fn terminal_conditions_met(&self) -> bool {
        self.application_complete
            && !self.event_guard_triggered
            && !self.catch_up_failure_triggered
            && !self.realization_failed
            && self.minimum_schedule_emitted()
            && self.schedule_stop_latched
            && !self.egress_backlog_pending
            && self.terminal_incoming == self.scheduled_incoming
            && self.terminal_outgoing == self.scheduled_outgoing
    }

    const fn schedule_closed(&self) -> bool {
        self.schedule_stop_latched
    }

    const fn latch_schedule_stop(&mut self, available: u64, required: u64) {
        if self.schedule_stop_latched
            || !self.application_complete
            || !self.minimum_schedule_emitted()
            || self.event_guard_triggered
            || self.catch_up_failure_triggered
            || self.realization_failed
        {
            return;
        }
        self.schedule_stop_latched = true;
        self.schedule_stop_latched_at_us = self.latest_elapsed_us;
        self.schedule_stop_available_bytes = available;
        self.schedule_stop_required_bytes = required;
        self.schedule_stop_scheduled_incoming = self.scheduled_incoming;
        self.schedule_stop_scheduled_outgoing = self.scheduled_outgoing;
        self.schedule_stop_terminal_incoming = self.terminal_incoming;
        self.schedule_stop_terminal_outgoing = self.terminal_outgoing;
    }

    const fn latch_terminal_if_ready(&mut self) {
        if self.terminal_conditions_met() {
            self.terminal_latched = true;
        }
    }

    const fn normally_complete(&self) -> bool {
        self.terminal_latched
    }

    const fn record_outcome(&mut self, packet: Packet, outcome: EventOutcome) {
        match (packet.direction(), outcome) {
            (
                Direction::Outgoing,
                EventOutcome::Satisfied { .. } | EventOutcome::FullySatisfied { .. },
            ) => {
                self.full_outgoing = self.full_outgoing.saturating_add(1);
                self.terminal_outgoing = self.terminal_outgoing.saturating_add(1);
            }
            (Direction::Outgoing, EventOutcome::PartiallySatisfied { .. }) => {
                self.partial_outgoing = self.partial_outgoing.saturating_add(1);
                self.terminal_outgoing = self.terminal_outgoing.saturating_add(1);
                self.realization_failed = true;
            }
            (Direction::Outgoing, EventOutcome::Suppressed { .. }) => {
                self.suppressed_outgoing = self.suppressed_outgoing.saturating_add(1);
                self.terminal_outgoing = self.terminal_outgoing.saturating_add(1);
                self.realization_failed = true;
            }
            (Direction::Outgoing, EventOutcome::Missed(_)) => {
                self.missed_outgoing = self.missed_outgoing.saturating_add(1);
                self.terminal_outgoing = self.terminal_outgoing.saturating_add(1);
                self.realization_failed = true;
            }
            (
                Direction::Incoming,
                EventOutcome::Missed(_)
                | EventOutcome::PartiallySatisfied { .. }
                | EventOutcome::Suppressed { .. },
            ) => {
                self.missed_incoming = self.missed_incoming.saturating_add(1);
                self.terminal_incoming = self.terminal_incoming.saturating_add(1);
                self.realization_failed = true;
            }
            (Direction::Incoming, _) => {
                self.terminal_incoming = self.terminal_incoming.saturating_add(1);
            }
        }
    }

    fn reject_overdue_cells(&mut self, elapsed_us: u64) -> bool {
        if self.schedule_closed() || self.event_guard_triggered || self.catch_up_failure_triggered {
            return self.catch_up_failure_triggered;
        }
        for direction in [Direction::Outgoing, Direction::Incoming] {
            if direction == Direction::Incoming && self.incoming_waiting_for_ack() {
                continue;
            }
            let next_us = match direction {
                Direction::Outgoing => self.next_outgoing_us,
                Direction::Incoming => self.next_incoming_us,
            };
            if next_us.saturating_add(self.parameters.interval_us) <= elapsed_us {
                match direction {
                    Direction::Outgoing => {
                        self.catch_up_outgoing = self.catch_up_outgoing.saturating_add(1);
                    }
                    Direction::Incoming => {
                        self.catch_up_incoming = self.catch_up_incoming.saturating_add(1);
                    }
                }
                self.catch_up_failure_triggered = true;
            }
        }
        self.catch_up_failure_triggered
    }

    fn pop_direction(&mut self, elapsed_us: u64, direction: Direction) -> Option<Packet> {
        if self.schedule_closed() || self.event_guard_triggered {
            return None;
        }
        if direction == Direction::Incoming && self.incoming_waiting_for_ack() {
            return None;
        }
        let (next_us, count) = match direction {
            Direction::Incoming => (&mut self.next_incoming_us, &mut self.scheduled_incoming),
            Direction::Outgoing => (&mut self.next_outgoing_us, &mut self.scheduled_outgoing),
        };
        // `max_events` is per-direction, with receipt validation capping the
        // combined two-direction schedule at 20,000 cells. This keeps the
        // canonical 6,000-cell direction at 120 seconds for rho=20ms.
        if *count >= self.parameters.max_events {
            self.event_guard_triggered = true;
            return None;
        }
        if *next_us > elapsed_us {
            return None;
        }
        let packet = Packet::new(
            Duration::from_micros(*next_us),
            direction,
            self.parameters.packet_size,
        )
        .ok()?;
        *next_us = next_us.saturating_add(self.parameters.interval_us);
        *count = count.saturating_add(1);
        Some(packet)
    }
}

impl Defense for Buflo {
    fn enable_buflo_acknowledged_incoming_startup(&mut self) -> bool {
        if self.parameters.packet_size != 1_200
            || self.parameters.interval_us != 20_000
            || self.scheduled_outgoing != 0
            || self.scheduled_incoming != 0
            || self.incoming_startup.is_some()
        {
            return false;
        }
        self.incoming_startup = Some(BufloIncomingStartupDiagnostics {
            schema_version: 1,
            policy: "qualified-chaff-terminal-ack-cadence-start-v1",
            time_basis: "native-controller-defense-elapsed-us-v1",
            period_us: 20_000,
            packet_size_bytes: 1_200,
            armed: false,
            armed_at_us: None,
            ready_at_us: None,
            startup_suppressed_opportunities: 0,
            ready_endpoint: None,
            ready_stream: None,
            ready_resource_id: None,
            ready_request_id: None,
            request_stream_final_size: None,
            ack_observed_at_us: None,
            eligible_exact_capacity_bytes: None,
        });
        true
    }

    fn arm_buflo_incoming_after_ack(&mut self, mut ready: BufloIncomingStartupDiagnostics) -> bool {
        if !self.incoming_waiting_for_ack()
            || ready.schema_version != 1
            || ready.policy != "qualified-chaff-terminal-ack-cadence-start-v1"
            || ready.time_basis != "native-controller-defense-elapsed-us-v1"
            || ready.period_us != 20_000
            || ready.packet_size_bytes != 1_200
            || ready.armed
            || ready.armed_at_us.is_some()
            || self.scheduled_outgoing == 0
            || ready.startup_suppressed_opportunities != self.scheduled_outgoing
            || ready.ready_at_us.is_none()
            || ready.ack_observed_at_us.is_none()
            || ready.ack_observed_at_us > ready.ready_at_us
            || ready
                .eligible_exact_capacity_bytes
                .is_none_or(|bytes| bytes < 1_200)
            || ready
                .request_stream_final_size
                .is_none_or(|bytes| bytes == 0)
            || ready.ready_endpoint.is_none()
            || ready.ready_stream.is_none()
            || ready.ready_resource_id.is_none()
            || ready.ready_request_id.is_none()
        {
            return false;
        }
        let Some(first_us) = ready
            .ready_at_us
            .and_then(|at| (at / 20_000).checked_add(1))
            .and_then(|tick| tick.checked_mul(20_000))
        else {
            return false;
        };
        ready.armed = true;
        ready.armed_at_us = Some(first_us);
        ready.startup_suppressed_opportunities = first_us / 20_000;
        self.next_incoming_us = first_us;
        self.incoming_startup = Some(ready);
        true
    }

    fn observe(&mut self, signal: DefenseSignal) {
        self.latest_elapsed_us = self
            .latest_elapsed_us
            .max(u64::try_from(signal.at.as_micros()).unwrap_or(u64::MAX));
        let fresh_terminal_backlog_snapshot =
            matches!(signal.kind, SignalKind::EgressBacklog { pending: false });
        match signal.kind {
            SignalKind::ApplicationComplete => self.application_complete = true,
            // Aggregate backlog remains the final drain-completion evidence,
            // but it cannot itself close the schedule. Only the controller's
            // typed decision proves that every schedule-authorising blocker,
            // including a due rolling identity, has cleared.
            SignalKind::EgressBacklog { pending } => self.egress_backlog_pending = pending,
            SignalKind::TerminalCellCapacityExhausted {
                available,
                required,
            } => self.latch_schedule_stop(available, required),
            SignalKind::Resolved { packet, outcome } => self.record_outcome(packet, outcome),
            SignalKind::TerminalPrimaryPartial {
                slot,
                packet,
                consumed,
                retired,
            } => {
                if self.terminal_primary_partial.is_some()
                    || self.terminal_incoming >= self.scheduled_incoming
                    || packet.timestamp() > signal.at
                    || !super::traits::terminal_primary_partial_split_valid(
                        packet,
                        self.parameters.packet_size,
                        consumed,
                        retired,
                    )
                {
                    self.realization_failed = true;
                } else {
                    self.terminal_primary_partial = Some(slot);
                    self.missed_incoming = self.missed_incoming.saturating_add(1);
                    self.terminal_incoming = self.terminal_incoming.saturating_add(1);
                }
            }
            _ => {}
        }
        // Terminal closure is irreversible.  Reduce all prerequisite signals
        // first, then latch only from a controller-generated snapshot of the
        // aggregate application/control/parser backlog.  In particular, a
        // previously observed `false` must not be reused by a later onLoad or
        // event-resolution observation after new parser work has appeared.
        if fresh_terminal_backlog_snapshot {
            self.latch_terminal_if_ready();
        }
    }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        // Exact-cell failure is terminal. In particular, a transport outcome
        // can be queued immediately before a later rolling release; never
        // materialize that next cell while the failure is being reduced.
        if self.realization_failed {
            return None;
        }
        let elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.latest_elapsed_us = self.latest_elapsed_us.max(elapsed_us);
        if self.reject_overdue_cells(elapsed_us) {
            return None;
        }
        let first =
            if self.incoming_waiting_for_ack() || self.next_outgoing_us <= self.next_incoming_us {
                Direction::Outgoing
            } else {
                Direction::Incoming
            };
        self.pop_direction(elapsed_us, first).or_else(|| {
            self.pop_direction(
                elapsed_us,
                match first {
                    Direction::Outgoing => Direction::Incoming,
                    Direction::Incoming => Direction::Outgoing,
                },
            )
        })
    }

    fn next_outgoing_prearm(&self) -> Option<Packet> {
        if self.schedule_closed()
            || self.event_guard_triggered
            || self.catch_up_failure_triggered
            || self.realization_failed
            || self.scheduled_outgoing >= self.parameters.max_events
        {
            return None;
        }
        Packet::new(
            Duration::from_micros(self.next_outgoing_us),
            Direction::Outgoing,
            self.parameters.packet_size,
        )
        .ok()
    }

    fn next_event_at(&self) -> Option<Duration> {
        if self.is_complete() || self.realization_failed {
            return None;
        }
        (!self.schedule_closed()).then(|| {
            Duration::from_micros(if self.incoming_waiting_for_ack() {
                self.next_outgoing_us
            } else {
                self.next_incoming_us.min(self.next_outgoing_us)
            })
        })
    }

    fn is_complete(&self) -> bool {
        self.normally_complete() || self.event_guard_triggered || self.catch_up_failure_triggered
    }

    fn is_outgoing_complete(&self) -> bool {
        (self.schedule_closed() && self.terminal_outgoing == self.scheduled_outgoing)
            || self.is_complete()
    }

    fn can_release_chaff_send_shaping(&self) -> bool {
        // A sent request/FIN can become retransmission-pending after the
        // schedule stops. BuFLO has no targetless cleanup phase: retain Normal
        // stream shaping until the final typed chaff cancellation replaces any
        // such work with peer-confirmed RESET/STOP_SENDING control.
        false
    }

    fn terminal_failure(&self) -> Option<&'static str> {
        if self.event_guard_triggered {
            Some("BuFLO event guard exhausted before normal completion")
        } else if self.catch_up_failure_triggered {
            Some("BuFLO scheduler fell behind a constant-rate cell boundary")
        } else if self.realization_failed {
            Some("BuFLO exact cell realization failed")
        } else {
            None
        }
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffAndShape
    }

    fn incoming_slot_must_resolve_in_window(&self) -> bool {
        true
    }

    fn base_chaff_requires_peer_acknowledgment(&self) -> bool {
        // Scheduled receive credit must never be owned by a request whose
        // STREAM bytes or FIN can return to the send backlog after loss.  A
        // complete peer acknowledgment makes that request prefix terminal;
        // terminal BuFLO drain can then retain the response credit without a
        // targetless opportunity to retransmit the request after stop.
        true
    }

    fn requires_terminal_chaff_drain(&self) -> bool {
        true
    }

    fn accepts_new_chaff_requests(&self) -> bool {
        !(self.application_complete && self.minimum_schedule_emitted())
    }

    fn terminal_chaff_backlog_cell_bytes(&self) -> Option<u64> {
        Some(u64::from(self.parameters.packet_size))
    }

    fn terminal_chaff_cancellation_reason(&self) -> Option<QcsdChaffCancellationReason> {
        self.terminal_latched
            .then_some(QcsdChaffCancellationReason::BufloTerminalSubcellTail)
    }

    fn diagnostics(&self) -> DefenseDiagnostics {
        let mut incoming_startup = self.incoming_startup;
        if let Some(startup) = &mut incoming_startup
            && !startup.armed
        {
            startup.startup_suppressed_opportunities = self.scheduled_outgoing;
        }
        DefenseDiagnostics {
            buflo_incoming_startup: incoming_startup,
            buflo_paper_equivalent: false,
            buflo_client_only: true,
            buflo_scheduled_outgoing_cells: self.scheduled_outgoing,
            buflo_scheduled_incoming_cells: self.scheduled_incoming,
            buflo_full_outgoing_cells: self.full_outgoing,
            buflo_partial_outgoing_cells: self.partial_outgoing,
            buflo_suppressed_outgoing_cells: self.suppressed_outgoing,
            buflo_missed_outgoing_cells: self.missed_outgoing,
            buflo_missed_incoming_cells: self.missed_incoming,
            buflo_catch_up_outgoing_cells: self.catch_up_outgoing,
            buflo_catch_up_incoming_cells: self.catch_up_incoming,
            buflo_outgoing_unresolved_cells: self
                .scheduled_outgoing
                .saturating_sub(self.terminal_outgoing),
            buflo_incoming_unresolved_cells: self
                .scheduled_incoming
                .saturating_sub(self.terminal_incoming),
            buflo_egress_backlog_pending: self.egress_backlog_pending,
            buflo_application_complete: self.application_complete,
            buflo_schedule_stop_latched: self.schedule_stop_latched,
            buflo_schedule_stop_latched_at_us: self.schedule_stop_latched_at_us,
            buflo_schedule_stop_available_bytes: self.schedule_stop_available_bytes,
            buflo_schedule_stop_required_bytes: self.schedule_stop_required_bytes,
            buflo_schedule_stop_scheduled_incoming_cells: self.schedule_stop_scheduled_incoming,
            buflo_schedule_stop_scheduled_outgoing_cells: self.schedule_stop_scheduled_outgoing,
            buflo_schedule_stop_terminal_incoming_cells: self.schedule_stop_terminal_incoming,
            buflo_schedule_stop_terminal_outgoing_cells: self.schedule_stop_terminal_outgoing,
            buflo_minimum_duration_reached: self.minimum_schedule_emitted(),
            buflo_event_guard_triggered: self.event_guard_triggered,
            ..DefenseDiagnostics::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Buflo;
    use crate::{
        BufloParameters, Defense as _, DefenseSignal, Direction, QcsdImplementationScope,
        SignalKind,
    };

    fn parameters() -> BufloParameters {
        BufloParameters {
            schema_version: 1,
            interval_us: 10,
            minimum_duration_us: 30,
            packet_size: 1_200,
            max_events: 100,
            implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
            paper_equivalent: false,
            duration_budget_policy: None,
        }
    }

    #[test]
    fn terminal_primary_partial_keeps_one_miss_and_allows_honest_terminal_drain() {
        let mut params = parameters();
        params.minimum_duration_us = 0;
        let mut defense = Buflo::from_parameters(params);
        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing");
        let incoming = defense.next_event(Duration::ZERO).expect("incoming");
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::Resolved {
                packet: outgoing,
                outcome: crate::EventOutcome::Satisfied { observed: 1_200 },
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::TerminalPrimaryPartial {
                slot: crate::QcsdSlotId(1),
                packet: incoming,
                consumed: 1_199,
                retired: 1,
            },
        });
        let before = defense.diagnostics();
        assert_eq!(before.buflo_scheduled_incoming_cells, 1);
        assert_eq!(defense.terminal_incoming - defense.missed_incoming, 0);
        assert_eq!(before.buflo_missed_incoming_cells, 1);
        assert_eq!(defense.terminal_incoming, 1);
        assert!(defense.terminal_failure().is_none());
        assert!(!defense.is_complete());
        for kind in [
            SignalKind::ApplicationComplete,
            SignalKind::TerminalCellCapacityExhausted {
                available: 0,
                required: 1_200,
            },
            SignalKind::EgressBacklog { pending: false },
        ] {
            defense.observe(DefenseSignal {
                at: Duration::ZERO,
                kind,
            });
        }
        assert!(defense.is_complete());
        assert_eq!(defense.terminal_incoming - defense.missed_incoming, 0);
        assert_eq!(defense.diagnostics().buflo_missed_incoming_cells, 1);
    }

    #[test]
    fn terminal_primary_partial_rejects_bad_split_second_partial_and_ordinary_miss() {
        for invalid in 0..5 {
            let mut defense = Buflo::from_parameters(parameters());
            defense.next_event(Duration::ZERO).expect("outgoing");
            let incoming = defense.next_event(Duration::ZERO).expect("incoming");
            let signal = SignalKind::TerminalPrimaryPartial {
                slot: crate::QcsdSlotId(1),
                packet: incoming,
                consumed: if invalid == 0 { 0 } else { 1_199 },
                retired: if invalid == 1 {
                    0
                } else if invalid == 2 {
                    2
                } else {
                    1
                },
            };
            if invalid == 4 {
                defense.observe(DefenseSignal {
                    at: Duration::ZERO,
                    kind: SignalKind::Resolved {
                        packet: incoming,
                        outcome: crate::EventOutcome::Missed(
                            crate::MissedSlotReason::ReceiveCreditRetired,
                        ),
                    },
                });
            } else {
                defense.observe(DefenseSignal {
                    at: Duration::ZERO,
                    kind: signal,
                });
                if invalid == 3 {
                    defense.observe(DefenseSignal {
                        at: Duration::ZERO,
                        kind: signal,
                    });
                }
            }
            assert!(defense.terminal_failure().is_some(), "invalid {invalid}");
            assert_eq!(
                defense
                    .terminal_incoming
                    .saturating_sub(defense.missed_incoming),
                0
            );
        }
    }

    fn acknowledged_startup_defense() -> Buflo {
        let mut params = parameters();
        params.interval_us = 20_000;
        let mut defense = Buflo::from_parameters(params);
        assert!(defense.enable_buflo_acknowledged_incoming_startup());
        defense
    }

    fn ready_startup(defense: &Buflo, at: u64) -> crate::BufloIncomingStartupDiagnostics {
        let mut ready = defense
            .diagnostics()
            .buflo_incoming_startup
            .expect("enabled");
        ready.ready_at_us = Some(at);
        ready.ready_endpoint = Some(1);
        ready.ready_stream = Some(0);
        ready.ready_resource_id = Some(14);
        ready.ready_request_id = Some(0);
        ready.request_stream_final_size = Some(185);
        ready.ack_observed_at_us = Some(at);
        ready.eligible_exact_capacity_bytes = Some(24_048);
        ready
    }

    #[test]
    fn acknowledged_startup_keeps_outgoing_zero_and_arms_incoming_on_next_grid() {
        for ack_at in [1, 19_999, 20_000, 20_001] {
            let mut defense = acknowledged_startup_defense();
            let first = defense.next_event(Duration::ZERO).expect("shaped tickzero");
            assert_eq!(
                (first.direction(), first.timestamp_us(), first.length()),
                (Direction::Outgoing, 0, 1_200)
            );
            assert!(defense.next_event(Duration::ZERO).is_none());
            assert_eq!(defense.next_event_at(), Some(Duration::from_micros(20_000)));
            if ack_at >= 20_000 {
                assert_eq!(
                    defense
                        .next_event(Duration::from_micros(20_000))
                        .expect("outgoing tickone")
                        .direction(),
                    Direction::Outgoing
                );
            }
            assert!(defense.arm_buflo_incoming_after_ack(ready_startup(&defense, ack_at)));
            let first_incoming = (ack_at / 20_000 + 1) * 20_000;
            let startup = defense
                .diagnostics()
                .buflo_incoming_startup
                .expect("receipt");
            assert_eq!(startup.armed_at_us, Some(first_incoming));
            assert_eq!(
                startup.startup_suppressed_opportunities,
                first_incoming / 20_000
            );
            assert!(
                defense
                    .next_event(Duration::from_micros(first_incoming - 1))
                    .is_none()
            );
            let outgoing = defense
                .next_event(Duration::from_micros(first_incoming))
                .expect("same-grid outgoing first");
            assert_eq!(
                (outgoing.direction(), outgoing.timestamp_us()),
                (Direction::Outgoing, first_incoming)
            );
            let incoming = defense
                .next_event(Duration::from_micros(first_incoming))
                .expect("first incoming");
            assert_eq!(
                (
                    incoming.direction(),
                    incoming.timestamp_us(),
                    incoming.length()
                ),
                (Direction::Incoming, first_incoming, 1_200)
            );
            assert!(
                defense
                    .next_event(Duration::from_micros(first_incoming))
                    .is_none()
            );
        }
    }

    #[test]
    fn acknowledged_startup_rejects_inconsistent_public_ready_proofs() {
        let mut base = acknowledged_startup_defense();
        base.next_event(Duration::ZERO).expect("outgoing");
        let valid = ready_startup(&base, 1);
        for variant in 0..13 {
            let mut ready = valid;
            match variant {
                0 => ready.schema_version = 2,
                1 => ready.policy = "unknown",
                2 => ready.time_basis = "unknown",
                3 => ready.period_us = 10_000,
                4 => ready.packet_size_bytes = 600,
                5 => ready.armed = true,
                6 => ready.armed_at_us = Some(0),
                7 => ready.startup_suppressed_opportunities += 1,
                8 => ready.ack_observed_at_us = Some(2),
                9 => ready.eligible_exact_capacity_bytes = Some(1_199),
                10 => ready.request_stream_final_size = Some(0),
                11 => ready.ready_request_id = None,
                _ => ready.ready_at_us = Some(u64::MAX),
            }
            assert!(
                !base.arm_buflo_incoming_after_ack(ready),
                "variant{variant}"
            );
            assert!(
                !base
                    .diagnostics()
                    .buflo_incoming_startup
                    .expect("receipt")
                    .armed
            );
        }
        assert!(base.arm_buflo_incoming_after_ack(valid));
        assert!(
            !base.arm_buflo_incoming_after_ack(valid),
            "cannot move a sealed incoming epoch"
        );
    }

    #[test]
    fn acknowledged_startup_without_ack_retains_zero_incoming_and_honest_guard() {
        let mut params = parameters();
        params.interval_us = 20_000;
        params.max_events = 3;
        let mut defense = Buflo::from_parameters(params);
        assert!(defense.enable_buflo_acknowledged_incoming_startup());
        for tick in 0..3 {
            let at = Duration::from_micros(tick * 20_000);
            assert_eq!(
                defense.next_event(at).expect("outgoing").direction(),
                Direction::Outgoing
            );
            assert!(defense.next_event(at).is_none());
        }
        assert!(defense.next_event(Duration::from_micros(60_000)).is_none());
        assert_eq!(
            defense.terminal_failure(),
            Some("BuFLO event guard exhausted before normal completion")
        );
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.buflo_scheduled_incoming_cells, 0);
        assert_eq!(diagnostics.buflo_missed_incoming_cells, 0);
        assert!(!diagnostics.buflo_incoming_startup.expect("receipt").armed);
    }

    #[test]
    fn outgoing_prearm_preview_is_pure_and_tracks_only_the_next_cursor() {
        let mut defense = Buflo::from_parameters(parameters());
        let preview = defense.next_outgoing_prearm().expect("t=0 preview");
        assert_eq!(preview.timestamp(), Duration::ZERO);
        assert_eq!(preview.direction(), Direction::Outgoing);
        assert_eq!(defense.next_outgoing_prearm(), Some(preview));
        assert_eq!(defense.diagnostics().buflo_scheduled_outgoing_cells, 0);

        assert_eq!(defense.next_event(Duration::ZERO), Some(preview));
        let incoming = defense.next_event(Duration::ZERO).expect("t=0 incoming");
        assert_eq!(incoming.direction(), Direction::Incoming);
        let next = defense.next_outgoing_prearm().expect("next preview");
        assert_eq!(next.timestamp(), Duration::from_micros(10));
        assert_eq!(defense.diagnostics().buflo_scheduled_outgoing_cells, 1);
    }

    #[test]
    fn constant_cells_run_until_both_application_and_minimum_duration_complete() {
        let mut defense = Buflo::from_parameters(parameters());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });
        let mut actual = Vec::new();
        for at in [0, 10, 20, 30] {
            while let Some(packet) = defense.next_event(Duration::from_micros(at)) {
                actual.push((packet.timestamp_us(), packet.direction()));
            }
        }
        assert_eq!(
            actual,
            [
                (0, Direction::Outgoing),
                (0, Direction::Incoming),
                (10, Direction::Outgoing),
                (10, Direction::Incoming),
                (20, Direction::Outgoing),
                (20, Direction::Incoming),
                (30, Direction::Outgoing),
                (30, Direction::Incoming),
            ]
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(30),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(30),
            kind: SignalKind::TerminalCellCapacityExhausted {
                available: 0,
                required: 1_200,
            },
        });
        for (_, direction) in actual {
            let packet = crate::Packet::new(Duration::ZERO, direction, 1_200).expect("packet");
            defense.observe(DefenseSignal {
                at: Duration::from_micros(30),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: crate::EventOutcome::Satisfied { observed: 1_000 },
                },
            });
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(30),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        assert!(defense.is_complete());
    }

    #[test]
    fn aggregate_empty_stops_new_cells_then_drains_old_outcomes() {
        let mut defense = Buflo::from_parameters(parameters());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });
        let mut scheduled = Vec::new();
        for at in [0, 10, 20, 30] {
            while let Some(packet) = defense.next_event(Duration::from_micros(at)) {
                scheduled.push(packet);
            }
        }
        assert_eq!(defense.next_event_at(), Some(Duration::from_micros(40)));
        while let Some(packet) = defense.next_event(Duration::from_micros(40)) {
            scheduled.push(packet);
        }
        assert_eq!(scheduled.len(), 10);
        assert_eq!(scheduled[8].timestamp_us(), 40);
        assert_eq!(scheduled[8].direction(), Direction::Outgoing);
        assert_eq!(scheduled[9].timestamp_us(), 40);
        assert_eq!(scheduled[9].direction(), Direction::Incoming);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(41),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        assert!(!defense.diagnostics().buflo_schedule_stop_latched);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(41),
            kind: SignalKind::TerminalCellCapacityExhausted {
                available: 0,
                required: 1_200,
            },
        });
        assert!(!defense.is_outgoing_complete());
        assert!(defense.diagnostics().buflo_schedule_stop_latched);
        assert_eq!(defense.next_event_at(), None);
        assert_eq!(defense.next_event(Duration::from_micros(50)), None);
        assert_eq!(scheduled.len(), 10);
        assert!(!defense.is_complete());
        for packet in scheduled {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(50),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: crate::EventOutcome::Satisfied { observed: 1_200 },
                },
            });
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(50),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        assert!(defense.is_complete());
    }

    #[test]
    fn terminal_capacity_stop_blocks_new_cells_while_advertised_credit_drains() {
        let mut defense = Buflo::from_parameters(parameters());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });
        let mut outgoing = Vec::new();
        let mut incoming = Vec::new();
        for at in [0, 10, 20, 30] {
            while let Some(packet) = defense.next_event(Duration::from_micros(at)) {
                match packet.direction() {
                    Direction::Outgoing => outgoing.push(packet),
                    Direction::Incoming => incoming.push(packet),
                }
            }
        }
        for packet in outgoing {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(30),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: crate::EventOutcome::Satisfied { observed: 1_200 },
                },
            });
        }
        for packet in incoming.iter().copied().take(2) {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(30),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: crate::EventOutcome::Satisfied { observed: 1_200 },
                },
            });
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(31),
            kind: SignalKind::TerminalCellCapacityExhausted {
                available: 655,
                required: 1_200,
            },
        });

        assert!(defense.is_outgoing_complete());
        assert!(
            !defense.can_release_chaff_send_shaping(),
            "a stopped BuFLO schedule never authorizes targetless chaff STREAM recovery"
        );
        assert!(!defense.is_complete());
        assert_eq!(defense.next_event_at(), None);
        assert_eq!(defense.next_event(Duration::from_micros(100)), None);
        let diagnostics = defense.diagnostics();
        assert!(diagnostics.buflo_schedule_stop_latched);
        assert_eq!(diagnostics.buflo_schedule_stop_latched_at_us, 31);
        assert_eq!(diagnostics.buflo_schedule_stop_available_bytes, 655);
        assert_eq!(diagnostics.buflo_schedule_stop_required_bytes, 1_200);
        assert_eq!(diagnostics.buflo_schedule_stop_scheduled_outgoing_cells, 4);
        assert_eq!(diagnostics.buflo_schedule_stop_scheduled_incoming_cells, 4);
        assert_eq!(diagnostics.buflo_schedule_stop_terminal_outgoing_cells, 4);
        assert_eq!(diagnostics.buflo_schedule_stop_terminal_incoming_cells, 2);

        for packet in incoming.into_iter().skip(2) {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(81),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: crate::EventOutcome::Satisfied { observed: 1_200 },
                },
            });
        }
        assert!(
            !defense.is_complete(),
            "aggregate transport debt still drains"
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(82),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        assert!(defense.is_complete());
    }

    #[test]
    fn inclusive_tau_and_onload_close_only_new_chaff_replenishment() {
        let mut defense = Buflo::from_parameters(parameters());
        assert!(defense.accepts_new_chaff_requests());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });
        assert!(defense.accepts_new_chaff_requests());

        for at in [0, 10, 20, 30] {
            while defense.next_event(Duration::from_micros(at)).is_some() {}
        }

        assert!(defense.minimum_schedule_emitted());
        assert!(!defense.accepts_new_chaff_requests());
        assert!(
            !defense.is_complete(),
            "already-open chaff and scheduled cells must still drain naturally"
        );
    }

    #[test]
    fn terminal_boundary_is_irreversible_after_the_parser_tail_starts() {
        let mut defense = Buflo::from_parameters(parameters());
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });
        let mut scheduled = Vec::new();
        for at in [0, 10, 20, 30] {
            while let Some(packet) = defense.next_event(Duration::from_micros(at)) {
                scheduled.push(packet);
            }
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(31),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(31),
            kind: SignalKind::TerminalCellCapacityExhausted {
                available: 0,
                required: 1_200,
            },
        });
        for packet in scheduled {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(31),
                kind: SignalKind::Resolved {
                    packet,
                    outcome: crate::EventOutcome::Satisfied { observed: 1_200 },
                },
            });
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(31),
            kind: SignalKind::EgressBacklog { pending: false },
        });
        assert!(defense.is_complete());

        // A parser-only tail is controller backlog, but it cannot reopen a
        // schedule that stopped at the first eligible post-tau boundary.
        defense.observe(DefenseSignal {
            at: Duration::from_micros(32),
            kind: SignalKind::EgressBacklog { pending: true },
        });
        assert!(defense.is_complete());
        assert_eq!(defense.next_event_at(), None);
        assert_eq!(defense.next_event(Duration::from_micros(40)), None);
    }

    #[test]
    fn event_guard_is_typed_terminal_failure() {
        let mut parameters = parameters();
        parameters.max_events = 2;
        let mut defense = Buflo::from_parameters(parameters);
        for at in [0, 10, 20] {
            while defense.next_event(Duration::from_micros(at)).is_some() {}
        }
        assert!(defense.is_complete());
        assert!(defense.terminal_failure().is_some());
        assert!(defense.diagnostics().buflo_event_guard_triggered);
        assert_eq!(defense.terminal_chaff_cancellation_reason(), None);
    }

    #[test]
    fn buflo_duration200_crosses_old_capacity_without_changing_cells_or_the_final_guard() {
        let parameters = BufloParameters::from_json(
            r#"{"schema_version":1,"interval_us":20000,"minimum_duration_us":10000000,"packet_size":1200,"max_events":10000,"implementation_scope":"client_only_quic","paper_equivalent":false,"duration_budget_policy":"rapid-v6-fixed-200s-duration-budget-v1"}"#,
            1_200,
        )
        .expect("prospective fixed budget");
        let mut defense = Buflo::from_parameters(parameters);
        for tick in 0..10_000 {
            let elapsed = Duration::from_micros(tick * 20_000);
            for direction in [Direction::Outgoing, Direction::Incoming] {
                let packet = defense.next_event(elapsed).expect("one scheduled cell");
                assert_eq!(packet.timestamp(), elapsed);
                assert_eq!(packet.direction(), direction);
                assert_eq!(packet.length(), 1_200);
            }
            assert!(defense.terminal_failure().is_none());
            if tick == 6_000 {
                let diagnostics = defense.diagnostics();
                assert_eq!(diagnostics.buflo_scheduled_incoming_cells, 6_001);
                assert_eq!(diagnostics.buflo_scheduled_outgoing_cells, 6_001);
                assert!(!diagnostics.buflo_event_guard_triggered);
            }
        }
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.buflo_scheduled_incoming_cells, 10_000);
        assert_eq!(diagnostics.buflo_scheduled_outgoing_cells, 10_000);
        assert_eq!(defense.next_event(Duration::from_micros(200_000_000)), None);
        assert_eq!(
            defense.terminal_failure(),
            Some("BuFLO event guard exhausted before normal completion")
        );
        assert!(defense.diagnostics().buflo_event_guard_triggered);
    }

    #[test]
    fn overdue_poll_fails_without_emitting_a_catch_up_burst() {
        let mut defense = Buflo::from_parameters(parameters());
        assert_eq!(defense.next_event(Duration::from_micros(25)), None);
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.buflo_catch_up_outgoing_cells, 1);
        assert_eq!(diagnostics.buflo_catch_up_incoming_cells, 1);
        assert_eq!(diagnostics.buflo_scheduled_outgoing_cells, 0);
        assert_eq!(diagnostics.buflo_scheduled_incoming_cells, 0);
        assert!(defense.is_complete());
        assert_eq!(
            defense.terminal_failure(),
            Some("BuFLO scheduler fell behind a constant-rate cell boundary")
        );
        assert_eq!(defense.terminal_chaff_cancellation_reason(), None);
    }

    #[test]
    fn deterministic_random_traces_match_independent_constant_rate_oracle() {
        // This deliberately uses a test-local LCG and a closed-form schedule
        // oracle rather than the production scheduler or QCSD RNG.
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        let mut draw = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };

        for _case in 0..512 {
            let interval = draw() % 50 + 1;
            let minimum_tick = draw() % 101;
            let application_complete_tick = draw() % 151;
            let backlog_clear_tick = draw() % 151;
            let first_closed_tick = (minimum_tick + 1)
                .max(application_complete_tick)
                .max(backlog_clear_tick);
            let parameters = BufloParameters {
                schema_version: 1,
                interval_us: interval,
                minimum_duration_us: minimum_tick * interval,
                packet_size: 1_200,
                max_events: 1_000,
                implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
                paper_equivalent: false,
                duration_budget_policy: None,
            };
            let mut defense = Buflo::from_parameters(parameters.clone());
            let mut actual = Vec::new();
            for tick in 0..=first_closed_tick + 2 {
                let at = Duration::from_micros(tick * interval);
                if tick == application_complete_tick {
                    defense.observe(DefenseSignal {
                        at,
                        kind: SignalKind::ApplicationComplete,
                    });
                }
                if tick >= backlog_clear_tick {
                    defense.observe(DefenseSignal {
                        at,
                        kind: SignalKind::EgressBacklog { pending: false },
                    });
                }
                if tick == first_closed_tick {
                    defense.observe(DefenseSignal {
                        at,
                        kind: SignalKind::TerminalCellCapacityExhausted {
                            available: 0,
                            required: 1_200,
                        },
                    });
                }
                while let Some(packet) = defense.next_event(at) {
                    actual.push((packet.timestamp_us(), packet.direction()));
                    defense.observe(DefenseSignal {
                        at,
                        kind: SignalKind::Resolved {
                            packet,
                            outcome: crate::EventOutcome::Satisfied {
                                observed: packet.length(),
                            },
                        },
                    });
                }
                if tick >= backlog_clear_tick {
                    defense.observe(DefenseSignal {
                        at,
                        kind: SignalKind::EgressBacklog { pending: false },
                    });
                }
            }

            let mut expected = Vec::new();
            for tick in 0..first_closed_tick {
                let timestamp = tick * interval;
                expected.push((timestamp, Direction::Outgoing));
                expected.push((timestamp, Direction::Incoming));
            }
            assert_eq!(actual, expected);
            assert!(defense.is_complete());
            let diagnostics = defense.diagnostics();
            assert_eq!(
                diagnostics.buflo_scheduled_outgoing_cells,
                first_closed_tick
            );
            assert_eq!(
                diagnostics.buflo_scheduled_incoming_cells,
                first_closed_tick
            );
            assert_eq!(diagnostics.buflo_catch_up_outgoing_cells, 0);
            assert_eq!(diagnostics.buflo_catch_up_incoming_cells, 0);

            // An independently selected initial delay of at least one cadence
            // necessarily crosses the first half-open cell window. Production
            // must fail closed once and emit no catch-up event.
            let mut delayed = Buflo::from_parameters(parameters);
            let late = Duration::from_micros((draw() % 5 + 1) * interval);
            assert_eq!(delayed.next_event(late), None);
            let diagnostics = delayed.diagnostics();
            assert_eq!(diagnostics.buflo_scheduled_outgoing_cells, 0);
            assert_eq!(diagnostics.buflo_scheduled_incoming_cells, 0);
            assert_eq!(diagnostics.buflo_catch_up_outgoing_cells, 1);
            assert_eq!(diagnostics.buflo_catch_up_incoming_cells, 1);
            assert!(delayed.terminal_failure().is_some());
        }
    }
}
