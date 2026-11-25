#[derive(Debug)]
struct RbingTerminalBoundaryDefense {
    complete: bool,
    failure: Option<&'static str>,
}

impl Defense for RbingTerminalBoundaryDefense {
    fn observe(&mut self, _: DefenseSignal) {}
    fn next_event(&mut self, _: Duration) -> Option<Packet> { None }
    fn next_event_at(&self) -> Option<Duration> { None }
    fn is_complete(&self) -> bool { self.complete }
    fn is_outgoing_complete(&self) -> bool { true }
    fn mode(&self) -> DefenseMode { DefenseMode::ChaffAndShape }
    fn terminal_failure(&self) -> Option<&'static str> { self.failure }
}

#[test]
fn rbing_owned_retry_survives_application_complete_while_defense_is_live() {
    let (mut c, outcomes) = rbing_owned_data_actual_unread_prefix(true);
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    let app = QcsdStreamId(0);
    c.streams.open(ep, app, QcsdRequestRole::Application, true, 16, 1_000, 50);

    // Reproduce the saved ordering: the original exact-first pass wholly
    // rolls back, then onLoad is observed before the same-window retry.
    c.poll(Duration::ZERO);
    c.drain_observations();
    assert!(outcomes.borrow().is_empty());
    assert_eq!(c.control.incoming.len(), 1);
    assert_eq!(c.cs_rbing_capacity_retry_at.len(), 1);
    assert!(!c.drain_actions().any(|a| matches!(a, QcsdAction::LeaseParserReceive { .. })));

    c.observe(QcsdObservation::ApplicationComplete, Duration::from_micros(100));
    assert!(c.application_complete);
    assert!(!c.cs_rbing_owned_chaff_boundary(ep, st));
    assert!(c.cs_rbing_owned_chaff_boundary_for_retry(ep, st, true));
    c.poll(Duration::from_micros(250));
    c.drain_observations();
    rbing_assert_old_unowned_one_plus_new_owned600(&mut c, &outcomes, Duration::from_micros(250));
}

#[test]
fn rbing_owned_boundary_after_application_complete_requires_rolled_back_live_retry() {
    let (mut c, _) = rbing_owned_data_actual_unread_prefix(true);
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    c.observe(QcsdObservation::ApplicationComplete, Duration::ZERO);
    assert!(!c.cs_rbing_owned_chaff_boundary(ep, st));
    assert!(!c.cs_rbing_owned_chaff_boundary_for_retry(ep, st, false));
    assert!(c.cs_rbing_owned_chaff_boundary_for_retry(ep, st, true));
    c.poll(Duration::ZERO);
    assert!(!c.drain_actions().any(|a| matches!(a, QcsdAction::LeaseParserReceive { .. })));

    c.defense = Box::new(RbingTerminalBoundaryDefense { complete: true, failure: None });
    assert!(!c.cs_rbing_owned_chaff_boundary_for_retry(ep, st, true));
    c.defense = Box::new(RbingTerminalBoundaryDefense { complete: false, failure: Some("test terminal failure") });
    assert!(!c.cs_rbing_owned_chaff_boundary_for_retry(ep, st, true));
}
// Synthetic replay of the genuinely saved r.Bing stream80 framing sequence.
// The original one-shot defense isolates the real whole600 allocator and
// physical ownership reducer. It is not a public runtime or pilot proof.
#[derive(Debug)]
struct RbingLiveAllocatorFixture(ExactIncomingOneShot);
impl Defense for RbingLiveAllocatorFixture {
    fn observe(&mut self, signal: DefenseSignal) { self.0.observe(signal); }
    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> { self.0.next_event(elapsed) }
    fn next_event_at(&self) -> Option<Duration> { self.0.next_event_at() }
    // Unlike the old one-shot fixture, actual CS remains live after one due
    // cell. This preserves the candidate's explicit !is_complete guard.
    fn is_complete(&self) -> bool { false }
    fn is_outgoing_complete(&self) -> bool { true }
    fn mode(&self) -> DefenseMode { DefenseMode::ChaffAndShape }
    fn incoming_slot_must_resolve_in_window(&self) -> bool { true }
}

// The B816 successor preserves the live-CS fixture's deliberately open
// schedule, but also lets the test prove that B815's stop remains a FIN-only
// transition. The inner one-shot still records the original slot outcome.
#[derive(Debug)]
struct B816LiveAllocatorFixture {
    inner: ExactIncomingOneShot,
    incoming_stop: Rc<RefCell<bool>>,
}

impl Defense for B816LiveAllocatorFixture {
    fn observe(&mut self, signal: DefenseSignal) { self.inner.observe(signal); }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        (!*self.incoming_stop.borrow())
            .then(|| self.inner.next_event(elapsed))
            .flatten()
    }

    fn next_event_at(&self) -> Option<Duration> {
        (!*self.incoming_stop.borrow())
            .then(|| self.inner.next_event_at())
            .flatten()
    }

    fn is_complete(&self) -> bool { false }
    fn is_outgoing_complete(&self) -> bool { true }
    fn mode(&self) -> DefenseMode { DefenseMode::ChaffAndShape }
    fn incoming_slot_must_resolve_in_window(&self) -> bool { true }

    fn stop_fresh_incoming_after_terminal_chaff_replenishment(
        &mut self,
        _: Duration,
    ) -> bool {
        if *self.incoming_stop.borrow() {
            return false;
        }
        *self.incoming_stop.borrow_mut() = true;
        true
    }
}

#[derive(Debug)]
struct B815FutureIncomingFixture {
    event: Option<Packet>,
    incoming_stop: Rc<RefCell<bool>>,
    emitted: Rc<RefCell<u64>>,
}

impl Defense for B815FutureIncomingFixture {
    fn observe(&mut self, _: DefenseSignal) {}

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        if *self.incoming_stop.borrow() {
            return None;
        }
        let packet = self.event.filter(|packet| packet.timestamp() <= elapsed)?;
        self.event = None;
        *self.emitted.borrow_mut() += 1;
        Some(packet)
    }

    fn next_event_at(&self) -> Option<Duration> {
        (!*self.incoming_stop.borrow())
            .then_some(self.event)
            .flatten()
            .map(Packet::timestamp)
    }

    fn is_complete(&self) -> bool {
        false
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

    fn stop_fresh_incoming_after_terminal_chaff_replenishment(
        &mut self,
        _: Duration,
    ) -> bool {
        if *self.incoming_stop.borrow() {
            return false;
        }
        *self.incoming_stop.borrow_mut() = true;
        true
    }
}

fn b815_future_incoming_controller(
    incoming_stop: Rc<RefCell<bool>>,
    emitted: Rc<RefCell<u64>>,
) -> QcsdController {
    let packet = Packet::new(Duration::from_micros(10), Direction::Incoming, 600)
        .expect("test incoming packet");
    let mut controller = QcsdController::with_defense(
        prospective_rbing_config(),
        None,
        Box::new(B815FutureIncomingFixture {
            event: Some(packet),
            incoming_stop,
            emitted,
        }),
    )
    .expect("test controller");
    ready(&mut controller, 1, "https://r.bing.com");
    controller
}

fn b815_closure_proof(
    policy: &'static str,
    slot: u64,
) -> super::TerminalChaffPartialCellDiagnostics {
    super::TerminalChaffPartialCellDiagnostics {
        schema_version: 1,
        source: "test",
        policy,
        resource_id: 4,
        request_id: 0,
        endpoint: 1,
        stream: 80,
        slot,
        target_us: 3,
        cell_bytes: 600,
        requested_bytes: 600,
        advertised_bytes: 600,
        consumed_bytes: 425,
        retired_bytes: 175,
        fin_at_us: 3,
        status: 200,
        body_bytes: 5_000,
    }
}

fn rbing_owned_data_actual_stall(enabled: bool) -> (QcsdController, Rc<RefCell<Vec<EventOutcome>>>) {
    rbing_owned_data_actual_stall_with_terminal_policy(enabled, false)
}

// Model the observed root013 pre-proof frontier before its final sixteen
// slotless parser bytes are granted. It is a real active r4 request: request
// FIN ACK, 200/no-CL HEADERS, decoded DATA, a current DATA parser boundary,
// and a matching peer STREAM_DATA_BLOCKED report. There is deliberately no
// scheduled slot, ledger, claim, or parser owner at construction.
fn rbing_b816_preproof_frontier_with_body(
    resource_id: u32,
    acknowledged: bool,
    blocked: bool,
    application_complete: bool,
    expected_body: u64,
) -> (
    QcsdController,
    Rc<RefCell<Vec<EventOutcome>>>,
    Rc<RefCell<bool>>,
) {
    let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).unwrap();
    let (one, outcomes) = ExactIncomingOneShot::new(packet);
    let incoming_stop = Rc::new(RefCell::new(false));
    let mut c = QcsdController::with_defense(
        prospective_rbing_config(),
        None,
        Box::new(B816LiveAllocatorFixture {
            inner: one,
            incoming_stop: Rc::clone(&incoming_stop),
        }),
    )
    .unwrap();
    c.cs_rbing_capacity_retry = true;
    ready(&mut c, 1, "https://r.bing.com");
    assert!(c.streams.enable_cs_live_chaff_headers());
    assert!(c.streams.enable_cs_rbing_current_data());
    assert!(c.streams.enable_cs_rbing_owned_data_continuation());
    assert!(c.streams.enable_cs_rbing_terminal_chaff_partial(4));
    c.cs_rbing_current_data = true;
    c.cs_rbing_owned_data_continuation = true;
    c.terminal_chaff_partial_cell_policy = true;
    c.terminal_chaff_partial_resource_id = Some(4);
    c.terminal_chaff_replenishment_closure = true;
    c.terminal_chaff_replenishment_b815_incoming_stop = true;
    c.terminal_chaff_preproof_capacity_preparation = true;

    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    let role = QcsdRequestRole::Chaff {
        resource_id,
        request_id: Some(crate::QcsdChaffRequestId(0)),
    };
    c.streams.open(ep, st, role, true, 16, 1_000, expected_body);
    c.streams
        .record_chaff_request_acknowledgment(ep, st, role, 0, 73, true);
    assert!(c.streams.record_pre_header_blocked(ep, st, 16));
    let first = c
        .streams
        .cs_live_chaff_header_bootstrap_lease(ep, st, expected_body)
        .unwrap();
    assert_eq!(
        (first.absolute_limit, first.increase, first.scheduled),
        (1_000, 984, false)
    );
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.advertised(1_000);
    state.receive.bytes_read(928);
    state.response_headers(928, Some(200), None);
    state.receive.bytes_read(3);
    c.streams.record_cs_rbing_current_data_frame(ep, st, 3, 69);
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.data_frame(3, 69);
    state.receive.bytes_read(69);
    state.receive.header_progress(1, true);
    if !acknowledged {
        // A post-FIN range makes the otherwise-real response ineligible;
        // B816 must require an active contiguous request ACK at admission.
        c.streams.record_chaff_request_acknowledgment(ep, st, role, 73, 1, false);
    }
    assert_eq!(c.streams.consumed(ep, st), Some(1_000));
    if blocked {
        assert!(c.streams.record_parser_blocked(ep, st, 1_000));
    }
    assert_eq!(c.streams.aggregate_capacity().chaff_incoming, 0);
    c.drain_actions().for_each(drop);
    if application_complete {
        c.observe(QcsdObservation::ApplicationComplete, Duration::from_micros(1));
        c.drain_observations();
    }
    (c, outcomes, incoming_stop)
}

fn rbing_b816_preproof_frontier(
    resource_id: u32,
    acknowledged: bool,
    blocked: bool,
    application_complete: bool,
) -> (
    QcsdController,
    Rc<RefCell<Vec<EventOutcome>>>,
    Rc<RefCell<bool>>,
) {
    rbing_b816_preproof_frontier_with_body(
        resource_id, acknowledged, blocked, application_complete, 5_000,
    )
}

fn rbing_b817_held_live_data_frontier() -> (
    QcsdController,
    Rc<RefCell<Vec<EventOutcome>>>,
    Rc<RefCell<bool>>,
) {
    let (mut controller, outcomes, incoming_stop) =
        rbing_b816_preproof_frontier_with_body(4, true, true, true, 20_000);
    controller.terminal_chaff_postlease_live_data_successor = true;
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    controller.poll(Duration::from_micros(2));
    controller.drain_observations();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(
                action,
                QcsdAction::LeaseParserReceive {
                    endpoint: candidate_endpoint,
                    stream: candidate_stream,
                    absolute_limit: 1_016,
                    increase: 16,
                    owner: None,
                } if *candidate_endpoint == endpoint && *candidate_stream == stream
            ))
            .count(),
        1
    );
    assert!(controller.terminal_chaff_postlease_live_data().is_none());
    (controller, outcomes, incoming_stop)
}

fn b817_observe(
    controller: &mut QcsdController,
    observation: QcsdObservation,
    at_us: u64,
    sequence: u64,
) {
    controller.observe_with_production_metadata(
        observation,
        Duration::from_micros(at_us),
        sequence,
        sequence.saturating_mul(1_000).saturating_add(at_us),
    );
}

fn b817_observe_live_prefix(
    controller: &mut QcsdController,
    data_bytes: u64,
    final_lease_read: u64,
    sequence: u64,
) {
    b817_observe_live_prefix_with_header(
        controller,
        data_bytes,
        5,
        final_lease_read,
        sequence,
    );
}

fn b817_observe_live_prefix_with_header(
    controller: &mut QcsdController,
    data_bytes: u64,
    frame_header_bytes: u64,
    final_lease_read: u64,
    sequence: u64,
) {
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    b817_observe(
        controller,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_016, slot: None,
        },
        3,
        sequence,
    );
    b817_observe(
        controller,
        QcsdObservation::StreamDataBlocked { endpoint, stream, blocked_at: 1_016 },
        4,
        sequence + 1,
    );
    b817_observe_live_tail_with_header(
        controller,
        data_bytes,
        frame_header_bytes,
        final_lease_read,
        sequence + 2,
    );
}

fn b817_observe_live_tail(
    controller: &mut QcsdController,
    data_bytes: u64,
    final_lease_read: u64,
    sequence: u64,
) {
    b817_observe_live_tail_with_header(
        controller,
        data_bytes,
        5,
        final_lease_read,
        sequence,
    );
}

fn b817_observe_live_tail_with_header(
    controller: &mut QcsdController,
    data_bytes: u64,
    frame_header_bytes: u64,
    final_lease_read: u64,
    sequence: u64,
) {
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    for (offset, bytes) in [(0, 1), (1, 1), (2, 3)] {
        b817_observe(
            controller,
            QcsdObservation::BytesRead { endpoint, stream, bytes },
            5 + offset,
            sequence + u64::from(offset),
        );
    }
    b817_observe(
        controller,
        QcsdObservation::DataFrame {
            endpoint, stream, frame_header_bytes, data_bytes,
        },
        8,
        sequence + 3,
    );
    b817_observe(
        controller,
        QcsdObservation::BytesRead {
            endpoint, stream, bytes: final_lease_read,
        },
        9,
        sequence + 4,
    );
}

fn assert_b817_no_handoff_then_original_expiry(
    controller: &mut QcsdController,
    outcomes: &Rc<RefCell<Vec<EventOutcome>>>,
) {
    assert!(controller.terminal_chaff_postlease_live_data().is_none());
    assert!(!controller.drain_actions().any(|action| matches!(
        action,
        QcsdAction::LeaseParserReceive {
            increase: 600,
            owner: Some(_),
            ..
        }
    )));
    controller.poll(Duration::from_micros(5_000));
    controller.drain_observations();
    assert_eq!(
        &*outcomes.borrow(),
        &[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]
    );
    assert!(controller.terminal_chaff_postlease_live_data().is_none());
}

fn rbing_b816_advance_real_prefix(c: &mut QcsdController, at: Duration) {
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    c.observe(
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint: ep,
            stream: st,
            absolute_limit: 1_016,
            slot: None,
        },
        at,
    );
    c.observe(
        QcsdObservation::BytesRead {
            endpoint: ep,
            stream: st,
            bytes: 2,
        },
        at + Duration::from_micros(1),
    );
    c.observe(
        QcsdObservation::DataFrame {
            endpoint: ep,
            stream: st,
            frame_header_bytes: 2,
            data_bytes: 13,
        },
        at + Duration::from_micros(2),
    );
    c.observe(
        QcsdObservation::BytesRead {
            endpoint: ep,
            stream: st,
            bytes: 13,
        },
        at + Duration::from_micros(3),
    );
    c.observe(
        QcsdObservation::BytesRead {
            endpoint: ep,
            stream: st,
            bytes: 1,
        },
        at + Duration::from_micros(4),
    );
    c.observe(
        QcsdObservation::HeaderProgress {
            endpoint: ep,
            stream: st,
            min_remaining: 1,
            awaiting_data_frame: true,
        },
        at + Duration::from_micros(5),
    );
    c.observe(
        QcsdObservation::StreamDataBlocked {
            endpoint: ep,
            stream: st,
            blocked_at: 1_016,
        },
        at + Duration::from_micros(6),
    );
    assert_eq!(c.streams.consumed(ep, st), Some(1_016));
    assert_eq!(
        c.streams
            .owned_data_continuation_capacity(ep, st, 600),
        600
    );
}

// A second real current-DATA frontier used only to prove that the B816-held
// identity cannot be silently reassigned to another eligible chaff stream.
fn rbing_b816_seed_owned_data_frontier(
    c: &mut QcsdController,
    stream: QcsdStreamId,
    request_id: u64,
) {
    let endpoint = QcsdEndpointId(1);
    let role = QcsdRequestRole::Chaff {
        resource_id: 4,
        request_id: Some(crate::QcsdChaffRequestId(request_id)),
    };
    c.streams.open(endpoint, stream, role, true, 16, 1_000, 5_000);
    c.streams
        .record_chaff_request_acknowledgment(endpoint, stream, role, 0, 73, true);
    assert!(c.streams.record_pre_header_blocked(endpoint, stream, 16));
    let first = c
        .streams
        .cs_live_chaff_header_bootstrap_lease(endpoint, stream, 5_000)
        .expect("second real header lease");
    assert_eq!((first.absolute_limit, first.increase), (1_000, 984));
    let state = c.streams.get_mut(endpoint, stream).expect("second stream");
    state.receive.advertised(1_000);
    state.receive.bytes_read(928);
    state.response_headers(928, Some(200), None);
    state.receive.bytes_read(3);
    c.streams
        .record_cs_rbing_current_data_frame(endpoint, stream, 3, 69);
    let state = c.streams.get_mut(endpoint, stream).expect("second DATA");
    state.receive.data_frame(3, 69);
    state.receive.bytes_read(69);
    state.receive.header_progress(1, true);
    let prefix = c
        .streams
        .cs_rbing_current_data_prefix_lease(endpoint, stream, 1)
        .expect("second actual sixteen-byte prefix");
    assert_eq!((prefix.absolute_limit, prefix.increase), (1_016, 16));
    let state = c.streams.get_mut(endpoint, stream).expect("second prefix");
    state.receive.advertised(1_016);
    state.receive.bytes_read(2);
    c.streams
        .record_cs_rbing_current_data_frame(endpoint, stream, 2, 13);
    let state = c.streams.get_mut(endpoint, stream).expect("second frame");
    state.receive.data_frame(2, 13);
    state.receive.bytes_read(13);
    state.receive.bytes_read(1);
    state.receive.header_progress(1, true);
    assert!(c.streams.record_parser_blocked(endpoint, stream, 1_016));
    assert_eq!(
        c.streams
            .owned_data_continuation_capacity(endpoint, stream, 600),
        600
    );
}

#[test]
fn rbing_b816_due_only_preproof_capacity_is_real_and_binds_later_slot() {
    let (mut c, outcomes, incoming_stop) = rbing_b816_preproof_frontier(4, true, true, true);
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);

    // The first due exact cell is held before it has a ledger or scheduled
    // owner, and B816 grants only the actual sixteen-byte parser suffix.
    c.poll(Duration::from_micros(2));
    c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(
                action,
                QcsdAction::LeaseParserReceive {
                    endpoint: candidate_endpoint,
                    stream: candidate_stream,
                    absolute_limit: 1_016,
                    increase: 16,
                    owner: None,
                } if *candidate_endpoint == endpoint && *candidate_stream == stream
            ))
            .count(),
        1
    );
    assert!(!actions.iter().any(|action| matches!(
        action,
        QcsdAction::RequestChaff { .. }
            | QcsdAction::IncreaseReceiveLimit { .. }
            | QcsdAction::SlotSatisfied { .. }
    )));
    assert!(c.pending_slots.is_empty());
    assert!(c.control.incoming.is_empty());
    assert!(c.control.credit.is_empty());
    assert!(c.control.claims.is_empty());
    assert!(c.incoming_credit_ledger.is_empty());
    assert_eq!(c.control.next_slot_id, 1);
    assert!(outcomes.borrow().is_empty());
    assert!(!*incoming_stop.borrow());
    assert!(c.terminal_chaff_partial_cells().is_empty());
    assert!(!c.terminal_chaff_replenishment_closed());
    let preparation = c
        .terminal_chaff_preproof_capacity_preparation()
        .expect("one actual B816 pre-materialization receipt");
    assert_eq!(
        (
            preparation.resource_id,
            preparation.endpoint,
            preparation.stream,
            preparation.frontier,
            preparation.slot,
            preparation.target_us,
            preparation.lease_start,
            preparation.lease_end,
            preparation.lease_bytes,
            preparation.materialized_at_us,
        ),
        (4, 1, 80, 1_000, 0, 0, 1_000, 1_016, 16, None)
    );
    assert!(c
        .b816_preproof_capacity_witness(endpoint, stream, 1_016, 16)
        .is_some());

    // Only observed advertisement and parser progress turn that slotless
    // suffix into the already-existing 600-byte owned-DATA continuation.
    rbing_b816_advance_real_prefix(&mut c, Duration::from_micros(3));
    assert!(c.drain_actions().next().is_none());
    c.poll(Duration::from_micros(10));
    c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    let owner = actions
        .iter()
        .find_map(|action| match action {
            QcsdAction::LeaseParserReceive {
                endpoint: candidate_endpoint,
                stream: candidate_stream,
                absolute_limit: 1_616,
                increase: 600,
                owner: Some(owner),
            } if *candidate_endpoint == endpoint && *candidate_stream == stream => Some(*owner),
            _ => None,
        })
        .expect("later original exact cell owns the physical 600-byte lease");
    assert!(!actions
        .iter()
        .any(|action| matches!(action, QcsdAction::RequestChaff { .. })));
    assert!(!actions.iter().any(|action| matches!(
        action,
        QcsdAction::IncreaseReceiveLimit { stream: candidate, .. }
            if *candidate != stream
    )));
    assert_eq!(owner.slot, QcsdSlotId(0));
    let ledger = c
        .incoming_credit_ledger
        .get(&owner.slot)
        .expect("original due cell has its normal later ledger");
    assert_eq!(
        (ledger.requested(), ledger.advertised, ledger.consumed, ledger.retired),
        (600, 0, 0, 0)
    );
    assert_eq!(
        c.terminal_chaff_preproof_capacity_preparation()
            .expect("same receipt")
            .materialized_at_us,
        Some(10)
    );
    assert!(c.terminal_chaff_partial_cells().is_empty());
    assert!(!c.terminal_chaff_replenishment_closed());
    assert!(!*incoming_stop.borrow());

    // A valid FIN, not the pre-proof parser work, remains the sole B815/B816
    // closure trigger.
    if let crate::stream::ReceiveState::ReceivingData { data_length, .. } =
        &mut c.streams.get_mut(endpoint, stream).expect("active r4 stream").receive
    {
        *data_length = 5_000;
    } else {
        panic!("B816 fixture must remain in DATA");
    }
    c.observe(
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint,
            stream,
            absolute_limit: 1_616,
            slot: None,
        },
        Duration::from_micros(11),
    );
    c.observe(
        QcsdObservation::BytesRead {
            endpoint,
            stream,
            bytes: 425,
        },
        Duration::from_micros(12),
    );
    assert!(c.terminal_chaff_partial_cells().is_empty());
    assert!(!c.terminal_chaff_replenishment_closed());
    assert!(!*incoming_stop.borrow());
    c.observe(
        QcsdObservation::StreamFinished {
            endpoint,
            stream,
            finish: crate::QcsdStreamFinish::Fin,
        },
        Duration::from_micros(13),
    );
    let proof = c
        .terminal_chaff_partial_cells()
        .first()
        .expect("only actual terminal FIN creates proof");
    assert_eq!(
        proof.policy,
        "r-bing-cs600-b816-due-only-preproof-active-r4-parser-capacity-then-first-proven-terminal-chaff-fin-closes-replenishment-and-stops-fresh-incoming-v1"
    );
    assert_eq!(proof.slot, owner.slot.0);
    assert!(c.terminal_chaff_replenishment_closed());
    assert!(*incoming_stop.borrow());
}

#[test]
fn rbing_b816_rejects_missing_wrong_unacked_and_precomplete_frontiers() {
    for (label, resource_id, acknowledged, blocked, application_complete) in [
        ("missing blocked frontier", 4, true, false, true),
        ("wrong resource", 3, true, true, true),
        ("unacknowledged request", 4, false, true, true),
        ("application not complete", 4, true, true, false),
    ] {
        let (mut c, outcomes, incoming_stop) = rbing_b816_preproof_frontier(
            resource_id,
            acknowledged,
            blocked,
            application_complete,
        );
        c.poll(Duration::from_micros(2));
        c.drain_observations();
        let actions: Vec<_> = c.drain_actions().collect();
        assert!(
            !actions.iter().any(|action| matches!(
                action,
                QcsdAction::LeaseParserReceive {
                    increase: 16,
                    owner: None,
                    ..
                }
            )),
            "{label} must not create B816 parser permission"
        );
        assert!(
            c.terminal_chaff_preproof_capacity_preparation().is_none(),
            "{label} must not create B816 receipt"
        );
        assert_eq!(c.control.incoming.len(), 1, "{label} uses original materialization");
        let original = c.control.incoming[0].slot;
        assert_eq!(original, QcsdSlotId(0));
        assert_eq!(c.control.incoming[0].packet.timestamp(), Duration::ZERO);
        assert_eq!(c.control.incoming[0].remaining, 600);
        assert_eq!(c.cs_rbing_capacity_retry_at.len(), 1);
        assert_eq!(c.next_deadline(), Some(Duration::from_micros(252)));
        assert!(c.incoming_credit_ledger.contains_key(&original));
        assert!(!*incoming_stop.borrow());
        assert!(c.terminal_chaff_partial_cells().is_empty());
        assert!(!c.terminal_chaff_replenishment_closed());

        // The original half-open five-millisecond expiry remains fatal when
        // the actual qualifying frontier was absent.
        c.poll(Duration::from_micros(5_000));
        c.drain_observations();
        assert_eq!(
            &*outcomes.borrow(),
            &[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)],
            "{label} preserves original DeadlineExpired"
        );
        assert!(c.control.incoming.is_empty());
        assert!(c.cs_rbing_capacity_retry_at.is_empty());
        assert!(c.terminal_chaff_preproof_capacity_preparation().is_none());
        assert!(!*incoming_stop.borrow());
    }
}

#[test]
fn rbing_b816_fin_before_original_owned_advertisement_cannot_close_or_succeed() {
    let (mut c, outcomes, incoming_stop) = rbing_b816_preproof_frontier(4, true, true, true);
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    c.poll(Duration::from_micros(2));
    c.drain_observations();
    assert!(c.terminal_chaff_preproof_capacity_preparation().is_some());
    c.drain_actions().for_each(drop);

    // The held identity has no ledger or owned 600-byte lease, so even an
    // observed FIN cannot become a terminal proof or B815 closure.
    c.observe(
        QcsdObservation::StreamFinished {
            endpoint,
            stream,
            finish: crate::QcsdStreamFinish::Fin,
        },
        Duration::from_micros(3),
    );
    assert!(c.terminal_chaff_partial_cells().is_empty());
    assert!(!c.terminal_chaff_replenishment_closed());
    assert!(!*incoming_stop.borrow());
    assert!(outcomes.borrow().is_empty());

    c.poll(Duration::from_micros(5_000));
    c.drain_observations();
    assert_eq!(
        &*outcomes.borrow(),
        &[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]
    );
    assert!(c.terminal_chaff_partial_cells().is_empty());
    assert!(!c.terminal_chaff_replenishment_closed());
    assert!(!*incoming_stop.borrow());
}

#[test]
fn rbing_b816_held_slot_cannot_retarget_another_eligible_chaff_stream() {
    let (mut c, outcomes, incoming_stop) = rbing_b816_preproof_frontier(4, true, true, true);
    let endpoint = QcsdEndpointId(1);
    let held_stream = QcsdStreamId(80);
    let other_stream = QcsdStreamId(1);

    c.poll(Duration::from_micros(2));
    c.drain_observations();
    c.drain_actions().for_each(drop);
    assert_eq!(
        c.terminal_chaff_preproof_capacity_preparation()
            .expect("held source receipt")
            .stream,
        held_stream.0
    );

    // Introduce a lower-numbered independently eligible r4 frontier before
    // A's held identity materializes. B816 must retain its original stream.
    rbing_b816_seed_owned_data_frontier(&mut c, other_stream, 1);
    rbing_b816_advance_real_prefix(&mut c, Duration::from_micros(3));
    c.poll(Duration::from_micros(4_999));
    c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    let owned: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            QcsdAction::LeaseParserReceive {
                endpoint: candidate_endpoint,
                stream: candidate_stream,
                increase: 600,
                owner: Some(owner),
                ..
            } if *candidate_endpoint == endpoint => Some((*candidate_stream, *owner)),
            _ => None,
        })
        .collect();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].0, held_stream);
    assert_eq!(owned[0].1.slot, QcsdSlotId(0));
    assert!(!actions.iter().any(|action| matches!(
        action,
        QcsdAction::LeaseParserReceive { stream, .. }
            | QcsdAction::IncreaseReceiveLimit { stream, .. }
                if *stream == other_stream
    )));
    assert!(!c
        .control
        .credit
        .iter()
        .any(|credit| credit.stream == other_stream));
    assert!(!c
        .control
        .claims
        .iter()
        .any(|claim| claim.stream == other_stream));
    assert_eq!(
        c.terminal_chaff_preproof_capacity_preparation()
            .expect("same source receipt")
            .materialized_at_us,
        Some(4_999)
    );
    assert!(outcomes.borrow().is_empty());
    assert!(!*incoming_stop.borrow());
}

#[test]
fn rbing_b816_does_nothing_without_due_incoming_or_for_outgoing() {
    let (mut c, _, _) = rbing_b816_preproof_frontier(4, true, true, true);
    c.defense = Box::new(RbingTerminalBoundaryDefense {
        complete: false,
        failure: None,
    });
    c.poll(Duration::from_micros(2));
    c.drain_observations();
    assert!(c.drain_actions().next().is_none());
    assert!(c.terminal_chaff_preproof_capacity_preparation().is_none());
    assert!(c.pending_slots.is_empty());
    assert!(c.incoming_credit_ledger.is_empty());
    assert_eq!(c.control.next_slot_id, 0);

    let outgoing = Packet::new(Duration::from_micros(3), Direction::Outgoing, 600)
        .expect("outgoing test cell");
    let (one, _) = ExactIncomingOneShot::new(outgoing);
    c.defense = Box::new(B816LiveAllocatorFixture {
        inner: one,
        incoming_stop: Rc::new(RefCell::new(false)),
    });
    c.poll(Duration::from_micros(4));
    c.drain_observations();
    assert!(!c.drain_actions().any(|action| matches!(
        action,
        QcsdAction::LeaseParserReceive { .. }
            | QcsdAction::IncreaseReceiveLimit { .. }
    )));
    assert!(c.terminal_chaff_preproof_capacity_preparation().is_none());
}

#[test]
fn rbing_b816_enable_is_one_shot_and_pins_r4() {
    let mut c = prospective_rbing_actual_cs();
    c.enable_cs_live_chaff_header_progress().unwrap();
    c.enable_cs_rbing_same_window_capacity_retry("r.bing.com")
        .unwrap();
    c.enable_cs_rbing_current_data("r.bing.com").unwrap();
    c.enable_cs_rbing_owned_data_continuation("r.bing.com")
        .unwrap();
    assert!(c
        .enable_cs_rbing_terminal_chaff_partial_replenishment_b816("r.bing.com", 3)
        .is_err());
    assert!(!c.terminal_chaff_partial_cell_policy);
    assert!(!c.terminal_chaff_preproof_capacity_preparation);
    c.enable_cs_rbing_terminal_chaff_partial_replenishment_b816("r.bing.com", 4)
        .unwrap();
    assert!(c.terminal_chaff_partial_cell_policy);
    assert_eq!(c.terminal_chaff_partial_resource_id, Some(4));
    assert!(c.terminal_chaff_preproof_capacity_preparation);
    assert!(c
        .enable_cs_rbing_terminal_chaff_partial_replenishment_b816("r.bing.com", 4)
        .is_err());
}



#[test]
fn rbing_b816_held_parser_progress_at_exclusive_deadline_still_expires() {
    let (mut c, outcomes, incoming_stop) = rbing_b816_preproof_frontier(4, true, true, true);
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    c.poll(Duration::from_micros(2));
    c.drain_observations();
    c.drain_actions().for_each(drop);
    assert_eq!(c.next_deadline(), Some(Duration::from_micros(5_000)));

    // The final blocked frontier is observed exactly at the original exclusive
    // deadline. It can prove physical readiness, but it cannot relax or cross
    // that deadline into an owned 600-byte realization.
    rbing_b816_advance_real_prefix(&mut c, Duration::from_micros(4_994));
    assert_eq!(c.streams.consumed(endpoint, stream), Some(1_016));
    c.poll(Duration::from_micros(5_000));
    c.drain_observations();
    assert_eq!(
        &*outcomes.borrow(),
        &[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]
    );
    assert!(!c.drain_actions().any(|action| matches!(
        action,
        QcsdAction::LeaseParserReceive {
            increase: 600,
            owner: Some(_),
            ..
        } | QcsdAction::SlotSatisfied { .. }
    )));
    assert!(c.control.incoming.is_empty());
    assert_eq!(
        c.terminal_chaff_preproof_capacity_preparation()
            .expect("held receipt")
            .materialized_at_us,
        None
    );
    assert!(c.terminal_chaff_partial_cells().is_empty());
    assert!(!c.terminal_chaff_replenishment_closed());
    assert!(!*incoming_stop.borrow());
}

#[test]
fn rbing_b817_exact_live_postlease_data_handoff_is_one_owned_slotless_600() {
    let (mut c, outcomes, incoming_stop) = rbing_b817_held_live_data_frontier();
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);

    // This is the saved live shape: physical 16-byte lease advertisement,
    // matching BLOCKED, three reads totaling the five-byte DATA header, a
    // 10,719-byte decoded DATA extent, then the final eleven lease bytes.
    b817_observe_live_prefix(&mut c, 10_719, 11, 100);
    let actions: Vec<_> = c.drain_actions().collect();
    let owner = actions
        .iter()
        .find_map(|action| match action {
            QcsdAction::LeaseParserReceive {
                endpoint: candidate_endpoint,
                stream: candidate_stream,
                absolute_limit: 1_616,
                increase: 600,
                owner: Some(owner),
            } if *candidate_endpoint == endpoint && *candidate_stream == stream => Some(*owner),
            _ => None,
        })
        .expect("B817 produces exactly the held original same-stream owner");
    assert_eq!(owner.slot, QcsdSlotId(0));
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(
                action,
                QcsdAction::LeaseParserReceive {
                    endpoint: candidate_endpoint,
                    stream: candidate_stream,
                    increase: 600,
                    owner: Some(_),
                    ..
                } if *candidate_endpoint == endpoint && *candidate_stream == stream
            ))
            .count(),
        1
    );
    assert!(!actions.iter().any(|action| matches!(
        action,
        QcsdAction::RequestChaff { .. }
            | QcsdAction::IncreaseReceiveLimit { .. }
            | QcsdAction::ConfigureManualReceive { .. }
    )));
    assert!(c.control.incoming.is_empty());
    assert_eq!(c.pending_slots.len(), 1);
    assert!(c.pending_slots.contains_key(&owner.slot));
    let record = c
        .terminal_chaff_postlease_live_data()
        .expect("exact live B817 handoff receipt");
    assert_eq!(
        (
            record.resource_id,
            record.request_id,
            record.endpoint,
            record.stream,
            record.slot,
            record.lease_start,
            record.lease_end,
        ),
        (4, 0, 1, 80, 0, 1_000, 1_016)
    );
    assert_eq!(
        (
            record.frame_header_start,
            record.frame_payload_start,
            record.frame_payload_end,
            record.lease_consumption_end,
            record.owned_lease_start,
            record.owned_lease_end,
            record.handoff_at_us,
        ),
        (1_000, 1_005, 11_724, 1_016, 1_016, 1_616, 9)
    );
    assert_eq!(
        (
            record.lease_advertised_production_sequence,
            record.blocked_production_sequence,
            record.frame_production_sequence,
            record.lease_consumed_production_sequence,
        ),
        (Some(100), Some(101), Some(105), Some(106))
    );
    assert!(record.owned_advertised_at_us.is_none());
    assert!(!record.owned_advertised_predeadline_verified);
    assert_eq!(
        c.incoming_credit_ledger
            .get(&owner.slot)
            .map(|ledger| (ledger.requested(), ledger.advertised, ledger.consumed)),
        Some((600, 0, 0))
    );

    // The actual transport callback is slotless for a parser lease. Its
    // identity is joined through the live owned parser range and exact ledger,
    // not fabricated as a slot-attributed callback.
    b817_observe(
        &mut c,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_616, slot: None,
        },
        10,
        107,
    );
    let record = c.terminal_chaff_postlease_live_data().unwrap();
    assert_eq!(record.owned_advertised_at_us, Some(10));
    assert_eq!(record.owned_advertised_at_ns, Some(10_000));
    assert!(record.owned_advertised_predeadline_verified);
    assert_eq!(record.owned_advertised_production_sequence, Some(107));
    assert_eq!(
        c.incoming_credit_ledger
            .get(&owner.slot)
            .map(|ledger| (ledger.requested(), ledger.advertised, ledger.consumed)),
        Some((600, 600, 0))
    );

    // The later genuine FIN remains the sole closure edge, and must keep B817
    // in the policy/receipt chain rather than falling back to B816.
    if let crate::stream::ReceiveState::ReceivingData { data_length, .. } =
        &mut c.streams.get_mut(endpoint, stream).unwrap().receive
    {
        *data_length = 20_000;
    } else {
        panic!("B817 fixture must remain in DATA");
    }
    b817_observe(
        &mut c,
        QcsdObservation::BytesRead { endpoint, stream, bytes: 425 },
        11,
        108,
    );
    b817_observe(
        &mut c,
        QcsdObservation::StreamFinished {
            endpoint, stream, finish: crate::QcsdStreamFinish::Fin,
        },
        12,
        109,
    );
    let proof = c.terminal_chaff_partial_cells().first().unwrap();
    assert_eq!(
        proof.policy,
        "r-bing-cs600-b817-post-lease-live-data-frame-same-stream-600-successor-then-first-proven-terminal-chaff-fin-closes-replenishment-and-stops-fresh-incoming-v1"
    );
    assert_eq!(proof.slot, owner.slot.0);
    assert!(c.terminal_chaff_replenishment_closed());
    assert!(*incoming_stop.borrow());
    assert!(outcomes.borrow().is_empty());
}

#[test]
fn rbing_b817_rejects_missing_metadata_wrong_identity_and_nonincreasing_order() {
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);

    // The controller's ordinary test reducer is intentionally ineligible:
    // every physical witness must carry a real production sequence/time.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    c.observe(
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_016, slot: None,
        },
        Duration::from_micros(3),
    );
    c.observe(
        QcsdObservation::StreamDataBlocked { endpoint, stream, blocked_at: 1_016 },
        Duration::from_micros(4),
    );
    for (at, bytes) in [(5, 1), (6, 1), (7, 3), (9, 11)] {
        c.observe(
            QcsdObservation::BytesRead { endpoint, stream, bytes },
            Duration::from_micros(at),
        );
        if at == 7 {
            c.observe(
                QcsdObservation::DataFrame {
                    endpoint, stream, frame_header_bytes: 5, data_bytes: 10_719,
                },
                Duration::from_micros(8),
            );
        }
    }
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);

    // A slotful callback cannot impersonate the physical slotless parser
    // lease; it invalidates the held witness before the remaining real shape.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    b817_observe(
        &mut c,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_016, slot: Some(QcsdSlotId(0)),
        },
        3,
        100,
    );
    b817_observe(
        &mut c,
        QcsdObservation::StreamDataBlocked { endpoint, stream, blocked_at: 1_016 },
        4,
        101,
    );
    b817_observe_live_tail(&mut c, 10_719, 11, 102);
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);

    // The blocked point must both match the lease end and strictly follow the
    // advertisement in production order; an equal sequence fails closed.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    b817_observe(
        &mut c,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_016, slot: None,
        },
        3,
        100,
    );
    b817_observe(
        &mut c,
        QcsdObservation::StreamDataBlocked { endpoint, stream, blocked_at: 1_016 },
        4,
        100,
    );
    b817_observe_live_tail(&mut c, 10_719, 11, 101);
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);

    // A wrong same-stream BLOCKED frontier also poisons the one held identity.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    b817_observe(
        &mut c,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_016, slot: None,
        },
        3,
        100,
    );
    b817_observe(
        &mut c,
        QcsdObservation::StreamDataBlocked { endpoint, stream, blocked_at: 1_015 },
        4,
        101,
    );
    b817_observe_live_tail(&mut c, 10_719, 11, 102);
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);
}

#[test]
fn rbing_b817_rejects_nonfive_data_frame_headers() {
    for frame_header_bytes in [1, 4, 6] {
        let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
        b817_observe_live_prefix_with_header(&mut c, 10_719, frame_header_bytes, 11, 100);
        assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);
    }
}

#[test]
fn rbing_b817_requires_full_lease_payload_extent_and_frame_before_final_read() {
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);

    // A 15-byte lease read never creates the owned successor.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    b817_observe_live_prefix(&mut c, 10_719, 10, 100);
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);

    // The declared DATA payload must reach lease_end + 600, not merely begin
    // under the final five header bytes.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    b817_observe_live_prefix(&mut c, 599, 11, 100);
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);

    // All sixteen bytes before the frame can never be retroactively repaired
    // by a later DATA callback. The only handoff call site is BytesRead, and
    // the recorded frame must strictly precede the final lease consumption.
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    b817_observe(
        &mut c,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_016, slot: None,
        },
        3,
        100,
    );
    b817_observe(
        &mut c,
        QcsdObservation::StreamDataBlocked { endpoint, stream, blocked_at: 1_016 },
        4,
        101,
    );
    b817_observe(
        &mut c,
        QcsdObservation::BytesRead { endpoint, stream, bytes: 16 },
        5,
        102,
    );
    b817_observe(
        &mut c,
        QcsdObservation::DataFrame {
            endpoint, stream, frame_header_bytes: 5, data_bytes: 10_719,
        },
        6,
        103,
    );
    assert_b817_no_handoff_then_original_expiry(&mut c, &outcomes);
}

#[test]
fn rbing_b817_late_slotless_owned_advertisement_cannot_complete_receipt() {
    let (mut c, outcomes, _) = rbing_b817_held_live_data_frontier();
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    {
        let (mut slotful, _, _) = rbing_b817_held_live_data_frontier();
        b817_observe_live_prefix(&mut slotful, 10_719, 11, 100);
        slotful.drain_actions().for_each(drop);
        // The final parser lease also has a slotless physical callback.
        // A fabricated original slot on an otherwise timely callback cannot
        // complete the B817 receipt.
        b817_observe(
            &mut slotful,
            QcsdObservation::ReceiveLimitAdvertised {
                endpoint, stream, absolute_limit: 1_616, slot: Some(QcsdSlotId(0)),
            },
            10,
            107,
        );
        let record = slotful.terminal_chaff_postlease_live_data().unwrap();
        assert!(record.owned_advertised_at_us.is_none());
        assert!(record.owned_advertised_at_ns.is_none());
        assert!(!record.owned_advertised_predeadline_verified);
        assert!(record.owned_advertised_production_sequence.is_none());
    }
    b817_observe_live_prefix(&mut c, 10_719, 11, 100);
    assert!(c.drain_actions().any(|action| matches!(
        action,
        QcsdAction::LeaseParserReceive {
            endpoint: candidate_endpoint,
            stream: candidate_stream,
            absolute_limit: 1_616,
            increase: 600,
            owner: Some(_),
        } if candidate_endpoint == endpoint && candidate_stream == stream
    )));
    assert!(c
        .terminal_chaff_postlease_live_data()
        .is_some_and(|record| record.owned_advertised_at_us.is_none()));

    // Credit advertisement expires the unadvertised original exact cell first.
    // This late slotless transport callback cannot repopulate the receipt
    // after its range and ledger have been rolled back.
    b817_observe(
        &mut c,
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint, stream, absolute_limit: 1_616, slot: None,
        },
        5_000,
        107,
    );
    c.drain_observations();
    let record = c.terminal_chaff_postlease_live_data().unwrap();
    assert!(record.owned_advertised_at_us.is_none());
    assert!(record.owned_advertised_at_ns.is_none());
    assert!(!record.owned_advertised_predeadline_verified);
    assert!(record.owned_advertised_production_sequence.is_none());
    assert!(!c.incoming_credit_ledger.contains_key(&QcsdSlotId(0)));
    assert_eq!(
        &*outcomes.borrow(),
        &[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]
    );
}

fn rbing_owned_data_actual_stall_with_terminal_policy(
    enabled: bool,
    terminal_policy: bool,
) -> (QcsdController, Rc<RefCell<Vec<EventOutcome>>>) {
    let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).unwrap();
    let (one, outcomes) = ExactIncomingOneShot::new(packet);
    let mut c = QcsdController::with_defense(prospective_rbing_config(), None,
        Box::new(RbingLiveAllocatorFixture(one))).unwrap();
    c.cs_rbing_capacity_retry = true;
    ready(&mut c, 1, "https://r.bing.com");
    assert!(c.streams.enable_cs_live_chaff_headers());
    assert!(c.streams.enable_cs_rbing_current_data());
    c.cs_rbing_current_data = true;
    if enabled {
        assert!(c.streams.enable_cs_rbing_owned_data_continuation());
        c.cs_rbing_owned_data_continuation = true;
        if terminal_policy {
            assert!(c.streams.enable_cs_rbing_terminal_chaff_partial(4));
            c.terminal_chaff_partial_cell_policy = true;
            c.terminal_chaff_partial_resource_id = Some(4);
        }
    }
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    let role = QcsdRequestRole::Chaff {
        resource_id: 4,
        request_id: Some(crate::QcsdChaffRequestId(0)),
    };
    c.streams.open(ep, st, role, true, 16, 1_000, 5_000);
    c.streams.record_chaff_request_acknowledgment(ep, st, role, 0, 73, true);
    assert!(c.streams.record_pre_header_blocked(ep, st, 16));
    let first = c.streams.cs_live_chaff_header_bootstrap_lease(ep, st, 5_000).unwrap();
    assert_eq!((first.absolute_limit, first.increase, first.scheduled), (1_000, 984, false));
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.advertised(1_000);
    state.receive.bytes_read(928);
    state.response_headers(928, Some(200), None);
    state.receive.bytes_read(3);
    c.streams.record_cs_rbing_current_data_frame(ep, st, 3, 69);
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.data_frame(3, 69);
    state.receive.bytes_read(69);
    state.receive.header_progress(1, true);
    let prefix = c.streams.cs_rbing_current_data_prefix_lease(ep, st, 1).unwrap();
    assert_eq!((prefix.absolute_limit, prefix.increase), (1_016, 16));
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.advertised(1_016);
    state.receive.bytes_read(2);
    c.streams.record_cs_rbing_current_data_frame(ep, st, 2, 13);
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.data_frame(2, 13);
    state.receive.bytes_read(13);
    state.receive.bytes_read(1);
    state.receive.header_progress(1, true);
    assert!(c.streams.record_parser_blocked(ep, st, 1_016));
    assert_eq!(c.streams.aggregate_capacity().chaff_incoming, 0);
    c.drain_actions().for_each(drop);
    (c, outcomes)
}

#[test]
fn rbing_owned_data_controller_disabled_reproduces_capacity_wait() {
    let (mut c, outcomes) = rbing_owned_data_actual_stall(false);
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    let before = c.streams.get_mut(ep, st).unwrap().receive.clone();
    c.poll(Duration::ZERO);
    c.drain_observations();
    assert!(outcomes.borrow().is_empty());
    assert_eq!(c.control.incoming.len(), 1);
    assert_eq!(c.control.incoming[0].remaining, 600);
    assert_eq!(c.streams.get_mut(ep, st).unwrap().receive, before);
    assert!(!c.drain_actions().any(|a| matches!(a, QcsdAction::LeaseParserReceive { .. })));
    c.poll(Duration::from_micros(5_000));
    c.drain_observations();
    assert_eq!(&*outcomes.borrow(), &[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]);
}

#[test]
fn rbing_owned_data_controller_whole600_has_no_credit_before_physical_advertisement() {
    let (mut c, outcomes) = rbing_owned_data_actual_stall(true);
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    c.poll(Duration::ZERO);
    c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    assert!(actions.iter().any(|a| matches!(a,
        QcsdAction::LeaseParserReceive { endpoint, stream, absolute_limit: 1_616,
            increase: 600, owner: Some(_) } if *endpoint == ep && *stream == st)));
    assert!(!actions.iter().any(|a| matches!(a, QcsdAction::SlotSatisfied { .. })));
    assert!(outcomes.borrow().is_empty());
    assert!(c.control.incoming.is_empty());
    assert_eq!(c.control.next_slot_id, 1);
    let ledger = c.incoming_credit_ledger.values().next().unwrap();
    assert_eq!((ledger.requested(), ledger.advertised, ledger.consumed, ledger.retired), (600, 0, 0, 0));
    if let crate::stream::ReceiveState::ReceivingData { parser_lease_used, .. } =
        c.streams.get_mut(ep, st).unwrap().receive { assert_eq!(parser_lease_used, 1_000); }
    c.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ep, stream: st, absolute_limit: 1_616, slot: None,
    }, Duration::from_micros(100));
    let ledger = c.incoming_credit_ledger.values().next().unwrap();
    assert_eq!((ledger.requested(), ledger.advertised, ledger.consumed, ledger.retired), (600, 600, 0, 0));
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 2 }, Duration::from_micros(200));
    c.observe(QcsdObservation::DataFrame {
        endpoint: ep, stream: st, frame_header_bytes: 2, data_bytes: 598,
    }, Duration::from_micros(201));
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 598 }, Duration::from_micros(202));
    assert_eq!(c.scheduled_incoming_requested_bytes, 600);
    assert_eq!(c.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(c.scheduled_incoming_consumed_bytes, 600);
    assert_eq!(c.scheduled_incoming_retired_bytes, 0);
}

#[test]
fn rbing_owned_data_controller_preserves_application_priority_and_atomic_rollback() {
    let (mut c, outcomes) = rbing_owned_data_actual_stall(true);
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    c.streams.open(ep, QcsdStreamId(0), QcsdRequestRole::Application, true, 16, 1_000, 50);
    let before = c.streams.get_mut(ep, st).unwrap().receive.clone();
    let app_before = c.streams.get_mut(ep, QcsdStreamId(0)).unwrap().receive.clone();
    c.poll(Duration::ZERO);
    c.drain_observations();
    assert!(outcomes.borrow().is_empty());
    assert_eq!(c.control.incoming[0].remaining, 600);
    assert_eq!(c.streams.get_mut(ep, st).unwrap().receive, before);
    assert_eq!(c.streams.get_mut(ep, QcsdStreamId(0)).unwrap().receive, app_before);
    assert!(c.control.credit.is_empty() && c.control.claims.is_empty());
    assert!(!c.drain_actions().any(|a| matches!(a,
        QcsdAction::LeaseParserReceive { .. } | QcsdAction::IncreaseReceiveLimit { .. })));
}

#[test]
fn rbing_owned_data_controller_startup_gate_is_exact_and_one_shot() {
    let mut c = prospective_rbing_actual_cs();
    assert!(c.enable_cs_rbing_owned_data_continuation("r.bing.com").is_err());
    c.enable_cs_live_chaff_header_progress().unwrap();
    c.enable_cs_rbing_same_window_capacity_retry("r.bing.com").unwrap();
    c.enable_cs_rbing_current_data("r.bing.com").unwrap();
    assert!(c.enable_cs_rbing_owned_data_continuation("angkanet26.com").is_err());
    c.enable_cs_rbing_owned_data_continuation("r.bing.com").unwrap();
    assert!(c.enable_cs_rbing_owned_data_continuation("r.bing.com").is_err());
    let mut c = prospective_rbing_actual_cs();
    c.enable_cs_live_chaff_header_progress().unwrap();
    c.enable_cs_rbing_same_window_capacity_retry("r.bing.com").unwrap();
    c.enable_cs_rbing_current_data("r.bing.com").unwrap();
    ready(&mut c, 1, "https://r.bing.com");
    assert!(c.enable_cs_rbing_owned_data_continuation("r.bing.com").is_err());
}

fn rbing_owned_data_actual_unread_prefix(enabled: bool) -> (QcsdController, Rc<RefCell<Vec<EventOutcome>>>) {
    let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).unwrap();
    let (one, outcomes) = ExactIncomingOneShot::new(packet);
    let mut c = QcsdController::with_defense(prospective_rbing_config(), None,
        Box::new(RbingLiveAllocatorFixture(one))).unwrap();
    c.cs_rbing_capacity_retry = true;
    ready(&mut c, 1, "https://r.bing.com");
    assert!(c.streams.enable_cs_live_chaff_headers());
    assert!(c.streams.enable_cs_rbing_current_data());
    c.cs_rbing_current_data = true;
    if enabled {
        assert!(c.streams.enable_cs_rbing_owned_data_continuation());
        c.cs_rbing_owned_data_continuation = true;
    }
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    let role = QcsdRequestRole::Chaff {
        resource_id: 4,
        request_id: Some(crate::QcsdChaffRequestId(0)),
    };
    c.streams.open(ep, st, role, true, 16, 1_000, 5_000);
    c.streams.record_chaff_request_acknowledgment(ep, st, role, 0, 73, true);
    assert!(c.streams.record_pre_header_blocked(ep, st, 16));
    let first = c.streams.cs_live_chaff_header_bootstrap_lease(ep, st, 5_000).unwrap();
    assert_eq!((first.absolute_limit, first.increase, first.scheduled), (1_000, 984, false));
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.advertised(1_000);
    state.receive.bytes_read(928);
    state.response_headers(928, Some(200), None);
    state.receive.bytes_read(3);
    c.streams.record_cs_rbing_current_data_frame(ep, st, 3, 69);
    let state = c.streams.get_mut(ep, st).unwrap();
    state.receive.data_frame(3, 69);
    state.receive.bytes_read(69);
    state.receive.header_progress(1, true);
    let prefix = c.streams.cs_rbing_current_data_prefix_lease(ep, st, 1).unwrap();
    assert_eq!((prefix.absolute_limit, prefix.increase), (1_016, 16));
    // Actual saved controller ownership: leave the final advertised byte
    // unread. The old fixture consumed a fabricated extra byte and omitted
    // this controller range, so it did not exercise the live boundary gate.
    c.parser_lease_ranges.insert((ep, st), vec![ParserLeaseRange {
        start: 1_000, end: 1_016, owner: None, unowned: true,
        reservation_debited: false, advertised: false,
    }]);
    c.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ep, stream: st, absolute_limit: 1_016, slot: None,
    }, Duration::ZERO);
    c.observe(QcsdObservation::StreamDataBlocked {
        endpoint: ep, stream: st, blocked_at: 1_016,
    }, Duration::ZERO);
    for _ in 0..2 {
        c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 1 }, Duration::ZERO);
    }
    c.observe(QcsdObservation::DataFrame {
        endpoint: ep, stream: st, frame_header_bytes: 2, data_bytes: 13,
    }, Duration::ZERO);
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 13 }, Duration::ZERO);
    c.observe(QcsdObservation::HeaderProgress {
        endpoint: ep, stream: st, min_remaining: 1, awaiting_data_frame: true,
    }, Duration::ZERO);
    assert_eq!(c.streams.consumed(ep, st), Some(1_015));
    let range = &c.parser_lease_ranges[&(ep, st)][0];
    assert_eq!((range.start, range.end, range.owner, range.unowned, range.advertised),
        (1_015, 1_016, None, true, true));
    c.drain_actions().for_each(drop);
    (c, outcomes)
}

fn rbing_assert_old_unowned_one_plus_new_owned600(
    c: &mut QcsdController, outcomes: &Rc<RefCell<Vec<EventOutcome>>>, at: Duration,
) {
    let ep = QcsdEndpointId(1);
    let st = QcsdStreamId(80);
    let actions: Vec<_> = c.drain_actions().collect();
    let owners: Vec<_> = actions.iter().filter_map(|a| match a {
        QcsdAction::LeaseParserReceive { endpoint, stream, absolute_limit: 1_616,
            increase: 600, owner: Some(owner) } if *endpoint == ep && *stream == st => Some(*owner),
        _ => None,
    }).collect();
    assert_eq!(owners.len(), 1);
    let owner = owners[0];
    assert!(outcomes.borrow().is_empty());
    assert_eq!(c.parser_lease_ranges[&(ep, st)].len(), 2);
    let old = &c.parser_lease_ranges[&(ep, st)][0];
    assert_eq!((old.start, old.end, old.owner, old.unowned), (1_015, 1_016, None, true));
    let new = &c.parser_lease_ranges[&(ep, st)][1];
    assert_eq!((new.start, new.end, new.owner, new.unowned), (1_016, 1_616, Some(owner), false));
    let ledger = &c.incoming_credit_ledger[&owner.slot];
    assert_eq!((ledger.requested(), ledger.advertised, ledger.consumed, ledger.retired), (600, 0, 0, 0));
    c.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ep, stream: st, absolute_limit: 1_616, slot: None,
    }, at + Duration::from_micros(1));
    assert_eq!(c.incoming_credit_ledger[&owner.slot].advertised, 600);
    // The first real byte belongs solely to the old unowned range.
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 1 }, at + Duration::from_micros(2));
    assert_eq!(c.incoming_credit_ledger[&owner.slot].consumed, 0);
    for _ in 0..2 {
        c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 1 }, at + Duration::from_micros(3));
    }
    // A 598-byte DATA length uses two varint length bytes plus one type byte.
    c.observe(QcsdObservation::DataFrame {
        endpoint: ep, stream: st, frame_header_bytes: 3, data_bytes: 598,
    }, at + Duration::from_micros(4));
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 598 }, at + Duration::from_micros(5));
    assert_eq!(c.streams.consumed(ep, st), Some(1_616));
    assert!(c.parser_lease_ranges.get(&(ep, st)).is_none_or(Vec::is_empty));
    assert_eq!((c.scheduled_incoming_requested_bytes, c.scheduled_incoming_advertised_bytes,
        c.scheduled_incoming_consumed_bytes, c.scheduled_incoming_retired_bytes), (600, 600, 600, 0));
    assert_eq!(c.drain_actions().filter(|a| matches!(a,
        QcsdAction::SlotSatisfied { slot, .. } if *slot == owner.slot)).count(), 1);
    if let crate::stream::ReceiveState::ReceivingData { parser_lease_used, parser_lease_capacity, .. } =
        c.streams.get_mut(ep, st).unwrap().receive {
        assert_eq!((parser_lease_used, parser_lease_capacity), (1_000, 1_000));
    } else { panic!("original receive state"); }
}

#[test]
fn rbing_owned_data_continuation_rejects_known_subcell_chaff_body_tail() {
    let (mut c, outcomes) = rbing_owned_data_actual_unread_prefix(true);
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    if let crate::stream::ReceiveState::ReceivingData { data_length, .. } =
        &mut c.streams.get_mut(endpoint, stream).unwrap().receive
    {
        // The qualified response has 5,000 body bytes.  A 599-byte tail is
        // insufficient to fund another exact 600-byte incoming cell, even
        // though raw framing can make the final response stream longer.
        *data_length = 4_401;
    } else {
        panic!("fixture must have observed chaff DATA");
    }
    assert!(c.streams.cs_rbing_owned_data_opportunities(endpoint).is_empty());
    c.poll(Duration::ZERO);
    c.drain_observations();
    assert!(outcomes.borrow().is_empty());
    assert!(!c.drain_actions().any(|action| matches!(
        action,
        QcsdAction::LeaseParserReceive { stream: candidate, increase: 600, owner: Some(_), .. }
            if candidate == stream
    )));
}

#[test]
fn rbing_terminal_chaff_fin_retains_exact_425_of_600_and_raw_retirement() {
    let (mut c, _) = rbing_owned_data_actual_stall_with_terminal_policy(true, true);
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    if let crate::stream::ReceiveState::ReceivingData { data_length, .. } =
        &mut c.streams.get_mut(endpoint, stream).expect("live chaff stream").receive
    {
        // The exact prepared 5,000-byte fixture response is complete; only
        // raw HTTP/3 framing remains for the 425/175 owned-cell split.
        *data_length = 5_000;
    } else {
        panic!("fixture must have observed chaff DATA");
    }
    assert!(c
        .streams
        .cs_rbing_terminal_chaff_partial_eligible(endpoint, stream));
    c.poll(Duration::ZERO);
    c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    let owner = actions
        .iter()
        .find_map(|action| match action {
            QcsdAction::LeaseParserReceive {
                endpoint: candidate_endpoint,
                stream: candidate_stream,
                absolute_limit,
                increase: 600,
                owner: Some(owner),
            } if *candidate_endpoint == endpoint && *candidate_stream == stream => {
                Some((*absolute_limit, *owner))
            }
            _ => None,
        })
        .expect("terminal cell is physically leased");
    c.observe(
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint,
            stream,
            absolute_limit: owner.0,
            slot: None,
        },
        Duration::from_micros(1),
    );
    c.observe(
        QcsdObservation::BytesRead {
            endpoint,
            stream,
            bytes: 425,
        },
        Duration::from_micros(2),
    );
    let range = c
        .parser_lease_ranges
        .get(&(endpoint, stream))
        .and_then(|ranges| ranges.iter().find(|range| range.owner == Some(owner.1)))
        .expect("remaining owned terminal range");
    let ledger = c
        .incoming_credit_ledger
        .get(&owner.1.slot)
        .expect("terminal ledger");
    assert_eq!(
        (
            range.bytes(),
            range.advertised,
            range.unowned,
            range.reservation_debited,
            ledger.advertised,
            ledger.consumed,
            ledger.retired,
            ledger.local_realization_emitted,
        ),
        (175, true, false, false, 600, 425, 0, true)
    );
    assert!(c
        .streams
        .cs_rbing_terminal_chaff_partial_eligible(endpoint, stream));
    c.observe(
        QcsdObservation::StreamFinished {
            endpoint,
            stream,
            finish: crate::QcsdStreamFinish::Fin,
        },
        Duration::from_micros(3),
    );
    let proof = c
        .terminal_chaff_partial_cells()
        .first()
        .expect("qualified terminal chaff proof");
    assert_eq!(
        (
            proof.resource_id,
            proof.request_id,
            proof.slot,
            proof.cell_bytes,
            proof.advertised_bytes,
            proof.consumed_bytes,
            proof.retired_bytes,
        ),
        (4, 0, owner.1.slot.0, 600, 600, 425, 175)
    );
    assert!(c.drain_actions().any(|action| matches!(
        action,
        QcsdAction::SlotMissed {
            slot,
            reason: MissedSlotReason::ReceiveCreditRetired,
            ..
        } if slot == owner.1.slot
    )));
    assert!(c.observations.iter().any(|observation| matches!(
        observation,
        super::QueuedDefenseObservation::Signal(DefenseSignal {
            kind: SignalKind::TerminalChaffPartial { slot, consumed: 425, retired: 175, .. },
            ..
        }) if *slot == owner.1.slot
    )));
}

#[test]
fn rbing_b814_first_proven_terminal_chaff_fin_closes_replenishment() {
    let (mut c, _) = rbing_owned_data_actual_stall_with_terminal_policy(true, true);
    c.terminal_chaff_replenishment_closure = true;
    c.chaff = Some(super::ChaffManager::new(
        ResourceManifest {
            resources: vec![Resource {
                id: 4,
                url: "https://r.bing.com/chaff".into(),
                kind: "Image".into(),
                content_length: Some(5_000),
                data_length: 5_000,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: Vec::new(),
            }],
        },
        false,
    ));
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    c.request_chaff_if_needed(true);
    assert_eq!(c.chaff.as_ref().expect("chaff manager").pending_count(), 4);
    assert_eq!(
        c.actions
            .iter()
            .filter(|action| matches!(action, QcsdAction::RequestChaff { .. }))
            .count(),
        4
    );

    // This second request represents an already-open qualified stream. B814
    // must not cancel it when the first proof closes future replenishment.
    let active_stream = QcsdStreamId(81);
    let active_role = QcsdRequestRole::Chaff {
        resource_id: 4,
        request_id: Some(crate::QcsdChaffRequestId(100)),
    };
    c.streams
        .open(endpoint, active_stream, active_role, true, 16, 1_000, 5_000);

    if let crate::stream::ReceiveState::ReceivingData { data_length, .. } =
        &mut c.streams.get_mut(endpoint, stream).expect("live chaff stream").receive
    {
        *data_length = 5_000;
    } else {
        panic!("fixture must have observed chaff DATA");
    }
    c.poll(Duration::ZERO);
    c.drain_observations();
    let owner = c
        .actions
        .iter()
        .find_map(|action| match action {
            QcsdAction::LeaseParserReceive {
                endpoint: candidate_endpoint,
                stream: candidate_stream,
                absolute_limit,
                increase: 600,
                owner: Some(owner),
            } if *candidate_endpoint == endpoint && *candidate_stream == stream => {
                Some((*absolute_limit, *owner))
            }
            _ => None,
        })
        .expect("terminal cell is physically leased");
    c.observe(
        QcsdObservation::ReceiveLimitAdvertised {
            endpoint,
            stream,
            absolute_limit: owner.0,
            slot: None,
        },
        Duration::from_micros(1),
    );
    c.observe(
        QcsdObservation::BytesRead {
            endpoint,
            stream,
            bytes: 425,
        },
        Duration::from_micros(2),
    );
    c.observe(
        QcsdObservation::StreamFinished {
            endpoint,
            stream,
            finish: crate::QcsdStreamFinish::Fin,
        },
        Duration::from_micros(3),
    );

    let proof = c
        .terminal_chaff_partial_cells()
        .first()
        .expect("qualified B814 terminal chaff proof");
    assert_eq!(
        proof.policy,
        "r-bing-cs600-first-proven-terminal-chaff-fin-closes-replenishment-v1"
    );
    let closure = c
        .terminal_chaff_replenishment_closure()
        .expect("first fully proven FIN closes B814 replenishment");
    assert_eq!(
        (
            closure.resource_id,
            closure.request_id,
            closure.endpoint,
            closure.stream,
            closure.slot,
            closure.proof_count,
            closure.future_replenishment,
            closure.active_streams,
        ),
        (
            proof.resource_id,
            proof.request_id,
            proof.endpoint,
            proof.stream,
            proof.slot,
            1,
            "rejected",
            "preserved",
        )
    );
    assert_eq!(c.chaff.as_ref().expect("chaff manager").pending_count(), 0);
    assert!(!c
        .actions
        .iter()
        .any(|action| matches!(action, QcsdAction::RequestChaff { .. })));
    assert_eq!(
        c.streams.get_mut(endpoint, active_stream).map(|state| state.role),
        Some(active_role)
    );

    c.drain_actions().for_each(drop);
    c.request_chaff_if_needed(true);
    assert!(!c
        .drain_actions()
        .any(|action| matches!(action, QcsdAction::RequestChaff { .. })));
}

#[test]
fn rbing_b815_closure_stops_fresh_incoming_before_materialization() {
    let incoming_stop = Rc::new(RefCell::new(false));
    let emitted = Rc::new(RefCell::new(0));
    let mut c = b815_future_incoming_controller(Rc::clone(&incoming_stop), Rc::clone(&emitted));
    c.terminal_chaff_replenishment_closure = true;
    c.terminal_chaff_replenishment_b815_incoming_stop = true;
    c.close_terminal_chaff_replenishment(
        b815_closure_proof(
            "r-bing-cs600-b815-first-proven-terminal-chaff-fin-closes-replenishment-and-stops-fresh-incoming-v1",
            815,
        ),
        Duration::from_micros(3),
    );

    assert!(*incoming_stop.borrow());
    assert_eq!(
        c.terminal_chaff_replenishment_closure()
            .expect("B815 closure receipt")
            .policy,
        "r-bing-cs600-b815-first-proven-terminal-chaff-fin-closes-replenishment-and-stops-fresh-incoming-v1"
    );
    c.poll(Duration::from_micros(10));
    c.drain_observations();
    assert_eq!(*emitted.borrow(), 0);
    assert_eq!(c.control.next_slot_id, 0);
    assert!(!c.drain_actions().any(|action| {
        matches!(
            action,
            QcsdAction::RequestChaff { .. }
                | QcsdAction::SlotMissed {
                    reason: MissedSlotReason::DeadlineExpired,
                    ..
                }
        )
    }));

    let b814_stop = Rc::new(RefCell::new(false));
    let b814_emitted = Rc::new(RefCell::new(0));
    let mut b814 =
        b815_future_incoming_controller(Rc::clone(&b814_stop), Rc::clone(&b814_emitted));
    b814.terminal_chaff_replenishment_closure = true;
    b814.close_terminal_chaff_replenishment(
        b815_closure_proof(
            "r-bing-cs600-first-proven-terminal-chaff-fin-closes-replenishment-v1",
            814,
        ),
        Duration::from_micros(3),
    );
    assert!(!*b814_stop.borrow());
    b814.poll(Duration::from_micros(10));
    assert_eq!(*b814_emitted.borrow(), 1);
}

#[test]
fn rbing_terminal_chaff_partial_rejects_short_prepared_body() {
    let (mut c, _) = rbing_owned_data_actual_stall_with_terminal_policy(true, true);
    let endpoint = QcsdEndpointId(1);
    let stream = QcsdStreamId(80);
    if let crate::stream::ReceiveState::ReceivingData { data_length, .. } =
        &mut c.streams.get_mut(endpoint, stream).expect("live chaff stream").receive
    {
        *data_length = 4_999;
    }
    assert!(!c
        .streams
        .cs_rbing_terminal_chaff_partial_eligible(endpoint, stream));
}

#[test]
fn rbing_unread_unowned_one_is_not_new600_credit_and_both_ranges_really_drain() {
    let (mut c, outcomes) = rbing_owned_data_actual_unread_prefix(true);
    assert!(c.cs_rbing_owned_chaff_boundary(QcsdEndpointId(1), QcsdStreamId(80)));
    c.poll(Duration::ZERO);
    c.drain_observations();
    rbing_assert_old_unowned_one_plus_new_owned600(&mut c, &outcomes, Duration::ZERO);
}

#[test]
fn rbing_partial_exact_rolls_back_before_same_deadline_owned600_retry() {
    let (mut c, outcomes) = rbing_owned_data_actual_unread_prefix(true);
    let ep = QcsdEndpointId(1);
    let app = QcsdStreamId(0);
    c.streams.open(ep, app, QcsdRequestRole::Application, true, 16, 1_000, 50);
    let before = c.streams.get_mut(ep, app).unwrap().receive.clone();
    c.poll(Duration::ZERO);
    c.drain_observations();
    assert!(outcomes.borrow().is_empty());
    assert_eq!(c.streams.get_mut(ep, app).unwrap().receive, before);
    assert_eq!(c.control.incoming.len(), 1);
    assert_eq!(c.control.incoming[0].remaining, 600);
    assert_eq!(c.cs_rbing_capacity_retry_at.len(), 1);
    assert!(!c.drain_actions().any(|a| matches!(a, QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::LeaseParserReceive { .. })));
    c.poll(Duration::from_micros(250));
    c.drain_observations();
    assert_eq!(c.streams.get_mut(ep, app).unwrap().receive, before);
    rbing_assert_old_unowned_one_plus_new_owned600(&mut c, &outcomes, Duration::from_micros(250));
}

#[test]
fn rbing_full_exact_first_pass_keeps_original_application_priority() {
    let (mut c, outcomes) = rbing_owned_data_actual_unread_prefix(true);
    let ep = QcsdEndpointId(1);let app = QcsdStreamId(0);
    c.streams.open(ep, app, QcsdRequestRole::Application, true, 16, 1_000, 1_000);
    let chaff_before = c.streams.get_mut(ep, QcsdStreamId(80)).unwrap().receive.clone();
    c.poll(Duration::ZERO);c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    assert!(actions.iter().any(|a| matches!(a,QcsdAction::IncreaseReceiveLimit { stream, .. } if *stream == app)));
    assert!(!actions.iter().any(|a| matches!(a,QcsdAction::LeaseParserReceive { .. })));
    assert_eq!(c.streams.get_mut(ep, QcsdStreamId(80)).unwrap().receive, chaff_before);
    assert!(outcomes.borrow().is_empty());
}

#[test]
fn rbing_unowned_prefix_refuses_wrong_ownership_frontier_and_advertisement() {
    for bad in 0..7 {
        let (mut c, _) = rbing_owned_data_actual_unread_prefix(true);
        let ep=QcsdEndpointId(1);let st=QcsdStreamId(80);
        let range=&mut c.parser_lease_ranges.get_mut(&(ep,st)).unwrap()[0];
        match bad {
            0 => range.unowned=false,
            1 => range.advertised=false,
            2 => range.reservation_debited=true,
            3 => range.owner=Some(QcsdParserLeaseOwner { slot:QcsdSlotId(9), packet:Packet::new(Duration::ZERO,Direction::Incoming,600).unwrap() }),
            4 => range.start-=1,
            5 => range.end+=1,
            _ => { let other=*range;c.parser_lease_ranges.get_mut(&(ep,st)).unwrap().push(other); },
        }
        assert!(!c.cs_rbing_owned_chaff_boundary(ep,st), "negative {bad}");
    }
}

#[test]
fn rbing_owned_fallback_cannot_extend_original_five_ms_deadline() {
    let (mut c, outcomes)=rbing_owned_data_actual_unread_prefix(true);
    let ep=QcsdEndpointId(1);c.streams.open(ep,QcsdStreamId(0),QcsdRequestRole::Application,true,16,1_000,50);
    c.poll(Duration::ZERO);c.drain_observations();c.drain_actions().for_each(drop);
    c.poll(Duration::from_micros(5_000));c.drain_observations();
    assert_eq!(&*outcomes.borrow(),&[EventOutcome::Missed(MissedSlotReason::DeadlineExpired)]);
    assert!(!c.drain_actions().any(|a| matches!(a,QcsdAction::LeaseParserReceive { owner:Some(_), .. })));
    assert_eq!(c.scheduled_incoming_advertised_bytes,0);
}

// Model the live state after 599 of an advertised earlier cell were consumed.
// The remaining byte is still the earlier owner's, never the next cell's.
fn rbing_prior_owned_one_fixture() -> (QcsdController, Rc<RefCell<Vec<EventOutcome>>>, QcsdSlotId) {
    let (mut c, outcomes) = rbing_owned_data_actual_unread_prefix(true);
    let ep = QcsdEndpointId(1); let st = QcsdStreamId(80);
    let old_slot = QcsdSlotId(999);
    let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).unwrap();
    let owner = QcsdParserLeaseOwner { slot: old_slot, packet };
    let range = &mut c.parser_lease_ranges.get_mut(&(ep, st)).unwrap()[0];
    range.owner = Some(owner); range.unowned = false; range.reservation_debited = false;
    c.pending_slots.insert(old_slot, packet);
    let mut ledger = IncomingCreditLedger::new(packet);
    ledger.endpoint = Some(ep); ledger.advertised = 600; ledger.consumed = 599;
    ledger.local_realization_emitted = true;
    c.incoming_credit_ledger.insert(old_slot, ledger);
    (c, outcomes, old_slot)
}

#[test]
fn rbing_prior_owned_one_and_new_owned_cell_remain_disjoint() {
    let (mut c, _, old_slot) = rbing_prior_owned_one_fixture();
    let ep = QcsdEndpointId(1); let st = QcsdStreamId(80);
    assert!(c.cs_rbing_owned_chaff_boundary(ep, st));
    c.poll(Duration::ZERO); c.drain_observations();
    let actions: Vec<_> = c.drain_actions().collect();
    let owner = actions.iter().find_map(|a| match a {
        QcsdAction::LeaseParserReceive { endpoint, stream, absolute_limit: 1616, increase: 600, owner: Some(owner) }
          if *endpoint == ep && *stream == st => Some(*owner), _ => None,
    }).expect("new due slot owns a disjoint cell");
    assert_ne!(owner.slot, old_slot);
    let ranges = &c.parser_lease_ranges[&(ep, st)];
    assert_eq!(ranges.len(), 2);
    assert_eq!((ranges[0].start, ranges[0].end, ranges[0].owner.unwrap().slot), (1015, 1016, old_slot));
    assert_eq!((ranges[1].start, ranges[1].end, ranges[1].owner.unwrap().slot), (1016, 1616, owner.slot));
    c.observe(QcsdObservation::ReceiveLimitAdvertised { endpoint: ep, stream: st, absolute_limit: 1616, slot: None }, Duration::from_micros(1));
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 1 }, Duration::from_micros(2));
    assert_eq!(c.incoming_credit_ledger[&owner.slot].consumed, 0);
    assert!(c.incoming_credit_ledger.get(&old_slot).is_none());
    assert!(c.drain_actions().any(|a| matches!(a, QcsdAction::SlotSatisfied { slot, .. } if slot == old_slot)));
    for _ in 0..2 {
        c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 1 }, Duration::from_micros(3));
    }
    c.observe(QcsdObservation::DataFrame { endpoint: ep, stream: st, frame_header_bytes: 3, data_bytes: 598 }, Duration::from_micros(4));
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: st, bytes: 598 }, Duration::from_micros(5));
    assert!(c.incoming_credit_ledger.get(&owner.slot).is_none());
    assert!(c.drain_actions().any(|a| matches!(a, QcsdAction::SlotSatisfied { slot, .. } if slot == owner.slot)));
    assert!(c.parser_lease_ranges.get(&(ep,st)).is_none_or(Vec::is_empty));
}

#[test]
fn rbing_prior_owned_one_requires_complete_original_ownership_proof() {
    for bad in 0..8 {
        let (mut c, _, old_slot) = rbing_prior_owned_one_fixture();
        let ep=QcsdEndpointId(1); let st=QcsdStreamId(80);
        match bad {
            0 => c.incoming_credit_ledger.get_mut(&old_slot).unwrap().local_realization_emitted=false,
            1 => c.incoming_credit_ledger.get_mut(&old_slot).unwrap().consumed=598,
            2 => c.incoming_credit_ledger.get_mut(&old_slot).unwrap().retired=1,
            3 => c.incoming_credit_ledger.get_mut(&old_slot).unwrap().advertised=599,
            4 => { c.pending_slots.remove(&old_slot); },
            5 => c.parser_lease_ranges.get_mut(&(ep,st)).unwrap()[0].advertised=false,
            6 => c.parser_lease_ranges.get_mut(&(ep,st)).unwrap()[0].reservation_debited=true,
            _ => c.incoming_credit_ledger.get_mut(&old_slot).unwrap().endpoint=Some(QcsdEndpointId(2)),
        }
        assert!(!c.cs_rbing_owned_chaff_boundary(ep,st), "bad ownership {bad}");
    }
}

#[test]
fn rbing_ten_balancing_selects_less_consumed_eligible_chaff_without_new_credit() {
    let (mut c, _) = rbing_owned_data_actual_unread_prefix(true);
    c.config.max_chaff_streams = 10;
    let ep=QcsdEndpointId(1); let old=QcsdStreamId(80); let fresh=QcsdStreamId(84);
    // Reproduce one already-advanced stream with its same unowned one-byte
    // frontier, and one genuine fresh ACKed/decoded-DATA frontier.
    if let crate::stream::ReceiveState::ReceivingData { advertised_limit, requested_limit,
        consumed, pending_parser_boundary, .. } = &mut c.streams.get_mut(ep,old).unwrap().receive {
        *advertised_limit=1_616; *requested_limit=1_616; *consumed=1_615;
        *pending_parser_boundary=Some(1_615);
    } else { panic!("original receiving-data state"); }
    let r=&mut c.parser_lease_ranges.get_mut(&(ep,old)).unwrap()[0];r.start=1_615;r.end=1_616;
    assert!(c.streams.record_parser_blocked(ep,old,1_616));
    let role=QcsdRequestRole::Chaff { resource_id:4, request_id:Some(crate::QcsdChaffRequestId(1)) };
    c.streams.open(ep,fresh,role,true,16,1_000,5_000);
    c.streams.record_chaff_request_acknowledgment(ep,fresh,role,0,73,true);
    assert!(c.streams.record_pre_header_blocked(ep,fresh,16));
    let first=c.streams.cs_live_chaff_header_bootstrap_lease(ep,fresh,5_000).unwrap();
    assert_eq!((first.absolute_limit,first.increase),(1_000,984));
    let state=c.streams.get_mut(ep,fresh).unwrap();state.receive.advertised(1_000);state.receive.bytes_read(928);
    state.response_headers(928,Some(200),None);state.receive.bytes_read(3);
    c.streams.record_cs_rbing_current_data_frame(ep,fresh,3,69);
    let state=c.streams.get_mut(ep,fresh).unwrap();state.receive.data_frame(3,69);state.receive.bytes_read(69);state.receive.header_progress(1,true);
    let prefix=c.streams.cs_rbing_current_data_prefix_lease(ep,fresh,1).unwrap();
    assert_eq!((prefix.absolute_limit,prefix.increase),(1_016,16));
    c.parser_lease_ranges.insert((ep,fresh),vec![ParserLeaseRange { start:1_000,end:1_016,owner:None,unowned:true,reservation_debited:false,advertised:false }]);
    c.observe(QcsdObservation::ReceiveLimitAdvertised {endpoint:ep,stream:fresh,absolute_limit:1_016,slot:None},Duration::ZERO);
    c.observe(QcsdObservation::StreamDataBlocked {endpoint:ep,stream:fresh,blocked_at:1_016},Duration::ZERO);
    for _ in 0..2 {c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:fresh,bytes:1},Duration::ZERO);}
    c.observe(QcsdObservation::DataFrame {endpoint:ep,stream:fresh,frame_header_bytes:2,data_bytes:13},Duration::ZERO);
    c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:fresh,bytes:13},Duration::ZERO);
    c.observe(QcsdObservation::HeaderProgress {endpoint:ep,stream:fresh,min_remaining:1,awaiting_data_frame:true},Duration::ZERO);
    c.drain_actions().for_each(drop);
    assert!(c.cs_rbing_owned_chaff_boundary(ep,old));assert!(c.cs_rbing_owned_chaff_boundary(ep,fresh));
    c.poll(Duration::ZERO);c.drain_observations();
    let actions:Vec<_>=c.drain_actions().collect();
    assert!(actions.iter().any(|a| matches!(a,QcsdAction::LeaseParserReceive {stream, increase:600, owner:Some(_), ..} if *stream==fresh)));
    assert!(!actions.iter().any(|a| matches!(a,QcsdAction::LeaseParserReceive {stream, ..} if *stream==old)));
    assert_eq!(c.streams.consumed(ep,old),Some(1_615));
    assert_eq!(c.streams.consumed(ep,fresh),Some(1_015));
}

#[test]
fn rbing_supported_prior_owned_one_to_three_bytes_remain_with_original_slot() {
    for streams in [5, 10, 50] {
    for tail in 1..=3 {
        let (mut c, _, old_slot)=rbing_prior_owned_one_fixture();
        c.config.max_chaff_streams=streams;
        let ep=QcsdEndpointId(1);let st=QcsdStreamId(80);
        if let crate::stream::ReceiveState::ReceivingData {consumed,pending_parser_boundary,..} =
            &mut c.streams.get_mut(ep,st).unwrap().receive {
            *consumed=1_016-tail;*pending_parser_boundary=Some(*consumed);
        } else {panic!("receiving data");}
        c.parser_lease_ranges.get_mut(&(ep,st)).unwrap()[0].start=1_016-tail;
        c.incoming_credit_ledger.get_mut(&old_slot).unwrap().consumed=600-tail;
        assert!(c.cs_rbing_owned_chaff_boundary(ep,st),"tail {tail}");
        c.poll(Duration::ZERO);c.drain_observations();
        let actions:Vec<_>=c.drain_actions().collect();
        let owner=actions.iter().find_map(|a| match a {
            QcsdAction::LeaseParserReceive {stream,increase:600,owner:Some(owner),..}
                if *stream==st=>Some(*owner),_=>None,
        }).expect("new due slot owns its own cell");
        assert_ne!(owner.slot,old_slot);
        let ranges=&c.parser_lease_ranges[&(ep,st)];
        assert_eq!((ranges[0].start,ranges[0].end,ranges[0].owner.unwrap().slot),(1_016-tail,1_016,old_slot));
        assert_eq!((ranges[1].start,ranges[1].end,ranges[1].owner.unwrap().slot),(1_016,1_616,owner.slot));
        c.observe(QcsdObservation::ReceiveLimitAdvertised {endpoint:ep,stream:st,absolute_limit:1_616,slot:None},Duration::from_micros(1));
        c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:st,bytes:tail},Duration::from_micros(2));
        assert!(c.incoming_credit_ledger.get(&old_slot).is_none());
        assert_eq!(c.incoming_credit_ledger[&owner.slot].consumed,0);
        assert!(c.drain_actions().any(|a| matches!(a,QcsdAction::SlotSatisfied {slot,..} if slot==old_slot)));
        c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:st,bytes:600},Duration::from_micros(3));
        assert!(c.incoming_credit_ledger.get(&owner.slot).is_none());
        assert!(c.drain_actions().any(|a| matches!(a,QcsdAction::SlotSatisfied {slot,..} if slot==owner.slot)));
    }
    }
}

#[test]
fn rbing_owned_long_tail_remains_rejected() {
    for streams in [5, 10, 50] {
        let tail = 4;
        let (mut c,_,old_slot)=rbing_prior_owned_one_fixture(); c.config.max_chaff_streams=streams;
        let ep=QcsdEndpointId(1);let st=QcsdStreamId(80);
        if let crate::stream::ReceiveState::ReceivingData {consumed,pending_parser_boundary,..} =
            &mut c.streams.get_mut(ep,st).unwrap().receive {
            *consumed=1_016-tail;*pending_parser_boundary=Some(*consumed);
        } else {panic!("receiving data");}
        c.parser_lease_ranges.get_mut(&(ep,st)).unwrap()[0].start=1_016-tail;
        c.incoming_credit_ledger.get_mut(&old_slot).unwrap().consumed=600-tail;
        assert!(!c.cs_rbing_owned_chaff_boundary(ep,st),"streams {streams} tail {tail}");
    }
}

#[test]
fn rbing_fifty_balancing_selects_less_consumed_eligible_chaff_without_new_credit() {
    let (mut c, _) = rbing_owned_data_actual_unread_prefix(true);
    c.config.max_chaff_streams = 50;
    let ep=QcsdEndpointId(1); let old=QcsdStreamId(80); let fresh=QcsdStreamId(84);
    // Reproduce one already-advanced stream with its same unowned one-byte
    // frontier, and one genuine fresh ACKed/decoded-DATA frontier.
    if let crate::stream::ReceiveState::ReceivingData { advertised_limit, requested_limit,
        consumed, pending_parser_boundary, .. } = &mut c.streams.get_mut(ep,old).unwrap().receive {
        *advertised_limit=1_616; *requested_limit=1_616; *consumed=1_615;
        *pending_parser_boundary=Some(1_615);
    } else { panic!("original receiving-data state"); }
    let r=&mut c.parser_lease_ranges.get_mut(&(ep,old)).unwrap()[0];r.start=1_615;r.end=1_616;
    assert!(c.streams.record_parser_blocked(ep,old,1_616));
    let role=QcsdRequestRole::Chaff { resource_id:4, request_id:Some(crate::QcsdChaffRequestId(1)) };
    c.streams.open(ep,fresh,role,true,16,1_000,5_000);
    c.streams.record_chaff_request_acknowledgment(ep,fresh,role,0,73,true);
    assert!(c.streams.record_pre_header_blocked(ep,fresh,16));
    let first=c.streams.cs_live_chaff_header_bootstrap_lease(ep,fresh,5_000).unwrap();
    assert_eq!((first.absolute_limit,first.increase),(1_000,984));
    let state=c.streams.get_mut(ep,fresh).unwrap();state.receive.advertised(1_000);state.receive.bytes_read(928);
    state.response_headers(928,Some(200),None);state.receive.bytes_read(3);
    c.streams.record_cs_rbing_current_data_frame(ep,fresh,3,69);
    let state=c.streams.get_mut(ep,fresh).unwrap();state.receive.data_frame(3,69);state.receive.bytes_read(69);state.receive.header_progress(1,true);
    let prefix=c.streams.cs_rbing_current_data_prefix_lease(ep,fresh,1).unwrap();
    assert_eq!((prefix.absolute_limit,prefix.increase),(1_016,16));
    c.parser_lease_ranges.insert((ep,fresh),vec![ParserLeaseRange { start:1_000,end:1_016,owner:None,unowned:true,reservation_debited:false,advertised:false }]);
    c.observe(QcsdObservation::ReceiveLimitAdvertised {endpoint:ep,stream:fresh,absolute_limit:1_016,slot:None},Duration::ZERO);
    c.observe(QcsdObservation::StreamDataBlocked {endpoint:ep,stream:fresh,blocked_at:1_016},Duration::ZERO);
    for _ in 0..2 {c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:fresh,bytes:1},Duration::ZERO);}
    c.observe(QcsdObservation::DataFrame {endpoint:ep,stream:fresh,frame_header_bytes:2,data_bytes:13},Duration::ZERO);
    c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:fresh,bytes:13},Duration::ZERO);
    c.observe(QcsdObservation::HeaderProgress {endpoint:ep,stream:fresh,min_remaining:1,awaiting_data_frame:true},Duration::ZERO);
    c.drain_actions().for_each(drop);
    assert!(c.cs_rbing_owned_chaff_boundary(ep,old));assert!(c.cs_rbing_owned_chaff_boundary(ep,fresh));
    c.poll(Duration::ZERO);c.drain_observations();
    let actions:Vec<_>=c.drain_actions().collect();
    assert!(actions.iter().any(|a| matches!(a,QcsdAction::LeaseParserReceive {stream, increase:600, owner:Some(_), ..} if *stream==fresh)));
    assert!(!actions.iter().any(|a| matches!(a,QcsdAction::LeaseParserReceive {stream, ..} if *stream==old)));
    assert_eq!(c.streams.consumed(ep,old),Some(1_615));
    assert_eq!(c.streams.consumed(ep,fresh),Some(1_015));
}


#[test]
fn rbing_fifty_prior_owned_one_to_three_bytes_remain_with_original_slot() {
    for tail in 1..=3 {
        let (mut c, _, old_slot)=rbing_prior_owned_one_fixture();
        c.config.max_chaff_streams=50;
        let ep=QcsdEndpointId(1);let st=QcsdStreamId(80);
        if let crate::stream::ReceiveState::ReceivingData {consumed,pending_parser_boundary,..} =
            &mut c.streams.get_mut(ep,st).unwrap().receive {
            *consumed=1_016-tail;*pending_parser_boundary=Some(*consumed);
        } else {panic!("receiving data");}
        c.parser_lease_ranges.get_mut(&(ep,st)).unwrap()[0].start=1_016-tail;
        c.incoming_credit_ledger.get_mut(&old_slot).unwrap().consumed=600-tail;
        assert!(c.cs_rbing_owned_chaff_boundary(ep,st),"tail {tail}");
        c.poll(Duration::ZERO);c.drain_observations();
        let actions:Vec<_>=c.drain_actions().collect();
        let owner=actions.iter().find_map(|a| match a {
            QcsdAction::LeaseParserReceive {stream,increase:600,owner:Some(owner),..}
                if *stream==st=>Some(*owner),_=>None,
        }).expect("new due slot owns its own cell");
        assert_ne!(owner.slot,old_slot);
        let ranges=&c.parser_lease_ranges[&(ep,st)];
        assert_eq!((ranges[0].start,ranges[0].end,ranges[0].owner.unwrap().slot),(1_016-tail,1_016,old_slot));
        assert_eq!((ranges[1].start,ranges[1].end,ranges[1].owner.unwrap().slot),(1_016,1_616,owner.slot));
        c.observe(QcsdObservation::ReceiveLimitAdvertised {endpoint:ep,stream:st,absolute_limit:1_616,slot:None},Duration::from_micros(1));
        c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:st,bytes:tail},Duration::from_micros(2));
        assert!(c.incoming_credit_ledger.get(&old_slot).is_none());
        assert_eq!(c.incoming_credit_ledger[&owner.slot].consumed,0);
        assert!(c.drain_actions().any(|a| matches!(a,QcsdAction::SlotSatisfied {slot,..} if slot==old_slot)));
        c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:st,bytes:600},Duration::from_micros(3));
        assert!(c.incoming_credit_ledger.get(&owner.slot).is_none());
        assert!(c.drain_actions().any(|a| matches!(a,QcsdAction::SlotSatisfied {slot,..} if slot==owner.slot)));
    }
}


#[test]
fn rbing_fifty_mixed_cell_gives_exact_application_and_chaff_the_same_owner() {
    let (mut c, outcomes) = rbing_owned_data_actual_stall(true);
    c.config.max_chaff_streams = 50;
    let ep=QcsdEndpointId(1);let app=QcsdStreamId(0);let chaff=QcsdStreamId(80);
    c.streams.open(ep,app,QcsdRequestRole::Application,true,16,1_000,50);
    c.poll(Duration::ZERO);c.drain_observations();
    let actions:Vec<_>=c.drain_actions().collect();
    let (app_slot, app_packet)=actions.iter().find_map(|a| match a {QcsdAction::IncreaseReceiveLimit {stream,slot,packet,..} if *stream==app=>Some((*slot,*packet)),_=>None}).expect("exact application part");
    let owner=actions.iter().find_map(|a| match a {QcsdAction::LeaseParserReceive {stream,increase:566,owner:Some(owner),..} if *stream==chaff=>Some(*owner),_=>None}).expect("same-slot chaff remainder");
    assert_eq!(owner.slot,app_slot);assert_eq!(owner.packet,app_packet);
    assert!(outcomes.borrow().is_empty());
    let ledger=&c.incoming_credit_ledger[&app_slot];assert_eq!((ledger.requested(),ledger.advertised,ledger.consumed,ledger.retired),(600,0,0,0));
}

#[test]
fn rbing_fifty_mixed_cell_does_not_apply_to_other_stream_setting() {
    let (mut c, outcomes)=rbing_owned_data_actual_stall(true);c.config.max_chaff_streams=10;
    let ep=QcsdEndpointId(1);c.streams.open(ep,QcsdStreamId(0),QcsdRequestRole::Application,true,16,1_000,50);
    c.poll(Duration::ZERO);c.drain_observations();assert!(outcomes.borrow().is_empty());
    assert_eq!(c.control.incoming[0].remaining,600);assert!(c.control.credit.is_empty() && c.control.claims.is_empty());
}

#[test]
fn rbing_fifty_mixed_cell_shortfall_cannot_satisfy_and_same_owner_drains() {
    let (mut c, outcomes) = rbing_owned_data_actual_stall(true);
    c.config.max_chaff_streams = 50;
    let ep=QcsdEndpointId(1);let app=QcsdStreamId(0);let chaff=QcsdStreamId(80);
    c.streams.open(ep,app,QcsdRequestRole::Application,true,16,1_000,50);
    c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:app,bytes:16},Duration::ZERO);
    c.poll(Duration::ZERO);c.drain_observations();
    let actions:Vec<_>=c.drain_actions().collect();
    let (slot,packet)=actions.iter().find_map(|a| match a {
        QcsdAction::IncreaseReceiveLimit {stream,slot,packet,absolute_limit:50,..}
            if *stream==app=>Some((*slot,*packet)),_=>None,
    }).expect("application cell part");
    let (chaff_limit,owner)=actions.iter().find_map(|a| match a {
        QcsdAction::LeaseParserReceive {stream,absolute_limit,increase:566,owner:Some(owner),..}
            if *stream==chaff=>Some((*absolute_limit,*owner)),_=>None,
    }).expect("chaff cell remainder");
    assert_eq!((owner.slot,owner.packet),(slot,packet));
    assert!(outcomes.borrow().is_empty());
    c.observe(QcsdObservation::ReceiveLimitAdvertised {endpoint:ep,stream:app,absolute_limit:50,slot:Some(slot)},Duration::from_micros(1));
    c.observe(QcsdObservation::ReceiveLimitAdvertised {endpoint:ep,stream:chaff,absolute_limit:chaff_limit,slot:None},Duration::from_micros(2));
    c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:app,bytes:34},Duration::from_micros(3));
    c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:chaff,bytes:565},Duration::from_micros(4));
    let ledger=&c.incoming_credit_ledger[&slot];
    assert_eq!((ledger.advertised,ledger.consumed,ledger.retired,ledger.unresolved()),(600,599,0,1));
    assert!(!c.drain_actions().any(|a|matches!(a,QcsdAction::SlotSatisfied {slot:s,..} if s==slot)));
    c.observe(QcsdObservation::BytesRead {endpoint:ep,stream:chaff,bytes:1},Duration::from_micros(5));
    assert!(c.incoming_credit_ledger.get(&slot).is_none());
    assert!(c.drain_actions().any(|a|matches!(a,QcsdAction::SlotSatisfied {slot:s,..} if s==slot)));
}
