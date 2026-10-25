// Synthetic method-level causal fixtures, never a captured receipt or proof.
use super::*;
use crate::{CsBufloConfig, CsBufloEarlyTermination, CsBufloPaddingMode, CsBufloParameters,
    Packet, QcsdChaffRequestId, QcsdImplementationScope, Resource};

const EP: QcsdEndpointId = QcsdEndpointId(1);
const STREAM: QcsdStreamId = QcsdStreamId(80);
fn role() -> QcsdRequestRole {
    QcsdRequestRole::Chaff { resource_id: 3, request_id: Some(QcsdChaffRequestId(0)) }
}
fn controller() -> QcsdController {
    let defense = CsBuflo::from_parameters(CsBufloParameters {
        schema_version: 1, packet_size: 600, initial_interval_us: 8_192,
        minimum_interval_us: 4_096, maximum_interval_us: 32_768,
        initial_adaptation_boundary_bytes: 16_384, quiet_time_us: 2_000_000,
        outgoing_padding_mode: CsBufloPaddingMode::Payload,
        incoming_padding_mode: CsBufloPaddingMode::Payload, timing_sample_limit: 1_000,
        jitter_denominator: 100, jitter_max_numerator: 200,
        early_termination: CsBufloEarlyTermination::Local, max_events: 1_000_000,
        implementation_scope: QcsdImplementationScope::ClientOnlyQuic, paper_equivalent: false,
    }, 12410680401537876901);
    QcsdController::with_defense(QcsdConfig {
        max_udp_payload_size: 1_200,
        defense: DefenseConfig::CsBuflo(CsBufloConfig { parameters: "synthetic-method-fixture-only.json".into() }),
        ..QcsdConfig::default()
    }, Some(ResourceManifest { resources: vec![Resource {
        id: 3, url: "https://s.alicdn.com/@img/imgextra/i4/O1CN013JX4r629MmzCY1tkw_!!6000000008054-2-tps-85-85.png".into(),
        kind: "Image".into(), content_length: Some(1_798), data_length: 1_798,
        chaff_priority: true, known_valid: true, depends_on: vec![], headers: vec![],
    }] }), Box::new(defense)).expect("real CS reducer, no files or network")
}
fn open(c: &mut QcsdController) {
    c.observe(QcsdObservation::EndpointReady { endpoint: EP, origin: "https://s.alicdn.com".into(),
        max_udp_payload_size: 1_200 }, Duration::ZERO);
    c.observe(QcsdObservation::StreamOpened { endpoint: EP, stream: STREAM,
        role: role(), expected_response_length: Some(1_798) }, Duration::ZERO);
    c.drain_actions().for_each(drop);
    c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 16 }, Duration::from_micros(1));
    c.drain_actions().for_each(drop);
}
fn ack(c: &mut QcsdController) {
    c.observe(QcsdObservation::StreamDataAcknowledged { endpoint: EP, stream: STREAM, role: role(),
        offset: 0, bytes: 100, fin: true }, Duration::from_micros(2));
}
fn headers(c: &mut QcsdController) {
    c.observe(QcsdObservation::HeaderProgress { endpoint: EP, stream: STREAM,
        min_remaining: 74, awaiting_data_frame: false }, Duration::from_micros(3));
}
fn assert74(actions: &[QcsdAction]) {
    assert!(matches!(actions, [QcsdAction::LeaseParserReceive {
        endpoint: EP, stream: STREAM, absolute_limit: 90, increase: 74, owner: None,
    }]));
}

#[test]
fn ali_live_headers_controller_actual74_path_never_mints_scheduled_credit() {
    let mut c = controller();
    c.enable_cs_live_chaff_header_progress().unwrap();
    open(&mut c); ack(&mut c); headers(&mut c);
    let actions: Vec<_> = c.drain_actions().collect();
    assert74(&actions);
    assert_eq!((c.scheduled_incoming_requested_bytes, c.scheduled_incoming_advertised_bytes,
        c.scheduled_incoming_consumed_bytes, c.scheduled_incoming_retired_bytes), (0,0,0,0));
    let ranges = &c.parser_lease_ranges[&(EP, STREAM)];
    assert_eq!((ranges[0].start, ranges[0].end, ranges[0].owner,
        ranges[0].reservation_debited, ranges[0].unowned), (16,90,None,false,true));
    c.observe(QcsdObservation::ReceiveLimitAdvertised { endpoint: EP, stream: STREAM,
        absolute_limit: 90, slot: None }, Duration::from_micros(4));
    c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 74 }, Duration::from_micros(5));
    c.observe(QcsdObservation::ResponseHeaders { endpoint: EP, stream: STREAM, frame_bytes: 90,
        status: Some(499), content_length: Some(0) }, Duration::from_micros(6));
    assert_eq!(c.streams.aggregate_capacity().chaff_incoming, 0);
    assert!(c.streams.release_stream(EP, STREAM, 501).is_none());
    assert_eq!(c.scheduled_incoming_consumed_bytes, 0, "slotless parsing cannot heal any cell");
    assert!(c.parser_lease_ranges.get(&(EP, STREAM)).is_none_or(Vec::is_empty));
}

#[test]
fn ali_live_headers_controller_delayed_fin_ack_retries_only_retained_current_debt() {
    let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap(); open(&mut c);
    headers(&mut c);
    assert!(c.next_action().is_none());
    c.observe(QcsdObservation::StreamDataAcknowledged { endpoint: EP, stream: STREAM, role: role(),
        offset: 0, bytes: 100, fin: true }, Duration::from_micros(4));
    assert74(&c.drain_actions().collect::<Vec<_>>());
    c.observe(QcsdObservation::HeaderProgress { endpoint: EP, stream: STREAM,
        min_remaining: 74, awaiting_data_frame: false }, Duration::from_micros(5));
    assert!(c.next_action().is_none(), "pending parser permission cannot be duplicated");
}

#[test]
fn ali_live_headers_controller_owned_claim_and_terminal_state_refuse() {
    for case in 0..4 {
        let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap(); open(&mut c); ack(&mut c);
        match case {
            0 => {
                let packet = Packet::new(Duration::ZERO, Direction::Incoming, 600).unwrap();
                c.control.claims.push(PendingClaim { reservation_debited: false,
                    slot: QcsdSlotId(83), packet, endpoint: EP, stream: STREAM, remaining: 501 });
            }
            1 => {
                c.observe(QcsdObservation::ApplicationComplete, Duration::from_micros(2));
                c.flush_defense_observations();
                assert!(c.defense.is_incoming_complete(), "true CS incoming stop, not onLoad alone");
            }
            2 => { c.scheduler.remove_endpoint(EP); }
            _ => { c.streams.mark_receive_unavailable(EP, STREAM); }
        }
        headers(&mut c);
        assert!(c.next_action().is_none(), "case{case} cannot acquire a new lease");
    }
}

#[test]
fn ali_live_headers_controller_unstarted_fixed_cs_opt_in_only() {
    let mut default = controller();
    assert!(!default.streams.cs_live_chaff_headers_enabled());
    default.enable_cs_live_chaff_header_progress().unwrap();
    assert!(default.enable_cs_live_chaff_header_progress().is_err());
    for case in 0..8 {
        let mut c = controller();
        match case {
            0 => c.config.control_interval_us = 5_001,
            1 => c.config.initial_max_stream_data = 17,
            2 => c.config.max_stream_data_excess = 1_001,
            3 => c.config.max_udp_payload_size = 1_450,
            4 => c.config.max_chaff_streams = 6,
            5 => c.config.defense = DefenseConfig::None,
            6 => c.config.drop_unsatisfied_events = true,
            _ => open(&mut c),
        }
        assert!(c.enable_cs_live_chaff_header_progress().is_err(), "case{case} changes authority");
        assert!(!c.streams.cs_live_chaff_headers_enabled());
    }
}

#[test]
fn ali_live_headers_controller_recorded600_173_427_stays_strict_negative() {
    for enabled in [false, true] {
        let mut c = controller();
        if enabled { c.enable_cs_live_chaff_header_progress().unwrap(); }
        let slot = QcsdSlotId(83);
        let packet = Packet::new(Duration::from_micros(332_251), Direction::Incoming, 600).unwrap();
        // Full original terminal arithmetic; no invented success or old-row repair.
        c.pending_slots.insert(slot, packet);
        c.incoming_credit_ledger.insert(slot, IncomingCreditLedger {
            packet, endpoint: Some(EP), multiple_endpoints: false, advertised: 600,
            local_realization_emitted: true, consumed: 99 + 74, retired: 0,
        });
        c.scheduled_incoming_requested_bytes = 600;
        c.scheduled_incoming_advertised_bytes = 600;
        c.scheduled_incoming_consumed_bytes = 173;
        c.record_retired_credit(slot, 427, Duration::from_micros(333_966));
        assert!(matches!(c.next_action(), Some(QcsdAction::SlotMissed {
            slot: actual, reason: MissedSlotReason::ReceiveCreditRetired, ..
        }) if actual == slot));
        assert!(c.incoming_terminal_process_witness(slot).is_none());
        assert_eq!(c.scheduled_incoming_retired_bytes, 427);
        assert!(!c.incoming_slot_is_locally_realized(slot));
        assert!(c.next_action().is_none());
    }
}

// Only new config-to-controller and exact typed witness boundaries are selected
// by the ali_cs_activation_ filter; the original eleven+one method results stand.
#[test]
fn ali_cs_activation_controller_resolved_flag_is_default_off_and_one_shot() {
    let mut c = controller();
    assert_eq!(c.configure_cs_live_chaff_header_progress().unwrap(), false);
    assert!(!c.streams.cs_live_chaff_headers_enabled());
    c.config.cs_live_chaff_header_progress = true;
    assert_eq!(c.configure_cs_live_chaff_header_progress().unwrap(), true);
    assert!(c.streams.cs_live_chaff_headers_enabled());
    assert!(c.configure_cs_live_chaff_header_progress().is_err());
}

#[test]
fn ali_cs_activation_controller_rechecks_changed_config_and_existing_work() {
    let mut changed = controller();
    changed.config.cs_live_chaff_header_progress = true;
    changed.config.control_interval_us = 5_001;
    assert!(changed.configure_cs_live_chaff_header_progress().is_err());
    assert!(!changed.streams.cs_live_chaff_headers_enabled());
    let mut started = controller();
    open(&mut started);
    started.config.cs_live_chaff_header_progress = true;
    assert!(started.configure_cs_live_chaff_header_progress().is_err());
    assert!(!started.streams.cs_live_chaff_headers_enabled());
}

#[test]
fn ali_cs_activation_witness_requires_the_actual_unowned_74_action_identity() {
    let mut c = controller();
    assert!(c.cs_live_chaff_header_lease_witness(EP, STREAM, 90, 74).is_none());
    c.config.cs_live_chaff_header_progress = true;
    assert!(c.configure_cs_live_chaff_header_progress().unwrap());
    open(&mut c); ack(&mut c); headers(&mut c);
    assert74(&c.drain_actions().collect::<Vec<_>>());
    assert_eq!(c.cs_live_chaff_header_lease_witness(EP, STREAM, 90, 74), Some((74, 1_798)));
    assert!(c.cs_live_chaff_header_lease_witness(EP, STREAM, 91, 74).is_none());
    assert!(c.cs_live_chaff_header_lease_witness(EP, STREAM, 90, 75).is_none());
    assert!(c.cs_live_chaff_header_lease_witness(QcsdEndpointId(2), STREAM, 90, 74).is_none());
    assert!(c.cs_live_chaff_header_lease_witness(EP, QcsdStreamId(84), 90, 74).is_none());
    assert_eq!((c.scheduled_incoming_requested_bytes, c.scheduled_incoming_advertised_bytes,
        c.scheduled_incoming_consumed_bytes, c.scheduled_incoming_retired_bytes), (0,0,0,0));
}

// Native147 synthetic causal fixtures. No captured outcome is re-labelled.
// Unlike open(), this models the actual pristine BLOCKED16/no-HeaderProgress.
fn cs_bootstrap_pristine(c: &mut QcsdController) {
    c.observe(QcsdObservation::EndpointReady { endpoint: EP,
        origin: "https://s.alicdn.com".into(), max_udp_payload_size: 1_200 }, Duration::ZERO);
    c.observe(QcsdObservation::StreamOpened { endpoint: EP, stream: STREAM,
        role: role(), expected_response_length: Some(1_798) }, Duration::ZERO);
    c.drain_actions().for_each(drop);
}
fn cs_bootstrap_ack(c: &mut QcsdController, offset: u64, bytes: u64, fin: bool) {
    c.observe(QcsdObservation::StreamDataAcknowledged { endpoint: EP, stream: STREAM,
        role: role(), offset, bytes, fin }, Duration::from_micros(2));
}
fn cs_bootstrap_blocked(c: &mut QcsdController, blocked_at: u64) {
    c.observe(QcsdObservation::StreamDataBlocked { endpoint: EP, stream: STREAM, blocked_at },
        Duration::from_micros(3));
}
fn cs_bootstrap_assert_permission(c: &mut QcsdController) {
    let actions: Vec<_> = c.drain_actions().collect();
    assert!(matches!(actions.as_slice(), [QcsdAction::LeaseParserReceive {
        endpoint: EP, stream: STREAM, absolute_limit: 1_000, increase: 984, owner: None,
    }]), "pristine ACK/BLOCKED16 requires one bounded raw-prefix permission: {actions:?}");
    assert_eq!((c.scheduled_incoming_requested_bytes, c.scheduled_incoming_advertised_bytes,
        c.scheduled_incoming_consumed_bytes, c.scheduled_incoming_retired_bytes), (0,0,0,0));
    assert!(c.pending_slots.is_empty());
    assert_eq!(c.streams.aggregate_capacity().chaff_incoming, 0,
        "an unobserved response is not scheduled capacity");
    let ranges = &c.parser_lease_ranges[&(EP,STREAM)];
    assert_eq!((ranges.len(), ranges[0].start, ranges[0].end, ranges[0].owner,
        ranges[0].reservation_debited, ranges[0].unowned), (1,16,1_000,None,false,true));
    assert!(c.cs_live_chaff_header_lease_witness(EP, STREAM, 1_000, 984).is_none(),
        "the new prefix must never masquerade as old observed HeaderProgress debt");
    if let crate::stream::ReceiveState::ReceivingHeaders { parser_lease_capacity, parser_lease_used, .. } =
        c.streams.get_mut(EP, STREAM).unwrap().receive {
        assert_eq!((parser_lease_capacity,parser_lease_used), (1_000,984));
    } else { panic!("no HEADERS have been parsed"); }
}

#[test]
fn cs_header_bootstrap_blocked16_ack_first_without_header_progress() {
    let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap();
    cs_bootstrap_pristine(&mut c);
    cs_bootstrap_ack(&mut c,0,79,true);
    assert!(c.next_action().is_none(), "ACK alone grants no prefix");
    cs_bootstrap_blocked(&mut c,16);
    cs_bootstrap_assert_permission(&mut c);
    cs_bootstrap_blocked(&mut c,16); cs_bootstrap_ack(&mut c,0,79,true);
    assert!(c.next_action().is_none(), "duplicate or old BLOCKED/ACK cannot grant twice");
}

#[test]
fn cs_header_bootstrap_blocked_first_delayed_contiguous_fin_ack() {
    let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap();
    cs_bootstrap_pristine(&mut c); cs_bootstrap_blocked(&mut c,16);
    assert!(c.next_action().is_none());
    cs_bootstrap_ack(&mut c,39,40,true);
    assert!(c.next_action().is_none(), "a hole is not a complete request");
    cs_bootstrap_ack(&mut c,0,39,false);
    cs_bootstrap_assert_permission(&mut c);
}

#[test]
fn cs_header_bootstrap_does_not_qualify_unknown_changed_or_non200_response() {
    for (status,length) in [(None,None),(Some(499),Some(0)),(Some(200),None),
        (Some(200),Some(1_799))] {
        let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap();
        cs_bootstrap_pristine(&mut c); cs_bootstrap_ack(&mut c,0,79,true);
        cs_bootstrap_blocked(&mut c,16); cs_bootstrap_assert_permission(&mut c);
        c.observe(QcsdObservation::ReceiveLimitAdvertised { endpoint: EP, stream: STREAM,
            absolute_limit: 1_000, slot: None }, Duration::from_micros(4));
        c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 80 }, Duration::from_micros(5));
        c.observe(QcsdObservation::ResponseHeaders { endpoint: EP, stream: STREAM,
            frame_bytes: 80, status, content_length: length }, Duration::from_micros(6));
        assert_eq!(c.streams.aggregate_capacity().chaff_incoming,0);
        assert!(c.streams.release_stream(EP,STREAM,600).is_none());
        assert_eq!(c.scheduled_incoming_advertised_bytes,0);
    }
}

#[test]
fn cs_header_bootstrap_real200_body_spill_never_heals_a_scheduled600_cell() {
    let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap();
    cs_bootstrap_pristine(&mut c); cs_bootstrap_ack(&mut c,0,79,true);
    cs_bootstrap_blocked(&mut c,16); cs_bootstrap_assert_permission(&mut c);
    c.observe(QcsdObservation::ReceiveLimitAdvertised { endpoint: EP, stream: STREAM,
        absolute_limit: 1_000, slot: None }, Duration::from_micros(4));
    c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 80 }, Duration::from_micros(5));
    c.observe(QcsdObservation::ResponseHeaders { endpoint: EP, stream: STREAM,
        frame_bytes: 80, status: Some(200), content_length: Some(1_798) }, Duration::from_micros(6));
    assert!(c.streams.aggregate_capacity().chaff_incoming > 0,
        "only matching live 200 HEADERS unlock the original body allocator");
    c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 3 }, Duration::from_micros(7));
    c.observe(QcsdObservation::DataFrame { endpoint: EP, stream: STREAM,
        frame_header_bytes: 3, data_bytes: 1_798 }, Duration::from_micros(8));
    c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 917 }, Duration::from_micros(9));
    assert_eq!(c.streams.consumed(EP,STREAM),Some(1_000));
    assert_eq!((c.scheduled_incoming_requested_bytes,c.scheduled_incoming_advertised_bytes,
        c.scheduled_incoming_consumed_bytes,c.scheduled_incoming_retired_bytes), (0,0,0,0));
    assert!(c.pending_slots.is_empty());
    assert!(c.parser_lease_ranges.get(&(EP,STREAM)).is_none_or(Vec::is_empty));
}

#[test]
fn cs_header_bootstrap_negative_role_ack_state_budget_and_slot_ownership() {
    for case in 0..13 {
        let mut c = controller();
        if case != 0 { c.enable_cs_live_chaff_header_progress().unwrap(); }
        cs_bootstrap_pristine(&mut c);
        if case == 5 {
            // The controller deliberately ignores a chaff StreamOpened length.
            // Use the original public registry constructor before any ACK to
            // exercise its independent prepared-extent guard without a private setter.
            c.streams.open(EP, STREAM, role(), true, 16, 1_000, 1_799);
        }
        if case != 1 { cs_bootstrap_ack(&mut c,0,79,true); }
        match case {
            0 | 1 => {},
            2 => {
                c.observe(QcsdObservation::ApplicationComplete, Duration::from_micros(2));
                c.flush_defense_observations();
                assert!(c.defense.is_incoming_complete(), "true CS incoming stop, not onLoad alone");
            },
            3 => { c.scheduler.remove_endpoint(EP); },
            4 => { c.streams.mark_receive_unavailable(EP,STREAM); },
            5 => {}, // Independent public-constructor extent mismatch above.
            6 => { c.streams.get_mut(EP,STREAM).unwrap().role = QcsdRequestRole::Application; },
            7 => { c.streams.get_mut(EP,STREAM).unwrap().role = QcsdRequestRole::Chaff { resource_id: 3, request_id: None }; },
            8 => { c.observe(QcsdObservation::BytesRead { endpoint: EP, stream: STREAM, bytes: 1 }, Duration::from_micros(2)); },
            9 => {
                let packet = Packet::new(Duration::ZERO,Direction::Incoming,600).unwrap();
                c.control.claims.push(PendingClaim { reservation_debited: false,
                    slot: QcsdSlotId(83), packet, endpoint: EP, stream: STREAM, remaining: 600 });
            },
            10 => {
                if let crate::stream::ReceiveState::ReceivingHeaders { parser_lease_capacity, .. } =
                    &mut c.streams.get_mut(EP,STREAM).unwrap().receive { *parser_lease_capacity = 999; }
            },
            11 => {
                if let crate::stream::ReceiveState::ReceivingHeaders { parser_lease_used, .. } =
                    &mut c.streams.get_mut(EP,STREAM).unwrap().receive { *parser_lease_used = 1; }
            },
            _ => { cs_bootstrap_ack(&mut c,79,1,true); },
        }
        c.drain_actions().for_each(drop);
        cs_bootstrap_blocked(&mut c,16);
        assert!(c.next_action().is_none(), "case{case} cannot obtain a pristine prefix");
        assert_eq!(c.scheduled_incoming_advertised_bytes,0);
    }
    let mut c = controller(); c.enable_cs_live_chaff_header_progress().unwrap();
    cs_bootstrap_pristine(&mut c); cs_bootstrap_ack(&mut c,0,79,true);
    cs_bootstrap_blocked(&mut c,17);
    assert!(c.next_action().is_none(),"wrong frontier is not retained evidence");
}
