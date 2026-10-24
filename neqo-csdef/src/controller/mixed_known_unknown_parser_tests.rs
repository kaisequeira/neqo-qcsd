// Synthetic controller/receive/ledger fixtures, not network or Raw evidence.
// The candidate expectation is the only baseline/candidate test-file difference.
const MIXED_PARSER_FAIRNESS_CANDIDATE: bool = true;

// Real production slot materialization, shared by collect_due_events. The
// preassigned arm models the old remainder helper explicitly and must remain
// outside a pristine-cell fairness change. No scheduler credit is fabricated.
fn mixed_parser_stage_full_cell(
    c: &mut QcsdController,
    endpoint: QcsdEndpointId,
    slot: QcsdSlotId,
    target: Duration,
    preassigned: bool,
) {
    assert!(!c.incoming_credit_ledger.contains_key(&slot));
    let packet = Packet::new(target, Direction::Incoming, 1_200).unwrap();
    c.materialize_incoming(slot, packet, target);
    assert!(c.incoming_credit_ledger[&slot].endpoint.is_none());
    assert!(c.incoming_slot_is_untouched(
        c.control.incoming.iter().find(|pending| pending.slot == slot).unwrap()
    ));
    if preassigned {
        c.incoming_credit_ledger.get_mut(&slot).unwrap().assign_endpoint(endpoint);
    }
    let untouched = c.incoming_slot_is_untouched(
        c.control.incoming.iter().find(|pending| pending.slot == slot).unwrap()
    );
    assert_eq!(untouched, !preassigned);
    eprintln!("MIXED_PARSER_SLOT_DISCRIMINATOR slot={slot:?} real_materialize=true preassigned={preassigned} untouched={untouched}");
    c.process_incoming(u64::try_from(target.as_micros()).unwrap(), target);
    c.retry_pending_parser_leases();
}


fn mixed_parser_with_known_application()
-> (QcsdController, QcsdEndpointId, QcsdStreamId, QcsdStreamId, QcsdStreamId) {
    let (mut c, ep, app, cover) = native118_parser_with_known_cover();
    let known = QcsdStreamId(8);
    c.observe(QcsdObservation::StreamOpened {
        endpoint: ep, stream: known, role: QcsdRequestRole::Application,
        expected_response_length: Some(10_000),
    }, Duration::ZERO);
    c.observe(QcsdObservation::ResponseHeaders {
        endpoint: ep, stream: known, frame_bytes: 16,
        status: Some(200), content_length: Some(10_000),
    }, Duration::ZERO);
    c.streams.get_mut(ep, known).unwrap().receive =
        crate::stream::ReceiveState::ReceivingData {
            advertised_limit: 1_000, requested_limit: 1_000, known_limit: 10_016,
            reservation_capacity: 1_000, reservation_available: 1_000,
            consumed: 1_000, payload_floor: 10_000, framing_bytes: 16,
            parser_lease_capacity: 1_000, parser_lease_used: 0,
            parser_lease_exhausted: false, last_parser_lease_boundary: None,
            pending_parser_boundary: None, data_length: 984,
        };
    c.drain_actions().for_each(drop);
    assert_eq!(c.buflo_retained_parser_room(ep, app), 1_200);
    (c, ep, app, known, cover)
}

fn mixed_parser_advertise(c: &mut QcsdController, actions: &[QcsdAction], at: Duration) {
    for action in actions {
        match *action {
            QcsdAction::IncreaseReceiveLimit { endpoint, stream, absolute_limit, slot, .. } =>
                c.observe(QcsdObservation::ReceiveLimitAdvertised {
                    endpoint, stream, absolute_limit, slot: Some(slot),
                }, at),
            QcsdAction::LeaseParserReceive { endpoint, stream, absolute_limit, .. } =>
                c.observe(QcsdObservation::ReceiveLimitAdvertised {
                    endpoint, stream, absolute_limit, slot: None,
                }, at),
            _ => {}
        }
    }
}

#[test]
fn mixed_parser_competing_known_application_four_fresh_cells() {
    let (mut c, ep, app, known, _) = mixed_parser_with_known_application();
    let mut probes = 0;
    for index in 0..4_u64 {
        let slot = QcsdSlotId(160_000 + index);
        let target = Duration::from_micros((index + 1) * 64_000);
        let app_before = c.streams.consumed(ep, app).unwrap();
        let known_before = c.streams.receive_limits(ep, known).unwrap().1;
        mixed_parser_stage_full_cell(&mut c, ep, slot, target, false);
        let actions: Vec<_> = c.drain_actions().collect();
        let parser: Vec<_> = actions.iter().filter_map(|action| match action {
            QcsdAction::LeaseParserReceive {
                stream, absolute_limit, increase, owner: Some(owner), ..
            } if *stream == app && owner.slot == slot => Some((*absolute_limit, *increase)),
            _ => None,
        }).collect();
        let known_grants: Vec<_> = actions.iter().filter_map(|action| match action {
            QcsdAction::IncreaseReceiveLimit { stream, absolute_limit, slot: owner, .. }
                if *stream == known && *owner == slot => Some(*absolute_limit - known_before),
            _ => None,
        }).collect();
        let fair_turn = MIXED_PARSER_FAIRNESS_CANDIDATE && index % 2 == 0;
        assert_eq!(parser.len(), usize::from(fair_turn));
        assert_eq!(known_grants, vec![if fair_turn { 1_072 } else { 1_200 }]);
        if fair_turn { assert_eq!(parser[0].1, 128); probes += 1; }
        assert!(c.control.claims.is_empty());
        assert_eq!(c.incoming_credit_ledger[&slot].consumed, 0);
        let at = target + Duration::from_micros(1);
        mixed_parser_advertise(&mut c, &actions, at);
        assert_eq!(c.incoming_credit_ledger[&slot].advertised, 1_200);
        assert_eq!(c.incoming_credit_ledger[&slot].consumed, 0);
        if fair_turn {
            // First read includes the old one-byte unowned suffix. Later probes
            // begin exactly at their owned boundary; neither declaration is data.
            let read_bytes = parser[0].0 - app_before;
            c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: app, bytes: 3 }, at);
            c.observe(QcsdObservation::DataFrame {
                endpoint: ep, stream: app, frame_header_bytes: 3,
                data_bytes: read_bytes - 3,
            }, at);
            c.observe(QcsdObservation::BytesRead {
                endpoint: ep, stream: app, bytes: read_bytes - 3,
            }, at);
            c.observe(QcsdObservation::HeaderProgress {
                endpoint: ep, stream: app, min_remaining: 1, awaiting_data_frame: true,
            }, at);
            c.observe(QcsdObservation::StreamDataBlocked {
                endpoint: ep, stream: app, blocked_at: parser[0].0,
            }, at);
        }
        c.observe(QcsdObservation::BytesRead {
            endpoint: ep, stream: known, bytes: known_grants[0],
        }, at);
        assert!(c.drain_actions().any(|action| matches!(action,
            QcsdAction::SlotSatisfied { slot: owner, .. } if owner == slot)));
        assert!(!c.incoming_credit_ledger.contains_key(&slot));
        assert_eq!(c.buflo_retained_parser_room(ep, app), 1_200);
        assert_eq!(c.buflo_retained_parser_demands[&(ep, app)].boundary,
            Some(c.streams.consumed(ep, app).unwrap()));
        assert_eq!(c.scheduled_incoming_consumed_bytes, (index + 1) * 1_200);
        assert_eq!(c.scheduled_incoming_retired_bytes, 0);
        assert!(c.buflo_fin_permission_releases.is_empty());
    }
    assert_eq!(probes, if MIXED_PARSER_FAIRNESS_CANDIDATE { 2 } else { 0 });
}

#[test]
fn mixed_parser_without_known_application_control() {
    let (mut c, ep, app, cover) = native118_parser_with_known_cover();
    let slot = QcsdSlotId(160_010);
    mixed_parser_stage_full_cell(&mut c, ep, slot, Duration::from_micros(64_000), false);
    let actions: Vec<_> = c.drain_actions().collect();
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::LeaseParserReceive { stream, increase: 128, owner: Some(owner), .. }
            if *stream == app && owner.slot == slot)));
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::IncreaseReceiveLimit { stream, absolute_limit: 2_072, slot: owner, .. }
            if *stream == cover && *owner == slot)));
    assert_eq!(c.incoming_credit_ledger[&slot].consumed, 0);
    assert_eq!(c.scheduled_incoming_retired_bytes, 0);

    // A preassigned owner keeps the old exact-first allocation. This negative
    // prevents the candidate from widening its pristine-cell authority merely
    // to make the fresh-cell progress test pass.
    let (mut pre, ep, app, known, _) = mixed_parser_with_known_application();
    let pre_slot = QcsdSlotId(160_013);
    mixed_parser_stage_full_cell(&mut pre, ep, pre_slot, Duration::from_micros(64_000), true);
    let pre_actions: Vec<_> = pre.drain_actions().collect();
    assert!(!pre_actions.iter().any(|action| matches!(action,
        QcsdAction::LeaseParserReceive { stream, owner: Some(owner), .. }
            if *stream == app && owner.slot == pre_slot)));
    assert!(pre_actions.iter().any(|action| matches!(action,
        QcsdAction::IncreaseReceiveLimit { stream, absolute_limit: 2_200, slot: owner, .. }
            if *stream == known && *owner == pre_slot)));
    assert_eq!(pre.incoming_credit_ledger[&pre_slot].consumed, 0);
    assert_eq!(pre.scheduled_incoming_retired_bytes, 0);
}

#[test]
fn mixed_parser_incomplete_cell_rolls_back_exact_ownership() {
    let (mut c, ep, app, cover) = native118_parser_with_known_cover();
    if let crate::stream::ReceiveState::ReceivingData { known_limit, .. } =
        &mut c.streams.get_mut(ep, cover).unwrap().receive { *known_limit = 2_000; }
    let before_app = c.streams.get_mut(ep, app).unwrap().receive.clone();
    let before_cover = c.streams.get_mut(ep, cover).unwrap().receive.clone();
    let before_ranges = c.advertised_incoming_credit.clone();
    let cursor = c.buflo_incoming_stream_cursor.clone();
    let slot = QcsdSlotId(160_011);
    mixed_parser_stage_full_cell(&mut c, ep, slot, Duration::from_micros(64_000), false);
    let actions: Vec<_> = c.drain_actions().collect();
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::SlotMissed { slot: owner, reason: MissedSlotReason::InsufficientIncomingCapacity, .. }
            if *owner == slot)));
    assert!(!actions.iter().any(|action| matches!(action,
        QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::LeaseParserReceive { .. })));
    assert_eq!(c.streams.get_mut(ep, app).unwrap().receive, before_app);
    assert_eq!(c.streams.get_mut(ep, cover).unwrap().receive, before_cover);
    assert_eq!(c.advertised_incoming_credit, before_ranges);
    assert_eq!(c.buflo_incoming_stream_cursor, cursor);
    assert!(c.control.claims.is_empty());
    assert_eq!(c.scheduled_incoming_requested_bytes, 1_200);
    assert_eq!(c.scheduled_incoming_advertised_bytes, 0);
    assert_eq!(c.scheduled_incoming_consumed_bytes, 0);
    // No permission was advertised. The failed scheduled declaration is still
    // retired honestly by fail_incoming_slots; it is neither received data nor
    // an unresolved owner that may be silently reused by a later cell.
    assert_eq!(c.scheduled_incoming_retired_bytes, 1_200);
    assert_eq!(c.defense_diagnostics().scheduled_incoming_unresolved_bytes, 0);
    assert!(!c.incoming_credit_ledger.contains_key(&slot));
    assert!(!actions.iter().any(|action| matches!(action,
        QcsdAction::SlotSatisfied { slot: owner, .. } if *owner == slot)));
    c.flush_defense_observations();
    assert_eq!(c.terminal_failure(), Some("BuFLO exact cell realization failed"));
}

#[test]
fn mixed_parser_permission_is_not_data_and_reset_stays_missed() {
    let (mut c, ep, app, cover) = native118_parser_with_known_cover();
    let slot = QcsdSlotId(160_012);
    let at = Duration::from_micros(64_001);
    mixed_parser_stage_full_cell(&mut c, ep, slot, Duration::from_micros(64_000), false);
    let actions: Vec<_> = c.drain_actions().collect();
    mixed_parser_advertise(&mut c, &actions, at);
    assert_eq!(c.incoming_credit_ledger[&slot].advertised, 1_200);
    c.observe(QcsdObservation::DataFrame {
        endpoint: ep, stream: app, frame_header_bytes: 3, data_bytes: 126,
    }, at);
    assert_eq!(c.incoming_credit_ledger[&slot].consumed, 0);
    assert!(!c.drain_actions().any(|action| matches!(action,
        QcsdAction::SlotSatisfied { slot: owner, .. } if owner == slot)));
    c.observe(QcsdObservation::StreamFinished {
        endpoint: ep, stream: app, finish: QcsdStreamFinish::Reset,
    }, at);
    c.observe(QcsdObservation::BytesRead { endpoint: ep, stream: cover, bytes: 1_072 }, at);
    let actions: Vec<_> = c.drain_actions().collect();
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::SlotMissed { slot: owner, reason: MissedSlotReason::ReceiveCreditRetired, .. }
            if *owner == slot)));
    assert!(!actions.iter().any(|action| matches!(action,
        QcsdAction::SlotSatisfied { slot: owner, .. } if *owner == slot)));
    assert_eq!(c.scheduled_incoming_consumed_bytes, 1_072);
    assert_eq!(c.scheduled_incoming_retired_bytes, 128);
    assert_eq!(c.defense_diagnostics().scheduled_incoming_unresolved_bytes, 0);
    assert!(c.buflo_fin_permission_releases.is_empty());
    c.flush_defense_observations();
    assert_eq!(c.terminal_failure(), Some("BuFLO exact cell realization failed"));
}

// Keep the focused production gate on the existing cap, physical window,
// bound-primary fairness and unopted-mode contracts. These original tests are
// called unchanged in the same cfg(test) module; this adds no production path.
#[test]
fn mixed_parser_original_cap_window_primary_and_unopted_regressions() {
    buflo_native113_unknown_parser1200_cap_is_independent_of_ordinary_known_rights();
    buflo_native113_finite_capacity_rollback_and_original_window_remain_strict();
    buflo_bound_primary_whole_cell_fair_turn_keeps_one_byte_and_guard_contracts();
    buflo_stream_fairness_preserves_unopted_and_twenty_ms_order();
}
