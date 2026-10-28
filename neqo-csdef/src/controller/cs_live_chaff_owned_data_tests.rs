// Synthetic slot-lifecycle reproduction; this is not a live capture or receipt.
use super::*;
use crate::{
    CsBufloConfig, CsBufloEarlyTermination, CsBufloPaddingMode, CsBufloParameters,
    QcsdChaffRequestId, QcsdImplementationScope, Resource, stream::ReceiveState,
};

const ENDPOINT: QcsdEndpointId = QcsdEndpointId(1);
const STREAMS: [QcsdStreamId; 5] = [
    QcsdStreamId(80), QcsdStreamId(84), QcsdStreamId(88), QcsdStreamId(92), QcsdStreamId(96),
];

fn controller() -> QcsdController {
    let defense = CsBuflo::from_parameters(CsBufloParameters {
        schema_version: 1,
        packet_size: 600,
        initial_interval_us: 8_192,
        minimum_interval_us: 4_096,
        maximum_interval_us: 32_768,
        initial_adaptation_boundary_bytes: 16_384,
        quiet_time_us: 2_000_000,
        outgoing_padding_mode: CsBufloPaddingMode::Payload,
        incoming_padding_mode: CsBufloPaddingMode::Payload,
        timing_sample_limit: 1_000,
        jitter_denominator: 100,
        jitter_max_numerator: 200,
        early_termination: CsBufloEarlyTermination::Local,
        max_events: 1_000_000,
        implementation_scope: QcsdImplementationScope::ClientOnlyQuic,
        paper_equivalent: false,
    }, 15_305_592_820_452_181_456);
    let mut result = QcsdController::with_defense(QcsdConfig {
        max_udp_payload_size: 1_200,
        defense: DefenseConfig::CsBuflo(CsBufloConfig {
            parameters: "synthetic-rbing-parser-frontier-only.json".into(),
        }),
        ..QcsdConfig::default()
    }, Some(ResourceManifest { resources: vec![Resource {
        id: 4,
        url: "https://r.bing.com/rp/5RUBu5dEYIDzWQtuZRVAHjBjuyc.br.js".into(),
        kind: "Other".into(),
        content_length: Some(564_884),
        data_length: 564_884,
        chaff_priority: true,
        known_valid: true,
        depends_on: vec![],
        headers: vec![],
    }] }), Box::new(defense)).unwrap();
    result.enable_cs_live_chaff_header_progress().unwrap();
    result.observe(QcsdObservation::EndpointReady {
        endpoint: ENDPOINT,
        origin: "https://r.bing.com".into(),
        max_udp_payload_size: 1_200,
    }, Duration::ZERO);
    result.drain_actions().for_each(drop);
    for (index, stream) in STREAMS.into_iter().enumerate() {
        let role = QcsdRequestRole::Chaff {
            resource_id: 4,
            request_id: Some(QcsdChaffRequestId(u64::try_from(index).unwrap())),
        };
        result.streams.open(ENDPOINT, stream, role, true, 16, 1_000, 564_884);
        result.streams.record_chaff_request_acknowledgment(
            ENDPOINT, stream, role, 0, 73, true,
        );
        let (header_bytes, data_bytes) = [(927, 70), (927, 70), (928, 69), (928, 69), (926, 71)][index];
        let state = result.streams.get_mut(ENDPOINT, stream).unwrap();
        state.response_headers(header_bytes, Some(200), None);
        state.receive = ReceiveState::ReceivingData {
            advertised_limit: 1_000,
            requested_limit: 1_000,
            known_limit: 564_884 + header_bytes + 3,
            reservation_capacity: 1_000,
            reservation_available: 1_000,
            consumed: 1_000,
            payload_floor: 564_884,
            framing_bytes: header_bytes + 3,
            parser_lease_capacity: 1_000,
            parser_lease_used: 984,
            parser_lease_exhausted: false,
            last_parser_lease_boundary: None,
            pending_parser_boundary: Some(1_000),
            data_length: data_bytes,
        };
    }
    result
}

fn due_incoming(controller: &mut QcsdController, at: Duration) -> QcsdSlotId {
    controller.collect_due_events(at);
    controller.drain_observations();
    let incoming = controller.control.incoming.first().unwrap();
    assert_eq!(incoming.packet.length(), 600);
    incoming.slot
}

#[test]
fn cs_owned_chaff_five_blocked_streams_need_real_due_owner_and_physical_credit() {
    let mut controller = controller();
    assert_eq!(controller.streams.aggregate_capacity().chaff_incoming, 0);
    controller.retry_pending_parser_leases();
    assert!(controller.drain_actions().all(|action| !matches!(
        action, QcsdAction::LeaseParserReceive { owner: Some(_), .. }
    )));
    assert_eq!(controller.scheduled_incoming_requested_bytes, 0);
    let at = Duration::from_micros(10_000);
    let slot = due_incoming(&mut controller, at);
    controller.process_incoming(10_000, at);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert!(matches!(&actions[..], [QcsdAction::LeaseParserReceive {
        endpoint: ENDPOINT, stream: QcsdStreamId(80), absolute_limit: 1_600,
        increase: 600, owner: Some(owner),
    }] if owner.slot == slot && owner.packet.length() == 600));
    assert!(!controller.incoming_slot_is_locally_realized(slot));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 0);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream: STREAMS[0], absolute_limit: 1_600, slot: None,
    }, Duration::from_micros(10_001));
    assert!(controller.incoming_slot_is_locally_realized(slot));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    controller.observe(QcsdObservation::DataFrame {
        endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 3, data_bytes: 597,
    }, Duration::from_micros(10_002));
    controller.observe(QcsdObservation::BytesRead {
        endpoint: ENDPOINT, stream: STREAMS[0], bytes: 600,
    }, Duration::from_micros(10_003));
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 600);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert!(controller.defense.terminal_failure().is_none());
}

#[test]
fn cs_owned_chaff_invalid_ack_or_status_and_expired_slot_still_refuse() {
    for case in 0..3 {
        let mut controller = controller();
        for stream in STREAMS {
            match case {
                0 => controller.streams.get_mut(ENDPOINT, stream).unwrap().status = Some(499),
                1 => {
                    let role = controller.streams.get_mut(ENDPOINT, stream).unwrap().role;
                    controller.streams.record_chaff_request_acknowledgment(
                        ENDPOINT, stream, role, 73, 1, true,
                    );
                }
                _ => {}
            }
        }
        let at = Duration::from_micros(10_000);
        let slot = due_incoming(&mut controller, at);
        let elapsed = if case == 2 { Duration::from_micros(15_000) } else { at };
        controller.process_incoming(10_000, elapsed);
        controller.retry_pending_parser_leases();
        let actions: Vec<_> = controller.drain_actions().collect();
        assert!(actions.iter().any(|action| matches!(action,
            QcsdAction::SlotMissed { slot: missed, .. } if *missed == slot)));
        assert!(!actions.iter().any(|action| matches!(action,
            QcsdAction::LeaseParserReceive { owner: Some(_), .. })));
        assert_eq!(controller.scheduled_incoming_advertised_bytes, 0);
        assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    }
}

#[test]
fn cs_owned_chaff_exact_tail_and_parser_remainder_keep_one_600_byte_owner() {
    let mut controller = controller();
    if let ReceiveState::ReceivingData { data_length, pending_parser_boundary, .. } =
        &mut controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive
    {
        *data_length += 67;
        *pending_parser_boundary = None;
    }
    let at = Duration::from_micros(10_000);
    let slot = due_incoming(&mut controller, at);
    controller.process_incoming(10_000, at);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert!(matches!(&actions[..], [
        QcsdAction::IncreaseReceiveLimit {
            stream: QcsdStreamId(80), absolute_limit: 1_067, slot: exact_owner, ..
        },
        QcsdAction::LeaseParserReceive {
            stream: QcsdStreamId(84), absolute_limit: 1_533, increase: 533,
            owner: Some(parser_owner), ..
        },
    ] if *exact_owner == slot && parser_owner.slot == slot
        && parser_owner.packet.length() == 600));
    assert_eq!(controller.scheduled_incoming_requested_bytes, 600);
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 0);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream: STREAMS[0], absolute_limit: 1_067, slot: Some(slot),
    }, Duration::from_micros(10_001));
    assert!(!controller.incoming_slot_is_locally_realized(slot));
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream: STREAMS[1], absolute_limit: 1_533, slot: None,
    }, Duration::from_micros(10_002));
    assert!(controller.incoming_slot_is_locally_realized(slot));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
}


fn one_byte_owned_prefix() -> (QcsdController, QcsdSlotId) {
    let mut controller = controller();
    // Keep the five-stream role/ACK fixture, but focus this lifecycle on one
    // eligible stream. Other streams cannot receive actions in this fixture.
    for stream in &STREAMS[1..] {
        assert!(controller.streams.mark_receive_unavailable(ENDPOINT, *stream));
    }
    let at = Duration::from_micros(10_000);
    let old_slot = due_incoming(&mut controller, at);
    controller.process_incoming(10_000, at);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert!(matches!(&actions[..], [QcsdAction::LeaseParserReceive {
        stream: QcsdStreamId(80), absolute_limit: 1_600, increase: 600,
        owner: Some(owner), ..
    }] if owner.slot == old_slot));
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream: STREAMS[0], absolute_limit: 1_600, slot: None,
    }, Duration::from_micros(10_001));
    controller.observe(QcsdObservation::DataFrame {
        endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 2, data_bytes: 597,
    }, Duration::from_micros(10_002));
    controller.observe(QcsdObservation::BytesRead {
        endpoint: ENDPOINT, stream: STREAMS[0], bytes: 599,
    }, Duration::from_micros(10_003));
    controller.observe(QcsdObservation::HeaderProgress {
        endpoint: ENDPOINT, stream: STREAMS[0], min_remaining: 1, awaiting_data_frame: true,
    }, Duration::from_micros(10_004));
    controller.retry_pending_parser_leases();
    assert!(controller.drain_actions().all(|action| !matches!(action,
        QcsdAction::LeaseParserReceive { .. })));
    assert_eq!(controller.incoming_credit_ledger[&old_slot].consumed, 599);
    assert_eq!(controller.incoming_credit_ledger[&old_slot].unresolved(), 1);
    assert_eq!(controller.streams.receive_limits(ENDPOINT, STREAMS[0]), Some((1_600, 1_600)));
    assert_eq!(controller.streams.consumed(ENDPOINT, STREAMS[0]), Some(1_599));
    (controller, old_slot)
}

fn next_real_incoming(controller: &mut QcsdController) -> (QcsdSlotId, Duration) {
    for _ in 0..16 {
        let at = controller.defense.next_event_at().unwrap();
        controller.collect_due_events(at);
        controller.drain_observations();
        if let Some(incoming) = controller.control.incoming.first() {
            assert_eq!(incoming.packet.length(), 600);
            return (incoming.slot, at);
        }
    }
    panic!("the unchanged CS schedule must produce another incoming cell");
}

#[test]
fn cs_owned_chaff_one_byte_old_owner_is_not_reused_by_fresh_cell() {
    let (mut controller, old_slot) = one_byte_owned_prefix();
    let old_ledger = controller.incoming_credit_ledger[&old_slot];
    let old_range = controller.parser_lease_ranges[&(ENDPOINT, STREAMS[0])][0];
    assert_eq!((old_range.start, old_range.end), (1_599, 1_600));
    let (new_slot, at) = next_real_incoming(&mut controller);
    assert_ne!(new_slot, old_slot);
    controller.process_incoming(u64::try_from(at.as_micros()).unwrap(), at);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert!(matches!(&actions[..], [QcsdAction::LeaseParserReceive {
        endpoint: ENDPOINT, stream: QcsdStreamId(80), absolute_limit: 2_200,
        increase: 600, owner: Some(owner),
    }] if owner.slot == new_slot && owner.packet.length() == 600));
    assert_eq!(controller.incoming_credit_ledger[&old_slot], old_ledger);
    let ranges = &controller.parser_lease_ranges[&(ENDPOINT, STREAMS[0])];
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[0], old_range);
    assert_eq!((ranges[1].start, ranges[1].end), (1_600, 2_200));
    assert_eq!(ranges[1].owner.unwrap().slot, new_slot);
    assert!(!ranges[1].reservation_debited);
    assert_eq!(controller.scheduled_incoming_requested_bytes, 1_200);
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 599);
    assert!(!controller.incoming_slot_is_locally_realized(new_slot));
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream: STREAMS[0], absolute_limit: 2_200, slot: None,
    }, at);
    assert!(controller.incoming_slot_is_locally_realized(new_slot));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 1_200);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 599);
    // The first new frame-header byte still belongs to the old cell.
    controller.observe(QcsdObservation::BytesRead {
        endpoint: ENDPOINT, stream: STREAMS[0], bytes: 1,
    }, at + Duration::from_micros(1));
    assert!(controller.control.terminal_incoming.contains(&old_slot));
    assert!(!controller.incoming_credit_ledger.contains_key(&old_slot));
    assert!(controller.drain_actions().any(|action| matches!(action,
        QcsdAction::SlotSatisfied { slot, .. } if slot == old_slot)));
    assert_eq!(controller.incoming_credit_ledger[&new_slot].consumed, 0);
    controller.observe(QcsdObservation::DataFrame {
        endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 2, data_bytes: 599,
    }, at + Duration::from_micros(2));
    controller.observe(QcsdObservation::BytesRead {
        endpoint: ENDPOINT, stream: STREAMS[0], bytes: 600,
    }, at + Duration::from_micros(3));
    assert!(controller.control.terminal_incoming.contains(&new_slot));
    assert!(!controller.incoming_credit_ledger.contains_key(&new_slot));
    assert!(controller.drain_actions().any(|action| matches!(action,
        QcsdAction::SlotSatisfied { slot, .. } if slot == new_slot)));
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 1_200);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert!(controller.defense.terminal_failure().is_none());
}

#[test]
fn cs_owned_chaff_parser_prefix_cannot_reuse_expired_fresh_owner() {
    let (mut controller, old_slot) = one_byte_owned_prefix();
    let old_ledger = controller.incoming_credit_ledger[&old_slot];
    let (new_slot, at) = next_real_incoming(&mut controller);
    let expired = at + controller.exact_incoming_release_window();
    controller.process_incoming(u64::try_from(at.as_micros()).unwrap(), expired);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::SlotMissed { slot, .. } if *slot == new_slot)));
    assert!(!actions.iter().any(|action| matches!(action,
        QcsdAction::LeaseParserReceive { .. })));
    assert_eq!(controller.incoming_credit_ledger[&old_slot], old_ledger);
    assert_eq!(controller.streams.receive_limits(ENDPOINT, STREAMS[0]), Some((1_600, 1_600)));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 599);
}

fn final_body_controller() -> QcsdController {
    let mut controller = controller();
    // Give the five retained stream identities their genuine manager-issued
    // request IDs before installing the recorded parser frontier below.
    let manager = controller.chaff.as_mut().unwrap();
    let planned = manager.preprovision_to_limit(
        0, 5, &[(ENDPOINT, "https://r.bing.com".into())],
    );
    assert_eq!(planned.len(), STREAMS.len());
    for (index, request) in planned.into_iter().enumerate() {
        assert_eq!(request.request_id, QcsdChaffRequestId(u64::try_from(index).unwrap()));
        manager.request_opened(Some(request.request_id));
    }
    assert_eq!(manager.pending_count(), 0);
    controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive =
        ReceiveState::ReceivingData {
            advertised_limit: 568_903,
            requested_limit: 568_903,
            known_limit: 569_057,
            reservation_capacity: 1_000,
            reservation_available: 1_000,
            consumed: 568_903,
            payload_floor: 564_884,
            framing_bytes: 4_173,
            parser_lease_capacity: 1_000,
            parser_lease_used: 984,
            parser_lease_exhausted: false,
            last_parser_lease_boundary: Some(568_303),
            pending_parser_boundary: Some(568_903),
            data_length: 564_730,
        };
    // Stream 88 remains a live alternative for the intervening due cell.
    // Streams 92/96 cannot accidentally supply the expected split capacity.
    for stream in &STREAMS[3..] {
        assert!(controller.streams.mark_receive_unavailable(ENDPOINT, *stream));
    }
    controller
}

fn assert_owned_chaff_lease(
    actions: &[QcsdAction],
    stream: QcsdStreamId,
    absolute_limit: u64,
    increase: u64,
    slot: QcsdSlotId,
) {
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::LeaseParserReceive {
            endpoint: ENDPOINT, stream: candidate, absolute_limit: limit,
            increase: amount, owner: Some(owner),
        } if *candidate == stream && *limit == absolute_limit && *amount == increase
            && owner.slot == slot && owner.packet.length() == 600)));
}

fn advertise_owned_chaff_lease(
    controller: &mut QcsdController,
    stream: QcsdStreamId,
    absolute_limit: u64,
    at: Duration,
) {
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream, absolute_limit, slot: None,
    }, at);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained final-frame, three-cell and replacement lifecycle is one accounting oracle"
)]
fn cs_owned_chaff_final_body_split_waits_for_observed_data_then_fin_and_replacement() {
    let mut controller = final_body_controller();
    assert_eq!(controller.streams.aggregate_capacity().chaff_incoming, 0);
    let at = Duration::from_micros(10_000);
    let first = due_incoming(&mut controller, at);
    controller.process_incoming(10_000, at);
    controller.retry_pending_parser_leases();
    let mut actions: Vec<_> = controller.drain_actions().collect();
    assert_eq!(actions.len(), 2);
    assert_owned_chaff_lease(&actions, STREAMS[0], 569_057, 154, first);
    assert_owned_chaff_lease(&actions, STREAMS[1], 1_446, 446, first);
    assert!(!controller.incoming_slot_is_locally_realized(first));
    advertise_owned_chaff_lease(&mut controller, STREAMS[0], 569_057, at);
    assert!(!controller.incoming_slot_is_locally_realized(first));
    advertise_owned_chaff_lease(&mut controller, STREAMS[1], 1_446, at);
    assert!(controller.incoming_slot_is_locally_realized(first));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);

    // The actual next allocation preceded stream 80's final DATA header.
    // Do not invent future exact bytes: another real 600-byte cell goes to 88.
    // Match poll(): deliver the actual physical-advertisement signals before
    // asking the reactive defense for its next timer; they clear in_flight.
    controller.drain_observations();
    let (intervening, next_at) = next_real_incoming(&mut controller);
    assert_eq!(controller.streams.aggregate_capacity().chaff_incoming, 0);
    controller.process_incoming(u64::try_from(next_at.as_micros()).unwrap(), next_at);
    controller.retry_pending_parser_leases();
    let intervening_actions: Vec<_> = controller.drain_actions().collect();
    assert_eq!(intervening_actions.len(), 1);
    assert_owned_chaff_lease(&intervening_actions, STREAMS[2], 1_600, 600, intervening);
    advertise_owned_chaff_lease(&mut controller, STREAMS[2], 1_600, next_at);
    assert!(controller.incoming_slot_is_locally_realized(intervening));
    actions.extend(intervening_actions);
    let read_at = next_at + Duration::from_micros(1);
    for observation in [
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[2], frame_header_bytes: 3, data_bytes: 597,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[2], bytes: 600 },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[0], bytes: 3 },
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 3, data_bytes: 154,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[0], bytes: 151 },
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[1], frame_header_bytes: 3, data_bytes: 443,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[1], bytes: 446 },
        QcsdObservation::HeaderProgress {
            endpoint: ENDPOINT, stream: STREAMS[1], min_remaining: 1, awaiting_data_frame: true,
        },
    ] {
        controller.observe(observation, read_at);
    }
    assert_eq!(controller.streams.aggregate_capacity().chaff_incoming, 3);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 1_200);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert!(controller.control.terminal_incoming.contains(&first));
    assert!(controller.control.terminal_incoming.contains(&intervening));
    actions.extend(controller.drain_actions());

    controller.drain_observations();
    let (last, last_at) = next_real_incoming(&mut controller);
    controller.process_incoming(u64::try_from(last_at.as_micros()).unwrap(), last_at);
    controller.retry_pending_parser_leases();
    let last_actions: Vec<_> = controller.drain_actions().collect();
    assert_eq!(last_actions.len(), 2);
    assert!(last_actions.iter().any(|action| matches!(action,
        QcsdAction::IncreaseReceiveLimit {
            endpoint: ENDPOINT, stream: QcsdStreamId(80), absolute_limit: 569_060, slot, ..
        } if *slot == last)));
    assert_owned_chaff_lease(&last_actions, STREAMS[1], 2_043, 597, last);
    controller.observe(QcsdObservation::ReceiveLimitAdvertised {
        endpoint: ENDPOINT, stream: STREAMS[0], absolute_limit: 569_060, slot: Some(last),
    }, last_at);
    assert!(!controller.incoming_slot_is_locally_realized(last));
    advertise_owned_chaff_lease(&mut controller, STREAMS[1], 2_043, last_at);
    assert!(controller.incoming_slot_is_locally_realized(last));
    actions.extend(last_actions);
    controller.observe(QcsdObservation::BytesRead {
        endpoint: ENDPOINT, stream: STREAMS[0], bytes: 3,
    }, last_at + Duration::from_micros(1));
    controller.observe(QcsdObservation::HeaderProgress {
        endpoint: ENDPOINT, stream: STREAMS[0], min_remaining: 1, awaiting_data_frame: true,
    }, last_at + Duration::from_micros(2));
    let fin_actions: Vec<_> = controller.drain_actions().collect();
    assert!(fin_actions.iter().any(|action| matches!(action,
        QcsdAction::LeaseParserReceive {
            endpoint: ENDPOINT, stream: QcsdStreamId(80), absolute_limit: 569_076,
            increase: 16, owner: None,
        })));
    assert!(matches!(controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive,
        ReceiveState::ReceivingData { parser_lease_used: 1_000, data_length: 564_884, .. }));
    advertise_owned_chaff_lease(&mut controller, STREAMS[0], 569_076,
        last_at + Duration::from_micros(3));
    actions.extend(fin_actions);
    for observation in [
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[0], bytes: 2 },
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 2, data_bytes: 0,
        },
        QcsdObservation::PeerFinRead {
            endpoint: ENDPOINT, stream: STREAMS[0], final_size: 569_062,
            encoded_receive_limit: 569_076, manual_receive_limit: 569_076,
            bytes_received: 569_062, bytes_read: 569_062, buffered_bytes: 0,
        },
        QcsdObservation::StreamFinished {
            endpoint: ENDPOINT, stream: STREAMS[0], finish: crate::QcsdStreamFinish::Fin,
        },
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[1], frame_header_bytes: 3, data_bytes: 594,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[1], bytes: 597 },
    ] {
        controller.observe(observation, last_at + Duration::from_micros(4));
    }
    controller.request_chaff_if_needed(false);
    actions.extend(controller.drain_actions());
    assert!(controller.streams.get_mut(ENDPOINT, STREAMS[0]).is_none());
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::RequestChaff { endpoint: ENDPOINT, resource, request_id }
            if resource.id == 4 && *request_id == QcsdChaffRequestId(5))));
    for slot in [first, intervening, last] {
        assert!(actions.iter().any(|action| matches!(action,
            QcsdAction::SlotSatisfied { slot: satisfied, .. } if *satisfied == slot)));
        assert!(!controller.incoming_credit_ledger.contains_key(&slot));
    }
    assert!(actions.iter().all(|action| !matches!(action, QcsdAction::SlotMissed { .. })));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 1_800);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 1_800);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert!(controller.defense.terminal_failure().is_none());
}

#[test]
fn cs_owned_chaff_final_body_split_without_other_capacity_rolls_back() {
    let mut controller = final_body_controller();
    for stream in &STREAMS[1..] {
        assert!(controller.streams.mark_receive_unavailable(ENDPOINT, *stream));
    }
    let before = controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive.clone();
    let at = Duration::from_micros(10_000);
    let slot = due_incoming(&mut controller, at);
    controller.process_incoming(10_000, at);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert!(actions.iter().any(|action| matches!(action,
        QcsdAction::SlotMissed {
            slot: missed, reason: crate::MissedSlotReason::InsufficientIncomingCapacity, ..
        } if *missed == slot)));
    assert!(actions.iter().all(|action| !matches!(action,
        QcsdAction::IncreaseReceiveLimit { .. } | QcsdAction::LeaseParserReceive { .. })));
    assert!(controller.control.claims.is_empty());
    assert!(controller.parser_lease_ranges.is_empty());
    assert_eq!(controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive, before);
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 0);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    // The refused unadvertised cell still terminalizes its full requested
    // budget as retired. No byte was granted, consumed, or silently waived.
    assert_eq!(controller.scheduled_incoming_retired_bytes, 600);
    controller.drain_observations();
    assert!(controller.defense.terminal_failure().is_some());
}

fn three_body_bytes_short_owned_prefix() -> (QcsdController, QcsdSlotId, Duration) {
    let mut controller = final_body_controller();
    // Recorded Native163 stream 80: the prepared body is 564884, but the
    // consumed DATA extent is only 564881. The next three RAW bytes are not
    // a promise that a new DATA frame and its three BODY bytes can complete.
    controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive =
        ReceiveState::ReceivingData {
            advertised_limit: 569_053,
            requested_limit: 569_053,
            known_limit: 569_056,
            reservation_capacity: 1_000,
            reservation_available: 1_000,
            consumed: 569_053,
            payload_floor: 564_884,
            framing_bytes: 4_172,
            parser_lease_capacity: 1_000,
            parser_lease_used: 984,
            parser_lease_exhausted: false,
            last_parser_lease_boundary: Some(568_582),
            pending_parser_boundary: Some(569_053),
            data_length: 564_881,
        };
    let at = Duration::from_micros(10_000);
    let slot = due_incoming(&mut controller, at);
    controller.process_incoming(10_000, at);
    controller.retry_pending_parser_leases();
    let actions: Vec<_> = controller.drain_actions().collect();
    assert_eq!(actions.len(), 2);
    assert_owned_chaff_lease(&actions, STREAMS[0], 569_056, 3, slot);
    assert_owned_chaff_lease(&actions, STREAMS[1], 1_597, 597, slot);
    // The framing follow-up cannot precede the original physical ownership.
    controller.retry_pending_parser_leases();
    assert!(controller.drain_actions().all(|a| !matches!(a,
        QcsdAction::LeaseParserReceive { owner: None, .. })));
    advertise_owned_chaff_lease(&mut controller, STREAMS[0], 569_056, at);
    assert!(!controller.incoming_slot_is_locally_realized(slot));
    advertise_owned_chaff_lease(&mut controller, STREAMS[1], 1_597, at);
    assert!(controller.incoming_slot_is_locally_realized(slot));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    controller.drain_actions().for_each(drop);
    (controller, slot, at)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one real controller oracle preserves the old three-byte owner through framing, FIN and replacement"
)]
fn cs_owned_three_body_bytes_short_uses_remaining_unowned_framing_without_forgiving_owner() {
    let (mut controller, slot, at) = three_body_bytes_short_owned_prefix();
    let original = controller.incoming_credit_ledger[&slot];
    assert_eq!(controller.streams.aggregate_capacity().chaff_incoming, 0);
    controller.retry_pending_parser_leases();
    let mut actions: Vec<_> = controller.drain_actions().collect();
    // This assertion must fail on unmodified Native163. It has cleared the
    // boundary after assigning three owned bytes and emits no follow-up.
    assert!(matches!(&actions[..], [QcsdAction::LeaseParserReceive {
        endpoint: ENDPOINT, stream: QcsdStreamId(80), absolute_limit: 569_072,
        increase: 16, owner: None,
    }]));
    assert_eq!(controller.incoming_credit_ledger[&slot], original);
    assert_eq!(controller.scheduled_incoming_requested_bytes, 600);
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 0);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert_eq!(controller.streams.aggregate_capacity().chaff_incoming, 0);
    let ranges = &controller.parser_lease_ranges[&(ENDPOINT, STREAMS[0])];
    assert_eq!(ranges.len(), 2);
    assert_eq!((ranges[0].start, ranges[0].end), (569_053, 569_056));
    assert!(ranges[0].advertised && !ranges[0].unowned && !ranges[0].reservation_debited);
    assert_eq!(ranges[0].owner.unwrap().slot, slot);
    assert_eq!((ranges[1].start, ranges[1].end), (569_056, 569_072));
    assert!(ranges[1].unowned && !ranges[1].advertised && ranges[1].owner.is_none());
    assert!(matches!(controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive,
        ReceiveState::ReceivingData {
            parser_lease_capacity: 1_000, parser_lease_used: 1_000,
            parser_lease_exhausted: true, data_length: 564_881, ..
        }));
    advertise_owned_chaff_lease(&mut controller, STREAMS[0], 569_072,
        at + Duration::from_micros(1));
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    controller.retry_pending_parser_leases();
    assert!(controller.drain_actions().all(|a| !matches!(a,
        QcsdAction::LeaseParserReceive { .. })));
    // A genuine small DATA frame uses two framing bytes and three body bytes.
    // The old owner consumes exactly its first three raw bytes; only the next
    // two body bytes and the final empty DATA/FIN use the unowned allowance.
    for observation in [
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[0], bytes: 2 },
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 2, data_bytes: 3,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[0], bytes: 3 },
        QcsdObservation::HeaderProgress {
            endpoint: ENDPOINT, stream: STREAMS[0], min_remaining: 1, awaiting_data_frame: true,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[0], bytes: 2 },
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[0], frame_header_bytes: 2, data_bytes: 0,
        },
        QcsdObservation::PeerFinRead {
            endpoint: ENDPOINT, stream: STREAMS[0], final_size: 569_060,
            encoded_receive_limit: 569_072, manual_receive_limit: 569_072,
            bytes_received: 569_060, bytes_read: 569_060, buffered_bytes: 0,
        },
        QcsdObservation::StreamFinished {
            endpoint: ENDPOINT, stream: STREAMS[0], finish: crate::QcsdStreamFinish::Fin,
        },
    ] {
        controller.observe(observation, at + Duration::from_micros(2));
    }
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 3);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert_eq!(controller.incoming_credit_ledger[&slot].unresolved(), 597);
    for observation in [
        QcsdObservation::DataFrame {
            endpoint: ENDPOINT, stream: STREAMS[1], frame_header_bytes: 3, data_bytes: 594,
        },
        QcsdObservation::BytesRead { endpoint: ENDPOINT, stream: STREAMS[1], bytes: 597 },
    ] {
        controller.observe(observation, at + Duration::from_micros(3));
    }
    controller.request_chaff_if_needed(false);
    actions.extend(controller.drain_actions());
    assert!(controller.streams.get_mut(ENDPOINT, STREAMS[0]).is_none());
    assert!(actions.iter().any(|a| matches!(a,
        QcsdAction::RequestChaff { endpoint: ENDPOINT, resource, request_id }
            if resource.id == 4 && *request_id == QcsdChaffRequestId(5))));
    assert!(actions.iter().any(|a| matches!(a,
        QcsdAction::SlotSatisfied { slot: satisfied, .. } if *satisfied == slot)));
    assert!(!controller.incoming_credit_ledger.contains_key(&slot));
    assert_eq!(controller.scheduled_incoming_requested_bytes, 600);
    assert_eq!(controller.scheduled_incoming_advertised_bytes, 600);
    assert_eq!(controller.scheduled_incoming_consumed_bytes, 600);
    assert_eq!(controller.scheduled_incoming_retired_bytes, 0);
    assert!(actions.iter().all(|a| !matches!(a, QcsdAction::SlotMissed { .. })));
    assert!(controller.defense.terminal_failure().is_none());
}

#[test]
fn cs_owned_three_byte_tail_framing_preserves_all_original_scope_and_budget_guards() {
    for case in 0..12 {
        let (mut controller, slot, _) = three_body_bytes_short_owned_prefix();
        match case {
            0 => controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().status = Some(499),
            1 => {
                let role = controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().role;
                controller.streams.record_chaff_request_acknowledgment(
                    ENDPOINT, STREAMS[0], role, 73, 1, true,
                );
            }
            2 => controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap()
                .response_headers(0, Some(200), Some(564_884)),
            3 | 4 | 5 | 6 => {
                if let ReceiveState::ReceivingData {
                    parser_lease_used, parser_lease_exhausted,
                    last_parser_lease_boundary, data_length, ..
                } = &mut controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive {
                    match case {
                        3 => { *parser_lease_used = 1_000; *parser_lease_exhausted = true; }
                        4 => *parser_lease_used = 985,
                        5 => *last_parser_lease_boundary = None,
                        6 => *data_length = 564_885,
                        _ => unreachable!(),
                    }
                }
            }
            7 => controller.parser_lease_ranges.get_mut(&(ENDPOINT, STREAMS[0])).unwrap()[0]
                .advertised = false,
            8 => controller.parser_lease_ranges.get_mut(&(ENDPOINT, STREAMS[0])).unwrap()[0]
                .owner = None,
            9 => { controller.pending_slots.remove(&slot); }
            10 => { controller.incoming_credit_ledger.remove(&slot); }
            11 => { assert!(controller.streams.mark_receive_unavailable(ENDPOINT, STREAMS[0])); }
            _ => unreachable!(),
        }
        let before = controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive.clone();
        let counters = (controller.scheduled_incoming_requested_bytes,
            controller.scheduled_incoming_advertised_bytes,
            controller.scheduled_incoming_consumed_bytes,
            controller.scheduled_incoming_retired_bytes);
        controller.retry_pending_parser_leases();
        assert!(controller.drain_actions().all(|a| !matches!(a,
            QcsdAction::LeaseParserReceive { .. })), "scope case {case}");
        assert_eq!(controller.streams.get_mut(ENDPOINT, STREAMS[0]).unwrap().receive, before);
        assert_eq!((controller.scheduled_incoming_requested_bytes,
            controller.scheduled_incoming_advertised_bytes,
            controller.scheduled_incoming_consumed_bytes,
            controller.scheduled_incoming_retired_bytes), counters);
    }
}
