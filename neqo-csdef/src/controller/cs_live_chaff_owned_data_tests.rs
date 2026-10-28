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
