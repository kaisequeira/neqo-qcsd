// Synthetic reproduction of the retained Rbing parser frontier, not a receipt.
use super::*;
use crate::QcsdChaffRequestId;

const ENDPOINT: QcsdEndpointId = QcsdEndpointId(1);
const STREAM: QcsdStreamId = QcsdStreamId(80);
const BODY_BYTES: u64 = 564_884;

fn role() -> QcsdRequestRole {
    QcsdRequestRole::Chaff {
        resource_id: 4,
        request_id: Some(QcsdChaffRequestId(0)),
    }
}

#[test]
fn cs_owned_chaff_final_body_extent_caps_only_private_permission() {
    let mut registry = frontier();
    registry.get_mut(ENDPOINT, STREAM).unwrap().receive = ReceiveState::ReceivingData {
        advertised_limit: 568_903,
        requested_limit: 568_903,
        known_limit: 569_057,
        reservation_capacity: 1_000,
        reservation_available: 1_000,
        consumed: 568_903,
        payload_floor: BODY_BYTES,
        framing_bytes: 4_173,
        parser_lease_capacity: 1_000,
        parser_lease_used: 984,
        parser_lease_exhausted: false,
        last_parser_lease_boundary: Some(568_303),
        pending_parser_boundary: Some(568_903),
        data_length: 564_730,
    };
    assert_eq!(registry.aggregate_capacity().chaff_incoming, 0);
    assert!(registry.allocation_opportunities(ENDPOINT, DefenseMode::ChaffAndShape).is_empty());
    assert_eq!(registry.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 154);
    let candidates = registry.cs_live_chaff_owned_data_opportunities(ENDPOINT);
    assert_eq!(candidates.len(), 1);
    assert_eq!((candidates[0].stream, candidates[0].exact, candidates[0].claimable),
        (STREAM, 0, 0));
    let before = registry.get_mut(ENDPOINT, STREAM).unwrap().receive.clone();
    for too_large in [155, 600, 601, 1_200] {
        assert!(registry.cs_live_chaff_owned_data_continuation(ENDPOINT, STREAM, too_large)
            .is_none());
        assert_eq!(registry.get_mut(ENDPOINT, STREAM).unwrap().receive, before);
    }
    let lease = registry.cs_live_chaff_owned_data_continuation(ENDPOINT, STREAM, 154)
        .expect("only this short suffix can belong to the current cell");
    assert_eq!((lease.absolute_limit, lease.increase, lease.scheduled), (569_057, 154, true));
    let state = registry.get_mut(ENDPOINT, STREAM).unwrap();
    assert!(matches!(state.receive, ReceiveState::ReceivingData {
        parser_lease_used: 984, reservation_available: 1_000, ..
    }));
    state.receive.advertised(569_057);
    state.receive.bytes_read(3);
    state.receive.data_frame(3, 154);
    state.receive.bytes_read(151);
    assert_eq!(registry.aggregate_capacity().chaff_incoming, 3);
    assert_eq!(registry.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 0);
    assert!(registry.cs_live_chaff_owned_data_opportunities(ENDPOINT).is_empty());
    let release = registry.release_stream(ENDPOINT, STREAM, 600).unwrap();
    assert_eq!((release.absolute_limit, release.increase), (569_060, 3));
}

fn frontier() -> StreamRegistry {
    let mut registry = StreamRegistry::default();
    assert!(registry.enable_cs_live_chaff_headers());
    registry.open(ENDPOINT, STREAM, role(), true, 16, 1_000, BODY_BYTES);
    registry.record_chaff_request_acknowledgment(ENDPOINT, STREAM, role(), 0, 73, true);
    let state = registry.get_mut(ENDPOINT, STREAM).unwrap();
    state.response_headers(927, Some(200), None);
    // The actual response had 927 HEADERS bytes, a three-byte DATA header and
    // 70 DATA bytes. It then requested the next frame at raw offset 1,000.
    state.receive = ReceiveState::ReceivingData {
        advertised_limit: 1_000,
        requested_limit: 1_000,
        known_limit: BODY_BYTES + 930,
        reservation_capacity: 1_000,
        reservation_available: 1_000,
        consumed: 1_000,
        payload_floor: BODY_BYTES,
        framing_bytes: 930,
        parser_lease_capacity: 1_000,
        parser_lease_used: 984,
        parser_lease_exhausted: false,
        last_parser_lease_boundary: None,
        pending_parser_boundary: Some(1_000),
        data_length: 70,
    };
    registry
}

#[test]
fn cs_owned_chaff_missing_length_never_exposes_prepared_forecast() {
    let registry = frontier();
    assert_eq!(registry.aggregate_capacity().chaff_incoming, 0);
    assert!(registry
        .allocation_opportunities(ENDPOINT, DefenseMode::ChaffAndShape)
        .is_empty());
    assert_eq!(
        registry.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600),
        600
    );
}

#[test]
fn cs_owned_chaff_only_decoded_data_extent_becomes_exact_capacity() {
    let mut registry = frontier();
    registry.get_mut(ENDPOINT, STREAM).unwrap().receive.data_frame(3, 600);
    assert_eq!(registry.aggregate_capacity().chaff_incoming, 603);
    let opportunities = registry.allocation_opportunities(ENDPOINT, DefenseMode::ChaffAndShape);
    assert_eq!((opportunities[0].exact, opportunities[0].claimable), (603, 0));
    assert_eq!(registry.claim_stream(ENDPOINT, STREAM, 600), 0);
    let release = registry.release_stream(ENDPOINT, STREAM, BODY_BYTES).unwrap();
    assert_eq!((release.absolute_limit, release.increase), (1_603, 603));
    assert_eq!(registry.aggregate_capacity().chaff_incoming, 0);
    assert!(registry.release_stream(ENDPOINT, STREAM, 1).is_none());
}

#[test]
fn cs_owned_chaff_due_quantum_preserves_budget_and_cannot_repeat() {
    let mut registry = frontier();
    let before = registry.get_mut(ENDPOINT, STREAM).unwrap().receive.clone();
    let lease = registry
        .cs_live_chaff_owned_data_continuation(ENDPOINT, STREAM, 600)
        .unwrap();
    assert_eq!((lease.absolute_limit, lease.increase, lease.scheduled), (1_600, 600, true));
    let after = registry.get_mut(ENDPOINT, STREAM).unwrap().receive.clone();
    if let (
        ReceiveState::ReceivingData {
            parser_lease_used: old_used,
            reservation_available: old_available,
            known_limit: old_known,
            ..
        },
        ReceiveState::ReceivingData {
            parser_lease_used: new_used,
            reservation_available: new_available,
            known_limit: new_known,
            ..
        },
    ) = (before, after)
    {
        assert_eq!((new_used, new_available, new_known), (old_used, old_available, old_known));
    } else {
        panic!("the live DATA state must remain controlled");
    }
    assert!(registry
        .cs_live_chaff_owned_data_continuation(ENDPOINT, STREAM, 600)
        .is_none());
    assert!(registry.cancel_parser_lease(ENDPOINT, STREAM, 1_600, 600, false));
    assert_eq!(registry.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 600);
}

#[test]
fn cs_owned_chaff_current_response_ack_boundary_and_quantum_are_required() {
    for case in 0..13 {
        let mut registry = frontier();
        let state = registry.get_mut(ENDPOINT, STREAM).unwrap();
        match case {
            0 => state.role = QcsdRequestRole::Application,
            1 => state.receive_actions_available = false,
            2 => state.observed_response_length = ObservedResponseLength::Conflicting,
            3 => state.status = Some(499),
            4 => state.expected_chaff_body_bytes = 0,
            5 => {
                state.observed_response_length = ObservedResponseLength::Final {
                    status: 200,
                    content_length: Some(BODY_BYTES),
                };
            }
            6 => {
                state.role = QcsdRequestRole::Chaff { resource_id: 4, request_id: None };
            }
            7 => {
                if let ReceiveState::ReceivingData { pending_parser_boundary, .. } =
                    &mut state.receive
                {
                    *pending_parser_boundary = None;
                }
            }
            8 => {
                if let ReceiveState::ReceivingData { consumed, .. } = &mut state.receive {
                    *consumed -= 1;
                }
            }
            9 => {
                if let ReceiveState::ReceivingData { requested_limit, .. } = &mut state.receive {
                    *requested_limit += 1;
                }
            }
            10 => {
                state.request_acknowledged_ranges.clear();
                state.request_acknowledged_final_size = None;
            }
            11 => {
                if let ReceiveState::ReceivingData { last_parser_lease_boundary, .. } =
                    &mut state.receive
                {
                    *last_parser_lease_boundary = Some(1_000);
                }
            }
            _ => {
                if let ReceiveState::ReceivingData { data_length, .. } = &mut state.receive {
                    *data_length = BODY_BYTES + 1;
                }
            }
        }
        assert_eq!(registry.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 0,
            "case {case} cannot acquire a due-cell continuation");
    }
    for quantum in [0, 601, 1_200] {
        assert_eq!(frontier().cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, quantum), 0);
    }
    for remaining in [1, 599, 600] {
        // These are remainders of the controller's unchanged 600-byte owner,
        // not new packet sizes or permission without a due slot.
        assert_eq!(frontier().cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, remaining),
            remaining);
    }
    let mut default_off = frontier();
    default_off.cs_live_chaff_headers = false;
    assert_eq!(default_off.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 0);
    let mut missing_ack = frontier();
    missing_ack.record_chaff_request_acknowledgment(ENDPOINT, STREAM, role(), 73, 1, true);
    assert_eq!(missing_ack.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 0);
}


fn recorded_parser_prefix(stream: QcsdStreamId) -> StreamRegistry {
    let (requested, consumed, framing, data, last_boundary, request_id) = match stream {
        QcsdStreamId(80) => (17_460, 17_459, 1_025, 16_434, 16_860, 0),
        QcsdStreamId(84) => (29_800, 29_799, 1_095, 28_704, 29_200, 1),
        _ => panic!("only the two retained current parser prefixes are fixtures"),
    };
    let role = QcsdRequestRole::Chaff {
        resource_id: 4,
        request_id: Some(QcsdChaffRequestId(request_id)),
    };
    let mut registry = StreamRegistry::default();
    assert!(registry.enable_cs_live_chaff_headers());
    registry.open(ENDPOINT, stream, role, true, 16, 1_000, BODY_BYTES);
    // Stream 84's genuine FIN ACK preceded the ACK of the request prefix.
    registry.record_chaff_request_acknowledgment(ENDPOINT, stream, role, 4, 69, true);
    registry.record_chaff_request_acknowledgment(ENDPOINT, stream, role, 0, 4, false);
    let state = registry.get_mut(ENDPOINT, stream).unwrap();
    state.response_headers(framing, Some(200), None);
    state.receive = ReceiveState::ReceivingData {
        advertised_limit: requested,
        requested_limit: requested,
        known_limit: BODY_BYTES + framing,
        reservation_capacity: 1_000,
        reservation_available: 1_000,
        consumed,
        payload_floor: BODY_BYTES,
        framing_bytes: framing,
        parser_lease_capacity: 1_000,
        parser_lease_used: 984,
        parser_lease_exhausted: false,
        last_parser_lease_boundary: Some(last_boundary),
        pending_parser_boundary: Some(consumed),
        data_length: data,
    };
    registry
}

#[test]
fn cs_owned_chaff_recorded_one_byte_prefix_preserves_prior_credit() {
    for (stream, requested, consumed) in [
        (QcsdStreamId(80), 17_460, 17_459),
        (QcsdStreamId(84), 29_800, 29_799),
    ] {
        let mut registry = recorded_parser_prefix(stream);
        assert_eq!(registry.aggregate_capacity().chaff_incoming, 0);
        assert!(registry
            .allocation_opportunities(ENDPOINT, DefenseMode::ChaffAndShape)
            .is_empty(), "prepared 200/None is still not a public forecast");
        let before = registry.get_mut(ENDPOINT, stream).unwrap().receive.clone();
        let lease = registry
            .cs_live_chaff_owned_data_continuation(ENDPOINT, stream, 600)
            .unwrap();
        assert_eq!((lease.absolute_limit, lease.increase, lease.scheduled),
            (requested + 600, 600, true));
        assert_eq!(registry.consumed(ENDPOINT, stream), Some(consumed));
        let mut expected = before.clone();
        if let ReceiveState::ReceivingData {
            requested_limit, last_parser_lease_boundary, pending_parser_boundary, ..
        } = &mut expected {
            *requested_limit += 600;
            *last_parser_lease_boundary = Some(consumed);
            *pending_parser_boundary = None;
        }
        assert_eq!(registry.get_mut(ENDPOINT, stream).unwrap().receive, expected,
            "only fresh requested credit and the boundary marker may change");
        assert!(registry
            .cs_live_chaff_owned_data_continuation(ENDPOINT, stream, 600)
            .is_none(), "the same parser boundary cannot acquire twice");
        assert!(registry.cancel_parser_lease(ENDPOINT, stream, requested + 600, 600, false));
        assert_eq!(registry.receive_limits(ENDPOINT, stream), Some((requested, requested)));
        assert_eq!(registry.consumed(ENDPOINT, stream), Some(consumed));
        assert_eq!(registry.cs_live_chaff_owned_data_capacity(ENDPOINT, stream, 600), 600);
    }
}

#[test]
fn cs_owned_chaff_prefix_refuses_data_inflight_large_tail_and_stale_authority() {
    for case in 0..9 {
        let mut registry = recorded_parser_prefix(STREAM);
        let state = registry.get_mut(ENDPOINT, STREAM).unwrap();
        match case {
            0 => {
                // A decoded but unread 50-byte DATA extent is not a header prefix.
                if let ReceiveState::ReceivingData { data_length, .. } = &mut state.receive {
                    *data_length += 50;
                }
            }
            1 | 2 => {
                if let ReceiveState::ReceivingData {
                    requested_limit, advertised_limit, ..
                } = &mut state.receive {
                    let tail = if case == 1 { 17 } else { 597 };
                    *requested_limit = 17_459 + tail;
                    *advertised_limit = *requested_limit;
                }
            }
            3 => {
                if let ReceiveState::ReceivingData { pending_parser_boundary, .. } =
                    &mut state.receive
                {
                    *pending_parser_boundary = Some(17_458);
                }
            }
            4 => {
                if let ReceiveState::ReceivingData { last_parser_lease_boundary, .. } =
                    &mut state.receive
                {
                    *last_parser_lease_boundary = Some(17_459);
                }
            }
            5 => {
                state.request_acknowledged_ranges.clear();
                state.request_acknowledged_final_size = None;
            }
            6 => state.role = QcsdRequestRole::Application,
            7 => state.observed_response_length = ObservedResponseLength::Conflicting,
            _ => {
                if let ReceiveState::ReceivingData { advertised_limit, .. } = &mut state.receive {
                    *advertised_limit -= 1;
                }
            }
        }
        let before = state.receive.clone();
        assert_eq!(registry.cs_live_chaff_owned_data_capacity(ENDPOINT, STREAM, 600), 0,
            "case {case} is not a current bounded parser prefix");
        assert!(registry
            .cs_live_chaff_owned_data_continuation(ENDPOINT, STREAM, 600)
            .is_none());
        assert_eq!(registry.get_mut(ENDPOINT, STREAM).unwrap().receive, before);
    }
}
