// Source-only method fixtures. These synthetic callbacks are not network proof.
use super::*;
use crate::QcsdChaffRequestId;

const EP: QcsdEndpointId = QcsdEndpointId(1);
const STREAM: QcsdStreamId = QcsdStreamId(80);
fn role() -> QcsdRequestRole {
    QcsdRequestRole::Chaff {
        resource_id: 3,
        request_id: Some(QcsdChaffRequestId(0)),
    }
}
fn fixture(enabled: bool, ack: bool, budget: u64) -> StreamRegistry {
    let mut r = StreamRegistry::default();
    if enabled {
        assert!(r.enable_cs_live_chaff_headers());
    }
    r.open(EP, STREAM, role(), true, 16, budget, 1_798);
    r.get_mut(EP, STREAM).unwrap().receive.bytes_read(16);
    if ack {
        r.record_chaff_request_acknowledgment(EP, STREAM, role(), 0, 100, true);
    }
    r.header_progress(EP, STREAM, 74, false);
    r.retain_aggregate_framing_debt(EP, STREAM, 74, false);
    r
}
fn lease(r: &mut StreamRegistry) -> Option<ParserLease> {
    r.cs_live_chaff_header_lease(EP, STREAM, 74, 1_798)
}

#[test]
fn ali_live_headers_default_retains_original_forecast_counterexample() {
    let mut r = fixture(false, true, 1_000);
    assert_eq!(r.capacity(EP).chaff_incoming, 1_782);
    assert!(
        r.allocation_opportunities(EP, DefenseMode::ChaffAndShape)
            .iter()
            .any(|o| o.stream == STREAM && o.exact == 1_782)
    );
    let grant = r.release_stream(EP, STREAM, 501).unwrap();
    assert_eq!(grant.absolute_limit, 517);
    assert!(
        lease(&mut r).is_none(),
        "default off grants no new framing permission"
    );
    // Recorded Ali arithmetic: app99 + chaff74 = 173; 600 - 173 = 427.
    assert_eq!(600_u64 - (99 + 74), 517 - 90);
}

#[test]
fn ali_live_headers_observed74_is_unowned_and_never_forecast501() {
    let mut r = fixture(true, true, 1_000);
    assert_eq!(r.aggregate_capacity().chaff_incoming, 0);
    assert!(
        r.allocation_opportunities(EP, DefenseMode::ChaffAndShape)
            .is_empty()
    );
    assert!(r.release_stream(EP, STREAM, 501).is_none());
    assert_eq!(r.claim_stream(EP, STREAM, 501), 0);
    let p = lease(&mut r).expect("genuine74 prefix");
    assert_eq!((p.absolute_limit, p.increase, p.scheduled), (90, 74, false));
    if let ReceiveState::ReceivingHeaders {
        parser_lease_used,
        parser_lease_capacity,
        ..
    } = r.get_mut(EP, STREAM).unwrap().receive
    {
        assert_eq!((parser_lease_used, parser_lease_capacity), (74, 1_000));
    } else {
        panic!("still receiving HEADERS");
    }
    assert!(
        lease(&mut r).is_none(),
        "same offset cannot be leased twice"
    );
    let s = r.get_mut(EP, STREAM).unwrap();
    s.receive.advertised(90);
    s.receive.bytes_read(74);
    s.response_headers(90, Some(499), Some(0));
    assert_eq!(r.aggregate_capacity().chaff_incoming, 0);
    assert!(r.release_stream(EP, STREAM, 501).is_none());
}

#[test]
fn ali_live_headers_request_fin_ack_is_not_an_inferred_label() {
    for case in 0..4 {
        let mut r = fixture(true, false, 1_000);
        match case {
            0 => {
                r.record_chaff_request_acknowledgment(EP, STREAM, role(), 0, 100, false);
            }
            1 => {
                r.record_chaff_request_acknowledgment(EP, STREAM, role(), 1, 99, true);
            }
            2 => {
                r.record_chaff_request_acknowledgment(
                    EP,
                    STREAM,
                    QcsdRequestRole::Application,
                    0,
                    100,
                    true,
                );
            }
            _ => {
                r.record_chaff_request_acknowledgment(EP, STREAM, role(), 0, 100, true);
                r.record_chaff_request_acknowledgment(EP, STREAM, role(), 100, 1, true);
            }
        }
        assert!(
            lease(&mut r).is_none(),
            "case{case} has no complete valid FIN ACK"
        );
    }
    let mut r = fixture(true, false, 1_000);
    r.record_chaff_request_acknowledgment(EP, STREAM, role(), 50, 50, true);
    assert!(lease(&mut r).is_none());
    r.record_chaff_request_acknowledgment(EP, STREAM, role(), 0, 50, false);
    assert!(
        lease(&mut r).is_some(),
        "contiguous independently ACKed request+FIN"
    );
}

#[test]
fn ali_live_headers_original_lifetime_budget_is_strict() {
    for (budget, debt, expected) in [
        (73, 74, false),
        (74, 74, true),
        (1_000, 1_000, true),
        (1_000, 1_001, false),
        (1_000, 0, false),
    ] {
        let mut r = fixture(true, true, budget);
        r.header_progress(EP, STREAM, debt, false);
        r.retain_aggregate_framing_debt(EP, STREAM, debt, false);
        assert_eq!(
            r.cs_live_chaff_header_lease(EP, STREAM, debt, 1_798)
                .is_some(),
            expected
        );
    }
}

#[test]
fn ali_live_headers_stale_debt_data_boundary_and_wrong_prepared_extent_refuse() {
    for case in 0..5 {
        let mut r = fixture(true, true, 1_000);
        match case {
            0 => {
                r.get_mut(EP, STREAM).unwrap().receive.bytes_read(1);
            }
            1 => {
                r.header_progress(EP, STREAM, 74, true);
                r.retain_aggregate_framing_debt(EP, STREAM, 74, true);
            }
            2 => {
                r.clear_pre_header_blocked(EP, STREAM);
            }
            3 => {
                let receive = &mut r.get_mut(EP, STREAM).unwrap().receive;
                assert_eq!(receive.release(1), Some((17, 1)));
                receive.advertised(17);
            }
            _ => {
                r.mark_receive_unavailable(EP, STREAM);
            }
        }
        assert!(
            lease(&mut r).is_none(),
            "case{case} invalidates this exact live frontier"
        );
    }
    let mut r = fixture(true, true, 1_000);
    assert!(
        r.cs_live_chaff_header_lease(EP, STREAM, 74, 1_799)
            .is_none()
    );
    assert!(
        r.cs_live_chaff_header_lease(QcsdEndpointId(2), STREAM, 74, 1_798)
            .is_none()
    );
}

#[test]
fn ali_live_headers_only_current_consistent_prepared200_exposes_capacity() {
    for (status, length, allowed) in [
        (200, Some(1_798), true),
        (499, Some(0), false),
        (204, Some(1_798), false),
        (200, Some(1_799), false),
        (200, None, false),
    ] {
        let mut r = fixture(true, true, 1_000);
        let grant = lease(&mut r).unwrap();
        let state = r.get_mut(EP, STREAM).unwrap();
        state.receive.advertised(grant.absolute_limit);
        state.receive.bytes_read(74);
        state.response_headers(90, Some(status), length);
        assert_eq!(r.aggregate_capacity().chaff_incoming > 0, allowed);
        assert_eq!(
            !r.allocation_opportunities(EP, DefenseMode::ChaffAndShape)
                .is_empty(),
            allowed
        );
        assert!(
            lease(&mut r).is_none(),
            "post-HEADERS is outside the new capability"
        );
    }
    let mut r = fixture(true, true, 1_000);
    let grant = lease(&mut r).unwrap();
    let state = r.get_mut(EP, STREAM).unwrap();
    state.receive.advertised(grant.absolute_limit);
    state.receive.bytes_read(74);
    state.response_headers(90, Some(200), Some(1_798));
    r.get_mut(EP, STREAM)
        .unwrap()
        .response_headers(90, Some(499), Some(0));
    assert_eq!(r.aggregate_capacity().chaff_incoming, 0);
}

#[test]
fn ali_live_headers_application_capacity_and_terminal_invalidation_stay_strict() {
    let mut r = StreamRegistry::default();
    assert!(r.enable_cs_live_chaff_headers());
    r.open(
        EP,
        QcsdStreamId(76),
        QcsdRequestRole::Application,
        true,
        16,
        1_000,
        1_471,
    );
    assert_eq!(r.aggregate_capacity().application_incoming, 1_455);
    assert!(r.release_stream(EP, QcsdStreamId(76), 99).is_some());
    assert!(
        !r.enable_cs_live_chaff_headers(),
        "cannot activate a second time"
    );
    let mut old = fixture(false, true, 1_000);
    assert!(
        !old.enable_cs_live_chaff_headers(),
        "cannot reinterpret an existing stream"
    );
    let mut fresh = fixture(true, true, 1_000);
    fresh.mark_receive_unavailable(EP, STREAM);
    assert!(lease(&mut fresh).is_none());
    assert_eq!(fresh.aggregate_capacity().chaff_incoming, 0);
}
