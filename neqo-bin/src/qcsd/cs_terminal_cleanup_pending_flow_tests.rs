// Test-only connected HTTP/3 components for the Euro127 cleanup guard question.
// They use the original in-process Neqo handshake, FIN/ACK, HTTP parser and
// transport flow-control implementation. There is no physical network,
// twenty-resource defense run, qualified response or scientific-credit claim.
// The original local_abandon_real_http3_fixture uses a BuFLO config; the
// Http3Client CS cleanup API tested here has no defense-mode input. Thus these
// tests isolate that protocol API, not the runner's CS terminal-latch proof.

#[tokio::test(flavor = "current_thread")]
async fn euro_cs_cleanup_other_stream_control_only_refuses_then_same_target_retries() {
    let output = trace_output_dir("euro-cs-cleanup-other-control");
    let (mut endpoint, mut server, target) = local_abandon_real_http3_fixture(&output);
    let now = test_fixture::now();
    let role = QcsdRequestRole::Chaff {
        resource_id: 0,
        request_id: Some(QcsdChaffRequestId(7)),
    };
    let other = endpoint.client.apply_qcsd_action(now, QcsdAction::RequestChaff {
        endpoint: endpoint.id,
        resource: Resource {
            id: 1,
            url: "https://127.0.0.1:4433/no-response".into(),
            kind: "Other".into(),
            content_length: Some(3_000),
            data_length: 3_000,
            chaff_priority: true,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        },
        request_id: QcsdChaffRequestId(8),
    }).unwrap().unwrap();
    assert_ne!(other, target);
    endpoint.client.stream_close_send(other, now).unwrap();
    endpoint.client.apply_qcsd_action(now, QcsdAction::ConfigureManualReceive {
        endpoint: endpoint.id,
        stream: QcsdStreamId(other.as_u64()),
        initial_limit: 16,
    }).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    assert!(server.events().any(|event| matches!(event,
        neqo_http3::Http3ServerEvent::Headers { stream, fin: true, .. }
            if stream.stream_id() == other)));
    endpoint.client.qcsd_prepare_stream_output(now);
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    assert!(endpoint.client.qcsd_chaff_send_stream_peer_confirmed(target));
    assert!(endpoint.client.qcsd_chaff_send_stream_peer_confirmed(other));
    assert!(!endpoint.client.qcsd_qpack_decoder_handler_pending());
    assert!(!endpoint.client.qcsd_qpack_decoder_transport_pending());
    assert!(!endpoint.client.qcsd_has_pending_stream_send());
    assert!(!endpoint.client.qcsd_has_pending_defense_control());

    // A real accepted, unencoded, UNOWNED parser action on the OTHER stream
    // makes only the global defense-control predicate pending. The target's
    // receive window is not changed or granted an additional byte.
    let control = QcsdAction::LeaseParserReceive {
        endpoint: endpoint.id,
        stream: QcsdStreamId(other.as_u64()),
        absolute_limit: 17,
        increase: 1,
        owner: None,
    };
    assert_eq!(endpoint.client.apply_qcsd_receive_action(&control).unwrap(),
        Some(QcsdReceiveLimitOutcome::Applied));
    let identities = endpoint.client.qcsd_pending_receive_action_identities();
    assert_eq!(identities, [control.receive_identity().unwrap()]);
    assert!(identities.iter().all(|identity| identity.stream().0 != target.as_u64()));
    assert!(!endpoint.client.qcsd_has_pending_stream_send());
    assert!(endpoint.client.qcsd_has_pending_defense_control());
    assert!(matches!(endpoint.client.qcsd_abandon_cs_terminal_chaff(target, role),
        Err(neqo_http3::Error::InvalidInput)));
    assert_eq!(endpoint.client.qcsd_pending_receive_action_identities(), identities);
    assert_eq!(endpoint.client.read_data(now, target, &mut [0; 1]).unwrap(), (0, false));

    // Drive and ACK the actual control frame. This is NOT permission to
    // cancel pending body-owned credit and NOT a forged readiness boolean.
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    assert!(endpoint.client.qcsd_pending_receive_action_identities().is_empty());
    assert!(!endpoint.client.qcsd_has_pending_defense_control());
    assert!(!endpoint.client.qcsd_qpack_decoder_handler_pending());
    assert!(!endpoint.client.qcsd_qpack_decoder_transport_pending());
    assert!(!endpoint.client.qcsd_has_pending_stream_send());
    let before = endpoint.client.transport_stats().frame_tx;
    let proof = endpoint.client.qcsd_abandon_cs_terminal_chaff(target, role).unwrap();
    assert_eq!((proof.receive.encoded_receive_limit, proof.receive.manual_receive_limit,
        proof.receive.consumed, proof.receive.retired, proof.receive.buffered_bytes),
        (1_763, 1_763, 1_763, 1_763, 0));
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let after = endpoint.client.transport_stats().frame_tx;
    assert_eq!(after.max_stream_data, before.max_stream_data);
    assert_eq!(after.stop_sending, before.stop_sending);
    assert_eq!(after.reset_stream, before.reset_stream);
    assert_eq!(after.stream, before.stream);
    drop(endpoint);
    drop(server);
    fs::remove_dir_all(output).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn euro_cs_cleanup_body_owned_pending_remains_strict_and_atomic() {
    let output = trace_output_dir("euro-cs-cleanup-owned-credit");
    let (mut endpoint, server, target, mut traces) =
        local_abandon_serialization_real_http3_fixture(&output);
    let now = test_fixture::now();
    let owned = QcsdAction::IncreaseReceiveLimit {
        endpoint: endpoint.id,
        stream: QcsdStreamId(target.as_u64()),
        absolute_limit: 1_764,
        packet: Packet::new(Duration::ZERO, Direction::Incoming, 1).unwrap(),
        slot: QcsdSlotId(90),
    };
    assert_eq!(endpoint.client.apply_qcsd_receive_action(&owned).unwrap(),
        Some(QcsdReceiveLimitOutcome::Applied));
    let expected = vec![owned.receive_identity().unwrap()];
    assert_eq!(endpoint.client.qcsd_pending_receive_action_identities(), expected);
    let cancellation = QcsdAction::CancelChaff {
        endpoint: endpoint.id,
        stream: QcsdStreamId(target.as_u64()),
        reason: QcsdChaffCancellationReason::CsBufloLocalEarlyTermination,
    };
    let error = super::prepare_chaff_cancellation(
        &mut endpoint, &mut traces, now, &cancellation).unwrap_err();
    assert!(matches!(error, Error::SlotInvariant(message)
        if message.contains("only unowned parser leases")));
    assert_eq!(endpoint.client.qcsd_pending_receive_action_identities(), expected);
    assert_eq!(endpoint.streams[&target].outcome, "in_flight");
    assert!(!endpoint.streams[&target].complete);
    assert!(endpoint.terminal_local_abandonments.is_empty());
    let role = endpoint.streams[&target].role;
    assert!(matches!(endpoint.client.qcsd_abandon_cs_terminal_chaff(target, role),
        Err(neqo_http3::Error::InvalidInput)));
    assert_eq!(endpoint.client.qcsd_pending_receive_action_identities(), expected);
    drop(traces);
    drop(endpoint);
    drop(server);
    fs::remove_dir_all(output).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn euro_cs_cleanup_already_closed_handler_is_not_retryable_success() {
    let output = trace_output_dir("euro-cs-cleanup-closed-handler");
    let (mut endpoint, server, target) = local_abandon_real_http3_fixture(&output);
    let role = QcsdRequestRole::Chaff {
        resource_id: 0,
        request_id: Some(QcsdChaffRequestId(7)),
    };
    let first = endpoint.client.qcsd_abandon_cs_terminal_chaff(target, role).unwrap();
    assert_eq!(first.receive.consumed, 1_763);
    assert!(matches!(endpoint.client.qcsd_abandon_cs_terminal_chaff(target, role),
        Err(neqo_http3::Error::InvalidStreamId)));
    drop(endpoint);
    drop(server);
    fs::remove_dir_all(output).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn euro_cs_cleanup_actual_peer_fin_complete_receive_is_not_a_local_cancel() {
    let output = trace_output_dir("euro-cs-cleanup-peer-fin");
    let started = test_fixture::now();
    let clock = QcsdObservationClock::new(started);
    let (mut endpoint, mut server) = connected_runner_endpoint_with_server_config(
        &output, started, &clock, QcsdEndpointId(0), 4_433,
        QcsdConfig { initial_max_stream_data: 16,
            defense: cs_projection_test_defense(), ..QcsdConfig::default() });
    endpoint.client.qcsd_enable_send_shaping(false);
    let target = endpoint.client.apply_qcsd_action(started, QcsdAction::RequestChaff {
        endpoint: endpoint.id,
        resource: Resource {
            id: 0, url: "https://127.0.0.1:4433/complete".into(),
            kind: "Other".into(), content_length: Some(64), data_length: 64,
            chaff_priority: true, known_valid: true, depends_on: Vec::new(),
            headers: Vec::new(),
        },
        request_id: QcsdChaffRequestId(7),
    }).unwrap().unwrap();
    endpoint.client.stream_close_send(target, started).unwrap();
    endpoint.client.apply_qcsd_action(started, QcsdAction::ConfigureManualReceive {
        endpoint: endpoint.id, stream: QcsdStreamId(target.as_u64()),
        initial_limit: 1_763,
    }).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let response = server.events().find_map(|event| match event {
        neqo_http3::Http3ServerEvent::Headers { stream, fin: true, .. }
            if stream.stream_id() == target => Some(stream),
        _ => None,
    }).unwrap();
    response.send_headers(&[neqo_common::Header::new(":status", "200"),
        neqo_common::Header::new("content-length", "64")]).unwrap();
    assert_eq!(response.send_data(&[b'x'; 64], started).unwrap(), 64);
    response.stream_close_send(started).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let mut total = 0;
    let mut peer_fin = false;
    for _ in 0..4 {
        let (bytes, fin) = endpoint.client.read_data(started, target, &mut [0; 4_096]).unwrap();
        total += bytes;
        if fin { peer_fin = true; break; }
    }
    assert_eq!(total, 64);
    assert!(peer_fin, "the real peer FIN, not local closure, completed this receive");
    endpoint.client.qcsd_prepare_stream_output(started);
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let before = endpoint.client.transport_stats().frame_tx;
    let role = QcsdRequestRole::Chaff {
        resource_id: 0, request_id: Some(QcsdChaffRequestId(7)),
    };
    assert!(matches!(endpoint.client.qcsd_abandon_cs_terminal_chaff(target, role),
        Err(neqo_http3::Error::InvalidInput)));
    let after = endpoint.client.transport_stats().frame_tx;
    assert_eq!(after.max_stream_data, before.max_stream_data);
    assert_eq!(after.stop_sending, before.stop_sending);
    assert_eq!(after.reset_stream, before.reset_stream);
    drop(endpoint);
    drop(server);
    fs::remove_dir_all(output).unwrap();
}

// This same test compiles against original149 and the candidate. Original149
// reaches the real strict InvalidInput at the first busy-control application;
// the candidate must retain the action until real packet/ACK progress, then
// produce one actual typed proof and applied acknowledgement. The other
// control stream is a disclosed protocol-only component premise, outside the
// synthetic one-target controller workload; its setup observations are drained.
#[tokio::test(flavor = "current_thread")]
async fn euro_cs_cleanup_real_runner_defers_control_then_applies_exact_receipt_ack() {
    let output = trace_output_dir("euro-cs-real-runner-pending-ack");
    let (mut endpoint, mut server, target) = cs_idle_initial_real_http3_fixture(&output, true, false);
    let (mut controller, cancel) = cs_idle_terminal_controller(&mut endpoint, target);
    let cancel = cancel.expect("original real controller issued the target cleanup");
    let now = test_fixture::now();
    let other = endpoint.client.apply_qcsd_action(now, QcsdAction::RequestChaff {
        endpoint: endpoint.id,
        resource: Resource { id: 1, url: "https://127.0.0.1:4433/protocol-control-only".into(),
            kind: "Other".into(), content_length: Some(3_000), data_length: 3_000,
            chaff_priority: true, known_valid: true, depends_on: Vec::new(), headers: Vec::new() },
        request_id: QcsdChaffRequestId(8),
    }).unwrap().unwrap();
    endpoint.client.stream_close_send(other, now).unwrap();
    endpoint.client.apply_qcsd_action(now, QcsdAction::ConfigureManualReceive {
        endpoint: endpoint.id, stream: QcsdStreamId(other.as_u64()), initial_limit: 16,
    }).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    endpoint.client.qcsd_prepare_stream_output(now);
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    assert!(endpoint.client.qcsd_chaff_send_stream_peer_confirmed(other));
    assert!(!endpoint.client.qcsd_has_pending_defense_control());
    let control = QcsdAction::LeaseParserReceive { endpoint: endpoint.id,
        stream: QcsdStreamId(other.as_u64()), absolute_limit: 17, increase: 1, owner: None };
    endpoint.client.apply_qcsd_receive_action(&control).unwrap();
    assert!(endpoint.client.qcsd_has_pending_defense_control());
    // Drain only the disclosed other-stream fixture setup observations. This
    // changes neither actual transport state nor the packet counters that gate
    // candidate retries; no production path suppresses these observations.
    drop(endpoint.client.qcsd_timestamped_observations());
    let mut endpoints = vec![endpoint];
    let mut traces = TraceFiles::new(&output, now).unwrap();
    super::apply_action_batch(&mut endpoints, &mut controller, None, &mut traces,
        now, Duration::from_micros(1), vec![cancel])
        .expect("busy GLOBAL control defers a valid target instead of aborting");
    assert_eq!(controller.defense_diagnostics().cs_buflo_local_et_stream_cancellations, 0);
    assert!(endpoints[0].streams.contains_key(&target));
    assert!(endpoints[0].terminal_local_abandonments.is_empty());
    assert!(!controller.is_complete());
    // An immediate repeat has no packet progress and must not mutate or spin.
    super::apply_queued_actions(&mut endpoints, &mut controller, None, &mut traces,
        now, Duration::from_micros(1)).unwrap();
    assert_eq!(controller.defense_diagnostics().cs_buflo_local_et_stream_cancellations, 0);
    controller.observe(QcsdObservation::EgressBacklog { pending: false }, Duration::from_micros(2));
    controller.poll(Duration::from_micros(2));
    assert!(!controller.is_complete(), "pending typed cancellation blocks premature empty completion");
    assert!(!controller.drain_actions().any(|a|matches!(a,
        QcsdAction::CancelChaff { stream, .. } if stream.0 == target.as_u64())));
    test_fixture::exchange_packets(&mut endpoints[0].client, &mut server, false, None);
    assert!(!endpoints[0].client.qcsd_has_pending_defense_control());
    drop(endpoints[0].client.qcsd_timestamped_observations());
    super::apply_queued_actions(&mut endpoints, &mut controller, None, &mut traces,
        now, Duration::from_micros(3)).unwrap();
    assert_eq!(controller.defense_diagnostics().cs_buflo_local_et_stream_cancellations, 1);
    assert_eq!(endpoints[0].terminal_local_abandonments.len(), 1);
    assert!(!endpoints[0].streams.contains_key(&target));
    assert_eq!(endpoints[0].completed.len(), 1);
    assert_eq!(endpoints[0].completed[0].outcome, "local_early_termination_cancelled");
    assert!(controller.requires_terminal_egress_backlog_snapshot());
    controller.observe(QcsdObservation::EgressBacklog { pending: false }, Duration::from_micros(4));
    controller.poll(Duration::from_micros(4));
    assert!(controller.is_complete());
    super::apply_queued_actions(&mut endpoints, &mut controller, None, &mut traces,
        now, Duration::from_micros(4)).unwrap();
    assert_eq!(endpoints[0].terminal_local_abandonments.len(), 1);
    assert_eq!(controller.defense_diagnostics().cs_buflo_local_et_stream_cancellations, 1);
    drop(traces);drop(endpoints);drop(server);fs::remove_dir_all(output).unwrap();
}
