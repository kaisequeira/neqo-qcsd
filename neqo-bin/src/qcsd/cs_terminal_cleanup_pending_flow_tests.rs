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

// Prospective Native151 component regression for the saved Fonts150 failure.
// The only synthetic premise is the completed application and its retained
// natural-byte padding basis. All replacement request/FIN/ACK, BLOCKED,
// HeaderProgress, response HEADERS/DATA, receive actions and wire observations
// below come from the original in-process HTTP/3 and QUIC implementations.
// This is not a physical Fonts replay, qualified response, full CS completion,
// receipt, policy waiver, workload-vintage update or scientific-credit claim.

fn fonts_after_onload_controller() -> (QcsdController, Duration) {
    let mut parameters = cs_idle_component_parameters();
    parameters.packet_size = 600;
    parameters.max_events = 1_000_000;
    // Use the original connected CS600 fixture's deterministic seed7 and
    // its first actual incoming opportunity, rather than batching100ms.
    let mut probe = neqo_csdef::CsBuflo::from_parameters(parameters.clone(), 7);
    let first_at = probe.next_event_at().expect("real seed7 first deadline");
    let first = probe.next_event(first_at).expect("real first CS opportunity");
    assert_eq!((first.direction(), first.length()), (Direction::Incoming, 600));
    assert!(probe.next_event(first_at).is_none());
    let mut defense = neqo_csdef::CsBuflo::from_parameters(parameters, 7);
    // Saved-case geometry is a disclosed fixture input, not invented reads or
    // scheduled credit. It keeps the real incoming stop predicate false.
    neqo_csdef::Defense::observe_application_bytes(
        &mut defense, Duration::ZERO, Direction::Incoming, 4_205_798);
    let mut controller = QcsdController::with_defense(QcsdConfig {
        defense: cs_projection_test_defense(), max_udp_payload_size: 1_200,
        initial_max_stream_data: 16, cs_live_chaff_header_progress: true,
        tail_wait_us: 0, ..QcsdConfig::default()
    }, Some(ResourceManifest { resources: vec![Resource {
        id: 0, url: "https://127.0.0.1:4433/replacement".into(), kind: "Other".into(),
        content_length: Some(585_976), data_length: 585_976,
        chaff_priority: true, known_valid: true, depends_on: Vec::new(), headers: Vec::new(),
    }] }), Box::new(defense)).unwrap();
    assert!(controller.configure_cs_live_chaff_header_progress().unwrap());
    (controller, first_at)
}

async fn fonts_after_onload_real_h3_case(delayed_ack_delivery: bool) {
    let output = trace_output_dir(if delayed_ack_delivery {
        "fonts-after-onload-observed-header-debt"
    } else { "fonts-after-onload-immediate-ack-header-debt" });
    let now = test_fixture::now();
    let clock = QcsdObservationClock::new(now);
    let (mut endpoint, mut server) = connected_runner_endpoint_with_server_config(
        &output, now, &clock, QcsdEndpointId(0), 4_433,
        QcsdConfig { initial_max_stream_data: 16,
            defense: cs_projection_test_defense(), ..QcsdConfig::default() });
    endpoint.client.qcsd_enable_send_shaping(false);
    let (mut controller, first_at) = fonts_after_onload_controller();
    for record in endpoint.client.qcsd_timestamped_observations() {
        controller.observe(record.into_observation(), Duration::ZERO);
    }
    controller.drain_actions().for_each(drop);
    controller.observe(QcsdObservation::ApplicationComplete, Duration::from_micros(1));
    controller.flush_defense_observations();
    let before = controller.defense_diagnostics();
    assert!(before.cs_buflo_application_complete);
    assert_eq!(before.cs_buflo_incoming_padding_target_bytes, 8_388_608);
    assert!(!before.cs_buflo_incoming_termination_stop_latched);
    assert!(!before.cs_buflo_local_termination_latched);

    // This is a newly opened post-onLoad replacement, not an old stream made
    // to look fresh. The server keeps the exact advertised fixture body size.
    let target = endpoint.client.apply_qcsd_action(now, QcsdAction::RequestChaff {
        endpoint: endpoint.id,
        resource: Resource { id: 0, url: "https://127.0.0.1:4433/replacement".into(),
            kind: "Other".into(), content_length: Some(585_976), data_length: 585_976,
            chaff_priority: true, known_valid: true, depends_on: Vec::new(), headers: Vec::new() },
        request_id: QcsdChaffRequestId(0),
    }).unwrap().unwrap();
    endpoint.client.stream_close_send(target, now).unwrap();
    endpoint.client.apply_qcsd_action(now, QcsdAction::ConfigureManualReceive {
        endpoint: endpoint.id, stream: QcsdStreamId(target.as_u64()), initial_limit: 16,
    }).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let response = server.events().find_map(|event| match event {
        neqo_http3::Http3ServerEvent::Headers { stream, fin: true, .. }
            if stream.stream_id() == target => Some(stream),
        _ => None,
    }).expect("real server received this replacement request and FIN");
    assert!(endpoint.client.qcsd_chaff_send_stream_peer_confirmed(target));
    response.send_headers(&[neqo_common::Header::new(":status", "200"),
        neqo_common::Header::new("content-length", "585976"),
        neqo_common::Header::new("x-component-pad", "z".repeat(128))]).unwrap();
    // Real SendMessage::send_data returns0 while its HEADERS are blocked
    // by the initial16 raw-byte window. No response body is buffered here.
    assert_eq!(response.send_data(&[b'x'; 4_096], now).unwrap(), 0);
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let _ = endpoint.client.read_data(now, target, &mut [0; 4_096]).unwrap();
    let records = endpoint.client.qcsd_timestamped_observations();
    assert!(records.iter().any(|r| matches!(r.observation(),
        QcsdObservation::StreamDataBlocked { stream, blocked_at: 16, .. }
            if stream.0 == target.as_u64())));
    assert!(records.iter().any(|r| matches!(r.observation(),
        QcsdObservation::HeaderProgress { stream, min_remaining, awaiting_data_frame: false, .. }
            if stream.0 == target.as_u64() && *min_remaining > 0)));
    assert!(!records.iter().any(|r| matches!(r.observation(),
        QcsdObservation::ResponseHeaders { stream, .. } if stream.0 == target.as_u64())));
    // process_multiple_input drives the real HTTP/3 parser immediately.
    // This fresh replacement already has actual HEADERS debt, not a pristine
    // ReceiveState bootstrap. Keep its exact observed obligation and raw count.
    let header_debt = records.iter().find_map(|r| match r.observation() {
        QcsdObservation::HeaderProgress { stream, min_remaining, awaiting_data_frame: false, .. }
            if stream.0 == target.as_u64() && *min_remaining > 0 => Some(*min_remaining),
        _ => None,
    }).unwrap();
    let mut consumed_raw = records.iter().filter_map(|r| match r.observation() {
        QcsdObservation::BytesRead { stream, bytes, .. } if stream.0 == target.as_u64() => Some(*bytes),
        _ => None,
    }).sum::<u64>();
    let mut deferred_acks = Vec::new();
    for record in records {
        if delayed_ack_delivery && matches!(record.observation(),
            QcsdObservation::StreamDataAcknowledged { stream, fin: true, .. }
                if stream.0 == target.as_u64()) {
            // Delayed reducer delivery is explicit: the original ACK record is
            // retained and delivered below, never replaced or marked complete.
            deferred_acks.push(record);
        } else {
            controller.observe(record.into_observation(), Duration::from_micros(2));
        }
    }
    let mut actions: Vec<_> = controller.drain_actions().collect();
    if delayed_ack_delivery {
        assert!(!deferred_acks.is_empty());
        assert!(!actions.iter().any(|a| matches!(a, QcsdAction::LeaseParserReceive { .. })),
            "actual HEADERS debt cannot bypass the original complete FIN-ACK guard");
        for record in deferred_acks {
            controller.observe(record.into_observation(), Duration::from_micros(3));
        }
        actions.extend(controller.drain_actions());
    }
    let leases: Vec<_> = actions.into_iter().filter(|a| matches!(a,
        QcsdAction::LeaseParserReceive { stream, owner: None, .. }
            if stream.0 == target.as_u64())).collect();
    assert_eq!(leases.len(), 1,
        "active CS padding must finish this post-onLoad replacement HEADERS, without scheduled credit");
    let lease = &leases[0];
    let (absolute_limit, increase) = match lease {
        QcsdAction::LeaseParserReceive { absolute_limit, increase, .. } => (*absolute_limit, *increase),
        _ => unreachable!(),
    };
    assert!(increase > 0 && increase <= 1_000 && absolute_limit <= 1_016);
    assert_eq!((absolute_limit, increase), (16 + header_debt, header_debt));
    assert!(controller.cs_live_chaff_header_lease_witness(
        endpoint.id, QcsdStreamId(target.as_u64()), absolute_limit, increase).is_some(),
        "only this actual exact HEADERS-debt witness, no bootstrap claim");
    let permission_only = controller.defense_diagnostics();
    assert_eq!((permission_only.scheduled_incoming_requested_bytes,
        permission_only.scheduled_incoming_advertised_bytes,
        permission_only.scheduled_incoming_consumed_bytes,
        permission_only.scheduled_incoming_retired_bytes), (0, 0, 0, 0));
    endpoint.client.apply_qcsd_receive_action(lease).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    // Only actual parser permission can flush HEADERS and expose any body
    // send space. Exact header debt can leave zero DATA space; pristine1000
    // permission admits only the real remainder after HEADERS/frame bytes.
    let permitted_body = response.send_data(&[b'x'; 4_096], now).unwrap();
    assert!(permitted_body <= 1_000);
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let (body, fin) = endpoint.client.read_data(now, target, &mut [0; 4_096]).unwrap();
    assert_eq!(body, permitted_body);
    assert!(!fin);
    let parsed = endpoint.client.qcsd_timestamped_observations();
    assert!(parsed.iter().any(|r| matches!(r.observation(),
        QcsdObservation::ResponseHeaders { stream, status: Some(200), content_length: Some(585_976), .. }
            if stream.0 == target.as_u64())));
    consumed_raw += parsed.iter().filter_map(|r| match r.observation() {
        QcsdObservation::BytesRead { stream, bytes, .. } if stream.0 == target.as_u64() => Some(*bytes),
        _ => None,
    }).sum::<u64>();
    for record in parsed {
        controller.observe(record.into_observation(), Duration::from_micros(4));
    }
    // Retain and apply actual unowned DATA-framing permissions; discarding an
    // issued action would leave controller and transport receive limits apart.
    let mut additional_unowned = 0;
    for action in controller.drain_actions().collect::<Vec<_>>() {
        match &action {
            QcsdAction::LeaseParserReceive { stream, increase, owner: None, .. }
                if stream.0 == target.as_u64() => additional_unowned += *increase,
            _ => panic!("unexpected action before this first scheduled opportunity"),
        }
        endpoint.client.apply_qcsd_receive_action(&action).unwrap();
    }
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let prefix_records = endpoint.client.qcsd_timestamped_observations();
    consumed_raw += prefix_records.iter().filter_map(|r| match r.observation() {
        QcsdObservation::BytesRead { stream, bytes, .. } if stream.0 == target.as_u64() => Some(*bytes),
        _ => None,
    }).sum::<u64>();
    for record in prefix_records {
        controller.observe(record.into_observation(), Duration::from_micros(5));
    }
    assert!(controller.drain_actions().next().is_none(), "no unaccounted recursive parser action");
    controller.flush_defense_observations();
    assert_eq!(controller.defense_diagnostics().scheduled_incoming_consumed_bytes, 0,
        "slotless parser permission cannot satisfy a scheduled incoming cell");
    // Exact HEADERS-debt permission may end before the first DATA frame.
    // This path proves real HEADERS completion and zero scheduled ownership;
    // the immediate-ACK path below exercises a full owned600 cell.
    if delayed_ack_delivery {
        assert_eq!(controller.defense_diagnostics().scheduled_incoming_requested_bytes, 0);
        drop(endpoint); drop(server); fs::remove_dir_all(output).unwrap();
        return;
    }
    // The unchanged allocator may now create one new owned600 release from
    // real current DATA capacity. No estimated body capacity is advertised.
    controller.poll(first_at);
    let owned = controller.drain_actions().find(|action| matches!(action,
        QcsdAction::IncreaseReceiveLimit { stream, packet, .. }
            if stream.0 == target.as_u64() && packet.length() == 600))
        .expect("matching actual200 HEADERS and observed DATA fund the original owned cell");
    endpoint.client.apply_qcsd_receive_action(&owned).unwrap();
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let unowned_unused = (absolute_limit + additional_unowned).checked_sub(consumed_raw).unwrap();
    assert!(unowned_unused <= 1_000);
    let owned_body = response.send_data(&[b'x'; 4_096], now).unwrap();
    assert!(owned_body > 0 && owned_body < 600 + usize::try_from(unowned_unused).unwrap(),
        "raw permission includes actual DATA-frame bytes; unowned bytes stay separate");
    test_fixture::exchange_packets(&mut endpoint.client, &mut server, false, None);
    let (body, fin) = endpoint.client.read_data(now, target, &mut [0; 4_096]).unwrap();
    assert_eq!(body, owned_body);
    assert!(!fin);
    let owned_records = endpoint.client.qcsd_timestamped_observations();
    let mut raw = 0;
    let mut framed = 0;
    let mut advertised = false;
    for record in &owned_records {
        match record.observation() {
            QcsdObservation::BytesRead { stream, bytes, .. }
                if stream.0 == target.as_u64() => raw += *bytes,
            QcsdObservation::DataFrame { stream, frame_header_bytes, data_bytes, .. }
                if stream.0 == target.as_u64() => framed += *frame_header_bytes + *data_bytes,
            QcsdObservation::ReceiveLimitAdvertised { stream, slot: Some(_), .. }
                if stream.0 == target.as_u64() => advertised = true,
            _ => {}
        }
    }
    assert!(advertised);
    assert_eq!((raw, framed), (600 + unowned_unused, 600 + unowned_unused),
        "every actual raw byte is framing/body; only the new600 carries scheduled ownership");
    for record in owned_records {
        controller.observe(record.into_observation(), first_at + Duration::from_micros(1));
    }
    controller.flush_defense_observations();
    let after = controller.defense_diagnostics();
    assert_eq!((after.scheduled_incoming_requested_bytes,
        after.scheduled_incoming_advertised_bytes, after.scheduled_incoming_consumed_bytes,
        after.scheduled_incoming_retired_bytes), (600, 600, 600, 0));
    assert_eq!(after.cs_buflo_missed_incoming_cells, 0);
    assert!(controller.terminal_failure().is_none());
    drop(endpoint); drop(server); fs::remove_dir_all(output).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn fonts_cs_after_onload_real_h3_immediate_ack_replacement_keeps_owned_credit_strict() {
    fonts_after_onload_real_h3_case(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn fonts_cs_after_onload_real_h3_current_debt_waits_original_fin_ack() {
    fonts_after_onload_real_h3_case(true).await;
}

#[test]
fn fonts_cs_after_onload_original_five_terminal_controls_remain_strict() {
    // The existing tokio::test entry functions own their own current-thread
    // runtime. This synchronous wrapper invokes their unchanged real bodies.
    euro_cs_cleanup_other_stream_control_only_refuses_then_same_target_retries();
    euro_cs_cleanup_body_owned_pending_remains_strict_and_atomic();
    euro_cs_cleanup_already_closed_handler_is_not_retryable_success();
    euro_cs_cleanup_actual_peer_fin_complete_receive_is_not_a_local_cancel();
    euro_cs_cleanup_real_runner_defers_control_then_applies_exact_receipt_ack();
}


// Prospective Native155 failure-localization components. These preserve the
// original strict outcome; they do not replay Euro108 or authorize a retry.
#[tokio::test(flavor = "current_thread")]
async fn cs_terminal_failure_diagnostic_same_target_unowned_pending_stays_strict() {
    let output = trace_output_dir("cs-terminal-diagnostic-same-target");
    let (mut endpoint, server, target) = local_abandon_real_http3_fixture(&output);
    let role = QcsdRequestRole::Chaff {
        resource_id: 0, request_id: Some(QcsdChaffRequestId(7)),
    };
    assert_eq!(endpoint.client.qcsd_cs_terminal_chaff_readiness(target, role, None).unwrap(),
        neqo_http3::QcsdCsTerminalReadiness::Ready);
    let control = QcsdAction::LeaseParserReceive {
        endpoint: endpoint.id, stream: QcsdStreamId(target.as_u64()),
        absolute_limit: 1_764, increase: 1, owner: None,
    };
    assert_eq!(endpoint.client.apply_qcsd_receive_action(&control).unwrap(),
        Some(QcsdReceiveLimitOutcome::Applied));
    let identities = endpoint.client.qcsd_pending_receive_action_identities();
    assert_eq!(identities, [control.receive_identity().unwrap()]);
    let before = endpoint.client.transport_stats().frame_tx;
    assert!(matches!(endpoint.client.qcsd_cs_terminal_chaff_readiness(target, role, None),
        Err(neqo_http3::Error::InvalidInput)));
    assert_eq!(endpoint.client.qcsd_pending_receive_action_identities(), identities);
    assert!(endpoint.client.qcsd_has_pending_defense_control());
    assert!(endpoint.terminal_local_abandonments.is_empty());
    let after = endpoint.client.transport_stats().frame_tx;
    assert_eq!(after.max_stream_data, before.max_stream_data);
    assert_eq!(after.stop_sending, before.stop_sending);
    assert_eq!(after.reset_stream, before.reset_stream);
    assert_eq!(after.stream, before.stream);
    drop(endpoint); drop(server); fs::remove_dir_all(output).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cs_terminal_failure_diagnostic_other_target_control_remains_pending() {
    let output = trace_output_dir("cs-terminal-diagnostic-other-target");
    let (mut endpoint, mut server, target) = local_abandon_real_http3_fixture(&output);
    let now = test_fixture::now();
    let role = QcsdRequestRole::Chaff {
        resource_id: 0, request_id: Some(QcsdChaffRequestId(7)),
    };
    let other = endpoint.client.apply_qcsd_action(now, QcsdAction::RequestChaff {
        endpoint: endpoint.id,
        resource: Resource {
            id: 1, url: "https://127.0.0.1:4433/protocol-control-only".into(),
            kind: "Other".into(), content_length: Some(3_000), data_length: 3_000,
            chaff_priority: true, known_valid: true, depends_on: Vec::new(), headers: Vec::new(),
        },
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
    let control = QcsdAction::LeaseParserReceive {
        endpoint: endpoint.id, stream: QcsdStreamId(other.as_u64()),
        absolute_limit: 17, increase: 1, owner: None,
    };
    assert_eq!(endpoint.client.apply_qcsd_receive_action(&control).unwrap(),
        Some(QcsdReceiveLimitOutcome::Applied));
    let identities = endpoint.client.qcsd_pending_receive_action_identities();
    let before = endpoint.client.transport_stats().frame_tx;
    assert_eq!(endpoint.client.qcsd_cs_terminal_chaff_readiness(target, role, None).unwrap(),
        neqo_http3::QcsdCsTerminalReadiness::PendingDefenseControl);
    assert_eq!(endpoint.client.qcsd_pending_receive_action_identities(), identities);
    assert!(endpoint.terminal_local_abandonments.is_empty());
    let after = endpoint.client.transport_stats().frame_tx;
    assert_eq!(after.max_stream_data, before.max_stream_data);
    assert_eq!(after.stop_sending, before.stop_sending);
    assert_eq!(after.reset_stream, before.reset_stream);
    assert_eq!(after.stream, before.stream);
    drop(endpoint); drop(server); fs::remove_dir_all(output).unwrap();
}
