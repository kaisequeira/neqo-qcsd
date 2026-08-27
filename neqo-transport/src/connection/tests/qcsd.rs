// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    net::SocketAddr,
    num::NonZeroUsize,
    rc::Rc,
    time::{Duration, Instant},
};

use neqo_csdef::{
    Direction, MissedSlotReason, Packet, QcsdCongestionReason, QcsdDatagramClass, QcsdEndpointId,
    QcsdObservation, QcsdObservationClock, QcsdReceiveActionIdentity, QcsdReceiveLimitFatal,
    QcsdReceiveLimitOutcome, QcsdRequestRole, QcsdSendPolicy, QcsdSlotId, QcsdSlotOutcome,
    QcsdStreamId, TrafficMorphingConfig, TrafficMorphingEgress, TrafficMorphingOutcome,
};
use test_fixture::{DEFAULT_ADDR, DEFAULT_ADDR_V4, fixture_init, now};

use super::{
    AT_LEAST_PTO, CountingConnectionIdGenerator, DEFAULT_RTT, connect_force_idle, connect_rtt_idle,
    cwnd_avail, default_client, default_server, fill_cwnd, fill_stream, handshake_with_modifier,
};
use crate::{
    Connection, ConnectionParameters, Error, StreamType,
    connection::params::INITIAL_LOCAL_MAX_STREAM_DATA, frame::Frame, recovery::StreamRecoveryToken,
    sender::PACING_BURST_SIZE, tracking::PacketNumberSpace,
};

fn qcsd_client_for(remote: SocketAddr) -> Connection {
    fixture_init();
    Connection::new_client(
        test_fixture::DEFAULT_SERVER_NAME,
        test_fixture::DEFAULT_ALPN,
        Rc::new(RefCell::new(CountingConnectionIdGenerator::default())),
        remote,
        remote,
        ConnectionParameters::default().max_udp_payload_size(1_200),
        now(),
    )
    .expect("create QCSD client")
}

fn queue_target(
    connection: &mut Connection,
    slot: u64,
    size: u16,
    allow_stream_data: bool,
) -> Result<(), Error> {
    let packet =
        Packet::new(Duration::ZERO, Direction::Outgoing, size).map_err(|_| Error::InvalidInput)?;
    let queued_at = now();
    connection.qcsd_queue_scheduled_packet_target_window(
        QcsdSlotId(slot),
        packet,
        queued_at,
        queued_at + Duration::from_secs(1),
        allow_stream_data,
    )
}

fn queue_congestion_sensitive_target(
    connection: &mut Connection,
    slot: u64,
    size: u16,
    allow_stream_data: bool,
    queued_at: Instant,
) -> Result<(), Error> {
    let packet =
        Packet::new(Duration::ZERO, Direction::Outgoing, size).map_err(|_| Error::InvalidInput)?;
    connection.qcsd_queue_scheduled_packet_target_window_with_policy(
        QcsdSlotId(slot),
        packet,
        queued_at,
        queued_at + Duration::from_secs(1),
        allow_stream_data,
        QcsdSendPolicy::CongestionSensitive,
    )
}

#[test]
fn legacy_packet_target_queue_preserves_four_argument_signature() {
    fn accepts_legacy_signature(
        _queue: fn(&mut Connection, QcsdSlotId, Packet, Instant, bool) -> Result<(), Error>,
    ) {
    }

    accepts_legacy_signature(Connection::qcsd_queue_scheduled_packet_target);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "capture a deliberately stale fake drive clock to prove the legacy API reads no clock"
)]
fn legacy_packet_target_is_immediately_eligible_on_a_fake_clock() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let fake_now = Instant::now();
    let deadline = fake_now + Duration::from_secs(1);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 300).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(39), packet, deadline, false)
        .unwrap();

    let target = client
        .qcsd_eligible_packet_target(fake_now)
        .expect("legacy target has no lower eligibility bound");
    assert_eq!(target.slot, QcsdSlotId(39));
    assert_eq!(target.not_before, None);
    assert_eq!(client.qcsd_packet_target_wakeup(fake_now), Some(deadline));
}

#[test]
fn legacy_target_can_precede_a_nonregressing_explicit_window() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let base = now();
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 300).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(35),
            packet,
            base + Duration::from_millis(20),
            false,
        )
        .unwrap();

    assert_eq!(
        client.qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(36),
            packet,
            base + Duration::from_millis(10),
            base + Duration::from_millis(15),
            false,
        ),
        Err(Error::InvalidInput),
        "deadline ordering remains queue-wide"
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);

    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(36),
            packet,
            base + Duration::from_millis(10),
            base + Duration::from_millis(30),
            false,
        )
        .expect("None sorts before an explicit lower bound");
    assert_eq!(client.qcsd_pending_packet_targets(), 2);
    assert_eq!(client.qcsd_packet_targets[0].not_before, None);
    assert_eq!(
        client.qcsd_packet_targets[1].not_before,
        Some(base + Duration::from_millis(10))
    );
}

#[test]
fn explicit_window_rejects_a_legacy_successor_without_hiding_later_regressions() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    let base = now();
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 300).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(37),
            packet,
            base + Duration::from_millis(10),
            base + Duration::from_millis(20),
            false,
        )
        .unwrap();

    assert_eq!(
        client.qcsd_queue_scheduled_packet_target(
            QcsdSlotId(38),
            packet,
            base + Duration::from_millis(30),
            false,
        ),
        Err(Error::InvalidInput),
        "an immediate lower bound cannot follow a future lower bound"
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);

    assert_eq!(
        client.qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(39),
            packet,
            base + Duration::from_millis(5),
            base + Duration::from_millis(30),
            false,
        ),
        Err(Error::InvalidInput),
        "the rejected legacy target must not hide an explicit release regression"
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
}

fn traffic_morphing_config() -> TrafficMorphingConfig {
    TrafficMorphingConfig {
        matrix: "inline.json".into(),
        workload_id: "test source".into(),
        ingress_packet_size: 1_200,
        max_ingress_deficit_bytes: 8_000,
    }
}

fn drain_observations(connection: &mut Connection) -> Vec<QcsdObservation> {
    connection
        .qcsd_timestamped_observations()
        .into_iter()
        .map(neqo_csdef::TimestampedQcsdObservation::into_observation)
        .collect()
}

const TRAFFIC_MORPHING_PARAMETERS: &str = r#"{
    "adaptation":"qcsd-client-only",
    "buckets":[64,1200],
    "generated_by":"transport test",
    "paper_equivalent":false,
    "profiles":[{
        "incoming":{
            "expected_added_bytes":0.0,
            "l1_distance":0.0,
            "realized_distribution":[0.0,1.0],
            "rows":[[0.0,1.0],[0.0,1.0]],
            "source_distribution":[0.0,1.0],
            "target_distribution":[0.0,1.0]
        },
        "outgoing":{
            "expected_added_bytes":1136.0,
            "l1_distance":0.0,
            "realized_distribution":[0.0,1.0],
            "rows":[[0.0,1.0],[0.0,1.0]],
            "source_distribution":[1.0,0.0],
            "target_distribution":[0.0,1.0]
        },
        "source":"test source",
        "target":"test target"
    }],
    "schema_version":2,
    "udp_payload_ceiling":1200
}"#;

fn enable_traffic_morphing(client: &mut Connection) {
    client.qcsd_set_udp_payload_ceiling(1_200).unwrap();
    let morpher = TrafficMorphingEgress::from_json(
        &traffic_morphing_config(),
        7,
        1_200,
        TRAFFIC_MORPHING_PARAMETERS,
    )
    .expect("morpher");
    client.qcsd_enable_traffic_morphing(morpher);
}

#[test]
fn udp_payload_ceiling_pads_ipv4_and_ipv6_initials_to_exactly_1200() {
    for remote in [DEFAULT_ADDR_V4, DEFAULT_ADDR] {
        let mut client = qcsd_client_for(remote);
        client.qcsd_set_udp_payload_ceiling(1_200).unwrap();

        let initial = client.process_output(now()).dgram().unwrap();
        assert_eq!(initial.len(), 1_200, "address family: {remote}");
    }
}

#[test]
fn udp_payload_ceiling_caps_ipv4_and_ipv6_handshake_coalescing() {
    for remote in [DEFAULT_ADDR_V4, DEFAULT_ADDR] {
        let mut client = qcsd_client_for(remote);
        client.qcsd_set_udp_payload_ceiling(1_200).unwrap();
        let mut server = default_server();
        let mut datagrams = 0;

        handshake_with_modifier(
            &mut client,
            &mut server,
            now(),
            Duration::ZERO,
            |datagram| {
                datagrams += 1;
                assert!(datagram.len() <= 1_200, "address family: {remote}");
                Some(datagram)
            },
        );
        assert!(datagrams > 2);
    }
}

#[test]
fn exact_packet_targets_produce_one_udp_datagram_each() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    for (slot, target) in [900_u16, 1_000, 1_200].into_iter().enumerate() {
        queue_target(&mut client, slot as u64, target, false).unwrap();
        assert_eq!(client.qcsd_pending_packet_targets(), 1);
        let datagram = client.process_output(now()).dgram().unwrap();
        assert_eq!(datagram.len(), usize::from(target));
        assert_eq!(client.qcsd_pending_packet_targets(), 0);
        server.process_input(datagram, now());
        _ = server.process_output(now());
    }
}

#[test]
fn traffic_morphing_pads_the_natural_packet_in_place() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    enable_traffic_morphing(&mut client);
    assert_eq!(
        client.qcsd_morphing_optional_stream_limit(
            PacketNumberSpace::ApplicationData,
            64,
            1_199,
            false,
        ),
        None
    );
    assert_eq!(
        client.qcsd_morphing_optional_stream_limit(
            PacketNumberSpace::ApplicationData,
            64,
            1_200,
            false,
        ),
        Some(1_200)
    );
    assert_eq!(
        client.qcsd_morphing_optional_stream_limit(
            PacketNumberSpace::ApplicationData,
            64,
            1_200,
            true,
        ),
        None
    );

    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream, &[0xA5; 100]).unwrap();
    let datagram = client.process_output(now()).dgram().unwrap();
    assert_eq!(datagram.len(), 1_200);
    server.process_input(datagram, now());
    let mut received = [0; 128];
    let (read, _) = server.stream_recv(stream, &mut received).unwrap();
    assert_eq!(read, 100);
    assert!(received[..read].iter().all(|byte| *byte == 0xA5));

    let observations = drain_observations(&mut client);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::TrafficMorphingEgress {
            endpoint: QcsdEndpointId(7),
            source_udp_size,
            outcome: TrafficMorphingOutcome::Morphed {
                target_udp_size: 1_200
            },
        } if *source_udp_size < 1_200
    )));
}

#[test]
fn traffic_morphing_defers_optional_streams_before_sampling_when_capacity_is_short() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    queue_target(&mut client, 1, 300, false).unwrap();
    assert_eq!(client.process_output(now()).dgram().unwrap().len(), 300);
    let filler = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, filler);
    let mut send_time = now();
    while cwnd_avail(&client) > client.plpmtu() {
        match client.process_output(send_time) {
            crate::Output::Datagram(_) => {}
            crate::Output::Callback(delay) => send_time += delay,
            crate::Output::None => panic!("stream data should fill the congestion window"),
        }
    }
    let partial = cwnd_avail(&client);
    assert!((256..1_200).contains(&partial));

    enable_traffic_morphing(&mut client);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xA5; 100]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();

    assert!(client.process_output(send_time).dgram().is_none());
    assert!(
        !drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::TrafficMorphingEgress { .. }
            ))
    );
}

#[test]
fn packet_target_rejects_unsafe_sizes() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);

    assert_eq!(
        queue_target(&mut client, 1, 63, false),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        queue_target(&mut client, 2, u16::MAX, false),
        Err(Error::InvalidInput)
    );
    client.qcsd_set_udp_payload_ceiling(1_200).unwrap();
    assert_eq!(client.qcsd_max_udp_payload_size(), Some(1_200));
    assert_eq!(
        queue_target(&mut client, 3, 1_201, false),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn packet_target_never_shapes_handshake_output() {
    let mut client = default_client();
    assert_eq!(
        queue_target(&mut client, 1, 1_200, false),
        Err(Error::NotAvailable)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn target_uses_safe_partial_congestion_window_capacity() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    queue_target(&mut client, 1, 300, false).unwrap();
    assert_eq!(client.process_output(now()).dgram().unwrap().len(), 300);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    let mut send_time = now();
    while cwnd_avail(&client) > client.plpmtu() {
        match client.process_output(send_time) {
            crate::Output::Datagram(datagram) => assert_eq!(datagram.len(), client.plpmtu()),
            crate::Output::Callback(delay) => send_time += delay,
            crate::Output::None => panic!("stream data should fill the remaining window"),
        }
    }
    let partial = u16::try_from(cwnd_avail(&client)).unwrap();
    assert!((64..u16::try_from(client.plpmtu()).unwrap()).contains(&partial));

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, partial).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(2),
            packet,
            send_time,
            send_time + Duration::from_secs(1),
            false,
        )
        .unwrap();
    assert_eq!(
        client.process_output(send_time).dgram().unwrap().len(),
        usize::from(partial)
    );
}

#[test]
fn attributed_target_reports_exact_satisfaction() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    let queued_at = now();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(11),
            packet,
            queued_at,
            queued_at + Duration::from_secs(1),
            false,
        )
        .unwrap();
    assert_eq!(
        client.process_output(queued_at).dgram().unwrap().len(),
        1_000
    );
    assert!(
        drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    endpoint: QcsdEndpointId(7),
                    slot: QcsdSlotId(11),
                    observed_size: 1_000,
                }
            ))
    );
}

#[test]
fn exact_target_reports_nonzero_lateness_in_packet_composition() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let release = now();
    let attempted_at = release + Duration::from_micros(123);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(12),
            packet,
            release,
            release + Duration::from_secs(1),
            false,
        )
        .unwrap();
    assert_eq!(
        client.process_output(attempted_at).dgram().unwrap().len(),
        1_000
    );

    let observations = drain_observations(&mut client);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::SlotSatisfied {
            slot: QcsdSlotId(12),
            observed_size: 1_000,
            ..
        }
    )));
    let composition = observations
        .iter()
        .find_map(|observation| match observation {
            QcsdObservation::ClassifiedDatagram {
                direction: Direction::Outgoing,
                composition: Some(composition),
                ..
            } if composition.desired_udp_bytes == 1_000 => Some(*composition),
            _ => None,
        })
        .expect("exact target packet composition");
    assert_eq!(composition.observed_udp_bytes, 1_000);
    assert_eq!(composition.lateness_us, 123);
}

#[test]
fn congestion_sensitive_full_target_reports_complete_composition() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let queued_at = now();
    queue_congestion_sensitive_target(&mut client, 111, 300, false, queued_at).unwrap();

    let attempted_at = queued_at + Duration::from_micros(123);
    assert_eq!(
        client.process_output(attempted_at).dgram().unwrap().len(),
        300
    );
    let observations = drain_observations(&mut client);
    let composition = observations
        .iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(111),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(*composition),
            _ => None,
        })
        .expect("typed full outcome");
    assert_eq!(composition.desired_udp_bytes, 300);
    assert_eq!(composition.observed_udp_bytes, 300);
    assert_eq!(composition.application_stream_bytes, 0);
    assert_eq!(composition.retransmission_stream_bytes, 0);
    assert_eq!(composition.chaff_stream_bytes, 0);
    assert_eq!(composition.defense_control_bytes, 1);
    assert!(composition.quic_padding_bytes > 0);
    assert_eq!(composition.lateness_us, 123);
    assert_eq!(
        composition
            .application_stream_bytes
            .saturating_add(composition.retransmission_stream_bytes)
            .saturating_add(composition.chaff_stream_bytes)
            .saturating_add(composition.defense_control_bytes)
            .saturating_add(composition.quic_padding_bytes)
            .saturating_add(composition.other_quic_bytes),
        composition.observed_udp_bytes
    );
}

#[test]
fn real_bearing_target_does_not_add_a_redundant_defense_ping() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream, &[0xA5; 100]).unwrap();
    client
        .qcsd_register_stream_role(stream, QcsdRequestRole::Application)
        .unwrap();
    let queued_at = now();
    queue_congestion_sensitive_target(&mut client, 119, 300, true, queued_at).unwrap();

    let dropped = client.process_output(queued_at).dgram().unwrap();
    assert_eq!(dropped.len(), 300);
    let composition = drain_observations(&mut client)
        .into_iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(119),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(composition),
            _ => None,
        })
        .expect("real-bearing target has typed composition");
    assert!(composition.application_stream_bytes > 0);
    assert_eq!(composition.defense_control_bytes, 0);
    assert!(composition.quic_padding_bytes > 0);
}

#[test]
fn scheduled_receive_credit_is_counted_as_defense_control() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let limit = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap() + 100;
    client
        .qcsd_set_stream_receive_limit_for_slot(stream, limit, QcsdSlotId(199))
        .unwrap();
    let queued_at = now();
    queue_congestion_sensitive_target(&mut client, 120, 300, false, queued_at).unwrap();

    assert_eq!(client.process_output(queued_at).dgram().unwrap().len(), 300);
    let composition = drain_observations(&mut client)
        .into_iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(120),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(composition),
            _ => None,
        })
        .expect("credit-bearing target has typed composition");
    assert!(composition.defense_control_bytes > 1);
    assert!(composition.quic_padding_bytes > 0);
    assert!(client.qcsd_has_pending_defense_control());

    let recovery_at = queued_at + AT_LEAST_PTO;
    queue_congestion_sensitive_target(&mut client, 121, 300, false, recovery_at).unwrap();
    let retransmission = client
        .process_output(recovery_at)
        .dgram()
        .expect("lost receive control is retransmitted in the next target");
    assert_eq!(retransmission.len(), 300);
    let retransmitted_composition = drain_observations(&mut client)
        .into_iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(121),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(composition),
            _ => None,
        })
        .expect("retransmitted credit has typed composition");
    assert!(retransmitted_composition.defense_control_bytes > 1);
    server.process_input(retransmission, recovery_at);
    let ack_at = recovery_at + DEFAULT_RTT;
    let acknowledgment = server
        .process_output(ack_at)
        .dgram()
        .expect("peer acknowledges retransmitted receive control");
    client.process_input(acknowledgment, ack_at);
    assert!(!client.qcsd_has_pending_defense_control());
}

#[test]
fn terminal_receive_stream_drops_unrecoverable_receive_control_backlog() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream, b"request").unwrap();
    client.stream_close_send(stream).unwrap();
    let started_at = now();
    let request = client
        .process_output(started_at)
        .dgram()
        .expect("request datagram");
    server.process_input(request, started_at);

    let limit = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap() + 100;
    client
        .qcsd_set_stream_receive_limit_for_slot(stream, limit, QcsdSlotId(198))
        .unwrap();
    let control_at = started_at + DEFAULT_RTT;
    let lost_control = client
        .process_output(control_at)
        .dgram()
        .expect("MAX_STREAM_DATA datagram");
    assert!(client.qcsd_has_pending_defense_control());
    drop(lost_control);

    server.stream_send(stream, b"response").unwrap();
    server.stream_close_send(stream).unwrap();
    let response_at = control_at + DEFAULT_RTT;
    let response = server
        .process_output(response_at)
        .dgram()
        .expect("terminal response datagram");
    client.process_input(response, response_at);
    assert!(
        !client.qcsd_has_pending_defense_control(),
        "a known final size makes the lost receive window irrelevant"
    );

    // Drive loss declaration as well: the stale provenance entry is removed,
    // rather than surviving forever after Recv -> DataRecvd/SizeKnown.
    drop(client.process_output(control_at + AT_LEAST_PTO));
    assert!(
        client.qcsd_unacked_defense_receive_limits.is_empty(),
        "unrecoverable receive control is terminalized on loss"
    );
}

#[test]
fn congestion_sensitive_target_uses_and_reports_partial_cwnd_capacity() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    // Consume an exact non-MTU-sized target first so filling with full-size
    // packets leaves a deterministic usable partial window.
    let send_time = now();
    queue_congestion_sensitive_target(&mut client, 112, 300, false, send_time).unwrap();
    assert_eq!(client.process_output(send_time).dgram().unwrap().len(), 300);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    let mut send_time = send_time;
    while cwnd_avail(&client) > client.plpmtu() {
        match client.process_output(send_time) {
            crate::Output::Datagram(datagram) => assert_eq!(datagram.len(), client.plpmtu()),
            crate::Output::Callback(delay) => send_time += delay,
            crate::Output::None => panic!("stream data should fill the remaining window"),
        }
    }
    let partial = u16::try_from(cwnd_avail(&client)).unwrap();
    assert!((64..1_200).contains(&partial));
    queue_congestion_sensitive_target(&mut client, 113, 1_200, false, send_time).unwrap();

    assert_eq!(
        client.process_output(send_time).dgram().unwrap().len(),
        usize::from(partial)
    );
    assert!(drain_observations(&mut client).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(113),
                outcome: QcsdSlotOutcome::Partial {
                    composition,
                    reason: QcsdCongestionReason::CongestionLimited,
                },
                ..
            } if composition.desired_udp_bytes == 1_200
                && composition.observed_udp_bytes == partial
        )
    }));
}

#[test]
fn local_et_waits_for_split_stop_ack_and_lost_reset_recovery() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream, b"request").unwrap();
    let established_at = now();
    let request = client
        .process_output(established_at)
        .dgram()
        .expect("request datagram");
    server.process_input(request, established_at);
    client.qcsd_enable_send_shaping(true);

    // Emit RESET_STREAM first and deliberately lose that datagram. Send
    // shaping remains enabled with no slot: the exact local-ET identity must
    // use the maintenance path rather than releasing arbitrary stream bytes.
    client.stream_reset_send(stream, 0).unwrap();
    client.qcsd_mark_chaff_cancellation(stream);
    assert!(client.qcsd_unacked_local_et_resets.contains(&stream));
    let reset_frames_before = client.stats().frame_tx.reset_stream;
    let reset_at = established_at + DEFAULT_RTT;
    let lost_reset = client
        .process_output(reset_at)
        .dgram()
        .expect("local-ET reset datagram");
    assert_eq!(
        client.stats().frame_tx.reset_stream,
        reset_frames_before + 1,
        "the first cancellation datagram contains exactly the queued reset"
    );
    assert!(client.qcsd_unacked_local_et_resets.contains(&stream));
    assert!(client.qcsd_has_pending_defense_control());
    drop(lost_reset);

    // Queue STOP_SENDING only after RESET_STREAM is in flight, forcing the two
    // cancellation controls into separate packets. The STOP acknowledgment
    // must not erase the independently lost reset obligation.
    client.stream_stop_sending(stream, 0).unwrap();
    client.qcsd_mark_chaff_cancellation(stream);
    assert!(client.qcsd_unacked_local_et_resets.contains(&stream));
    let reset_frames_before_stop = client.stats().frame_tx.reset_stream;
    let stop_frames_before = client.stats().frame_tx.stop_sending;
    // Keep this inside the established connection's PTO. `connect_force_idle`
    // has a near-zero synthetic RTT, so a full DEFAULT_RTT delay would make
    // the reset timer-expire and legitimately coalesce its retransmission with
    // STOP_SENDING instead of exercising split recovery identities.
    let stop_at = reset_at + Duration::from_millis(1);
    let stop = client
        .process_output(stop_at)
        .dgram()
        .expect("local-ET stop-sending datagram");
    assert_eq!(
        client.stats().frame_tx.reset_stream,
        reset_frames_before_stop,
        "the later STOP_SENDING datagram must not also carry the lost reset"
    );
    assert_eq!(
        client.stats().frame_tx.stop_sending,
        stop_frames_before + 1,
        "the later cancellation datagram carries STOP_SENDING"
    );
    assert!(client.qcsd_unacked_local_et_resets.contains(&stream));
    server.process_input(stop, stop_at);
    let stop_ack_at = stop_at + DEFAULT_RTT;
    let stop_ack = server
        .process_output(stop_ack_at)
        .dgram()
        .expect("STOP_SENDING acknowledgment");
    client.process_input(stop_ack, stop_ack_at);
    assert!(
        client.qcsd_unacked_local_et_resets.contains(&stream),
        "the STOP acknowledgment must not clear the RESET identity"
    );
    assert!(
        client
            .streams
            .qcsd_local_et_reset_pending_or_in_flight(stream),
        "the unacknowledged RESET remains queued, in flight, or recoverable"
    );
    assert!(
        client.qcsd_has_pending_defense_control(),
        "lost RESET_STREAM remains terminal backlog after STOP_SENDING is ACKed"
    );

    let recovery_at = reset_at + AT_LEAST_PTO;
    let recovered_reset = client
        .process_output(recovery_at)
        .dgram()
        .expect("lost local-ET reset retransmission");
    server.process_input(recovered_reset, recovery_at);
    let reset_ack_at = recovery_at + DEFAULT_RTT;
    let reset_ack = server
        .process_output(reset_ack_at)
        .dgram()
        .expect("RESET_STREAM acknowledgment");
    client.process_input(reset_ack, reset_ack_at);
    assert!(!client.qcsd_has_pending_defense_control());
}

#[test]
fn local_et_stop_ack_waits_for_peer_reset_when_final_size_is_unknown() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(stream, b"request").unwrap();
    client.stream_close_send(stream).unwrap();
    client.stream_stop_sending(stream, 0).unwrap();
    client.qcsd_mark_chaff_cancellation(stream);
    assert!(client.qcsd_unacked_local_et_stop_sending.contains(&stream));
    assert!(client.qcsd_unacked_local_et_resets.is_empty());

    // ACKing STOP_SENDING with no known final size moves the receive half to
    // WaitForReset. That state remains terminal defense-control backlog.
    let stop_token = StreamRecoveryToken::StopSending {
        stream_id: stream,
        encoded_bytes: 4,
    };
    client.streams.acked(&stop_token);
    client.qcsd_local_et_receive_state_changed(stream);
    assert!(
        client
            .streams
            .qcsd_local_et_stop_pending_or_in_flight(stream)
    );
    assert!(client.qcsd_has_pending_defense_control());

    // The ordinary peer's RESET_STREAM supplies final size and is the exact
    // receive-side terminal boundary for this client-only cancellation.
    client
        .streams
        .input_frame(
            &Frame::ResetStream {
                stream_id: stream,
                application_error_code: 0,
                final_size: 0,
            },
            &mut client.stats.borrow_mut().frame_rx,
        )
        .unwrap();
    client.qcsd_local_et_receive_state_changed(stream);
    assert!(!client.qcsd_has_pending_defense_control());
    assert!(!client.qcsd_unacked_local_et_stop_sending.contains(&stream));
}

#[test]
fn suppressed_outcomes_accept_only_typed_congestion_evidence() {
    for (slot, reason) in [
        (113, QcsdCongestionReason::CongestionLimited),
        (114, QcsdCongestionReason::PacingLimited),
    ] {
        let mut client = default_client();
        let mut server = default_server();
        connect_force_idle(&mut client, &mut server);
        client.qcsd_enable(QcsdEndpointId(7), false);
        let queued_at = now();
        queue_congestion_sensitive_target(&mut client, slot, 300, false, queued_at).unwrap();
        let target = client
            .qcsd_eligible_packet_target(queued_at)
            .expect("eligible target");
        client.qcsd_suppress_congestion_sensitive_target(&target, reason);
        assert!(drain_observations(&mut client).iter().any(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotResolved {
                    slot: observed_slot,
                    outcome: QcsdSlotOutcome::Suppressed {
                        reason: observed,
                        ..
                    },
                    ..
                } if *observed_slot == QcsdSlotId(slot) && *observed == reason
            )
        }));
    }
}

#[test]
fn pacing_limited_congestion_sensitive_target_is_suppressed_exactly_once() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    for _ in 0..=PACING_BURST_SIZE {
        assert!(client.process_output(now).dgram().is_some());
    }
    assert!(!client.process_output(now).callback().is_zero());

    queue_congestion_sensitive_target(&mut client, 116, 1_000, false, now).unwrap();
    _ = client.process_output(now);
    let first = drain_observations(&mut client);
    assert_eq!(
        first
            .iter()
            .filter(|observation| matches!(
                observation,
                QcsdObservation::SlotResolved {
                    slot: QcsdSlotId(116),
                    outcome: QcsdSlotOutcome::Suppressed {
                        reason: QcsdCongestionReason::PacingLimited,
                        ..
                    },
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 0);

    _ = client.process_output(now);
    assert!(!drain_observations(&mut client).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(116),
                ..
            }
        )
    }));
}

#[test]
fn mandatory_frame_failure_remains_a_missed_fidelity_error() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let queued_at = now();
    queue_congestion_sensitive_target(&mut client, 115, 300, false, queued_at).unwrap();
    let target = client
        .qcsd_eligible_packet_target(queued_at)
        .expect("eligible target");
    client.qcsd_miss_congestion_sensitive_target(&target, MissedSlotReason::MandatoryFrames);
    let observations = drain_observations(&mut client);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::SlotMissed {
            slot: QcsdSlotId(115),
            reason: MissedSlotReason::MandatoryFrames,
            ..
        }
    )));
    assert!(!observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::SlotResolved {
            slot: QcsdSlotId(115),
            ..
        }
    )));
}

#[test]
fn future_packet_target_is_fully_inert_until_not_before() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    client.qcsd_enable_stream_transcript(true);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    client
        .qcsd_register_stream_role(stream, QcsdRequestRole::Application)
        .unwrap();

    let drive_at = now();
    let release = drive_at + Duration::from_millis(100);
    let deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 300).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(QcsdSlotId(40), packet, release, deadline, false)
        .unwrap();

    let natural = client
        .process_multiple_output(drive_at, NonZeroUsize::new(2).unwrap())
        .dgram()
        .expect("ordinary stream output remains available");
    assert_eq!(
        natural.num_datagrams(),
        2,
        "a future target must not clamp ordinary output batching"
    );
    assert_eq!(client.qcsd_active_target, None);
    assert_eq!(client.qcsd_slot_send_budget, 0);
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    let transcript = client.qcsd_stream_transmissions();
    assert!(!transcript.is_empty());
    assert!(transcript.iter().all(|entry| entry.slot.is_none()));
    let observations = drain_observations(&mut client);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataTransmitted {
            role: QcsdRequestRole::Application,
            slot: None,
            ..
        }
    )));
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::ClassifiedDatagram {
            direction: Direction::Outgoing,
            class: QcsdDatagramClass::Natural,
            ..
        }
    )));
    assert!(!observations.iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::ClassifiedDatagram {
                direction: Direction::Outgoing,
                class: QcsdDatagramClass::DefenseCover,
                ..
            } | QcsdObservation::SlotSatisfied {
                slot: QcsdSlotId(40),
                ..
            }
        )
    }));
}

#[test]
fn future_packet_preview_cancels_by_exact_identity_without_an_outcome() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);

    let queued_at = now();
    let release = queued_at + Duration::from_millis(20);
    let deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::from_millis(20), Direction::Outgoing, 300).unwrap();
    client
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(41), packet, release, deadline, true)
        .unwrap();
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    assert_eq!(client.qcsd_packet_target_wakeup(queued_at), Some(release));

    let mismatch = Packet::new(Duration::from_millis(20), Direction::Outgoing, 301).unwrap();
    assert_eq!(
        client.qcsd_cancel_scheduled_packet_target(QcsdSlotId(41), mismatch),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);

    client
        .qcsd_cancel_scheduled_packet_target(QcsdSlotId(41), packet)
        .unwrap();
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
    assert_eq!(client.qcsd_packet_target_wakeup(queued_at), None);
    assert!(
        !drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    slot: QcsdSlotId(41),
                    ..
                } | QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(41),
                    ..
                } | QcsdObservation::SlotResolved {
                    slot: QcsdSlotId(41),
                    ..
                }
            ))
    );
}

#[test]
fn canceling_a_preview_preserves_its_committed_predecessor_wakeup() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let queued_at = now();
    let first_release = queued_at + Duration::from_millis(10);
    let first_deadline = first_release + Duration::from_millis(5);
    let second_release = first_deadline + Duration::from_millis(5);
    let second_deadline = second_release + Duration::from_millis(5);
    let first = Packet::new(Duration::from_millis(10), Direction::Outgoing, 300).unwrap();
    let second = Packet::new(Duration::from_millis(20), Direction::Outgoing, 300).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(46),
            first,
            first_release,
            first_deadline,
            true,
        )
        .unwrap();
    client
        .qcsd_prearm_scheduled_packet_target_window(
            QcsdSlotId(47),
            second,
            second_release,
            second_deadline,
            true,
        )
        .unwrap();
    client
        .qcsd_cancel_scheduled_packet_target(QcsdSlotId(47), second)
        .unwrap();
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    assert_eq!(
        client.qcsd_packet_target_wakeup(queued_at),
        Some(first_release)
    );
}

#[test]
fn future_packet_preview_is_inert_through_release_and_expiry() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);

    let queued_at = now();
    let release = queued_at + Duration::from_millis(20);
    let deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::from_millis(20), Direction::Outgoing, 300).unwrap();
    client
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(42), packet, release, deadline, true)
        .unwrap();

    _ = client.process_output(release);
    _ = client.process_output(deadline + Duration::from_micros(1));
    assert_eq!(client.qcsd_active_target, None);
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    assert!(!drain_observations(&mut client).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotSatisfied {
                slot: QcsdSlotId(42),
                ..
            } | QcsdObservation::SlotMissed {
                slot: QcsdSlotId(42),
                ..
            } | QcsdObservation::SlotResolved {
                slot: QcsdSlotId(42),
                ..
            }
        )
    }));
    client
        .qcsd_cancel_scheduled_packet_target(QcsdSlotId(42), packet)
        .unwrap();
}

#[test]
fn committed_preview_realizes_or_expires_with_one_terminal_outcome() {
    let mut realized = default_client();
    let mut server = default_server();
    connect_force_idle(&mut realized, &mut server);
    realized.qcsd_enable(QcsdEndpointId(7), true);
    let release = now() + Duration::from_millis(10);
    let deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::from_millis(10), Direction::Outgoing, 900).unwrap();
    realized
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(54), packet, release, deadline, true)
        .unwrap();
    realized
        .qcsd_commit_scheduled_packet_target(QcsdSlotId(54), packet)
        .unwrap();
    assert_eq!(realized.process_output(release).dgram().unwrap().len(), 900);
    let outcomes = drain_observations(&mut realized);
    assert_eq!(
        outcomes
            .iter()
            .filter(|observation| matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    slot: QcsdSlotId(54),
                    observed_size: 900,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(realized.qcsd_pending_packet_targets(), 0);
    _ = realized.process_output(release);
    assert!(
        !drain_observations(&mut realized).iter().any(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    slot: QcsdSlotId(54),
                    ..
                } | QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(54),
                    ..
                }
            )
        })
    );

    let mut expired = default_client();
    let mut server = default_server();
    connect_force_idle(&mut expired, &mut server);
    expired.qcsd_enable(QcsdEndpointId(7), true);
    let release = now() + Duration::from_millis(10);
    let deadline = release + Duration::from_millis(5);
    expired
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(55), packet, release, deadline, true)
        .unwrap();
    expired
        .qcsd_commit_scheduled_packet_target(QcsdSlotId(55), packet)
        .unwrap();
    _ = expired.process_output(deadline);
    let outcomes = drain_observations(&mut expired);
    assert_eq!(
        outcomes
            .iter()
            .filter(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(55),
                    reason: MissedSlotReason::DeadlineExpired,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(expired.qcsd_pending_packet_targets(), 0);
    _ = expired.process_output(deadline);
    assert!(!drain_observations(&mut expired).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotSatisfied {
                slot: QcsdSlotId(55),
                ..
            } | QcsdObservation::SlotMissed {
                slot: QcsdSlotId(55),
                ..
            }
        )
    }));
}

#[test]
fn preview_commit_identity_and_single_provisional_tail_are_fail_closed() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let release = now() + Duration::from_millis(10);
    let deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::from_millis(10), Direction::Outgoing, 900).unwrap();
    client
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(56), packet, release, deadline, true)
        .unwrap();
    assert_eq!(
        client.qcsd_commit_scheduled_packet_target(QcsdSlotId(57), packet),
        Err(Error::InvalidInput)
    );
    let mismatch = Packet::new(Duration::from_millis(10), Direction::Outgoing, 901).unwrap();
    assert_eq!(
        client.qcsd_commit_scheduled_packet_target(QcsdSlotId(56), mismatch),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        client.qcsd_prearm_scheduled_packet_target_window(
            QcsdSlotId(57),
            packet,
            deadline + Duration::from_millis(1),
            deadline + Duration::from_millis(2),
            true,
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    client
        .qcsd_cancel_scheduled_packet_target(QcsdSlotId(56), packet)
        .unwrap();
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
    assert!(drain_observations(&mut client).is_empty());
}

#[test]
fn preview_close_is_inert_but_committed_close_has_one_outcome() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let release = now() + Duration::from_secs(1);
    let deadline = release + Duration::from_secs(1);
    let packet = Packet::new(Duration::from_secs(1), Direction::Outgoing, 300).unwrap();
    client
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(43), packet, release, deadline, true)
        .unwrap();
    client.close(now(), 0, "close inert preview");
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
    assert!(
        !drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(43),
                    ..
                }
            ))
    );

    let mut committed = default_client();
    let mut server = default_server();
    connect_force_idle(&mut committed, &mut server);
    committed.qcsd_enable(QcsdEndpointId(7), true);
    let release = now() + Duration::from_secs(1);
    let deadline = release + Duration::from_secs(1);
    committed
        .qcsd_prearm_scheduled_packet_target_window(QcsdSlotId(44), packet, release, deadline, true)
        .unwrap();
    committed
        .qcsd_commit_scheduled_packet_target(QcsdSlotId(44), packet)
        .unwrap();
    assert_eq!(
        committed.qcsd_cancel_scheduled_packet_target(QcsdSlotId(44), packet),
        Err(Error::InvalidInput)
    );
    committed.close(now(), 0, "close committed preview");
    let outcomes = drain_observations(&mut committed)
        .into_iter()
        .filter(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(44),
                    reason: MissedSlotReason::EndpointClosed,
                    ..
                }
            )
        })
        .count();
    assert_eq!(outcomes, 1);
}

#[test]
fn rejected_packet_preview_never_publishes_a_slot_outcome() {
    let endpoint = QcsdEndpointId(7);
    let slot = QcsdSlotId(45);
    let packet = Packet::new(Duration::from_secs(1), Direction::Outgoing, 300).unwrap();
    let release = now() + Duration::from_secs(1);
    let deadline = release + Duration::from_secs(1);
    let mut disconnected = default_client();
    disconnected.qcsd_enable(endpoint, true);
    assert_eq!(
        disconnected
            .qcsd_prearm_scheduled_packet_target_window(slot, packet, release, deadline, true,),
        Err(Error::NotAvailable)
    );
    assert!(drain_observations(&mut disconnected).is_empty());

    let mut connected = default_client();
    let mut server = default_server();
    connect_force_idle(&mut connected, &mut server);
    connected.qcsd_enable(endpoint, true);
    connected.qcsd_set_udp_payload_ceiling(1_200).unwrap();
    let oversized = Packet::new(Duration::from_secs(1), Direction::Outgoing, 1_201).unwrap();
    assert_eq!(
        connected
            .qcsd_prearm_scheduled_packet_target_window(slot, oversized, release, deadline, true,),
        Err(Error::InvalidInput)
    );
    assert!(drain_observations(&mut connected).is_empty());
}

#[test]
fn resolved_target_leaves_future_successor_fully_inert() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);

    let release = now();
    let first_deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 300).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(48),
            packet,
            release,
            first_deadline,
            true,
        )
        .unwrap();
    let future_release = first_deadline + Duration::from_millis(10);
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(49),
            packet,
            future_release,
            future_release + Duration::from_millis(5),
            true,
        )
        .unwrap();

    assert_eq!(client.process_output(release).dgram().unwrap().len(), 300);
    assert_eq!(client.qcsd_active_target, None);
    assert_eq!(client.qcsd_slot_send_budget, 0);
    assert_eq!(client.qcsd_pending_packet_targets(), 1);

    _ = client.process_output(first_deadline);
    assert_eq!(client.qcsd_active_target, None);
    assert_eq!(client.qcsd_slot_send_budget, 0);
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    assert!(!drain_observations(&mut client).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotSatisfied {
                slot: QcsdSlotId(49),
                ..
            }
        )
    }));
}

#[test]
fn legacy_qcsd_enable_methods_preserve_unit_signatures() {
    const ENABLE: fn(&mut Connection, QcsdEndpointId, bool) = Connection::qcsd_enable;
    const ENABLE_WITH_CLOCK: fn(&mut Connection, QcsdEndpointId, bool, QcsdObservationClock) =
        Connection::qcsd_enable_with_observation_clock;

    let mut direct = default_client();
    ENABLE(&mut direct, QcsdEndpointId(6), false);
    assert_eq!(direct.qcsd_endpoint, Some(QcsdEndpointId(6)));

    let mut shared = default_client();
    ENABLE_WITH_CLOCK(
        &mut shared,
        QcsdEndpointId(7),
        false,
        QcsdObservationClock::new(now()),
    );
    assert_eq!(shared.qcsd_endpoint, Some(QcsdEndpointId(7)));
}

#[test]
fn checked_qcsd_rebind_is_rejected_atomically() {
    let endpoint = QcsdEndpointId(7);
    let mut client = default_client();
    let clock = QcsdObservationClock::new(now());
    client
        .qcsd_try_enable_with_observation_clock(endpoint, false, clock.clone())
        .expect("initial checked bind");
    assert_eq!(
        clock
            .record_at(QcsdObservation::EndpointClosed { endpoint }, now())
            .sequence(),
        0
    );

    assert_eq!(
        client.qcsd_try_enable(QcsdEndpointId(8), true),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        client.qcsd_try_enable_with_observation_clock(
            QcsdEndpointId(9),
            true,
            QcsdObservationClock::new(now()),
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_endpoint, Some(endpoint));
    assert!(!client.qcsd_send_shaping);
    assert_eq!(
        client
            .qcsd_observation_clock
            .as_ref()
            .expect("original clock retained")
            .record_at(QcsdObservation::EndpointClosed { endpoint }, now())
            .sequence(),
        1
    );
}

#[test]
fn legacy_qcsd_rebind_is_a_noop_that_preserves_endpoint_and_clock() {
    let endpoint = QcsdEndpointId(7);
    let mut client = default_client();
    let clock = QcsdObservationClock::new(now());
    client.qcsd_enable_with_observation_clock(endpoint, false, clock.clone());
    assert_eq!(
        clock
            .record_at(QcsdObservation::EndpointClosed { endpoint }, now())
            .sequence(),
        0
    );

    client.qcsd_enable(QcsdEndpointId(8), true);
    client.qcsd_enable_with_observation_clock(
        QcsdEndpointId(9),
        true,
        QcsdObservationClock::new(now()),
    );
    assert_eq!(client.qcsd_endpoint, Some(endpoint));
    assert!(!client.qcsd_send_shaping);
    assert_eq!(
        client
            .qcsd_observation_clock
            .as_ref()
            .expect("original clock retained")
            .record_at(QcsdObservation::EndpointClosed { endpoint }, now())
            .sequence(),
        1
    );
}

#[test]
fn packet_target_outcome_keeps_its_enqueue_endpoint_after_checked_rebind_attempt() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let release = now() + Duration::from_millis(10);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 900).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(50),
            packet,
            release,
            release + Duration::from_millis(5),
            false,
        )
        .unwrap();
    assert_eq!(
        client.qcsd_try_enable(QcsdEndpointId(8), false),
        Err(Error::InvalidInput),
        "an established target binding cannot be replaced"
    );

    assert_eq!(client.process_output(release).dgram().unwrap().len(), 900);
    let outcomes: Vec<_> = drain_observations(&mut client)
        .into_iter()
        .filter(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    slot: QcsdSlotId(50),
                    ..
                }
            )
        })
        .collect();
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(
        outcomes[0],
        QcsdObservation::SlotSatisfied {
            endpoint: QcsdEndpointId(7),
            slot: QcsdSlotId(50),
            ..
        }
    ));

    let second_release = release + Duration::from_millis(10);
    let second_deadline = second_release + Duration::from_millis(5);
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(51),
            packet,
            second_release,
            second_deadline,
            false,
        )
        .unwrap();
    _ = client.process_output(second_deadline);
    let misses: Vec<_> = drain_observations(&mut client)
        .into_iter()
        .filter(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(51),
                    ..
                }
            )
        })
        .collect();
    assert_eq!(misses.len(), 1);
    assert!(matches!(
        misses[0],
        QcsdObservation::SlotMissed {
            endpoint: QcsdEndpointId(7),
            slot: QcsdSlotId(51),
            reason: MissedSlotReason::DeadlineExpired,
            ..
        }
    ));
}

#[test]
fn expired_head_does_not_disable_live_successor_batch_clamp() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);

    let drive_at = now() + Duration::from_millis(10);
    let expired_release = drive_at
        .checked_sub(Duration::from_nanos(2))
        .expect("fixture instant permits subtraction");
    let expired_deadline = drive_at
        .checked_sub(Duration::from_nanos(1))
        .expect("fixture instant permits subtraction");
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 900).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(52),
            packet,
            expired_release,
            expired_deadline,
            false,
        )
        .unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(53),
            packet,
            drive_at,
            drive_at + Duration::from_millis(5),
            false,
        )
        .unwrap();

    let batch = client
        .process_multiple_output(drive_at, NonZeroUsize::new(2).unwrap())
        .dgram()
        .expect("live successor emits its target");
    assert_eq!(
        batch.num_datagrams(),
        1,
        "an eligible successor clamps the entire output batch"
    );
    assert_eq!(batch.iter().next().unwrap().len(), 900);
    let observations = drain_observations(&mut client);
    assert_eq!(
        observations
            .iter()
            .filter(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(52),
                    reason: MissedSlotReason::DeadlineExpired,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        observations
            .iter()
            .filter(|observation| matches!(
                observation,
                QcsdObservation::SlotSatisfied {
                    slot: QcsdSlotId(53),
                    ..
                }
            ))
            .count(),
        1
    );
}

#[test]
fn mandatory_ack_before_release_is_unattributed() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let sent_at = now();
    let stream = server.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut server, stream);
    let incoming = server
        .process_output(sent_at)
        .dgram()
        .expect("server stream packet");
    client.process_input(incoming, sent_at);

    let ack_at = sent_at + DEFAULT_RTT;
    let release = ack_at + Duration::from_secs(1);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window_with_policy(
            QcsdSlotId(41),
            packet,
            release,
            release + Duration::from_millis(5),
            false,
            QcsdSendPolicy::CongestionSensitive,
        )
        .unwrap();
    let acknowledgment = client
        .process_output(ack_at)
        .dgram()
        .expect("mandatory acknowledgment");
    assert_ne!(acknowledgment.len(), 1_000);
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    let observations = drain_observations(&mut client);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::ClassifiedDatagram {
            direction: Direction::Outgoing,
            class: QcsdDatagramClass::Natural,
            ..
        }
    )));
    assert!(!observations.iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::ClassifiedDatagram {
                direction: Direction::Outgoing,
                class: QcsdDatagramClass::DefenseCover,
                ..
            } | QcsdObservation::SlotSatisfied {
                slot: QcsdSlotId(41),
                ..
            } | QcsdObservation::SlotResolved {
                slot: QcsdSlotId(41),
                ..
            }
        )
    }));
}

#[test]
fn packet_target_activates_at_release_and_expires_at_deadline() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);

    let queued_at = now();
    let release = queued_at + Duration::from_millis(10);
    let deadline = release + Duration::from_millis(5);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 900).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(QcsdSlotId(42), packet, release, deadline, false)
        .unwrap();
    let just_before_release = release
        .checked_sub(Duration::from_nanos(1))
        .expect("release is after the fixture epoch");
    assert_eq!(
        client.process_output(just_before_release).callback(),
        Duration::from_nanos(1),
        "the transport must wake exactly at the target release"
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
    assert_eq!(client.process_output(release).dgram().unwrap().len(), 900);
    assert!(drain_observations(&mut client).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotSatisfied {
                slot: QcsdSlotId(42),
                ..
            }
        )
    }));

    let second_release = deadline + Duration::from_millis(10);
    let second_deadline = second_release + Duration::from_millis(5);
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(43),
            packet,
            second_release,
            second_deadline,
            false,
        )
        .unwrap();
    _ = client.process_output(second_deadline);
    assert!(drain_observations(&mut client).iter().any(|observation| {
        matches!(
            observation,
            QcsdObservation::SlotMissed {
                slot: QcsdSlotId(43),
                reason: MissedSlotReason::DeadlineExpired,
                ..
            }
        )
    }));
}

#[test]
fn packet_target_rejects_inverted_and_nonmonotonic_windows() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 900).unwrap();
    let base = now();
    let release = base + Duration::from_millis(10);
    let deadline = release + Duration::from_millis(5);
    client
        .qcsd_queue_scheduled_packet_target_window(QcsdSlotId(44), packet, release, deadline, false)
        .unwrap();
    assert_eq!(
        client.qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(45),
            packet,
            deadline,
            deadline,
            false,
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        client.qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(46),
            packet,
            release
                .checked_sub(Duration::from_nanos(1))
                .expect("release is after the fixture epoch"),
            deadline + Duration::from_nanos(1),
            false,
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        client.qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(47),
            packet,
            release + Duration::from_nanos(1),
            deadline
                .checked_sub(Duration::from_nanos(1))
                .expect("deadline is after the fixture epoch"),
            false,
        ),
        Err(Error::InvalidInput)
    );
    assert_eq!(client.qcsd_pending_packet_targets(), 1);
}

#[test]
fn expired_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    let deadline = now();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(12),
            packet,
            deadline
                .checked_sub(Duration::from_nanos(1))
                .expect("deadline is after the fixture epoch"),
            deadline,
            false,
        )
        .unwrap();
    _ = client.process_output(deadline);
    assert!(
        drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(12),
                    reason: MissedSlotReason::DeadlineExpired,
                    ..
                }
            ))
    );
}

#[test]
fn congestion_limited_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let (_dropped, exhausted_at) = fill_cwnd(&mut client, stream, now());
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(14),
            packet,
            exhausted_at
                .checked_sub(Duration::from_nanos(1))
                .expect("deadline is after the fixture epoch"),
            exhausted_at,
            false,
        )
        .unwrap();
    _ = client.process_output(exhausted_at);
    assert!(
        drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(14),
                    reason: MissedSlotReason::CongestionLimited,
                    ..
                }
            ))
    );
}

#[test]
fn pacing_limited_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    let now = connect_rtt_idle(&mut client, &mut server, DEFAULT_RTT);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    fill_stream(&mut client, stream);
    for _ in 0..=PACING_BURST_SIZE {
        assert!(client.process_output(now).dgram().is_some());
    }
    assert!(!client.process_output(now).callback().is_zero());

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(15),
            packet,
            now.checked_sub(Duration::from_nanos(1))
                .expect("deadline is after the fixture epoch"),
            now,
            false,
        )
        .unwrap();
    _ = client.process_output(now);
    assert!(
        drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::SlotMissed {
                    slot: QcsdSlotId(15),
                    reason: MissedSlotReason::PacingLimited,
                    ..
                }
            ))
    );
}

#[test]
fn endpoint_close_retires_future_target_once() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let queued_at = now();
    let not_before = queued_at + Duration::from_secs(1);
    let deadline = not_before + Duration::from_secs(1);
    for slot in [20, 21] {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
        client
            .qcsd_queue_scheduled_packet_target_window(
                QcsdSlotId(slot),
                packet,
                not_before,
                deadline,
                false,
            )
            .unwrap();
    }
    client.close(now(), 0, "test close");
    let misses: Vec<_> = drain_observations(&mut client)
        .into_iter()
        .filter_map(|observation| {
            matches!(
                &observation,
                QcsdObservation::SlotMissed {
                    reason: MissedSlotReason::EndpointClosed,
                    ..
                }
            )
            .then_some(observation)
        })
        .collect();
    assert_eq!(misses.len(), 2);
    let slots: std::collections::BTreeSet<_> = misses
        .iter()
        .filter_map(|observation| match observation {
            QcsdObservation::SlotMissed { slot, .. } => Some(*slot),
            _ => None,
        })
        .collect();
    assert_eq!(slots, [QcsdSlotId(20), QcsdSlotId(21)].into());
    assert!(misses.iter().all(|observation| matches!(
        observation,
        QcsdObservation::SlotMissed {
            endpoint: QcsdEndpointId(7),
            ..
        }
    )));
    client.close(now(), 0, "duplicate close");
    assert!(drain_observations(&mut client).is_empty());
    assert_eq!(client.qcsd_pending_packet_targets(), 0);
}

#[test]
fn manual_receive_credit_is_reported_only_after_encoding() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let limit = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap() + 100;
    let slot = QcsdSlotId(99);
    client
        .qcsd_set_stream_receive_limit_for_slot(stream, limit, slot)
        .unwrap();
    assert!(drain_observations(&mut client).is_empty());
    _ = client.process_output(now()).dgram().unwrap();
    assert!(
        drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::ReceiveLimitAdvertised {
                    stream: observed_stream,
                    absolute_limit,
                    slot: Some(observed_slot),
                    ..
                } if observed_stream.0 == stream.as_u64()
                    && *absolute_limit == limit
                    && *observed_slot == slot
            ))
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "typed lifecycle, pending-ledger monotonicity, and exact parser/scheduled identities form one transport oracle"
)]
fn receive_limit_action_preview_is_typed_and_includes_pending_ledger() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let initial = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap();
    client
        .qcsd_set_stream_receive_limit(stream, initial)
        .expect("initial manual limit");
    let identity = QcsdReceiveActionIdentity::Scheduled {
        endpoint: QcsdEndpointId(0),
        stream: QcsdStreamId(stream.as_u64()),
        absolute_limit: initial + 10,
        slot: QcsdSlotId(4),
    };
    assert_eq!(
        client.qcsd_preview_stream_receive_limit_action(
            stream,
            initial + 10,
            Some(identity),
            None,
            None,
            true,
        ),
        Ok(QcsdReceiveLimitOutcome::Applied)
    );
    assert_eq!(
        client.qcsd_apply_stream_receive_limit_action(
            stream,
            initial + 10,
            Some(identity),
            None,
            true,
        ),
        Ok(QcsdReceiveLimitOutcome::Applied)
    );
    assert_eq!(
        client
            .qcsd_preview_stream_receive_limit_action(
                stream,
                initial + 10,
                Some(identity),
                None,
                None,
                true,
            )
            .expect_err("duplicate pending ledger entry")
            .kind,
        QcsdReceiveLimitFatal::Ledger
    );
    assert_eq!(
        client
            .qcsd_preview_stream_receive_limit_action(
                stream,
                initial + 9,
                Some(QcsdReceiveActionIdentity::Scheduled {
                    endpoint: QcsdEndpointId(0),
                    stream: QcsdStreamId(stream.as_u64()),
                    absolute_limit: initial + 9,
                    slot: QcsdSlotId(5),
                }),
                None,
                None,
                true,
            )
            .expect_err("pending manual limit cannot decrease")
            .kind,
        QcsdReceiveLimitFatal::Order
    );
    assert_eq!(
        client
            .qcsd_preview_stream_receive_limit_action(
                stream,
                initial + 13,
                Some(QcsdReceiveActionIdentity::ParserLease {
                    endpoint: QcsdEndpointId(0),
                    stream: QcsdStreamId(stream.as_u64()),
                    absolute_limit: initial + 13,
                    increase: 4,
                    owner: None,
                }),
                None,
                Some(initial + 9),
                true,
            )
            .expect_err("parser range must join the pending limit")
            .kind,
        QcsdReceiveLimitFatal::Ledger
    );
    assert_eq!(
        client.qcsd_preview_stream_receive_limit_action(
            crate::StreamId::new(stream.as_u64() + 400),
            initial + 10,
            None,
            None,
            None,
            true,
        ),
        Ok(QcsdReceiveLimitOutcome::Gone)
    );
    assert_eq!(
        client.qcsd_pending_receive_action_identities(),
        vec![identity]
    );
    client
        .qcsd_preview_receive_action_cancellation(&[identity])
        .expect("pending action is cancelable");
    client
        .qcsd_commit_receive_action_cancellation(&[identity])
        .expect("pending action cancellation");
    assert!(client.qcsd_pending_receive_action_identities().is_empty());
}

#[test]
fn typed_receive_identity_is_removed_only_after_actual_encoding() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let endpoint = QcsdEndpointId(7);
    client.qcsd_enable(endpoint, false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let initial = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap();
    client
        .qcsd_set_stream_receive_limit(stream, initial)
        .expect("manual receive");
    let identity = QcsdReceiveActionIdentity::Scheduled {
        endpoint,
        stream: QcsdStreamId(stream.as_u64()),
        absolute_limit: initial + 10,
        slot: QcsdSlotId(44),
    };
    client
        .qcsd_apply_stream_receive_limit_action(stream, initial + 10, Some(identity), None, true)
        .expect("apply typed limit");
    assert_eq!(
        client.qcsd_pending_receive_action_identities(),
        vec![identity]
    );
    _ = client.process_output(now()).dgram().expect("encode limit");
    assert!(client.qcsd_pending_receive_action_identities().is_empty());
    assert_eq!(
        client
            .qcsd_preview_receive_action_cancellation(&[identity])
            .expect_err("encoded identity cannot be revoked")
            .kind,
        QcsdReceiveLimitFatal::Ledger
    );
}

#[test]
fn retained_final_size_can_cancel_an_earlier_cross_batch_pending_limit() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let endpoint = QcsdEndpointId(7);
    client.qcsd_enable(endpoint, false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let initial = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap();
    client
        .qcsd_set_stream_receive_limit(stream, initial)
        .expect("manual receive");
    let first = QcsdReceiveActionIdentity::Scheduled {
        endpoint,
        stream: QcsdStreamId(stream.as_u64()),
        absolute_limit: initial + 10,
        slot: QcsdSlotId(51),
    };
    client
        .qcsd_apply_stream_receive_limit_action(stream, initial + 10, Some(first), None, true)
        .expect("accept first batch action");
    client
        .streams
        .get_recv_stream_mut(stream)
        .expect("receive stream")
        .inbound_stream_frame(true, 10, &[])
        .expect("FIN with gap");
    let second = QcsdReceiveActionIdentity::Scheduled {
        endpoint,
        stream: QcsdStreamId(stream.as_u64()),
        absolute_limit: initial + 20,
        slot: QcsdSlotId(52),
    };
    assert_eq!(
        client.qcsd_preview_stream_receive_limit_action(
            stream,
            initial + 20,
            Some(second),
            None,
            None,
            true,
        ),
        Ok(QcsdReceiveLimitOutcome::FinalKnown)
    );
    client
        .qcsd_preview_receive_action_cancellation(&[first])
        .expect("retained final-known FC previews rollback");
    client
        .qcsd_commit_receive_action_cancellation(&[first])
        .expect("retained final-known FC commits rollback");
    assert!(client.qcsd_pending_receive_action_identities().is_empty());
}

#[test]
fn endpoint_close_retains_pending_identity_tombstone_until_reconciliation() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let endpoint = QcsdEndpointId(7);
    client.qcsd_enable(endpoint, false);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    let initial = u64::try_from(INITIAL_LOCAL_MAX_STREAM_DATA).unwrap();
    client
        .qcsd_set_stream_receive_limit(stream, initial)
        .expect("manual receive");
    let identity = QcsdReceiveActionIdentity::Scheduled {
        endpoint,
        stream: QcsdStreamId(stream.as_u64()),
        absolute_limit: initial + 10,
        slot: QcsdSlotId(61),
    };
    client
        .qcsd_apply_stream_receive_limit_action(stream, initial + 10, Some(identity), None, true)
        .expect("pending action");
    client.close(now(), 0, "close before encoding");
    assert_eq!(
        client.qcsd_pending_receive_action_identities(),
        vec![identity]
    );
    client
        .qcsd_preview_receive_action_cancellation(&[identity])
        .expect("closed tombstone previews");
    client
        .qcsd_commit_receive_action_cancellation(&[identity])
        .expect("closed tombstone reconciles");
    assert!(client.qcsd_pending_receive_action_identities().is_empty());
}

#[test]
fn terminal_automatic_receive_configuration_is_typed_noop() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client
        .streams
        .get_recv_stream_mut(stream)
        .expect("receive stream")
        .inbound_stream_frame(true, 10, &[])
        .expect("FIN with gap");
    assert_eq!(
        client.qcsd_stream_receive_lifecycle(stream),
        QcsdReceiveLimitOutcome::FinalKnown
    );
    assert_eq!(
        client.qcsd_apply_stream_auto_receive_action(stream, 1_024),
        Ok(QcsdReceiveLimitOutcome::FinalKnown)
    );
    let gone = crate::StreamId::new(stream.as_u64() + 400);
    assert_eq!(
        client.qcsd_apply_stream_auto_receive_action(gone, 1_024),
        Ok(QcsdReceiveLimitOutcome::Gone)
    );
}

#[test]
fn legacy_manual_receive_limit_preserves_terminal_error_mapping() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    let stream = client.stream_create(StreamType::BiDi).unwrap();
    client
        .streams
        .get_recv_stream_mut(stream)
        .expect("receive stream")
        .inbound_stream_frame(true, 10, &[])
        .expect("FIN with gap");
    assert_eq!(
        client.qcsd_set_stream_receive_limit(stream, 1_024),
        Err(Error::InvalidInput),
        "legacy existing-stream terminal mapping is stable"
    );
    assert_eq!(
        client.qcsd_set_stream_receive_limit(crate::StreamId::new(stream.as_u64() + 400), 1_024,),
        Err(Error::InvalidStreamId),
        "only an absent receive stream uses InvalidStreamId"
    );
}

#[test]
fn shaped_slot_sends_application_before_chaff() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(chaff, &[0xCC; 1_000]).unwrap();
    client.stream_send(application, &[0xAA; 1_000]).unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 120).unwrap();
    let queued_at = now();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(13),
            packet,
            queued_at,
            queued_at + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let datagram = client.process_output(now()).dgram().unwrap();
    let observations = drain_observations(&mut client);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataTransmitted {
            endpoint: QcsdEndpointId(7),
            stream,
            role: QcsdRequestRole::Application,
            offset: 0,
            bytes,
            ..
        } if stream.0 == application.as_u64() && *bytes > 0
    )));
    assert!(!observations.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataTransmitted {
            role: QcsdRequestRole::Chaff { .. },
            ..
        }
    )));
    server.process_input(datagram, now());
    let mut buffer = [0; 1_024];
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert!(read > 0);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    if let Ok((read, _)) = server.stream_recv(chaff, &mut buffer) {
        assert_eq!(read, 0);
    }
}

#[test]
fn chaff_only_target_does_not_consume_application_stream_data() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 400]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();

    queue_target(&mut client, 40, 900, false).unwrap();
    let cover = client.process_output(now()).dgram().unwrap();
    assert_eq!(cover.len(), 900);
    server.process_input(cover, now());
    let mut buffer = [0; 512];
    assert!(server.stream_recv(application, &mut buffer).is_err());

    let application_datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(application_datagram, now());
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 400);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
}

#[test]
fn chaff_can_finish_after_outgoing_shaping_is_released() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(chaff, &[0xCC; 400]).unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();
    assert!(client.process_output(now()).dgram().is_none());

    client.qcsd_release_chaff_send_shaping();
    let datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(datagram, now());
    let mut buffer = [0; 512];
    let (read, _) = server.stream_recv(chaff, &mut buffer).unwrap();
    assert_eq!(read, 400);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xCC));
}

#[test]
fn cs_local_et_releases_only_application_sends_and_reenable_resets_the_proof() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 400]).unwrap();
    client.stream_send(chaff, &[0xCC; 400]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();
    assert!(client.process_output(now()).dgram().is_none());

    client.qcsd_release_application_send_shaping();
    let datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(datagram, now());
    let mut buffer = [0; 512];
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 400);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    assert!(server.stream_recv(chaff, &mut buffer).is_err());

    client.stream_send(application, &[0xBB; 100]).unwrap();
    client.qcsd_enable_send_shaping(true);
    assert!(client.process_output(now()).dgram().is_none());
    queue_target(&mut client, 91, 120, false).expect("control-only target");
    client.qcsd_release_application_send_shaping();
    let datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(datagram, now());
    let control_only_application = server.stream_recv(application, &mut buffer);
    if let Ok((read, fin)) = control_only_application {
        assert_eq!((read, fin), (0, false));
    }
    assert!(server.stream_recv(chaff, &mut buffer).is_err());

    let datagram = client.process_output(now()).dgram().unwrap();
    server.process_input(datagram, now());
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 100);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xBB));
    assert!(server.stream_recv(chaff, &mut buffer).is_err());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one loss-recovery oracle verifies original mixed transmission, selective release, and peer ACK"
)]
fn cs_local_et_application_release_recovers_only_application_after_mixed_loss() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);

    let application = client.stream_create(StreamType::BiDi).unwrap();
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 800]).unwrap();
    client.stream_close_send(application).unwrap();
    client.stream_send(chaff, &[0xCC; 800]).unwrap();
    client.stream_close_send(chaff).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();

    let mut original_observations = Vec::new();
    for slot in [92, 93] {
        queue_target(&mut client, slot, 1_200, true).unwrap();
        let dropped = client
            .process_output(now())
            .dgram()
            .expect("shaped packet carrying original stream data");
        assert_eq!(dropped.len(), 1_200);
        original_observations.extend(drain_observations(&mut client));
    }
    let transmitted = |role: QcsdRequestRole| {
        original_observations
            .iter()
            .filter_map(|observation| match observation {
                QcsdObservation::StreamDataTransmitted {
                    role: observed_role,
                    bytes,
                    ..
                } if *observed_role == role => Some(*bytes),
                _ => None,
            })
            .sum::<u64>()
    };
    assert_eq!(transmitted(QcsdRequestRole::Application), 800);
    assert_eq!(
        transmitted(QcsdRequestRole::Chaff {
            resource_id: 1,
            request_id: None,
        }),
        800
    );

    let recovery_at = now() + AT_LEAST_PTO;
    drop(client.process_output(recovery_at));
    let mut buffer = [0; 1_024];
    assert!(server.stream_recv(application, &mut buffer).is_err());
    assert!(server.stream_recv(chaff, &mut buffer).is_err());

    client.qcsd_release_application_send_shaping();
    let recovery = client
        .process_output(recovery_at)
        .dgram()
        .expect("application retransmission becomes targetless after local ET");
    server.process_input(recovery, recovery_at);
    let (read, fin) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 800);
    assert!(fin);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    if let Ok((read, fin)) = server.stream_recv(chaff, &mut buffer) {
        assert_eq!((read, fin), (0, false));
    }

    let ack_at = recovery_at + DEFAULT_RTT;
    let acknowledgment = server
        .process_output(ack_at)
        .dgram()
        .expect("peer acknowledgment for recovered application data");
    client.process_input(acknowledgment, ack_at);
    let acknowledged = drain_observations(&mut client);
    assert!(acknowledged.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataAcknowledged {
            stream,
            role: QcsdRequestRole::Application,
            offset: 0,
            bytes: 800,
            fin: true,
            ..
        } if stream.0 == application.as_u64()
    )));
    assert!(!acknowledged.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataAcknowledged {
            role: QcsdRequestRole::Chaff { .. },
            ..
        }
    )));
    drop(client.process_output(ack_at));
    let post_acknowledgment = drain_observations(&mut client);
    assert!(
        !post_acknowledgment.iter().any(|observation| matches!(
            observation,
            QcsdObservation::StreamDataTransmitted { .. }
        ))
    );
}

#[test]
fn shaped_chaff_request_waits_for_a_target_and_reports_complete_peer_ack() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    let role = QcsdRequestRole::Chaff {
        resource_id: 1,
        request_id: None,
    };
    client.stream_send(chaff, &[0xCC; 400]).unwrap();
    client.stream_close_send(chaff).unwrap();
    client.qcsd_register_stream_role(chaff, role).unwrap();

    // Locally queued chaff data, including FIN, cannot cross without a molded
    // outgoing target while stream-send shaping is active.
    assert!(client.process_output(now()).dgram().is_none());
    assert!(
        !drain_observations(&mut client)
            .iter()
            .any(|observation| matches!(
                observation,
                QcsdObservation::StreamDataTransmitted {
                    role: QcsdRequestRole::Chaff { .. },
                    ..
                } | QcsdObservation::StreamDataAcknowledged { .. }
            ))
    );
    assert!(
        client.qcsd_stream_transmissions().is_empty(),
        "the qualifier transcript is default-disabled"
    );

    client.qcsd_enable_stream_transcript(true);
    queue_target(&mut client, 41, 1_200, true).unwrap();
    let sent_at = now();
    let request = client
        .process_output(sent_at)
        .dgram()
        .expect("molded target carries the chaff request");
    let transmitted = drain_observations(&mut client);
    assert!(transmitted.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataTransmitted {
            endpoint: QcsdEndpointId(7),
            stream,
            role: observed_role,
            offset: 0,
            bytes: 400,
            fin: true,
            slot: Some(QcsdSlotId(41)),
        } if stream.0 == chaff.as_u64() && *observed_role == role
    )));
    assert!(
        !transmitted.iter().any(|observation| matches!(
            observation,
            QcsdObservation::StreamDataAcknowledged { .. }
        ))
    );
    let transcript = client.qcsd_stream_transmissions();
    assert!(!transcript.is_empty());
    assert!(transcript.iter().enumerate().all(|(sequence, entry)| {
        entry.sequence == u64::try_from(sequence).unwrap()
            && entry.stream.0 == chaff.as_u64()
            && entry.slot == Some(QcsdSlotId(41))
    }));
    assert_eq!(transcript.iter().map(|entry| entry.bytes).sum::<u64>(), 400);
    assert!(transcript.iter().any(|entry| entry.fin));

    server.process_input(request, sent_at);
    let mut received = [0; 512];
    let (read, fin) = server.stream_recv(chaff, &mut received).unwrap();
    assert_eq!(read, 400);
    assert!(fin);
    let ack_at = sent_at + DEFAULT_RTT;
    let acknowledgment = server
        .process_output(ack_at)
        .dgram()
        .expect("delayed peer acknowledgment");
    client.process_input(acknowledgment, ack_at);

    let acknowledged = drain_observations(&mut client);
    assert!(acknowledged.iter().any(|observation| matches!(
        observation,
        QcsdObservation::StreamDataAcknowledged {
            endpoint: QcsdEndpointId(7),
            stream,
            role: observed_role,
            offset: 0,
            bytes: 400,
            fin: true,
        } if stream.0 == chaff.as_u64() && *observed_role == role
    )));
}

#[test]
fn natural_stream_transcript_is_targetless_and_each_packet_token_is_recorded_once() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    client.qcsd_enable_stream_transcript(true);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 3_000]).unwrap();
    client.stream_close_send(application).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();

    let mut sent = 0_usize;
    while let Some(datagram) = client.process_output(now()).dgram() {
        sent += 1;
        server.process_input(datagram, now());
    }
    assert!(sent > 1, "fixture must exercise multiple packet assemblies");
    let transcript = client.qcsd_stream_transmissions();
    assert!(transcript.len() > 1);
    assert!(transcript.iter().enumerate().all(|(sequence, entry)| {
        entry.sequence == u64::try_from(sequence).unwrap()
            && entry.stream.0 == application.as_u64()
            && entry.slot.is_none()
    }));
    let mut ranges: Vec<_> = transcript
        .iter()
        .filter(|entry| entry.bytes > 0)
        .map(|entry| (entry.offset, entry.offset + entry.bytes))
        .collect();
    ranges.sort_unstable();
    assert_eq!(ranges.first().map(|range| range.0), Some(0));
    assert_eq!(ranges.last().map(|range| range.1), Some(3_000));
    assert!(ranges.windows(2).all(|pair| {
        pair.first()
            .zip(pair.last())
            .is_some_and(|(first, last)| first.1 == last.0)
    }));
    assert_eq!(
        transcript.iter().map(|entry| entry.bytes).sum::<u64>(),
        3_000,
        "cumulative recovery tokens must not be recorded twice"
    );
    assert!(transcript.iter().any(|entry| entry.fin));
}

#[test]
fn lost_application_data_waits_for_a_later_shaped_slot() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAA; 1_000]).unwrap();
    client.stream_send(chaff, &[0xCC; 1_000]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).unwrap();
    let queued_at = now();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(30),
            packet,
            queued_at,
            queued_at + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let dropped = client.process_output(now()).dgram().unwrap();
    assert_eq!(dropped.len(), 1_200);

    let recovery_time = now() + AT_LEAST_PTO;
    _ = client.process_output(recovery_time);
    let mut buffer = [0; 1_024];
    assert!(server.stream_recv(application, &mut buffer).is_err());

    queue_congestion_sensitive_target(&mut client, 31, 1_200, true, recovery_time).unwrap();
    let retransmission = client.process_output(recovery_time).dgram().unwrap();
    assert_eq!(retransmission.len(), 1_200);
    let composition = drain_observations(&mut client)
        .into_iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(31),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(composition),
            _ => None,
        })
        .expect("retransmission target has typed wire composition");
    assert_eq!(composition.application_stream_bytes, 0);
    assert!(composition.retransmission_stream_bytes > 0);
    server.process_input(retransmission, recovery_time);
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 1_000);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    if let Ok((read, _)) = server.stream_recv(chaff, &mut buffer) {
        assert!(buffer[..read].iter().all(|byte| *byte == 0xCC));
    }
}

#[test]
fn mixed_lost_prefix_and_fresh_suffix_keep_exact_composition_and_fill_the_slot() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let application = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(application, &[0xAB; 3_000]).unwrap();
    client
        .qcsd_register_stream_role(application, QcsdRequestRole::Application)
        .unwrap();

    let queued_at = now();
    let first = Packet::new(Duration::ZERO, Direction::Outgoing, 600).unwrap();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(34),
            first,
            queued_at,
            queued_at + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let dropped = client.process_output(queued_at).dgram().unwrap();
    assert_eq!(dropped.len(), 600);
    _ = drain_observations(&mut client);

    let recovery_time = queued_at + AT_LEAST_PTO;
    _ = client.process_output(recovery_time);
    queue_congestion_sensitive_target(&mut client, 35, 1_200, true, recovery_time).unwrap();
    let mixed = client.process_output(recovery_time).dgram().unwrap();
    assert_eq!(mixed.len(), 1_200);
    let composition = drain_observations(&mut client)
        .into_iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(35),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(composition),
            _ => None,
        })
        .expect("mixed recovery target has typed wire composition");
    assert!(composition.retransmission_stream_bytes > 0);
    assert!(composition.application_stream_bytes > 0);
    assert_eq!(composition.chaff_stream_bytes, 0);
    assert!(composition.quic_padding_bytes < 600);

    server.process_input(mixed, recovery_time);
    let mut buffer = [0; 2_048];
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert!(read > 1_000);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAB));
}

#[test]
fn lost_chaff_data_is_reported_as_retransmission_not_fresh_chaff() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), true);
    let chaff = client.stream_create(StreamType::BiDi).unwrap();
    client.stream_send(chaff, &[0xCC; 1_000]).unwrap();
    client
        .qcsd_register_stream_role(
            chaff,
            QcsdRequestRole::Chaff {
                resource_id: 1,
                request_id: None,
            },
        )
        .unwrap();

    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_200).unwrap();
    let queued_at = now();
    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(32),
            packet,
            queued_at,
            queued_at + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let dropped = client.process_output(queued_at).dgram().unwrap();
    assert_eq!(dropped.len(), 1_200);

    let recovery_time = queued_at + AT_LEAST_PTO;
    _ = client.process_output(recovery_time);
    queue_congestion_sensitive_target(&mut client, 33, 1_200, true, recovery_time).unwrap();
    let retransmission = client.process_output(recovery_time).dgram().unwrap();
    let composition = drain_observations(&mut client)
        .into_iter()
        .find_map(|observation| match observation {
            QcsdObservation::SlotResolved {
                slot: QcsdSlotId(33),
                outcome: QcsdSlotOutcome::Full { composition },
                ..
            } => Some(composition),
            _ => None,
        })
        .expect("chaff retransmission has typed wire composition");
    assert_eq!(composition.application_stream_bytes, 0);
    assert!(composition.retransmission_stream_bytes > 0);
    assert_eq!(composition.chaff_stream_bytes, 0);

    server.process_input(retransmission, recovery_time);
    let mut buffer = [0; 1_024];
    let (read, _) = server.stream_recv(chaff, &mut buffer).unwrap();
    assert_eq!(read, 1_000);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xCC));
}
