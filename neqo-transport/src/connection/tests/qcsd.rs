// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{cell::RefCell, net::SocketAddr, rc::Rc, time::Duration};

use neqo_csdef::{
    Direction, MissedSlotReason, Packet, QcsdEndpointId, QcsdObservation, QcsdRequestRole,
    QcsdSlotId, TrafficMorphingConfig, TrafficMorphingEgress, TrafficMorphingOutcome,
};
use test_fixture::{DEFAULT_ADDR, DEFAULT_ADDR_V4, fixture_init, now};

use super::{
    AT_LEAST_PTO, CountingConnectionIdGenerator, DEFAULT_RTT, connect_force_idle, connect_rtt_idle,
    cwnd_avail, default_client, default_server, fill_cwnd, fill_stream, handshake_with_modifier,
};
use crate::{
    Connection, ConnectionParameters, Error, StreamType,
    connection::params::INITIAL_LOCAL_MAX_STREAM_DATA, sender::PACING_BURST_SIZE,
    tracking::PacketNumberSpace,
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
    connection.qcsd_queue_scheduled_packet_target(
        QcsdSlotId(slot),
        packet,
        now() + Duration::from_secs(1),
        allow_stream_data,
    )
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
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(2),
            packet,
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
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(11),
            packet,
            now() + Duration::from_secs(1),
            false,
        )
        .unwrap();
    assert_eq!(client.process_output(now()).dgram().unwrap().len(), 1_000);
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
fn expired_target_reports_a_typed_miss() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
    client
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(12), packet, now(), false)
        .unwrap();
    _ = client.process_output(now());
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
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(14), packet, exhausted_at, false)
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
        .qcsd_queue_scheduled_packet_target(QcsdSlotId(15), packet, now, false)
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
fn closing_endpoint_misses_every_pending_target() {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    client.qcsd_enable(QcsdEndpointId(7), false);
    for slot in [20, 21] {
        let packet = Packet::new(Duration::ZERO, Direction::Outgoing, 1_000).unwrap();
        client
            .qcsd_queue_scheduled_packet_target(
                QcsdSlotId(slot),
                packet,
                now() + Duration::from_secs(1),
                false,
            )
            .unwrap();
    }
    client.close(now(), 0, "test close");
    let misses = drain_observations(&mut client)
        .into_iter()
        .filter(|observation| {
            matches!(
                observation,
                QcsdObservation::SlotMissed {
                    reason: MissedSlotReason::EndpointClosed,
                    ..
                }
            )
        })
        .count();
    assert_eq!(misses, 2);
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
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(13),
            packet,
            now() + Duration::from_secs(1),
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
    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(30),
            packet,
            now() + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let dropped = client.process_output(now()).dgram().unwrap();
    assert_eq!(dropped.len(), 1_200);

    let recovery_time = now() + AT_LEAST_PTO;
    _ = client.process_output(recovery_time);
    let mut buffer = [0; 1_024];
    assert!(server.stream_recv(application, &mut buffer).is_err());

    client
        .qcsd_queue_scheduled_packet_target(
            QcsdSlotId(31),
            packet,
            recovery_time + Duration::from_secs(1),
            true,
        )
        .unwrap();
    let retransmission = client.process_output(recovery_time).dgram().unwrap();
    assert_eq!(retransmission.len(), 1_200);
    server.process_input(retransmission, recovery_time);
    let (read, _) = server.stream_recv(application, &mut buffer).unwrap();
    assert_eq!(read, 1_000);
    assert!(buffer[..read].iter().all(|byte| *byte == 0xAA));
    if let Ok((read, _)) = server.stream_recv(chaff, &mut buffer) {
        assert!(buffer[..read].iter().all(|byte| *byte == 0xCC));
    }
}
