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
    Direction, MissedSlotReason, Packet, QcsdDatagramClass, QcsdEndpointId, QcsdObservation,
    QcsdObservationClock, QcsdReceiveActionIdentity, QcsdReceiveLimitFatal,
    QcsdReceiveLimitOutcome, QcsdRequestRole, QcsdSlotId, QcsdStreamId, TrafficMorphingConfig,
    TrafficMorphingEgress, TrafficMorphingOutcome,
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
    let queued_at = now();
    connection.qcsd_queue_scheduled_packet_target_window(
        QcsdSlotId(slot),
        packet,
        queued_at,
        queued_at + Duration::from_secs(1),
        allow_stream_data,
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
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(41),
            packet,
            release,
            release + Duration::from_millis(5),
            false,
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

    client
        .qcsd_queue_scheduled_packet_target_window(
            QcsdSlotId(31),
            packet,
            recovery_time,
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
